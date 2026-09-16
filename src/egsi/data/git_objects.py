"""Safe access to files in bare Git object stores."""

from __future__ import annotations

import base64
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator, TypeVar

from egsi.data.repository_paths import canonical_repo_blob_path


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_GIT_TIMEOUT_SECONDS = 10.0
_CANONICAL_DIFF_MAX_BYTES = 2 * 1024 * 1024
_GIT_METADATA_MAX_BYTES = 64 * 1024
_PROCESS_GROUP_TERM_GRACE_SECONDS = 0.1
_PROCESS_GROUP_KILL_GRACE_SECONDS = 0.1
_READER_JOIN_GRACE_SECONDS = 0.1
_GIT_CACHE_MAX_ENTRIES = 1_000_000
_GIT_CACHE_MAX_DEPTH = 128
_ISOLATED_BARE_CONFIG = b"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = true
\tattributesfile = /dev/null
"""
_ISOLATED_BARE_HEAD = b"ref: refs/heads/egsi-isolated\n"
_QueryResult = TypeVar("_QueryResult", bytes, bool)


@dataclass(slots=True)
class _GitQueryCapture:
    stores: dict[Path, str]
    entries: list[dict[str, Any]]
    seen: set[tuple[str, str, str]] = field(default_factory=set)


@dataclass(slots=True)
class _GitQueryReplay:
    stores: dict[Path, str]
    entries: dict[tuple[str, str, str], dict[str, Any]]


_GIT_QUERY_CAPTURE: ContextVar[_GitQueryCapture | None] = ContextVar(
    "egsi_git_query_capture", default=None
)
_GIT_QUERY_REPLAY: ContextVar[_GitQueryReplay | None] = ContextVar(
    "egsi_git_query_replay", default=None
)


def _query_key(
    store_path: str, operation: str, arguments: tuple[str | int, ...]
) -> tuple[str, str, str]:
    return (
        store_path,
        operation,
        json.dumps(arguments, ensure_ascii=True, separators=(",", ":")),
    )


def _encoded_query_result(
    *,
    store_path: str,
    operation: str,
    arguments: tuple[str | int, ...],
    result: bytes | bool | BaseException,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "store_path": store_path,
        "operation": operation,
        "arguments": list(arguments),
    }
    if type(result) is bytes:
        entry.update(
            {
                "outcome": "bytes",
                "result_base64": base64.b64encode(result).decode("ascii"),
            }
        )
    elif type(result) is bool:
        entry.update({"outcome": "bool", "result_bool": result})
    elif isinstance(result, GitCacheIntegrityError):
        raise result
    elif isinstance(result, FileNotFoundError):
        entry.update({"outcome": "error", "error_kind": "FileNotFoundError"})
    elif isinstance(result, ValueError):
        entry.update({"outcome": "error", "error_kind": "ValueError"})
    elif isinstance(result, RuntimeError):
        entry.update({"outcome": "error", "error_kind": "RuntimeError"})
    else:
        raise TypeError("unsupported semantic Git query result")
    return entry


def _decoded_query_result(entry: dict[str, Any]) -> bytes | bool:
    outcome = entry.get("outcome")
    if outcome == "bytes":
        return base64.b64decode(entry["result_base64"], validate=True)
    if outcome == "bool":
        return entry["result_bool"]
    if outcome == "error":
        kind = entry.get("error_kind")
        error_type = {
            "FileNotFoundError": FileNotFoundError,
            "ValueError": ValueError,
            "RuntimeError": RuntimeError,
        }.get(kind)
        if error_type is None:
            raise ValueError("semantic Git query error kind is invalid")
        raise error_type("captured semantic Git query failed")
    raise ValueError("semantic Git query outcome is invalid")


def _relative_cache_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise ValueError("path must be a non-empty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or "\x00" in value:
        raise ValueError("path must remain inside the declared root")
    if path.as_posix() in {"", "."}:
        raise ValueError("path must name a file")
    return path.parts


@dataclass(frozen=True, slots=True)
class GitCacheIdentity:
    """One byte-exact identity entry captured through an already-open directory."""

    relative_path: str
    st_dev: int
    st_ino: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


class GitCacheIntegrityError(ValueError):
    """A live cache changed after its safe identity closure was established."""


@dataclass(slots=True)
class _GitCacheBudget:
    """One aggregate entry/depth budget for every linked cache namespace."""

    entry_count: int = 0

    def check_depth(self, depth: int) -> None:
        if depth > _GIT_CACHE_MAX_DEPTH:
            raise ValueError("Git cache directory depth exceeds its bound")

    def append(
        self, entries: list[GitCacheIdentity], entry: GitCacheIdentity
    ) -> None:
        self.entry_count += 1
        if self.entry_count > _GIT_CACHE_MAX_ENTRIES:
            raise ValueError("Git cache identity closure exceeds its bound")
        entries.append(entry)

    def extend(
        self,
        entries: list[GitCacheIdentity],
        additions: Iterable[GitCacheIdentity],
    ) -> None:
        for entry in additions:
            self.append(entries, entry)


def _identity(relative_path: str, info: os.stat_result) -> GitCacheIdentity:
    return GitCacheIdentity(
        relative_path=relative_path,
        st_dev=info.st_dev,
        st_ino=info.st_ino,
        mode=info.st_mode,
        nlink=info.st_nlink,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_directory_at(parent_fd: int, name: str, description: str) -> int:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 1:
            raise OSError
        return descriptor
    except OSError as exc:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        raise ValueError(f"Git cache {description} is unavailable or unsafe") from exc


def _entry_descriptor(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        return descriptor, os.fstat(descriptor)
    except OSError as exc:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        raise ValueError(
            "Git cache object-store entry escapes its allowed boundary"
        ) from exc


def _join_identity_path(parent: str, name: str) -> str:
    if "/" in name or name in {"", ".", ".."} or "\x00" in name:
        raise ValueError("Git cache contains an invalid entry name")
    if parent == ".":
        return name
    if parent.endswith(":."):
        return f"{parent[:-1]}{name}"
    return f"{parent}/{name}"


def _capture_directory_tree(
    descriptor: int,
    *,
    relative_path: str,
    entries: list[GitCacheIdentity],
    budget: _GitCacheBudget,
    depth: int = 0,
) -> None:
    budget.check_depth(depth)
    before = os.fstat(descriptor)
    if not stat.S_ISDIR(before.st_mode) or before.st_nlink < 1:
        raise ValueError("Git cache object store cannot be traversed")
    budget.append(entries, _identity(relative_path, before))
    try:
        names = sorted(os.listdir(descriptor), key=os.fsencode)
    except OSError as exc:
        raise ValueError("Git cache object store cannot be traversed") from exc
    for name in names:
        child_path = _join_identity_path(relative_path, name)
        child_fd, child_info = _entry_descriptor(descriptor, name)
        try:
            if stat.S_ISLNK(child_info.st_mode):
                raise ValueError(
                    "Git cache object-store entry escapes its allowed boundary"
                )
            if stat.S_ISDIR(child_info.st_mode):
                directory_fd = _open_directory_at(
                    descriptor, name, "object store directory"
                )
                try:
                    opened_info = os.fstat(directory_fd)
                    if _identity(child_path, opened_info) != _identity(
                        child_path, child_info
                    ):
                        raise ValueError("Git cache identity changed during traversal")
                    _capture_directory_tree(
                        directory_fd,
                        relative_path=child_path,
                        entries=entries,
                        budget=budget,
                        depth=depth + 1,
                    )
                finally:
                    os.close(directory_fd)
            elif stat.S_ISREG(child_info.st_mode) and child_info.st_nlink >= 1:
                budget.check_depth(depth + 1)
                budget.append(entries, _identity(child_path, child_info))
            else:
                raise ValueError(
                    "Git cache object store contains an unsupported special file"
                )
        finally:
            os.close(child_fd)
    try:
        after_names = sorted(os.listdir(descriptor), key=os.fsencode)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError("Git cache object store cannot be traversed") from exc
    if names != after_names or _identity(relative_path, before) != _identity(
        relative_path, after
    ):
        raise ValueError("Git cache identity changed during traversal")


def _read_regular_below(
    directory_fd: int,
    parts: tuple[str, ...],
    *,
    description: str,
) -> bytes | None:
    """Read one bounded regular file through no-follow directory descriptors."""

    current = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, _directory_flags(), dir_fd=current)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise ValueError(f"Git cache {description} is unsafe") from exc
            os.close(current)
            current = child
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            file_fd = os.open(parts[-1], flags, dir_fd=current)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError(f"Git cache {description} is unsafe") from exc
        try:
            before = os.fstat(file_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink < 1
                or before.st_size > _GIT_METADATA_MAX_BYTES
            ):
                raise ValueError(f"Git cache {description} is malformed")
            chunks: list[bytes] = []
            remaining = before.st_size + 1
            while remaining:
                chunk = os.read(file_fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_fd)
            if (
                len(raw) != before.st_size
                or _identity(description, before) != _identity(description, after)
            ):
                raise ValueError(f"Git cache {description} changed while reading")
            return raw
        finally:
            os.close(file_fd)
    finally:
        os.close(current)


class GitCacheGuard:
    """Bind a complete no-follow Git-cache identity closure to real queries."""

    def __init__(self, root: Path, value: object) -> None:
        self._closed = False
        self._query_depth = 0
        self._lock = threading.RLock()
        self._parts = _relative_cache_path(value)
        try:
            root_path = Path(root).resolve(strict=True)
            self._root_fd = os.open(root_path, _directory_flags())
        except (OSError, FileNotFoundError) as exc:
            raise ValueError("root must exist") from exc
        self._mount_target: str | None = None
        try:
            root_info = os.fstat(self._root_fd)
            if not stat.S_ISDIR(root_info.st_mode):
                raise ValueError("root must exist")
            self._boundary_fd = os.dup(self._root_fd)
            self._location_parts = self._parts
            if self._parts[0] == "data":
                try:
                    mount_before = os.stat(
                        "data", dir_fd=self._root_fd, follow_symlinks=False
                    )
                except OSError as exc:
                    raise ValueError("declared data mount is unavailable") from exc
                if stat.S_ISLNK(mount_before.st_mode):
                    target = os.readlink("data", dir_fd=self._root_fd)
                    mount_after = os.stat(
                        "data", dir_fd=self._root_fd, follow_symlinks=False
                    )
                    if _identity("@mount:data", mount_before) != _identity(
                        "@mount:data", mount_after
                    ):
                        raise ValueError("declared data mount changed")
                    target_path = Path(target)
                    if not target_path.is_absolute():
                        target_path = root_path / target_path
                    try:
                        boundary_path = target_path.resolve(strict=True)
                        boundary_fd = os.open(boundary_path, _directory_flags())
                    except (OSError, FileNotFoundError) as exc:
                        raise ValueError("declared data mount is unavailable") from exc
                    os.close(self._boundary_fd)
                    self._boundary_fd = boundary_fd
                    self._mount_target = target
                    self._location_parts = self._parts[1:]
            budget = _GitCacheBudget()
            self._cache_fd, location = self._open_location(budget)
            self._pinned_cache_identity = _identity(".", os.fstat(self._cache_fd))
            self.cache_path = Path(os.readlink(f"/proc/self/fd/{self._cache_fd}"))
            self._boundary_path = Path(
                os.readlink(f"/proc/self/fd/{self._boundary_fd}")
            )
            self._git_dir_path = Path(f"/proc/self/fd/{self._cache_fd}")
            self.identity_closure = self._capture(location, budget=budget)
            by_path = {entry.relative_path: entry for entry in self.identity_closure}
            head = by_path.get("HEAD")
            objects = by_path.get("objects")
            if head is None or not stat.S_ISREG(head.mode):
                raise ValueError("Git cache HEAD must be a regular file")
            if objects is None or not stat.S_ISDIR(objects.mode):
                raise ValueError("Git cache objects must be a directory")
        except BaseException:
            self.close()
            raise

    def _open_location(
        self, budget: _GitCacheBudget
    ) -> tuple[int, tuple[GitCacheIdentity, ...]]:
        current = os.dup(self._boundary_fd)
        identities: list[GitCacheIdentity] = []
        relative = ""
        try:
            for depth, part in enumerate(self._location_parts, start=1):
                budget.check_depth(depth)
                child = _open_directory_at(current, part, "declared directory")
                os.close(current)
                current = child
                relative = part if not relative else f"{relative}/{part}"
                identities.append(
                    _identity(f"@location:{relative}", os.fstat(current))
                )
            return current, tuple(identities)
        except BaseException:
            os.close(current)
            raise

    def _capture_mount(self) -> list[GitCacheIdentity]:
        result: list[GitCacheIdentity] = []
        if self._mount_target is not None:
            try:
                before = os.stat("data", dir_fd=self._root_fd, follow_symlinks=False)
                target = os.readlink("data", dir_fd=self._root_fd)
                after = os.stat("data", dir_fd=self._root_fd, follow_symlinks=False)
            except OSError as exc:
                raise ValueError("declared data mount changed") from exc
            if (
                not stat.S_ISLNK(before.st_mode)
                or target != self._mount_target
                or _identity("@mount:data", before)
                != _identity("@mount:data", after)
            ):
                raise ValueError("declared data mount changed")
            result.append(_identity("@mount:data", before))
        return result

    def _target_parts(
        self, raw: str, *, base: tuple[str, ...], description: str
    ) -> tuple[str, ...]:
        if not raw or "\x00" in raw:
            raise ValueError(f"Git cache {description} is malformed")
        target = Path(raw)
        if target.is_absolute():
            normalized = Path(os.path.normpath(target))
            try:
                parts = list(normalized.relative_to(self._boundary_path).parts)
            except ValueError as exc:
                raise ValueError(
                    f"Git cache {description} escapes its allowed boundary"
                ) from exc
        else:
            parts = list(base)
            for part in target.parts:
                if part in {"", "."}:
                    continue
                if part == "..":
                    if not parts:
                        raise ValueError(
                            f"Git cache {description} escapes its allowed boundary"
                        )
                    parts.pop()
                else:
                    parts.append(part)
        return tuple(parts)

    def _open_boundary_directory(
        self,
        parts: tuple[str, ...],
        *,
        namespace: str,
        budget: _GitCacheBudget,
    ) -> tuple[int, list[GitCacheIdentity]]:
        current = os.dup(self._boundary_fd)
        identities: list[GitCacheIdentity] = []
        relative = ""
        try:
            for depth, part in enumerate(parts, start=1):
                budget.check_depth(depth)
                child = _open_directory_at(current, part, namespace)
                os.close(current)
                current = child
                relative = part if not relative else f"{relative}/{part}"
                identities.append(
                    _identity(f"@{namespace}-location:{relative}", os.fstat(current))
                )
            return current, identities
        except BaseException:
            os.close(current)
            raise

    def _capture_linked_object_stores(
        self,
        entries: list[GitCacheIdentity],
        budget: _GitCacheBudget,
    ) -> None:
        """Capture commondir and recursively declared alternates inside the boundary."""

        cache_paths = {entry.relative_path for entry in entries}
        object_parts = (*self._location_parts, "objects")
        common_raw = (
            _read_regular_below(
                self._cache_fd, ("commondir",), description="commondir"
            )
            if "commondir" in cache_paths
            else None
        )
        if common_raw is not None:
            try:
                common_text = common_raw.decode("utf-8").strip()
            except UnicodeError as exc:
                raise ValueError("Git cache commondir is malformed") from exc
            common_parts = self._target_parts(
                common_text,
                base=self._location_parts,
                description="commondir",
            )
            common_fd, common_location = self._open_boundary_directory(
                common_parts, namespace="common", budget=budget
            )
            budget.extend(entries, common_location)
            common_start = len(entries)
            try:
                _capture_directory_tree(
                    common_fd,
                    relative_path="@common:.",
                    entries=entries,
                    budget=budget,
                    depth=len(common_parts),
                )
            finally:
                os.close(common_fd)
            common_entries = entries[common_start:]
            if "@common:objects" not in {
                entry.relative_path for entry in common_entries
            }:
                raise ValueError("Git cache objects must be a directory")
            object_parts = (*common_parts, "objects")

        pending = [(object_parts, 0)]
        visited: set[tuple[int, int]] = set()
        while pending:
            current_parts, alternate_depth = pending.pop()
            budget.check_depth(alternate_depth)
            namespace = f"objects:{'/'.join(current_parts)}"
            objects_fd, location = self._open_boundary_directory(
                current_parts, namespace=namespace, budget=budget
            )
            try:
                info = os.fstat(objects_fd)
                key = (info.st_dev, info.st_ino)
                if key in visited:
                    continue
                visited.add(key)
                if current_parts != object_parts:
                    budget.extend(entries, location)
                    _capture_directory_tree(
                        objects_fd,
                        relative_path=f"@alternate:{'/'.join(current_parts)}",
                        entries=entries,
                        budget=budget,
                        depth=len(current_parts),
                    )
                alternates_raw = _read_regular_below(
                    objects_fd,
                    ("info", "alternates"),
                    description="alternates",
                )
                if alternates_raw is not None:
                    try:
                        alternate_lines = alternates_raw.decode("utf-8").splitlines()
                    except UnicodeError as exc:
                        raise ValueError("Git cache alternates is malformed") from exc
                    for line in alternate_lines:
                        if not line:
                            continue
                        pending.append(
                            (
                                self._target_parts(
                                    line,
                                    base=current_parts,
                                    description="alternate object directory",
                                ),
                                alternate_depth + 1,
                            )
                        )
            finally:
                os.close(objects_fd)

    def _capture(
        self,
        location: tuple[GitCacheIdentity, ...] | None = None,
        *,
        budget: _GitCacheBudget | None = None,
    ) -> tuple[GitCacheIdentity, ...]:
        if self._closed:
            raise ValueError("Git cache guard is closed")
        if budget is None:
            budget = _GitCacheBudget()
        opened_fd: int | None = None
        if location is None:
            opened_fd, location = self._open_location(budget)
            if _identity(".", os.fstat(opened_fd)) != self._pinned_cache_identity:
                os.close(opened_fd)
                raise ValueError("Git cache identity closure changed")
        entries: list[GitCacheIdentity] = []
        mount = self._capture_mount()
        if mount:
            budget.check_depth(1)
        budget.extend(entries, mount)
        budget.extend(entries, location)
        try:
            _capture_directory_tree(
                self._cache_fd,
                relative_path=".",
                entries=entries,
                budget=budget,
                depth=len(self._location_parts),
            )
            self._capture_linked_object_stores(entries, budget)
        finally:
            if opened_fd is not None:
                os.close(opened_fd)
        entries.sort(key=lambda entry: os.fsencode(entry.relative_path))
        if len(entries) != budget.entry_count or len(entries) > _GIT_CACHE_MAX_ENTRIES:
            raise ValueError("Git cache identity closure exceeds its bound")
        if len({entry.relative_path for entry in entries}) != len(entries):
            raise ValueError("Git cache identity closure is ambiguous")
        return tuple(entries)

    @contextmanager
    def query(self) -> Iterator[None]:
        """Require one real query to start and end at the same safe closure."""

        with self._lock:
            if self._query_depth:
                self._query_depth += 1
                try:
                    yield
                finally:
                    self._query_depth -= 1
                return
            try:
                before = self._capture()
            except ValueError as exc:
                raise GitCacheIntegrityError(str(exc)) from exc
            if before != self.identity_closure:
                raise GitCacheIntegrityError("Git cache identity closure changed")
            self._query_depth = 1
            try:
                yield
            finally:
                self._query_depth = 0
                try:
                    after = self._capture()
                except ValueError as exc:
                    raise GitCacheIntegrityError(str(exc)) from exc
                if after != before:
                    raise GitCacheIntegrityError(
                        "Git cache identity closure changed"
                    )

    def open_store(self) -> "GitObjectStore":
        try:
            with self.query():
                return GitObjectStore(self.cache_path, _guard=self)
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> "GitCacheGuard":
        if self._closed:
            raise ValueError("Git cache guard is closed")
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        for name in ("_cache_fd", "_boundary_fd", "_root_fd"):
            descriptor = getattr(self, name, None)
            if isinstance(descriptor, int):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)

    def __del__(self) -> None:
        self.close()


def validate_git_cache(root: Path, value: object) -> Path:
    """Validate one cache with the same no-follow closure used by real queries."""

    guard = GitCacheGuard(root, value)
    try:
        return guard.cache_path
    finally:
        guard.close()


@contextmanager
def capture_git_queries(
    stores: dict[Path, str],
) -> Iterator[list[dict[str, Any]]]:
    """Capture bounded public Git queries for immutable semantic replay."""

    if _GIT_QUERY_CAPTURE.get() is not None or _GIT_QUERY_REPLAY.get() is not None:
        raise RuntimeError("semantic Git query context is already active")
    normalized: dict[Path, str] = {}
    for path, relative in stores.items():
        resolved = Path(path).resolve(strict=True)
        if (
            not isinstance(relative, str)
            or not relative.startswith("data/")
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or resolved in normalized
        ):
            raise ValueError("semantic Git capture store mapping is invalid")
        normalized[resolved] = relative
    entries: list[dict[str, Any]] = []
    state = _GitQueryCapture(stores=normalized, entries=entries)
    token = _GIT_QUERY_CAPTURE.set(state)
    try:
        yield entries
    finally:
        _GIT_QUERY_CAPTURE.reset(token)
        entries.sort(
            key=lambda item: _query_key(
                item["store_path"], item["operation"], tuple(item["arguments"])
            )
        )


@contextmanager
def replay_git_queries(
    root: Path,
    entries: list[dict[str, Any]],
    *,
    store_paths: list[str] | None = None,
) -> Iterator[None]:
    """Serve only captured queries to stores materialized below *root*."""

    if _GIT_QUERY_CAPTURE.get() is not None or _GIT_QUERY_REPLAY.get() is not None:
        raise RuntimeError("semantic Git query context is already active")
    root = Path(root).resolve(strict=True)
    stores: dict[Path, str] = {}
    indexed: dict[tuple[str, str, str], dict[str, Any]] = {}
    declared_stores = (
        sorted({entry["store_path"] for entry in entries})
        if store_paths is None
        else store_paths
    )
    previous_store = ""
    for relative in declared_stores:
        relative_path = Path(relative) if isinstance(relative, str) else Path()
        if (
            not isinstance(relative, str)
            or not relative.startswith("data/")
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or "\\" in relative
            or "\x00" in relative
            or relative_path.as_posix() != relative
            or relative <= previous_store
        ):
            raise ValueError("semantic Git replay store mapping is invalid")
        path = (root / relative).resolve(strict=True)
        if (
            root not in path.parents
            or path in stores
            or not path.is_dir()
            or not (path / "objects").is_dir()
            or not (path / "HEAD").is_file()
        ):
            raise ValueError("semantic Git replay store mapping is invalid")
        stores[path] = relative
        previous_store = relative
    for entry in entries:
        relative = entry["store_path"]
        if relative not in stores.values():
            raise ValueError("semantic Git query uses an undeclared replay store")
        key = _query_key(relative, entry["operation"], tuple(entry["arguments"]))
        if key in indexed:
            raise ValueError("semantic Git query closure contains a duplicate")
        indexed[key] = entry
    token = _GIT_QUERY_REPLAY.set(_GitQueryReplay(stores=stores, entries=indexed))
    try:
        yield
    finally:
        _GIT_QUERY_REPLAY.reset(token)


def verify_git_queries(
    root: Path,
    entries: list[dict[str, Any]],
    *,
    store_paths: list[str] | None = None,
) -> None:
    """Rerun every captured query against the pinned live Git boundaries."""

    declared_stores = (
        sorted({entry["store_path"] for entry in entries})
        if store_paths is None
        else store_paths
    )
    guarded_stores: dict[str, tuple[GitCacheGuard, GitObjectStore]] = {}
    try:
        for relative in declared_stores:
            guard = GitCacheGuard(root, relative)
            try:
                guarded_stores[relative] = (guard, guard.open_store())
            except BaseException:
                guard.close()
                raise
        for expected in entries:
            relative = expected["store_path"]
            try:
                guard, store = guarded_stores[relative]
            except KeyError:
                raise ValueError(
                    "semantic Git query uses an undeclared live store"
                ) from None
            arguments = tuple(expected["arguments"])
            operation = expected["operation"]
            try:
                # This outer scope is deliberate: it also contains any caller or
                # test instrumentation wrapped around the public store method.
                with guard.query():
                    if operation == "canonical_diff":
                        observed: bytes | bool | BaseException = store.canonical_diff(
                            *arguments
                        )
                    elif operation == "contains":
                        observed = store.contains(*arguments)
                    elif operation == "read_bytes":
                        observed = store.read_bytes(*arguments)
                    else:
                        raise ValueError("semantic Git query operation is invalid")
            except GitCacheIntegrityError:
                raise
            except (FileNotFoundError, RuntimeError, ValueError) as error:
                observed = error
            if _encoded_query_result(
                store_path=relative,
                operation=operation,
                arguments=arguments,
                result=observed,
            ) != expected:
                if isinstance(observed, ValueError) and str(observed).startswith(
                    "Git cache"
                ):
                    raise observed
                raise ValueError("semantic Git query result changed")
    finally:
        for guard, _ in guarded_stores.values():
            guard.close()


def validate_path(path: str) -> str:
    """Return a byte-exact canonical repository-relative POSIX blob path."""

    return canonical_repo_blob_path(path)


def _validate_commit(commit: str) -> str:
    if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a lowercase 40-character hexadecimal SHA-1")
    return commit


def _git_environment(alternate_objects: Path | None = None) -> dict[str, str]:
    """Return a Git environment independent of caller-controlled Git settings."""

    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    if alternate_objects is not None:
        environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = _git_path_list_entry(
            alternate_objects
        )
    return environment


def _git_path_list_entry(path: Path) -> str:
    """C-style quote one literal Git path-list entry."""

    value = os.fspath(path)
    escaped: list[str] = []
    named_escapes = {
        "\\": "\\\\",
        '"': '\\"',
        "\a": "\\a",
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\v": "\\v",
        "\f": "\\f",
        "\r": "\\r",
    }
    for character in value:
        if character in named_escapes:
            escaped.append(named_escapes[character])
        elif ord(character) < 32 or ord(character) == 127:
            escaped.append(f"\\{ord(character):03o}")
        else:
            escaped.append(character)
    return '"' + "".join(escaped) + '"'


@contextmanager
def _isolated_bare_shell() -> Iterator[Path]:
    """Yield a minimal bare repository which has no caller-controlled config."""

    with tempfile.TemporaryDirectory(prefix="egsi-canonical-diff-") as directory:
        git_dir = Path(directory)
        os.chmod(git_dir, 0o700)
        (git_dir / "objects").mkdir(mode=0o700)
        (git_dir / "refs").mkdir(mode=0o700)
        (git_dir / "config").write_bytes(_ISOLATED_BARE_CONFIG)
        (git_dir / "HEAD").write_bytes(_ISOLATED_BARE_HEAD)
        yield git_dir


def _git_command(git_dir: Path, arguments: tuple[str, ...]) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        f"--git-dir={git_dir}",
        *arguments,
    ]


def _terminate_and_reap(
    process: subprocess.Popen[bytes],
    reader: "_BoundedReader | None" = None,
    *,
    reader_started: bool = False,
    process_reaped: bool = False,
) -> None:
    """Bound cleanup of a Git process group and any stdout reader."""

    if not process_reaped:
        _signal_process_group(process, signal.SIGTERM)
        # Do not reap the leader during this grace: retaining its PID prevents a
        # concurrent group from reusing the PGID before the final group signal.
        time.sleep(_PROCESS_GROUP_TERM_GRACE_SECONDS)

        # Always address the original process group, even when its leader has exited.
        _signal_process_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=_PROCESS_GROUP_KILL_GRACE_SECONDS)
        except (subprocess.TimeoutExpired, OSError, AttributeError):
            pass

    if process.stdout is not None:
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
    if reader is not None and reader_started:
        reader.thread.join(timeout=_READER_JOIN_GRACE_SECONDS)


def _signal_process_group(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    """Signal a dedicated Git process group, falling back for lightweight fakes."""

    pid = getattr(process, "pid", None)
    killpg = getattr(os, "killpg", None)
    if isinstance(pid, int) and pid > 0 and killpg is not None:
        try:
            killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass

    action = "terminate" if sig == signal.SIGTERM else "kill"
    method = getattr(process, action, None)
    if method is not None:
        try:
            method()
        except OSError:
            pass


class _BoundedReader:
    """A platform-neutral reader which owns only a fixed-size byte buffer."""

    def __init__(self, stream: object, capacity: int) -> None:
        self._stream = stream
        self.buffer = bytearray(capacity)
        self.length = 0
        self.overflow = False
        self.failed = False
        self.finished = threading.Event()
        self.thread = threading.Thread(target=self._read, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _read(self) -> None:
        try:
            view = memoryview(self.buffer)
            while self.length < len(self.buffer):
                count = self._stream.readinto(view[self.length :])
                if not count:
                    break
                self.length += count
            self.overflow = self.length == len(self.buffer)
        except Exception:
            self.failed = True
        finally:
            self.finished.set()

    def bytes(self) -> bytes:
        return bytes(self.buffer[: self.length])


def _git_pass_fds(
    git_dir: Path,
    *,
    alternate_objects: Path | None,
    inherited_directory_fd: int | None,
) -> tuple[int, ...]:
    """Validate and retain one guarded directory descriptor for Git."""

    if inherited_directory_fd is None:
        return ()
    if (
        type(inherited_directory_fd) is not int
        or inherited_directory_fd < 3
    ):
        raise ValueError("inherited Git directory descriptor is invalid")
    try:
        info = os.fstat(inherited_directory_fd)
    except OSError:
        raise ValueError("inherited Git directory descriptor is invalid") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 1:
        raise ValueError("inherited Git directory descriptor is invalid")

    descriptor_path = Path(f"/proc/self/fd/{inherited_directory_fd}")
    if Path(git_dir) != descriptor_path and (
        alternate_objects is None
        or Path(alternate_objects) != descriptor_path / "objects"
    ):
        raise ValueError("Git path is not bound to its inherited descriptor")
    return (inherited_directory_fd,)


def _run_text(
    git_dir: Path,
    *arguments: str,
    inherited_directory_fd: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a small Git metadata query with a finite, sanitized execution context."""

    pass_fds = _git_pass_fds(
        git_dir,
        alternate_objects=None,
        inherited_directory_fd=inherited_directory_fd,
    )
    process: subprocess.Popen[str] | None = None
    start_failed = False
    try:
        process = subprocess.Popen(
            _git_command(git_dir, arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=_git_environment(),
            start_new_session=True,
            close_fds=True,
            pass_fds=pass_fds,
        )
    except OSError:
        start_failed = True
    if start_failed:
        raise RuntimeError("git command failed")
    assert process is not None

    stdout = ""
    timed_out = False
    failed = False
    try:
        stdout, _ = process.communicate(timeout=_GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
    except OSError:
        failed = True

    if timed_out:
        _terminate_and_reap(process)
        raise RuntimeError("git command timed out")
    if failed:
        _terminate_and_reap(process)
        raise RuntimeError("git command failed")
    return subprocess.CompletedProcess(process.args, process.returncode, stdout=stdout)


def _read_limited(
    git_dir: Path,
    arguments: tuple[str, ...],
    expected_size: int,
    *,
    alternate_objects: Path | None = None,
    inherited_directory_fd: int | None = None,
) -> bytes:
    """Read only ``expected_size + 1`` bytes from Git, with one hard deadline."""

    pass_fds = _git_pass_fds(
        git_dir,
        alternate_objects=alternate_objects,
        inherited_directory_fd=inherited_directory_fd,
    )
    process: subprocess.Popen[bytes] | None = None
    start_failed = False
    try:
        process = subprocess.Popen(
            _git_command(git_dir, arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
            bufsize=0,
            env=_git_environment(alternate_objects),
            start_new_session=True,
            close_fds=True,
            pass_fds=pass_fds,
        )
    except OSError:
        start_failed = True
    if start_failed:
        raise RuntimeError("git command failed")
    assert process is not None and process.stdout is not None

    reader: _BoundedReader | None = None
    reader_started = False
    process_reaped = False
    completed = False
    try:
        deadline = time.monotonic() + _GIT_TIMEOUT_SECONDS
        reader = _BoundedReader(process.stdout, expected_size + 1)
        try:
            reader.start()
        except BaseException:
            reader_started = getattr(reader.thread, "ident", None) is not None
            raise
        else:
            reader_started = True
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not reader.finished.wait(timeout=remaining):
            raise RuntimeError("git command timed out")
        if reader.failed:
            raise RuntimeError("git command failed")
        if reader.overflow:
            raise ValueError

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("git command timed out")
        try:
            process.wait(timeout=remaining)
            process_reaped = True
        except subprocess.TimeoutExpired:
            raise RuntimeError("git command timed out") from None
        except OSError:
            raise RuntimeError("git command failed") from None

        if reader.thread.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("git command timed out")
            reader.thread.join(timeout=remaining)
            if reader.thread.is_alive():
                raise RuntimeError("git command timed out")
        if process.returncode != 0:
            raise FileNotFoundError
        payload = reader.bytes()
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
        completed = True
        return payload
    finally:
        if not completed:
            _terminate_and_reap(
                process,
                reader,
                reader_started=reader_started,
                process_reaped=process_reaped,
            )


class GitObjectStore:
    """Read blobs from a bare Git cache without accepting revision expressions."""

    def __init__(
        self, git_dir: Path, *, _guard: GitCacheGuard | None = None
    ) -> None:
        provided_path = Path(git_dir)
        self._guard = _guard
        self._closed = False
        self._inherited_directory_fd = (
            _guard._cache_fd if _guard is not None else None
        )
        if _guard is not None:
            replay = _GIT_QUERY_REPLAY.get()
            if replay is not None and _guard.cache_path in replay.stores:
                self.git_dir = _guard.cache_path
                self._objects_dir = self.git_dir / "objects"
                self._semantic_store_path = replay.stores[_guard.cache_path]
                return
            git_dir = _guard._git_dir_path
            self.git_dir = git_dir
            self._objects_dir = git_dir / "objects"
            capture = _GIT_QUERY_CAPTURE.get()
            if capture is not None:
                try:
                    self._semantic_store_path = capture.stores[_guard.cache_path]
                except KeyError:
                    raise ValueError(
                        "semantic Git query used an undeclared store"
                    ) from None
            else:
                self._semantic_store_path = None
            probe = _run_text(
                git_dir,
                "rev-parse",
                "--is-bare-repository",
                inherited_directory_fd=self._inherited_directory_fd,
            )
            if probe.returncode != 0 or probe.stdout.strip() != "true":
                raise FileNotFoundError(provided_path)
            return
        try:
            git_dir = provided_path.resolve(strict=True)
        except FileNotFoundError:
            raise FileNotFoundError(provided_path) from None
        replay = _GIT_QUERY_REPLAY.get()
        if replay is not None and git_dir in replay.stores:
            self.git_dir = git_dir
            self._objects_dir = git_dir / "objects"
            self._semantic_store_path = replay.stores[git_dir]
            return
        if (
            not git_dir.is_dir()
            or not (git_dir / "objects").is_dir()
            or not (git_dir / "HEAD").is_file()
        ):
            raise FileNotFoundError(git_dir)

        probe = _run_text(git_dir, "rev-parse", "--is-bare-repository")
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            raise FileNotFoundError(git_dir)
        self.git_dir = git_dir
        self._objects_dir = (git_dir / "objects").resolve(strict=True)
        capture = _GIT_QUERY_CAPTURE.get()
        if capture is not None:
            try:
                self._semantic_store_path = capture.stores[git_dir]
            except KeyError:
                raise ValueError("semantic Git query used an undeclared store") from None
        else:
            self._semantic_store_path = None

    def close(self) -> None:
        guard = getattr(self, "_guard", None)
        if guard is not None:
            self._closed = True
            self._inherited_directory_fd = None
            self._guard = None
            guard.close()

    def __enter__(self) -> "GitObjectStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _semantic_query(
        self,
        operation: str,
        arguments: tuple[str | int, ...],
        execute: Callable[[], _QueryResult],
    ) -> _QueryResult:
        if self._closed:
            raise ValueError("Git object store is closed")
        replay = _GIT_QUERY_REPLAY.get()
        store_path = self._semantic_store_path
        if replay is not None:
            if store_path is None:
                raise RuntimeError("semantic Git replay store is unbound")
            key = _query_key(store_path, operation, arguments)
            try:
                entry = replay.entries[key]
            except KeyError:
                raise RuntimeError("semantic Git query was not captured") from None
            return _decoded_query_result(entry)  # type: ignore[return-value]

        capture = _GIT_QUERY_CAPTURE.get()
        try:
            if self._guard is None:
                result: _QueryResult | BaseException = execute()
            else:
                with self._guard.query():
                    result = execute()
        except GitCacheIntegrityError:
            raise
        except (FileNotFoundError, RuntimeError, ValueError) as error:
            result = error
        if capture is not None:
            if store_path is None:
                raise RuntimeError("semantic Git capture store is unbound")
            key = _query_key(store_path, operation, arguments)
            if key not in capture.seen:
                capture.entries.append(
                    _encoded_query_result(
                        store_path=store_path,
                        operation=operation,
                        arguments=arguments,
                        result=result,
                    )
                )
                capture.seen.add(key)
        if isinstance(result, BaseException):
            raise result
        return result

    validate_path = staticmethod(validate_path)

    def _is_commit(self, commit: str) -> str:
        safe_commit = _validate_commit(commit)
        result = _run_text(
            self.git_dir,
            "cat-file",
            "-t",
            safe_commit,
            inherited_directory_fd=self._inherited_directory_fd,
        )
        if result.returncode != 0 or result.stdout.strip() != "commit":
            raise ValueError("commit must identify a commit object")
        return safe_commit

    def _is_commit_for_diff(
        self, commit: str, git_dir: Path, alternate_objects: Path
    ) -> str:
        """Validate a diff endpoint with a bounded commit-type probe."""

        safe_commit = _validate_commit(commit)
        try:
            payload = _read_limited(
                git_dir,
                ("cat-file", "-t", safe_commit),
                _GIT_METADATA_MAX_BYTES,
                alternate_objects=alternate_objects,
                inherited_directory_fd=self._inherited_directory_fd,
            )
        except (FileNotFoundError, ValueError):
            raise ValueError("commit must identify a commit object") from None
        if (
            b"\x00" in payload
            or any(len(line) > _GIT_METADATA_MAX_BYTES for line in payload.splitlines())
            or payload.decode("utf-8", errors="replace").strip() != "commit"
        ):
            raise ValueError("commit must identify a commit object")
        return safe_commit

    def _expression(self, commit: str, path: str) -> tuple[str, str]:
        safe_commit = self._is_commit(commit)
        safe_path = validate_path(path)
        return f"{safe_commit}:{safe_path}", safe_path

    def canonical_diff(self, old_commit: str, new_commit: str) -> bytes:
        """Return one bounded canonical diff between two exact commit objects."""

        def execute() -> bytes:
            with _isolated_bare_shell() as git_dir:
                safe_old = self._is_commit_for_diff(
                    old_commit, git_dir, self._objects_dir
                )
                safe_new = self._is_commit_for_diff(
                    new_commit, git_dir, self._objects_dir
                )
                arguments = (
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--binary",
                    "--full-index",
                    "--no-color",
                    safe_old,
                    safe_new,
                    "--",
                )
                try:
                    return _read_limited(
                        git_dir,
                        arguments,
                        _CANONICAL_DIFF_MAX_BYTES,
                        alternate_objects=self._objects_dir,
                        inherited_directory_fd=self._inherited_directory_fd,
                    )
                except ValueError:
                    raise ValueError(
                        "canonical Git diff exceeds bounded input limit"
                    ) from None
                except FileNotFoundError:
                    raise RuntimeError("canonical Git diff failed") from None

        return self._semantic_query(
            "canonical_diff", (old_commit, new_commit), execute
        )

    def _is_blob(self, expression: str) -> bool:
        # cat-file -e is deliberately the existence check; -t excludes trees.
        if _run_text(
            self.git_dir,
            "cat-file",
            "-e",
            expression,
            inherited_directory_fd=self._inherited_directory_fd,
        ).returncode != 0:
            return False
        kind = _run_text(
            self.git_dir,
            "cat-file",
            "-t",
            expression,
            inherited_directory_fd=self._inherited_directory_fd,
        )
        return kind.returncode == 0 and kind.stdout.strip() == "blob"

    def contains(self, commit: str, path: str) -> bool:
        """Return whether *path* names a blob in this exact 40-hex commit."""

        def execute() -> bool:
            expression, _ = self._expression(commit, path)
            return self._is_blob(expression)

        return self._semantic_query("contains", (commit, path), execute)

    def read_bytes(self, commit: str, path: str, max_bytes: int = 1_000_000) -> bytes:
        """Read a pinned blob, rejecting content larger than *max_bytes*."""

        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive integer")

        def execute() -> bytes:
            expression, safe_path = self._expression(commit, path)
            if not self._is_blob(expression):
                raise FileNotFoundError(f"repository blob not found: {safe_path}")

            size_result = _run_text(
                self.git_dir,
                "cat-file",
                "-s",
                expression,
                inherited_directory_fd=self._inherited_directory_fd,
            )
            try:
                object_size = (
                    int(size_result.stdout.strip())
                    if size_result.returncode == 0
                    else -1
                )
            except ValueError:
                object_size = -1
            if object_size < 0:
                raise FileNotFoundError(f"repository blob not found: {safe_path}")
            if object_size > max_bytes:
                raise ValueError(f"file exceeds limit {max_bytes} bytes: {safe_path}")

            try:
                return _read_limited(
                    self.git_dir,
                    ("show", expression),
                    object_size,
                    inherited_directory_fd=self._inherited_directory_fd,
                )
            except ValueError:
                raise ValueError(
                    f"file exceeds limit {max_bytes} bytes: {safe_path}"
                ) from None
            except FileNotFoundError:
                raise FileNotFoundError(
                    f"repository blob not found: {safe_path}"
                ) from None

        return self._semantic_query(
            "read_bytes", (commit, path, max_bytes), execute
        )

    def read_text(self, commit: str, path: str, max_bytes: int = 1_000_000) -> str:
        """Read a pinned blob as UTF-8 with malformed sequences replaced."""

        return self.read_bytes(commit, path, max_bytes=max_bytes).decode("utf-8", errors="replace")
