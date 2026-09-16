"""POSIX directory-fd anchored output trees and cross-process batch locks."""

from __future__ import annotations

import contextvars
import fcntl
import json
import os
import secrets
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Callable


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCK_NAME = ".egsi-batch.lock"


def _absolute(path: Path) -> Path:
    value = Path(path).absolute()
    if not value.is_absolute():
        raise ValueError("path must be absolute")
    return value


def _open_tree_from(start_fd: int, parts: tuple[str, ...], *, create: bool) -> int:
    current_fd = os.dup(start_fd)
    try:
        for component in parts:
            if component in {"", ".", ".."} or "/" in component:
                raise ValueError("unsafe directory component")
            try:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(next_fd)
                raise ValueError("output ancestor must be a real directory")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


class BatchLock:
    """Exclusive lock whose directory fd is also the transaction filesystem anchor."""

    def __init__(self, output_root: Path) -> None:
        self.path = _absolute(output_root)
        self.root_fd: int | None = None
        self.lock_fd: int | None = None
        self._context_token: contextvars.Token[BatchLock | None] | None = None

    def open_relative_directory(self, parts: tuple[str, ...], *, create: bool = True) -> int:
        if self.root_fd is None:
            raise RuntimeError("batch lock is not active")
        return _open_tree_from(self.root_fd, parts, create=create)

    def __enter__(self) -> "BatchLock":
        if os.name != "posix":
            raise ValueError("secure batch locks require POSIX")
        self.root_fd = open_directory_fd(self.path, create=True, ignore_active=True)
        try:
            try:
                before = os.stat(_LOCK_NAME, dir_fd=self.root_fd, follow_symlinks=False)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ValueError("batch lock must be a single-link regular file")
            except FileNotFoundError:
                before = None
            self.lock_fd = os.open(
                _LOCK_NAME,
                os.O_RDWR
                | os.O_CREAT
                | os.O_NONBLOCK
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=self.root_fd,
            )
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("batch lock must be a single-link regular file")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
            observed = os.stat(_LOCK_NAME, dir_fd=self.root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or (observed.st_dev, observed.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ValueError("batch lock identity changed while acquiring")
            self._context_token = _ACTIVE_BATCH.set(self)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        if self._context_token is not None:
            _ACTIVE_BATCH.reset(self._context_token)
            self._context_token = None
        if self.lock_fd is not None:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self.lock_fd)
                self.lock_fd = None
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None


_ACTIVE_BATCH: contextvars.ContextVar[BatchLock | None] = contextvars.ContextVar(
    "egsi_active_batch_lock", default=None
)


def active_batch_lock(output_root: Path) -> BatchLock | None:
    active = _ACTIVE_BATCH.get()
    if active is not None and active.path == _absolute(output_root):
        return active
    return None


def open_directory_fd(
    path: Path,
    *,
    create: bool = True,
    ignore_active: bool = False,
) -> int:
    """Open/create a directory path without following any component."""

    if os.name != "posix":
        raise ValueError("secure directory anchors require POSIX")
    absolute = _absolute(path)
    if not ignore_active:
        active = _ACTIVE_BATCH.get()
        if active is not None:
            try:
                relative = absolute.relative_to(active.path)
            except ValueError:
                pass
            else:
                return active.open_relative_directory(relative.parts, create=create)
    anchor_fd = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        return _open_tree_from(anchor_fd, absolute.parts[1:], create=create)
    finally:
        os.close(anchor_fd)


def _relative_parts(value: Path) -> tuple[str, ...]:
    pure = PurePosixPath(value.as_posix())
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("artifact path must be a safe relative path")
    return pure.parts


class AnchoredDirectory:
    """Hold one output directory fd for an entire read/write lifecycle."""

    def __init__(
        self,
        path: Path,
        *,
        subdirectories: tuple[str, ...] = (),
        create: bool = True,
    ) -> None:
        self.path = _absolute(path)
        self.root_fd = open_directory_fd(self.path, create=create)
        self._subdirectories: dict[str, int] = {}
        try:
            for name in subdirectories:
                parts = _relative_parts(Path(name))
                if len(parts) != 1:
                    raise ValueError("anchored subdirectory must have one component")
                self._subdirectories[name] = _open_tree_from(
                    self.root_fd, (name,), create=create
                )
        except Exception:
            self.close()
            raise

    @classmethod
    def from_fd(cls, path: Path, root_fd: int) -> "AnchoredDirectory":
        """Adopt a duplicate of an already-open directory anchor."""

        info = os.fstat(root_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("anchored descriptor must name a directory")
        instance = cls.__new__(cls)
        instance.path = _absolute(path)
        instance.root_fd = os.dup(root_fd)
        instance._subdirectories = {}
        return instance

    def close(self) -> None:
        for fd in self._subdirectories.values():
            os.close(fd)
        self._subdirectories.clear()
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1

    def __enter__(self) -> "AnchoredDirectory":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        self.close()

    def relative(self, path: Path) -> Path:
        try:
            relative = _absolute(path).relative_to(self.path)
        except ValueError:
            raise ValueError("artifact path escapes anchored directory") from None
        _relative_parts(relative)
        if len(relative.parts) > 2:
            raise ValueError("artifact path is too deep for anchored directory")
        return relative

    def _parent(self, relative: Path) -> tuple[int, str]:
        parts = _relative_parts(relative)
        if len(parts) == 1:
            return self.root_fd, parts[0]
        if len(parts) == 2 and parts[0] in self._subdirectories:
            return self._subdirectories[parts[0]], parts[1]
        raise ValueError("artifact parent is not anchored")

    @staticmethod
    def _safe_stat(parent_fd: int, name: str) -> os.stat_result | None:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("artifact must be a single-link regular file")
        return info

    def read_regular(self, relative: Path, *, limit: int) -> bytes:
        parent_fd, name = self._parent(relative)
        before = self._safe_stat(parent_fd, name)
        if before is None or before.st_size > limit:
            if before is None:
                raise FileNotFoundError(name)
            raise OverflowError
        fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
        try:
            observed = os.fstat(fd)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or observed.st_size > limit
                or (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ValueError("artifact identity changed during read")
            chunks: list[bytes] = []
            remaining = observed.st_size
            while remaining:
                chunk = os.read(fd, min(1_048_576, remaining))
                if not chunk:
                    raise ValueError("artifact truncated during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def exists_regular(self, relative: Path) -> bool:
        parent_fd, name = self._parent(relative)
        return self._safe_stat(parent_fd, name) is not None

    def stat_regular(self, relative: Path) -> os.stat_result:
        parent_fd, name = self._parent(relative)
        info = self._safe_stat(parent_fd, name)
        if info is None:
            raise FileNotFoundError(name)
        return info

    def unlink_regular(self, relative: Path, *, missing_ok: bool = True) -> None:
        parent_fd, name = self._parent(relative)
        info = self._safe_stat(parent_fd, name)
        if info is None:
            if missing_ok:
                return
            raise FileNotFoundError(name)
        os.unlink(name, dir_fd=parent_fd)
        try:
            os.fsync(parent_fd)
        except OSError:
            pass

    def atomic_bytes(
        self,
        relative: Path,
        raw: bytes,
        *,
        limit: int,
        verifier: Callable[[bytes], None] | None = None,
    ) -> None:
        if len(raw) > limit:
            raise ValueError("artifact exceeds write limit")
        parent_fd, name = self._parent(relative)
        before = self._safe_stat(parent_fd, name)
        previous = None if before is None else self.read_regular(relative, limit=limit)

        def token(info: os.stat_result | None) -> tuple[int, int, int, int] | None:
            if info is None:
                return None
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

        before_token = token(before)
        temporary = f".{name}.{secrets.token_hex(16)}.tmp"
        created = False
        try:
            fd = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            if verifier is not None:
                verifier(raw)
            if token(self._safe_stat(parent_fd, name)) != before_token:
                raise RuntimeError("fatal: atomic destination changed before replace")
            try:
                os.replace(
                    temporary,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            except OSError:
                try:
                    observed = self.read_regular(relative, limit=limit)
                except FileNotFoundError:
                    observed = None
                except (OSError, ValueError, OverflowError):
                    raise RuntimeError(
                        "fatal: atomic replace outcome is ambiguous"
                    ) from None
                if observed == raw:
                    # The rename committed even though its reporting layer
                    # raised.  The anchored destination content is decisive.
                    created = False
                elif observed == previous:
                    raise
                else:
                    raise RuntimeError(
                        "fatal: atomic replace outcome is ambiguous"
                    ) from None
            else:
                created = False
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
        finally:
            if created:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

    def atomic_json(self, relative: Path, value: dict[str, Any], *, limit: int) -> None:
        raw = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        self.atomic_bytes(relative, raw, limit=limit)

    def quarantine(
        self,
        source: Path,
        destination: Path,
    ) -> None:
        source_parent, source_name = self._parent(source)
        destination_parent, destination_name = self._parent(destination)
        self._safe_stat(source_parent, source_name)
        if self._safe_stat(destination_parent, destination_name) is not None:
            destination_name = f"{destination_name}.{os.getpid()}.{secrets.token_hex(4)}"
        os.replace(
            source_name,
            destination_name,
            src_dir_fd=source_parent,
            dst_dir_fd=destination_parent,
        )
        try:
            os.fsync(source_parent)
            if destination_parent != source_parent:
                os.fsync(destination_parent)
        except OSError:
            pass

    def list_regular(self, relative_directory: str = "") -> list[str]:
        fd = self.root_fd if not relative_directory else self._subdirectories[relative_directory]
        result: list[str] = []
        for name in os.listdir(fd):
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                result.append(name)
            elif (
                not relative_directory
                and name in self._subdirectories
                and stat.S_ISDIR(info.st_mode)
            ):
                continue
            elif name != _LOCK_NAME:
                raise ValueError("anchored output contains an unsafe entry")
        return sorted(result)
