"""Deterministic disk cache for non-authoritative teacher responses."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
from typing import TypeAlias

from pydantic import ValidationError

from .base import Teacher, TeacherRequest, TeacherResponse


def cache_key(
    provider: str,
    model: str,
    request: TeacherRequest,
    *,
    provenance: str | None = None,
) -> str:
    """Return a stable key for one provider/model/request tuple."""

    if provenance is not None and (
        type(provenance) is not str
        or not provenance.startswith("sha256:")
        or len(provenance) != 71
        or any(character not in "0123456789abcdef" for character in provenance[7:])
    ):
        raise ValueError("cache provenance must be a SHA-256 commitment")
    value = {
        "provider": provider,
        "model": model,
        "request": request.model_dump(mode="json"),
    }
    if provenance is not None:
        value["provenance"] = provenance
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


request_cache_key = cache_key


_MAX_CACHE_ENTRY_BYTES = 2 * 1_024 * 1_024
_READ_RACE_ATTEMPTS = 3
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FileToken: TypeAlias = tuple[int, int, int, int, int, int, int]


class _RetryableCacheRace(Exception):
    """One safe regular entry was atomically replaced before it could be opened."""


def _require_secure_posix() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NONBLOCK")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
    ):
        raise OSError("secure teacher cache requires POSIX dir_fd support")


def _open_directory(directory: Path, *, create: bool) -> int | None:
    """Open/create every cache-directory component without following links."""

    _require_secure_posix()
    absolute = Path(directory).absolute()
    if not absolute.is_absolute() or any(part in {"", ".", ".."} for part in absolute.parts[1:]):
        raise OSError("invalid cache directory")
    current_fd: int | None = None
    try:
        current_fd = os.open(absolute.anchor, _DIRECTORY_FLAGS)
        for component in absolute.parts[1:]:
            try:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    os.close(current_fd)
                    return None
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    # A concurrent creator is acceptable only if the anchored,
                    # no-follow open below proves it created a real directory.
                    pass
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(next_fd)
                raise OSError("cache component is not a directory")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
        raise


def _file_token(info: os.stat_result) -> _FileToken:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _validate_cache_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 0
        or info.st_size > _MAX_CACHE_ENTRY_BYTES
    ):
        raise OSError("cache entry is not an unambiguous bounded regular file")


def _read_entry_once_at(directory_fd: int, name: str) -> tuple[bytes | None, _FileToken | None]:
    try:
        expected = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    _validate_cache_file(expected)
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        raise _RetryableCacheRace from None
    try:
        before = os.fstat(descriptor)
        _validate_cache_file(before)
        if _file_identity(expected) != _file_identity(before):
            raise _RetryableCacheRace
        if _file_token(expected) != _file_token(before):
            raise OSError("cache entry metadata changed before bounded read")
        chunks: list[bytes] = []
        remaining = _MAX_CACHE_ENTRY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        _validate_cache_file(after)
        if (
            len(raw) > _MAX_CACHE_ENTRY_BYTES
            or len(raw) != after.st_size
            or _file_token(before) != _file_token(after)
        ):
            raise OSError("cache entry changed during bounded read")
        return raw, _file_token(after)
    finally:
        os.close(descriptor)


def _read_entry_at(directory_fd: int, name: str) -> tuple[bytes | None, _FileToken | None]:
    """Read an anchored entry with bounded retries for atomic-replace races only."""

    for attempt in range(_READ_RACE_ATTEMPTS):
        try:
            return _read_entry_once_at(directory_fd, name)
        except _RetryableCacheRace:
            if attempt + 1 == _READ_RACE_ATTEMPTS:
                raise OSError("cache entry remained unstable") from None
    raise AssertionError("bounded cache retry loop must return or raise")


def _destination_token_at(directory_fd: int, name: str) -> _FileToken | None:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _validate_cache_file(info)
    return _file_token(info)


def _unlink_temporary_at(directory_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        pass


def _serialized_response(response: TeacherResponse) -> bytes:
    response = TeacherResponse.model_validate(response.model_dump(mode="json"))
    raw = json.dumps(
        response.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(raw) > _MAX_CACHE_ENTRY_BYTES:
        raise ValueError("cache response is too large")
    return raw


def _atomic_write_at(directory_fd: int, name: str, raw: bytes) -> None:
    """Atomically write within one anchored directory descriptor."""

    previous, previous_token = _read_entry_at(directory_fd, name)
    temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(temporary_name, _WRITE_FLAGS, 0o600, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("temporary cache entry is unsafe")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

        temporary_raw, _ = _read_entry_at(directory_fd, temporary_name)
        if temporary_raw != raw:
            raise OSError("temporary cache verification failed")
        if _destination_token_at(directory_fd, name) != previous_token:
            raise OSError("cache destination changed before replace")

        try:
            os.replace(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        except Exception as replace_error:
            observed, _ = _read_entry_at(directory_fd, name)
            if observed == raw:
                # Covers both a post-commit error and an idempotent pre-commit
                # failure when the prior entry already had the desired bytes.
                _unlink_temporary_at(directory_fd, temporary_name)
                temporary_name = ""
            elif observed == previous:
                raise replace_error
            else:
                raise RuntimeError("ambiguous teacher cache replace") from None
        else:
            temporary_name = ""

        committed, _ = _read_entry_at(directory_fd, name)
        if committed != raw:
            raise OSError("committed cache verification failed")
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            _unlink_temporary_at(directory_fd, temporary_name)


class TeacherCache:
    """A small filesystem cache whose entries are validated before use."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)

    def path_for(self, key: str) -> Path:
        digest = key.removeprefix("sha256:")
        if not key.startswith("sha256:") or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid teacher cache key")
        return self.directory / f"{digest}.json"

    def read(self, key: str) -> TeacherResponse | None:
        name = self.path_for(key).name
        directory_fd: int | None = None
        try:
            directory_fd = _open_directory(self.directory, create=False)
            if directory_fd is None:
                return None
            raw, _ = _read_entry_at(directory_fd, name)
            if raw is None:
                return None
            data = json.loads(raw.decode("utf-8"))
            response = TeacherResponse.model_validate(data)
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, TypeError, ValueError):
            raise RuntimeError("teacher cache invalid") from None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
        return response.model_copy(update={"cached": True})

    def write(self, key: str, response: TeacherResponse) -> None:
        name = self.path_for(key).name
        directory_fd: int | None = None
        try:
            raw = _serialized_response(response)
            directory_fd = _open_directory(self.directory, create=True)
            if directory_fd is None:  # create=True cannot legitimately return None.
                raise OSError("cache directory could not be created")
            _atomic_write_at(directory_fd, name, raw)
        except Exception:
            raise RuntimeError("teacher cache write failed") from None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)


class CachedTeacher:
    """Wrap a teacher and persist successful normalized responses by request key."""

    def __init__(self, teacher: Teacher, cache: TeacherCache | Path | str) -> None:
        self._teacher = teacher
        self._cache = cache if isinstance(cache, TeacherCache) else TeacherCache(cache)

    @property
    def provider(self) -> str:
        return self._teacher.provider

    @property
    def model(self) -> str:
        return self._teacher.model

    @property
    def requested_model(self) -> str:
        """The configured request alias used in the cache key."""

        return self._teacher.model

    @property
    def cache_provenance(self) -> str | None:
        """Bind local-executable teachers to their verified binary identity."""

        value = getattr(self._teacher, "cache_identity", None)
        return value if type(value) is str else None

    @property
    def effective_max_retries(self) -> int | None:
        """Expose the validated adapter retry count without exposing secrets."""

        config = getattr(self._teacher, "config", None)
        value = getattr(config, "max_retries", None)
        return value if type(value) is int and 0 <= value <= 10 else None

    @property
    def effective_timeout_seconds(self) -> float | None:
        """Expose the validated adapter timeout used by one provider slot."""

        config = getattr(self._teacher, "config", None)
        value = getattr(config, "timeout_seconds", None)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            return None
        return float(value)

    def _validate_requested_identity(self, response: TeacherResponse) -> None:
        if (
            response.provider != self.provider
            or response.model != self.model
            or response.requested_model != self.model
        ):
            raise RuntimeError("teacher cache provenance mismatch")

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        key = cache_key(
            self.provider,
            self.model,
            request,
            provenance=self.cache_provenance,
        )
        cached = self._cache.read(key)
        if cached is not None:
            self._validate_requested_identity(cached)
            return cached
        response = self._teacher.generate(request)
        self._validate_requested_identity(response)
        self._cache.write(key, response)
        return response

    def close(self) -> None:
        """Forward shutdown to the wrapped teacher when it supports shutdown."""

        close = getattr(self._teacher, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "CachedTeacher":
        enter = getattr(self._teacher, "__enter__", None)
        if callable(enter):
            enter()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        exit_method = getattr(self._teacher, "__exit__", None)
        if callable(exit_method):
            return bool(exit_method(exc_type, exc, traceback))
        self.close()
        return False


def read_cache(root: Path | str, key: str) -> TeacherResponse | None:
    """Read one validated response from a cache root."""

    return TeacherCache(root).read(key)


def write_cache(root: Path | str, key: str, value: TeacherResponse) -> Path:
    """Atomically write one response to a cache root and return its final path."""

    cache = TeacherCache(root)
    cache.write(key, value)
    return cache.path_for(key)
