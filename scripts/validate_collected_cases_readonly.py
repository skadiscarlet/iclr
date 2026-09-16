#!/usr/bin/env python3
"""Run collection validation in an isolated, writable CoW/copy snapshot."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


_FICLONE = 0x40049409
_MAX_DEPTH = 32
_MAX_ENTRIES = 100_000
_SNAPSHOT_TOP_LEVEL = ("artifacts", "catalog", "scripts")


class _CloneState:
    def __init__(self) -> None:
        self.entries = 0
        self.directories: set[tuple[int, int]] = set()

    def charge(self) -> None:
        self.entries += 1
        if self.entries > _MAX_ENTRIES:
            raise ValueError("snapshot entry limit exceeded")


def _same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _copy_bytes(source_fd: int, destination_fd: int) -> None:
    while True:
        chunk = os.read(source_fd, 1_048_576)
        if not chunk:
            return
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise OSError("snapshot copy made no progress")
            view = view[written:]


def _clone_regular(source: Path, destination: Path, state: _CloneState) -> None:
    state.charge()
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    destination_fd: int | None = None
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"unsafe source data entry: {source.name}")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            fcntl.ioctl(destination_fd, _FICLONE, source_fd)
        except OSError as error:
            if error.errno not in {
                errno.EXDEV,
                errno.EINVAL,
                errno.ENOTTY,
                errno.EOPNOTSUPP,
                errno.ENOSYS,
            }:
                raise
            os.ftruncate(destination_fd, 0)
            os.lseek(destination_fd, 0, os.SEEK_SET)
            os.lseek(source_fd, 0, os.SEEK_SET)
            _copy_bytes(source_fd, destination_fd)
        os.fchmod(destination_fd, stat.S_IMODE(before.st_mode))
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        if not _same_identity(before, after):
            raise ValueError("source data changed while snapshotting")
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)
    os.utime(
        destination,
        ns=(before.st_atime_ns, before.st_mtime_ns),
        follow_symlinks=False,
    )


def _clone_directory(
    source: Path,
    destination: Path,
    state: _CloneState,
    *,
    depth: int,
) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError("snapshot directory depth limit exceeded")
    state.charge()
    before = source.lstat()
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ValueError(f"unsafe source data entry: {source.name}")
    identity = (before.st_dev, before.st_ino)
    if identity in state.directories:
        raise ValueError("snapshot directory cycle or alias detected")
    state.directories.add(identity)
    destination.mkdir(mode=0o700)
    with os.scandir(source) as iterator:
        entries = sorted(iterator, key=lambda entry: entry.name)
    for entry in entries:
        child_source = source / entry.name
        child_destination = destination / entry.name
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"unsafe source data entry: {entry.name}")
        if stat.S_ISDIR(info.st_mode):
            _clone_directory(
                child_source,
                child_destination,
                state,
                depth=depth + 1,
            )
        elif stat.S_ISREG(info.st_mode):
            _clone_regular(child_source, child_destination, state)
        else:
            raise ValueError(f"unsafe source data entry: {entry.name}")
    after = source.lstat()
    if not _same_identity(before, after):
        raise ValueError("source data changed while snapshotting")
    os.chmod(destination, stat.S_IMODE(before.st_mode))
    os.utime(
        destination,
        ns=(before.st_atime_ns, before.st_mtime_ns),
        follow_symlinks=False,
    )


def _validate_top_level(source_data: Path) -> dict[str, os.stat_result]:
    entries: dict[str, os.stat_result] = {}
    with os.scandir(source_data) as iterator:
        for entry in iterator:
            info = entry.stat(follow_symlinks=False)
            if (
                not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or stat.S_ISLNK(info.st_mode)
            ):
                raise ValueError(f"unsafe source data entry: {entry.name}")
            entries[entry.name] = info
    for required in ("catalog", "scripts"):
        info = entries.get(required)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"required source data entry is unavailable: {required}")
    reports = entries.get("reports")
    if reports is not None and not stat.S_ISDIR(reports.st_mode):
        raise ValueError("source reports entry is not a directory")
    return entries


def _build_snapshot(source_data: Path, shadow_data: Path) -> None:
    entries = _validate_top_level(source_data)
    shadow_data.mkdir(mode=0o700)
    state = _CloneState()
    for name in _SNAPSHOT_TOP_LEVEL:
        info = entries.get(name)
        if info is None:
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"required snapshot entry is not a directory: {name}")
        _clone_directory(source_data / name, shadow_data / name, state, depth=0)
    (shadow_data / "reports").mkdir(mode=0o700)


def run_readonly(repo_root: Path) -> int:
    """Execute the shadow validator; no shadow file aliases a source inode."""

    root = Path(repo_root).resolve(strict=True)
    source_data = (root / "data").resolve(strict=True)
    if not source_data.is_dir():
        raise ValueError("source data directory is unavailable")
    source_validator = source_data / "scripts/validate_collected_cases.py"
    validator_mode = source_validator.lstat().st_mode
    if stat.S_ISLNK(validator_mode) or not stat.S_ISREG(validator_mode):
        raise ValueError("collection validator is not a regular file")

    # The shadow must not be a descendant of the repository: otherwise an
    # untrusted validator can escape upward to the repository's ``data`` link.
    with tempfile.TemporaryDirectory(
        prefix="egsi-collection-validation-"
    ) as directory:
        shadow_root = Path(directory)
        shadow_data = shadow_root / "data"
        _build_snapshot(source_data, shadow_data)
        validator = shadow_data / "scripts/validate_collected_cases.py"
        shadow_scripts = str(shadow_data / "scripts")
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": shadow_scripts,
            "PWD": str(shadow_root),
            "HOME": str(shadow_root),
            "TMPDIR": str(shadow_root),
            "PYTHONHASHSEED": "0",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        result = subprocess.run(
            [sys.executable, str(validator)],
            cwd=shadow_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode


def main() -> int:
    return run_readonly(Path(__file__).resolve().parents[1])


if __name__ == "__main__":
    raise SystemExit(main())
