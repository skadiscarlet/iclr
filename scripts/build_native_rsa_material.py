#!/usr/bin/env python3
"""Maintenance-only RSA material/header and public build-record builder."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ALGORITHM = "rsa-2048-sha256-pkcs1-v1_5"
ATTESTATION_VERSION = "2"
CONTRACT_DOMAIN = b"EGSI_NATIVE_BINARY_CONTRACT_V4\0"
BUILD_DOMAIN = b"EGSI_NATIVE_BUILD_ID_V2\0"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPILER_FLAGS = [
    "-std=c11", "-Os", "-static", "-nostdlib", "-nostartfiles",
    "-nodefaultlibs", "-ffreestanding", "-fno-builtin",
    "-fno-stack-protector", "-fno-pie", "-no-pie",
    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-Wl,--build-id=none", "-Wl,-z,noexecstack",
    "-Wl,--fatal-warnings", "-s",
]
ELF_CONTRACT = {
    "elf_class": "ELF64",
    "elf_data": "little-endian",
    "elf_type": "ET_EXEC",
    "machine": "EM_X86_64",
    "pt_interp": False,
    "pt_dynamic": False,
    "dt_needed_count": 0,
    "static": True,
}
PYTHON_RUNTIME_SCHEMA = "3.0"
PYTHON_RUNTIME_INVOCATION = "glibc-loader-fd-preload-v2"
MAX_RUNTIME_FILES = 256
MAX_RUNTIME_DEPTH = 16
MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_TOTAL_BYTES = 512 * 1024 * 1024
STARTUP_CODE_SCHEMA = "2.0"
STARTUP_CODE_STRATEGY = "source-tree-no-bytecode-native-closure-v2"
STARTUP_CODE_PYCACHE_PREFIX = "/nonexistent/egsi-locked-pycache"
MAX_STARTUP_CODE_FILES = 4096
MAX_STARTUP_CODE_DIRECTORIES = 1024
MAX_STARTUP_CODE_ABSENT_PATHS = 16
MAX_STARTUP_CODE_FILE_BYTES = 4 * 1024 * 1024
MAX_STARTUP_CODE_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_LIBRARY_DIRECTORIES = (
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/lib",
    "/lib64",
    "/lib/x86_64-linux-gnu",
)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _commitment(value: dict[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return _sha256(_canonical(copy))


def _write_private(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short maintenance write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _u32_words(value: int) -> list[int]:
    if value < 0 or value.bit_length() > 2048:
        raise ValueError("RSA value does not fit 2048 bits")
    return [(value >> (32 * index)) & 0xFFFFFFFF for index in range(64)]


def _word_macro(name: str, words: list[int]) -> str:
    body = ",".join(f"0x{word:08x}U" for word in words)
    return f"#define {name} {{{body}}}\n"


def _byte_macro(name: str, raw: bytes) -> str:
    body = ",".join(f"0x{value:02x}" for value in raw)
    return f"#define {name} {{{body}}}\n"


def _c_string(value: str) -> str:
    if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-+" for character in value):
        raise ValueError(
            f"native build path contains unsupported characters: {value}"
        )
    return json.dumps(value)


def _load_or_generate_private_key(path: Path | None) -> rsa.RSAPrivateKey:
    if path is None:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if not path.is_absolute():
        raise ValueError("synthetic private key path must be absolute")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > 64 * 1024
    ):
        raise ValueError("synthetic private key file is unsafe")
    raw = path.read_bytes()
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError("synthetic private key changed during read")
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("synthetic key is not RSA")
    return key


def _safe_regular_bytes(path: Path, *, limit: int) -> tuple[bytes, os.stat_result]:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size <= 0
        or before.st_size > limit
    ):
        raise ValueError("native build input is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise ValueError("native build input changed before read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("native build input was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("native build input grew during read")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_nlink,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise ValueError("native build input changed during read")
    finally:
        os.close(descriptor)
    return b"".join(chunks), after


def _safe_startup_regular_bytes(
    path: Path, *, limit: int = MAX_STARTUP_CODE_FILE_BYTES
) -> tuple[bytes, os.stat_result]:
    """Read an immutable startup-code file, including legitimate empty .py files."""
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size < 0
        or before.st_size > limit
    ):
        raise ValueError("Python startup code file is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        expected = (
            before.st_dev, before.st_ino, before.st_nlink, before.st_mode,
            before.st_uid, before.st_gid, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        if (
            opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_mode,
            opened.st_uid, opened.st_gid, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        ) != expected:
            raise ValueError("Python startup code changed before read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("Python startup code was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("Python startup code grew during read")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_nlink, after.st_mode,
            after.st_uid, after.st_gid, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ) != expected:
            raise ValueError("Python startup code changed during read")
    finally:
        os.close(descriptor)
    return b"".join(chunks), after


def _identity(path: Path, raw: bytes, info: os.stat_result) -> dict[str, Any]:
    return {
        "path": str(path),
        "type": "regular",
        "mode": stat.S_IMODE(info.st_mode),
        "device": info.st_dev,
        "inode": info.st_ino,
        "links": info.st_nlink,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "sha256": _sha256(raw),
    }


def _directory_identity(path: Path) -> tuple[dict[str, Any], tuple[int, ...]]:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("Python startup code directory is unsafe")
    snapshot = (
        info.st_dev, info.st_ino, info.st_nlink, info.st_mode,
        info.st_uid, info.st_gid, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )
    return (
        {
            "path": str(path),
            "type": "directory",
            "mode": stat.S_IMODE(info.st_mode),
            "device": info.st_dev,
            "inode": info.st_ino,
            "links": info.st_nlink,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns,
            "sha256": None,
        },
        snapshot,
    )


def _cstring(raw: bytes, offset: int, size: int) -> str:
    if offset < 0 or offset >= size:
        raise ValueError("ELF dynamic string offset is invalid")
    end = raw.find(b"\0", offset, size)
    if end < 0:
        raise ValueError("ELF dynamic string is unterminated")
    value = raw[offset:end].decode("utf-8", "strict")
    if not value or "\0" in value or any(ord(character) < 33 for character in value):
        raise ValueError("ELF dynamic string is invalid")
    return value


def _parse_elf64(raw: bytes, *, require_interpreter: bool) -> dict[str, Any]:
    if len(raw) < 64:
        raise ValueError("Python runtime ELF header is truncated")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw, 0)
    ident = header[0]
    elf_type, machine = header[1], header[2]
    program_offset, program_entry_size, program_count = header[5], header[9], header[10]
    if (
        ident[:4] != b"\x7fELF"
        or ident[4] != 2
        or ident[5] != 1
        or ident[6] != 1
        or elf_type not in {2, 3}
        or machine != 62
        or program_entry_size != 56
        or not 1 <= program_count <= 128
        or program_offset < 64
        or program_offset + program_entry_size * program_count > len(raw)
    ):
        raise ValueError("Python runtime ELF contract is unsupported")
    loads: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter: str | None = None
    for index in range(program_count):
        values = struct.unpack_from(
            "<IIQQQQQQ", raw, program_offset + index * program_entry_size
        )
        kind, offset, virtual, file_size = values[0], values[2], values[3], values[5]
        if offset + file_size > len(raw):
            raise ValueError("Python runtime ELF segment is out of bounds")
        if kind == 1:
            loads.append((virtual, offset, file_size))
        elif kind == 2:
            if dynamic is not None:
                raise ValueError("Python runtime has duplicate PT_DYNAMIC")
            dynamic = (offset, file_size)
        elif kind == 3:
            if interpreter is not None or file_size < 2 or file_size > 4096:
                raise ValueError("Python runtime has invalid PT_INTERP")
            segment = raw[offset : offset + file_size]
            if not segment.endswith(b"\0") or b"\0" in segment[:-1]:
                raise ValueError("Python runtime PT_INTERP is not canonical")
            interpreter = segment[:-1].decode("utf-8", "strict")
            if not interpreter.startswith("/") or Path(interpreter).as_posix() != interpreter:
                raise ValueError("Python runtime PT_INTERP path is invalid")
    if not loads or dynamic is None or (require_interpreter and interpreter is None):
        raise ValueError("Python runtime ELF is missing its dynamic contract")
    tags: dict[int, list[int]] = {}
    dynamic_offset, dynamic_size = dynamic
    if dynamic_size % 16 or dynamic_size > 64 * 1024:
        raise ValueError("Python runtime dynamic table is invalid")
    terminated = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        tag, value = struct.unpack_from("<qQ", raw, offset)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    if not terminated or len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1:
        raise ValueError("Python runtime dynamic strings are invalid")
    string_vaddr = tags[5][0]
    string_size = tags[10][0]
    if not 1 <= string_size <= 1024 * 1024:
        raise ValueError("Python runtime dynamic string table is oversized")
    string_offset: int | None = None
    for virtual, offset, file_size in loads:
        if virtual <= string_vaddr and string_vaddr + string_size <= virtual + file_size:
            translated = offset + (string_vaddr - virtual)
            if string_offset is not None and translated != string_offset:
                raise ValueError("Python runtime string table mapping is ambiguous")
            string_offset = translated
    if string_offset is None or string_offset + string_size > len(raw):
        raise ValueError("Python runtime string table is unmapped")
    strings = raw[string_offset : string_offset + string_size]
    needed = [_cstring(strings, value, len(strings)) for value in tags.get(1, [])]
    if len(needed) != len(set(needed)):
        raise ValueError("Python runtime has duplicate DT_NEEDED entries")
    if any("/" in name or name in {".", ".."} for name in needed):
        raise ValueError("Python runtime dependency name is unsafe")
    soname_values = tags.get(14, [])
    if len(soname_values) > 1:
        raise ValueError("Python runtime has duplicate DT_SONAME entries")
    soname = (
        _cstring(strings, soname_values[0], len(strings))
        if soname_values else None
    )
    if soname is not None and (
        "/" in soname or soname in {".", ".."}
    ):
        raise ValueError("Python runtime SONAME is unsafe")

    def paths(tag: int) -> list[str]:
        values = tags.get(tag, [])
        if len(values) > 1:
            raise ValueError("Python runtime has duplicate search-path tags")
        if not values:
            return []
        result = _cstring(strings, values[0], len(strings)).split(":")
        if not result or any(not item for item in result):
            raise ValueError("Python runtime search path is invalid")
        return result

    runpath = paths(29)
    rpath = paths(15)
    if runpath and rpath:
        raise ValueError("Python runtime has both RPATH and RUNPATH")
    return {
        "elf_class": "ELF64",
        "elf_data": "little-endian",
        "elf_type": "ET_EXEC" if elf_type == 2 else "ET_DYN",
        "machine": "EM_X86_64",
        "pt_interp": interpreter,
        "dt_needed": needed,
        "dt_soname": soname,
        "dt_runpath": runpath,
        "dt_rpath": rpath,
    }


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _search_directories(elf: dict[str, Any], origin: Path) -> list[Path]:
    raw_paths = elf["dt_runpath"] or elf["dt_rpath"]
    result: list[Path] = []
    for raw in raw_paths:
        if "$" in raw:
            replaced = raw.replace("${ORIGIN}", "$ORIGIN")
            if replaced.count("$ORIGIN") != 1 or not replaced.startswith("$ORIGIN"):
                raise ValueError("Python runtime uses an unsupported loader token")
            suffix = replaced[len("$ORIGIN") :]
            if suffix and not suffix.startswith("/"):
                raise ValueError("Python runtime ORIGIN expansion is invalid")
            candidate = Path(os.path.normpath(str(origin) + suffix))
            if not _is_relative_to(candidate, origin):
                raise ValueError("Python runtime ORIGIN expansion escapes its directory")
        else:
            candidate = Path(raw)
            if not candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError("Python runtime search path is not absolute")
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            continue
        info = resolved.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("Python runtime search directory is unsafe")
        if resolved not in result:
            result.append(resolved)
    for raw in DEFAULT_LIBRARY_DIRECTORIES:
        try:
            resolved = Path(raw).resolve(strict=True)
        except FileNotFoundError:
            continue
        if resolved not in result:
            result.append(resolved)
    return result


def _runtime_file(path: Path, *, role: str, needed_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = path.resolve(strict=True)
    if not resolved.is_absolute() or not stat.S_ISREG(resolved.lstat().st_mode):
        raise ValueError("Python runtime dependency path is unsafe")
    raw, info = _safe_regular_bytes(resolved, limit=MAX_RUNTIME_FILE_BYTES)
    elf = _parse_elf64(raw, require_interpreter=False)
    identity = _identity(resolved, raw, info)
    return (
        {
            "role": role,
            "needed_name": needed_name,
            "path": str(resolved),
            "mode": identity["mode"],
            "size": identity["size"],
            "device": identity["device"],
            "inode": identity["inode"],
            "sha256": identity["sha256"],
            "identity": identity,
            "elf": elf,
        },
        elf,
    )


def _resolve_needed(name: str, elf: dict[str, Any], origin: Path) -> Path:
    matches: set[Path] = set()
    system_directories = {
        Path(raw).resolve(strict=True)
        for raw in DEFAULT_LIBRARY_DIRECTORIES
        if Path(raw).exists()
    }
    for directory in _search_directories(elf, origin):
        candidate = directory / name
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            continue
        # Distribution SONAME aliases in immutable shared-library directories
        # are resolved once and the regular target is pinned/preloaded by FD.
        # Private RUNPATH/RPATH aliases remain forbidden.
        if candidate.is_symlink() and directory not in system_directories:
            raise ValueError("Python runtime dependency final path is a symlink")
        if resolved.parent != directory:
            raise ValueError("Python runtime dependency escapes its search directory")
        raw, _ = _safe_regular_bytes(resolved, limit=MAX_RUNTIME_FILE_BYTES)
        target = _parse_elf64(raw, require_interpreter=False)
        if target["dt_soname"] is None:
            raise ValueError(
                f"Python runtime dependency has no DT_SONAME: {name}"
            )
        if target["dt_soname"] != name:
            raise ValueError(
                f"Python runtime dependency DT_SONAME mismatch: {name}"
            )
        matches.add(resolved)
    if not matches:
        raise ValueError(f"Python runtime dependency is missing: {name}")
    if len(matches) != 1:
        raise ValueError(f"Python runtime dependency name is ambiguous: {name}")
    return matches.pop()


def _target_stdlib_root(
    interpreter_path: Path,
    interpreter_raw: bytes,
    files: list[dict[str, Any]],
) -> tuple[Path, str]:
    matches = [
        item for item in files
        if re.fullmatch(r"libpython(\d+\.\d+)\.so(?:\..*)?", item["needed_name"])
    ]
    if len(matches) != 1:
        raise ValueError("Python runtime has no unique libpython dependency")
    libpython = matches[0]
    version_match = re.fullmatch(
        r"libpython(\d+\.\d+)\.so(?:\..*)?", libpython["needed_name"]
    )
    assert version_match is not None
    version = version_match.group(1)
    libpython_path = Path(libpython["path"])
    libpython_raw, _ = _safe_regular_bytes(
        libpython_path, limit=MAX_RUNTIME_FILE_BYTES
    )
    direct = libpython_path.parent / f"python{version}"
    candidates = {direct}
    for raw in (interpreter_raw, libpython_raw):
        for match in re.findall(rb"/[A-Za-z0-9_./-]{1,900}", raw):
            try:
                text = match.decode("ascii", "strict")
            except UnicodeDecodeError:
                continue
            base = Path(text)
            candidates.add(base / "lib" / f"python{version}")
            if base.name == "lib":
                candidates.add(base / f"python{version}")
            if base.name == f"python{version}":
                candidates.add(base)
    valid: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError):
            continue
        if (
            resolved.is_dir()
            and not resolved.is_symlink()
            and (resolved / "encodings/__init__.py").is_file()
            and (resolved / "os.py").is_file()
        ):
            valid.add(resolved)
    try:
        direct_resolved = direct.resolve(strict=True)
    except (FileNotFoundError, OSError):
        direct_resolved = None
    if direct_resolved in valid:
        return direct_resolved, version
    if len(valid) != 1:
        raise ValueError("Python runtime stdlib root is ambiguous")
    return valid.pop(), version


def _ancestor_chain_contract(path: Path) -> list[dict[str, Any]]:
    """Bind every raw directory component without resolving symlink aliases."""

    if not path.is_absolute() or str(path) != path.as_posix():
        raise ValueError("Python import root is not canonical")
    parts = path.parts
    if not parts or parts[0] != "/" or any(
        part in {"", ".", ".."} for part in parts[1:]
    ):
        raise ValueError("Python import root is not canonical")
    chain: list[dict[str, Any]] = []
    current = Path("/")
    for index, component in enumerate(("/", *parts[1:])):
        if index:
            current = current / component
        before = current.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise ValueError("Python import root has a symlink component")
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("Python import root component is not a directory")
        identity = {
            "path": str(current),
            "type": "directory",
            "mode": stat.S_IMODE(before.st_mode),
            "device": before.st_dev,
            "inode": before.st_ino,
            "links": before.st_nlink,
            "uid": before.st_uid,
            "gid": before.st_gid,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "sha256": None,
        }
        after = current.lstat()
        if (
            before.st_dev, before.st_ino, before.st_nlink, before.st_mode,
            before.st_uid, before.st_gid, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_nlink, after.st_mode,
            after.st_uid, after.st_gid, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise ValueError("Python import root changed during ancestor scan")
        chain.append({"path": str(current), "identity": identity})
    return chain


def _raw_compiled_prefix(
    interpreter_raw: bytes,
    runtime_files: list[dict[str, Any]],
    stdlib_root: Path,
    version: str,
) -> Path:
    libpython = next(
        item for item in runtime_files
        if re.fullmatch(
            r"libpython\d+\.\d+\.so(?:\..*)?", item["needed_name"]
        )
    )
    libpython_raw, _ = _safe_regular_bytes(
        Path(libpython["path"]), limit=MAX_RUNTIME_FILE_BYTES
    )
    prefixes: set[Path] = set()
    for raw in (interpreter_raw, libpython_raw):
        for match in re.findall(rb"/[A-Za-z0-9_./-]{1,900}", raw):
            try:
                base = Path(match.decode("ascii", "strict"))
            except UnicodeDecodeError:
                continue
            candidates = [(base, base / "lib" / f"python{version}")]
            if base.name == "lib":
                candidates.append((base.parent, base / f"python{version}"))
            if base.name == f"python{version}":
                candidates.append((base.parent.parent, base))
            for prefix, candidate in candidates:
                try:
                    resolved = candidate.resolve(strict=True)
                except (FileNotFoundError, OSError):
                    continue
                if resolved == stdlib_root:
                    # Validate the raw prefix before canonicalization can erase
                    # a compiled-prefix symlink alias.
                    _ancestor_chain_contract(prefix)
                    _ancestor_chain_contract(candidate)
                    prefixes.add(prefix)
    if len(prefixes) != 1:
        raise ValueError("Python runtime raw compiled prefix is ambiguous")
    return prefixes.pop()


def _import_root_contract(
    path: Path, *, resolved_path: Path | None = None
) -> dict[str, Any]:
    chain = _ancestor_chain_contract(path)
    resolved = path.resolve(strict=True)
    if resolved_path is not None and resolved != resolved_path:
        raise ValueError("Python import root does not resolve to its pinned root")
    return {
        "raw_path": str(path),
        "resolved_path": str(resolved),
        "ancestor_chain": chain,
    }


def _site_packages_roots(
    interpreter_path: Path, version: str
) -> list[Path]:
    runner = interpreter_path.parent.parent
    candidate = runner / "lib" / f"python{version}" / "site-packages"
    if not candidate.exists() and not candidate.is_symlink():
        return []
    info = candidate.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("locked site-packages root is unsafe")
    _ancestor_chain_contract(candidate)
    return [candidate]


def _native_extension_roots(
    lib_dynload_root: Path, site_packages_roots: list[Path]
) -> list[dict[str, str]]:
    roots: list[dict[str, str]] = []

    def consider(path: Path, source: str) -> None:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("Python native extension closure contains a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Python native extension closure contains a special node")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            magic = os.read(descriptor, 4)
        finally:
            os.close(descriptor)
        if magic == b"\x7fELF":
            roots.append({"path": str(path), "source": source})

    for child in sorted(lib_dynload_root.iterdir(), key=lambda item: item.name):
        consider(child, "lib-dynload")
    for site_root in site_packages_roots:
        for current, names, filenames in os.walk(site_root, followlinks=False):
            current_path = Path(current)
            kept: list[str] = []
            for name in sorted(names):
                child = current_path / name
                info = child.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise ValueError(
                        "locked site-packages contains an unsafe directory"
                    )
                kept.append(name)
            names[:] = kept
            for name in sorted(filenames):
                consider(current_path / name, "site-packages")
    if not roots:
        raise ValueError("Python native extension root set is empty")
    return sorted(roots, key=lambda item: (item["source"], item["path"]))


def _python_startup_code_contract(
    root: Path,
    interpreter_path: Path,
    interpreter_raw: bytes,
    runtime_files: list[dict[str, Any]],
) -> dict[str, Any]:
    stdlib_root, version = _target_stdlib_root(
        interpreter_path, interpreter_raw, runtime_files
    )
    compiled_prefix = _raw_compiled_prefix(
        interpreter_raw, runtime_files, stdlib_root, version
    )
    lib_dynload_root = stdlib_root / "lib-dynload"
    if not lib_dynload_root.is_dir() or lib_dynload_root.is_symlink():
        raise ValueError("Python runtime lib-dynload root is unsafe")

    excluded = {
        "site-packages", "__pycache__", "lib-dynload",
        f"config-{version}-x86_64-linux-gnu",
    }
    file_specs: list[tuple[str, Path]] = []
    directory_specs: dict[Path, str] = {}

    for current, names, filenames in os.walk(stdlib_root, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for name in sorted(names):
            child = current_path / name
            if name in excluded:
                continue
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("Python startup code directory entry is unsafe")
            kept.append(name)
        names[:] = kept
        relative_dir = current_path.relative_to(stdlib_root).as_posix()
        directory_specs[current_path] = (
            "stdlib:." if relative_dir == "." else f"stdlib:{relative_dir}"
        )
        for name in sorted(filenames):
            child = current_path / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("Python startup code symlink is forbidden")
            if name.endswith(".pyc"):
                raise ValueError("legacy Python bytecode is forbidden")
            if name.endswith(".py"):
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("Python startup source is not regular")
                relative = child.relative_to(stdlib_root).as_posix()
                file_specs.append((f"stdlib:{relative}", child))

    directory_specs[lib_dynload_root] = "lib-dynload:."
    for child in sorted(lib_dynload_root.iterdir(), key=lambda item: item.name):
        info = child.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("Python lib-dynload entry is unsafe")
        file_specs.append((f"lib-dynload:{child.name}", child))

    runner_prefix = interpreter_path.parent.parent
    runner_lib = runner_prefix / "lib"
    runner_stdlib = runner_lib / f"python{version}"
    site_packages_roots = _site_packages_roots(interpreter_path, version)
    pyvenv = runner_prefix / "pyvenv.cfg"
    base_zip = stdlib_root.parent / f"python{version.replace('.', '')}.zip"
    runner_zip = runner_lib / f"python{version.replace('.', '')}.zip"
    absent_paths: list[Path] = []
    pycache_prefix = Path(STARTUP_CODE_PYCACHE_PREFIX)
    if pycache_prefix.exists() or pycache_prefix.is_symlink():
        raise ValueError("pinned Python pycache prefix must remain absent")
    absent_paths.append(pycache_prefix)

    if pyvenv.exists() or pyvenv.is_symlink():
        file_specs.append(("runner:pyvenv.cfg", pyvenv))
    else:
        absent_paths.append(pyvenv)
    if runner_stdlib.exists() or runner_stdlib.is_symlink():
        info = runner_stdlib.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("runner shadow stdlib root is unsafe")
        directory_specs[runner_stdlib] = "runner:stdlib-root"
        for landmark in (runner_stdlib / "os.py", runner_stdlib / "encodings"):
            if landmark.exists() or landmark.is_symlink():
                raise ValueError("runner shadow stdlib landmark is forbidden")
    else:
        absent_paths.append(runner_stdlib)
    for candidate in (base_zip, runner_zip):
        if candidate.exists() or candidate.is_symlink():
            raise ValueError("Python startup zip path is forbidden")
        absent_paths.append(candidate)

    for path in absent_paths:
        parent = path.parent
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError("Python absent startup path has no safe parent")
        if parent != Path("/"):
            directory_specs.setdefault(
                parent, f"absent-parent:{parent.as_posix()}"
            )
    directory_specs.setdefault(stdlib_root.parent, "stdlib-parent:.")
    directory_specs.setdefault(runner_prefix, "runner:prefix")
    if runner_lib.is_dir() and not runner_lib.is_symlink():
        directory_specs.setdefault(runner_lib, "runner:lib")

    if not 1 <= len(file_specs) <= MAX_STARTUP_CODE_FILES:
        raise ValueError("Python startup code file count exceeds its bound")
    if not 1 <= len(directory_specs) <= MAX_STARTUP_CODE_DIRECTORIES:
        raise ValueError("Python startup code directory count exceeds its bound")
    if not 1 <= len(absent_paths) <= MAX_STARTUP_CODE_ABSENT_PATHS:
        raise ValueError("Python startup absent path count exceeds its bound")

    files: list[dict[str, Any]] = []
    total_bytes = 0
    for relative_path, path in sorted(file_specs, key=lambda item: item[0]):
        raw, info = _safe_startup_regular_bytes(path)
        total_bytes += len(raw)
        if total_bytes > MAX_STARTUP_CODE_TOTAL_BYTES:
            raise ValueError("Python startup code bytes exceed their bound")
        files.append({
            "relative_path": relative_path,
            "path": str(path),
            "identity": _identity(path, raw, info),
        })

    directories: list[dict[str, Any]] = []
    directory_snapshots: list[tuple[Path, tuple[int, ...]]] = []
    for path, relative_path in sorted(
        directory_specs.items(), key=lambda item: (item[1], str(item[0]))
    ):
        identity, snapshot = _directory_identity(path)
        directories.append({
            "relative_path": relative_path,
            "path": str(path),
            "identity": identity,
        })
        directory_snapshots.append((path, snapshot))
    for path, expected in directory_snapshots:
        _, observed = _directory_identity(path)
        if observed != expected:
            raise ValueError("Python startup code directory changed during scan")

    value: dict[str, Any] = {
        "schema_version": STARTUP_CODE_SCHEMA,
        "strategy": STARTUP_CODE_STRATEGY,
        "pycache_prefix": STARTUP_CODE_PYCACHE_PREFIX,
        "stdlib_root": str(stdlib_root),
        "lib_dynload_root": str(lib_dynload_root),
        "import_roots": {
            "compiled_prefix": _import_root_contract(compiled_prefix),
            "stdlib_root": _import_root_contract(
                compiled_prefix / "lib" / f"python{version}",
                resolved_path=stdlib_root,
            ),
            "lib_dynload_root": _import_root_contract(
                compiled_prefix / "lib" / f"python{version}" / "lib-dynload",
                resolved_path=lib_dynload_root,
            ),
            "site_packages_roots": [
                _import_root_contract(path) for path in site_packages_roots
            ],
            "expected_isolated_state": {
                "sys_path": [
                    str(compiled_prefix / "lib" / f"python{version.replace('.', '')}.zip"),
                    str(compiled_prefix / "lib" / f"python{version}"),
                    str(compiled_prefix / "lib" / f"python{version}" / "lib-dynload"),
                ],
                "sys_prefix": str(compiled_prefix),
                "sys_base_prefix": str(compiled_prefix),
            },
        },
        "files": files,
        "directories": directories,
        "absent_paths": sorted(str(path) for path in set(absent_paths)),
        "file_count": len(files),
        "directory_count": len(directories),
        "absent_path_count": len(set(absent_paths)),
        "total_bytes": total_bytes,
        "limits": {
            "max_files": MAX_STARTUP_CODE_FILES,
            "max_directories": MAX_STARTUP_CODE_DIRECTORIES,
            "max_absent_paths": MAX_STARTUP_CODE_ABSENT_PATHS,
            "max_file_bytes": MAX_STARTUP_CODE_FILE_BYTES,
            "max_total_bytes": MAX_STARTUP_CODE_TOTAL_BYTES,
        },
        "closure_sha256": "sha256:" + "0" * 64,
    }
    value["closure_sha256"] = _commitment(value, "closure_sha256")
    return value


def _runtime_preload_indices(files: list[dict[str, Any]]) -> list[int]:
    """Build a dependency-first preload plan without duplicate SONAME maps."""

    if len(files) < 2 or files[0].get("role") != "loader":
        raise ValueError("Python runtime preload plan has no loader closure")
    loader_name = files[0]["needed_name"]
    selected: list[int] = []
    by_soname: dict[str, int] = {loader_name: 0}
    for index, item in enumerate(files[1:], start=1):
        soname = item["elf"]["dt_soname"]
        if soname is not None:
            previous = by_soname.get(soname)
            if previous is not None:
                if files[previous]["sha256"] != item["sha256"]:
                    raise ValueError(
                        "Python runtime has conflicting SONAME aliases"
                    )
                # Keep the alias FD pinned, but do not map or initialize the
                # exact same ELF image a second time through glibc --preload.
                continue
            by_soname[soname] = index
        selected.append(index)

    positions = {
        file_index: position
        for position, file_index in enumerate(selected)
    }
    for file_index in selected:
        item = files[file_index]
        for needed_name in item["elf"]["dt_needed"]:
            if needed_name == loader_name:
                continue
            dependency_index = by_soname.get(needed_name)
            if (
                dependency_index is None
                or dependency_index not in positions
                or positions[dependency_index] >= positions[file_index]
            ):
                raise ValueError(
                    "Python runtime preload plan is not dependency-first"
                )
    if not selected:
        raise ValueError("Python runtime preload plan is empty")
    return selected


def _python_runtime_contract(root: Path) -> dict[str, Any]:
    interpreter_path = root / ".work/offline-test-runner-venv/bin/python"
    raw, info = _safe_regular_bytes(interpreter_path, limit=MAX_RUNTIME_FILE_BYTES)
    interpreter_elf = _parse_elf64(raw, require_interpreter=True)
    interpreter_identity = _identity(interpreter_path, raw, info)
    interp_raw = interpreter_elf["pt_interp"]
    assert isinstance(interp_raw, str)
    loader_resolved = Path(interp_raw).resolve(strict=True)
    loader, loader_elf = _runtime_file(
        loader_resolved, role="loader", needed_name=Path(interp_raw).name
    )
    files: list[dict[str, Any]] = [loader]
    by_path: dict[str, dict[str, Any]] = {loader["path"]: loader}
    by_name: dict[str, str] = {loader["needed_name"]: loader["path"]}
    visiting: set[str] = set()
    total_bytes = info.st_size + loader["size"]

    def visit(parent_path: Path, elf: dict[str, Any], depth: int) -> None:
        nonlocal total_bytes
        if depth > MAX_RUNTIME_DEPTH:
            raise ValueError("Python runtime dependency depth exceeds its bound")
        parent_key = str(parent_path)
        if parent_key in visiting:
            raise ValueError("Python runtime dependency cycle is forbidden")
        visiting.add(parent_key)
        try:
            for name in elf["dt_needed"]:
                # The PT_INTERP loader is already the active object.  glibc's
                # libc may name that same loader in DT_NEEDED even when the
                # interpreter contract pins it at a non-default path; reuse
                # the active loader instead of resolving and preloading a
                # second ld-linux image.
                resolved = (
                    Path(loader["path"])
                    if name == loader["needed_name"]
                    else _resolve_needed(name, elf, parent_path.parent)
                )
                key = str(resolved)
                if name in by_name and by_name[name] != key:
                    raise ValueError("Python runtime dependency name is ambiguous")
                by_name[name] = key
                if key in visiting:
                    raise ValueError("Python runtime dependency cycle is forbidden")
                if key in by_path:
                    continue
                if len(files) >= MAX_RUNTIME_FILES:
                    raise ValueError("Python runtime file count exceeds its bound")
                item, child_elf = _runtime_file(
                    resolved, role="dependency", needed_name=name
                )
                total_bytes += item["size"]
                if total_bytes > MAX_RUNTIME_TOTAL_BYTES:
                    raise ValueError("Python runtime bytes exceed their bound")
                visit(resolved, child_elf, depth + 1)
                # Post-order insertion is the executable preload contract:
                # every dependency precedes the object that needs it.
                files.append(item)
                by_path[key] = item
        finally:
            visiting.remove(parent_key)

    visit(interpreter_path, interpreter_elf, 0)
    # The loader is invoked directly, so its own dynamic requirements must also
    # be part of the same held closure even when the current glibc loader has none.
    visit(Path(loader["path"]), loader_elf, 0)
    interpreter = {
        "path": str(interpreter_path),
        "mode": interpreter_identity["mode"],
        "size": interpreter_identity["size"],
        "device": interpreter_identity["device"],
        "inode": interpreter_identity["inode"],
        "sha256": interpreter_identity["sha256"],
        "identity": interpreter_identity,
        "elf": interpreter_elf,
        "loader_path": loader["path"],
    }
    startup_code = _python_startup_code_contract(
        root, interpreter_path, raw, files
    )
    extension_roots = _native_extension_roots(
        Path(startup_code["lib_dynload_root"]),
        [
            Path(item["raw_path"])
            for item in startup_code["import_roots"]["site_packages_roots"]
        ],
    )
    for root_item in extension_roots:
        extension_path = Path(root_item["path"])
        key = str(extension_path.resolve(strict=True))
        if key in visiting:
            raise ValueError("Python runtime dependency cycle is forbidden")
        if key not in by_path:
            if len(files) >= MAX_RUNTIME_FILES:
                raise ValueError("Python runtime file count exceeds its bound")
            item, extension_elf = _runtime_file(
                extension_path,
                role="extension-root",
                needed_name=extension_path.name,
            )
            total_bytes += item["size"]
            if total_bytes > MAX_RUNTIME_TOTAL_BYTES:
                raise ValueError("Python runtime bytes exceed their bound")
            visit(extension_path, extension_elf, 0)
            files.append(item)
            by_path[key] = item
        root_item["file_index"] = files.index(by_path[key])
    preload_file_indices = _runtime_preload_indices(files)
    value: dict[str, Any] = {
        "schema_version": PYTHON_RUNTIME_SCHEMA,
        "invocation": PYTHON_RUNTIME_INVOCATION,
        "interpreter": interpreter,
        "files": files,
        "preload_file_indices": preload_file_indices,
        "native_extension_roots": extension_roots,
        "startup_code": startup_code,
        "limits": {
            "max_files": MAX_RUNTIME_FILES,
            "max_depth": MAX_RUNTIME_DEPTH,
            "max_file_bytes": MAX_RUNTIME_FILE_BYTES,
            "max_total_bytes": MAX_RUNTIME_TOTAL_BYTES,
        },
        "closure_sha256": "sha256:" + "0" * 64,
    }
    value["closure_sha256"] = _commitment(value, "closure_sha256")
    return value


def _runtime_entry_initializer(item: dict[str, Any]) -> str:
    identity = item["identity"]
    digest = bytes.fromhex(item["sha256"].removeprefix("sha256:"))
    mtime_s, mtime_ns = divmod(identity["mtime_ns"], 1_000_000_000)
    ctime_s, ctime_ns = divmod(identity["ctime_ns"], 1_000_000_000)
    return (
        "{" + _c_string(item["path"]) + ","
        + "{.device=" + str(identity["device"]) + "UL,.inode=" + str(identity["inode"]) + "UL,.links=" + str(identity["links"]) + "UL,.mode=" + str(identity["mode"] | stat.S_IFREG) + "U,.uid=" + str(identity["uid"]) + "U,.gid=" + str(identity["gid"]) + "U,.size=" + str(identity["size"]) + "L,.modification_time={" + str(mtime_s) + "L," + str(mtime_ns) + "L},.change_time={" + str(ctime_s) + "L," + str(ctime_ns) + "L}},"
        + "{" + ",".join(f"0x{byte:02x}" for byte in digest) + "}}"
    )


def _runtime_entries_macro(runtime: dict[str, Any]) -> str:
    entries = [runtime["interpreter"], *runtime["files"]]
    return "#define EGSI_PYTHON_RUNTIME_ENTRIES {" + ",".join(
        _runtime_entry_initializer(item) for item in entries
    ) + "}\n"


def _runtime_preload_indices_macro(runtime: dict[str, Any]) -> str:
    return "#define EGSI_PYTHON_RUNTIME_PRELOAD_INDICES {" + ",".join(
        f"{index}U" for index in runtime["preload_file_indices"]
    ) + "}\n"


def _startup_file_initializer(item: dict[str, Any]) -> str:
    identity = item["identity"]
    digest = bytes.fromhex(identity["sha256"].removeprefix("sha256:"))
    mtime_s, mtime_ns = divmod(identity["mtime_ns"], 1_000_000_000)
    ctime_s, ctime_ns = divmod(identity["ctime_ns"], 1_000_000_000)
    return (
        "{" + _c_string(item["path"]) + ","
        + "{.device=" + str(identity["device"]) + "UL,.inode=" + str(identity["inode"]) + "UL,.links=" + str(identity["links"]) + "UL,.mode=" + str(identity["mode"] | stat.S_IFREG) + "U,.uid=" + str(identity["uid"]) + "U,.gid=" + str(identity["gid"]) + "U,.size=" + str(identity["size"]) + "L,.modification_time={" + str(mtime_s) + "L," + str(mtime_ns) + "L},.change_time={" + str(ctime_s) + "L," + str(ctime_ns) + "L}},"
        + "{" + ",".join(f"0x{byte:02x}" for byte in digest) + "}}"
    )


def _startup_directory_initializer(item: dict[str, Any]) -> str:
    identity = item["identity"]
    mtime_s, mtime_ns = divmod(identity["mtime_ns"], 1_000_000_000)
    ctime_s, ctime_ns = divmod(identity["ctime_ns"], 1_000_000_000)
    return (
        "{" + _c_string(item["path"]) + ","
        + "{.device=" + str(identity["device"]) + "UL,.inode=" + str(identity["inode"]) + "UL,.links=" + str(identity["links"]) + "UL,.mode=" + str(identity["mode"] | stat.S_IFDIR) + "U,.uid=" + str(identity["uid"]) + "U,.gid=" + str(identity["gid"]) + "U,.size=" + str(identity["size"]) + "L,.modification_time={" + str(mtime_s) + "L," + str(mtime_ns) + "L},.change_time={" + str(ctime_s) + "L," + str(ctime_ns) + "L}}}"
    )


def _directory_identity_initializer(identity: dict[str, Any]) -> str:
    mtime_s, mtime_ns = divmod(identity["mtime_ns"], 1_000_000_000)
    ctime_s, ctime_ns = divmod(identity["ctime_ns"], 1_000_000_000)
    return (
        "{.device=" + str(identity["device"]) + "UL,.inode="
        + str(identity["inode"]) + "UL,.links=" + str(identity["links"])
        + "UL,.mode=" + str(identity["mode"] | stat.S_IFDIR)
        + "U,.uid=" + str(identity["uid"]) + "U,.gid="
        + str(identity["gid"]) + "U,.size=" + str(identity["size"])
        + "L,.modification_time={" + str(mtime_s) + "L,"
        + str(mtime_ns) + "L},.change_time={" + str(ctime_s)
        + "L," + str(ctime_ns) + "L}}"
    )


def _import_root_values(startup: dict[str, Any]) -> list[dict[str, Any]]:
    roots = startup["import_roots"]
    return [
        roots["compiled_prefix"],
        roots["stdlib_root"],
        roots["lib_dynload_root"],
        *roots["site_packages_roots"],
    ]


def _import_roots_macro(startup: dict[str, Any]) -> str:
    values = []
    for root in _import_root_values(startup):
        identities = ",".join(
            _directory_identity_initializer(item["identity"])
            for item in root["ancestor_chain"]
        )
        values.append(
            "{" + _c_string(root["raw_path"]) + ","
            + str(len(root["ancestor_chain"])) + "U,{" + identities + "}}"
        )
    return "#define EGSI_IMPORT_ROOTS {" + ",".join(values) + "}\n"


def _startup_files_macro(startup: dict[str, Any]) -> str:
    return "#define EGSI_STARTUP_CODE_FILES {" + ",".join(
        _startup_file_initializer(item) for item in startup["files"]
    ) + "}\n"


def _startup_directories_macro(startup: dict[str, Any]) -> str:
    return "#define EGSI_STARTUP_CODE_DIRECTORIES {" + ",".join(
        _startup_directory_initializer(item) for item in startup["directories"]
    ) + "}\n"


def _startup_absent_paths_macro(startup: dict[str, Any]) -> str:
    return "#define EGSI_STARTUP_CODE_ABSENT_PATHS {" + ",".join(
        _c_string(path) for path in startup["absent_paths"]
    ) + "}\n"


def _material(arguments: argparse.Namespace) -> None:
    root = arguments.root.resolve(strict=True)
    source = (root / "scripts/locked_launcher.c").resolve(strict=True)
    bootstrap = (root / "scripts/locked_runtime_bootstrap.py").resolve(strict=True)
    bootstrap_raw, bootstrap_info = _safe_regular_bytes(
        bootstrap, limit=1024 * 1024
    )
    bootstrap_sha_raw = hashlib.sha256(bootstrap_raw).digest()
    bootstrap_mode = stat.S_IMODE(bootstrap_info.st_mode)
    bootstrap_size = len(bootstrap_raw)
    python_runtime = _python_runtime_contract(root)
    runtime_commitment_raw = bytes.fromhex(
        python_runtime["closure_sha256"].removeprefix("sha256:")
    )
    startup_code = python_runtime["startup_code"]
    startup_commitment_raw = bytes.fromhex(
        startup_code["closure_sha256"].removeprefix("sha256:")
    )
    private_key = _load_or_generate_private_key(arguments.test_private_key_pem)
    numbers = private_key.private_numbers()
    public = numbers.public_numbers
    if private_key.key_size != 2048 or public.e != 65537:
        raise ValueError("native signer requires RSA-2048 exponent 65537")
    modulus = public.n
    modulus_words = _u32_words(modulus)
    private_words = _u32_words(numbers.d)
    rr_words = _u32_words(pow(2, 4096, modulus))
    n0_inv = (-pow(modulus_words[0], -1, 1 << 32)) & 0xFFFFFFFF
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id_raw = hashlib.sha256(spki).digest()
    source_sha_raw = hashlib.sha256(source.read_bytes()).digest()
    build_id_raw = hashlib.sha256(
        BUILD_DOMAIN
        + spki
        + str(root).encode("utf-8", "strict")
        + b"\0"
        + source_sha_raw
        + bootstrap_sha_raw
        + bootstrap_size.to_bytes(8, "big")
        + bootstrap_mode.to_bytes(4, "big")
        + runtime_commitment_raw
    ).digest()
    contract_raw = hashlib.sha256(
        CONTRACT_DOMAIN
        + key_id_raw
        + build_id_raw
        + ALGORITHM.encode("ascii")
        + b"\0"
        + bootstrap_sha_raw
        + bootstrap_size.to_bytes(8, "big")
        + bootstrap_mode.to_bytes(4, "big")
        + runtime_commitment_raw
    ).digest()
    common = "".join(
        (
            _word_macro("EGSI_RSA_MODULUS_WORDS", modulus_words),
            _word_macro("EGSI_RSA_RR_WORDS", rr_words),
            f"#define EGSI_RSA_N0_INV 0x{n0_inv:08x}U\n",
            _byte_macro("EGSI_NATIVE_KEY_ID_BYTES", key_id_raw),
            _byte_macro("EGSI_NATIVE_BUILD_ID_BYTES", build_id_raw),
            _byte_macro("EGSI_NATIVE_CONTRACT_BYTES", contract_raw),
            _byte_macro("EGSI_BOOTSTRAP_SHA256_BYTES", bootstrap_sha_raw),
            _byte_macro("EGSI_PYTHON_SHA256_BYTES", bytes.fromhex(
                python_runtime["interpreter"]["sha256"].removeprefix("sha256:")
            )),
            _byte_macro("EGSI_PYTHON_RUNTIME_CLOSURE_BYTES", runtime_commitment_raw),
            _byte_macro("EGSI_STARTUP_CODE_CLOSURE_BYTES", startup_commitment_raw),
            f"#define EGSI_BOOTSTRAP_SIZE {bootstrap_size}UL\n",
            f"#define EGSI_BOOTSTRAP_MODE 0{bootstrap_mode:03o}U\n",
            f"#define EGSI_PYTHON_SIZE {python_runtime['interpreter']['size']}UL\n",
            f"#define EGSI_PYTHON_MODE 0{python_runtime['interpreter']['mode']:03o}U\n",
            f"#define EGSI_PYTHON_DEVICE {python_runtime['interpreter']['device']}UL\n",
            f"#define EGSI_PYTHON_INODE {python_runtime['interpreter']['inode']}UL\n",
            f"#define EGSI_PYTHON_RUNTIME_FILE_COUNT {len(python_runtime['files'])}U\n",
            f"#define EGSI_PYTHON_RUNTIME_ENTRY_COUNT {len(python_runtime['files']) + 1}U\n",
            f"#define EGSI_PYTHON_RUNTIME_PRELOAD_COUNT {len(python_runtime['preload_file_indices'])}U\n",
            "#define EGSI_PYTHON_INTERPRETER_INDEX 0U\n",
            "#define EGSI_PYTHON_LOADER_INDEX 1U\n",
            _runtime_entries_macro(python_runtime),
            _runtime_preload_indices_macro(python_runtime),
            f"#define EGSI_IMPORT_ROOT_COUNT {len(_import_root_values(startup_code))}U\n",
            _import_roots_macro(startup_code),
            f"#define EGSI_STARTUP_CODE_FILE_COUNT {startup_code['file_count']}U\n",
            f"#define EGSI_STARTUP_CODE_DIRECTORY_COUNT {startup_code['directory_count']}U\n",
            f"#define EGSI_STARTUP_CODE_ABSENT_COUNT {startup_code['absent_path_count']}U\n",
            f"#define EGSI_STARTUP_CODE_TOTAL_BYTES {startup_code['total_bytes']}UL\n",
            f"#define EGSI_STARTUP_CODE_PYCACHE_PREFIX {_c_string(startup_code['pycache_prefix'])}\n",
            _startup_files_macro(startup_code),
            _startup_directories_macro(startup_code),
            _startup_absent_paths_macro(startup_code),
            f"#define EGSI_SOURCE_ROOT {_c_string(str(root))}\n",
            f"#define EGSI_PYTHON_PATH {_c_string(str(root / '.work/offline-test-runner-venv/bin/python'))}\n",
            f"#define EGSI_BOOTSTRAP_PATH {_c_string(str(root / 'scripts/locked_runtime_bootstrap.py'))}\n",
            f"#define EGSI_RECEIPT_SELF {_c_string(str(root / 'scripts/run_test_receipt'))}\n",
            f"#define EGSI_RERUN_SELF {_c_string(str(root / 'scripts/rerun_first_case_hard_gate'))}\n",
            f"#define EGSI_VERIFIER_SELF {_c_string(str(root / 'scripts/verify_first_case_hard_gate'))}\n",
            f"#define EGSI_LIVE_RUN_SELF {_c_string(str(root / 'scripts/run_fail_fast_enrich'))}\n",
            f"#define EGSI_LIVE_VERIFY_SELF {_c_string(str(root / 'scripts/verify_fail_fast_enrich'))}\n",
        )
    )
    private_header = (
        common
        + _word_macro("EGSI_RSA_SIGNING_EXPONENT_WORDS", private_words)
        + "#define EGSI_HAS_RSA_SIGNING_EXPONENT 1\n"
    ).encode("ascii")
    public_header = common.encode("ascii")
    public_material = {
        "schema_version": "3.0",
        "algorithm": ALGORITHM,
        "attestation_version": ATTESTATION_VERSION,
        "public_key": {
            "exponent": public.e,
            "modulus_hex": modulus.to_bytes(256, "big").hex(),
            "spki_der_base64": base64.b64encode(spki).decode("ascii"),
            "key_id": _sha256(spki),
        },
        "build_id": "sha256:" + build_id_raw.hex(),
        "native_contract_sha256": "sha256:" + contract_raw.hex(),
        "python_runtime": python_runtime,
        "bootstrap_anchor": {
            "path": "scripts/locked_runtime_bootstrap.py",
            "mode": bootstrap_mode,
            "size": bootstrap_size,
            "sha256": "sha256:" + bootstrap_sha_raw.hex(),
        },
    }
    _write_private(arguments.private_header, private_header, 0o600)
    _write_private(arguments.public_header, public_header, 0o600)
    _write_private(
        arguments.public_material,
        _canonical(public_material) + b"\n",
        0o600,
    )


def _file_identity(
    path: Path,
    display: str,
    digest: str | None,
    *,
    reject_hardlink: bool = True,
) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (reject_hardlink and info.st_nlink != 1):
        raise ValueError("native build record path is unsafe")
    return {
        "path": display,
        "type": "regular",
        "mode": stat.S_IMODE(info.st_mode),
        "device": info.st_dev,
        "inode": info.st_ino,
        "links": info.st_nlink,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "sha256": digest,
    }


def _read_digest(path: Path) -> str:
    return _sha256(path.read_bytes())


def _record(arguments: argparse.Namespace) -> None:
    root = arguments.root.resolve(strict=True)
    public_material = json.loads(arguments.public_material.read_text(encoding="utf-8"))
    if (
        type(public_material) is not dict
        or public_material.get("schema_version") != "3.0"
        or public_material.get("algorithm") != ALGORITHM
        or public_material.get("attestation_version") != ATTESTATION_VERSION
        or type(public_material.get("bootstrap_anchor")) is not dict
    ):
        raise ValueError("public RSA material is invalid")
    for digest in (
        arguments.receipt_sha256,
        arguments.report_sha256,
        public_material.get("build_id"),
        public_material.get("native_contract_sha256"),
        public_material.get("public_key", {}).get("key_id"),
    ):
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError("native public digest is invalid")
    receipt = root / "scripts/run_test_receipt"
    report = root / "scripts/rerun_first_case_hard_gate"
    verifier = root / "scripts/verify_first_case_hard_gate"
    live_run = root / "scripts/run_fail_fast_enrich"
    live_verify = root / "scripts/verify_fail_fast_enrich"
    expected_modes = (
        (receipt, 0o111),
        (report, 0o111),
        (verifier, 0o555),
        (live_run, 0o111),
        (live_verify, 0o555),
    )
    for path, mode in expected_modes:
        if stat.S_IMODE(path.lstat().st_mode) != mode:
            raise ValueError("native launcher installation mode is invalid")
    source = root / "scripts/locked_launcher.c"
    build = root / "scripts/rebuild_locked_launchers"
    helper = root / "scripts/build_native_rsa_material.py"
    compiler = Path("/usr/bin/gcc").resolve(strict=True)
    verifier_sha = _read_digest(verifier)
    record: dict[str, Any] = {
        **public_material,
        "source_identity": _file_identity(source, "scripts/locked_launcher.c", _read_digest(source)),
        "build_script_identity": _file_identity(build, "scripts/rebuild_locked_launchers", _read_digest(build)),
        "key_builder_identity": _file_identity(helper, "scripts/build_native_rsa_material.py", _read_digest(helper)),
        "compiler_identity": _file_identity(
            compiler,
            str(compiler),
            _read_digest(compiler),
            reject_hardlink=False,
        ),
        "compiler_flags": COMPILER_FLAGS,
        "mode_defines": {
            "receipt_signer": "-DLAUNCH_KIND=1",
            "report_signer": "-DLAUNCH_KIND=2",
            "public_verifier": "-DLAUNCH_KIND=3",
            "live_enrichment_signer": "-DLAUNCH_KIND=4",
            "live_enrichment_verifier": "-DLAUNCH_KIND=5",
        },
        "key_injection": "ephemeral-private-signer-header",
        "signers": {
            "receipt": {
                "role": "receipt_signer",
                "file": "scripts/run_test_receipt",
                "build_sha256": arguments.receipt_sha256,
                "identity": _file_identity(receipt, "scripts/run_test_receipt", arguments.receipt_sha256),
                "elf": ELF_CONTRACT,
            },
            "report": {
                "role": "report_signer",
                "file": "scripts/rerun_first_case_hard_gate",
                "build_sha256": arguments.report_sha256,
                "identity": _file_identity(report, "scripts/rerun_first_case_hard_gate", arguments.report_sha256),
                "elf": ELF_CONTRACT,
            },
            "live_enrichment": {
                "role": "live_enrichment_signer",
                "file": "scripts/run_fail_fast_enrich",
                "build_sha256": arguments.live_run_sha256,
                "identity": _file_identity(
                    live_run,
                    "scripts/run_fail_fast_enrich",
                    arguments.live_run_sha256,
                ),
                "elf": ELF_CONTRACT,
            },
        },
        "verifier": {
            "role": "public_verifier",
            "file": "scripts/verify_first_case_hard_gate",
            "sha256": verifier_sha,
            "identity": _file_identity(verifier, "scripts/verify_first_case_hard_gate", verifier_sha),
            "elf": ELF_CONTRACT,
        },
        "live_verifier": {
            "role": "live_enrichment_verifier",
            "file": "scripts/verify_fail_fast_enrich",
            "sha256": _read_digest(live_verify),
            "identity": _file_identity(
                live_verify,
                "scripts/verify_fail_fast_enrich",
                _read_digest(live_verify),
            ),
            "elf": ELF_CONTRACT,
        },
        "record_commitment_sha256": "sha256:" + "0" * 64,
    }
    record["record_commitment_sha256"] = _commitment(
        record, "record_commitment_sha256"
    )
    _write_private(arguments.output, _canonical(record) + b"\n", 0o600)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="build_native_rsa_material")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    material = subparsers.add_parser("material")
    material.add_argument("--root", type=Path, required=True)
    material.add_argument("--private-header", type=Path, required=True)
    material.add_argument("--public-header", type=Path, required=True)
    material.add_argument("--public-material", type=Path, required=True)
    material.add_argument("--test-private-key-pem", type=Path)
    material.set_defaults(handler=_material)
    record = subparsers.add_parser("record")
    record.add_argument("--root", type=Path, required=True)
    record.add_argument("--public-material", type=Path, required=True)
    record.add_argument("--receipt-sha256", required=True)
    record.add_argument("--report-sha256", required=True)
    record.add_argument("--live-run-sha256", required=True)
    record.add_argument("--output", type=Path, required=True)
    record.set_defaults(handler=_record)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    arguments.handler(arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
