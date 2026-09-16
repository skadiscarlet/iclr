#!/usr/bin/env python3
"""Stdlib-only gate for every execution that may import locked site code."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import runpy
import stat
import subprocess
import sys
import sysconfig
import traceback
from typing import Any, Callable, Iterator


# Capture the stdlib callable before site/project code can monkeypatch the
# shared subprocess module object used by the preloaded validator closure.
_RUN_PROCESS = subprocess.run


_RUNNER_RELATIVE = Path(".work/offline-test-runner-venv")
_LOCK_RELATIVE = Path("configs/offline-test-runner.lock.json")
_BOOTSTRAP_RELATIVE = Path("scripts/locked_runtime_bootstrap.py")
_CONTRACT_VERSION = "offline-pytest-runner-v8"
_MAX_LOCK_BYTES = 16 * 1024 * 1024
_MAX_FILE_BYTES = 512 * 1024 * 1024
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTITY_FIELDS = {
    "path",
    "type",
    "mode",
    "device",
    "inode",
    "links",
    "uid",
    "gid",
    "size",
    "mtime_ns",
    "ctime_ns",
    "sha256",
}
_DISTRIBUTION_FIELDS = {
    "name",
    "version",
    "location",
    "module_file",
    "module_file_sha256",
}
_LOCK_FIELDS = {
    "schema_version",
    "runner_contract_version",
    "command_executable",
    "resolved_executable",
    "executable_identity",
    "python_implementation",
    "python_version",
    "sys_prefix",
    "sys_base_prefix",
    "pyvenv_cfg_identity",
    "include_system_site_packages",
    "no_pth",
    "distributions",
    "site_packages_root",
    "site_packages_inventory",
    "site_packages_tree_sha256",
    "stdlib_root",
    "stdlib_inventory",
    "stdlib_tree_sha256",
    "stdlib_file_count",
    "isolated_sys_path",
    "project_source_tree_sha256",
    "project_installed_tree_sha256",
    "project_inventory",
    "project_identity_sha256",
    "native_launcher_contract",
    "bootstrap_identity",
    "canonical_config_file",
    "canonical_config_identity",
    "lock_commitment_sha256",
}
_NATIVE_CONTRACT_FIELDS = {
    "schema_version",
    "source_file",
    "source_identity",
    "build_script_file",
    "build_script_identity",
    "key_builder_file",
    "key_builder_identity",
    "build_record_file",
    "build_record_identity",
    "build_record_commitment_sha256",
    "compiler_file",
    "compiler_identity",
    "compiler_flags",
    "mode_defines",
    "key_injection",
    "attestation_version",
    "attestation_algorithm",
    "public_key_id",
    "build_id",
    "binary_contract_sha256",
    "bootstrap_anchor",
    "python_runtime_summary",
    "launchers",
    "contract_sha256",
}
_PYTHON_RUNTIME_SUMMARY_FIELDS = {
    "schema_version", "invocation", "interpreter", "files",
    "preload_file_indices", "native_extension_roots", "startup_code", "limits",
    "manifest_sha256", "summary_sha256",
}
_PYTHON_STARTUP_SUMMARY_FIELDS = {
    "schema_version", "strategy", "pycache_prefix", "stdlib_root",
    "lib_dynload_root", "import_roots", "file_count", "directory_count",
    "absent_path_count", "total_bytes", "limits", "manifest_sha256",
    "summary_sha256",
}
_PYTHON_STARTUP_ROOT_FIELDS = {"path", "identity"}
_NATIVE_PUBLIC_CONTRACT = re.compile(
    rb"\AEGSI_NATIVE_ATTESTATION_VERSION=2\n"
    rb"EGSI_NATIVE_ALGORITHM=rsa-2048-sha256-pkcs1-v1_5\n"
    rb"EGSI_NATIVE_PUBLIC_KEY_ID=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_NATIVE_BUILD_ID=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_NATIVE_BINARY_CONTRACT=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_BOOTSTRAP_PATH=([^\n]+)\n"
    rb"EGSI_BOOTSTRAP_SHA256=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_BOOTSTRAP_SIZE=([1-9][0-9]{0,6})\n"
    rb"EGSI_BOOTSTRAP_MODE=([0-7]{4})\n"
    rb"EGSI_PYTHON_PATH=([^\n]+)\n"
    rb"EGSI_PYTHON_SHA256=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_PYTHON_SIZE=([1-9][0-9]{0,8})\n"
    rb"EGSI_PYTHON_MODE=([0-7]{4})\n"
    rb"EGSI_PYTHON_DEVICE=([0-9]{1,20})\n"
    rb"EGSI_PYTHON_INODE=([1-9][0-9]{0,19})\n"
    rb"EGSI_PYTHON_RUNTIME_CLOSURE=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_PYTHON_RUNTIME_FILE_COUNT=([1-9][0-9]{0,2})\n"
    rb"EGSI_PYTHON_STARTUP_CODE_CLOSURE=(sha256:[0-9a-f]{64})\n"
    rb"EGSI_PYTHON_STARTUP_CODE_FILE_COUNT=([1-9][0-9]{0,3})\n"
    rb"EGSI_PYTHON_STARTUP_CODE_DIRECTORY_COUNT=([1-9][0-9]{0,3})\n"
    rb"EGSI_PYTHON_STARTUP_CODE_ABSENT_COUNT=([1-9][0-9]?)\n"
    rb"EGSI_PYTHON_STARTUP_CODE_TOTAL_BYTES=([1-9][0-9]{0,8})\n\Z"
)
_NATIVE_LAUNCHER_FIELDS = {
    "file",
    "role",
    "read_policy",
    "build_sha256",
    "identity",
    "elf_class",
    "elf_data",
    "elf_type",
    "machine",
    "pt_interp",
    "pt_dynamic",
    "dt_needed_count",
    "static",
}
_NATIVE_BUILD_RECORD_RELATIVE = Path("configs/native-signer-build-record.json")
_NATIVE_BUILD_RECORD_FIELDS = {
    "schema_version", "algorithm", "attestation_version", "public_key",
    "build_id", "native_contract_sha256", "source_identity",
    "bootstrap_anchor", "python_runtime",
    "build_script_identity", "key_builder_identity", "compiler_identity",
    "compiler_flags", "mode_defines", "key_injection", "signers",
    "verifier", "live_verifier", "record_commitment_sha256",
}
_NATIVE_PUBLIC_KEY_FIELDS = {
    "exponent", "modulus_hex", "spki_der_base64", "key_id",
}
_NATIVE_BOOTSTRAP_ANCHOR_FIELDS = {"path", "mode", "size", "sha256"}
_NATIVE_RECORD_SIGNER_FIELDS = {
    "role", "file", "build_sha256", "identity", "elf",
}
_NATIVE_RECORD_VERIFIER_FIELDS = {
    "role", "file", "sha256", "identity", "elf",
}
_NATIVE_ELF_FIELDS = {
    "elf_class", "elf_data", "elf_type", "machine", "pt_interp",
    "pt_dynamic", "dt_needed_count", "static",
}
_NATIVE_COMPILER_FLAGS = [
    "-std=c11",
    "-Os",
    "-static",
    "-nostdlib",
    "-nostartfiles",
    "-nodefaultlibs",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-pie",
    "-no-pie",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-Wl,--build-id=none",
    "-Wl,-z,noexecstack",
    "-Wl,--fatal-warnings",
    "-s",
]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", "strict")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _commitment(value: dict[str, Any], key: str) -> str:
    canonical = dict(value)
    canonical.pop(key, None)
    return _sha256(_canonical(canonical))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in runner lock")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    del value
    raise ValueError("non-finite constant in runner lock")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite number in runner lock")
    return result


def _strict_json(raw: bytes) -> Any:
    if len(raw) > _MAX_LOCK_BYTES:
        raise ValueError("runner lock exceeds its byte bound")
    return json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "special"


def _metadata(path: str, info: os.stat_result, digest: str | None) -> dict[str, Any]:
    return {
        "path": path,
        "type": _kind(info.st_mode),
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


def _identity_tuple(info: os.stat_result) -> tuple[int, ...]:
    return (
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_regular(
    path: Path,
    *,
    display_path: str | None = None,
    reject_hardlink: bool,
    limit: int = _MAX_FILE_BYTES,
) -> tuple[bytes, dict[str, Any]]:
    before_path = path.lstat()
    if (
        not stat.S_ISREG(before_path.st_mode)
        or (reject_hardlink and before_path.st_nlink != 1)
        or before_path.st_size < 0
        or before_path.st_size > limit
    ):
        raise ValueError("unsafe regular file in locked runtime")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if _identity_tuple(before) != _identity_tuple(before_path):
            raise ValueError("runtime file identity changed before read")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                raise ValueError("short read in locked runtime")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("runtime file grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if (
        _identity_tuple(before) != _identity_tuple(after)
        or _identity_tuple(after) != _identity_tuple(after_path)
    ):
        raise ValueError("runtime file changed during read")
    raw = b"".join(chunks)
    return raw, _metadata(
        str(path) if display_path is None else display_path,
        after,
        _sha256(raw),
    )


def _read_inherited_regular_fd(
    descriptor: int, *, limit: int
) -> bytes:
    if descriptor < 3 or limit < 0:
        raise ValueError("inherited runtime descriptor is invalid")
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > limit
    ):
        raise ValueError("inherited runtime descriptor is unsafe")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor, min(1_048_576, before.st_size - offset), offset
        )
        if not chunk:
            raise ValueError("short pread from inherited runtime descriptor")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, offset):
        raise ValueError("inherited runtime descriptor grew during pread")
    after = os.fstat(descriptor)
    if _identity_tuple(before) != _identity_tuple(after):
        raise ValueError("inherited runtime descriptor changed during pread")
    return b"".join(chunks)


def _symlink_identity(path: Path, display_path: str) -> dict[str, Any]:
    before = path.lstat()
    if not stat.S_ISLNK(before.st_mode):
        raise ValueError("runtime symlink identity is invalid")
    target = os.readlink(path)
    after = path.lstat()
    if _identity_tuple(before) != _identity_tuple(after):
        raise ValueError("runtime symlink changed during read")
    return _metadata(
        display_path,
        after,
        _sha256(target.encode("utf-8", "surrogateescape")),
    )


def _scan_tree(
    root: Path,
    *,
    reject_symlinks: bool,
    reject_hardlinks: bool,
    exclude: Callable[[Path, bool], bool] | None = None,
) -> list[dict[str, Any]]:
    root = root.resolve(strict=True)
    inventory: list[dict[str, Any]] = []

    def walk(directory: Path, relative: str) -> None:
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ValueError("runtime tree root is unsafe")
        inventory.append(_metadata(relative, before, None))
        with os.scandir(directory) as stream:
            children = sorted(stream, key=lambda item: item.name)
        for child in children:
            path = directory / child.name
            info = path.lstat()
            is_directory = stat.S_ISDIR(info.st_mode)
            if exclude is not None and exclude(path, is_directory):
                continue
            child_relative = (
                child.name if relative == "." else f"{relative}/{child.name}"
            )
            kind = _kind(info.st_mode)
            if kind == "directory":
                walk(path, child_relative)
            elif kind == "regular":
                _, item = _read_regular(
                    path,
                    display_path=child_relative,
                    reject_hardlink=reject_hardlinks,
                )
                inventory.append(item)
            elif kind == "symlink":
                if reject_symlinks:
                    raise ValueError("symlink in locked runtime closure")
                inventory.append(_symlink_identity(path, child_relative))
            else:
                raise ValueError("special node in locked runtime closure")
        after = directory.lstat()
        if _identity_tuple(before) != _identity_tuple(after):
            raise ValueError("runtime directory changed during scan")

    walk(root, ".")
    return inventory


def _stdlib_exclude(path: Path, is_directory: bool) -> bool:
    if is_directory and path.name in {
        "site-packages",
        "dist-packages",
        "__pycache__",
    }:
        return True
    return not is_directory and path.suffix in {".pyc", ".pyo"}


def _project_exclude(path: Path, is_directory: bool) -> bool:
    return (is_directory and path.name == "__pycache__") or (
        not is_directory and path.suffix in {".pyc", ".pyo"}
    )


def _site_packages_exclude(path: Path, is_directory: bool) -> bool:
    """Ignore only interpreter-derived bytecode in the locked site closure."""

    return (is_directory and path.name == "__pycache__") or (
        not is_directory and path.suffix in {".pyc", ".pyo"}
    )


def _site_packages_inventory(site_packages: Path) -> list[dict[str, Any]]:
    """Return durable site-package identities, excluding derived directories."""

    return [
        item
        for item in _scan_tree(
            site_packages,
            reject_symlinks=True,
            reject_hardlinks=True,
            exclude=_site_packages_exclude,
        )
        if item["type"] == "regular"
    ]


def _project_tree_content(path: Path) -> str:
    inventory = _scan_tree(
        path,
        reject_symlinks=True,
        reject_hardlinks=True,
        exclude=_project_exclude,
    )
    files = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in inventory
        if item["type"] == "regular"
    ]
    if not files:
        raise ValueError("project runtime tree is empty")
    return _sha256(_canonical(files))


def _project_inventory(
    root: Path, native_launcher_contract: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    opaque_signers = {
        item["file"]: item["identity"]
        for item in (
            native_launcher_contract["launchers"].values()
            if native_launcher_contract is not None
            else ()
        )
        if item["read_policy"] == "opaque-execute-only"
    }
    for relative_root in ("src", "tests", "scripts", "configs", "idea-stage"):
        tree = root / relative_root

        def exclude(path: Path, is_directory: bool) -> bool:
            if (is_directory and path.name == "__pycache__") or (
                not is_directory and path.suffix in {".pyc", ".pyo"}
            ):
                raise ValueError("project bytecode cache is forbidden")
            relative = (
                f"{relative_root}/{path.relative_to(tree).as_posix()}"
            )
            return (not is_directory and relative in opaque_signers) or (
                relative_root == "configs"
                and not is_directory
                and path.name == _LOCK_RELATIVE.name
            )

        for item in _scan_tree(
            tree,
            reject_symlinks=True,
            reject_hardlinks=True,
            exclude=exclude,
        ):
            if item["type"] == "directory":
                # The scan still rejects unsafe directory entries and detects
                # every persistent add/remove through the regular-file set.
                # Do not bind volatile directory mtime/ctime: canonical tests
                # create then remove local fixtures, while file identities
                # remain the durable mutate-and-restore boundary.
                continue
            copied = dict(item)
            copied["path"] = (
                relative_root
                if item["path"] == "."
                else f"{relative_root}/{item['path']}"
            )
            inventory.append(copied)
    inventory.extend(dict(item) for item in opaque_signers.values())
    _, pyproject = _read_regular(
        root / "pyproject.toml",
        display_path="pyproject.toml",
        reject_hardlink=True,
        limit=1024 * 1024,
    )
    inventory.append(pyproject)
    return sorted(inventory, key=lambda item: item["path"])


def _elf_static_launcher(
    path: Path, *, root: Path
) -> dict[str, Any]:
    raw, identity = _read_regular(
        path,
        display_path=path.relative_to(root).as_posix(),
        reject_hardlink=True,
        limit=1024 * 1024,
    )
    if (
        len(raw) < 64
        or raw[:4] != b"\x7fELF"
        or raw[4] != 2
        or raw[5] != 1
        or int.from_bytes(raw[16:18], "little") != 2
        or int.from_bytes(raw[18:20], "little") != 62
    ):
        raise ValueError("native launcher is not a static x86_64 ELF")
    program_offset = int.from_bytes(raw[32:40], "little")
    program_size = int.from_bytes(raw[54:56], "little")
    program_count = int.from_bytes(raw[56:58], "little")
    if (
        program_size < 56
        or program_count <= 0
        or program_offset < 64
        or program_offset + program_size * program_count > len(raw)
    ):
        raise ValueError("native launcher program headers are invalid")
    program_types = [
        int.from_bytes(
            raw[
                program_offset + index * program_size :
                program_offset + index * program_size + 4
            ],
            "little",
        )
        for index in range(program_count)
    ]
    if 1 not in program_types or 2 in program_types or 3 in program_types:
        raise ValueError("native launcher has a dynamic loader contract")
    return {
        "file": path.relative_to(root).as_posix(),
        "identity": identity,
        "elf_class": "ELF64",
        "elf_data": "little-endian",
        "elf_type": "ET_EXEC",
        "machine": "EM_X86_64",
        "pt_interp": False,
        "pt_dynamic": False,
        "dt_needed_count": 0,
        "static": True,
    }


def _valid_native_elf(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == _NATIVE_ELF_FIELDS
        and value.get("elf_class") == "ELF64"
        and value.get("elf_data") == "little-endian"
        and value.get("elf_type") == "ET_EXEC"
        and value.get("machine") == "EM_X86_64"
        and value.get("pt_interp") is False
        and value.get("pt_dynamic") is False
        and value.get("dt_needed_count") == 0
        and value.get("static") is True
    )


def _valid_python_elf(value: object, *, interpreter: bool) -> bool:
    pt_interp = value.get("pt_interp") if type(value) is dict else None
    return (
        type(value) is dict
        and set(value)
        == {
            "elf_class", "elf_data", "elf_type", "machine", "pt_interp",
            "dt_needed", "dt_soname", "dt_runpath", "dt_rpath",
        }
        and value.get("elf_class") == "ELF64"
        and value.get("elf_data") == "little-endian"
        and value.get("elf_type") in {"ET_EXEC", "ET_DYN"}
        and value.get("machine") == "EM_X86_64"
        and (
            type(pt_interp) is str and Path(pt_interp).is_absolute()
            if interpreter
            else pt_interp is None
            or type(pt_interp) is str and Path(pt_interp).is_absolute()
        )
        and type(value.get("dt_needed")) is list
        and len(value["dt_needed"]) == len(set(value["dt_needed"]))
        and all(
            type(item) is str and item and "/" not in item
            for item in value["dt_needed"]
        )
        and (
            value.get("dt_soname") is None
            or type(value["dt_soname"]) is str
            and value["dt_soname"]
            and "/" not in value["dt_soname"]
        )
        and type(value.get("dt_runpath")) is list
        and type(value.get("dt_rpath")) is list
        and not (value["dt_runpath"] and value["dt_rpath"])
        and all(
            type(item) is str and item
            for item in (*value["dt_runpath"], *value["dt_rpath"])
        )
    )


def _valid_runtime_file(value: object, *, role: str) -> bool:
    if (
        type(value) is not dict
        or set(value)
        != {
            "role", "needed_name", "path", "mode", "size", "device",
            "inode", "sha256", "identity", "elf",
        }
        or value.get("role") != role
        or type(value.get("needed_name")) is not str
        or not value["needed_name"]
        or "/" in value["needed_name"]
        or type(value.get("path")) is not str
        or not Path(value["path"]).is_absolute()
        or type(value.get("mode")) is not int
        or value["mode"] & 0o022
        or not _valid_identity(value.get("identity"), allow_symlink=False)
        or value["identity"].get("type") != "regular"
        or value["identity"].get("path") != value["path"]
        or value["identity"].get("links") != 1
        or any(
            value.get(field) != value["identity"].get(field)
            for field in ("mode", "size", "device", "inode", "sha256")
        )
        or not _valid_python_elf(value.get("elf"), interpreter=False)
    ):
        return False
    return (
        0 < value["size"] <= 64 * 1024 * 1024
        and (
            role == "extension-root"
            or value["elf"].get("dt_soname") == value["needed_name"]
        )
    )


def _valid_runtime_preload_plan(
    value: object, files: list[dict[str, Any]]
) -> bool:
    if (
        type(value) is not list
        or not value
        or value != sorted(set(value))
        or any(
            type(index) is not int or not 1 <= index < len(files)
            for index in value
        )
    ):
        return False
    selected = set(value)
    if any(
        item.get("role") == "dependency" and index not in selected
        for index, item in enumerate(files)
    ):
        return False
    loader_name = files[0].get("needed_name")
    by_soname: dict[str, int] = {}
    for index in value:
        soname = files[index]["elf"].get("dt_soname")
        if soname is not None:
            if soname in by_soname:
                return False
            by_soname[soname] = index
    positions = {file_index: position for position, file_index in enumerate(value)}
    for index in value:
        for needed_name in files[index]["elf"]["dt_needed"]:
            if needed_name == loader_name:
                continue
            dependency_index = by_soname.get(needed_name)
            if (
                dependency_index is None
                or positions[dependency_index] >= positions[index]
            ):
                return False
    for index, item in enumerate(files[1:], start=1):
        if index in selected:
            continue
        soname = item["elf"].get("dt_soname")
        representative = by_soname.get(soname) if soname is not None else None
        if (
            item.get("role") != "extension-root"
            or representative is None
            or files[representative].get("sha256") != item.get("sha256")
        ):
            return False
    return True


def _import_root_entries(value: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        value["compiled_prefix"],
        value["stdlib_root"],
        value["lib_dynload_root"],
        *value["site_packages_roots"],
    ]


def _import_root_metadata_from(path: Path) -> int:
    # / and /tmp are shared mutable ancestors in synthetic/test deployments.
    # Bind their directory identity (dev/inode/mode/owner), but begin the full
    # metadata/ABA contract at the first operator-owned component below /tmp.
    return 2 if path == Path("/tmp") or path.is_relative_to("/tmp") else 0


def _directory_contract_matches(
    current: dict[str, Any], expected: dict[str, Any], *, full: bool
) -> bool:
    if full:
        return current == expected
    return all(
        current.get(field) == expected.get(field)
        for field in (
            "path", "type", "mode", "device", "inode", "uid", "gid",
            "sha256",
        )
    )


def _valid_import_root_entry(value: object) -> bool:
    if (
        type(value) is not dict
        or set(value) != {"raw_path", "resolved_path", "ancestor_chain"}
        or type(value.get("raw_path")) is not str
        or not Path(value["raw_path"]).is_absolute()
        or value.get("resolved_path") != value["raw_path"]
        or type(value.get("ancestor_chain")) is not list
        or not 2 <= len(value["ancestor_chain"]) <= 32
    ):
        return False
    expected_paths = [Path("/")]
    current = Path("/")
    for component in Path(value["raw_path"]).parts[1:]:
        if component in {"", ".", ".."}:
            return False
        current = current / component
        expected_paths.append(current)
    if len(expected_paths) != len(value["ancestor_chain"]):
        return False
    for expected, item in zip(expected_paths, value["ancestor_chain"], strict=True):
        if (
            type(item) is not dict
            or set(item) != {"path", "identity"}
            or item.get("path") != str(expected)
            or not _valid_identity(item.get("identity"), allow_symlink=False)
            or item["identity"].get("type") != "directory"
            or item["identity"].get("path") != item["path"]
        ):
            return False
    return value["ancestor_chain"][-1]["path"] == value["raw_path"]


def _valid_import_roots(
    value: object, *, stdlib_root: str, lib_dynload_root: str
) -> bool:
    if (
        type(value) is not dict
        or set(value) != {
            "compiled_prefix", "stdlib_root", "lib_dynload_root",
            "site_packages_roots", "expected_isolated_state",
        }
        or not _valid_import_root_entry(value.get("compiled_prefix"))
        or not _valid_import_root_entry(value.get("stdlib_root"))
        or not _valid_import_root_entry(value.get("lib_dynload_root"))
        or type(value.get("site_packages_roots")) is not list
        or any(
            not _valid_import_root_entry(item)
            for item in value["site_packages_roots"]
        )
    ):
        return False
    prefix = Path(value["compiled_prefix"]["raw_path"])
    stdlib = Path(value["stdlib_root"]["raw_path"])
    lib_dynload = Path(value["lib_dynload_root"]["raw_path"])
    if (
        str(stdlib) != stdlib_root
        or str(lib_dynload) != lib_dynload_root
        or stdlib.parent.name != "lib"
        or stdlib.parent.parent != prefix
        or lib_dynload != stdlib / "lib-dynload"
        or len({item["raw_path"] for item in value["site_packages_roots"]})
        != len(value["site_packages_roots"])
    ):
        return False
    version = stdlib.name.removeprefix("python")
    compact_version = version.replace(".", "")
    state = value.get("expected_isolated_state")
    return state == {
        "sys_path": [
            str(prefix / "lib" / f"python{compact_version}.zip"),
            str(stdlib),
            str(lib_dynload),
        ],
        "sys_prefix": str(prefix),
        "sys_base_prefix": str(prefix),
    }


def _valid_python_startup_code(
    value: object, *, root: Path | None = None
) -> bool:
    if (
        type(value) is not dict
        or set(value) != {
            "schema_version", "strategy", "pycache_prefix",
            "stdlib_root", "lib_dynload_root", "import_roots",
            "files", "directories",
            "absent_paths", "file_count", "directory_count",
            "absent_path_count", "total_bytes", "limits",
            "closure_sha256",
        }
        or value.get("schema_version") != "2.0"
        or value.get("strategy")
        != "source-tree-no-bytecode-native-closure-v2"
        or value.get("pycache_prefix")
        != "/nonexistent/egsi-locked-pycache"
        or type(value.get("stdlib_root")) is not str
        or not Path(value["stdlib_root"]).is_absolute()
        or type(value.get("lib_dynload_root")) is not str
        or not Path(value["lib_dynload_root"]).is_absolute()
        or value["lib_dynload_root"]
        != str(Path(value["stdlib_root"]) / "lib-dynload")
        or value.get("limits") != {
            "max_files": 4096,
            "max_directories": 1024,
            "max_absent_paths": 16,
            "max_file_bytes": 4 * 1024 * 1024,
            "max_total_bytes": 64 * 1024 * 1024,
        }
        or value.get("closure_sha256")
        != _commitment(value, "closure_sha256")
        or type(value.get("files")) is not list
        or not 1 <= len(value["files"]) <= 4096
        or type(value.get("directories")) is not list
        or not 1 <= len(value["directories"]) <= 1024
        or type(value.get("absent_paths")) is not list
        or not 1 <= len(value["absent_paths"]) <= 16
        or value.get("file_count") != len(value["files"])
        or value.get("directory_count") != len(value["directories"])
        or value.get("absent_path_count") != len(value["absent_paths"])
        or len(set(value["absent_paths"])) != len(value["absent_paths"])
        or value["pycache_prefix"] not in value["absent_paths"]
        or any(
            type(path) is not str or not Path(path).is_absolute()
            for path in value["absent_paths"]
        )
    ):
        return False
    import_roots = value.get("import_roots")
    if not _valid_import_roots(
        import_roots,
        stdlib_root=value["stdlib_root"],
        lib_dynload_root=value["lib_dynload_root"],
    ):
        return False
    for item in value["files"]:
        if (
            type(item) is not dict
            or set(item) != {"relative_path", "path", "identity"}
            or type(item.get("relative_path")) is not str
            or not item["relative_path"]
            or type(item.get("path")) is not str
            or not Path(item["path"]).is_absolute()
            or not _valid_identity(item.get("identity"), allow_symlink=False)
            or item["identity"].get("type") != "regular"
            or item["identity"].get("path") != item["path"]
            or item["identity"].get("links") != 1
            or item["identity"].get("mode", 0) & 0o022
            or not 0 <= item["identity"].get("size", -1) <= 4 * 1024 * 1024
        ):
            return False
    for item in value["directories"]:
        if (
            type(item) is not dict
            or set(item) != {"relative_path", "path", "identity"}
            or type(item.get("relative_path")) is not str
            or not item["relative_path"]
            or type(item.get("path")) is not str
            or not Path(item["path"]).is_absolute()
            or not _valid_identity(item.get("identity"), allow_symlink=False)
            or item["identity"].get("type") != "directory"
            or item["identity"].get("path") != item["path"]
            or item["identity"].get("mode", 0) & 0o022
        ):
            return False
    if (
        len({item["relative_path"] for item in value["files"]})
        != len(value["files"])
        or len({item["path"] for item in value["files"]})
        != len(value["files"])
        or len({item["relative_path"] for item in value["directories"]})
        != len(value["directories"])
        or len({item["path"] for item in value["directories"]})
        != len(value["directories"])
        or value.get("total_bytes")
        != sum(item["identity"]["size"] for item in value["files"])
        or not 0 < value["total_bytes"] <= 64 * 1024 * 1024
    ):
        return False
    relative = {item["relative_path"] for item in value["files"]}
    if (
        "stdlib:encodings/__init__.py" not in relative
        or "stdlib:subprocess.py" not in relative
        or not any(
            item.startswith("lib-dynload:") and item.endswith(".so")
            for item in relative
        )
    ):
        return False
    if root is not None:
        try:
            for item in value["files"]:
                _, current = _read_regular(
                    Path(item["path"]), display_path=item["path"],
                    reject_hardlink=True, limit=4 * 1024 * 1024,
                )
                if current != item["identity"]:
                    return False
            for item in value["directories"]:
                path = Path(item["path"])
                info = path.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or _metadata(item["path"], info, None) != item["identity"]
                ):
                    return False
            for absent in value["absent_paths"]:
                try:
                    Path(absent).lstat()
                except FileNotFoundError:
                    continue
                return False
            for item in _import_root_entries(import_roots):
                metadata_from = _import_root_metadata_from(
                    Path(item["raw_path"])
                )
                for index, component in enumerate(item["ancestor_chain"]):
                    path = Path(component["path"])
                    info = path.lstat()
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)
                        or not _directory_contract_matches(
                            _metadata(str(path), info, None),
                            component["identity"],
                            full=index >= metadata_from,
                        )
                    ):
                        return False
        except (OSError, ValueError):
            return False
    return True


def _valid_python_runtime(value: object, *, root: Path | None = None) -> bool:
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema_version", "invocation", "interpreter", "files",
            "preload_file_indices", "native_extension_roots", "startup_code",
            "limits", "closure_sha256",
        }
        or value.get("schema_version") != "3.0"
        or value.get("invocation") != "glibc-loader-fd-preload-v2"
        or value.get("limits")
        != {
            "max_files": 256,
            "max_depth": 16,
            "max_file_bytes": 64 * 1024 * 1024,
            "max_total_bytes": 512 * 1024 * 1024,
        }
        or value.get("closure_sha256") != _commitment(value, "closure_sha256")
        or not _valid_python_startup_code(value.get("startup_code"), root=root)
        or type(value.get("interpreter")) is not dict
        or set(value["interpreter"])
        != {
            "path", "mode", "size", "device", "inode", "sha256",
            "identity", "elf", "loader_path",
        }
        or not _valid_identity(
            value["interpreter"].get("identity"), allow_symlink=False
        )
        or value["interpreter"]["identity"].get("type") != "regular"
        or value["interpreter"]["identity"].get("links") != 1
        or value["interpreter"].get("mode", 0) & 0o022
        or any(
            value["interpreter"].get(field)
            != value["interpreter"]["identity"].get(field)
            for field in ("path", "mode", "size", "device", "inode", "sha256")
        )
        or not _valid_python_elf(
            value["interpreter"].get("elf"), interpreter=True
        )
        or type(value.get("files")) is not list
        or not 2 <= len(value["files"]) <= 256
        or not _valid_runtime_file(value["files"][0], role="loader")
        or any(
            not any(
                _valid_runtime_file(item, role=role)
                for role in ("dependency", "extension-root")
            )
            for item in value["files"][1:]
        )
        or value["interpreter"].get("loader_path")
        != value["files"][0].get("path")
        or len({item["path"] for item in value["files"]})
        != len(value["files"])
        or value["interpreter"].get("size", 0)
        + sum(item["size"] for item in value["files"])
        > 512 * 1024 * 1024
        or not _valid_runtime_preload_plan(
            value.get("preload_file_indices"), value["files"]
        )
    ):
        return False
    roots = value.get("native_extension_roots")
    if (
        type(roots) is not list
        or not roots
        or len({item.get("path") for item in roots if type(item) is dict})
        != len(roots)
    ):
        return False
    for item in roots:
        if (
            type(item) is not dict
            or set(item) != {"path", "source", "file_index"}
            or item.get("source") not in {"lib-dynload", "site-packages"}
            or type(item.get("path")) is not str
            or type(item.get("file_index")) is not int
            or not 0 <= item["file_index"] < len(value["files"])
            or value["files"][item["file_index"]].get("path") != item["path"]
        ):
            return False
    if root is not None:
        expected_python = root / ".work/offline-test-runner-venv/bin/python"
        if value["interpreter"]["path"] != str(expected_python):
            return False
        entries = [value["interpreter"], *value["files"]]
        try:
            for item in entries:
                _, current = _read_regular(
                    Path(item["path"]),
                    display_path=item["path"],
                    reject_hardlink=True,
                    limit=64 * 1024 * 1024,
                )
                if current != item["identity"]:
                    return False
        except (OSError, ValueError):
            return False
    return True


def _startup_root_summary(
    startup: dict[str, Any], relative_path: str, path_field: str
) -> dict[str, Any]:
    matches = [
        item for item in startup["directories"]
        if item.get("relative_path") == relative_path
        and item.get("path") == startup[path_field]
    ]
    if len(matches) != 1:
        raise ValueError("Python startup root identity is missing")
    return {
        "path": matches[0]["path"],
        "identity": matches[0]["identity"],
    }


def _compact_python_runtime_contract(
    value: dict[str, Any], *, root: Path | None = None
) -> dict[str, Any]:
    """Project the validated full build manifest into a bounded public summary."""

    if not _valid_python_runtime(value, root=root):
        raise ValueError("full Python runtime contract is invalid")
    startup = value["startup_code"]
    startup_summary: dict[str, Any] = {
        "schema_version": "2.0",
        "strategy": startup["strategy"],
        "pycache_prefix": startup["pycache_prefix"],
        "stdlib_root": _startup_root_summary(
            startup, "stdlib:.", "stdlib_root"
        ),
        "lib_dynload_root": _startup_root_summary(
            startup, "lib-dynload:.", "lib_dynload_root"
        ),
        "import_roots": startup["import_roots"],
        "file_count": startup["file_count"],
        "directory_count": startup["directory_count"],
        "absent_path_count": startup["absent_path_count"],
        "total_bytes": startup["total_bytes"],
        "limits": dict(startup["limits"]),
        "manifest_sha256": startup["closure_sha256"],
        "summary_sha256": "sha256:" + "0" * 64,
    }
    startup_summary["summary_sha256"] = _commitment(
        startup_summary, "summary_sha256"
    )
    summary: dict[str, Any] = {
        "schema_version": "2.0",
        "invocation": value["invocation"],
        "interpreter": value["interpreter"],
        "files": value["files"],
        "preload_file_indices": value["preload_file_indices"],
        "native_extension_roots": value["native_extension_roots"],
        "startup_code": startup_summary,
        "limits": dict(value["limits"]),
        "manifest_sha256": value["closure_sha256"],
        "summary_sha256": "sha256:" + "0" * 64,
    }
    summary["summary_sha256"] = _commitment(summary, "summary_sha256")
    if not _valid_python_runtime_summary(summary):
        raise ValueError("compact Python runtime contract is invalid")
    return summary


def _valid_startup_root_summary(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == _PYTHON_STARTUP_ROOT_FIELDS
        and type(value.get("path")) is str
        and Path(value["path"]).is_absolute()
        and _valid_identity(value.get("identity"), allow_symlink=False)
        and value["identity"].get("type") == "directory"
        and value["identity"].get("path") == value["path"]
        and value["identity"].get("mode", 0) & 0o022 == 0
    )


def _valid_python_startup_summary(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == _PYTHON_STARTUP_SUMMARY_FIELDS
        and value.get("schema_version") == "2.0"
        and value.get("strategy")
        == "source-tree-no-bytecode-native-closure-v2"
        and value.get("pycache_prefix")
        == "/nonexistent/egsi-locked-pycache"
        and _valid_startup_root_summary(value.get("stdlib_root"))
        and _valid_startup_root_summary(value.get("lib_dynload_root"))
        and value["lib_dynload_root"]["path"]
        == str(Path(value["stdlib_root"]["path"]) / "lib-dynload")
        and _valid_import_roots(
            value.get("import_roots"),
            stdlib_root=value["stdlib_root"]["path"],
            lib_dynload_root=value["lib_dynload_root"]["path"],
        )
        and type(value.get("file_count")) is int
        and 1 <= value["file_count"] <= 4096
        and type(value.get("directory_count")) is int
        and 1 <= value["directory_count"] <= 1024
        and type(value.get("absent_path_count")) is int
        and 1 <= value["absent_path_count"] <= 16
        and type(value.get("total_bytes")) is int
        and 0 < value["total_bytes"] <= 64 * 1024 * 1024
        and value.get("limits") == {
            "max_files": 4096,
            "max_directories": 1024,
            "max_absent_paths": 16,
            "max_file_bytes": 4 * 1024 * 1024,
            "max_total_bytes": 64 * 1024 * 1024,
        }
        and _SHA256.fullmatch(str(value.get("manifest_sha256"))) is not None
        and value.get("summary_sha256")
        == _commitment(value, "summary_sha256")
    )


def _valid_python_runtime_summary(value: object) -> bool:
    if (
        type(value) is not dict
        or set(value) != _PYTHON_RUNTIME_SUMMARY_FIELDS
        or value.get("schema_version") != "2.0"
        or value.get("invocation") != "glibc-loader-fd-preload-v2"
        or value.get("limits") != {
            "max_files": 256,
            "max_depth": 16,
            "max_file_bytes": 64 * 1024 * 1024,
            "max_total_bytes": 512 * 1024 * 1024,
        }
        or _SHA256.fullmatch(str(value.get("manifest_sha256"))) is None
        or value.get("summary_sha256")
        != _commitment(value, "summary_sha256")
        or not _valid_python_startup_summary(value.get("startup_code"))
        or type(value.get("interpreter")) is not dict
        or set(value["interpreter"]) != {
            "path", "mode", "size", "device", "inode", "sha256",
            "identity", "elf", "loader_path",
        }
        or not _valid_identity(
            value["interpreter"].get("identity"), allow_symlink=False
        )
        or value["interpreter"]["identity"].get("type") != "regular"
        or value["interpreter"]["identity"].get("links") != 1
        or value["interpreter"].get("mode", 0) & 0o022
        or any(
            value["interpreter"].get(field)
            != value["interpreter"]["identity"].get(field)
            for field in ("path", "mode", "size", "device", "inode", "sha256")
        )
        or not _valid_python_elf(
            value["interpreter"].get("elf"), interpreter=True
        )
        or type(value.get("files")) is not list
        or not 2 <= len(value["files"]) <= 256
        or not _valid_runtime_file(value["files"][0], role="loader")
        or any(
            not any(
                _valid_runtime_file(item, role=role)
                for role in ("dependency", "extension-root")
            )
            for item in value["files"][1:]
        )
        or value["interpreter"].get("loader_path")
        != value["files"][0].get("path")
        or len({item["path"] for item in value["files"]})
        != len(value["files"])
        or value["interpreter"].get("size", 0)
        + sum(item["size"] for item in value["files"])
        > 512 * 1024 * 1024
        or not _valid_runtime_preload_plan(
            value.get("preload_file_indices"), value["files"]
        )
    ):
        return False
    roots = value.get("native_extension_roots")
    return (
        type(roots) is list
        and roots
        and all(
            type(item) is dict
            and set(item) == {"path", "source", "file_index"}
            and item.get("source") in {"lib-dynload", "site-packages"}
            and type(item.get("file_index")) is int
            and 0 <= item["file_index"] < len(value["files"])
            and value["files"][item["file_index"]].get("path")
            == item.get("path")
            for item in roots
        )
    )


def _expected_rsa_spki(modulus_hex: str) -> bytes:
    modulus = bytes.fromhex(modulus_hex)
    if len(modulus) != 256 or not (modulus[0] & 0x80):
        raise ValueError("native RSA modulus is not canonical 2048-bit")
    rsa_key = (
        b"\x30\x82\x01\x0a\x02\x82\x01\x01\x00"
        + modulus
        + b"\x02\x03\x01\x00\x01"
    )
    return (
        b"\x30\x82\x01\x22"
        b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
        b"\x03\x82\x01\x0f\x00"
        + rsa_key
    )


def _opaque_identity(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    info = path.lstat()
    current = _metadata(expected["path"], info, expected["sha256"])
    if current != expected:
        raise ValueError("execute-only native signer metadata changed")
    return current


def _native_build_record(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    path = root / _NATIVE_BUILD_RECORD_RELATIVE
    raw, identity = _read_regular(
        path,
        display_path=_NATIVE_BUILD_RECORD_RELATIVE.as_posix(),
        reject_hardlink=True,
        limit=4 * 1024 * 1024,
    )
    value = _strict_json(raw)
    if (
        type(value) is not dict
        or set(value) != _NATIVE_BUILD_RECORD_FIELDS
        or value.get("schema_version") != "3.0"
        or value.get("algorithm") != "rsa-2048-sha256-pkcs1-v1_5"
        or value.get("attestation_version") != "2"
        or value.get("compiler_flags") != _NATIVE_COMPILER_FLAGS
        or value.get("mode_defines")
        != {
            "receipt_signer": "-DLAUNCH_KIND=1",
            "report_signer": "-DLAUNCH_KIND=2",
            "public_verifier": "-DLAUNCH_KIND=3",
            "live_enrichment_signer": "-DLAUNCH_KIND=4",
            "live_enrichment_verifier": "-DLAUNCH_KIND=5",
        }
        or value.get("key_injection")
        != "ephemeral-private-signer-header"
        or type(value.get("public_key")) is not dict
        or set(value["public_key"]) != _NATIVE_PUBLIC_KEY_FIELDS
        or value["public_key"].get("exponent") != 65537
        or re.fullmatch(r"[0-9a-f]{512}", str(value["public_key"].get("modulus_hex"))) is None
        or _SHA256.fullmatch(str(value["public_key"].get("key_id"))) is None
        or _SHA256.fullmatch(str(value.get("build_id"))) is None
        or _SHA256.fullmatch(str(value.get("native_contract_sha256"))) is None
        or not _valid_python_runtime(value.get("python_runtime"), root=root)
        or type(value.get("bootstrap_anchor")) is not dict
        or set(value["bootstrap_anchor"]) != _NATIVE_BOOTSTRAP_ANCHOR_FIELDS
        or value["bootstrap_anchor"].get("path")
        != _BOOTSTRAP_RELATIVE.as_posix()
        or value["bootstrap_anchor"].get("mode") not in {0o444, 0o644}
        or type(value["bootstrap_anchor"].get("size")) is not int
        or not 1 <= value["bootstrap_anchor"]["size"] <= 1024 * 1024
        or _SHA256.fullmatch(
            str(value["bootstrap_anchor"].get("sha256"))
        ) is None
        or type(value.get("signers")) is not dict
        or set(value["signers"]) != {"receipt", "report", "live_enrichment"}
        or type(value.get("verifier")) is not dict
        or set(value["verifier"]) != _NATIVE_RECORD_VERIFIER_FIELDS
        or type(value.get("live_verifier")) is not dict
        or set(value["live_verifier"]) != _NATIVE_RECORD_VERIFIER_FIELDS
        or value.get("record_commitment_sha256")
        != _commitment(value, "record_commitment_sha256")
        or stat.S_IMODE(path.lstat().st_mode) != 0o444
    ):
        raise ValueError("native signer build record is invalid")
    try:
        spki = base64.b64decode(
            value["public_key"]["spki_der_base64"], validate=True
        )
    except (ValueError, TypeError):
        raise ValueError("native public key encoding is invalid") from None
    if (
        spki != _expected_rsa_spki(value["public_key"]["modulus_hex"])
        or _sha256(spki) != value["public_key"]["key_id"]
    ):
        raise ValueError("native public key fields disagree")
    expected_signers = {
        "receipt": (
            "receipt_signer", "scripts/run_test_receipt"
        ),
        "report": (
            "report_signer", "scripts/rerun_first_case_hard_gate"
        ),
        "live_enrichment": (
            "live_enrichment_signer", "scripts/run_fail_fast_enrich"
        ),
    }
    for name, (role, relative) in expected_signers.items():
        item = value["signers"][name]
        if (
            type(item) is not dict
            or set(item) != _NATIVE_RECORD_SIGNER_FIELDS
            or item.get("role") != role
            or item.get("file") != relative
            or _SHA256.fullmatch(str(item.get("build_sha256"))) is None
            or not _valid_identity(item.get("identity"), allow_symlink=False)
            or item["identity"].get("path") != relative
            or item["identity"].get("mode") != 0o111
            or item["identity"].get("sha256") != item["build_sha256"]
            or not _valid_native_elf(item.get("elf"))
        ):
            raise ValueError("native signer record entry is invalid")
        _opaque_identity(root / relative, item["identity"])
    verifier = value["verifier"]
    if (
        verifier.get("role") != "public_verifier"
        or verifier.get("file") != "scripts/verify_first_case_hard_gate"
        or _SHA256.fullmatch(str(verifier.get("sha256"))) is None
        or not _valid_identity(verifier.get("identity"), allow_symlink=False)
        or verifier["identity"].get("mode") != 0o555
        or verifier["identity"].get("sha256") != verifier["sha256"]
        or not _valid_native_elf(verifier.get("elf"))
    ):
        raise ValueError("native public verifier record entry is invalid")
    live_verifier = value["live_verifier"]
    if (
        live_verifier.get("role") != "live_enrichment_verifier"
        or live_verifier.get("file") != "scripts/verify_fail_fast_enrich"
        or _SHA256.fullmatch(str(live_verifier.get("sha256"))) is None
        or not _valid_identity(
            live_verifier.get("identity"), allow_symlink=False
        )
        or live_verifier["identity"].get("mode") != 0o555
        or live_verifier["identity"].get("sha256")
        != live_verifier["sha256"]
        or not _valid_native_elf(live_verifier.get("elf"))
    ):
        raise ValueError("native live verifier record entry is invalid")
    return value, identity


def _native_launcher_contract(root: Path) -> dict[str, Any]:
    record, record_identity = _native_build_record(root)
    source = root / "scripts/locked_launcher.c"
    build_script = root / "scripts/rebuild_locked_launchers"
    key_builder = root / "scripts/build_native_rsa_material.py"
    bootstrap = root / _BOOTSTRAP_RELATIVE
    compiler = Path("/usr/bin/gcc").resolve(strict=True)
    current_identities: list[dict[str, Any]] = []
    for path, display, reject_hardlink, limit in (
        (source, "scripts/locked_launcher.c", True, 1024 * 1024),
        (build_script, "scripts/rebuild_locked_launchers", True, 1024 * 1024),
        (key_builder, "scripts/build_native_rsa_material.py", True, 1024 * 1024),
        (compiler, str(compiler), False, 16 * 1024 * 1024),
    ):
        _, current = _read_regular(
            path,
            display_path=display,
            reject_hardlink=reject_hardlink,
            limit=limit,
        )
        current_identities.append(current)
    recorded_identities = [
        record["source_identity"], record["build_script_identity"],
        record["key_builder_identity"], record["compiler_identity"],
    ]
    if current_identities != recorded_identities:
        raise ValueError("native build inputs differ from public record")
    bootstrap_raw, bootstrap_identity = _read_regular(
        bootstrap,
        display_path=_BOOTSTRAP_RELATIVE.as_posix(),
        reject_hardlink=True,
        limit=1024 * 1024,
    )
    bootstrap_anchor = {
        "path": _BOOTSTRAP_RELATIVE.as_posix(),
        "mode": bootstrap_identity["mode"],
        "size": len(bootstrap_raw),
        "sha256": _sha256(bootstrap_raw),
    }
    if bootstrap_anchor != record["bootstrap_anchor"]:
        raise ValueError("native bootstrap differs from build record")
    verifier_elf = _elf_static_launcher(
        root / "scripts/verify_first_case_hard_gate", root=root
    )
    verifier_record = record["verifier"]
    if (
        verifier_elf["identity"] != verifier_record["identity"]
        or {field: verifier_elf[field] for field in _NATIVE_ELF_FIELDS}
        != verifier_record["elf"]
    ):
        raise ValueError("native public verifier differs from build record")
    live_verifier_elf = _elf_static_launcher(
        root / "scripts/verify_fail_fast_enrich", root=root
    )
    live_verifier_record = record["live_verifier"]
    if (
        live_verifier_elf["identity"] != live_verifier_record["identity"]
        or {
            field: live_verifier_elf[field] for field in _NATIVE_ELF_FIELDS
        }
        != live_verifier_record["elf"]
    ):
        raise ValueError("native live verifier differs from build record")
    launchers: dict[str, dict[str, Any]] = {}
    for name, item, read_policy in (
        ("receipt", record["signers"]["receipt"], "opaque-execute-only"),
        ("report_signer", record["signers"]["report"], "opaque-execute-only"),
        ("verifier", verifier_record, "readable-public-key-only"),
        (
            "live_enrichment_signer",
            record["signers"]["live_enrichment"],
            "opaque-execute-only",
        ),
        (
            "live_enrichment_verifier",
            live_verifier_record,
            "readable-public-key-only",
        ),
    ):
        elf = item["elf"]
        launchers[name] = {
            "file": item["file"],
            "role": item["role"],
            "read_policy": read_policy,
            "build_sha256": (
                item["build_sha256"]
                if "build_sha256" in item
                else item["sha256"]
            ),
            "identity": item["identity"],
            **elf,
        }
    public_outputs: list[tuple[str, ...]] = []
    for name in (
        "receipt", "report_signer", "verifier",
        "live_enrichment_signer", "live_enrichment_verifier",
    ):
        launcher = root / launchers[name]["file"]
        completed = _RUN_PROCESS(
            [str(launcher), "--native-public-contract"],
            cwd=root,
            env={
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8", "TZ": "UTC",
                "HOME": "/nonexistent", "TMPDIR": "/tmp",
            },
            capture_output=True,
            check=False,
            timeout=10,
        )
        match = _NATIVE_PUBLIC_CONTRACT.fullmatch(completed.stdout)
        if completed.returncode != 0 or completed.stderr or match is None:
            raise ValueError("native launcher public contract is invalid")
        public_outputs.append(
            tuple(match.group(index).decode("ascii") for index in range(1, 21))
        )
    python_runtime = record["python_runtime"]
    python_runtime_summary = _compact_python_runtime_contract(
        python_runtime, root=root
    )
    python_interpreter = python_runtime["interpreter"]
    expected_public = (
        record["public_key"]["key_id"], record["build_id"],
        record["native_contract_sha256"],
        str(root / _BOOTSTRAP_RELATIVE),
        record["bootstrap_anchor"]["sha256"],
        str(record["bootstrap_anchor"]["size"]),
        f"{record['bootstrap_anchor']['mode']:04o}",
        python_interpreter["path"],
        python_interpreter["sha256"],
        str(python_interpreter["size"]),
        f"{python_interpreter['mode']:04o}",
        str(python_interpreter["device"]),
        str(python_interpreter["inode"]),
        python_runtime_summary["manifest_sha256"],
        str(len(python_runtime["files"])),
        python_runtime_summary["startup_code"]["manifest_sha256"],
        str(python_runtime_summary["startup_code"]["file_count"]),
        str(python_runtime_summary["startup_code"]["directory_count"]),
        str(python_runtime_summary["startup_code"]["absent_path_count"]),
        str(python_runtime_summary["startup_code"]["total_bytes"]),
    )
    if set(public_outputs) != {expected_public}:
        raise ValueError("native launchers do not share the recorded contract")
    after_record, after_identity = _native_build_record(root)
    if after_record != record or after_identity != record_identity:
        raise ValueError("native build record changed during extraction")
    contract: dict[str, Any] = {
        "schema_version": "8.0",
        "source_file": "scripts/locked_launcher.c",
        "source_identity": current_identities[0],
        "build_script_file": "scripts/rebuild_locked_launchers",
        "build_script_identity": current_identities[1],
        "key_builder_file": "scripts/build_native_rsa_material.py",
        "key_builder_identity": current_identities[2],
        "build_record_file": _NATIVE_BUILD_RECORD_RELATIVE.as_posix(),
        "build_record_identity": record_identity,
        "build_record_commitment_sha256": record["record_commitment_sha256"],
        "compiler_file": str(compiler),
        "compiler_identity": current_identities[3],
        "compiler_flags": list(_NATIVE_COMPILER_FLAGS),
        "mode_defines": dict(record["mode_defines"]),
        "key_injection": record["key_injection"],
        "attestation_version": "2",
        "attestation_algorithm": record["algorithm"],
        "public_key_id": record["public_key"]["key_id"],
        "build_id": record["build_id"],
        "binary_contract_sha256": record["native_contract_sha256"],
        "bootstrap_anchor": bootstrap_anchor,
        "python_runtime_summary": python_runtime_summary,
        "launchers": launchers,
        "contract_sha256": "sha256:" + "0" * 64,
    }
    contract["contract_sha256"] = _commitment(contract, "contract_sha256")
    return contract


def _site_packages(prefix: Path) -> Path:
    current = prefix
    for component in (
        "lib",
        f"python{sys.version_info.major}.{sys.version_info.minor}",
        "site-packages",
    ):
        current = current / component
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("locked site-packages path is unsafe")
    return current.absolute()


def _distribution_contract(site_packages: Path, name: str) -> dict[str, str]:
    matches = sorted(site_packages.glob(f"{name}-*.dist-info"))
    if len(matches) != 1 or not matches[0].is_dir() or matches[0].is_symlink():
        raise ValueError("locked distribution metadata is ambiguous")
    metadata, _ = _read_regular(
        matches[0] / "METADATA", reject_hardlink=True, limit=4 * 1024 * 1024
    )
    headers: dict[str, str] = {}
    for line in metadata.decode("utf-8", "strict").splitlines():
        if not line:
            break
        key, separator, value = line.partition(":")
        if separator and key in {"Name", "Version"} and key not in headers:
            headers[key] = value.strip()
    if headers.get("Name", "").casefold() != name or not headers.get("Version"):
        raise ValueError("locked distribution metadata is invalid")
    module_file = site_packages / name / "__init__.py"
    _, module_identity = _read_regular(module_file, reject_hardlink=True)
    return {
        "name": name,
        "version": headers["Version"],
        "location": str(site_packages),
        "module_file": str(module_file),
        "module_file_sha256": module_identity["sha256"],
    }


def _require_execution_flags() -> None:
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.pycache_prefix == "/nonexistent/egsi-locked-pycache"
    ):
        raise ValueError("locked runtime requires pinned -X/-I/-B/-S")


def build_runtime_lock(root: str | Path) -> dict[str, Any]:
    """Build the exact current runtime value without importing site code."""

    _require_execution_flags()
    root_path = Path(root).resolve(strict=True)
    runner = (root_path / _RUNNER_RELATIVE).resolve(strict=True)
    expected_executable = runner / "bin/python"
    if Path(sys.executable).absolute() != expected_executable:
        raise ValueError("lock builder is not the fixed runner executable")
    resolved_executable = expected_executable.resolve(strict=True)
    executable_raw, executable_identity = _read_regular(
        resolved_executable,
        display_path=str(resolved_executable),
        reject_hardlink=True,
    )
    del executable_raw
    # ``-S`` deliberately prevents ``site`` from rewriting ``sys.prefix`` to
    # the venv.  The fixed command path is therefore the authoritative venv
    # prefix; ``sys.prefix``/``sys.base_prefix`` both describe the base
    # interpreter at this point.
    prefix = runner
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    if Path(sys.prefix).resolve(strict=True) != base_prefix or prefix == base_prefix:
        raise ValueError("isolated base interpreter identity is invalid")
    pyvenv_cfg = prefix / "pyvenv.cfg"
    pyvenv_raw, pyvenv_identity = _read_regular(
        pyvenv_cfg,
        display_path=str(pyvenv_cfg),
        reject_hardlink=True,
        limit=64 * 1024,
    )
    pyvenv_text = pyvenv_raw.decode("utf-8", "strict")
    include_system = any(
        line.strip().casefold() == "include-system-site-packages = true"
        for line in pyvenv_text.splitlines()
    )
    if include_system:
        raise ValueError("runner includes system site-packages")

    site_packages = _site_packages(prefix)
    site_inventory = _site_packages_inventory(site_packages)
    for item in site_inventory:
        name = Path(item["path"]).name
        if item["type"] == "regular" and (
            name in {"sitecustomize.py", "usercustomize.py"}
            or name.endswith(".pth")
        ):
            raise ValueError("startup hook in locked site-packages")
    site_tree_sha256 = _sha256(_canonical(site_inventory))

    stdlib_root = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    stdlib_inventory = _scan_tree(
        stdlib_root,
        reject_symlinks=False,
        reject_hardlinks=False,
        exclude=_stdlib_exclude,
    )
    stdlib_tree_sha256 = _sha256(_canonical(stdlib_inventory))
    stdlib_file_count = sum(
        item["type"] == "regular" for item in stdlib_inventory
    )

    source_root = (root_path / "src/egsi").resolve(strict=True)
    installed_root = (site_packages / "egsi").resolve(strict=True)
    source_tree_sha256 = _project_tree_content(source_root)
    installed_tree_sha256 = _project_tree_content(installed_root)
    if source_tree_sha256 != installed_tree_sha256:
        raise ValueError("installed project differs from committed source")
    native_launcher_contract = _native_launcher_contract(root_path)
    project_inventory = _project_inventory(root_path, native_launcher_contract)
    project_identity_sha256 = _sha256(_canonical(project_inventory))

    bootstrap = (root_path / _BOOTSTRAP_RELATIVE).resolve(strict=True)
    _, bootstrap_identity = _read_regular(
        bootstrap,
        display_path=str(bootstrap),
        reject_hardlink=True,
        limit=4 * 1024 * 1024,
    )
    config = (root_path / "pyproject.toml").resolve(strict=True)
    _, config_identity = _read_regular(
        config,
        display_path=str(config),
        reject_hardlink=True,
        limit=1024 * 1024,
    )
    base_sys_path = list(
        getattr(sys, "_egsi_locked_base_sys_path", tuple(sys.path))
    )
    if (
        not base_sys_path
        or any(type(item) is not str or not Path(item).is_absolute() for item in base_sys_path)
        or any(Path(item).is_relative_to(site_packages) for item in base_sys_path)
    ):
        raise ValueError("pre-site isolated sys.path is invalid")
    native_startup = native_launcher_contract["python_runtime_summary"][
        "startup_code"
    ]
    import_roots = native_startup["import_roots"]
    expected_state = import_roots["expected_isolated_state"]
    if (
        base_sys_path != expected_state["sys_path"]
        or str(Path(sys.prefix).absolute()) != expected_state["sys_prefix"]
        or str(Path(sys.base_prefix).absolute())
        != expected_state["sys_base_prefix"]
        or str(stdlib_root) != import_roots["stdlib_root"]["resolved_path"]
        or str(site_packages) not in {
            item["resolved_path"]
            for item in import_roots["site_packages_roots"]
        }
    ):
        raise ValueError("native Python import-root state is not exact")

    value: dict[str, Any] = {
        "schema_version": "8.0",
        "runner_contract_version": _CONTRACT_VERSION,
        "command_executable": str(expected_executable),
        "resolved_executable": str(resolved_executable),
        "executable_identity": executable_identity,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "sys_prefix": str(prefix),
        "sys_base_prefix": str(base_prefix),
        "pyvenv_cfg_identity": pyvenv_identity,
        "include_system_site_packages": False,
        "no_pth": True,
        "distributions": {
            name: _distribution_contract(site_packages, name)
            for name in ("pluggy", "pytest")
        },
        "site_packages_root": str(site_packages),
        "site_packages_inventory": site_inventory,
        "site_packages_tree_sha256": site_tree_sha256,
        "stdlib_root": str(stdlib_root),
        "stdlib_inventory": stdlib_inventory,
        "stdlib_tree_sha256": stdlib_tree_sha256,
        "stdlib_file_count": stdlib_file_count,
        "isolated_sys_path": base_sys_path,
        "project_source_tree_sha256": source_tree_sha256,
        "project_installed_tree_sha256": installed_tree_sha256,
        "project_inventory": project_inventory,
        "project_identity_sha256": project_identity_sha256,
        "native_launcher_contract": native_launcher_contract,
        "bootstrap_identity": bootstrap_identity,
        "canonical_config_file": "pyproject.toml",
        "canonical_config_identity": config_identity,
        "lock_commitment_sha256": "sha256:" + "0" * 64,
    }
    value["lock_commitment_sha256"] = _commitment(
        value, "lock_commitment_sha256"
    )
    validate_lock_schema(value)
    return value


def _valid_identity(item: object, *, allow_symlink: bool) -> bool:
    if type(item) is not dict or set(item) != _IDENTITY_FIELDS:
        return False
    if (
        type(item.get("path")) is not str
        or not item["path"]
        or item.get("type")
        not in ({"regular", "directory", "symlink"} if allow_symlink else {"regular", "directory"})
        or type(item.get("mode")) is not int
    ):
        return False
    for field in (
        "device",
        "inode",
        "links",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
    ):
        if type(item.get(field)) is not int or item[field] < 0:
            return False
    if item["links"] <= 0:
        return False
    return (
        item["sha256"] is None
        if item["type"] == "directory"
        else type(item["sha256"]) is str
        and _SHA256.fullmatch(item["sha256"]) is not None
    )


def _valid_native_launcher_contract(value: object) -> bool:
    if type(value) is not dict or set(value) != _NATIVE_CONTRACT_FIELDS:
        return False
    if (
        value.get("schema_version") != "8.0"
        or value.get("source_file") != "scripts/locked_launcher.c"
        or value.get("build_script_file")
        != "scripts/rebuild_locked_launchers"
        or value.get("key_builder_file")
        != "scripts/build_native_rsa_material.py"
        or value.get("build_record_file")
        != _NATIVE_BUILD_RECORD_RELATIVE.as_posix()
        or value.get("compiler_file") != "/usr/bin/gcc"
        or value.get("compiler_flags") != _NATIVE_COMPILER_FLAGS
        or value.get("mode_defines")
        != {
            "receipt_signer": "-DLAUNCH_KIND=1",
            "report_signer": "-DLAUNCH_KIND=2",
            "public_verifier": "-DLAUNCH_KIND=3",
            "live_enrichment_signer": "-DLAUNCH_KIND=4",
            "live_enrichment_verifier": "-DLAUNCH_KIND=5",
        }
        or value.get("key_injection")
        != "ephemeral-private-signer-header"
        or value.get("attestation_version") != "2"
        or value.get("attestation_algorithm")
        != "rsa-2048-sha256-pkcs1-v1_5"
        or _SHA256.fullmatch(str(value.get("public_key_id"))) is None
        or _SHA256.fullmatch(str(value.get("build_id"))) is None
        or _SHA256.fullmatch(str(value.get("binary_contract_sha256"))) is None
        or not _valid_python_runtime_summary(
            value.get("python_runtime_summary")
        )
        or type(value.get("bootstrap_anchor")) is not dict
        or set(value["bootstrap_anchor"]) != _NATIVE_BOOTSTRAP_ANCHOR_FIELDS
        or value["bootstrap_anchor"].get("path")
        != _BOOTSTRAP_RELATIVE.as_posix()
        or value["bootstrap_anchor"].get("mode") not in {0o444, 0o644}
        or type(value["bootstrap_anchor"].get("size")) is not int
        or not 1 <= value["bootstrap_anchor"]["size"] <= 1024 * 1024
        or _SHA256.fullmatch(
            str(value["bootstrap_anchor"].get("sha256"))
        ) is None
        or _SHA256.fullmatch(
            str(value.get("build_record_commitment_sha256"))
        ) is None
        or not _valid_identity(
            value.get("source_identity"), allow_symlink=False
        )
        or not _valid_identity(
            value.get("build_script_identity"), allow_symlink=False
        )
        or not _valid_identity(
            value.get("key_builder_identity"), allow_symlink=False
        )
        or not _valid_identity(
            value.get("build_record_identity"), allow_symlink=False
        )
        or not _valid_identity(
            value.get("compiler_identity"), allow_symlink=False
        )
        or type(value.get("launchers")) is not dict
        or set(value["launchers"])
        != {
            "receipt", "report_signer", "verifier",
            "live_enrichment_signer", "live_enrichment_verifier",
        }
    ):
        return False
    expected_files = {
        "receipt": "scripts/run_test_receipt",
        "report_signer": "scripts/rerun_first_case_hard_gate",
        "verifier": "scripts/verify_first_case_hard_gate",
        "live_enrichment_signer": "scripts/run_fail_fast_enrich",
        "live_enrichment_verifier": "scripts/verify_fail_fast_enrich",
    }
    expected_roles = {
        "receipt": ("receipt_signer", "opaque-execute-only", 0o111),
        "report_signer": ("report_signer", "opaque-execute-only", 0o111),
        "verifier": ("public_verifier", "readable-public-key-only", 0o555),
        "live_enrichment_signer": (
            "live_enrichment_signer", "opaque-execute-only", 0o111
        ),
        "live_enrichment_verifier": (
            "live_enrichment_verifier", "readable-public-key-only", 0o555
        ),
    }
    for name, launcher in value["launchers"].items():
        role, policy, mode = expected_roles[name]
        if (
            type(launcher) is not dict
            or set(launcher) != _NATIVE_LAUNCHER_FIELDS
            or launcher.get("file") != expected_files[name]
            or launcher.get("role") != role
            or launcher.get("read_policy") != policy
            or _SHA256.fullmatch(str(launcher.get("build_sha256"))) is None
            or not _valid_identity(
                launcher.get("identity"), allow_symlink=False
            )
            or launcher["identity"].get("mode") != mode
            or launcher["identity"].get("sha256")
            != launcher["build_sha256"]
            or not _valid_native_elf(
                {field: launcher.get(field) for field in _NATIVE_ELF_FIELDS}
            )
        ):
            return False
    return value.get("contract_sha256") == _commitment(
        value, "contract_sha256"
    )


def validate_lock_schema(value: dict[str, Any]) -> None:
    if (
        type(value) is not dict
        or set(value) != _LOCK_FIELDS
        or value.get("schema_version") != "8.0"
        or value.get("runner_contract_version") != _CONTRACT_VERSION
        or value.get("include_system_site_packages") is not False
        or value.get("no_pth") is not True
        or not _valid_identity(value.get("executable_identity"), allow_symlink=False)
        or not _valid_identity(value.get("pyvenv_cfg_identity"), allow_symlink=False)
        or not _valid_identity(value.get("bootstrap_identity"), allow_symlink=False)
        or not _valid_identity(value.get("canonical_config_identity"), allow_symlink=False)
        or type(value.get("site_packages_inventory")) is not list
        or not value["site_packages_inventory"]
        or any(
            not _valid_identity(item, allow_symlink=False)
            for item in value["site_packages_inventory"]
        )
        or type(value.get("stdlib_inventory")) is not list
        or not value["stdlib_inventory"]
        or any(
            not _valid_identity(item, allow_symlink=True)
            for item in value["stdlib_inventory"]
        )
        or value.get("site_packages_tree_sha256")
        != _sha256(_canonical(value["site_packages_inventory"]))
        or value.get("stdlib_tree_sha256")
        != _sha256(_canonical(value["stdlib_inventory"]))
        or type(value.get("stdlib_file_count")) is not int
        or value["stdlib_file_count"] <= 0
        or value["stdlib_file_count"]
        != sum(
            item["type"] == "regular" for item in value["stdlib_inventory"]
        )
        or type(value.get("distributions")) is not dict
        or set(value["distributions"]) != {"pluggy", "pytest"}
        or any(
            type(item) is not dict
            or set(item) != _DISTRIBUTION_FIELDS
            or item.get("name") != name
            or type(item.get("version")) is not str
            or not item["version"]
            or _SHA256.fullmatch(str(item.get("module_file_sha256"))) is None
            for name, item in value["distributions"].items()
        )
        or type(value.get("isolated_sys_path")) is not list
        or not value["isolated_sys_path"]
        or any(type(item) is not str or not Path(item).is_absolute() for item in value["isolated_sys_path"])
        or value.get("project_source_tree_sha256")
        != value.get("project_installed_tree_sha256")
        or type(value.get("project_inventory")) is not list
        or not value["project_inventory"]
        or any(
            not _valid_identity(item, allow_symlink=False)
            for item in value["project_inventory"]
        )
        or value.get("project_identity_sha256")
        != _sha256(_canonical(value["project_inventory"]))
        or not _valid_native_launcher_contract(
            value.get("native_launcher_contract")
        )
        or any(
            _SHA256.fullmatch(str(value.get(field))) is None
            for field in (
                "project_source_tree_sha256",
                "project_installed_tree_sha256",
            )
        )
        or value.get("lock_commitment_sha256")
        != _commitment(value, "lock_commitment_sha256")
    ):
        raise ValueError("offline runner lock schema is invalid")


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def write_runtime_lock(root: str | Path, value: dict[str, Any]) -> None:
    validate_lock_schema(value)
    root_path = Path(root).resolve(strict=True)
    path = root_path / _LOCK_RELATIVE
    parent = path.parent.resolve(strict=True)
    if parent != path.parent.absolute():
        raise ValueError("runner lock parent may not contain a symlink")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
    ):
        raise ValueError("runner lock destination is unsafe")
    raw = _canonical(value) + b"\n"
    if len(raw) > _MAX_LOCK_BYTES:
        raise ValueError("runner lock exceeds its byte bound")
    temporary = parent / (
        f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    committed, _ = _read_regular(
        path, reject_hardlink=True, limit=_MAX_LOCK_BYTES
    )
    if committed != raw or _strict_json(committed) != value:
        raise ValueError("runner lock readback mismatch")


def validate_runtime(
    root: str | Path,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """Fully re-read and compare the lock and every runtime closure entry."""

    _require_execution_flags()
    root_path = Path(root).resolve(strict=True)
    lock_path = root_path / _LOCK_RELATIVE
    raw_before, identity_before = _read_regular(
        lock_path, reject_hardlink=True, limit=_MAX_LOCK_BYTES
    )
    value = _strict_json(raw_before)
    if type(value) is not dict:
        raise ValueError("offline runner lock is not an object")
    validate_lock_schema(value)
    current = build_runtime_lock(root_path)
    raw_after, identity_after = _read_regular(
        lock_path, reject_hardlink=True, limit=_MAX_LOCK_BYTES
    )
    if raw_before != raw_after or identity_before != identity_after:
        raise ValueError("runner lock changed during validation")
    if value != current:
        raise ValueError("current runtime does not match offline runner lock")
    return value, _sha256(raw_after), identity_after


def _strict_value_arguments(
    arguments: list[str],
    *,
    value_options: dict[str, Callable[[str], bool]],
    flag_options: set[str],
) -> dict[str, int]:
    counts = {name: 0 for name in (*value_options, *flag_options)}
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in flag_options:
            counts[option] += 1
            if counts[option] != 1:
                raise ValueError("duplicate locked CLI flag")
            index += 1
            continue
        if option not in value_options or index + 1 >= len(arguments):
            raise ValueError("unknown or incomplete locked CLI option")
        value = arguments[index + 1]
        counts[option] += 1
        if counts[option] != 1 or not value_options[option](value):
            raise ValueError("duplicate or invalid locked CLI value")
        index += 2
    return counts


def _non_option(value: str) -> bool:
    return bool(value) and not value.startswith("--")


def _absolute_path(value: str) -> bool:
    return _non_option(value) and Path(value).is_absolute()


def _inherited_descriptor(value: str) -> bool:
    return (
        value.isdecimal()
        and len(value) <= 10
        and 3 <= int(value) <= 2_147_483_647
    )


def _strict_launcher_arguments(mode: str, arguments: list[str]) -> None:
    if arguments == ["--help"]:
        return
    if any(item == "--root" or item.startswith("--root=") for item in arguments):
        raise ValueError("launcher root injection is forbidden")
    if mode == "run-test-receipt":
        counts = _strict_value_arguments(
            arguments,
            value_options={
                "--name": lambda value: value in {"focused", "full"},
                "--output": _absolute_path,
            },
            flag_options=set(),
        )
        if counts != {"--name": 1, "--output": 1}:
            raise ValueError("receipt launcher options are incomplete")
        return
    if mode in {"rerun-first-case", "verify-first-case"}:
        rerun = mode == "rerun-first-case"
        counts = _strict_value_arguments(
            arguments,
            value_options={
                "--output-root": _absolute_path,
                "--case-id": _non_option,
                "--focused-receipt": _absolute_path,
                "--full-receipt": _absolute_path,
                "--report": _absolute_path,
                **(
                    {}
                    if rerun
                    else {"--mode": lambda value: value == "verify-only"}
                ),
            },
            flag_options={"--rerun-tests"} if rerun else set(),
        )
        for required in (
            "--output-root",
            "--case-id",
            "--focused-receipt",
            "--full-receipt",
            "--report",
        ):
            if counts[required] != 1:
                raise ValueError("verifier launcher options are incomplete")
        operation = "--rerun-tests" if rerun else "--mode"
        if counts[operation] != 1:
            raise ValueError("native gate operation is incomplete")
        return
    if mode in {
        "preflight-fail-fast-enrich",
        "run-fail-fast-enrich",
        "verify-fail-fast-enrich",
    }:
        preflight = mode == "preflight-fail-fast-enrich"
        execute = mode == "run-fail-fast-enrich"
        values: dict[str, Callable[[str], bool]] = {
            "--output-root": _absolute_path,
            "--attestation": _absolute_path,
            **{
                option: lambda value: _SHA256.fullmatch(value) is not None
                for option in _LIVE_NATIVE_HASH_OPTIONS
            },
        }
        if not preflight:
            values.update(
                {
                    "--case-file": _absolute_path,
                    "--scope-case-file": _absolute_path,
                }
            )
        if preflight:
            values.update(
                {
                    "--native-preflight-envelope": _absolute_path,
                    "--native-run-id": lambda value: re.fullmatch(
                        r"[0-9a-f]{64}", value
                    )
                    is not None,
                    "--native-nonce": lambda value: re.fullmatch(
                        r"[0-9a-f]{64}", value
                    )
                    is not None,
                    "--native-realtime-start-ns": lambda value: (
                        value.isdecimal() and len(value) <= 32
                    ),
                    "--native-monotonic-start-ns": lambda value: (
                        value.isdecimal() and len(value) <= 32
                    ),
                }
            )
        elif execute:
            values.update(
                {
                    "--provider-config": _absolute_path,
                    "--native-candidate-envelope": _absolute_path,
                    "--native-run-id": lambda value: re.fullmatch(
                        r"[0-9a-f]{64}", value
                    ) is not None,
                    "--native-nonce": lambda value: re.fullmatch(
                        r"[0-9a-f]{64}", value
                    ) is not None,
                    "--native-realtime-start-ns": lambda value: (
                        value.isdecimal() and len(value) <= 32
                    ),
                    "--native-monotonic-start-ns": lambda value: (
                        value.isdecimal() and len(value) <= 32
                    ),
                    "--native-pre-inventory-sha256": lambda value: (
                        _SHA256.fullmatch(value) is not None
                    ),
                    **{
                        option: lambda value: _SHA256.fullmatch(value)
                        is not None
                        for option in _LIVE_CURRENT_HASH_OPTIONS
                    },
                }
            )
        else:
            values["--mode"] = lambda value: value == "verify-only"
            if "--native-candidate-envelope" in arguments:
                values.update(
                    {
                        "--native-candidate-envelope": _absolute_path,
                        "--native-attestation-path": _absolute_path,
                        "--native-attestation-fd": _inherited_descriptor,
                        "--native-candidate-envelope-path": _absolute_path,
                        "--native-candidate-envelope-fd": _inherited_descriptor,
                        "--native-semantic-snapshot": _absolute_path,
                        "--native-semantic-snapshot-path": _absolute_path,
                        "--native-semantic-snapshot-fd": _inherited_descriptor,
                        "--native-run-id": lambda value: re.fullmatch(
                            r"[0-9a-f]{64}", value
                        )
                        is not None,
                        "--native-nonce": lambda value: re.fullmatch(
                            r"[0-9a-f]{64}", value
                        )
                        is not None,
                        "--native-realtime-start-ns": lambda value: (
                            value.isdecimal() and len(value) <= 32
                        ),
                        "--native-monotonic-start-ns": lambda value: (
                            value.isdecimal() and len(value) <= 32
                        ),
                        "--native-child-exit-code": lambda value: value
                        in {"0", "120"},
                        "--native-pre-inventory-sha256": lambda value: (
                            _SHA256.fullmatch(value) is not None
                        ),
                        **{
                            option: lambda value: _SHA256.fullmatch(value)
                            is not None
                            for option in _LIVE_CURRENT_HASH_OPTIONS
                        },
                    }
                )
            else:
                values.update(
                    {
                        "--native-attestation-path": _absolute_path,
                        "--native-attestation-fd": _inherited_descriptor,
                        "--native-attestation-sidecar-fd": _inherited_descriptor,
                        "--native-semantic-snapshot": _absolute_path,
                        "--native-semantic-snapshot-path": _absolute_path,
                        "--native-semantic-snapshot-fd": _inherited_descriptor,
                    }
                )
        counts = _strict_value_arguments(
            arguments, value_options=values, flag_options=set()
        )
        if any(count != 1 for count in counts.values()):
            raise ValueError("live launcher options are incomplete")
        return
    raise ValueError("unknown native launcher mode")


def _parse_mode(argv: list[str]) -> tuple[str, Path, list[str]]:
    if len(argv) < 3:
        raise ValueError("locked runtime mode/root are required")
    mode = argv[0]
    default_root = Path(__file__).resolve(strict=True).parents[1]
    if argv[1] != "--root" or argv[2] != str(default_root):
        raise ValueError("locked runtime root must be exactly singleton")
    root = Path(argv[2]).resolve(strict=True)
    remaining = argv[3:]
    root_tokens = [
        item
        for item in remaining
        if item == "--root" or item.startswith("--root=")
    ]
    if root_tokens:
        raise ValueError("duplicate locked runtime root")
    if mode in {
        "rerun-first-case", "verify-first-case", "run-test-receipt", "pytest",
        "preflight-fail-fast-enrich", "run-fail-fast-enrich",
        "verify-fail-fast-enrich",
    }:
        if not remaining or remaining[0] != "--":
            raise ValueError("locked runtime separator is required")
        remaining = remaining[1:]
    elif remaining[:1] == ["--"]:
        remaining = remaining[1:]
    if mode in {
        "rerun-first-case", "verify-first-case", "run-test-receipt",
        "preflight-fail-fast-enrich", "run-fail-fast-enrich",
        "verify-fail-fast-enrich",
    }:
        _strict_launcher_arguments(mode, remaining)
    return mode, root, remaining


def _exit_code(error: SystemExit) -> int:
    if error.code is None:
        return 0
    # pytest raises SystemExit with its IntEnum ExitCode, not always an exact
    # ``int``.  Preserve the numeric code instead of turning ExitCode.OK into
    # a false failure.
    if isinstance(error.code, int):
        return int(error.code)
    return 1


def _argument_values(arguments: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        if index + 1 >= len(arguments):
            raise ValueError("locked argument value is missing")
        result[arguments[index]] = arguments[index + 1]
    return result


_LIVE_NATIVE_HASH_OPTIONS = (
    "--native-bootstrap-sha256",
    "--native-focused-receipt-sha256",
    "--native-focused-sidecar-sha256",
    "--native-full-receipt-sha256",
    "--native-full-sidecar-sha256",
    "--native-binary-contract-sha256",
    "--native-public-key-id",
)
_LIVE_CURRENT_HASH_OPTIONS = (
    "--native-runner-lock-sha256",
    "--native-project-identity-sha256",
    "--native-canonical-test-contract-sha256",
    "--native-launcher-contract-sha256",
)


def _read_live_anchor_file(path: Path, *, limit: int) -> tuple[bytes, str]:
    raw, identity = _read_regular(
        path, reject_hardlink=True, limit=limit
    )
    if identity["mode"] != 0o600:
        raise ValueError("live trust anchor file mode is invalid")
    return raw, _sha256(raw)


def _live_receipt_trust_anchors(
    *,
    root: Path,
    output_root: Path,
    values: dict[str, str],
    lock: dict[str, Any],
    lock_sha256: str,
) -> dict[str, Any]:
    from egsi.generation.test_receipt import validate_test_receipt

    output_root = Path(output_root).absolute()
    focused_path = output_root / "reports/offline-focused-receipt.json"
    full_path = output_root / "reports/offline-full-receipt.json"
    focused_sidecar = Path(str(focused_path) + ".native-attestation")
    full_sidecar = Path(str(full_path) + ".native-attestation")
    focused_raw, focused_sha = _read_live_anchor_file(
        focused_path, limit=8 * 1024 * 1024
    )
    full_raw, full_sha = _read_live_anchor_file(
        full_path, limit=8 * 1024 * 1024
    )
    _, focused_sidecar_sha = _read_live_anchor_file(
        focused_sidecar, limit=4096
    )
    _, full_sidecar_sha = _read_live_anchor_file(full_sidecar, limit=4096)
    supplied = {
        "bootstrap_sha256": values["--native-bootstrap-sha256"],
        "focused_receipt_sha256": values[
            "--native-focused-receipt-sha256"
        ],
        "focused_sidecar_sha256": values[
            "--native-focused-sidecar-sha256"
        ],
        "full_receipt_sha256": values["--native-full-receipt-sha256"],
        "full_sidecar_sha256": values["--native-full-sidecar-sha256"],
        "native_contract_sha256": values[
            "--native-binary-contract-sha256"
        ],
        "public_key_id": values["--native-public-key-id"],
    }
    native = lock["native_launcher_contract"]
    bootstrap_anchor = native["bootstrap_anchor"]
    expected = {
        "bootstrap_sha256": bootstrap_anchor["sha256"],
        "focused_receipt_sha256": focused_sha,
        "focused_sidecar_sha256": focused_sidecar_sha,
        "full_receipt_sha256": full_sha,
        "full_sidecar_sha256": full_sidecar_sha,
        "native_contract_sha256": native["binary_contract_sha256"],
        "public_key_id": native["public_key_id"],
    }
    if supplied != expected:
        raise ValueError("native live receipt byte anchors disagree")
    focused = validate_test_receipt(
        focused_path, root=root, expected_name="focused", require_success=True
    )
    full = validate_test_receipt(
        full_path, root=root, expected_name="full", require_success=True
    )
    focused_runner = focused["runner"]
    full_runner = full["runner"]
    receipt_fields = (
        "runner_lock_sha256",
        "project_identity_sha256",
        "canonical_test_contract_sha256",
        "native_launcher_contract_sha256",
        "native_binary_contract_sha256",
        "native_public_key_id",
    )
    if any(
        focused_runner[field] != full_runner[field] for field in receipt_fields
    ):
        raise ValueError("focused/full receipt trust anchors disagree")
    current = {
        "runner_lock_sha256": lock_sha256,
        "project_identity_sha256": lock["project_identity_sha256"],
        "canonical_test_contract_sha256": focused_runner[
            "canonical_test_contract_sha256"
        ],
        "native_launcher_contract_sha256": native["contract_sha256"],
    }
    if (
        focused_runner["runner_lock_sha256"] != current["runner_lock_sha256"]
        or focused_runner["project_identity_sha256"]
        != current["project_identity_sha256"]
        or focused_runner["native_launcher_contract_sha256"]
        != current["native_launcher_contract_sha256"]
        or focused_runner["native_binary_contract_sha256"]
        != expected["native_contract_sha256"]
        or focused_runner["native_public_key_id"] != expected["public_key_id"]
    ):
        raise ValueError("test receipts are not current for the locked runtime")
    for option, field in zip(
        _LIVE_CURRENT_HASH_OPTIONS,
        (
            "runner_lock_sha256",
            "project_identity_sha256",
            "canonical_test_contract_sha256",
            "native_launcher_contract_sha256",
        ),
        strict=True,
    ):
        if option in values and values[option] != current[field]:
            raise ValueError("native current-runtime anchor disagrees")
    return {
        **expected,
        **current,
        "bootstrap_size": bootstrap_anchor["size"],
        "bootstrap_mode": bootstrap_anchor["mode"],
    }


def _atomic_private_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short locked preflight write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_live_preflight_envelope(
    *, path: Path, values: dict[str, str], anchors: dict[str, Any], pre_sha: str
) -> None:
    fields = (
        ("run_id", values["--native-run-id"]),
        ("nonce", values["--native-nonce"]),
        ("realtime_start_ns", values["--native-realtime-start-ns"]),
        ("monotonic_start_ns", values["--native-monotonic-start-ns"]),
        ("pre_inventory_sha256", pre_sha),
        ("bootstrap_sha256", anchors["bootstrap_sha256"]),
        ("focused_receipt_sha256", anchors["focused_receipt_sha256"]),
        ("focused_sidecar_sha256", anchors["focused_sidecar_sha256"]),
        ("full_receipt_sha256", anchors["full_receipt_sha256"]),
        ("full_sidecar_sha256", anchors["full_sidecar_sha256"]),
        ("runner_lock_sha256", anchors["runner_lock_sha256"]),
        ("project_identity_sha256", anchors["project_identity_sha256"]),
        (
            "canonical_test_contract_sha256",
            anchors["canonical_test_contract_sha256"],
        ),
        (
            "native_launcher_contract_sha256",
            anchors["native_launcher_contract_sha256"],
        ),
        ("native_binary_contract_sha256", anchors["native_contract_sha256"]),
        ("public_key_id", anchors["public_key_id"]),
    )
    raw = (
        "EGSI-LIVE-PREFLIGHT-V1\n"
        + "".join(f"{name}={value}\n" for name, value in fields)
    ).encode("ascii", "strict")
    if len(raw) > 4096:
        raise ValueError("live preflight envelope exceeds its bound")
    _atomic_private_bytes(path, raw)


def _live_inventory_snapshot(output_root: Path) -> list[dict[str, Any]]:
    roots = (
        Path("audit/teacher"), Path("cache/teacher"), Path("enrichment"),
        Path("reports/remaining-p0"), Path("reports/enrichment-summary.json"),
    )
    attestation = output_root / (
        "reports/remaining-p0/fail-fast-live-attestation.json"
    )
    excluded = {
        attestation,
        Path(str(attestation) + ".native-attestation"),
        Path(str(attestation) + ".native-preflight"),
        Path(str(attestation) + ".native-candidate"),
        Path(str(attestation) + ".native-snapshot"),
    }
    try:
        output_info = output_root.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(output_info.st_mode) or stat.S_ISLNK(output_info.st_mode):
        raise ValueError("live inventory output root is unsafe")
    result: list[dict[str, Any]] = []

    def append_file(path: Path) -> None:
        raw, identity = _read_regular(
            path, reject_hardlink=True, limit=16 * 1024 * 1024
        )
        result.append(
            {
                "relative_path": path.relative_to(output_root).as_posix(),
                "mode": identity["mode"],
                "size": len(raw),
                "sha256": identity["sha256"],
            }
        )
        if len(result) > 8192:
            raise ValueError("live inventory exceeds its file bound")

    def walk(directory: Path) -> None:
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ValueError("live inventory directory is unsafe")
        with os.scandir(directory) as stream:
            children = sorted(stream, key=lambda item: item.name)
        for child in children:
            path = directory / child.name
            if path in excluded:
                continue
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                walk(path)
            elif stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                append_file(path)
            else:
                raise ValueError(
                    "live inventory contains a symlink or special node"
                )
        if _identity_tuple(before) != _identity_tuple(directory.lstat()):
            raise ValueError("live inventory directory changed during scan")

    def target(relative: Path) -> Path | None:
        final = output_root / relative
        current = output_root
        for component in relative.parts:
            current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                return None
            if current != final and (
                not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            ):
                raise ValueError("live inventory parent is unsafe")
        return current

    for relative in roots:
        path = target(relative)
        if path is None or path in excluded:
            continue
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            append_file(path)
        elif stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            walk(path)
        else:
            raise ValueError("live inventory root is unsafe")
    if _identity_tuple(output_info) != _identity_tuple(output_root.lstat()):
        raise ValueError("live inventory output root changed during scan")
    return sorted(result, key=lambda item: item["relative_path"])


def _dispatch(mode: str, root: Path, arguments: list[str]) -> int:
    base_sys_path = tuple(sys.path)
    lock, lock_sha256, _ = validate_runtime(root)
    if arguments == ["--help"] and mode in {
        "run-fail-fast-enrich", "verify-fail-fast-enrich"
    }:
        command = mode.replace("-", "_")
        print(f"usage: {command} [locked native options]")
        return 0
    sys._egsi_locked_base_sys_path = base_sys_path
    live_pre_inventory = None
    if mode == "run-fail-fast-enrich":
        live_values = _argument_values(arguments)
        live_pre_inventory = _live_inventory_snapshot(
            Path(live_values["--output-root"]).absolute()
        )
    source = str((root / "src").resolve(strict=True))
    site_packages = lock["site_packages_root"]
    expected_path = [source, site_packages, *base_sys_path]
    sys.path[:] = expected_path
    sys._egsi_locked_runtime_bootstrap = (str(root), mode)
    # Site/project code must reuse this already-loaded validator.  Reloading
    # the bootstrap from its path after site code runs would execute a file
    # that may have changed before its identity was checked.
    sys._egsi_locked_runtime_validation = (str(root), validate_runtime)

    exit_code = 0
    try:
        if mode == "pytest":
            sys.argv = ["pytest", *arguments]
            runpy.run_module("pytest", run_name="__main__", alter_sys=True)
        elif mode in {"rerun-first-case", "verify-first-case"}:
            from egsi.generation.first_case_hard_gate import (
                first_case_cli_main,
            )

            exit_code = first_case_cli_main(arguments, root=root)
        elif mode == "run-test-receipt":
            from egsi.generation.test_receipt import receipt_cli_main

            exit_code = receipt_cli_main(arguments, root=root)
        elif mode == "preflight-fail-fast-enrich":
            values = _argument_values(arguments)
            output_root = Path(values["--output-root"]).absolute()
            attestation_path = Path(values["--attestation"]).absolute()
            preflight_path = Path(
                values["--native-preflight-envelope"]
            ).absolute()
            if (
                attestation_path
                != output_root
                / "reports/remaining-p0/fail-fast-live-attestation.json"
                or preflight_path
                != Path(str(attestation_path) + ".native-preflight")
                or values["--native-run-id"] == values["--native-nonce"]
            ):
                raise ValueError("live preflight paths or nonce are invalid")
            anchors = _live_receipt_trust_anchors(
                root=root,
                output_root=output_root,
                values=values,
                lock=lock,
                lock_sha256=lock_sha256,
            )
            pre_inventory = _live_inventory_snapshot(output_root)
            _write_live_preflight_envelope(
                path=preflight_path,
                values=values,
                anchors=anchors,
                pre_sha=_sha256(_canonical(pre_inventory)),
            )
        elif mode == "run-fail-fast-enrich":
            from egsi.generation.live_attestation import (
                execute_locked_live_enrichment,
            )

            values = _argument_values(arguments)
            anchors = _live_receipt_trust_anchors(
                root=root,
                output_root=Path(values["--output-root"]),
                values=values,
                lock=lock,
                lock_sha256=lock_sha256,
            )
            if (
                _sha256(_canonical(live_pre_inventory))
                != values["--native-pre-inventory-sha256"]
                or values["--native-run-id"] == values["--native-nonce"]
                or Path(values["--native-candidate-envelope"]).absolute()
                != Path(str(Path(values["--attestation"]).absolute()) + ".native-candidate")
            ):
                raise ValueError("live native preflight binding changed")
            live_attestation = execute_locked_live_enrichment(
                root=root,
                output_root=Path(values["--output-root"]),
                case_file=Path(values["--case-file"]),
                scope_case_file=Path(values["--scope-case-file"]),
                provider_config=Path(values["--provider-config"]),
                attestation_path=Path(values["--attestation"]),
                candidate_envelope_path=Path(
                    values["--native-candidate-envelope"]
                ),
                run_id=values["--native-run-id"],
                nonce=values["--native-nonce"],
                realtime_start_ns=int(values["--native-realtime-start-ns"]),
                monotonic_start_ns=int(values["--native-monotonic-start-ns"]),
                pre_inventory=live_pre_inventory,
                trust_anchors=anchors,
            )
            exit_code = int(live_attestation["child_exit_code"])
        elif mode == "verify-fail-fast-enrich":
            from egsi.generation.live_attestation import (
                verify_locked_live_enrichment,
                verify_live_semantic_snapshot_against_live,
            )

            values = _argument_values(arguments)
            candidate = values.get("--native-candidate-envelope")
            attestation_raw = None
            candidate_raw = None
            candidate_path = None
            semantic_snapshot_fd = int(
                values["--native-semantic-snapshot-fd"]
            )
            semantic_snapshot_path = Path(
                values["--native-semantic-snapshot-path"]
            ).absolute()
            if (
                values["--native-semantic-snapshot"]
                != f"/proc/self/fd/{semantic_snapshot_fd}"
            ):
                raise ValueError("live native semantic snapshot descriptor disagrees")
            semantic_snapshot_raw = _read_inherited_regular_fd(
                semantic_snapshot_fd, limit=16 * 1024 * 1024
            )
            if candidate is None:
                attestation_fd = int(values["--native-attestation-fd"])
                sidecar_fd = int(values["--native-attestation-sidecar-fd"])
                if (
                    len({attestation_fd, sidecar_fd, semantic_snapshot_fd}) != 3
                    or values["--attestation"]
                    != f"/proc/self/fd/{attestation_fd}"
                ):
                    raise ValueError("live native held descriptors disagree")
                attestation_path = Path(
                    values["--native-attestation-path"]
                ).absolute()
                if attestation_path != Path(values["--output-root"]).absolute() / (
                    "reports/remaining-p0/fail-fast-live-attestation.json"
                ):
                    raise ValueError("live native attestation path is not canonical")
                if semantic_snapshot_path != Path(
                    str(attestation_path) + ".native-snapshot"
                ):
                    raise ValueError("live native semantic snapshot path is not canonical")
                attestation_raw = _read_inherited_regular_fd(
                    attestation_fd, limit=16 * 1024 * 1024
                )
                sidecar_raw = _read_inherited_regular_fd(
                    sidecar_fd, limit=4096
                )
                artifact_digest_line = (
                    "artifact_sha256="
                    + hashlib.sha256(attestation_raw).hexdigest()
                    + "\n"
                ).encode("ascii")
                if sidecar_raw.count(artifact_digest_line) != 1:
                    raise ValueError("live native held sidecar digest disagrees")
            else:
                attestation_fd = int(values["--native-attestation-fd"])
                candidate_fd = int(
                    values["--native-candidate-envelope-fd"]
                )
                if (
                    len(
                        {attestation_fd, candidate_fd, semantic_snapshot_fd}
                    )
                    != 3
                    or values["--attestation"]
                    != f"/proc/self/fd/{attestation_fd}"
                    or candidate != f"/proc/self/fd/{candidate_fd}"
                ):
                    raise ValueError("live native candidate descriptors disagree")
                attestation_path = Path(
                    values["--native-attestation-path"]
                ).absolute()
                candidate_path = Path(
                    values["--native-candidate-envelope-path"]
                ).absolute()
                expected_attestation = Path(values["--output-root"]).absolute() / (
                    "reports/remaining-p0/fail-fast-live-attestation.json"
                )
                if (
                    attestation_path != expected_attestation
                    or candidate_path
                    != Path(str(expected_attestation) + ".native-candidate")
                    or semantic_snapshot_path
                    != Path(str(expected_attestation) + ".native-snapshot")
                ):
                    raise ValueError("live native candidate path is not canonical")
                attestation_raw = _read_inherited_regular_fd(
                    attestation_fd, limit=16 * 1024 * 1024
                )
                candidate_raw = _read_inherited_regular_fd(
                    candidate_fd, limit=4096
                )
            anchors = _live_receipt_trust_anchors(
                root=root,
                output_root=Path(values["--output-root"]),
                values=values,
                lock=lock,
                lock_sha256=lock_sha256,
            )
            semantic_value = json.loads(attestation_raw.decode("utf-8", "strict"))
            if type(semantic_value) is not dict:
                raise ValueError("live native attestation is not an object")
            verify_live_semantic_snapshot_against_live(
                semantic_snapshot_raw,
                expected_sha256=semantic_value.get("semantic_snapshot_sha256"),
                source_root=root,
                output_root=Path(values["--output-root"]),
            )
            verified = verify_locked_live_enrichment(
                root=root,
                output_root=Path(values["--output-root"]),
                case_file=Path(values["--case-file"]),
                scope_case_file=Path(values["--scope-case-file"]),
                attestation_path=attestation_path,
                attestation_raw=attestation_raw,
                candidate_envelope_path=candidate_path,
                candidate_envelope_raw=candidate_raw,
                semantic_snapshot_path=semantic_snapshot_path,
                semantic_snapshot_raw=semantic_snapshot_raw,
                expected_trust_anchors=anchors,
            )
            verify_live_semantic_snapshot_against_live(
                semantic_snapshot_raw,
                expected_sha256=verified["semantic_snapshot_sha256"],
                source_root=root,
                output_root=Path(values["--output-root"]),
            )
            if candidate is not None and (
                verified["run_id"] != values["--native-run-id"]
                or verified["nonce"] != values["--native-nonce"]
                or verified["realtime_start_ns"]
                != int(values["--native-realtime-start-ns"])
                or verified["monotonic_start_ns"]
                != int(values["--native-monotonic-start-ns"])
                or verified["child_exit_code"]
                != int(values["--native-child-exit-code"])
                or verified["pre_inventory_sha256"]
                != values["--native-pre-inventory-sha256"]
            ):
                raise ValueError("live native candidate metadata disagrees")
        elif mode == "probe":
            print("locked-runtime-probe-ok")
        else:
            raise ValueError("unknown locked runtime mode")
    except SystemExit as error:
        exit_code = _exit_code(error)
    except BaseException:
        traceback.print_exc()
        exit_code = 120

    try:
        if sys.path != expected_path:
            raise ValueError("site code changed the locked sys.path")
        validate_runtime(root)
    except BaseException:
        traceback.print_exc()
        exit_code = 121
    return exit_code


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        mode, root, remaining = _parse_mode(arguments)
        if mode == "build-lock":
            if remaining:
                raise ValueError("build-lock takes no trailing arguments")
            value = build_runtime_lock(root)
            write_runtime_lock(root, value)
            print(
                json.dumps(
                    {
                        "lock_commitment_sha256": value[
                            "lock_commitment_sha256"
                        ],
                        "runner_contract_version": value[
                            "runner_contract_version"
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        return _dispatch(mode, root, remaining)
    except BaseException:
        traceback.print_exc()
        return 122


if __name__ == "__main__":
    raise SystemExit(main())
