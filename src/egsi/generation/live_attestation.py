"""Inventory-bound payload signed by the native live-enrichment launcher."""

from __future__ import annotations

import hashlib
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import tempfile
import stat
import time
from typing import Any, Iterator


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
_MAX_FILES = 8192
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_SEMANTIC_SNAPSHOT_BYTES = 16 * 1024 * 1024
_MAX_GIT_QUERIES = 4096
_MAX_GIT_STORES = 1024
_ATTESTATION_RELATIVE = Path(
    "reports/remaining-p0/fail-fast-live-attestation.json"
)
_INVENTORY_ROOTS = (
    Path("audit/teacher"),
    Path("cache/teacher"),
    Path("enrichment"),
    Path("reports/remaining-p0"),
    Path("reports/enrichment-summary.json"),
)
_REQUIRED_ARTIFACT_PATHS = (
    "reports/remaining-p0/fail-fast-report.json",
    "enrichment/_batch-provenance.json",
    "reports/enrichment-summary.json",
)
_SEMANTIC_SNAPSHOT_SUFFIX = ".native-snapshot"
_SEMANTIC_OUTPUT_VOLATILE_DIRECTORIES = {
    _ATTESTATION_RELATIVE.parent.as_posix(),
    _ATTESTATION_RELATIVE.parent.parent.as_posix(),
}
_SEMANTIC_SOURCE_ROOTS = (
    Path("src"),
    Path("tests"),
    Path("configs"),
    Path("idea-stage"),
)
_HISTORICAL_SEMANTIC_CASE_IDS = (
    "ghsa-2m8h-fgr8-2q9w",
    "ghsa-3wfj-vh84-732p",
)
_TRUST_ANCHOR_FIELDS = {
    "bootstrap_sha256",
    "bootstrap_size",
    "bootstrap_mode",
    "focused_receipt_sha256",
    "focused_sidecar_sha256",
    "full_receipt_sha256",
    "full_sidecar_sha256",
    "runner_lock_sha256",
    "project_identity_sha256",
    "canonical_test_contract_sha256",
    "native_launcher_contract_sha256",
    "native_contract_sha256",
    "public_key_id",
}


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


def _commitment(value: dict[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return _sha256(_canonical(copy))


def _safe_file(path: Path) -> tuple[bytes, os.stat_result]:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > _MAX_FILE_BYTES
    ):
        raise ValueError("live inventory contains an unsafe file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            stat.S_IFMT(observed.st_mode),
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            stat.S_IFMT(before.st_mode),
        ):
            raise ValueError("live inventory file changed before read")
        chunks: list[bytes] = []
        remaining = observed.st_size
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                raise ValueError("live inventory file was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("live inventory file grew during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_nlink,
        observed.st_uid,
        observed.st_gid,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    ) or (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_mode,
        after_path.st_nlink,
        after_path.st_uid,
        after_path.st_gid,
        after_path.st_size,
        after_path.st_mtime_ns,
        after_path.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError("live inventory file changed during read")
    return b"".join(chunks), after


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _snapshot_tree(
    *,
    root: Path,
    directory: Path,
    excluded: set[Path],
    result: list[dict[str, Any]],
) -> None:
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
            _snapshot_tree(
                root=root,
                directory=path,
                excluded=excluded,
                result=result,
            )
        elif stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            raw, observed = _safe_file(path)
            result.append(
                {
                    "relative_path": path.relative_to(root).as_posix(),
                    "mode": stat.S_IMODE(observed.st_mode),
                    "size": len(raw),
                    "sha256": _sha256(raw),
                }
            )
            if len(result) > _MAX_FILES:
                raise ValueError("live inventory file count exceeds its bound")
        else:
            raise ValueError("live inventory contains a symlink or special node")
    after = directory.lstat()
    if _directory_identity(before) != _directory_identity(after):
        raise ValueError("live inventory directory changed during scan")


def _safe_inventory_target(root: Path, relative: Path) -> Path | None:
    current = root
    for component in relative.parts:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            return None
        if current != root / relative and (
            not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        ):
            raise ValueError("live inventory parent is unsafe")
    return current


def inventory_snapshot(output_root: Path) -> list[dict[str, Any]]:
    """Snapshot the complete teacher/enrichment/report evidence surface."""

    root = Path(output_root).absolute()
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ValueError("live inventory output root is unsafe")
    result: list[dict[str, Any]] = []
    excluded = {
        root / _ATTESTATION_RELATIVE,
        Path(str(root / _ATTESTATION_RELATIVE) + ".native-attestation"),
        Path(str(root / _ATTESTATION_RELATIVE) + ".native-preflight"),
        Path(str(root / _ATTESTATION_RELATIVE) + ".native-candidate"),
        Path(str(root / _ATTESTATION_RELATIVE) + _SEMANTIC_SNAPSHOT_SUFFIX),
    }
    for relative in _INVENTORY_ROOTS:
        path = _safe_inventory_target(root, relative)
        if path is None or path in excluded:
            continue
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            raw, observed = _safe_file(path)
            result.append(
                {
                    "relative_path": path.relative_to(root).as_posix(),
                    "mode": stat.S_IMODE(observed.st_mode),
                    "size": len(raw),
                    "sha256": _sha256(raw),
                }
            )
        elif stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            _snapshot_tree(
                root=root,
                directory=path,
                excluded=excluded,
                result=result,
            )
        else:
            raise ValueError("live inventory root is unsafe")
    if len(result) > _MAX_FILES:
        raise ValueError("live inventory file count exceeds its bound")
    if _directory_identity(root_info) != _directory_identity(root.lstat()):
        raise ValueError("live inventory output root changed during scan")
    return sorted(result, key=lambda item: item["relative_path"])


def _inventory_map(value: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if type(value) is not list:
        raise ValueError("live inventory is invalid")
    result: dict[str, dict[str, Any]] = {}
    previous = ""
    for item in value:
        if (
            type(item) is not dict
            or set(item) != {"relative_path", "mode", "size", "sha256"}
            or type(item.get("relative_path")) is not str
            or not item["relative_path"]
            or Path(item["relative_path"]).is_absolute()
            or ".." in Path(item["relative_path"]).parts
            or item["relative_path"] <= previous
            or type(item.get("mode")) is not int
            or not 0 <= item["mode"] <= 0o7777
            or type(item.get("size")) is not int
            or not 0 <= item["size"] <= _MAX_FILE_BYTES
            or _SHA256.fullmatch(str(item.get("sha256"))) is None
        ):
            raise ValueError("live inventory entry is invalid")
        previous = item["relative_path"]
        result[previous] = item
    return result


def _delta(
    pre: list[dict[str, Any]], post: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    before = _inventory_map(pre)
    after = _inventory_map(post)
    return {
        "created": [after[path] for path in sorted(after.keys() - before.keys())],
        "modified": [
            {"before": before[path], "after": after[path]}
            for path in sorted(before.keys() & after.keys())
            if before[path] != after[path]
        ],
        "deleted": [before[path] for path in sorted(before.keys() - after.keys())],
    }


def build_live_attestation(
    *,
    output_root: Path,
    case_file_sha256: str,
    scope_case_file_sha256: str,
    requested_case_ids: list[str],
    current_manifest_paths: list[str],
    current_response_commitments: list[str | None],
    current_cache_paths: list[str | None],
    run_id: str,
    nonce: str,
    realtime_start_ns: int,
    monotonic_start_ns: int,
    realtime_end_ns: int,
    monotonic_end_ns: int,
    child_exit_code: int,
    recovery_mode: str,
    target_reason: str,
    bootstrap_sha256: str,
    bootstrap_size: int,
    bootstrap_mode: int,
    focused_receipt_sha256: str,
    focused_sidecar_sha256: str,
    full_receipt_sha256: str,
    full_sidecar_sha256: str,
    runner_lock_sha256: str,
    project_identity_sha256: str,
    canonical_test_contract_sha256: str,
    native_launcher_contract_sha256: str,
    native_contract_sha256: str,
    public_key_id: str,
    provider_executable_identities: list[str],
    pre_inventory: list[dict[str, Any]],
    post_inventory: list[dict[str, Any]],
    semantic_snapshot_sha256: str = "sha256:" + "0" * 64,
) -> dict[str, Any]:
    before = _inventory_map(pre_inventory)
    after = _inventory_map(post_inventory)
    delta = _delta(pre_inventory, post_inventory)
    created_paths = {item["relative_path"] for item in delta["created"]}
    if any(path in before or path not in after or path not in created_paths for path in current_manifest_paths):
        raise ValueError("current attempt exists in the prebaseline or outside postdelta")
    if any(
        path is not None
        and (path in before or path not in after or path not in created_paths)
        for path in current_cache_paths
    ):
        raise ValueError("current response cache exists in the prebaseline")
    if any(path not in after for path in _REQUIRED_ARTIFACT_PATHS):
        raise ValueError("required live artifact is missing")
    artifact_hashes = {
        path: after[path]["sha256"] for path in _REQUIRED_ARTIFACT_PATHS
    }
    value: dict[str, Any] = {
        "schema_version": "4.0",
        "attestation_kind": "native_fail_fast_live_enrichment",
        "terminal_status": "PASS" if child_exit_code == 0 else "STOP",
        "output_root": str(Path(output_root).absolute()),
        "run_id": run_id,
        "nonce": nonce,
        "realtime_start_ns": realtime_start_ns,
        "monotonic_start_ns": monotonic_start_ns,
        "realtime_end_ns": realtime_end_ns,
        "monotonic_end_ns": monotonic_end_ns,
        "child_exit_code": child_exit_code,
        "case_file_sha256": case_file_sha256,
        "scope_case_file_sha256": scope_case_file_sha256,
        "requested_case_ids": requested_case_ids,
        "contiguous_case_digest": _sha256(_canonical(requested_case_ids)),
        "recovery_mode": recovery_mode,
        "target_reason": target_reason,
        "current_manifest_paths": current_manifest_paths,
        "current_response_commitments": current_response_commitments,
        "current_cache_paths": current_cache_paths,
        "provider_executable_identities": provider_executable_identities,
        "pre_inventory": pre_inventory,
        "pre_inventory_sha256": _sha256(_canonical(pre_inventory)),
        "post_inventory": post_inventory,
        "post_inventory_sha256": _sha256(_canonical(post_inventory)),
        "delta": delta,
        "artifact_hashes": artifact_hashes,
        "bootstrap_sha256": bootstrap_sha256,
        "bootstrap_size": bootstrap_size,
        "bootstrap_mode": bootstrap_mode,
        "focused_receipt_sha256": focused_receipt_sha256,
        "focused_sidecar_sha256": focused_sidecar_sha256,
        "full_receipt_sha256": full_receipt_sha256,
        "full_sidecar_sha256": full_sidecar_sha256,
        "runner_lock_sha256": runner_lock_sha256,
        "project_identity_sha256": project_identity_sha256,
        "canonical_test_contract_sha256": canonical_test_contract_sha256,
        "native_launcher_contract_sha256": native_launcher_contract_sha256,
        "native_contract_sha256": native_contract_sha256,
        "public_key_id": public_key_id,
        "semantic_snapshot_sha256": semantic_snapshot_sha256,
        "attestation_commitment_sha256": "sha256:" + "0" * 64,
    }
    value["attestation_commitment_sha256"] = _commitment(
        value, "attestation_commitment_sha256"
    )
    verify_live_attestation_binding(
        value, output_root=output_root, expected_post_inventory=post_inventory
    )
    return value


def verify_live_attestation_binding(
    value: dict[str, Any],
    *,
    output_root: Path,
    expected_post_inventory: list[dict[str, Any]] | None = None,
) -> None:
    required = {
        "schema_version", "attestation_kind", "terminal_status", "output_root",
        "run_id", "nonce",
        "realtime_start_ns", "monotonic_start_ns", "realtime_end_ns",
        "monotonic_end_ns", "child_exit_code", "case_file_sha256",
        "scope_case_file_sha256", "requested_case_ids", "contiguous_case_digest",
        "recovery_mode", "target_reason", "current_manifest_paths",
        "current_response_commitments", "current_cache_paths",
        "provider_executable_identities", "pre_inventory", "pre_inventory_sha256",
        "post_inventory", "post_inventory_sha256", "delta", "artifact_hashes",
        "bootstrap_sha256", "bootstrap_size", "bootstrap_mode",
        "focused_receipt_sha256", "focused_sidecar_sha256",
        "full_receipt_sha256", "full_sidecar_sha256", "runner_lock_sha256",
        "project_identity_sha256", "canonical_test_contract_sha256",
        "native_launcher_contract_sha256", "native_contract_sha256",
        "public_key_id", "semantic_snapshot_sha256",
        "attestation_commitment_sha256",
    }
    try:
        if (
            type(value) is not dict
            or set(value) != required
            or value["schema_version"] != "4.0"
            or value["attestation_kind"] != "native_fail_fast_live_enrichment"
            or value["terminal_status"] not in {"PASS", "STOP"}
            or value["output_root"] != str(Path(output_root).absolute())
            or _HEX64.fullmatch(value["run_id"]) is None
            or _HEX64.fullmatch(value["nonce"]) is None
            or value["run_id"] == value["nonce"]
            or any(
                type(value[field]) is not int or value[field] < 0
                for field in (
                    "realtime_start_ns", "monotonic_start_ns",
                    "realtime_end_ns", "monotonic_end_ns", "child_exit_code",
                )
            )
            or (
                value["terminal_status"], value["child_exit_code"]
            ) not in {("PASS", 0), ("STOP", 120)}
            or value["realtime_end_ns"] < value["realtime_start_ns"]
            or value["monotonic_end_ns"] < value["monotonic_start_ns"]
            or type(value["bootstrap_size"]) is not int
            or not 1 <= value["bootstrap_size"] <= 1024 * 1024
            or type(value["bootstrap_mode"]) is not int
            or not 0 <= value["bootstrap_mode"] <= 0o7777
            or any(
                _SHA256.fullmatch(str(value[field])) is None
                for field in (
                    "case_file_sha256", "scope_case_file_sha256",
                    "contiguous_case_digest", "pre_inventory_sha256",
                    "post_inventory_sha256", "native_contract_sha256",
                    "bootstrap_sha256", "focused_receipt_sha256",
                    "focused_sidecar_sha256", "full_receipt_sha256",
                    "full_sidecar_sha256", "runner_lock_sha256",
                    "project_identity_sha256",
                    "canonical_test_contract_sha256",
                    "native_launcher_contract_sha256", "public_key_id",
                    "semantic_snapshot_sha256",
                    "attestation_commitment_sha256",
                )
            )
            or value["recovery_mode"] not in {
                "forward_recovery", "explicit_reattestation"
            }
            or value["target_reason"] not in {
                "next_incomplete_contiguous_p0_segment",
                "native_live_attestation_for_prompt_v2_3",
            }
            or type(value["requested_case_ids"]) is not list
            or not value["requested_case_ids"]
            or len(value["requested_case_ids"])
            != len(set(value["requested_case_ids"]))
            or value["contiguous_case_digest"]
            != _sha256(_canonical(value["requested_case_ids"]))
            or type(value["current_manifest_paths"]) is not list
            or not 1 <= len(value["current_manifest_paths"]) <= 3
            or len(value["current_manifest_paths"])
            != len(set(value["current_manifest_paths"]))
            or any(
                type(item) is not str or not item
                for item in value["current_manifest_paths"]
            )
            or type(value["current_response_commitments"]) is not list
            or len(value["current_response_commitments"])
            != len(value["current_manifest_paths"])
            or len(
                [
                    item
                    for item in value["current_response_commitments"]
                    if item is not None
                ]
            )
            != len(
                {
                    item
                    for item in value["current_response_commitments"]
                    if item is not None
                }
            )
            or any(
                item is not None and _SHA256.fullmatch(str(item)) is None
                for item in value["current_response_commitments"]
            )
            or type(value["current_cache_paths"]) is not list
            or len(value["current_cache_paths"])
            != len(value["current_manifest_paths"])
            or len(
                [item for item in value["current_cache_paths"] if item is not None]
            )
            != len(
                {item for item in value["current_cache_paths"] if item is not None}
            )
            or any(
                item is not None and (type(item) is not str or not item)
                for item in value["current_cache_paths"]
            )
            or any(
                (response is None) != (cache is None)
                for response, cache in zip(
                    value["current_response_commitments"],
                    value["current_cache_paths"],
                    strict=True,
                )
            )
            or type(value["provider_executable_identities"]) is not list
            or len(value["provider_executable_identities"])
            != len(value["current_manifest_paths"])
            or any(
                _SHA256.fullmatch(str(item)) is None
                for item in value["provider_executable_identities"]
            )
        ):
            raise ValueError
        before = _inventory_map(value["pre_inventory"])
        after = _inventory_map(value["post_inventory"])
        if (
            value["pre_inventory_sha256"]
            != _sha256(_canonical(value["pre_inventory"]))
            or value["post_inventory_sha256"]
            != _sha256(_canonical(value["post_inventory"]))
            or value["delta"] != _delta(value["pre_inventory"], value["post_inventory"])
            or value["attestation_commitment_sha256"]
            != _commitment(value, "attestation_commitment_sha256")
        ):
            raise ValueError
        created = {
            item["relative_path"] for item in value["delta"]["created"]
        }
        if any(
            path in before or path not in after or path not in created
            for path in value["current_manifest_paths"]
        ):
            raise ValueError("current attempt exists in the prebaseline")
        if any(
            path is not None
            and (path in before or path not in after or path not in created)
            for path in value["current_cache_paths"]
        ):
            raise ValueError("current response cache exists in the prebaseline")
        current = (
            inventory_snapshot(output_root)
            if expected_post_inventory is None
            else expected_post_inventory
        )
        if current != value["post_inventory"]:
            raise ValueError
        if any(path not in after for path in _REQUIRED_ARTIFACT_PATHS):
            raise ValueError
        expected_artifacts = {
            path: after[path]["sha256"] for path in _REQUIRED_ARTIFACT_PATHS
        }
        if value["artifact_hashes"] != expected_artifacts:
            raise ValueError
    except ValueError as error:
        if str(error) == "current attempt exists in the prebaseline":
            raise
        raise ValueError("live attestation binding is invalid") from None
    except Exception:
        raise ValueError("live attestation binding is invalid") from None


def _decode_json_object(raw: bytes, *, limit: int = _MAX_FILE_BYTES) -> dict[str, Any]:
    if len(raw) > limit:
        raise ValueError("live attestation JSON exceeds its bound")
    value = json.loads(raw.decode("utf-8", "strict"))
    if type(value) is not dict:
        raise ValueError("live attestation JSON is not an object")
    return value


def _read_json_object(path: Path, *, limit: int = _MAX_FILE_BYTES) -> dict[str, Any]:
    raw, _ = _safe_file(path)
    return _decode_json_object(raw, limit=limit)


def _atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_private_bytes(path, _canonical(value) + b"\n")


def _atomic_private_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short live attestation write")
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


def _semantic_file_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _external_data_boundary(root: Path) -> dict[str, Any]:
    """Describe the one allowed top-level data mount without traversing it."""

    mount = root / "data"
    try:
        mount_info = mount.lstat()
    except FileNotFoundError:
        return {
            "mount_kind": "absent",
            "mount_relative_path": "data",
            "mount_identity": None,
            "symlink_target": None,
            "resolved_path": None,
            "resolved_identity": None,
        }
    if stat.S_ISLNK(mount_info.st_mode):
        try:
            target = os.readlink(mount)
            resolved = mount.resolve(strict=True)
            resolved_info = resolved.lstat()
        except (OSError, FileNotFoundError):
            raise ValueError("external data boundary is unavailable") from None
        if not stat.S_ISDIR(resolved_info.st_mode) or stat.S_ISLNK(
            resolved_info.st_mode
        ):
            raise ValueError("external data boundary is not a directory")
        return {
            "mount_kind": "external_symlink",
            "mount_relative_path": "data",
            "mount_identity": _semantic_file_identity(mount_info),
            "symlink_target": target,
            "resolved_path": str(resolved),
            "resolved_identity": _semantic_file_identity(resolved_info),
        }
    if not stat.S_ISDIR(mount_info.st_mode):
        raise ValueError("semantic data boundary contains a special node")
    resolved = mount.resolve(strict=True)
    return {
        "mount_kind": "local_directory",
        "mount_relative_path": "data",
        "mount_identity": _semantic_file_identity(mount_info),
        "symlink_target": None,
        "resolved_path": str(resolved),
        "resolved_identity": _semantic_file_identity(resolved.lstat()),
    }


def _data_relative(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("data/"):
        return None
    relative = Path(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "\\" in value
        or "\x00" in value
        or relative.as_posix() != value
    ):
        raise ValueError("declared semantic data path is invalid")
    return value


def _required_semantic_data_path(value: object) -> str:
    relative = _data_relative(value)
    if relative is None:
        raise ValueError("declared semantic data path is invalid")
    return relative


def _case_consumer_data_paths(case: Any) -> set[str]:
    """Return only schema fields whose referenced bytes enter live semantics."""

    return {
        _required_semantic_data_path(case.artifacts.patch_path),
        _required_semantic_data_path(case.artifacts.proof_obligations_path),
        _required_semantic_data_path(case.artifacts.manifest_path),
        _required_semantic_data_path(case.views.oracle_view_path),
        _required_semantic_data_path(case.views.policy_view_path),
    }


def _semantic_json_object(path: Path) -> dict[str, Any]:
    raw, _ = _safe_file(path)
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except Exception:
        raise ValueError("declared semantic data JSON is invalid") from None
    if type(value) is not dict:
        raise ValueError("declared semantic data JSON is invalid")
    return value


def _oracle_consumer_data_paths(value: dict[str, Any]) -> set[str]:
    """Mirror the only external-file fields read by build_oracle_context."""

    return {
        _required_semantic_data_path(value.get("advisory_path")),
        _required_semantic_data_path(value.get("patch_path")),
    }


def _manifest_consumer_cache_path(value: dict[str, Any]) -> str:
    resolution = value.get("resolution")
    if type(resolution) is not dict:
        raise ValueError("declared semantic data JSON is invalid")
    return _required_semantic_data_path(resolution.get("cache_path"))


def _bounded_case_ids(path: Path) -> list[str]:
    raw, _ = _safe_file(path)
    try:
        values = [
            line.split("#", 1)[0].strip()
            for line in raw.decode("utf-8", "strict").splitlines()
        ]
    except UnicodeError:
        raise ValueError("semantic case file is invalid") from None
    values = [value for value in values if value]
    if (
        not values
        or len(values) != len(set(values))
        or any(not value or "/" in value or "\\" in value for value in values)
    ):
        raise ValueError("semantic case file is invalid")
    return values


def _safe_data_node(
    *,
    boundary_root: Path,
    relative: str,
    directories: dict[str, dict[str, Any]],
) -> Path:
    """Resolve one declared data node while rejecting every nested link/special."""

    normalized = _data_relative(relative)
    if normalized is None:
        raise ValueError("declared semantic data path is invalid")
    current = boundary_root
    parts = Path(normalized).parts[1:]
    if not parts:
        raise ValueError("declared semantic data path is invalid")
    for index, component in enumerate(parts):
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            raise ValueError("declared semantic data path is unavailable") from None
        child_relative = Path("data", *parts[: index + 1]).as_posix()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("data closure contains a symlink")
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("data closure contains a special node")
            directories[child_relative] = {
                "relative_path": child_relative,
                **_semantic_file_identity(info),
            }
        elif stat.S_ISDIR(info.st_mode):
            directories[child_relative] = {
                "relative_path": child_relative,
                **_semantic_file_identity(info),
            }
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError("data closure contains a special node")
    return current


def _semantic_data_closure(
    *, root: Path, case_file: Path, scope_case_file: Path
) -> tuple[
    dict[str, Path],
    list[dict[str, Any]],
    dict[Path, str],
    list[Any],
]:
    """Collect only selected case-declared data files and Git query boundaries."""

    from egsi.contracts.case import CaseManifest

    boundary = _external_data_boundary(root)
    if boundary["mount_kind"] == "absent":
        return {}, [], {}, []
    boundary_root = Path(boundary["resolved_path"])
    directories: dict[str, dict[str, Any]] = {}
    catalog_path = _safe_data_node(
        boundary_root=boundary_root,
        relative="data/catalog/cases.jsonl",
        directories=directories,
    )
    catalog_raw, _ = _safe_file(catalog_path)
    cases: dict[str, CaseManifest] = {}
    try:
        for raw_line in catalog_raw.decode("utf-8", "strict").splitlines():
            if not raw_line.strip():
                continue
            raw_case = json.loads(raw_line)
            if type(raw_case) is not dict:
                raise ValueError
            case = CaseManifest.model_validate(raw_case)
            if case.case_id in cases:
                raise ValueError
            cases[case.case_id] = case
    except Exception:
        raise ValueError("semantic data catalog is invalid") from None

    selected_ids = set(_bounded_case_ids(case_file))
    selected_ids.update(_bounded_case_ids(scope_case_file))
    selected_ids.update(
        case_id for case_id in _HISTORICAL_SEMANTIC_CASE_IDS if case_id in cases
    )
    if not selected_ids <= set(cases):
        raise ValueError("semantic case is missing from the data catalog")

    files: dict[str, Path] = {"data/catalog/cases.jsonl": catalog_path}
    cache_stores: dict[Path, str] = {}

    def add_file(relative: str) -> Path:
        if relative in files:
            return files[relative]
        path = _safe_data_node(
            boundary_root=boundary_root,
            relative=relative,
            directories=directories,
        )
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            raise ValueError("declared semantic data file is not regular")
        files[relative] = path
        if len(files) > _MAX_FILES:
            raise ValueError("semantic data closure file count exceeds its bound")
        return path

    for case_id in sorted(selected_ids):
        case = cases[case_id]
        for relative in sorted(_case_consumer_data_paths(case)):
            add_file(relative)
        oracle_path = add_file(
            _required_semantic_data_path(case.views.oracle_view_path)
        )
        manifest_path = add_file(
            _required_semantic_data_path(case.artifacts.manifest_path)
        )
        for relative in sorted(
            _oracle_consumer_data_paths(_semantic_json_object(oracle_path))
        ):
            add_file(relative)
        cache_relative = _manifest_consumer_cache_path(
            _semantic_json_object(manifest_path)
        )
        cache_path = _safe_data_node(
            boundary_root=boundary_root,
            relative=cache_relative,
            directories=directories,
        )
        if not stat.S_ISDIR(cache_path.lstat().st_mode):
            raise ValueError("declared semantic Git cache is not a directory")
        resolved_cache = cache_path.resolve(strict=True)
        if (
            resolved_cache in cache_stores
            and cache_stores[resolved_cache] != cache_relative
        ) or (
            cache_relative in cache_stores.values()
            and cache_stores.get(resolved_cache) != cache_relative
        ):
            raise ValueError("semantic Git store mapping is ambiguous")
        cache_stores[resolved_cache] = cache_relative
        if len(cache_stores) > _MAX_GIT_STORES:
            raise ValueError("semantic Git store count exceeds its bound")

    ordered_cases = [cases[case_id] for case_id in sorted(selected_ids)]
    return (
        files,
        sorted(directories.values(), key=lambda item: item["relative_path"]),
        cache_stores,
        ordered_cases,
    )


def _semantic_source_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for relative in _SEMANTIC_SOURCE_ROOTS:
        base = root / relative
        if not base.exists():
            continue
        if not base.is_dir() or base.is_symlink():
            raise ValueError("semantic snapshot source root is unsafe")
        for path in sorted(base.rglob("*")):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise ValueError("semantic snapshot source contains a special node")
            result.append(path)
    scripts = root / "scripts"
    if scripts.is_dir() and not scripts.is_symlink():
        for path in sorted(scripts.glob("*.py")):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise ValueError("semantic snapshot script is unsafe")
            result.append(path)
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        info = pyproject.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("semantic snapshot pyproject is unsafe")
        result.append(pyproject)
    return sorted(set(result), key=lambda path: path.relative_to(root).as_posix())


def _semantic_output_files(output_root: Path) -> list[Path]:
    if not output_root.is_dir() or output_root.is_symlink():
        raise ValueError("semantic snapshot output root is unsafe")
    attestation = output_root / _ATTESTATION_RELATIVE
    excluded = {
        attestation,
        Path(str(attestation) + ".native-attestation"),
        Path(str(attestation) + ".native-preflight"),
        Path(str(attestation) + ".native-candidate"),
        Path(str(attestation) + _SEMANTIC_SNAPSHOT_SUFFIX),
    }
    result: list[Path] = []
    for path in sorted(output_root.rglob("*")):
        if path in excluded:
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("semantic snapshot output contains a special node")
        result.append(path)
    return result


def _semantic_output_directories(output_root: Path) -> list[dict[str, Any]]:
    """Capture output directories whose metadata can affect semantic replay."""

    if not output_root.is_dir() or output_root.is_symlink():
        raise ValueError("semantic snapshot output root is unsafe")
    result: list[dict[str, Any]] = []
    for path in sorted(output_root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            relative = path.relative_to(output_root).as_posix()
            # Publishing the immutable snapshot necessarily changes its immediate
            # parent directory.  That directory has no replay time semantics.
            if relative not in _SEMANTIC_OUTPUT_VOLATILE_DIRECTORIES:
                result.append(
                    {
                        "relative_path": relative,
                        **_semantic_file_identity(info),
                    }
                )
            continue
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("semantic snapshot output contains a special node")
    return result


def _semantic_snapshot_entry(
    *,
    namespace: str,
    base: Path,
    path: Path,
    relative_path: str | None = None,
) -> dict[str, Any]:
    raw, info = _safe_file(path)
    identity = _semantic_file_identity(info)
    return {
        "namespace": namespace,
        "relative_path": (
            path.relative_to(base).as_posix()
            if relative_path is None
            else relative_path
        ),
        **identity,
        "sha256": _sha256(raw),
        "contents_base64": base64.b64encode(raw).decode("ascii"),
    }


def create_live_semantic_snapshot(
    *,
    root: Path,
    output_root: Path,
    case_file: Path,
    scope_case_file: Path,
    snapshot_path: Path,
) -> tuple[bytes, str]:
    """Write one canonical immutable semantic-input bundle after provider exit."""

    root = Path(root).resolve(strict=True)
    output_root = Path(output_root).resolve(strict=True)
    case_file = Path(case_file).resolve(strict=True)
    scope_case_file = Path(scope_case_file).resolve(strict=True)
    snapshot_path = Path(snapshot_path).absolute()
    expected_snapshot = Path(
        str(output_root / _ATTESTATION_RELATIVE) + _SEMANTIC_SNAPSHOT_SUFFIX
    )
    if (
        snapshot_path != expected_snapshot
        or root not in case_file.parents
        or root not in scope_case_file.parents
    ):
        raise ValueError("semantic snapshot paths are not canonical")
    (
        data_files,
        data_directories,
        cache_stores,
        semantic_cases,
    ) = _semantic_data_closure(
        root=root,
        case_file=case_file,
        scope_case_file=scope_case_file,
    )
    data_boundary = _external_data_boundary(root)
    from egsi.data.context import build_oracle_context
    from egsi.data.git_objects import capture_git_queries

    with capture_git_queries(cache_stores) as git_query_closure:
        for case in semantic_cases:
            build_oracle_context(root, case)
        report_path = output_root / "reports/remaining-p0/fail-fast-report.json"
        if report_path.is_file() and not report_path.is_symlink():
            from egsi.generation.fail_fast_batch import verify_fail_fast_report

            verify_fail_fast_report(
                root=root,
                case_file=case_file,
                scope_case_file=scope_case_file,
                output_root=output_root,
            )
    if len(git_query_closure) > _MAX_GIT_QUERIES:
        raise ValueError("semantic Git query closure exceeds its bound")
    git_store_paths = sorted(cache_stores.values())
    second_closure = _semantic_data_closure(
        root=root,
        case_file=case_file,
        scope_case_file=scope_case_file,
    )
    if (
        _external_data_boundary(root) != data_boundary
        or set(second_closure[0]) != set(data_files)
        or any(second_closure[0][key] != data_files[key] for key in data_files)
        or second_closure[1] != data_directories
        or second_closure[2] != cache_stores
        or [case.case_id for case in second_closure[3]]
        != [case.case_id for case in semantic_cases]
    ):
        raise ValueError("semantic data closure changed during capture")
    output_directories = _semantic_output_directories(output_root)
    output_files = _semantic_output_files(output_root)
    entries = [
        *(
            _semantic_snapshot_entry(namespace="source", base=root, path=path)
            for path in _semantic_source_files(root)
        ),
        *(
            _semantic_snapshot_entry(
                namespace="source",
                base=root,
                path=path,
                relative_path=relative,
            )
            for relative, path in data_files.items()
        ),
        *(
            _semantic_snapshot_entry(
                namespace="output", base=output_root, path=path
            )
            for path in output_files
        ),
    ]
    if _semantic_output_directories(output_root) != output_directories:
        raise ValueError("semantic output directory closure changed during capture")
    entries.sort(key=lambda item: (item["namespace"], item["relative_path"]))
    if not entries or len(entries) > _MAX_FILES:
        raise ValueError("semantic snapshot file count is invalid")
    value: dict[str, Any] = {
        "schema_version": "2.0",
        "snapshot_kind": "native_live_semantic_inputs",
        "source_root": str(root),
        "output_root": str(output_root),
        "case_file_relative": case_file.relative_to(root).as_posix(),
        "scope_case_file_relative": scope_case_file.relative_to(root).as_posix(),
        "external_data_boundary": data_boundary,
        "data_directories": data_directories,
        "output_directories": output_directories,
        "git_store_paths": git_store_paths,
        "git_query_closure": git_query_closure,
        "files": entries,
        "snapshot_commitment_sha256": "sha256:" + "0" * 64,
    }
    value["snapshot_commitment_sha256"] = _commitment(
        value, "snapshot_commitment_sha256"
    )
    raw = _canonical(value) + b"\n"
    if len(raw) > _MAX_SEMANTIC_SNAPSHOT_BYTES:
        raise ValueError("semantic snapshot exceeds its bound")
    _atomic_private_bytes(snapshot_path, raw)
    observed, info = _safe_file(snapshot_path)
    if observed != raw or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("semantic snapshot publication changed")
    return raw, _sha256(raw)


def _decode_live_semantic_snapshot(
    raw: bytes,
    *,
    expected_sha256: str,
    source_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if (
        type(raw) is not bytes
        or not raw.endswith(b"\n")
        or len(raw) > _MAX_SEMANTIC_SNAPSHOT_BYTES
        or _sha256(raw) != expected_sha256
    ):
        raise ValueError("live semantic snapshot bytes are invalid")
    value = _decode_json_object(raw, limit=_MAX_SEMANTIC_SNAPSHOT_BYTES)
    required = {
        "schema_version",
        "snapshot_kind",
        "source_root",
        "output_root",
        "case_file_relative",
        "scope_case_file_relative",
        "external_data_boundary",
        "data_directories",
        "output_directories",
        "git_store_paths",
        "git_query_closure",
        "files",
        "snapshot_commitment_sha256",
    }
    if (
        set(value) != required
        or value["schema_version"] != "2.0"
        or value["snapshot_kind"] != "native_live_semantic_inputs"
        or value["source_root"] != str(Path(source_root).resolve(strict=True))
        or value["output_root"] != str(Path(output_root).resolve(strict=True))
        or value["snapshot_commitment_sha256"]
        != _commitment(value, "snapshot_commitment_sha256")
        or _canonical(value) + b"\n" != raw
        or type(value["files"]) is not list
        or not value["files"]
        or len(value["files"]) > _MAX_FILES
    ):
        raise ValueError("live semantic snapshot envelope is invalid")
    identity_fields = {
        "device",
        "inode",
        "mode",
        "nlink",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
    }

    def valid_identity(identity: object) -> bool:
        return bool(
            type(identity) is dict
            and set(identity) == identity_fields
            and all(type(identity[field]) is int and identity[field] >= 0 for field in identity_fields)
        )

    boundary = value["external_data_boundary"]
    boundary_fields = {
        "mount_kind",
        "mount_relative_path",
        "mount_identity",
        "symlink_target",
        "resolved_path",
        "resolved_identity",
    }
    if (
        type(boundary) is not dict
        or set(boundary) != boundary_fields
        or boundary["mount_kind"]
        not in {"absent", "local_directory", "external_symlink"}
        or boundary["mount_relative_path"] != "data"
    ):
        raise ValueError("live semantic external data boundary is invalid")
    if boundary["mount_kind"] == "absent":
        if any(
            boundary[field] is not None
            for field in (
                "mount_identity",
                "symlink_target",
                "resolved_path",
                "resolved_identity",
            )
        ):
            raise ValueError("live semantic external data boundary is invalid")
    elif (
        not valid_identity(boundary["mount_identity"])
        or not valid_identity(boundary["resolved_identity"])
        or type(boundary["resolved_path"]) is not str
        or not Path(boundary["resolved_path"]).is_absolute()
        or (
            boundary["mount_kind"] == "external_symlink"
            and (
                type(boundary["symlink_target"]) is not str
                or not boundary["symlink_target"]
            )
        )
        or (
            boundary["mount_kind"] == "local_directory"
            and boundary["symlink_target"] is not None
        )
    ):
        raise ValueError("live semantic external data boundary is invalid")

    if type(value["data_directories"]) is not list:
        raise ValueError("live semantic data directory closure is invalid")
    previous_directory = ""
    expected_directory_fields = {"relative_path", *identity_fields}
    data_directory_paths: set[str] = set()
    for directory in value["data_directories"]:
        if (
            type(directory) is not dict
            or set(directory) != expected_directory_fields
            or _data_relative(directory.get("relative_path")) is None
            or directory["relative_path"] <= previous_directory
            or not valid_identity(
                {field: directory[field] for field in identity_fields}
            )
        ):
            raise ValueError("live semantic data directory closure is invalid")
        previous_directory = directory["relative_path"]
        data_directory_paths.add(directory["relative_path"])

    if (
        type(value["output_directories"]) is not list
        or len(value["output_directories"]) > _MAX_FILES
    ):
        raise ValueError("live semantic output directory closure is invalid")
    previous_output_directory = ""
    output_directory_paths: set[str] = set()
    excluded_output_directories = _SEMANTIC_OUTPUT_VOLATILE_DIRECTORIES
    for directory in value["output_directories"]:
        relative_value = directory.get("relative_path") if type(directory) is dict else None
        relative = Path(relative_value) if type(relative_value) is str else Path()
        if (
            type(directory) is not dict
            or set(directory) != expected_directory_fields
            or type(relative_value) is not str
            or not relative_value
            or relative.is_absolute()
            or ".." in relative.parts
            or "\\" in relative_value
            or "\x00" in relative_value
            or relative.as_posix() != relative_value
            or relative_value in excluded_output_directories
            or relative_value <= previous_output_directory
            or not valid_identity(
                {field: directory[field] for field in identity_fields}
            )
            or directory["nlink"] < 1
        ):
            raise ValueError("live semantic output directory closure is invalid")
        previous_output_directory = relative_value
        output_directory_paths.add(relative_value)

    if (
        type(value["git_store_paths"]) is not list
        or len(value["git_store_paths"]) > _MAX_GIT_STORES
    ):
        raise ValueError("live semantic Git store closure is invalid")
    previous_store = ""
    git_store_paths: set[str] = set()
    for store_path in value["git_store_paths"]:
        if (
            type(store_path) is not str
            or _data_relative(store_path) is None
            or store_path not in data_directory_paths
            or store_path <= previous_store
        ):
            raise ValueError("live semantic Git store closure is invalid")
        previous_store = store_path
        git_store_paths.add(store_path)

    if (
        type(value["git_query_closure"]) is not list
        or len(value["git_query_closure"]) > _MAX_GIT_QUERIES
    ):
        raise ValueError("live semantic Git query closure is invalid")
    previous_query: tuple[str, str, str] | None = None
    for query in value["git_query_closure"]:
        if type(query) is not dict:
            raise ValueError("live semantic Git query closure is invalid")
        common = {"store_path", "operation", "arguments", "outcome"}
        outcome = query.get("outcome")
        expected_fields = (
            common | {"result_base64"}
            if outcome == "bytes"
            else common | {"result_bool"}
            if outcome == "bool"
            else common | {"error_kind"}
            if outcome == "error"
            else set()
        )
        arguments = query.get("arguments")
        operation = query.get("operation")
        safe_repository_path = True
        if (
            operation in {"contains", "read_bytes"}
            and type(arguments) is list
            and len(arguments) >= 2
            and type(arguments[1]) is str
        ):
            try:
                from egsi.data.git_objects import validate_path

                validate_path(arguments[1])
            except ValueError:
                safe_repository_path = False
        if (
            set(query) != expected_fields
            or _data_relative(query.get("store_path")) is None
            or query.get("store_path") not in git_store_paths
            or operation not in {"canonical_diff", "contains", "read_bytes"}
            or type(arguments) is not list
            or (
                operation in {"canonical_diff", "contains"}
                and len(arguments) != 2
            )
            or (operation == "read_bytes" and len(arguments) != 3)
            or not all(type(item) in {str, int} for item in arguments)
            or not all(type(item) is str for item in arguments[:2])
            or not safe_repository_path
            or _COMMIT40.fullmatch(arguments[0]) is None
            or (
                operation == "canonical_diff"
                and _COMMIT40.fullmatch(arguments[1]) is None
            )
            or (
                operation != "canonical_diff"
                and (
                    not arguments[1]
                    or arguments[1].startswith("/")
                    or ".." in Path(arguments[1]).parts
                )
            )
            or (
                operation == "read_bytes"
                and (
                    type(arguments[2]) is not int
                    or not 1 <= arguments[2] <= _MAX_FILE_BYTES
                )
            )
            or (
                outcome == "bool" and type(query.get("result_bool")) is not bool
            )
            or (
                outcome == "error"
                and query.get("error_kind")
                not in {"FileNotFoundError", "ValueError", "RuntimeError"}
            )
        ):
            raise ValueError("live semantic Git query closure is invalid")
        if outcome == "bytes":
            try:
                decoded_result = base64.b64decode(
                    query["result_base64"], validate=True
                )
            except Exception:
                raise ValueError("live semantic Git query closure is invalid") from None
            if (
                base64.b64encode(decoded_result).decode("ascii")
                != query["result_base64"]
                or len(decoded_result) > _MAX_FILE_BYTES
            ):
                raise ValueError("live semantic Git query closure is invalid")
        query_key = (
            query["store_path"],
            operation,
            json.dumps(arguments, ensure_ascii=True, separators=(",", ":")),
        )
        if previous_query is not None and query_key <= previous_query:
            raise ValueError("live semantic Git query closure is invalid")
        previous_query = query_key
    previous: tuple[str, str] | None = None
    expected_entry_fields = {
        "namespace",
        "relative_path",
        "device",
        "inode",
        "mode",
        "nlink",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
        "sha256",
        "contents_base64",
    }
    for entry in value["files"]:
        if type(entry) is not dict or set(entry) != expected_entry_fields:
            raise ValueError("live semantic snapshot entry is invalid")
        key = (entry["namespace"], entry["relative_path"])
        relative = Path(entry["relative_path"])
        if (
            entry["namespace"] not in {"source", "output"}
            or type(entry["relative_path"]) is not str
            or not entry["relative_path"]
            or relative.is_absolute()
            or ".." in relative.parts
            or (previous is not None and key <= previous)
            or any(
                type(entry[field]) is not int or entry[field] < 0
                for field in (
                    "device",
                    "inode",
                    "mode",
                    "nlink",
                    "uid",
                    "gid",
                    "size",
                    "mtime_ns",
                    "ctime_ns",
                )
            )
            or entry["nlink"] != 1
            or entry["size"] > _MAX_FILE_BYTES
            or _SHA256.fullmatch(str(entry["sha256"])) is None
            or type(entry["contents_base64"]) is not str
        ):
            raise ValueError("live semantic snapshot entry is invalid")
        try:
            contents = base64.b64decode(entry["contents_base64"], validate=True)
        except Exception:
            raise ValueError("live semantic snapshot contents are invalid") from None
        if (
            base64.b64encode(contents).decode("ascii")
            != entry["contents_base64"]
            or len(contents) != entry["size"]
            or _sha256(contents) != entry["sha256"]
        ):
            raise ValueError("live semantic snapshot contents disagree")
        previous = key
    for entry in value["files"]:
        if entry["namespace"] != "output":
            continue
        parent = Path(entry["relative_path"]).parent
        while parent != Path("."):
            parent_value = parent.as_posix()
            if (
                parent_value not in excluded_output_directories
                and parent_value not in output_directory_paths
            ):
                raise ValueError("live semantic output directory closure is invalid")
            parent = parent.parent
    for relative_value in output_directory_paths:
        parent = Path(relative_value).parent
        if (
            parent != Path(".")
            and parent.as_posix() not in excluded_output_directories
            and parent.as_posix() not in output_directory_paths
        ):
            raise ValueError("live semantic output directory closure is invalid")
    for field in ("case_file_relative", "scope_case_file_relative"):
        relative = Path(value[field])
        if (
            type(value[field]) is not str
            or not value[field]
            or relative.is_absolute()
            or ".." in relative.parts
            or not any(
                entry["namespace"] == "source"
                and entry["relative_path"] == value[field]
                for entry in value["files"]
            )
        ):
            raise ValueError("live semantic snapshot case path is invalid")
    return value


def verify_live_semantic_snapshot_against_live(
    raw: bytes,
    *,
    expected_sha256: str,
    source_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Compare every canonical ordinary file by metadata and digest."""

    source_root = Path(source_root).resolve(strict=True)
    output_root = Path(output_root).resolve(strict=True)
    value = _decode_live_semantic_snapshot(
        raw,
        expected_sha256=expected_sha256,
        source_root=source_root,
        output_root=output_root,
    )
    if _external_data_boundary(source_root) != value["external_data_boundary"]:
        raise ValueError("live semantic external data boundary changed")
    data_files, data_directories, cache_stores, _ = _semantic_data_closure(
        root=source_root,
        case_file=source_root / value["case_file_relative"],
        scope_case_file=source_root / value["scope_case_file_relative"],
    )
    if (
        data_directories != value["data_directories"]
        or sorted(cache_stores.values()) != value["git_store_paths"]
    ):
        raise ValueError("live semantic data directory closure changed")
    output_directories = _semantic_output_directories(output_root)
    if output_directories != value["output_directories"]:
        raise ValueError("live semantic output directory closure changed")
    current_paths = {
        ("source", path.relative_to(source_root).as_posix()): path
        for path in _semantic_source_files(source_root)
    }
    current_paths.update(
        {("source", relative): path for relative, path in data_files.items()}
    )
    current_paths.update(
        {
            ("output", path.relative_to(output_root).as_posix()): path
            for path in _semantic_output_files(output_root)
        }
    )
    expected_keys = {
        (entry["namespace"], entry["relative_path"]) for entry in value["files"]
    }
    if set(current_paths) != expected_keys:
        raise ValueError("live semantic snapshot file set changed")
    for entry in value["files"]:
        raw_file, info = _safe_file(
            current_paths[(entry["namespace"], entry["relative_path"])]
        )
        expected_identity = {
            field: entry[field]
            for field in (
                "device",
                "inode",
                "mode",
                "nlink",
                "uid",
                "gid",
                "size",
                "mtime_ns",
                "ctime_ns",
            )
        }
        if (
            _semantic_file_identity(info) != expected_identity
            or _sha256(raw_file) != entry["sha256"]
        ):
            raise ValueError("live semantic snapshot ordinary file changed")
    from egsi.data.git_objects import verify_git_queries

    verify_git_queries(
        source_root,
        value["git_query_closure"],
        store_paths=value["git_store_paths"],
    )
    if _external_data_boundary(source_root) != value["external_data_boundary"]:
        raise ValueError("live semantic external data boundary changed")
    final_files, final_directories, final_cache_stores, _ = _semantic_data_closure(
        root=source_root,
        case_file=source_root / value["case_file_relative"],
        scope_case_file=source_root / value["scope_case_file_relative"],
    )
    if (
        set(final_files) != set(data_files)
        or final_directories != data_directories
        or sorted(final_cache_stores.values()) != value["git_store_paths"]
        or _semantic_output_directories(output_root) != output_directories
    ):
        raise ValueError("live semantic closure changed during verification")
    return value


@contextmanager
def materialize_live_semantic_snapshot(
    raw: bytes,
    *,
    expected_sha256: str,
    source_root: Path,
    output_root: Path,
) -> Iterator[tuple[Path, Path, Path, Path]]:
    """Materialize only immutable-bundle bytes into a private replay tree."""

    value = _decode_live_semantic_snapshot(
        raw,
        expected_sha256=expected_sha256,
        source_root=source_root,
        output_root=output_root,
    )
    with tempfile.TemporaryDirectory(prefix="egsi-live-semantic-") as temporary:
        base = Path(temporary)
        replay_source = base / "source"
        replay_output = base / "output"
        replay_source.mkdir(mode=0o700)
        replay_output.mkdir(mode=0o700)
        for directory in value["output_directories"]:
            (replay_output / directory["relative_path"]).mkdir(
                parents=True, exist_ok=True, mode=0o700
            )
        for entry in value["files"]:
            namespace_root = (
                replay_source if entry["namespace"] == "source" else replay_output
            )
            path = namespace_root / entry["relative_path"]
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            contents = base64.b64decode(entry["contents_base64"], validate=True)
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                entry["mode"],
            )
            try:
                offset = 0
                while offset < len(contents):
                    written = os.write(descriptor, contents[offset:])
                    if written <= 0:
                        raise OSError("short semantic snapshot materialization")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            path.chmod(entry["mode"])
        for store_relative in value["git_store_paths"]:
            store = replay_source / store_relative
            store.mkdir(parents=True, exist_ok=True, mode=0o700)
            (store / "objects").mkdir(mode=0o700)
            (store / "HEAD").write_bytes(b"ref: refs/heads/semantic-replay\n")
        for directory in sorted(
            value["output_directories"],
            key=lambda item: (
                len(Path(item["relative_path"]).parts),
                item["relative_path"],
            ),
            reverse=True,
        ):
            path = replay_output / directory["relative_path"]
            path.chmod(directory["mode"])
            os.utime(
                path,
                ns=(directory["mtime_ns"], directory["mtime_ns"]),
                follow_symlinks=False,
            )
            observed = path.lstat()
            if (
                not stat.S_ISDIR(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or stat.S_IMODE(observed.st_mode) != directory["mode"]
                or observed.st_mtime_ns != directory["mtime_ns"]
            ):
                raise ValueError("semantic output directory materialization changed")
        from egsi.data.git_objects import replay_git_queries

        with replay_git_queries(
            replay_source,
            value["git_query_closure"],
            store_paths=value["git_store_paths"],
        ):
            yield (
                replay_source,
                replay_output,
                replay_source / value["case_file_relative"],
                replay_source / value["scope_case_file_relative"],
            )


def _candidate_envelope_bytes(
    *, value: dict[str, Any], attestation_sha256: str
) -> bytes:
    fields: tuple[tuple[str, str], ...] = (
        ("run_id", value["run_id"]),
        ("nonce", value["nonce"]),
        ("realtime_start_ns", str(value["realtime_start_ns"])),
        ("monotonic_start_ns", str(value["monotonic_start_ns"])),
        ("pre_inventory_sha256", value["pre_inventory_sha256"]),
        ("bootstrap_sha256", value["bootstrap_sha256"]),
        ("focused_receipt_sha256", value["focused_receipt_sha256"]),
        ("focused_sidecar_sha256", value["focused_sidecar_sha256"]),
        ("full_receipt_sha256", value["full_receipt_sha256"]),
        ("full_sidecar_sha256", value["full_sidecar_sha256"]),
        ("runner_lock_sha256", value["runner_lock_sha256"]),
        ("project_identity_sha256", value["project_identity_sha256"]),
        (
            "canonical_test_contract_sha256",
            value["canonical_test_contract_sha256"],
        ),
        (
            "native_launcher_contract_sha256",
            value["native_launcher_contract_sha256"],
        ),
        ("native_binary_contract_sha256", value["native_contract_sha256"]),
        ("public_key_id", value["public_key_id"]),
        ("semantic_snapshot_sha256", value["semantic_snapshot_sha256"]),
        ("child_exit_code", str(value["child_exit_code"])),
        ("terminal_status", value["terminal_status"]),
        ("post_inventory_sha256", value["post_inventory_sha256"]),
        ("attestation_sha256", attestation_sha256),
        (
            "attestation_commitment_sha256",
            value["attestation_commitment_sha256"],
        ),
    )
    try:
        raw = "EGSI-LIVE-CANDIDATE-V1\n" + "".join(
            f"{name}={field_value}\n" for name, field_value in fields
        )
        encoded = raw.encode("ascii", "strict")
    except (KeyError, UnicodeError):
        raise ValueError("live candidate envelope fields are invalid") from None
    if len(encoded) > 4096:
        raise ValueError("live candidate envelope exceeds its bound")
    return encoded


def publish_live_candidate_envelope(
    path: Path, *, attestation_path: Path, value: dict[str, Any]
) -> None:
    attestation_raw, attestation_info = _safe_file(Path(attestation_path))
    if stat.S_IMODE(attestation_info.st_mode) != 0o600:
        raise ValueError("live candidate attestation mode is invalid")
    raw = _candidate_envelope_bytes(
        value=value, attestation_sha256=_sha256(attestation_raw)
    )
    _atomic_private_bytes(Path(path), raw)
    verify_live_candidate_envelope(
        Path(path), attestation_path=Path(attestation_path), value=value
    )


def verify_live_candidate_envelope_bytes(
    envelope_raw: bytes, *, attestation_raw: bytes, value: dict[str, Any]
) -> None:
    try:
        if (
            type(envelope_raw) is not bytes
            or type(attestation_raw) is not bytes
            or len(envelope_raw) > 4096
            or envelope_raw
            != _candidate_envelope_bytes(
                value=value, attestation_sha256=_sha256(attestation_raw)
            )
        ):
            raise ValueError
    except Exception:
        raise ValueError("live candidate envelope is invalid") from None


def verify_live_candidate_envelope(
    path: Path, *, attestation_path: Path, value: dict[str, Any]
) -> None:
    try:
        envelope_raw, envelope_info = _safe_file(Path(path))
        attestation_raw, attestation_info = _safe_file(Path(attestation_path))
        if (
            stat.S_IMODE(envelope_info.st_mode) != 0o600
            or envelope_info.st_nlink != 1
            or stat.S_IMODE(attestation_info.st_mode) != 0o600
        ):
            raise ValueError
        verify_live_candidate_envelope_bytes(
            envelope_raw, attestation_raw=attestation_raw, value=value
        )
    except Exception:
        raise ValueError("live candidate envelope is invalid") from None


def _native_public_material(root: Path) -> tuple[str, str]:
    value = _read_json_object(root / "configs/native-signer-build-record.json")
    contract = value.get("native_contract_sha256")
    key_id = value.get("public_key", {}).get("key_id")
    if (
        _SHA256.fullmatch(str(contract)) is None
        or _SHA256.fullmatch(str(key_id)) is None
    ):
        raise ValueError("native public material is invalid")
    return contract, key_id


def _provider_bindings(
    output_root: Path, manifest_paths: list[str]
) -> tuple[list[str], list[str | None], list[str | None]]:
    identities: list[str] = []
    commitments: list[str | None] = []
    for relative in manifest_paths:
        value = _read_json_object(output_root / relative, limit=2 * 1024 * 1024)
        identity = value.get("executable_identity_commitment_sha256")
        commitment = value.get("response_commitment_sha256")
        if (
            _SHA256.fullmatch(str(identity)) is None
            or (
                value.get("status") == "committed"
                and _SHA256.fullmatch(str(commitment)) is None
            )
            or (
                value.get("status") == "quarantined"
                and (
                    value.get("failure_code") != "provider_failure_event"
                    or commitment is not None
                    or value.get("provider_response_model") is not None
                    or value.get("usage") is not None
                )
            )
            or value.get("status") not in {"committed", "quarantined"}
            or (commitment is not None and commitment in commitments)
        ):
            raise ValueError("provider terminal binding is invalid")
        identities.append(identity)
        commitments.append(commitment)
    by_commitment: dict[str, list[str]] = {
        item: [] for item in commitments if item is not None
    }
    cache_root = output_root / "cache/teacher"
    if cache_root.is_dir() and not cache_root.is_symlink():
        for path in sorted(cache_root.glob("*.json")):
            value = _read_json_object(path, limit=2 * 1024 * 1024)
            commitment = value.get("response_commitment_sha256")
            if commitment in by_commitment:
                by_commitment[commitment].append(
                    path.relative_to(output_root).as_posix()
                )
    cache_paths: list[str | None] = []
    for commitment in commitments:
        if commitment is None:
            cache_paths.append(None)
            continue
        paths = by_commitment[commitment]
        if len(paths) != 1:
            raise ValueError("provider response cache binding is ambiguous")
        cache_paths.append(paths[0])
    return identities, commitments, cache_paths


def execute_locked_live_enrichment(
    *,
    root: Path,
    output_root: Path,
    case_file: Path,
    scope_case_file: Path,
    provider_config: Path,
    attestation_path: Path,
    candidate_envelope_path: Path,
    run_id: str,
    nonce: str,
    realtime_start_ns: int,
    monotonic_start_ns: int,
    pre_inventory: list[dict[str, Any]],
    trust_anchors: dict[str, Any],
) -> dict[str, Any]:
    """Execute the one allowed live batch and publish the unsigned native payload."""

    from egsi.cli import _close_teacher, build_batch_teacher
    from egsi.generation.fail_fast_batch import run_fail_fast_batch
    from egsi.generation.pilot import _read_regular, _sha256, read_case_ids

    root = Path(root).resolve(strict=True)
    output_root = Path(output_root).absolute()
    case_file = Path(case_file).resolve(strict=True)
    scope_case_file = Path(scope_case_file).resolve(strict=True)
    provider_config = Path(provider_config).resolve(strict=True)
    attestation_path = Path(attestation_path).absolute()
    candidate_envelope_path = Path(candidate_envelope_path).absolute()
    if attestation_path != output_root / _ATTESTATION_RELATIVE:
        raise ValueError("live attestation path is not canonical")
    if candidate_envelope_path != Path(str(attestation_path) + ".native-candidate"):
        raise ValueError("live candidate envelope path is not canonical")
    if type(trust_anchors) is not dict or set(trust_anchors) != _TRUST_ANCHOR_FIELDS:
        raise ValueError("live trust anchors are invalid")
    if inventory_snapshot(output_root) != pre_inventory:
        raise ValueError("live prebaseline changed before provider execution")
    teacher = build_batch_teacher(
        provider_config,
        output_root / "cache/teacher",
        False,
        audit_root=output_root / "audit/teacher",
        working_root=output_root / "codex-work",
    )
    primary: BaseException | None = None
    report = None
    try:
        report = run_fail_fast_batch(
            root=root,
            case_file=case_file,
            scope_case_file=scope_case_file,
            output_root=output_root,
            teacher=teacher,
        )
    except BaseException as error:
        primary = error
    close_error = _close_teacher(teacher)
    if primary is not None:
        raise RuntimeError("locked live enrichment failed") from None
    if close_error is not None or report is None:
        raise RuntimeError("locked live teacher close failed") from None
    post_inventory = inventory_snapshot(output_root)
    manifest_paths = [item.manifest_path for item in report.current_attempts]
    contract, key_id = _native_public_material(root)
    identities, response_commitments, cache_paths = _provider_bindings(
        output_root, manifest_paths
    )
    semantic_snapshot_path = Path(
        str(attestation_path) + _SEMANTIC_SNAPSHOT_SUFFIX
    )
    semantic_snapshot_raw, semantic_snapshot_sha256 = create_live_semantic_snapshot(
        root=root,
        output_root=output_root,
        case_file=case_file,
        scope_case_file=scope_case_file,
        snapshot_path=semantic_snapshot_path,
    )
    terminal_status = (
        "PASS"
        if report.status == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
        else "STOP"
    )
    child_exit_code = 0 if terminal_status == "PASS" else 120
    value = build_live_attestation(
        output_root=output_root,
        case_file_sha256=_sha256(_read_regular(case_file, limit=64 * 1024)),
        scope_case_file_sha256=_sha256(
            _read_regular(scope_case_file, limit=64 * 1024)
        ),
        requested_case_ids=read_case_ids(case_file),
        current_manifest_paths=manifest_paths,
        current_response_commitments=response_commitments,
        current_cache_paths=cache_paths,
        run_id=run_id,
        nonce=nonce,
        realtime_start_ns=realtime_start_ns,
        monotonic_start_ns=monotonic_start_ns,
        realtime_end_ns=time.time_ns(),
        monotonic_end_ns=time.monotonic_ns(),
        child_exit_code=child_exit_code,
        recovery_mode=report.recovery_mode,
        target_reason=report.target_reason,
        bootstrap_sha256=trust_anchors["bootstrap_sha256"],
        bootstrap_size=trust_anchors["bootstrap_size"],
        bootstrap_mode=trust_anchors["bootstrap_mode"],
        focused_receipt_sha256=trust_anchors["focused_receipt_sha256"],
        focused_sidecar_sha256=trust_anchors["focused_sidecar_sha256"],
        full_receipt_sha256=trust_anchors["full_receipt_sha256"],
        full_sidecar_sha256=trust_anchors["full_sidecar_sha256"],
        runner_lock_sha256=trust_anchors["runner_lock_sha256"],
        project_identity_sha256=trust_anchors["project_identity_sha256"],
        canonical_test_contract_sha256=trust_anchors[
            "canonical_test_contract_sha256"
        ],
        native_launcher_contract_sha256=trust_anchors[
            "native_launcher_contract_sha256"
        ],
        native_contract_sha256=contract,
        public_key_id=key_id,
        provider_executable_identities=identities,
        pre_inventory=pre_inventory,
        post_inventory=post_inventory,
        semantic_snapshot_sha256=semantic_snapshot_sha256,
    )
    if (
        value["native_contract_sha256"]
        != trust_anchors["native_contract_sha256"]
        or value["public_key_id"] != trust_anchors["public_key_id"]
    ):
        raise ValueError("live native public anchors changed")
    _atomic_private_json(attestation_path, value)
    publish_live_candidate_envelope(
        candidate_envelope_path,
        attestation_path=attestation_path,
        value=value,
    )
    attestation_raw = _safe_file(attestation_path)[0]
    candidate_envelope_raw = _safe_file(candidate_envelope_path)[0]
    replayed = verify_locked_live_enrichment(
        root=root,
        output_root=output_root,
        case_file=case_file,
        scope_case_file=scope_case_file,
        attestation_path=attestation_path,
        attestation_raw=attestation_raw,
        candidate_envelope_path=candidate_envelope_path,
        candidate_envelope_raw=candidate_envelope_raw,
        semantic_snapshot_path=semantic_snapshot_path,
        semantic_snapshot_raw=semantic_snapshot_raw,
        expected_trust_anchors=trust_anchors,
    )
    if replayed != value:
        raise RuntimeError("locked live terminal replay changed")
    return value


def verify_locked_live_enrichment(
    *,
    root: Path,
    output_root: Path,
    case_file: Path,
    scope_case_file: Path,
    attestation_path: Path,
    attestation_raw: bytes | None = None,
    candidate_envelope_path: Path | None = None,
    candidate_envelope_raw: bytes | None = None,
    semantic_snapshot_path: Path | None = None,
    semantic_snapshot_raw: bytes | None = None,
    expected_trust_anchors: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute semantics from one native-held immutable input bundle."""

    committed_root = Path(root).resolve(strict=True)
    committed_output = Path(output_root).resolve(strict=True)
    committed_case = Path(case_file).resolve(strict=True)
    committed_scope = Path(scope_case_file).resolve(strict=True)
    attestation_path = Path(attestation_path)
    if attestation_raw is None:
        attestation_path = attestation_path.resolve(strict=True)
        attestation_raw = _safe_file(attestation_path)[0]
    elif type(attestation_raw) is not bytes or not attestation_path.is_absolute():
        raise ValueError("live native attestation replay bytes are invalid")
    if attestation_path != committed_output / _ATTESTATION_RELATIVE:
        raise ValueError("live attestation path is not canonical")
    value = _decode_json_object(attestation_raw)
    if semantic_snapshot_raw is not None:
        semantic_snapshot_path = Path(semantic_snapshot_path or "")
        expected_snapshot_path = Path(
            str(attestation_path) + _SEMANTIC_SNAPSHOT_SUFFIX
        )
        if (
            type(semantic_snapshot_raw) is not bytes
            or not semantic_snapshot_path.is_absolute()
            or semantic_snapshot_path != expected_snapshot_path
        ):
            raise ValueError("live native semantic snapshot path is invalid")
        with materialize_live_semantic_snapshot(
            semantic_snapshot_raw,
            expected_sha256=value["semantic_snapshot_sha256"],
            source_root=committed_root,
            output_root=committed_output,
        ) as (replay_root, replay_output, replay_case, replay_scope):
            replay_inventory = inventory_snapshot(replay_output)
            return _verify_locked_live_enrichment_semantics(
                root=replay_root,
                output_root=replay_output,
                committed_output_root=committed_output,
                case_file=replay_case,
                scope_case_file=replay_scope,
                attestation_path=attestation_path,
                attestation_raw=attestation_raw,
                value=value,
                candidate_envelope_path=candidate_envelope_path,
                candidate_envelope_raw=candidate_envelope_raw,
                expected_trust_anchors=expected_trust_anchors,
                expected_post_inventory=replay_inventory,
            )
    if semantic_snapshot_path is not None:
        raise ValueError("live semantic snapshot path lacks held bytes")
    return _verify_locked_live_enrichment_semantics(
        root=committed_root,
        output_root=committed_output,
        committed_output_root=committed_output,
        case_file=committed_case,
        scope_case_file=committed_scope,
        attestation_path=attestation_path,
        attestation_raw=attestation_raw,
        value=value,
        candidate_envelope_path=candidate_envelope_path,
        candidate_envelope_raw=candidate_envelope_raw,
        expected_trust_anchors=expected_trust_anchors,
        expected_post_inventory=None,
    )


def _verify_locked_live_enrichment_semantics(
    *,
    root: Path,
    output_root: Path,
    committed_output_root: Path,
    case_file: Path,
    scope_case_file: Path,
    attestation_path: Path,
    attestation_raw: bytes,
    value: dict[str, Any],
    candidate_envelope_path: Path | None,
    candidate_envelope_raw: bytes | None,
    expected_trust_anchors: dict[str, Any] | None,
    expected_post_inventory: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Run the full existing semantic replay over snapshot-derived paths."""

    from egsi.generation.fail_fast_batch import verify_fail_fast_report
    from egsi.generation.pilot import _read_regular, _sha256, read_case_ids

    root = Path(root).resolve(strict=True)
    output_root = Path(output_root).resolve(strict=True)
    committed_output_root = Path(committed_output_root).resolve(strict=True)
    case_file = Path(case_file).resolve(strict=True)
    scope_case_file = Path(scope_case_file).resolve(strict=True)
    attestation_path = Path(attestation_path)
    if attestation_path != committed_output_root / _ATTESTATION_RELATIVE:
        raise ValueError("live attestation path is not canonical")
    verify_live_attestation_binding(
        value,
        output_root=committed_output_root,
        expected_post_inventory=expected_post_inventory,
    )
    if expected_trust_anchors is not None:
        if (
            type(expected_trust_anchors) is not dict
            or set(expected_trust_anchors) != _TRUST_ANCHOR_FIELDS
            or any(
                value[field] != expected_trust_anchors[field]
                for field in _TRUST_ANCHOR_FIELDS
            )
        ):
            raise ValueError("live attestation trust anchors disagree")
    if candidate_envelope_path is not None:
        candidate_envelope_path = Path(candidate_envelope_path)
        if candidate_envelope_raw is None:
            candidate_envelope_path = candidate_envelope_path.resolve(strict=True)
        elif (
            type(candidate_envelope_raw) is not bytes
            or not candidate_envelope_path.is_absolute()
        ):
            raise ValueError("live native candidate replay bytes are invalid")
        if candidate_envelope_path != Path(str(attestation_path) + ".native-candidate"):
            raise ValueError("live candidate envelope path is not canonical")
        if candidate_envelope_raw is None:
            verify_live_candidate_envelope(
                candidate_envelope_path,
                attestation_path=attestation_path,
                value=value,
            )
        else:
            verify_live_candidate_envelope_bytes(
                candidate_envelope_raw,
                attestation_raw=attestation_raw,
                value=value,
            )
    elif candidate_envelope_raw is not None:
        raise ValueError("live candidate replay bytes lack a canonical path")
    contract, key_id = _native_public_material(root)
    report = verify_fail_fast_report(
        root=root,
        case_file=case_file,
        scope_case_file=scope_case_file,
        output_root=output_root,
    )
    manifest_paths = [item.manifest_path for item in report.current_attempts]
    identities, response_commitments, cache_paths = _provider_bindings(
        output_root, manifest_paths
    )
    if (
        value["case_file_sha256"]
        != _sha256(_read_regular(case_file, limit=64 * 1024))
        or value["scope_case_file_sha256"]
        != _sha256(_read_regular(scope_case_file, limit=64 * 1024))
        or value["requested_case_ids"] != read_case_ids(case_file)
        or value["current_manifest_paths"] != manifest_paths
        or value["current_response_commitments"] != response_commitments
        or value["current_cache_paths"] != cache_paths
        or value["provider_executable_identities"]
        != identities
        or value["recovery_mode"] != report.recovery_mode
        or value["target_reason"] != report.target_reason
        or value["native_contract_sha256"] != contract
        or value["public_key_id"] != key_id
        or value["terminal_status"]
        != (
            "PASS"
            if report.status
            == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
            else "STOP"
        )
        or value["child_exit_code"]
        != (
            0
            if report.status
            == "REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW"
            else 120
        )
    ):
        raise ValueError("live attestation disagrees with verified report")
    # The semantic verifier reads the report, manifests, cache, provenance,
    # and summary only through the materialized immutable bundle when native
    # snapshot bytes were supplied.  Recheck the same snapshot inventory.
    verify_live_attestation_binding(
        value,
        output_root=committed_output_root,
        expected_post_inventory=expected_post_inventory,
    )
    if candidate_envelope_path is not None:
        if candidate_envelope_raw is None:
            verify_live_candidate_envelope(
                candidate_envelope_path,
                attestation_path=attestation_path,
                value=value,
            )
        else:
            verify_live_candidate_envelope_bytes(
                candidate_envelope_raw,
                attestation_raw=attestation_raw,
                value=value,
            )
    return value
