"""Run only canonical offline pytest suites and commit replay-checkable receipts."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

from egsi.generation.pilot import (
    _dict_commitment,
    _read_regular,
    _sha256,
    write_report,
)
from egsi.generation.safeio import open_directory_fd
from egsi.strict_json import strict_json_loads


FOCUSED_TEST_FILES = (
    "tests/data/test_repository_paths.py",
    "tests/generation/test_enrichment.py",
    "tests/generation/test_fail_fast_batch.py",
    "tests/generation/test_human_audit.py",
    "tests/generation/test_pilot.py",
    "tests/generation/test_first_case_hard_gate.py",
    "tests/generation/test_test_receipt.py",
    "tests/teacher/test_codex_exec.py",
)
_RECORDED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "HOME": "<private-temporary-home>",
    "TMPDIR": "<private-temporary-tmp>",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
}
_FORBIDDEN_ROOT_PYTEST_HOOKS = (
    "conftest.py",
    "sitecustomize.py",
    "usercustomize.py",
    "pytest.ini",
    ".pytest.ini",
    "pytest.toml",
    ".pytest.toml",
    "setup.cfg",
    "tox.ini",
)
_RUNNER_CONTRACT_VERSION = "offline-pytest-runner-v8"
_PYTEST_CONTRACT_PREFIX = b"EGSI_PYTEST_CONTRACT="
_CANONICAL_CONTRACT_RELATIVE = Path(
    "configs/canonical-test-contract.v1.json"
)
_RECEIPT_FIELDS = {
    "schema_version",
    "receipt_kind",
    "native_attested",
    "name",
    "command",
    "cwd",
    "environment",
    "runner",
    "started_at_utc",
    "duration_ms",
    "exit_code",
    "passed_count",
    "failed_count",
    "summary_line",
    "stdout_base64",
    "stderr_base64",
    "stdout_sha256",
    "stderr_sha256",
    "project_identity_pre_sha256",
    "project_identity_post_sha256",
    "pytest_contract",
    "code_commitments",
    "runner_environment_commitment_sha256",
    "receipt_commitment_sha256",
}
_CODE_COMMITMENT_FIELDS = {
    "source_tree_sha256",
    "tests_tree_sha256",
    "pyproject_toml_sha256",
    "pytest_local_inventory_sha256",
    "offline_test_runner_lock_sha256",
    "historical_expectation_sha256",
    "first_case_historical_expectation_sha256",
    "project_identity_sha256",
    "canonical_test_contract_sha256",
}
_RUNNER_FIELDS = {
    "runner_contract_version",
    "command_executable",
    "resolved_executable",
    "executable_identity_sha256",
    "pyvenv_cfg_identity_sha256",
    "bootstrap_identity_sha256",
    "canonical_config_identity_sha256",
    "python_implementation",
    "python_version",
    "pytest_version",
    "pluggy_version",
    "pytest_module_file_sha256",
    "pluggy_module_file_sha256",
    "include_system_site_packages",
    "no_pth",
    "site_packages_tree_sha256",
    "stdlib_tree_sha256",
    "project_installed_tree_sha256",
    "runner_lock_sha256",
    "runner_lock_identity_sha256",
    "project_identity_sha256",
    "native_launcher_contract_sha256",
    "native_attestation_algorithm",
    "native_public_key_id",
    "native_build_id",
    "native_binary_contract_sha256",
    "canonical_test_contract_sha256",
}
_PYTEST_CONTRACT_FIELDS = {
    "schema_version",
    "exit_status",
    "collection_count",
    "collection_nodeids_sha256",
    "executed_count",
    "executed_nodeids_sha256",
    "passed_count",
    "failed_count",
    "skipped_count",
    "contract_sha256",
}
_CANONICAL_CONTRACT_FIELDS = {
    "schema_version",
    "contract_kind",
    "suites",
    "contract_sha256",
}
_CANONICAL_SUITE_FIELDS = {
    "targets",
    "collection_count",
    "nodeids",
    "nodeids_sha256",
}
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUMMARY = re.compile(r"(?P<count>[0-9]+) passed")
_FAILED = re.compile(r"(?P<count>[0-9]+) failed")
_MAX_CAPTURE_BYTES = 2 * 1024 * 1024
OFFICIAL_RECEIPT_TIMEOUT_SECONDS = 14_400
_PROTECTED_WORK_SUBTREES = (
    Path("offline-test-runner-venv"),
    Path("real-p0-codex-v2"),
    Path("real-p0-pragmatic-v1"),
    Path("p0-training-ready-v1"),
    Path("p1-pragmatic-control-v1"),
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _tree_commitment(root: Path, patterns: tuple[str, ...]) -> str:
    entries: list[dict[str, str]] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if path in seen or not path.is_file() or path.is_symlink():
                continue
            seen.add(path)
            raw = _read_regular(path, limit=16 * 1024 * 1024)
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _sha256(raw),
                }
            )
    if not entries:
        raise ValueError("test receipt code tree is empty")
    return _sha256(_canonical(entries))

def build_runner_lock(root: Path) -> dict[str, Any]:
    """Return a freshly and fully validated v7 runtime contract.

    Creating or rewriting a lock is intentionally reserved for the stdlib-only
    maintenance bootstrap; site code cannot self-sign a changed runtime.
    """

    value, _, _ = _load_runner_lock(root)
    return value


def _load_runner_lock(
    root: Path,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    """Revalidate the entire closure without a cross-boundary cache.

    The validator function was loaded by the stdlib-only bootstrap before any
    site/project import.  Re-running the bootstrap path here would itself be a
    use-before-validation bug if that file changed after startup.
    """

    root = Path(root).resolve(strict=True)
    marker = getattr(sys, "_egsi_locked_runtime_bootstrap", None)
    validation = getattr(sys, "_egsi_locked_runtime_validation", None)
    if not (
        type(marker) is tuple
        and len(marker) == 2
        and marker[0] == str(root)
        and type(validation) is tuple
        and len(validation) == 2
        and validation[0] == str(root)
        and callable(validation[1])
        and sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.pycache_prefix == "/nonexistent/egsi-locked-pycache"
    ):
        raise ValueError("locked runtime bootstrap is unavailable")
    try:
        value, lock_sha256, lock_identity = validation[1](root)
    except Exception:
        raise ValueError("offline runner lock validation failed") from None
    if (
        type(value) is not dict
        or value.get("schema_version") != "8.0"
        or value.get("runner_contract_version") != _RUNNER_CONTRACT_VERSION
        or type(lock_sha256) is not str
        or _SHA256.fullmatch(lock_sha256) is None
        or type(lock_identity) is not dict
    ):
        raise ValueError("offline runner lock validation failed")
    return value, lock_sha256, lock_identity


def load_runner_lock(root: Path) -> dict[str, Any]:
    """Load and exactly validate the source-approved local runtime."""

    value, _, _ = _load_runner_lock(root)
    return value


def update_runner_lock(root: Path) -> dict[str, Any]:
    """Fail closed: maintenance is only the stdlib bootstrap CLI."""

    del root
    raise ValueError("use scripts/update_offline_test_runner_lock.py")


def _load_canonical_test_contract(root: Path) -> dict[str, Any]:
    path = root / _CANONICAL_CONTRACT_RELATIVE
    raw = _read_regular(path, limit=2 * 1024 * 1024)
    value = strict_json_loads(raw, max_bytes=2 * 1024 * 1024)
    if (
        type(value) is not dict
        or set(value) != _CANONICAL_CONTRACT_FIELDS
        or value.get("schema_version") != "1.0"
        or value.get("contract_kind") != "canonical_pytest_collection"
        or type(value.get("suites")) is not dict
        or set(value["suites"]) != {"focused", "full"}
        or value.get("contract_sha256")
        != _dict_commitment(value, "contract_sha256")
    ):
        raise ValueError("canonical test contract is invalid")
    expected_targets = {
        "focused": list(FOCUSED_TEST_FILES),
        "full": ["tests"],
    }
    for name, suite in value["suites"].items():
        if (
            type(suite) is not dict
            or set(suite) != _CANONICAL_SUITE_FIELDS
            or suite.get("targets") != expected_targets[name]
            or type(suite.get("collection_count")) is not int
            or suite["collection_count"] <= 1
            or type(suite.get("nodeids")) is not list
            or len(suite["nodeids"]) != suite["collection_count"]
            or any(
                type(nodeid) is not str
                or not nodeid
                or not nodeid.startswith("tests/")
                for nodeid in suite["nodeids"]
            )
            or len(set(suite["nodeids"])) != len(suite["nodeids"])
            or suite.get("nodeids_sha256")
            != _sha256(_canonical(suite["nodeids"]))
        ):
            raise ValueError("canonical test suite contract is invalid")
    if value["suites"]["full"]["collection_count"] < value["suites"][
        "focused"
    ]["collection_count"]:
        raise ValueError("canonical test suite counts are incoherent")
    return value


def _current_code_commitments(
    root: Path, runner_lock_sha256: str, project_identity_sha256: str
) -> dict[str, str]:
    pyproject = root / "pyproject.toml"
    source_tree = _tree_commitment(root, ("src/**/*.py", "scripts/*.py"))
    tests_tree = _tree_commitment(root, ("tests/**/*.py",))
    pyproject_sha256 = _sha256(_read_regular(pyproject, limit=1024 * 1024))
    historical_expectation_sha256 = _sha256(
        _read_regular(
            root / "configs/historical-teacher-audit-expectation.v1.json",
            limit=1024 * 1024,
        )
    )
    first_case_historical_expectation_sha256 = _sha256(
        _read_regular(
            root
            / "configs/first-case-historical-teacher-audit-expectation.v1.json",
            limit=1024 * 1024,
        )
    )
    canonical_test_contract_sha256 = _sha256(
        _read_regular(
            root / _CANONICAL_CONTRACT_RELATIVE,
            limit=2 * 1024 * 1024,
        )
    )
    return {
        "source_tree_sha256": source_tree,
        "tests_tree_sha256": tests_tree,
        "pyproject_toml_sha256": pyproject_sha256,
        "pytest_local_inventory_sha256": _sha256(
            _canonical(
                {
                    "source_tree_sha256": source_tree,
                    "tests_tree_sha256": tests_tree,
                    "pyproject_toml_sha256": pyproject_sha256,
                    "offline_test_runner_lock_sha256": runner_lock_sha256,
                    "canonical_test_contract_sha256": (
                        canonical_test_contract_sha256
                    ),
                }
            )
        ),
        "offline_test_runner_lock_sha256": runner_lock_sha256,
        "historical_expectation_sha256": historical_expectation_sha256,
        "first_case_historical_expectation_sha256": (
            first_case_historical_expectation_sha256
        ),
        "project_identity_sha256": project_identity_sha256,
        "canonical_test_contract_sha256": canonical_test_contract_sha256,
    }


def current_code_commitments(root: Path) -> dict[str, str]:
    root = Path(root).resolve(strict=True)
    lock, runner_lock_sha256, _ = _load_runner_lock(root)
    return _current_code_commitments(
        root, runner_lock_sha256, lock["project_identity_sha256"]
    )


def _validate_pytest_root(root: Path) -> None:
    """Fail closed if a root hook or alternate pytest config exists at all."""

    for name in _FORBIDDEN_ROOT_PYTEST_HOOKS:
        try:
            (root / name).lstat()
        except FileNotFoundError:
            continue
        raise ValueError("forbidden root pytest hook or config exists")


def canonical_test_environment() -> dict[str, str]:
    """Return the exact security-relevant environment recorded in a receipt."""

    return dict(_RECORDED_ENVIRONMENT)


def _canonical_test_command(
    root: Path, name: str, runner_lock: dict[str, Any]
) -> list[str]:
    if name not in {"focused", "full"}:
        raise ValueError("unknown canonical test suite")
    relative_targets = FOCUSED_TEST_FILES if name == "focused" else ("tests",)
    for relative in relative_targets:
        target = root / relative
        target.resolve(strict=True).relative_to(root)
        if not target.exists() or target.is_symlink():
            raise ValueError("canonical test target is unavailable")
    return [
        runner_lock["command_executable"],
        "-X",
        "pycache_prefix=/nonexistent/egsi-locked-pycache",
        "-I",
        "-B",
        "-S",
        str((root / "scripts/locked_runtime_bootstrap.py").resolve(strict=True)),
        "pytest",
        "--root",
        str(root),
        "--",
        "-c",
        str((root / "pyproject.toml").resolve(strict=True)),
        "-q",
        "-p",
        "no:cacheprovider",
        "-p",
        "egsi.generation.pytest_contract",
        f"--confcutdir={(root / 'tests').resolve(strict=True)}",
        *relative_targets,
    ]


def canonical_test_command(root: Path, name: str) -> list[str]:
    """Return the only permitted argv for a named project test receipt."""

    root = Path(root).resolve(strict=True)
    _validate_pytest_root(root)
    runner_lock, _, _ = _load_runner_lock(root)
    return _canonical_test_command(root, name, runner_lock)


def _identity_sha256(value: dict[str, Any]) -> str:
    return _sha256(_canonical(value))


def _runner_contract_from_lock(
    lock: dict[str, Any], lock_sha256: str, lock_identity: dict[str, Any]
) -> dict[str, Any]:
    distributions = lock["distributions"]
    canonical_contract_entries = [
        item
        for item in lock["project_inventory"]
        if item["path"] == _CANONICAL_CONTRACT_RELATIVE.as_posix()
    ]
    if len(canonical_contract_entries) != 1:
        raise ValueError("canonical test contract is absent from runner lock")
    return {
        "runner_contract_version": lock["runner_contract_version"],
        "command_executable": lock["command_executable"],
        "resolved_executable": lock["resolved_executable"],
        "executable_identity_sha256": _identity_sha256(
            lock["executable_identity"]
        ),
        "pyvenv_cfg_identity_sha256": _identity_sha256(
            lock["pyvenv_cfg_identity"]
        ),
        "bootstrap_identity_sha256": _identity_sha256(
            lock["bootstrap_identity"]
        ),
        "canonical_config_identity_sha256": _identity_sha256(
            lock["canonical_config_identity"]
        ),
        "python_implementation": lock["python_implementation"],
        "python_version": lock["python_version"],
        "pytest_version": distributions["pytest"]["version"],
        "pluggy_version": distributions["pluggy"]["version"],
        "pytest_module_file_sha256": distributions["pytest"][
            "module_file_sha256"
        ],
        "pluggy_module_file_sha256": distributions["pluggy"][
            "module_file_sha256"
        ],
        "include_system_site_packages": lock[
            "include_system_site_packages"
        ],
        "no_pth": lock["no_pth"],
        "site_packages_tree_sha256": lock["site_packages_tree_sha256"],
        "stdlib_tree_sha256": lock["stdlib_tree_sha256"],
        "project_installed_tree_sha256": lock[
            "project_installed_tree_sha256"
        ],
        "runner_lock_sha256": lock_sha256,
        "runner_lock_identity_sha256": _identity_sha256(lock_identity),
        "project_identity_sha256": lock["project_identity_sha256"],
        "native_launcher_contract_sha256": lock[
            "native_launcher_contract"
        ]["contract_sha256"],
        "native_attestation_algorithm": lock["native_launcher_contract"][
            "attestation_algorithm"
        ],
        "native_public_key_id": lock["native_launcher_contract"][
            "public_key_id"
        ],
        "native_build_id": lock["native_launcher_contract"][
            "build_id"
        ],
        "native_binary_contract_sha256": lock["native_launcher_contract"][
            "binary_contract_sha256"
        ],
        "canonical_test_contract_sha256": canonical_contract_entries[0][
            "sha256"
        ],
    }


def _runner_contract(root: Path) -> dict[str, Any]:
    lock, lock_sha256, lock_identity = _load_runner_lock(root)
    return _runner_contract_from_lock(lock, lock_sha256, lock_identity)


def _runner_environment_commitment_from_lock(
    lock_sha256: str, lock_identity_sha256: str
) -> str:
    return _sha256(
        _canonical(
            {
                "runner_contract_version": _RUNNER_CONTRACT_VERSION,
                "runner_lock_sha256": lock_sha256,
                "runner_lock_identity_sha256": lock_identity_sha256,
                "environment": canonical_test_environment(),
            }
        )
    )


def _runner_environment_commitment(root: Path) -> str:
    _, lock_sha256, lock_identity = _load_runner_lock(root)
    return _runner_environment_commitment_from_lock(
        lock_sha256, _identity_sha256(lock_identity)
    )


def _test_runtime_snapshot(root: Path, name: str) -> dict[str, Any]:
    """Validate and capture every commitment used by one receipt boundary."""

    root = Path(root).resolve(strict=True)
    _validate_pytest_root(root)
    lock, lock_sha256, lock_identity = _load_runner_lock(root)
    canonical_contract = _load_canonical_test_contract(root)
    lock_identity_sha256 = _identity_sha256(lock_identity)
    return {
        "command": _canonical_test_command(root, name, lock),
        "runner": _runner_contract_from_lock(
            lock, lock_sha256, lock_identity
        ),
        "code_commitments": _current_code_commitments(
            root, lock_sha256, lock["project_identity_sha256"]
        ),
        "runner_environment_commitment_sha256": (
            _runner_environment_commitment_from_lock(
                lock_sha256, lock_identity_sha256
            )
        ),
        "canonical_test_suite": canonical_contract["suites"][name],
    }


def test_receipt_commitment(value: dict[str, Any]) -> str:
    return _dict_commitment(value, "receipt_commitment_sha256")


def _summary(stdout: bytes, stderr: bytes) -> tuple[int, int, str]:
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    passed_matches = list(_SUMMARY.finditer(text))
    if not passed_matches:
        return 0, 0, "pytest summary unavailable"
    passed = int(passed_matches[-1].group("count"))
    failed_matches = list(_FAILED.finditer(text))
    failed = int(failed_matches[-1].group("count")) if failed_matches else 0
    lines = [line.strip() for line in text.splitlines() if " passed" in line]
    summary_line = lines[-1][-512:] if lines else f"{passed} passed"
    return passed, failed, summary_line


def _pytest_contract(stdout: bytes, stderr: bytes) -> dict[str, Any]:
    captured = stdout + b"\n" + stderr
    if captured.count(_PYTEST_CONTRACT_PREFIX) != 1:
        raise ValueError("pytest emitted no unique execution contract")
    raw = captured.split(_PYTEST_CONTRACT_PREFIX, 1)[1].splitlines()[0]
    value = strict_json_loads(raw, max_bytes=64 * 1024)
    if (
        type(value) is not dict
        or set(value) != _PYTEST_CONTRACT_FIELDS
        or value.get("schema_version") != "1.0"
        or type(value.get("exit_status")) is not int
        or any(
            type(value.get(field)) is not int or value[field] < 0
            for field in (
                "collection_count",
                "executed_count",
                "passed_count",
                "failed_count",
                "skipped_count",
            )
        )
        or any(
            _SHA256.fullmatch(str(value.get(field))) is None
            for field in (
                "collection_nodeids_sha256",
                "executed_nodeids_sha256",
                "contract_sha256",
            )
        )
        or value.get("contract_sha256")
        != _dict_commitment(value, "contract_sha256")
    ):
        raise ValueError("pytest execution contract is invalid")
    return value


def _validate_pytest_execution_contract(
    value: dict[str, Any],
    *,
    expected: dict[str, Any],
    exit_code: int,
    passed: int,
    failed: int,
) -> None:
    if (
        value["exit_status"] != exit_code
        or value["collection_count"] != expected["collection_count"]
        or value["collection_nodeids_sha256"] != expected["nodeids_sha256"]
        or value["executed_count"] != value["collection_count"]
        or value["executed_nodeids_sha256"]
        != value["collection_nodeids_sha256"]
        or value["passed_count"] != passed
        or value["failed_count"] != failed
        or value["skipped_count"] != 0
        or passed + failed != value["executed_count"]
        or value["collection_count"] <= 1
    ):
        raise ValueError("pytest collection/execution contract mismatch")


def _execution_environment(home: Path, temporary: Path) -> dict[str, str]:
    environment = canonical_test_environment()
    environment["HOME"] = str(home)
    environment["TMPDIR"] = str(temporary)
    return environment


def _validate_receipt_output_destination(
    root: Path, output: Path, name: str
) -> Path:
    """Allow receipts only below project ``.work`` or the system ``/tmp``."""

    try:
        destination = Path(os.path.abspath(os.fspath(output)))
        resolved = destination.resolve(strict=False)
        work_root = (root / ".work").resolve(strict=False)
        temporary_root = Path("/tmp").resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("test receipt output destination is invalid") from None

    current = Path(destination.anchor)
    destination_exists = False
    try:
        for component in destination.parts[1:]:
            current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(
                    "test receipt output destination contains a symbolic link"
                )
            if current == destination:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError(
                        "test receipt output destination must be a single-link "
                        "regular file"
                    )
                destination_exists = True
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(
                    "test receipt output destination has a non-directory ancestor"
                )
    except OSError:
        raise ValueError("test receipt output destination is invalid") from None

    lexical_in_project = destination.is_relative_to(root)
    resolved_in_project = resolved.is_relative_to(root)
    below_work = (
        destination != work_root
        and resolved != work_root
        and destination.is_relative_to(work_root)
        and resolved.is_relative_to(work_root)
    )
    below_temporary = (
        destination.is_relative_to(temporary_root)
        and resolved.is_relative_to(temporary_root)
    )
    if lexical_in_project or resolved_in_project:
        expected_name = f"offline-{name}-receipt.json"
        protected = any(
            destination.is_relative_to(work_root / relative)
            or resolved.is_relative_to(
                (work_root / relative).resolve(strict=False)
            )
            for relative in _PROTECTED_WORK_SUBTREES
        )
        if below_work and destination_exists:
            raise ValueError(
                "test receipt output destination already exists inside "
                "project .work"
            )
        allowed = (
            below_work
            and destination.name == expected_name
            and resolved.name == expected_name
            and destination.parent.name == "reports"
            and resolved.parent.name == "reports"
            and not protected
        )
        if not allowed:
            raise ValueError(
                "test receipt output destination must be an unprotected "
                f".work/**/reports/{expected_name} path"
            )
    else:
        if not below_temporary:
            raise ValueError(
                "test receipt output destination must be below project .work "
                "or /tmp"
            )
    return destination


def _write_new_receipt_report(path: Path, report: dict[str, Any]) -> None:
    """Atomically publish one new project receipt without replacing a leaf."""

    if os.name != "posix" or type(report) is not dict:
        raise ValueError("test receipt publication is unavailable")
    try:
        raw = _canonical(report) + b"\n"
    except (TypeError, ValueError):
        raise ValueError("test receipt publication payload is invalid") from None
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("test receipt publication payload is oversized")
    try:
        parent_fd = open_directory_fd(path.parent, create=True)
    except (OSError, ValueError):
        raise ValueError("test receipt publication parent is unsafe") from None
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temporary_exists = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        temporary_exists = True
        try:
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "wb")
            descriptor = -1
            with handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        temporary_info = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(temporary_info.st_mode)
            or temporary_info.st_nlink != 1
            or stat.S_IMODE(temporary_info.st_mode) != 0o600
        ):
            raise ValueError("test receipt publication temporary is unsafe")
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise ValueError(
                "test receipt output destination appeared during test execution"
            ) from None
        os.unlink(temporary_name, dir_fd=parent_fd)
        temporary_exists = False
        published_info = os.stat(
            path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(published_info.st_mode)
            or published_info.st_nlink != 1
            or stat.S_IMODE(published_info.st_mode) != 0o600
            or (published_info.st_dev, published_info.st_ino)
            != (temporary_info.st_dev, temporary_info.st_ino)
        ):
            raise ValueError("test receipt publication identity is invalid")
        os.fsync(parent_fd)
    except ValueError:
        raise
    except OSError:
        raise ValueError("test receipt publication failed") from None
    finally:
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def run_test_receipt(
    *,
    root: Path,
    name: str,
    output: Path,
    timeout_seconds: int = OFFICIAL_RECEIPT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run one fixed project suite; callers cannot supply pytest argv."""

    if (
        type(name) is not str
        or name not in {"focused", "full"}
        or type(timeout_seconds) is not int
        or timeout_seconds <= 0
    ):
        raise ValueError("test receipt invocation is invalid")
    root = Path(root).resolve(strict=True)
    output = _validate_receipt_output_destination(root, output, name)
    before = _test_runtime_snapshot(root, name)
    command = before["command"]
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(
        prefix="egsi-offline-test-runner-", dir="/tmp"
    ) as temporary_root_value:
        temporary_root = Path(temporary_root_value)
        temporary_root.chmod(0o700)
        private_home = temporary_root / "home"
        private_tmp = temporary_root / "tmp"
        private_home.mkdir(mode=0o700)
        private_tmp.mkdir(mode=0o700)
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            shell=False,
            env=_execution_environment(private_home, private_tmp),
        )
    duration_ms = max(0, int((time.perf_counter() - started) * 1000))
    if (
        type(completed.stdout) is not bytes
        or type(completed.stderr) is not bytes
        or len(completed.stdout) > _MAX_CAPTURE_BYTES
        or len(completed.stderr) > _MAX_CAPTURE_BYTES
    ):
        raise ValueError("test output is invalid or exceeds receipt bound")
    after = _test_runtime_snapshot(root, name)
    if after != before:
        raise ValueError("runner or project changed during canonical test run")
    passed, failed, summary_line = _summary(completed.stdout, completed.stderr)
    pytest_contract = _pytest_contract(completed.stdout, completed.stderr)
    _validate_pytest_execution_contract(
        pytest_contract,
        expected=after["canonical_test_suite"],
        exit_code=completed.returncode,
        passed=passed,
        failed=failed,
    )
    receipt: dict[str, Any] = {
        "schema_version": "7.0",
        "receipt_kind": "canonical_offline_pytest_run",
        "native_attested": False,
        "name": name,
        "command": command,
        "cwd": ".",
        "environment": canonical_test_environment(),
        "runner": after["runner"],
        "started_at_utc": started_at.isoformat(),
        "duration_ms": duration_ms,
        "exit_code": completed.returncode,
        "passed_count": passed,
        "failed_count": failed,
        "summary_line": summary_line,
        "stdout_base64": base64.b64encode(completed.stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(completed.stderr).decode("ascii"),
        "stdout_sha256": _sha256(completed.stdout),
        "stderr_sha256": _sha256(completed.stderr),
        "project_identity_pre_sha256": before["runner"][
            "project_identity_sha256"
        ],
        "project_identity_post_sha256": after["runner"][
            "project_identity_sha256"
        ],
        "pytest_contract": pytest_contract,
        "code_commitments": after["code_commitments"],
        "runner_environment_commitment_sha256": after[
            "runner_environment_commitment_sha256"
        ],
        "receipt_commitment_sha256": "sha256:" + "0" * 64,
    }
    receipt["receipt_commitment_sha256"] = test_receipt_commitment(receipt)
    if output.is_relative_to(root):
        _write_new_receipt_report(output, receipt)
    else:
        write_report(output, receipt)
    committed = validate_test_receipt(
        output, root=root, expected_name=name, require_success=False
    )
    if committed != receipt:
        raise ValueError("test receipt readback mismatch")
    return receipt


def validate_test_receipt(
    path: Path,
    *,
    root: Path,
    expected_name: str,
    require_success: bool = True,
) -> dict[str, Any]:
    """Validate receipt structure, canonical argv/env/runner, output, and code."""

    try:
        root = Path(root).resolve(strict=True)
        snapshot = _test_runtime_snapshot(root, expected_name)
        info = Path(path).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError
        raw = _read_regular(Path(path), limit=8 * 1024 * 1024)
        value = strict_json_loads(raw, max_bytes=8 * 1024 * 1024)
        if type(value) is not dict or set(value) != _RECEIPT_FIELDS:
            raise ValueError
        if (
            value.get("schema_version") != "7.0"
            or value.get("receipt_kind") != "canonical_offline_pytest_run"
            or value.get("native_attested") is not False
            or value.get("name") != expected_name
            or expected_name not in {"focused", "full"}
            or value.get("command") != snapshot["command"]
            or value.get("cwd") != "."
            or value.get("environment") != canonical_test_environment()
            or type(value.get("runner")) is not dict
            or set(value["runner"]) != _RUNNER_FIELDS
            or value["runner"] != snapshot["runner"]
            or type(value.get("duration_ms")) is not int
            or value["duration_ms"] < 0
            or type(value.get("exit_code")) is not int
            or type(value.get("passed_count")) is not int
            or value["passed_count"] < 0
            or type(value.get("failed_count")) is not int
            or value["failed_count"] < 0
            or type(value.get("summary_line")) is not str
            or not value["summary_line"]
            or len(value["summary_line"].encode("utf-8")) > 512
            or type(value.get("stdout_base64")) is not str
            or type(value.get("stderr_base64")) is not str
            or not _SHA256.fullmatch(str(value.get("stdout_sha256")))
            or not _SHA256.fullmatch(str(value.get("stderr_sha256")))
            or value.get("project_identity_pre_sha256")
            != snapshot["runner"]["project_identity_sha256"]
            or value.get("project_identity_post_sha256")
            != snapshot["runner"]["project_identity_sha256"]
            or type(value.get("pytest_contract")) is not dict
            or set(value["pytest_contract"]) != _PYTEST_CONTRACT_FIELDS
            or type(value.get("code_commitments")) is not dict
            or set(value["code_commitments"]) != _CODE_COMMITMENT_FIELDS
            or any(
                not _SHA256.fullmatch(
                    str(value["code_commitments"].get(field))
                )
                for field in _CODE_COMMITMENT_FIELDS
            )
            or value.get("runner_environment_commitment_sha256")
            != snapshot["runner_environment_commitment_sha256"]
            or value.get("receipt_commitment_sha256")
            != test_receipt_commitment(value)
        ):
            raise ValueError
        stdout = base64.b64decode(value["stdout_base64"], validate=True)
        stderr = base64.b64decode(value["stderr_base64"], validate=True)
        observed_pytest_contract = _pytest_contract(stdout, stderr)
        if (
            len(stdout) > _MAX_CAPTURE_BYTES
            or len(stderr) > _MAX_CAPTURE_BYTES
            or value["stdout_sha256"] != _sha256(stdout)
            or value["stderr_sha256"] != _sha256(stderr)
            or (value["passed_count"], value["failed_count"], value["summary_line"])
            != _summary(stdout, stderr)
            or value["pytest_contract"] != observed_pytest_contract
        ):
            raise ValueError
        _validate_pytest_execution_contract(
            observed_pytest_contract,
            expected=snapshot["canonical_test_suite"],
            exit_code=value["exit_code"],
            passed=value["passed_count"],
            failed=value["failed_count"],
        )
        timestamp = datetime.fromisoformat(value["started_at_utc"])
        if timestamp.tzinfo is None:
            raise ValueError
        age = datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)
        if age.total_seconds() < -300 or age.total_seconds() > 86_400:
            raise ValueError
        if value["code_commitments"] != snapshot["code_commitments"]:
            raise ValueError
        if require_success and (
            value["exit_code"] != 0
            or value["failed_count"] != 0
            or value["passed_count"] <= 0
        ):
            raise ValueError
        return value
    except Exception:
        raise ValueError("test receipt validation failed") from None


def receipt_cli_main(argv: list[str], *, root: Path) -> int:
    """Locked-bootstrap-only CLI implementation for the native launcher."""

    parser = argparse.ArgumentParser(prog="run_test_receipt")
    parser.add_argument("--name", choices=("focused", "full"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        receipt = run_test_receipt(
            root=Path(root),
            name=arguments.name,
            output=arguments.output,
        )
    except Exception:
        return 2
    print(
        json.dumps(
            {
                "exit_code": receipt["exit_code"],
                "failed_count": receipt["failed_count"],
                "name": receipt["name"],
                "passed_count": receipt["passed_count"],
                "receipt_commitment_sha256": receipt[
                    "receipt_commitment_sha256"
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return int(receipt["exit_code"])
