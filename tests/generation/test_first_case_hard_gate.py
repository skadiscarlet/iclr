from __future__ import annotations

import ast
import base64
from contextlib import nullcontext
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import venv
from unittest.mock import MagicMock, patch

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parents[2]
SOURCE_OUTPUT = ROOT / ".work/real-p0-codex-v2"
CASE_ID = "ghsa-2m8h-fgr8-2q9w"
_FIRST_CASE_RETAINED_REQUEST_HASHES = {
    "sha256:2b5c0813090521e551898d9826badb33e33ae3a2134bbc72dbcc7360e236f91b",
    "sha256:7f1a883c1976f9f4ef44db4d3c707c7cdc794c94aac2f665c121edec3fec2ec4",
    "sha256:d84b78fbd6ad8c4d2143d0510bf8a367050b59e4d3804c16bfaaeb3d9153408f",
    "sha256:d8dcf6464ae26def2c8483d0b904fd72b7600a408b774c685e7e502f4dca1cb6",
    "sha256:68a3d9c4ad2cc6506aec853aed80cd6cd09d45604f9fec654f64f1a864aa59ae",
    "sha256:90645ae15c5181eeae8b4104718ed0a9f82d382ed4f9c438aec31d04a8aad4cd",
    "sha256:b6a9cb4e7cfb9e30e7070794b67e5481eea8a43306d249e621a87e24eef2c9e6",
    "sha256:d3194c5bab028d296915a34746e054fff363f4e2458f470b1281ac3962a77951",
    "sha256:3ff08b742a87a01533425742332ca34b6adb3330b543e52db72da157adc7f4a3",
    "sha256:7c7dbdb539baef3b02c5f7aac6118b161147da7b2d3d75678fe24d7e641df7b7",
}
_CURRENT_V23_REQUEST_HASH = (
    "sha256:7c7dbdb539baef3b02c5f7aac6118b161147da7b2d3d75678fe24d7e641df7b7"
)


def test_first_case_report_schema_requires_exact_compact_native_v8_projection() -> None:
    from egsi.generation.first_case_hard_gate import (
        _COMPACT_NATIVE_LAUNCHER_FIELDS,
        _COMPACT_NATIVE_RUNTIME_FIELDS,
        _COMPACT_NATIVE_STARTUP_FIELDS,
        _NATIVE_CONTRACT_FIELDS,
        _NATIVE_CONTRACT_SCHEMA_VERSION,
        _NATIVE_LAUNCHER_CONTRACT,
        _NATIVE_LAUNCHER_NAMES,
        VERIFIER_VERSION,
    )

    assert _NATIVE_CONTRACT_FIELDS == {
        "schema_version",
        "build_id",
        "public_key_id",
        "binary_contract_sha256",
        "build_record_file",
        "build_record_commitment_sha256",
        "contract_sha256",
        "bootstrap_anchor",
        "python_runtime_summary",
        "launchers",
    }
    assert _NATIVE_CONTRACT_SCHEMA_VERSION == "8.0"
    assert VERIFIER_VERSION == "5.2"
    assert _COMPACT_NATIVE_RUNTIME_FIELDS == {
        "schema_version",
        "invocation",
        "manifest_sha256",
        "summary_sha256",
        "startup_code",
    }
    assert _COMPACT_NATIVE_STARTUP_FIELDS == {
        "schema_version",
        "strategy",
        "manifest_sha256",
        "summary_sha256",
    }
    assert _COMPACT_NATIVE_LAUNCHER_FIELDS == {
        "file",
        "role",
        "read_policy",
        "build_sha256",
        "identity",
    }
    assert _NATIVE_LAUNCHER_NAMES == {
        "receipt",
        "report_signer",
        "verifier",
        "live_enrichment_signer",
        "live_enrichment_verifier",
    }
    assert _NATIVE_LAUNCHER_CONTRACT == {
        "receipt": (
            "scripts/run_test_receipt",
            "receipt_signer",
            "opaque-execute-only",
        ),
        "report_signer": (
            "scripts/rerun_first_case_hard_gate",
            "report_signer",
            "opaque-execute-only",
        ),
        "verifier": (
            "scripts/verify_first_case_hard_gate",
            "public_verifier",
            "readable-public-key-only",
        ),
        "live_enrichment_signer": (
            "scripts/run_fail_fast_enrich",
            "live_enrichment_signer",
            "opaque-execute-only",
        ),
        "live_enrichment_verifier": (
            "scripts/verify_fail_fast_enrich",
            "live_enrichment_verifier",
            "readable-public-key-only",
        ),
    }


def test_compact_native_projection_is_deterministic_and_strict_json_bounded() -> None:
    from egsi.contracts.trajectory import strict_json
    from egsi.generation.first_case_hard_gate import (
        _compact_native_launcher_contract,
    )

    full = json.loads(
        (ROOT / "configs/offline-test-runner.lock.json").read_text(
            encoding="utf-8"
        )
    )["native_launcher_contract"]
    with pytest.raises(ValueError, match="JSON structure exceeds safety limit"):
        strict_json({"native_launcher_contract": full})

    first = _compact_native_launcher_contract(full)
    second = _compact_native_launcher_contract(full)
    strict_json({"native_launcher_contract": first})

    assert first == second
    assert json.dumps(
        first, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") == json.dumps(
        second, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert first["contract_sha256"] == full["contract_sha256"]
    assert first["python_runtime_summary"]["summary_sha256"] == full[
        "python_runtime_summary"
    ]["summary_sha256"]
    assert first["python_runtime_summary"]["startup_code"][
        "summary_sha256"
    ] == full["python_runtime_summary"]["startup_code"]["summary_sha256"]


_COMPACT_NATIVE_TAMPER_PATHS = [
    ("schema_version",),
    ("build_id",),
    ("public_key_id",),
    ("binary_contract_sha256",),
    ("build_record_file",),
    ("build_record_commitment_sha256",),
    ("contract_sha256",),
    ("bootstrap_anchor", "sha256"),
    ("python_runtime_summary", "manifest_sha256"),
    ("python_runtime_summary", "summary_sha256"),
    (
        "python_runtime_summary",
        "startup_code",
        "manifest_sha256",
    ),
    (
        "python_runtime_summary",
        "startup_code",
        "summary_sha256",
    ),
] + [
    ("launchers", name, field)
    for name in (
        "receipt",
        "report_signer",
        "verifier",
        "live_enrichment_signer",
        "live_enrichment_verifier",
    )
    for field in ("build_sha256", "identity.sha256", "identity.mode")
]


@pytest.mark.parametrize("path", _COMPACT_NATIVE_TAMPER_PATHS)
def test_compact_native_projection_rejects_each_key_commitment_and_identity_tamper(
    path: tuple[str, ...],
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _compact_native_launcher_contract,
        _validate_compact_native_launcher_contract,
    )

    full = json.loads(
        (ROOT / "configs/offline-test-runner.lock.json").read_text(
            encoding="utf-8"
        )
    )["native_launcher_contract"]
    compact = json.loads(json.dumps(_compact_native_launcher_contract(full)))
    current: object = compact
    for component in path[:-1]:
        if "." in component:
            first, second = component.split(".", 1)
            current = current[first][second]  # type: ignore[index]
        else:
            current = current[component]  # type: ignore[index]
    field = path[-1]
    if "." in field:
        first, second = field.split(".", 1)
        container = current[first]  # type: ignore[index]
        old = container[second]
        container[second] = old + 1 if type(old) is int else str(old) + ".tampered"
    else:
        old = current[field]  # type: ignore[index]
        current[field] = old + 1 if type(old) is int else str(old) + ".tampered"  # type: ignore[index]

    with pytest.raises(ValueError, match="compact native launcher evidence mismatch"):
        _validate_compact_native_launcher_contract(compact, full)


_COMPACT_NATIVE_NUMERIC_PATHS = [
    ("bootstrap_anchor", "mode"),
    ("bootstrap_anchor", "size"),
] + [
    ("launchers", name, "identity", field)
    for name in (
        "receipt",
        "report_signer",
        "verifier",
        "live_enrichment_signer",
        "live_enrichment_verifier",
    )
    for field in (
        "mode",
        "links",
        "device",
        "inode",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
    )
]


@pytest.mark.parametrize("path", _COMPACT_NATIVE_NUMERIC_PATHS)
@pytest.mark.parametrize("invalid_kind", ["bool", "float"])
def test_compact_native_projection_rejects_bool_and_float_numeric_fields(
    path: tuple[str, ...], invalid_kind: str
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _compact_native_launcher_contract,
        _valid_compact_native_launcher_contract,
        _validate_compact_native_launcher_contract,
    )

    full = json.loads(
        (ROOT / "configs/offline-test-runner.lock.json").read_text(
            encoding="utf-8"
        )
    )["native_launcher_contract"]
    compact = json.loads(json.dumps(_compact_native_launcher_contract(full)))
    current: object = compact
    for component in path[:-1]:
        current = current[component]  # type: ignore[index]
    old = current[path[-1]]  # type: ignore[index]
    assert type(old) is int
    current[path[-1]] = (  # type: ignore[index]
        True if invalid_kind == "bool" else float(old)
    )

    assert _valid_compact_native_launcher_contract(compact) is False
    with pytest.raises(ValueError, match="compact native launcher evidence mismatch"):
        _validate_compact_native_launcher_contract(compact, full)


def _temporary_private_key(tmp_path: Path, name: str) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / name
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path


def _synthetic_probe_runner(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "synthetic-probe-project"
    (root / "scripts").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "configs").mkdir()
    (root / "idea-stage").mkdir()
    (root / "idea-stage/spec.json").write_text("{}\n", encoding="utf-8")
    (root / "src/egsi").mkdir(parents=True)
    (root / "src/egsi/__init__.py").write_text("\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='probe'\n", encoding="utf-8")
    shutil.copy2(
        ROOT / "scripts/locked_runtime_bootstrap.py",
        root / "scripts/locked_runtime_bootstrap.py",
    )
    for relative in (
        "scripts/locked_launcher.c",
        "scripts/rebuild_locked_launchers",
        "scripts/build_native_rsa_material.py",
    ):
        shutil.copy2(ROOT / relative, root / relative)
    private_key = _temporary_private_key(tmp_path, "probe.pem")
    runner = root / ".work/offline-test-runner-venv"
    venv.EnvBuilder(
        system_site_packages=False,
        clear=True,
        symlinks=False,
        with_pip=False,
    ).create(runner)
    site_packages = runner / "lib/python3.12/site-packages"
    shutil.copytree(root / "src/egsi", site_packages / "egsi")
    for name in ("pytest", "pluggy"):
        package = site_packages / name
        package.mkdir()
        (package / "__init__.py").write_text("\n", encoding="utf-8")
        metadata = site_packages / f"{name}-1.0.dist-info"
        metadata.mkdir()
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
            encoding="utf-8",
        )
    native_build = subprocess.run(
        [
            str(root / "scripts/rebuild_locked_launchers"),
            "--synthetic-output-dir",
            str(root / "scripts"),
            "--test-private-key-pem",
            str(private_key),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert native_build.returncode == 0, native_build.stderr
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HOME": "/nonexistent",
        "TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    built = subprocess.run(
        [
            str(runner / "bin/python"),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "build-lock", "--root", str(root),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    lock = json.loads(
        (root / "configs/offline-test-runner.lock.json").read_text(
            encoding="utf-8"
        )
    )
    return root, lock


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _commit(value: dict[str, object], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return _sha256(
        json.dumps(
            copy,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _strict_json_traversal_nodes(value: object) -> int:
    pending = [value]
    nodes = 0
    while pending:
        current = pending.pop()
        nodes += 1
        if type(current) is dict:
            pending.append(None)
            pending.extend(current.values())
        elif type(current) is list:
            pending.append(None)
            pending.extend(current)
    return nodes


def _completed(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    name = "full" if command[-1:] == ["tests"] else "focused"
    suite = json.loads(
        (ROOT / "configs/canonical-test-contract.v1.json").read_text()
    )["suites"][name]
    count = suite["collection_count"]
    contract: dict[str, object] = {
        "schema_version": "1.0",
        "exit_status": 0,
        "collection_count": count,
        "collection_nodeids_sha256": suite["nodeids_sha256"],
        "executed_count": count,
        "executed_nodeids_sha256": suite["nodeids_sha256"],
        "passed_count": count,
        "failed_count": 0,
        "skipped_count": 0,
        "contract_sha256": "sha256:" + "0" * 64,
    }
    contract["contract_sha256"] = _commit(
        contract, "contract_sha256"
    )
    return subprocess.CompletedProcess(
        command,
        0,
        stdout=(
            "................................ [100%]EGSI_PYTEST_CONTRACT="
            + json.dumps(contract, sort_keys=True, separators=(",", ":"))
            + f"\n{count} passed in 0.01s\n"
        ).encode(),
        stderr=b"",
    )


def _receipts(output: Path, tmp_path: Path) -> tuple[Path, Path]:
    from egsi.generation.test_receipt import canonical_test_command, run_test_receipt

    focused = output / "reports/offline-focused-receipt.json"
    full = output / "reports/offline-full-receipt.json"
    with patch("egsi.generation.test_receipt.subprocess.run") as run:
        run.side_effect = lambda command, **_: _completed(command)
        run_test_receipt(root=ROOT, name="focused", output=focused)
        run_test_receipt(root=ROOT, name="full", output=full)
    assert canonical_test_command(ROOT, "focused")
    return focused, full


def _fake_canonical_receipt(*, root: Path, name: str, output: Path):
    from egsi.generation import test_receipt as receipt_module

    command = receipt_module.canonical_test_command(root, name)
    with patch("egsi.generation.test_receipt.subprocess.run") as run:
        run.return_value = _completed(command)
        return receipt_module.run_test_receipt(
            root=root,
            name=name,
            output=output,
        )


def _issue_report(
    output: Path,
    *,
    report_name: str = "first-case-hard-gate-v2.json",
):
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    focused = output / "reports/offline-focused-receipt.json"
    full = output / "reports/offline-full-receipt.json"
    report_path = output / f"reports/{report_name}"
    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher",
        side_effect=_fake_canonical_receipt,
    ):
        report = verify_first_case_hard_gate(
            root=ROOT,
            output_root=output,
            case_id=CASE_ID,
            focused_receipt=focused,
            full_receipt=full,
            report_path=report_path,
            mode="rerun-tests",
        )
    return report, focused, full, report_path


def _copied_output(tmp_path: Path) -> Path:
    output = tmp_path / "real-p0-codex-v2"
    shutil.copytree(SOURCE_OUTPUT, output)
    recovered_case_id = "ghsa-3wfj-vh84-732p"
    recovered_record = output / "enrichment" / f"{recovered_case_id}.json"
    recovered_record.unlink(missing_ok=True)
    for archived_positive in (
        output / "enrichment/quarantine"
    ).glob(f"{recovered_case_id}.*.json"):
        archived_positive.unlink()
    archived_failures = sorted(
        (output / "reports/remaining-p0/history").glob(
            f"failure-{recovered_case_id}.*.json"
        )
    )
    assert len(archived_failures) == 1
    shutil.copy2(
        archived_failures[0],
        output / "enrichment/failures" / f"{recovered_case_id}.json",
    )
    audit_root = output / "audit/teacher"
    retained_responses: set[str] = set()
    for request_dir in sorted(audit_root.iterdir()):
        manifests = sorted(request_dir.glob("*/attempt-00/manifest.json"))
        values = [json.loads(path.read_text(encoding="utf-8")) for path in manifests]
        retain = (
            request_dir.name in _FIRST_CASE_RETAINED_REQUEST_HASHES
            or (
                request_dir.name != _CURRENT_V23_REQUEST_HASH
                and any(
                    value.get("status") == "quarantined"
                    and value.get("failure_code") == "provider_failure_event"
                    for value in values
                )
            )
        )
        if not retain:
            shutil.rmtree(request_dir)
            continue
        retained_responses.update(
            value["response_commitment_sha256"]
            for value in values
            if value.get("status") == "committed"
        )
    for cache_path in sorted((output / "cache/teacher").glob("*.json")):
        response = json.loads(cache_path.read_text(encoding="utf-8"))
        if response.get("response_commitment_sha256") not in retained_responses:
            cache_path.unlink()
    return output


def test_frozen_v21_validation_does_not_relax_current_v22_path_contract(
    tmp_path: Path,
) -> None:
    from egsi.contracts.enrichment import EnrichmentRecord
    from egsi.generation.enrichment import (
        _load_store,
        allowed_action_values,
        validate_payload,
    )
    from egsi.generation.first_case_hard_gate import (
        _validate_frozen_v21_payload,
        catalog_index,
    )

    output = _copied_output(tmp_path)
    case = catalog_index(ROOT)[CASE_ID]
    record = EnrichmentRecord.model_validate_json(
        (output / f"enrichment/{CASE_ID}.json").read_bytes()
    )
    vocabulary = allowed_action_values(ROOT)
    store = _load_store(ROOT, case)

    assert validate_payload(case, record.payload, store, vocabulary).valid is False
    assert _validate_frozen_v21_payload(
        case, record.payload, store, vocabulary
    ) == record.validation


def _tree_snapshot(root: Path) -> list[tuple[str, str, int, int, str | None]]:
    snapshot: list[tuple[str, str, int, int, str | None]] = []
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        kind = "file" if path.is_file() else "directory"
        digest = _sha256(path.read_bytes()) if kind == "file" else None
        snapshot.append(
            (
                path.relative_to(root).as_posix(),
                kind,
                info.st_mode,
                info.st_mtime_ns,
                digest,
            )
        )
    return snapshot


def _synthetic_native_attested_tree(
    tmp_path: Path,
) -> tuple[Path, Path]:
    synthetic_root = tmp_path / "synthetic-native"
    scripts = synthetic_root / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/locked_launcher.c", scripts / "locked_launcher.c")
    shutil.copy2(
        ROOT / "scripts/rebuild_locked_launchers",
        scripts / "rebuild_locked_launchers",
    )
    shutil.copy2(
        ROOT / "scripts/build_native_rsa_material.py",
        scripts / "build_native_rsa_material.py",
    )
    shutil.copy2(
        ROOT / "scripts/locked_runtime_bootstrap.py",
        scripts / "locked_runtime_bootstrap.py",
    )
    (synthetic_root / "configs").mkdir()
    runner_bin = synthetic_root / ".work/offline-test-runner-venv/bin"
    runner_bin.mkdir(parents=True)
    shutil.copy2(Path(sys.executable).resolve(strict=True), runner_bin / "python")
    (runner_bin / "python").chmod(0o755)
    private_key_path = _temporary_private_key(tmp_path, "native-tree.pem")
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    built = subprocess.run(
        [
            str(scripts / "rebuild_locked_launchers"),
            "--synthetic-output-dir",
            str(scripts),
            "--test-private-key-pem",
            str(private_key_path),
        ],
        cwd=synthetic_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    public = subprocess.run(
        [str(scripts / "run_test_receipt"), "--native-public-contract"],
        cwd=synthetic_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert public.returncode == 0, public.stderr
    fields = dict(line.split("=", 1) for line in public.stdout.splitlines())
    key_id = fields["EGSI_NATIVE_PUBLIC_KEY_ID"].removeprefix("sha256:")
    native_contract = fields["EGSI_NATIVE_BINARY_CONTRACT"].removeprefix(
        "sha256:"
    )
    output = tmp_path / "synthetic-output"
    reports = output / "reports"
    reports.mkdir(parents=True)
    artifacts = (
        (
            reports / "offline-focused-receipt.json",
            "egsi.test-receipt.focused.v1",
        ),
        (
            reports / "offline-full-receipt.json",
            "egsi.test-receipt.full.v1",
        ),
        (
            reports / "first-case-hard-gate.json",
            "egsi.first-case-report.v1",
        ),
    )
    for index, (artifact, domain) in enumerate(artifacts):
        artifact.write_text(
            json.dumps(
                {"native_attested": False, "synthetic_candidate": index},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        artifact.chmod(0o600)
        prefix = (
            "EGSI-NATIVE-ATTESTATION-V2\n"
            "algorithm=rsa-2048-sha256-pkcs1-v1_5\n"
            f"domain={domain}\n"
            f"artifact={artifact.name}\n"
            f"artifact_sha256={hashlib.sha256(artifact.read_bytes()).hexdigest()}\n"
            f"native_contract={native_contract}\n"
            f"key_id={key_id}\n"
        )
        signature = private_key.sign(
            prefix.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        ).hex()
        sidecar = Path(str(artifact) + ".native-attestation")
        sidecar.write_text(
            prefix + f"signature={signature}\n", encoding="ascii"
        )
        sidecar.chmod(0o600)
    return scripts, output


def test_only_rerun_tests_issues_attested_report_and_verify_only_replays(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    from egsi.teacher.base import TeacherRequest, teacher_request_hash

    output = _copied_output(tmp_path)
    case = gate_module.catalog_index(ROOT)[CASE_ID]
    context = gate_module.build_oracle_context(ROOT, case)
    vocabulary = gate_module._prompt_vocabulary(
        gate_module.allowed_action_values(ROOT)
    )
    expected_requests = {}
    for repair_code, repair_attempt in gate_module.EXPECTED_ATTEMPTS:
        system, user, schema = gate_module.enrichment_request_v21(
            context,
            vocabulary,
            repair_error=repair_code,
            repair_attempt=repair_attempt,
        )
        request = TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
        expected_requests[teacher_request_hash(request)] = request
    scan = gate_module._scan_teacher_audit(
        output,
        gate_module.PROVIDER,
        gate_module.MODEL,
        expected_requests=expected_requests,
    )
    assert (
        scan["committed"],
        scan["historical_unbound_committed"],
        scan["quarantined"],
        scan["manifest_count"],
    ) == (3, 6, 21, 30)
    assert scan["malformed_invalid"] == 0
    assert scan["identity_mismatches"] == 0
    assert scan["tool_events"] == 0
    assert scan["failure_codes"] == {"provider_failure_event": 21}
    assert scan["historical_unbound_set_sha256"] == (
        "sha256:56b3e5c42c38a0e76483f93e7a33fdc541174cd972fbab7a61b792b51b982833"
    )
    assert scan["historical_response_commitment_set_sha256"] == (
        "sha256:70098f756b27bb7ac8491d755fd789d1f117d2969475a123e36814cd8cad964d"
    )
    assert scan["provider_failure_audit_commitment_set_sha256"] == (
        "sha256:1a4bb5a83715bcaf2a5681505b6548ef7897b2db48f626cc6154e890f891bf58"
    )
    baseline_path = output / "reports/historical-teacher-audit-baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    cumulative_expectation = json.loads(
        (
            ROOT
            / "configs/first-case-historical-teacher-audit-expectation.v1.json"
        ).read_text(encoding="utf-8")
    )
    gate_module._validate_first_case_historical_delta(
        scan, baseline, cumulative_expectation
    )
    for field, different_identity in (
        ("provider", "different_provider"),
        ("model", "different_model"),
    ):
        resigned_cumulative = dict(cumulative_expectation)
        resigned_cumulative[field] = different_identity
        resigned_cumulative["expectation_commitment_sha256"] = _commit(
            resigned_cumulative, "expectation_commitment_sha256"
        )
        with pytest.raises(
            ValueError, match="historical expectation identity mismatch"
        ):
            gate_module._validate_first_case_historical_delta(
                scan, baseline, resigned_cumulative
            )
    generated, focused, full, report_path = _issue_report(output)
    from egsi.contracts.trajectory import strict_json

    strict_json(generated)
    replayed = gate_module.verify_first_case_hard_gate(
        root=ROOT,
        output_root=output,
        case_id=CASE_ID,
        focused_receipt=focused,
        full_receipt=full,
        report_path=report_path,
        mode="verify-only",
    )

    assert generated == replayed
    assert generated["attestation_mode"] == "rerun_tests"
    assert generated["status"] == "FIRST_CASE_GATE_PASSED"
    assert all(generated["hard_gates"].values())
    assert generated["human_semantic_judgment"] is None
    assert generated["scope"]["stop_marker"] == (
        "STOPPED_WITH_HISTORICAL_3WFJ_ATTEMPTS_BEFORE_LATER_EIGHT_P0_P1_GPU"
    )
    assert generated["scope"]["historical_remaining_p0_case_ids_attempted"] == [
        "ghsa-3wfj-vh84-732p"
    ]
    assert generated["scope"]["later_p0_cases_not_started"] == 8
    assert generated["final"]["provider_request_id_kind"] == "codex_thread_id"
    assert "provider_request_id" not in generated["final"]
    assert generated["verifier_evidence"]["verifier_source_sha256"].startswith(
        "sha256:"
    )
    native = generated["verifier_evidence"]["native_launcher_contract"]
    assert native["launchers"]["verifier"]["file"] == (
        "scripts/verify_first_case_hard_gate"
    )
    assert native["launchers"]["verifier"]["identity"]["mode"] == 0o555
    assert native["launchers"]["verifier"]["identity"]["sha256"] == native[
        "launchers"
    ]["verifier"]["build_sha256"]
    assert stat.S_IMODE(
        (ROOT / "scripts/verify_first_case_hard_gate").stat().st_mode
    ) == 0o555
    assert generated["test_receipts"]["focused"]["file_sha256"].startswith(
        "sha256:"
    )
    assert generated["invocations"]["current_final_record_committed"] == 1
    assert generated["invocations"]["current_repair_attempt_committed"] == 2
    assert generated["invocations"]["historical_unbound_committed"] == 6
    assert generated["invocations"]["added_after_smoke_historical"] == 5
    assert generated["invocations"]["malformed_invalid"] == 0
    assert generated["historical_evidence"][
        "historical_unbound_committed_set_sha256"
    ] == "sha256:56b3e5c42c38a0e76483f93e7a33fdc541174cd972fbab7a61b792b51b982833"
    assert baseline_path == (
        output / generated["historical_evidence"]["baseline_file"]
    )
    assert baseline["attestation_mode"] == "rerun_tests"
    # The report preserves the fail-fast pre-first-case baseline (5/20) while
    # binding the complete first-case audit inventory through a separate
    # cumulative expectation (6/21).  Reusing one source expectation for both
    # meanings is exactly the contract drift this regression prevents.
    assert baseline["historical_unbound_committed_count"] == 5
    assert baseline["historical_unbound_committed_set_sha256"] == (
        "sha256:3bb590d0ac78545a6a3552ac433ee745063801b5128f300ee2b9a8eadade5773"
    )
    assert baseline["provider_failure_event_quarantine_count"] == 20
    assert generated["historical_evidence"]["expectation_file"] == (
        "configs/first-case-historical-teacher-audit-expectation.v1.json"
    )
    base_expectation = json.loads(
        (ROOT / "configs/historical-teacher-audit-expectation.v1.json")
        .read_text(encoding="utf-8")
    )
    assert base_expectation["historical_unbound_committed_count"] == 5
    assert base_expectation["provider_failure_event_quarantine_count"] == 20
    assert cumulative_expectation["expectation_id"] == (
        "p0-first-case-cumulative-history-v1"
    )
    assert cumulative_expectation["historical_unbound_committed_count"] == 6
    assert cumulative_expectation[
        "provider_failure_event_quarantine_count"
    ] == 21
    assert generated["historical_evidence"]["baseline_file_sha256"] == _sha256(
        baseline_path.read_bytes()
    )
    assert (report_path.stat().st_mode & 0o777) == 0o600
    assert (baseline_path.stat().st_mode & 0o777) == 0o600


def test_current_full_native_contract_is_compacted_in_report_and_replays_byte_equal(
    tmp_path: Path,
) -> None:
    from egsi.contracts.trajectory import strict_json
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    lock_path = ROOT / "configs/offline-test-runner.lock.json"
    lock_raw = lock_path.read_bytes()
    lock = json.loads(lock_raw)
    lock_identity = {
        "path": "configs/offline-test-runner.lock.json",
        "sha256": _sha256(lock_raw),
    }
    output = _copied_output(tmp_path)
    with patch(
        "egsi.generation.first_case_hard_gate.load_runner_lock",
        return_value=lock,
    ), patch(
        "egsi.generation.test_receipt._load_runner_lock",
        return_value=(lock, _sha256(lock_raw), lock_identity),
    ):
        generated, focused, full, report_path = _issue_report(output)
        published = report_path.read_bytes()
        replayed = verify_first_case_hard_gate(
            root=ROOT,
            output_root=output,
            case_id=CASE_ID,
            focused_receipt=focused,
            full_receipt=full,
            report_path=report_path,
            mode="verify-only",
        )

    oversized = json.loads(json.dumps(generated))
    oversized["verifier_evidence"]["native_launcher_contract"] = lock[
        "native_launcher_contract"
    ]
    with pytest.raises(ValueError, match="JSON structure exceeds safety limit"):
        strict_json(oversized)
    strict_json(generated)

    assert _strict_json_traversal_nodes(oversized) > 4096
    assert _strict_json_traversal_nodes(generated) < 4096
    assert generated["schema_version"] == "5.2"
    assert generated == replayed
    assert report_path.read_bytes() == published


def test_report_mismatch_rejects_after_compact_report_publication(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        first_case_report_commitment,
        verify_first_case_hard_gate,
    )

    lock_path = ROOT / "configs/offline-test-runner.lock.json"
    lock_raw = lock_path.read_bytes()
    lock = json.loads(lock_raw)
    lock_identity = {
        "path": "configs/offline-test-runner.lock.json",
        "sha256": _sha256(lock_raw),
    }
    output = _copied_output(tmp_path)
    with patch(
        "egsi.generation.first_case_hard_gate.load_runner_lock",
        return_value=lock,
    ), patch(
        "egsi.generation.test_receipt._load_runner_lock",
        return_value=(lock, _sha256(lock_raw), lock_identity),
    ):
        _, focused, full, report_path = _issue_report(output)
        assert report_path.is_file()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["hard_gates"]["record_current"] = False
        report["report_commitment_sha256"] = first_case_report_commitment(
            report
        )
        report_path.write_text(
            json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="first-case hard gate"):
            verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="verify-only",
            )


def test_report_commitment_and_schema_reject_oversized_provider_failure_codes(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _validate_report_schema,
        first_case_report_commitment,
    )

    lock_path = ROOT / "configs/offline-test-runner.lock.json"
    lock_raw = lock_path.read_bytes()
    lock = json.loads(lock_raw)
    lock_identity = {
        "path": "configs/offline-test-runner.lock.json",
        "sha256": _sha256(lock_raw),
    }
    output = _copied_output(tmp_path)
    with patch(
        "egsi.generation.first_case_hard_gate.load_runner_lock",
        return_value=lock,
    ), patch(
        "egsi.generation.test_receipt._load_runner_lock",
        return_value=(lock, _sha256(lock_raw), lock_identity),
    ):
        report, _, _, _ = _issue_report(output)

    assert _strict_json_traversal_nodes(report) < 4096
    report["historical_evidence"]["provider_failure_codes"] = {
        f"failure-{index:04d}": 1 for index in range(5000)
    }
    report["report_commitment_sha256"] = _commit(
        report, "report_commitment_sha256"
    )
    assert _strict_json_traversal_nodes(report) > 4096

    with pytest.raises(ValueError, match="finite canonical UTF-8 JSON"):
        first_case_report_commitment(report)
    with pytest.raises(ValueError):
        _validate_report_schema(report)


def test_source_expectation_rejects_resigned_output_baseline_and_failure_history(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    import egsi.generation.human_audit as human_audit_module

    # One pathname may not supply the parsed trust value first and then be
    # reopened to supply different evidence bytes.  Under the old split API,
    # the first bounded read returned valid A and the evidence reopen returned
    # valid B, yielding A's commitment beside B's file digest.  The combined
    # API must observe the replacement before returning either result.
    expectation_root = tmp_path / "expectation-split-root"
    expectation_parent = expectation_root / "configs"
    expectation_parent.mkdir(parents=True)
    relative = Path("configs/expectation.json")
    expectation_path = expectation_root / relative
    alternate_path = expectation_parent / "alternate.json"
    original_path = expectation_parent / "original.json"
    value_a = json.loads(
        (
            ROOT / "configs/historical-teacher-audit-expectation.v1.json"
        ).read_text(encoding="utf-8")
    )
    value_b = dict(value_a)
    value_b["historical_unbound_committed_count"] += 1
    value_b["expectation_commitment_sha256"] = _commit(
        value_b, "expectation_commitment_sha256"
    )
    raw_a = json.dumps(
        value_a, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    raw_b = json.dumps(
        value_b, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    expectation_path.write_bytes(raw_a)
    alternate_path.write_bytes(raw_b)
    expectation_path.chmod(0o644)
    alternate_path.chmod(0o644)
    real_read = human_audit_module.os.read
    swapped = False

    def replace_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        chunk = real_read(descriptor, size)
        if chunk and not swapped:
            swapped = True
            os.replace(expectation_path, original_path)
            os.replace(alternate_path, expectation_path)
        return chunk

    with patch.object(
        human_audit_module.os, "read", side_effect=replace_after_first_read
    ):
        with pytest.raises(ValueError, match="historical expectation file is unsafe"):
            human_audit_module.historical_expectation_evidence(
                expectation_root,
                relative=relative,
                expectation_id=value_a["expectation_id"],
            )
    assert swapped is True
    assert expectation_path.read_bytes() == raw_b
    assert not (expectation_root / "reports").exists()

    # The pathname check is not authoritative: an unsafe actual descriptor
    # mode must be rejected even when both pathname stats are made to look
    # like the previously safe metadata.
    expectation_path.write_bytes(raw_a)
    expectation_path.chmod(0o644)
    real_stat = human_audit_module.os.stat
    safe_path_info = real_stat(expectation_path)
    expectation_path.chmod(0o666)

    def hide_actual_mode(path: object, *args: object, **kwargs: object):
        if (
            path == expectation_path.name
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            return safe_path_info
        return real_stat(path, *args, **kwargs)

    with patch.object(
        human_audit_module.os, "stat", side_effect=hide_actual_mode
    ):
        with pytest.raises(ValueError, match="historical expectation file is unsafe"):
            human_audit_module.load_historical_expectation_with_evidence(
                expectation_root,
                relative=relative,
                expectation_id=value_a["expectation_id"],
            )
    expectation_path.chmod(0o644)

    # A post-read pathname identity is part of the same transaction, rather
    # than advisory evidence gathered independently from the actual fd.
    alternate_path.write_bytes(raw_b)
    alternate_path.chmod(0o644)
    expected_info = real_stat(expectation_path)
    replacement_info = real_stat(alternate_path)
    pathname_stats = 0

    def replace_post_path_identity(
        path: object, *args: object, **kwargs: object
    ):
        nonlocal pathname_stats
        if (
            path == expectation_path.name
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            pathname_stats += 1
            return expected_info if pathname_stats == 1 else replacement_info
        return real_stat(path, *args, **kwargs)

    with patch.object(
        human_audit_module.os,
        "stat",
        side_effect=replace_post_path_identity,
    ):
        with pytest.raises(ValueError, match="historical expectation file is unsafe"):
            human_audit_module.load_historical_expectation_with_evidence(
                expectation_root,
                relative=relative,
                expectation_id=value_a["expectation_id"],
            )
    assert pathname_stats == 2

    # Even an A -> B -> A directory-entry ABA must fail closed.  Restoring the
    # original pathname/inode is insufficient because the anchored parent
    # metadata records the mutation.
    alternate_path.write_bytes(raw_b)
    alternate_path.chmod(0o644)
    aba_save = expectation_parent / "aba-save.json"
    parent_before_aba = real_stat(expectation_parent)
    aba_swapped = False

    def aba_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal aba_swapped
        chunk = real_read(descriptor, size)
        if chunk and not aba_swapped:
            aba_swapped = True
            os.replace(expectation_path, aba_save)
            os.replace(alternate_path, expectation_path)
            os.replace(expectation_path, alternate_path)
            os.replace(aba_save, expectation_path)
            os.utime(
                expectation_parent,
                ns=(
                    parent_before_aba.st_atime_ns,
                    parent_before_aba.st_mtime_ns + 1_000_000_000,
                ),
            )
        return chunk

    with patch.object(
        human_audit_module.os, "read", side_effect=aba_after_first_read
    ):
        with pytest.raises(ValueError, match="historical expectation file is unsafe"):
            human_audit_module.load_historical_expectation_with_evidence(
                expectation_root,
                relative=relative,
                expectation_id=value_a["expectation_id"],
            )
    assert aba_swapped is True
    assert expectation_path.read_bytes() == raw_a

    # Replacing the whole project root leaves the already-open configs and
    # leaf descriptors stable.  The absolute ancestor chain must still prove
    # that root/relative resolves to the same pinned directories after read.
    replacement_root = tmp_path / "expectation-replacement-root"
    replacement_parent = replacement_root / "configs"
    replacement_parent.mkdir(parents=True)
    replacement_path = replacement_root / relative
    replacement_path.write_bytes(raw_b)
    replacement_path.chmod(0o644)
    saved_old_root = tmp_path / "expectation-saved-old-root"
    root_swapped = False

    def replace_root_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal root_swapped
        chunk = real_read(descriptor, size)
        if chunk and not root_swapped:
            root_swapped = True
            os.replace(expectation_root, saved_old_root)
            os.replace(replacement_root, expectation_root)
        return chunk

    returned = None
    with patch.object(
        human_audit_module.os,
        "read",
        side_effect=replace_root_after_first_read,
    ):
        with pytest.raises(
            ValueError, match="historical expectation file is unsafe"
        ):
            returned = (
                human_audit_module.load_historical_expectation_with_evidence(
                    expectation_root,
                    relative=relative,
                    expectation_id=value_a["expectation_id"],
                )
            )
    assert root_swapped is True
    assert returned is None
    assert expectation_path.read_bytes() == raw_b

    # The hard-gate baseline helper must use the fail-closed combined API
    # before any receipt/provider/report writer can run.
    with patch.object(
        gate_module,
        "load_historical_expectation_with_evidence",
        create=True,
        side_effect=ValueError("historical expectation file is unsafe"),
    ) as combined, patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher"
    ) as run_receipt, patch(
        "egsi.generation.first_case_hard_gate.write_report"
    ) as write_report:
        with pytest.raises(ValueError, match="historical expectation file is unsafe"):
            gate_module._expected_historical_baseline(ROOT)
        combined.assert_called_once_with(ROOT)
        run_receipt.assert_not_called()
        write_report.assert_not_called()

    output = _copied_output(tmp_path)
    baseline_path = output / "reports/historical-teacher-audit-baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["baseline_commitment_sha256"] = _commit(
        baseline, "baseline_commitment_sha256"
    )
    baseline_path.write_text(
        json.dumps(baseline, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    baseline_path.chmod(0o600)

    quarantined = next(
        path
        for path in sorted((output / "audit/teacher").rglob("manifest.json"))
        if json.loads(path.read_text(encoding="utf-8"))["status"]
        == "quarantined"
    )
    manifest = json.loads(quarantined.read_text(encoding="utf-8"))
    manifest["latency_ms"] = float(manifest["latency_ms"]) + 1.0
    manifest["audit_commitment_sha256"] = _commit(
        manifest, "audit_commitment_sha256"
    )
    quarantined.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    quarantined.chmod(0o600)

    focused = output / "reports/resigned-focused.json"
    full = output / "reports/resigned-full.json"
    report_path = output / "reports/resigned-first-case.json"
    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher",
        side_effect=_fake_canonical_receipt,
    ):
        with pytest.raises(ValueError, match="first-case hard gate"):
            gate_module.verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="rerun-tests",
            )
    assert not report_path.exists()


def test_old_or_forged_1_and_999_receipts_cannot_issue_or_verify_pass_report(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate
    from egsi.generation.test_receipt import (
        canonical_test_command,
        run_test_receipt,
    )

    output = _copied_output(tmp_path)
    for count, name in ((1, "focused"), (999, "full")):
        path = output / f"reports/forged-{count}-{name}-receipt.json"
        command = canonical_test_command(ROOT, name)
        forged = _completed(command)
        expected_count = json.loads(
            (ROOT / "configs/canonical-test-contract.v1.json").read_text()
        )["suites"][name]["collection_count"]
        forged = subprocess.CompletedProcess(
            command,
            0,
            stdout=forged.stdout.replace(
                f"{expected_count} passed".encode(), f"{count} passed".encode()
            ),
            stderr=b"",
        )
        with patch("egsi.generation.test_receipt.subprocess.run") as run:
            run.return_value = forged
            with pytest.raises(ValueError, match="collection/execution"):
                run_test_receipt(root=ROOT, name=name, output=path)
        assert not path.exists()

    with pytest.raises(ValueError, match="first-case hard gate"):
        verify_first_case_hard_gate(
            root=ROOT,
            output_root=output,
            case_id=CASE_ID,
            focused_receipt=output / "reports/offline-focused-receipt.json",
            full_receipt=output / "reports/offline-full-receipt.json",
            report_path=output / "reports/first-case-hard-gate.json",
            mode="verify-only",
        )


@pytest.mark.parametrize(
    ("operation", "expected_replayed"),
    [("verify-only", False), ("rerun-tests", True)],
)
def test_verifier_cli_discloses_whether_tests_were_replayed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
    expected_replayed: bool,
) -> None:
    import egsi.generation.first_case_hard_gate as module
    monkeypatch.setattr(
        module,
        "verify_first_case_hard_gate",
        lambda **_: {
            "case_id": CASE_ID,
            "hard_gates": {"one": True},
            "status": "FIRST_CASE_GATE_PASSED",
            "scope": {
                "stop_marker": (
                    "STOPPED_AFTER_FIRST_CASE_BEFORE_REMAINING_P0_P1_GPU"
                )
            },
        },
    )
    common = [
        "--output-root", str(tmp_path),
        "--case-id", CASE_ID,
        "--focused-receipt", str(tmp_path / "focused.json"),
        "--full-receipt", str(tmp_path / "full.json"),
        "--report", str(tmp_path / "report.json"),
    ]
    operation_args = (
        ["--rerun-tests"]
        if operation == "rerun-tests"
        else ["--mode", "verify-only"]
    )
    assert module.first_case_cli_main(
        [*common, *operation_args], root=ROOT
    ) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["execution_replayed"] is expected_replayed


def test_verifier_cli_rejects_removed_generate_operation(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as module
    with pytest.raises(SystemExit) as exc:
        module.first_case_cli_main(
            [
                "--output-root", str(tmp_path),
                "--case-id", CASE_ID,
                "--focused-receipt", str(tmp_path / "focused.json"),
                "--full-receipt", str(tmp_path / "full.json"),
                "--report", str(tmp_path / "report.json"),
                "--mode", "generate",
            ],
            root=ROOT,
        )
    assert exc.value.code == 2


def test_default_cli_reexecutes_locked_isolated_runner_before_project_import(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "parent-shadow"
    (shadow / "egsi").mkdir(parents=True)
    (shadow / "egsi/__init__.py").write_text(
        "raise RuntimeError('parent shadow imported')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(shadow)
    environment["PYTHONUSERBASE"] = str(tmp_path / "user-base")
    script = ROOT / "scripts/verify_first_case_hard_gate"
    official = subprocess.run(
        [str(script), "--help"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert official.returncode == 0, official.stderr
    assert "--rerun-tests" not in official.stdout
    assert "verify-only" in official.stdout
    assert "parent shadow imported" not in official.stderr
    assert not (ROOT / "scripts/verify_first_case_hard_gate.py").exists()
    rerun = subprocess.run(
        [str(ROOT / "scripts/rerun_first_case_hard_gate"), "--help"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rerun.returncode == 0, rerun.stderr
    assert "--rerun-tests" in rerun.stdout
    assert "verify-only" not in rerun.stdout


def test_hard_gate_cli_does_not_import_pythonpath_shadow_before_isolation(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    marker = tmp_path / "SHADOW_IMPORT_EXECUTED"
    report = tmp_path / "must-not-create-report.json"
    (shadow / "json.py").write_text(
        f"open({str(marker)!r}, 'w').write('imported')\n"
        "raise RuntimeError('shadow json imported')\n",
        encoding="utf-8",
    )
    (shadow / "sitecustomize.py").write_text(
        f"open({str(marker)!r}, 'w').write('sitecustomize')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(shadow)
    completed = subprocess.run(
        [
            str(ROOT / "scripts/rerun_first_case_hard_gate"),
            "--help",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert not marker.exists()
    assert not report.exists()
    assert completed.returncode == 0


def test_official_verifier_rejects_duplicate_root_before_attacker_launcher(
    tmp_path: Path,
) -> None:
    attacker = tmp_path / "attacker-project"
    (attacker / "scripts").mkdir(parents=True)
    marker = tmp_path / "ATTACKER_LAUNCHER_EXECUTED"
    attacker_launcher = attacker / "scripts/run_test_receipt"
    attacker_launcher.write_text(
        "#!/bin/sh\n"
        f"printf executed > {str(marker)!r}\n"
        "exit 9\n",
        encoding="utf-8",
    )
    attacker_launcher.chmod(0o755)
    output = tmp_path / "output"
    output.mkdir()
    reports = output / "reports"
    completed = subprocess.run(
        [
            str(ROOT / "scripts/verify_first_case_hard_gate"),
            "--root", str(ROOT),
            "--output-root", str(output),
            "--case-id", CASE_ID,
            "--focused-receipt", str(reports / "focused.json"),
            "--full-receipt", str(reports / "full.json"),
            "--report", str(reports / "report.json"),
            "--rerun-tests",
            "--root", str(attacker),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert not marker.exists()
    assert not reports.exists()


def test_first_case_internal_receipt_rerun_uses_only_official_native_launcher(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    output = tmp_path / "focused.json"
    output.write_text("{}\n", encoding="utf-8")
    output.chmod(0o600)
    completed = subprocess.CompletedProcess(
        [str(ROOT / "scripts/run_test_receipt")],
        0,
        stdout=b'{"name":"focused"}\n',
        stderr=b"",
    )
    interpreter_contract = {
        "command_executable": str(ROOT / "pinned-python"),
        "resolved_executable": str(ROOT / "pinned-python"),
        "executable_identity": {"synthetic": True},
    }
    with patch.object(
        gate_module, "validate_test_receipt", return_value={"name": "focused"}
    ), patch.object(
        gate_module, "load_runner_lock", return_value=interpreter_contract
    ), patch.object(
        gate_module, "_run_bounded_process_group", return_value=completed
    ) as run:
        receipt = gate_module._run_official_receipt_launcher(
            root=ROOT,
            name="focused",
            output=output,
        )

    command = run.call_args.args[0]
    assert command == [
        str(ROOT / "scripts/run_test_receipt"),
        "--name", "focused",
        "--output", str(output),
    ]
    assert gate_module.OFFICIAL_RECEIPT_CLEANUP_GRACE_SECONDS == 300
    assert gate_module.OFFICIAL_RECEIPT_LAUNCHER_TIMEOUT_SECONDS == (
        gate_module.OFFICIAL_RECEIPT_TIMEOUT_SECONDS
        + gate_module.OFFICIAL_RECEIPT_CLEANUP_GRACE_SECONDS
    )
    assert gate_module.OFFICIAL_RECEIPT_LAUNCHER_TIMEOUT_SECONDS > (
        gate_module.OFFICIAL_RECEIPT_TIMEOUT_SECONDS
    )
    assert run.call_args.kwargs["timeout_seconds"] == (
        gate_module.OFFICIAL_RECEIPT_LAUNCHER_TIMEOUT_SECONDS
    )
    assert run.call_args.kwargs["_interpreter_contract"] is (
        interpreter_contract
    )
    assert receipt["name"] == "focused"


def test_bounded_process_group_timeout_kills_grandchild_without_delayed_marker(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    pid_file = tmp_path / "grandchild.pid"
    marker = tmp_path / "delayed.marker"
    grandchild = (
        "import os,signal,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        "time.sleep(1.5)\n"
        f"Path({str(marker)!r}).write_text('late')\n"
        "time.sleep(60)\n"
    )
    child = (
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
        "time.sleep(60)\n"
    )
    parent = (
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "time.sleep(60)\n"
    )

    with pytest.raises(ValueError, match="process group timed out"):
        _run_bounded_process_group(
            [sys.executable, "-c", parent],
            cwd=tmp_path,
            timeout_seconds=0.75,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )

    assert pid_file.is_file()
    grandchild_pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2.0
    while Path(f"/proc/{grandchild_pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    time.sleep(1.0)
    assert not Path(f"/proc/{grandchild_pid}").exists()
    assert not marker.exists()


def test_bounded_process_group_timeout_contains_setsid_grandchild(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    pid_file = tmp_path / "setsid-grandchild.pid"
    marker = tmp_path / "setsid-delayed.marker"
    grandchild = (
        "import os,signal,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        "time.sleep(1.5)\n"
        f"Path({str(marker)!r}).write_text('escaped')\n"
        "time.sleep(60)\n"
    )
    child = (
        "import subprocess,sys,time\n"
        "subprocess.Popen("
        f"[sys.executable, '-c', {grandchild!r}], start_new_session=True)\n"
        "time.sleep(60)\n"
    )
    parent = (
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "time.sleep(60)\n"
    )

    grandchild_pid: int | None = None
    try:
        with pytest.raises(ValueError, match="process group timed out"):
            _run_bounded_process_group(
                [sys.executable, "-c", parent],
                cwd=tmp_path,
                timeout_seconds=0.75,
                termination_grace_seconds=0.2,
                capture_limit=4096,
            )

        assert pid_file.is_file()
        grandchild_pid = int(pid_file.read_text(encoding="utf-8"))
        assert not Path(f"/proc/{grandchild_pid}").exists()
        time.sleep(1.0)
        assert not marker.exists()
    finally:
        if grandchild_pid is None and pid_file.is_file():
            grandchild_pid = int(pid_file.read_text(encoding="utf-8"))
        if grandchild_pid is not None and Path(
            f"/proc/{grandchild_pid}"
        ).exists():
            try:
                os.kill(grandchild_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_bounded_process_group_cleans_fast_success_detached_daemon(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    pid_file = tmp_path / "fast-detached.pid"
    marker = tmp_path / "fast-detached.marker"
    daemon = (
        "import os,signal,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        "time.sleep(1.0)\n"
        f"Path({str(marker)!r}).write_text('survived')\n"
        "time.sleep(60)\n"
    )
    root = (
        "import subprocess,sys,time\n"
        "from pathlib import Path\n"
        "subprocess.Popen("
        f"[sys.executable, '-c', {daemon!r}], start_new_session=True, "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL)\n"
        f"deadline=time.monotonic()+1.0\n"
        f"while not Path({str(pid_file)!r}).exists() and "
        "time.monotonic()<deadline: time.sleep(0.005)\n"
    )

    daemon_pid: int | None = None
    try:
        completed = _run_bounded_process_group(
            [sys.executable, "-c", root],
            cwd=tmp_path,
            timeout_seconds=2.0,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )
        assert completed.returncode == 0
        assert pid_file.is_file()
        daemon_pid = int(pid_file.read_text(encoding="utf-8"))
        assert not Path(f"/proc/{daemon_pid}").exists()
        time.sleep(1.2)
        assert not marker.exists()
    finally:
        if daemon_pid is None and pid_file.is_file():
            daemon_pid = int(pid_file.read_text(encoding="utf-8"))
        if daemon_pid is not None and Path(f"/proc/{daemon_pid}").exists():
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_bounded_process_group_cleans_double_detached_timeout_daemon(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    pid_file = tmp_path / "double-detached.pid"
    ready = tmp_path / "double-detached.ready"
    marker = tmp_path / "double-detached.marker"
    leaf = (
        "import os,signal,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        f"Path({str(ready)!r}).write_text('ready')\n"
        "time.sleep(1.0)\n"
        f"Path({str(marker)!r}).write_text('survived')\n"
        "time.sleep(60)\n"
    )
    middle = (
        "import subprocess,sys\n"
        "subprocess.Popen("
        f"[sys.executable, '-c', {leaf!r}], start_new_session=True, "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL)\n"
    )
    root = (
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {middle!r}], "
        "start_new_session=True)\n"
        "time.sleep(60)\n"
    )

    daemon_pid: int | None = None
    try:
        with pytest.raises(ValueError, match="process group timed out"):
            _run_bounded_process_group(
                [sys.executable, "-c", root],
                cwd=tmp_path,
                timeout_seconds=0.6,
                termination_grace_seconds=0.2,
                capture_limit=4096,
            )
        assert ready.is_file() and pid_file.is_file()
        daemon_pid = int(pid_file.read_text(encoding="utf-8"))
        assert not Path(f"/proc/{daemon_pid}").exists()
        time.sleep(0.8)
        assert not marker.exists()
    finally:
        if daemon_pid is None and pid_file.is_file():
            daemon_pid = int(pid_file.read_text(encoding="utf-8"))
        if daemon_pid is not None and Path(f"/proc/{daemon_pid}").exists():
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_dedicated_supervisor_preserves_preexisting_unrelated_child(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _proc_identity_is_current,
        _read_linux_proc_record,
        _run_bounded_process_group,
    )

    baseline = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        record = _read_linux_proc_record(baseline.pid)
        assert record is not None
        baseline_identity, parent_pid = record
        assert parent_pid == os.getpid()

        completed = _run_bounded_process_group(
            [sys.executable, "-c", "print('ok')"],
            cwd=tmp_path,
            timeout_seconds=2.0,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )

        assert completed.returncode == 0
        assert completed.stdout == b"ok\n"
        assert _proc_identity_is_current(baseline_identity)
        assert baseline.poll() is None
    finally:
        baseline.terminate()
        baseline.wait(timeout=2.0)


def test_helper_does_not_reap_concurrent_unrelated_thread_child(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    helper_started = tmp_path / "helper.started"
    root = (
        "import time\n"
        "from pathlib import Path\n"
        f"Path({str(helper_started)!r}).write_text('started')\n"
        "time.sleep(0.5)\n"
    )
    spawned = threading.Event()
    holder: list[subprocess.Popen[bytes]] = []

    def spawn_unrelated() -> None:
        deadline = time.monotonic() + 2.0
        while not helper_started.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        holder.append(child)
        spawned.set()

    thread = threading.Thread(target=spawn_unrelated)
    thread.start()
    try:
        completed = _run_bounded_process_group(
            [sys.executable, "-c", root],
            cwd=tmp_path,
            timeout_seconds=2.0,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )
        assert completed.returncode == 0
        assert spawned.wait(timeout=1.0)
        assert len(holder) == 1
        assert holder[0].poll() is None
        holder[0].terminate()
        assert holder[0].wait(timeout=2.0) == -signal.SIGTERM
    finally:
        thread.join(timeout=2.0)
        for child in holder:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2.0)


def test_dedicated_supervisor_pid_namespace_preserves_uid_gid_and_parent(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    source = ROOT / "src/egsi/generation/process_supervisor.py"
    program = (
        "import json,os\n"
        f"source={str(source)!r}\n"
        "print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),"
        "'stat_uid':os.stat(source).st_uid,'pid':os.getpid(),"
        "'ppid':os.getppid()},sort_keys=True))\n"
    )
    completed = _run_bounded_process_group(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        timeout_seconds=2.0,
        termination_grace_seconds=0.2,
        capture_limit=4096,
    )
    observed = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert observed == {
        "gid": os.getgid(),
        "pid": 2,
        "ppid": 1,
        "stat_uid": os.getuid(),
        "uid": os.getuid(),
    }


def test_nested_bounded_process_group_pins_child_inside_outer_pid_namespace(
    tmp_path: Path,
) -> None:
    supervisor = ROOT / "src/egsi/generation/process_supervisor.py"
    nested = (
        "import os,sys\n"
        "from pathlib import Path\n"
        "from egsi.generation.first_case_hard_gate import "
        "_run_bounded_process_group\n"
        "nspids=next(line.split()[1:] for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        "assert os.getpid() == 2\n"
        "assert len(nspids) >= 2 and int(nspids[-1]) == os.getpid()\n"
        "assert int(nspids[0]) != os.getpid()\n"
        "completed=_run_bounded_process_group("
        "[sys.executable,'-c',\"print('nested-ok')\"],"
        f"cwd=Path({str(tmp_path)!r}),timeout_seconds=2.0,"
        "termination_grace_seconds=0.2,capture_limit=4096)\n"
        "assert completed.returncode == 0\n"
        "assert completed.stdout == b'nested-ok\\n'\n"
        "print('outer-ok')\n"
    )
    outer = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            str(supervisor),
            "--cwd",
            str(ROOT),
            "--timeout-seconds",
            "10",
            "--termination-grace-seconds",
            "1",
            "--capture-limit",
            "65536",
            "--",
            sys.executable,
            "-c",
            nested,
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=False,
        check=False,
        timeout=15,
    )

    assert outer.returncode == 0, outer.stderr.decode("utf-8", "replace")
    envelope = json.loads(outer.stdout)
    target_stderr = base64.b64decode(envelope["stderr_base64"], validate=True)
    target_stdout = base64.b64decode(envelope["stdout_base64"], validate=True)
    assert envelope["status"] == "completed"
    assert envelope["returncode"] == 0, target_stderr.decode(
        "utf-8", "replace"
    )
    assert target_stdout == b"outer-ok\n"


def test_namespace_pid1_reaps_adopted_descendant_while_target_is_alive(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    pid_file = tmp_path / "adopted-descendant.pid"
    target = (
        "import os,time\n"
        "from pathlib import Path\n"
        f"pid_file=Path({str(pid_file)!r})\n"
        "intermediate=os.fork()\n"
        "if intermediate == 0:\n"
        "    descendant=os.fork()\n"
        "    if descendant == 0:\n"
        "        time.sleep(0.05)\n"
        "        os._exit(0)\n"
        "    pid_file.write_text(str(descendant))\n"
        "    os._exit(0)\n"
        "os.waitpid(intermediate, 0)\n"
        "deadline=time.monotonic()+0.75\n"
        "descendant=int(pid_file.read_text())\n"
        "while time.monotonic() < deadline:\n"
        "    try:\n"
        "        os.kill(descendant, 0)\n"
        "    except ProcessLookupError:\n"
        "        print('reaped')\n"
        "        break\n"
        "    time.sleep(0.005)\n"
        "else:\n"
        "    print('still-present')\n"
    )

    completed = _run_bounded_process_group(
        [sys.executable, "-c", target],
        cwd=tmp_path,
        timeout_seconds=2.0,
        termination_grace_seconds=0.2,
        capture_limit=4096,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"reaped\n"


def test_target_cannot_sigkill_namespace_pid1_or_escape_daemon(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    pid_file = tmp_path / "namespace-daemon.pid"
    marker = tmp_path / "namespace-daemon.marker"
    daemon = (
        "import os,time\n"
        "from pathlib import Path\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        "time.sleep(1.0)\n"
        f"Path({str(marker)!r}).write_text('escaped')\n"
        "time.sleep(60)\n"
    )
    target = (
        "import os,signal,subprocess,sys,time\n"
        "from pathlib import Path\n"
        "subprocess.Popen("
        f"[sys.executable, '-c', {daemon!r}], start_new_session=True, "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL)\n"
        "deadline=time.monotonic()+1.0\n"
        f"while not Path({str(pid_file)!r}).exists() and "
        "time.monotonic()<deadline: time.sleep(0.005)\n"
        "assert os.getppid() == 1\n"
        "os.kill(1, signal.SIGKILL)\n"
        "print('pid1-protected')\n"
    )

    daemon_pid: int | None = None
    try:
        completed = _run_bounded_process_group(
            [sys.executable, "-c", target],
            cwd=tmp_path,
            timeout_seconds=3.0,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )
        assert completed.returncode == 0
        assert completed.stdout == b"pid1-protected\n"
        assert pid_file.is_file()
        daemon_pid = int(pid_file.read_text(encoding="utf-8"))
        assert not Path(f"/proc/{daemon_pid}").exists()
        time.sleep(1.0)
        assert not marker.exists()
    finally:
        if daemon_pid is None and pid_file.is_file():
            daemon_pid = int(pid_file.read_text(encoding="utf-8"))
        if daemon_pid is not None and Path(f"/proc/{daemon_pid}").exists():
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_direct_sigkill_outer_eventually_destroys_pid_namespace(
    tmp_path: Path,
) -> None:
    supervisor = ROOT / "src/egsi/generation/process_supervisor.py"
    pid_file = tmp_path / "sigkill-outer-target.pid"
    ready = tmp_path / "sigkill-outer-target.ready"
    marker = tmp_path / "sigkill-outer-target.marker"
    target = (
        "import time\n"
        "from pathlib import Path\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        f"Path({str(ready)!r}).write_text('ready')\n"
        "time.sleep(0.5)\n"
        f"Path({str(marker)!r}).write_text('survived')\n"
        "time.sleep(60)\n"
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            str(supervisor),
            "--cwd",
            str(tmp_path),
            "--timeout-seconds",
            "60",
            "--termination-grace-seconds",
            "0.2",
            "--capture-limit",
            "4096",
            "--",
            sys.executable,
            "-c",
            target,
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    target_pid: int | None = None
    try:
        deadline = time.monotonic() + 3.0
        while not ready.is_file() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.005)
        assert ready.is_file() and pid_file.is_file()
        target_pid = int(pid_file.read_text(encoding="utf-8"))

        os.kill(process.pid, signal.SIGKILL)
        assert process.wait(timeout=2.0) == -signal.SIGKILL
        deadline = time.monotonic() + 2.0
        while Path(f"/proc/{target_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert not Path(f"/proc/{target_pid}").exists()
        time.sleep(0.55)
        assert not marker.exists()
    finally:
        if process.poll() is None:
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=2.0)
        if target_pid is not None and Path(f"/proc/{target_pid}").exists():
            try:
                os.kill(target_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_namespace_unavailable_fails_closed_without_launching_target(
    tmp_path: Path,
) -> None:
    import egsi.generation.process_supervisor as supervisor

    with patch.object(
        supervisor.os,
        "unshare",
        side_effect=PermissionError("synthetic namespace denial"),
    ), patch.object(supervisor.subprocess, "Popen") as popen:
        result = supervisor._namespace_supervise(
            [sys.executable, "-c", "print('unreachable')"],
            cwd=tmp_path,
            timeout_seconds=2.0,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )

    assert result == {
        "schema_version": "1.0",
        "status": "error",
        "returncode": None,
        "stdout_base64": "",
        "stderr_base64": "",
        "error_code": "namespace_unavailable",
    }
    popen.assert_not_called()


def test_bounded_process_group_never_changes_parent_subreaper_after_success(
    tmp_path: Path,
) -> None:
    from egsi.generation.process_supervisor import (
        _get_child_subreaper_state,
    )
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    before = _get_child_subreaper_state()
    completed = _run_bounded_process_group(
        [sys.executable, "-c", "print('ok')"],
        cwd=tmp_path,
        timeout_seconds=2.0,
        termination_grace_seconds=0.2,
        capture_limit=4096,
    )
    assert completed.returncode == 0
    assert _get_child_subreaper_state() == before


def test_bounded_process_group_launches_isolated_source_supervisor_without_parent_subreaper(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    from egsi.generation.process_supervisor import (
        _get_child_subreaper_state,
    )

    before = _get_child_subreaper_state()
    pinned_source: list[bytes] = []
    pinned_interpreter: list[bytes] = []

    def fail_after_inspecting_pinned_source(
        command: list[str], **kwargs: object
    ) -> None:
        descriptors = kwargs["pass_fds"]
        assert type(descriptors) is tuple and len(descriptors) == 4
        interpreter_fd = int(Path(command[0]).name)
        source_fd = int(Path(command[4]).name)
        gate_fd = int(command[6])
        ready_fd = int(command[8])
        assert command[5] == "--launch-gate-fd"
        assert command[7] == "--launch-ready-fd"
        assert set(descriptors) == {
            interpreter_fd,
            source_fd,
            gate_fd,
            ready_fd,
        }
        required_seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        assert (
            fcntl.fcntl(interpreter_fd, fcntl.F_GET_SEALS)
            & required_seals
            == required_seals
        )
        pinned_interpreter.append(
            os.pread(
                interpreter_fd,
                os.fstat(interpreter_fd).st_size + 1,
                0,
            )
        )
        pinned_source.append(os.pread(source_fd, 1024 * 1024, 0))
        raise OSError("synthetic launch failure")

    with patch.object(
        gate_module.subprocess,
        "Popen",
        side_effect=fail_after_inspecting_pinned_source,
    ) as popen:
        with pytest.raises(OSError, match="synthetic launch failure"):
            gate_module._run_bounded_process_group(
                [sys.executable, "-c", "print('unreachable')"],
                cwd=tmp_path,
                timeout_seconds=2.0,
                termination_grace_seconds=0.2,
                capture_limit=4096,
            )

    supervisor = (
        ROOT / "src/egsi/generation/process_supervisor.py"
    ).resolve(strict=True)
    supervisor_stat = supervisor.lstat()
    assert stat.S_ISREG(supervisor_stat.st_mode)
    assert supervisor_stat.st_nlink == 1
    launched = popen.call_args.args[0]
    assert launched[0].startswith("/proc/self/fd/")
    assert launched[1:4] == ["-I", "-B", "-S"]
    assert launched[4].startswith("/proc/self/fd/")
    assert launched[-4:] == [
        "--",
        sys.executable,
        "-c",
        "print('unreachable')",
    ]
    assert popen.call_args.kwargs["shell"] is False
    assert popen.call_args.kwargs["start_new_session"] is True
    assert popen.call_args.kwargs["close_fds"] is True
    assert len(pinned_source) == 1
    assert pinned_source[0] == supervisor.read_bytes()
    assert pinned_interpreter == [
        Path(sys.executable).resolve(strict=True).read_bytes()
    ]
    assert _get_child_subreaper_state() == before


@pytest.mark.parametrize("fault", ["proc_identity", "pidfd_pin"])
def test_post_launch_control_pin_failure_never_leaves_late_target_side_effect(
    tmp_path: Path,
    fault: str,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    marker = tmp_path / f"{fault}-late-marker"
    target = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(3.4)\n"
        f"Path({str(marker)!r}).write_text('escaped')\n"
    )
    fault_patch = (
        patch.object(gate_module, "_read_linux_proc_record", return_value=None)
        if fault == "proc_identity"
        else patch.object(gate_module, "_open_process_identity", return_value=None)
    )
    with fault_patch, patch.object(
        gate_module,
        "_PROCESS_SUPERVISOR_CLEANUP_BUDGET_SECONDS",
        -5.0,
    ):
        with pytest.raises(
            ValueError, match="process supervisor control pin failed"
        ):
            gate_module._run_bounded_process_group(
                [sys.executable, "-c", target],
                cwd=tmp_path,
                timeout_seconds=6.0,
                termination_grace_seconds=0.1,
                capture_limit=4096,
            )

    assert not marker.exists()
    time.sleep(0.55)
    assert not marker.exists()


def test_process_supervisor_capability_preflight_rejects_missing_pidfd_before_popen(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    with patch.object(
        gate_module.os,
        "pidfd_open",
        side_effect=OSError("synthetic pidfd denial"),
    ), patch.object(gate_module.subprocess, "Popen") as popen:
        with pytest.raises(ValueError, match="capabilities"):
            gate_module._run_bounded_process_group(
                [sys.executable, "-c", "raise SystemExit('unreachable')"],
                cwd=tmp_path,
                timeout_seconds=2.0,
                termination_grace_seconds=0.1,
                capture_limit=4096,
            )
    popen.assert_not_called()


@pytest.mark.parametrize(
    "stage",
    ["proc_identity", "pidfd_open", "gate_write_before", "gate_write_after"],
)
def test_control_setup_keyboard_interrupt_reaps_outer_and_blocks_late_target(
    tmp_path: Path,
    stage: str,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    marker = tmp_path / f"{stage}-keyboard-interrupt-marker"
    target = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(0.35)\n"
        f"Path({str(marker)!r}).write_text('escaped')\n"
    )
    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def record_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    if stage == "proc_identity":
        fault_patch = patch.object(
            gate_module,
            "_read_linux_proc_record",
            side_effect=KeyboardInterrupt,
        )
    elif stage == "pidfd_open":
        fault_patch = patch.object(
            gate_module,
            "_open_process_identity",
            side_effect=KeyboardInterrupt,
        )
    elif stage == "gate_write_before":
        def interrupt_before_write(
            descriptor: int, state: list[bool]
        ) -> None:
            del descriptor
            state[0] = True
            raise KeyboardInterrupt

        fault_patch = patch.object(
            gate_module,
            "_release_supervisor_launch_gate",
            side_effect=interrupt_before_write,
        )
    else:
        def write_then_interrupt(
            descriptor: int, state: list[bool]
        ) -> None:
            state[0] = True
            assert os.write(descriptor, b"G") == 1
            state[1] = True
            raise KeyboardInterrupt

        fault_patch = patch.object(
            gate_module,
            "_release_supervisor_launch_gate",
            side_effect=write_then_interrupt,
        )

    try:
        with patch.object(
            gate_module.subprocess,
            "Popen",
            side_effect=record_popen,
        ), fault_patch:
            with pytest.raises(KeyboardInterrupt):
                gate_module._run_bounded_process_group(
                    [sys.executable, "-c", target],
                    cwd=tmp_path,
                    timeout_seconds=2.0,
                    termination_grace_seconds=0.1,
                    capture_limit=4096,
                )
        assert len(spawned) == 1
        assert spawned[0].returncode is not None
        assert not marker.exists()
        time.sleep(0.55)
        assert not marker.exists()
    finally:
        for process in spawned:
            if process.poll() is None:
                os.kill(process.pid, signal.SIGKILL)
                process.wait(timeout=2.0)


def test_pidfd_signal_failure_falls_back_to_numeric_direct_child_cleanup(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    marker = tmp_path / "pidfd-signal-fallback-late-marker"
    target = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(3.4)\n"
        f"Path({str(marker)!r}).write_text('escaped')\n"
    )

    def deny_nonzero_signal(
        descriptor: int,
        signum: int,
        siginfo: object | None,
        flags: int,
    ) -> None:
        del descriptor, siginfo, flags
        if signum != 0:
            raise OSError("synthetic pidfd signal denial")

    with patch.object(
        gate_module.signal,
        "pidfd_send_signal",
        side_effect=deny_nonzero_signal,
    ), patch.object(
        gate_module,
        "_PROCESS_SUPERVISOR_CLEANUP_BUDGET_SECONDS",
        -5.0,
    ):
        with pytest.raises(ValueError, match="process group timed out"):
            gate_module._run_bounded_process_group(
                [sys.executable, "-c", target],
                cwd=tmp_path,
                timeout_seconds=6.0,
                termination_grace_seconds=0.1,
                capture_limit=4096,
            )

    assert not marker.exists()
    time.sleep(0.55)
    assert not marker.exists()


def test_pidfd_sigkill_failure_falls_back_to_unreaped_numeric_child() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    process = MagicMock(spec=subprocess.Popen)
    process.pid = 4321
    process.wait.side_effect = [
        subprocess.TimeoutExpired("supervisor", 2.0),
        0,
    ]
    process.returncode = -signal.SIGKILL

    def deny_pidfd_kill(
        descriptor: int,
        signum: int,
        siginfo: object | None,
        flags: int,
    ) -> None:
        del descriptor, siginfo, flags
        if signum == signal.SIGKILL:
            raise OSError("synthetic pidfd SIGKILL denial")

    with patch.object(
        gate_module.signal,
        "pidfd_send_signal",
        side_effect=deny_pidfd_kill,
    ), patch.object(gate_module.os, "kill") as numeric_kill:
        outcome = gate_module._terminate_supervisor_process(
            process,
            grace_seconds=0.1,
            root_pidfd=99,
        )

    assert outcome == "forced_fallback"
    numeric_kill.assert_called_once_with(4321, signal.SIGKILL)


def test_control_setup_cleanup_exception_prioritizes_containment_failure(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def record_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    try:
        with patch.object(
            gate_module.subprocess,
            "Popen",
            side_effect=record_popen,
        ), patch.object(
            gate_module,
            "_read_linux_proc_record",
            side_effect=KeyboardInterrupt,
        ), patch.object(
            gate_module,
            "_cleanup_supervisor_control_setup",
            side_effect=OSError("synthetic cleanup failure"),
        ):
            with pytest.raises(
                ValueError, match="process containment cleanup failed"
            ):
                gate_module._run_bounded_process_group(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=tmp_path,
                    timeout_seconds=2.0,
                    termination_grace_seconds=0.1,
                    capture_limit=4096,
                )
    finally:
        for process in spawned:
            if process.poll() is None:
                os.kill(process.pid, signal.SIGKILL)
                process.wait(timeout=2.0)


def test_bounded_process_group_never_changes_parent_subreaper_after_timeout(
    tmp_path: Path,
) -> None:
    from egsi.generation.process_supervisor import (
        _get_child_subreaper_state,
    )
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    before = _get_child_subreaper_state()
    with pytest.raises(ValueError, match="process group timed out"):
        _run_bounded_process_group(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=tmp_path,
            timeout_seconds=0.2,
            termination_grace_seconds=0.1,
            capture_limit=4096,
        )
    assert _get_child_subreaper_state() == before


def test_parent_outer_timeout_cleans_supervisor_tree_before_return(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    pid_file = tmp_path / "outer-timeout-leaf.pid"
    ready = tmp_path / "outer-timeout-leaf.ready"
    marker = tmp_path / "outer-timeout-leaf.marker"
    target = (
        "import os,signal,time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "host_pid=next(int(line.split()[1]) for line in "
        "Path('/proc/self/status').read_text().splitlines() "
        "if line.startswith('NSpid:'))\n"
        f"Path({str(pid_file)!r}).write_text(str(host_pid))\n"
        f"Path({str(ready)!r}).write_text('ready')\n"
        "time.sleep(1.0)\n"
        f"Path({str(marker)!r}).write_text('survived')\n"
        "time.sleep(60)\n"
    )

    leaf_pid: int | None = None
    try:
        with patch.object(
            gate_module,
            "_PROCESS_SUPERVISOR_CLEANUP_BUDGET_SECONDS",
            -1.5,
        ):
            with pytest.raises(ValueError, match="process group timed out"):
                gate_module._run_bounded_process_group(
                    [sys.executable, "-c", target],
                    cwd=tmp_path,
                    timeout_seconds=2.0,
                    termination_grace_seconds=0.2,
                    capture_limit=4096,
                )
        assert ready.is_file() and pid_file.is_file()
        leaf_pid = int(pid_file.read_text(encoding="utf-8"))
        assert not Path(f"/proc/{leaf_pid}").exists()
        time.sleep(1.0)
        assert not marker.exists()
    finally:
        if leaf_pid is None and pid_file.is_file():
            leaf_pid = int(pid_file.read_text(encoding="utf-8"))
        if leaf_pid is not None and Path(f"/proc/{leaf_pid}").exists():
            try:
                os.kill(leaf_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_outer_termination_after_pid1_reap_never_signals_reused_numeric_pid(
    tmp_path: Path,
) -> None:
    import egsi.generation.process_supervisor as supervisor

    result_read_fd, result_write_fd = os.pipe2(os.O_CLOEXEC)

    def reap_then_request_termination(pid: int) -> int:
        assert pid == 424242
        supervisor._OUTER_TERMINATION_REQUESTED = True
        return 0

    supervisor._OUTER_TERMINATION_REQUESTED = False
    try:
        with patch.object(
            supervisor,
            "_waitpid_nohang",
            side_effect=reap_then_request_termination,
        ), patch.object(
            supervisor,
            "_kill_and_reap_pid1",
            side_effect=AssertionError("reaped PID must never be signalled"),
        ):
            result = supervisor._outer_collect_result(
                424242,
                result_read_fd,
                timeout_seconds=1.0,
                termination_grace_seconds=0.1,
                capture_limit=4096,
            )
        assert result == {
            "schema_version": "1.0",
            "status": "error",
            "returncode": None,
            "stdout_base64": "",
            "stderr_base64": "",
            "error_code": "terminated",
        }
    finally:
        supervisor._OUTER_TERMINATION_REQUESTED = False
        os.close(result_read_fd)
        os.close(result_write_fd)


def test_supervisor_cleanup_ack_requires_unique_strict_terminated_relay() -> None:
    from egsi.generation.first_case_hard_gate import (
        _supervisor_cleanup_acknowledged,
    )

    terminated = {
        "schema_version": "1.0",
        "status": "error",
        "returncode": None,
        "stdout_base64": "",
        "stderr_base64": "",
        "error_code": "terminated",
    }
    assert _supervisor_cleanup_acknowledged(
        json.dumps(terminated).encode("ascii"), capture_limit=4096
    )
    for error_code in ("cleanup_failed", "internal_error", "timeout"):
        rejected = dict(terminated, error_code=error_code)
        assert not _supervisor_cleanup_acknowledged(
            json.dumps(rejected).encode("ascii"), capture_limit=4096
        )
    duplicate = (
        b'{"schema_version":"1.0","status":"error",'
        b'"returncode":null,"stdout_base64":"",'
        b'"stderr_base64":"","error_code":"terminated",'
        b'"error_code":"terminated"}'
    )
    assert not _supervisor_cleanup_acknowledged(
        duplicate, capture_limit=4096
    )


def test_supervisor_termination_outcome_distinguishes_forced_fallback() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    process = MagicMock(spec=subprocess.Popen)
    process.wait.side_effect = [
        subprocess.TimeoutExpired("supervisor", 2.0),
        0,
    ]
    with patch.object(
        gate_module.signal, "pidfd_send_signal"
    ) as send_signal:
        outcome = gate_module._terminate_supervisor_process(
            process,
            grace_seconds=0.2,
            root_pidfd=99,
        )

    assert outcome == "forced_fallback"
    assert send_signal.call_count == 2


def test_supervisor_graceful_termination_wait_exceeds_outer_reap_budget() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    process = MagicMock(spec=subprocess.Popen)
    process.wait.return_value = 0
    with patch.object(
        gate_module.signal, "pidfd_send_signal"
    ):
        outcome = gate_module._terminate_supervisor_process(
            process,
            grace_seconds=0.2,
            root_pidfd=99,
        )

    assert outcome == "graceful_exit"
    assert process.wait.call_args.kwargs["timeout"] > 1.0


def test_process_supervisor_cli_is_stdlib_only_and_emits_strict_result(
    tmp_path: Path,
) -> None:
    supervisor = ROOT / "src/egsi/generation/process_supervisor.py"
    raw_source = supervisor.read_bytes()
    source = raw_source.decode("utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.partition(".")[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.partition(".")[0])
    assert imported_roots <= set(sys.stdlib_module_names) | {"__future__"}
    assert all(
        banned not in source
        for banned in (
            "pkill",
            "killall",
            "/sys/fs/cgroup",
            "PR_SET_CHILD_SUBREAPER",
            "_linux_proc_snapshot",
        )
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            str(supervisor),
            "--cwd",
            str(tmp_path),
            "--timeout-seconds",
            "2.0",
            "--termination-grace-seconds",
            "0.2",
            "--capture-limit",
            "4096",
            "--",
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    result = json.loads(completed.stdout)
    assert set(result) == {
        "schema_version",
        "status",
        "returncode",
        "stdout_base64",
        "stderr_base64",
        "error_code",
    }
    assert result["schema_version"] == "1.0"
    assert result["status"] == "completed"
    assert result["returncode"] == 0
    assert result["error_code"] is None
    assert base64.b64decode(result["stdout_base64"], validate=True) == b"out\n"
    assert base64.b64decode(result["stderr_base64"], validate=True) == b"err\n"


def test_process_supervisor_dash_s_blocks_venv_pth_before_supervisor_code(
    tmp_path: Path,
) -> None:
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    interpreter = environment / "bin/python"
    site_packages = (
        environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    marker = tmp_path / "PTH_EXECUTED"
    (site_packages / "zzz_supervisor_attack.pth").write_text(
        "import pathlib; "
        f"pathlib.Path({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    control = subprocess.run(
        [str(interpreter), "-I", "-B", "-c", "print('control')"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    assert control.returncode == 0
    assert marker.read_text(encoding="utf-8") == "executed"
    marker.unlink()
    supervisor = ROOT / "src/egsi/generation/process_supervisor.py"
    completed = subprocess.run(
        [
            str(interpreter),
            "-I",
            "-B",
            "-S",
            str(supervisor),
            "--cwd",
            str(tmp_path),
            "--timeout-seconds",
            "2.0",
            "--termination-grace-seconds",
            "0.2",
            "--capture-limit",
            "4096",
            "--",
            sys.executable,
            "-c",
            "print('ok')",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert json.loads(completed.stdout)["status"] == "completed"
    assert not marker.exists()


def test_supervisor_source_is_hash_validated_and_sealed_before_path_swap(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    trusted = (
        ROOT / "src/egsi/generation/process_supervisor.py"
    ).read_bytes()
    supervisor = tmp_path / "process_supervisor.py"
    replacement = tmp_path / "replacement.py"
    supervisor.write_bytes(trusted)
    replacement.write_text("raise SystemExit('swapped')\n", encoding="utf-8")
    expected = "sha256:" + hashlib.sha256(trusted).hexdigest()
    observed: list[bytes] = []

    def swap_then_inspect(
        command: list[str], **kwargs: object
    ) -> None:
        os.replace(replacement, supervisor)
        descriptors = kwargs["pass_fds"]
        assert type(descriptors) is tuple and len(descriptors) == 4
        source_fd = int(Path(command[4]).name)
        gate_fd = int(command[6])
        assert command[5] == "--launch-gate-fd"
        assert source_fd in descriptors
        assert gate_fd in descriptors
        observed.append(os.pread(source_fd, 1024 * 1024, 0))
        with pytest.raises(OSError):
            os.write(source_fd, b"tamper")
        raise OSError("synthetic launch failure")

    with patch.object(
        gate_module,
        "_process_supervisor_source_path",
        return_value=supervisor,
    ), patch.object(
        gate_module,
        "_PROCESS_SUPERVISOR_SHA256",
        expected,
    ), patch.object(
        gate_module.subprocess,
        "Popen",
        side_effect=swap_then_inspect,
    ):
        with pytest.raises(OSError, match="synthetic launch failure"):
            gate_module._run_bounded_process_group(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout_seconds=2.0,
                termination_grace_seconds=0.2,
                capture_limit=4096,
            )

    assert observed == [trusted]
    assert supervisor.read_text(encoding="utf-8") == (
        "raise SystemExit('swapped')\n"
    )


def test_supervisor_interpreter_is_an_executable_sealed_copy_of_sys_executable() -> None:
    from egsi.generation.first_case_hard_gate import (
        _open_pinned_python_interpreter,
    )

    expected = Path(sys.executable).resolve(strict=True).read_bytes()
    descriptor = _open_pinned_python_interpreter()
    try:
        required_seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        assert (
            fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required_seals
            == required_seals
        )
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o111
        assert os.pread(descriptor, len(expected) + 1, 0) == expected
        completed = subprocess.run(
            [
                f"/proc/self/fd/{descriptor}",
                "-I",
                "-B",
                "-S",
                "-c",
                "print('sealed-interpreter-ok')",
            ],
            check=False,
            capture_output=True,
            text=False,
            close_fds=True,
            pass_fds=(descriptor,),
        )
        assert completed.returncode == 0
        assert completed.stdout == b"sealed-interpreter-ok\n"
        assert completed.stderr == b""
    finally:
        os.close(descriptor)


def test_supervisor_interpreter_pin_survives_in_place_source_overwrite(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    source = Path(sys.executable).resolve(strict=True)
    interpreter = tmp_path / "python"
    shutil.copy2(source, interpreter)
    trusted = interpreter.read_bytes()
    info = interpreter.lstat()
    contract = {
        "command_executable": str(interpreter),
        "resolved_executable": str(interpreter),
        "executable_identity": gate_module._interpreter_identity(
            interpreter,
            info,
            "sha256:" + hashlib.sha256(trusted).hexdigest(),
        ),
    }

    with patch.object(gate_module.sys, "executable", str(interpreter)):
        descriptor = gate_module._open_pinned_python_interpreter(contract)
    try:
        with interpreter.open("r+b", buffering=0) as handle:
            handle.seek(0)
            handle.write(b"\0" * len(trusted))
            handle.truncate(len(trusted))
            os.fsync(handle.fileno())
        assert os.pread(descriptor, len(trusted) + 1, 0) == trusted
    finally:
        os.close(descriptor)


def test_supervisor_interpreter_contract_mismatch_fails_closed() -> None:
    from egsi.generation.first_case_hard_gate import (
        _open_pinned_python_interpreter,
    )

    contract = {
        "command_executable": sys.executable,
        "resolved_executable": str(Path(sys.executable).resolve(strict=True)),
        "executable_identity": {
            "ctime_ns": 0,
            "device": 0,
            "gid": 0,
            "inode": 0,
            "links": 1,
            "mode": 0o755,
            "mtime_ns": 0,
            "path": str(Path(sys.executable).resolve(strict=True)),
            "sha256": "sha256:" + "0" * 64,
            "size": 1,
            "type": "regular",
            "uid": 0,
        },
    }
    with pytest.raises(ValueError, match="interpreter"):
        _open_pinned_python_interpreter(contract)


def test_supervisor_source_hash_mismatch_fails_before_interpreter_launch(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    supervisor = tmp_path / "process_supervisor.py"
    supervisor.write_text("raise SystemExit('untrusted')\n", encoding="utf-8")
    with patch.object(
        gate_module,
        "_process_supervisor_source_path",
        return_value=supervisor,
    ), patch.object(
        gate_module,
        "_PROCESS_SUPERVISOR_SHA256",
        "sha256:" + "0" * 64,
    ), patch.object(gate_module.subprocess, "Popen") as popen:
        with pytest.raises(ValueError, match="supervisor source"):
            gate_module._run_bounded_process_group(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout_seconds=2.0,
                termination_grace_seconds=0.2,
                capture_limit=4096,
            )
    popen.assert_not_called()


def test_parent_escalates_supervisor_cleanup_failure() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    value = {
        "schema_version": "1.0",
        "status": "error",
        "returncode": None,
        "stdout_base64": "",
        "stderr_base64": "",
        "error_code": "cleanup_failed",
    }
    with pytest.raises(ValueError, match="process containment cleanup failed"):
        gate_module._decode_process_supervisor_result(
            json.dumps(value, sort_keys=True).encode("utf-8"),
            command=[sys.executable, "-c", "pass"],
            capture_limit=4096,
        )


def test_linux_proc_identity_starttime_prevents_pid_reuse_signaling() -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    from egsi.generation.first_case_hard_gate import (
        _LinuxProcessIdentity,
        _open_process_identity,
        _proc_identity_is_current,
        _read_linux_proc_record,
    )

    current = _read_linux_proc_record(os.getpid())
    assert current is not None
    identity, _ = current
    assert _proc_identity_is_current(identity)
    before_fds = len(os.listdir("/proc/self/fd"))
    for _ in range(8):
        assert _read_linux_proc_record(os.getpid()) == current
        assert _proc_identity_is_current(identity)
    assert len(os.listdir("/proc/self/fd")) == before_fds

    reused = _LinuxProcessIdentity(
        pid=identity.pid,
        starttime=identity.starttime + 1,
    )
    assert not _proc_identity_is_current(reused)
    opened: list[int] = []
    real_pidfd_open = gate_module.os.pidfd_open

    def record_pidfd_open(pid: int, flags: int) -> int:
        descriptor = real_pidfd_open(pid, flags)
        opened.append(descriptor)
        return descriptor

    with patch.object(
        gate_module.os, "pidfd_open", side_effect=record_pidfd_open
    ):
        assert _open_process_identity(reused) is None
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])

    descriptor = _open_process_identity(identity)
    assert type(descriptor) is int
    try:
        signal.pidfd_send_signal(descriptor, 0, None, 0)
    finally:
        os.close(descriptor)
    assert len(os.listdir("/proc/self/fd")) == before_fds


def test_open_process_identity_closes_owned_pidfd_on_base_exception_only() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    current = gate_module._read_linux_proc_record(os.getpid())
    assert current is not None
    identity, parent_pid = current
    owned = os.pidfd_open(os.getpid(), 0)
    try:
        with patch.object(
            gate_module,
            "_read_linux_proc_record",
            side_effect=[current, KeyboardInterrupt],
        ), patch.object(gate_module.os, "pidfd_open", return_value=owned):
            with pytest.raises(KeyboardInterrupt):
                gate_module._open_process_identity(identity)
        with pytest.raises(OSError):
            os.fstat(owned)
    finally:
        try:
            os.close(owned)
        except OSError:
            pass

    borrowed = os.pidfd_open(os.getpid(), 0)
    try:
        with patch.object(
            gate_module,
            "_read_linux_proc_record",
            side_effect=KeyboardInterrupt,
        ):
            with pytest.raises(KeyboardInterrupt):
                gate_module._open_process_identity(
                    gate_module._LinuxProcessIdentity(
                        pid=identity.pid,
                        starttime=identity.starttime,
                    ),
                    pidfd=borrowed,
                )
        assert os.fstat(borrowed).st_ino > 0
    finally:
        os.close(borrowed)
    assert parent_pid >= 0


@pytest.mark.parametrize(
    "pid",
    [True, 2**31, 2**40, 10**5000],
    ids=[
        "bool",
        "int-max-plus-one",
        "two-to-forty",
        "string-conversion-overflow",
    ],
)
def test_linux_proc_record_rejects_pid_above_linux_pid_t_bound(
    pid: int,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    with patch.object(gate_module.os, "pidfd_open") as pidfd_open:
        assert gate_module._read_linux_proc_record(pid) is None
    pidfd_open.assert_not_called()


@pytest.mark.parametrize(
    "pidfd",
    [True, 2**31, 2**40, 10**5000],
    ids=[
        "bool",
        "int-max-plus-one",
        "two-to-forty",
        "string-conversion-overflow",
    ],
)
def test_linux_proc_record_rejects_fd_above_linux_int_bound(
    pidfd: int,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    with patch("builtins.open") as proc_open:
        assert gate_module._read_linux_proc_record(os.getpid(), pidfd=pidfd) is None
    proc_open.assert_not_called()


def test_linux_proc_record_maps_descendant_at_caller_namespace_depth() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    stat_fields = [b"S", b"99", *([b"0"] * 17), b"12345"]
    records = {
        "/proc/self/fdinfo/77": (
            b"pos:\t0\nflags:\t02000002\nPid:\t98\n"
            b"NSpid:\t98\t32\t2\n"
        ),
        "/proc/self/status": b"Name:\tcaller\nPid:\t68\nNSpid:\t68\t2\n",
        "/proc/98/stat": b"98 (descendant) " + b" ".join(stat_fields),
        "/proc/99/status": b"Name:\tparent\nPid:\t99\nNSpid:\t99\t33\t1\n",
    }
    opened_paths: list[str] = []

    def proc_open(path: object, *args: object, **kwargs: object) -> io.BytesIO:
        del args, kwargs
        opened_paths.append(str(path))
        return io.BytesIO(records[str(path)])

    with patch("builtins.open", side_effect=proc_open), patch.object(
        gate_module.os, "getpid", return_value=2
    ):
        record = gate_module._read_linux_proc_record(32, pidfd=77)

    assert record == (
        gate_module._LinuxProcessIdentity(pid=32, starttime=12345),
        33,
    )
    assert opened_paths.count("/proc/98/stat") == 2


def test_linux_proc_record_rejects_parent_mapping_when_target_stat_changes(
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    first_fields = [b"S", b"99", *([b"0"] * 17), b"12345"]
    second_fields = [b"S", b"68", *([b"0"] * 17), b"12345"]
    target_stats = iter(
        [
            b"98 (descendant) " + b" ".join(first_fields),
            b"98 (descendant) " + b" ".join(second_fields),
        ]
    )
    records = {
        "/proc/self/fdinfo/77": b"Pid:\t98\nNSpid:\t98\t32\n",
        "/proc/self/status": b"Pid:\t68\nNSpid:\t68\t2\n",
        # Numeric 99 now names a replacement parent visible as local PID 44.
        "/proc/99/status": b"Pid:\t99\nNSpid:\t99\t44\n",
    }

    def proc_open(path: object, *args: object, **kwargs: object) -> io.BytesIO:
        del args, kwargs
        if str(path) == "/proc/98/stat":
            return io.BytesIO(next(target_stats))
        return io.BytesIO(records[str(path)])

    with patch("builtins.open", side_effect=proc_open), patch.object(
        gate_module.os, "getpid", return_value=2
    ):
        assert gate_module._read_linux_proc_record(32, pidfd=77) is None


def test_linux_proc_record_parent_recheck_allows_volatile_stat_change() -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    first_fields = [b"S", b"99", *([b"0"] * 17), b"12345"]
    second_fields = list(first_fields)
    second_fields[11] = b"1"  # utime is unrelated to PPid/generation identity.
    target_stats = iter(
        [
            b"98 (descendant) " + b" ".join(first_fields),
            b"98 (descendant) " + b" ".join(second_fields),
        ]
    )
    records = {
        "/proc/self/fdinfo/77": b"Pid:\t98\nNSpid:\t98\t32\n",
        "/proc/self/status": b"Pid:\t68\nNSpid:\t68\t2\n",
        "/proc/99/status": b"Pid:\t99\nNSpid:\t99\t44\n",
    }

    def proc_open(path: object, *args: object, **kwargs: object) -> io.BytesIO:
        del args, kwargs
        if str(path) == "/proc/98/stat":
            return io.BytesIO(next(target_stats))
        return io.BytesIO(records[str(path)])

    with patch("builtins.open", side_effect=proc_open), patch.object(
        gate_module.os, "getpid", return_value=2
    ):
        record = gate_module._read_linux_proc_record(32, pidfd=77)

    assert record == (
        gate_module._LinuxProcessIdentity(pid=32, starttime=12345),
        44,
    )


def test_linux_proc_record_parent_recheck_exception_preserves_fd_ownership(
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    stat_fields = [b"S", b"99", *([b"0"] * 17), b"12345"]
    target_stat = b"98 (descendant) " + b" ".join(stat_fields)
    caller_status = b"Pid:\t68\nNSpid:\t68\t32\n"
    parent_status = b"Pid:\t99\nNSpid:\t99\t44\n"

    def run(*, pidfd: int, owned: bool) -> None:
        target_stat_reads = 0

        def proc_open(
            path: object, *args: object, **kwargs: object
        ) -> io.BytesIO:
            nonlocal target_stat_reads
            del args, kwargs
            proc_path = str(path)
            if proc_path == f"/proc/self/fdinfo/{pidfd}":
                return io.BytesIO(b"Pid:\t98\nNSpid:\t98\t32\n")
            if proc_path == "/proc/self/status":
                return io.BytesIO(caller_status)
            if proc_path == "/proc/99/status":
                return io.BytesIO(parent_status)
            if proc_path == "/proc/98/stat":
                target_stat_reads += 1
                if target_stat_reads == 2:
                    raise PermissionError("synthetic target stat denial")
                return io.BytesIO(target_stat)
            raise AssertionError(proc_path)

        pidfd_open = (
            patch.object(gate_module.os, "pidfd_open", return_value=pidfd)
            if owned
            else nullcontext()
        )
        with pidfd_open, patch(
            "builtins.open", side_effect=proc_open
        ), patch.object(gate_module.os, "getpid", return_value=32):
            result = gate_module._read_linux_proc_record(
                32,
                **({} if owned else {"pidfd": pidfd}),
            )
        assert result is None
        assert target_stat_reads == 2

    owned = os.pidfd_open(os.getpid(), 0)
    try:
        run(pidfd=owned, owned=True)
        with pytest.raises(OSError):
            os.fstat(owned)
    finally:
        try:
            os.close(owned)
        except OSError:
            pass

    borrowed = os.pidfd_open(os.getpid(), 0)
    try:
        run(pidfd=borrowed, owned=False)
        assert os.fstat(borrowed).st_ino > 0
    finally:
        os.close(borrowed)


@pytest.mark.parametrize(
    "confirmed_fdinfo",
    [
        b"Pid:\t-1\nNSpid:\t-1\n",
        b"ino:\t2\nPid:\t98\nNSpid:\t98\t32\n",
    ],
    ids=["reaped", "byte-changed"],
)
def test_linux_proc_record_rejects_reaped_pidfd_after_numeric_pid_aba(
    confirmed_fdinfo: bytes,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    stat_fields = [b"S", b"68", *([b"0"] * 17), b"12345"]
    initial_fdinfo = b"ino:\t1\nPid:\t98\nNSpid:\t98\t32\n"
    fdinfo_reads = iter([initial_fdinfo, confirmed_fdinfo])
    records = {
        "/proc/self/status": b"Name:\tcaller\nPid:\t68\nNSpid:\t68\t2\n",
        # The numeric PID has been reused with the same starttime value.
        "/proc/98/stat": b"98 (replacement) " + b" ".join(stat_fields),
        "/proc/68/status": b"Name:\tcaller\nPid:\t68\nNSpid:\t68\t2\n",
    }

    def proc_open(path: object, *args: object, **kwargs: object) -> io.BytesIO:
        del args, kwargs
        if str(path) == "/proc/self/fdinfo/77":
            return io.BytesIO(next(fdinfo_reads))
        return io.BytesIO(records[str(path)])

    with patch("builtins.open", side_effect=proc_open), patch.object(
        gate_module.os, "getpid", return_value=2
    ):
        assert gate_module._read_linux_proc_record(32, pidfd=77) is None


@pytest.mark.parametrize(
    ("caller_status", "target_fdinfo"),
    [
        (
            b"Pid:\t68\nNSpid:\t68\t2\t1\n",
            b"Pid:\t98\nNSpid:\t98\t32\n",
        ),
        (
            b"Pid:\t68\nNSpid:\t68\t7\n",
            b"Pid:\t98\nNSpid:\t98\t32\n",
        ),
        (
            b"Pid:\t68\nNSpid:\t68\t2\n",
            b"Pid:\t98\nNSpid:\t98\t31\n",
        ),
    ],
    ids=["target-not-visible", "caller-chain-mismatch", "local-pid-mismatch"],
)
def test_linux_proc_record_rejects_incompatible_namespace_chains(
    caller_status: bytes,
    target_fdinfo: bytes,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    records = {
        "/proc/self/fdinfo/77": target_fdinfo,
        "/proc/self/status": caller_status,
    }

    def proc_open(path: object, *args: object, **kwargs: object) -> io.BytesIO:
        del args, kwargs
        return io.BytesIO(records[str(path)])

    with patch("builtins.open", side_effect=proc_open), patch.object(
        gate_module.os, "getpid", return_value=2
    ):
        assert gate_module._read_linux_proc_record(32, pidfd=77) is None


def test_pid_namespace_fork_failure_fails_closed_without_target(
    tmp_path: Path,
) -> None:
    import egsi.generation.process_supervisor as supervisor

    with patch.object(
        supervisor, "_enter_same_id_user_namespace"
    ), patch.object(
        supervisor.os, "unshare"
    ), patch.object(
        supervisor.os, "fork", side_effect=OSError("synthetic fork denial")
    ), patch.object(
        supervisor.subprocess, "Popen"
    ) as popen:
        result = supervisor._namespace_supervise(
            [sys.executable, "-c", "print('unreachable')"],
            cwd=tmp_path,
            timeout_seconds=0.2,
            termination_grace_seconds=0.1,
            capture_limit=4096,
        )

    assert result == {
        "schema_version": "1.0",
        "status": "error",
        "returncode": None,
        "stdout_base64": "",
        "stderr_base64": "",
        "error_code": "namespace_unavailable",
    }
    popen.assert_not_called()


def test_bounded_process_group_preserves_output_and_rejects_capture_overflow(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _run_bounded_process_group,
    )

    completed = _run_bounded_process_group(
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ],
        cwd=tmp_path,
        timeout_seconds=2.0,
        termination_grace_seconds=0.2,
        capture_limit=64,
    )
    assert completed.returncode == 0
    assert completed.stdout == b"out\n"
    assert completed.stderr == b"err\n"

    with pytest.raises(ValueError, match="capture limit"):
        _run_bounded_process_group(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 4097)",
            ],
            cwd=tmp_path,
            timeout_seconds=2.0,
            termination_grace_seconds=0.2,
            capture_limit=4096,
        )


def test_locked_cli_never_executes_self_erasing_pth_before_rejection(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_probe_runner(tmp_path)
    site_packages = Path(str(lock["site_packages_root"]))
    hook = site_packages / "zzz_egsi_startup_attack.pth"
    module = site_packages / "evilhook.py"
    marker = tmp_path / "PTH_EXECUTED"
    assert not hook.exists() and not module.exists()
    module.write_text(
        "import os\n"
        f"open({str(marker)!r}, 'w').write('executed')\n"
        f"os.unlink({str(hook)!r})\n"
        f"os.unlink({str(module)!r})\n",
        encoding="utf-8",
    )
    hook.write_text("import evilhook\n", encoding="utf-8")
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "probe", "--root", str(root),
        ],
        cwd=root,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "HOME": "/nonexistent",
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert not marker.exists()
    assert completed.returncode != 0
    assert hook.exists() and module.exists()


def test_first_case_report_schema_rejects_unknown_nested_fields(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        _validate_report_schema,
        first_case_report_commitment,
        verify_first_case_hard_gate,
    )

    output = _copied_output(tmp_path)
    report, _, _, _ = _issue_report(output)
    report["prompt_contract"]["surprise"] = True
    report["report_commitment_sha256"] = first_case_report_commitment(report)

    with pytest.raises(ValueError, match="prompt contract fields"):
        _validate_report_schema(report)


def test_rerun_tests_mode_reissues_both_canonical_suites_before_reporting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    import egsi.generation.test_receipt as receipt_module

    output = _copied_output(tmp_path)
    focused = output / "reports/offline-focused-receipt.json"
    full = output / "reports/offline-full-receipt.json"
    report_path = output / "reports/first-case-hard-gate-v2.json"
    calls: list[str] = []

    def run_canonical(*, root: Path, name: str, output: Path):
        calls.append(name)
        command = receipt_module.canonical_test_command(root, name)
        with patch("egsi.generation.test_receipt.subprocess.run") as run:
            run.return_value = _completed(command)
            return receipt_module.run_test_receipt(
                root=root,
                name=name,
                output=output,
            )

    monkeypatch.setattr(gate_module, "_run_official_receipt_launcher", run_canonical)
    report = gate_module.verify_first_case_hard_gate(
        root=ROOT,
        output_root=output,
        case_id=CASE_ID,
        focused_receipt=focused,
        full_receipt=full,
        report_path=report_path,
        mode="rerun-tests",
    )

    assert calls == ["focused", "full"]
    assert report["status"] == "FIRST_CASE_GATE_PASSED"
    assert report["attestation_mode"] == "rerun_tests"
    assert report_path.exists()


@pytest.mark.parametrize("kind", ["escape", "symlink", "hardlink"])
def test_first_case_report_path_is_anchored_and_rejects_ambiguous_destinations(
    tmp_path: Path,
    kind: str,
) -> None:
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    output = _copied_output(tmp_path)
    focused, full = _receipts(output, tmp_path)
    victim = tmp_path / "victim.json"
    victim.write_text("DO-NOT-OVERWRITE", encoding="utf-8")
    if kind == "escape":
        report_path = tmp_path / "escaped-report.json"
    else:
        report_path = output / "reports/unsafe-report.json"
        if kind == "symlink":
            report_path.symlink_to(victim)
        else:
            os.link(victim, report_path)

    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher"
    ) as run_receipt:
        with pytest.raises(ValueError, match="first-case hard gate"):
            verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="rerun-tests",
            )
        run_receipt.assert_not_called()

    assert victim.read_text(encoding="utf-8") == "DO-NOT-OVERWRITE"
    if kind == "escape":
        assert not report_path.exists()


def test_verify_only_is_byte_and_metadata_read_only_on_valid_tree(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    output = _copied_output(tmp_path)
    report, focused, full, report_path = _issue_report(output)
    before = _tree_snapshot(output)

    observed = verify_first_case_hard_gate(
        root=ROOT,
        output_root=output,
        case_id=CASE_ID,
        focused_receipt=focused,
        full_receipt=full,
        report_path=report_path,
        mode="verify-only",
    )

    assert observed == report
    assert _tree_snapshot(output) == before


def test_verify_only_missing_reports_directory_fails_without_creating_anything(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    output = tmp_path / "empty-output"
    output.mkdir()
    before = _tree_snapshot(output)
    reports = output / "reports"
    with pytest.raises(ValueError, match="first-case hard gate"):
        verify_first_case_hard_gate(
            root=ROOT,
            output_root=output,
            case_id=CASE_ID,
            focused_receipt=reports / "focused.json",
            full_receipt=reports / "full.json",
            report_path=reports / "report.json",
            mode="verify-only",
        )
    assert not reports.exists()
    assert _tree_snapshot(output) == before


def test_rerun_lexical_alias_fails_before_creating_reports_directory(
    tmp_path: Path,
) -> None:
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    output = tmp_path / "empty-output"
    output.mkdir()
    reports = output / "reports"
    same = reports / "same.json"
    before = _tree_snapshot(output)
    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher"
    ) as run_receipt:
        with pytest.raises(ValueError, match="first-case hard gate"):
            verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=same,
                full_receipt=reports / "full.json",
                report_path=same,
                mode="rerun-tests",
            )
        run_receipt.assert_not_called()
    assert not reports.exists()
    assert _tree_snapshot(output) == before


@pytest.mark.parametrize("alias_kind", ["same_path", "hardlink"])
def test_report_and_receipt_aliases_fail_before_writes_and_preserve_old_evidence(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    from egsi.generation.first_case_hard_gate import verify_first_case_hard_gate

    output = _copied_output(tmp_path)
    reports = output / "reports"
    first = reports / "alias-first.json"
    second = reports / "alias-second.json"
    first.write_bytes(b"OLD-FIRST")
    first.chmod(0o600)
    second.write_bytes(b"OLD-SECOND")
    second.chmod(0o600)
    if alias_kind == "same_path":
        report_path, focused, full = first, first, second
    else:
        first.unlink()
        os.link(second, first)
        report_path = reports / "alias-report.json"
        focused, full = first, second
    before = {
        path: path.read_bytes()
        for path in {first, second}
    }

    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher"
    ) as run_receipt:
        with pytest.raises(ValueError, match="first-case hard gate"):
            verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="rerun-tests",
            )
        run_receipt.assert_not_called()

    assert {path: path.read_bytes() for path in before} == before
    if report_path not in before:
        assert not report_path.exists()


def test_report_publication_is_absolute_last_without_post_publish_rechecks(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    from egsi.generation.pilot import write_report as real_write_report

    output = _copied_output(tmp_path)
    focused = output / "reports/race-focused.json"
    full = output / "reports/race-full.json"
    report_path = output / "reports/race-report.json"

    published = False
    require_unchanged = gate_module._require_receipts_unchanged

    def track_report(path: Path, value: dict[str, object]) -> None:
        nonlocal published
        real_write_report(path, value)
        if path == report_path:
            published = True

    def reject_post_publish_check(*args: object, **kwargs: object) -> None:
        assert published is False, "receipt recheck occurred after PASS publish"
        require_unchanged(*args, **kwargs)

    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher",
        side_effect=_fake_canonical_receipt,
    ), patch(
        "egsi.generation.first_case_hard_gate.write_report",
        side_effect=track_report,
    ), patch(
        "egsi.generation.first_case_hard_gate._require_receipts_unchanged",
        side_effect=reject_post_publish_check,
    ):
        report = gate_module.verify_first_case_hard_gate(
            root=ROOT,
            output_root=output,
            case_id=CASE_ID,
            focused_receipt=focused,
            full_receipt=full,
            report_path=report_path,
            mode="rerun-tests",
        )
    assert published is True
    assert report["status"] == "FIRST_CASE_GATE_PASSED"
    assert report_path.exists()


@pytest.mark.parametrize("existing", [False, True])
def test_report_publish_failure_restores_old_bytes_or_removes_new_report(
    tmp_path: Path,
    existing: bool,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module
    from egsi.generation.pilot import write_report as real_write_report

    output = _copied_output(tmp_path)
    focused = output / "reports/failure-focused.json"
    full = output / "reports/failure-full.json"
    report_path = output / "reports/failure-report.json"
    old = b"OLD-PASS-REPORT\n"
    if existing:
        report_path.write_bytes(old)
        report_path.chmod(0o600)

    def raise_after_replace(path: Path, value: dict[str, object]) -> None:
        real_write_report(path, value)
        if path == report_path:
            raise RuntimeError("injected post-replace failure")

    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher",
        side_effect=_fake_canonical_receipt,
    ), patch(
        "egsi.generation.first_case_hard_gate.write_report",
        side_effect=raise_after_replace,
    ):
        with pytest.raises(ValueError, match="first-case hard gate"):
            gate_module.verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="rerun-tests",
            )

    if existing:
        assert report_path.read_bytes() == old
        assert (report_path.stat().st_mode & 0o777) == 0o600
    else:
        assert not report_path.exists()


def test_receipt_race_during_final_prepublication_revalidation_keeps_old_report(
    tmp_path: Path,
) -> None:
    import egsi.generation.first_case_hard_gate as gate_module

    output = _copied_output(tmp_path)
    focused = output / "reports/race-focused.json"
    full = output / "reports/race-full.json"
    report_path = output / "reports/race-report.json"
    old = b"OLD-PASS-REPORT\n"
    report_path.write_bytes(old)
    report_path.chmod(0o600)
    real_recheck = gate_module._require_receipts_unchanged
    calls = 0

    def mutate_on_final_recheck(expected: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            focused.write_bytes(focused.read_bytes() + b" ")
        real_recheck(expected)

    with patch(
        "egsi.generation.first_case_hard_gate._run_official_receipt_launcher",
        side_effect=_fake_canonical_receipt,
    ), patch(
        "egsi.generation.first_case_hard_gate._require_receipts_unchanged",
        side_effect=mutate_on_final_recheck,
    ):
        with pytest.raises(ValueError, match="first-case hard gate"):
            gate_module.verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="rerun-tests",
            )
    assert calls == 2
    assert report_path.read_bytes() == old


@pytest.mark.parametrize(
    "tamper",
    [
        "record",
        "record_points_to_repair_response",
        "missing_cache",
        "unknown_event",
        "incomplete_lifecycle",
        "history_count",
        "receipt_mismatch",
        "report_mismatch",
    ],
)
def test_source_controlled_first_case_verifier_rejects_adversarial_copies(
    tmp_path: Path,
    tamper: str,
) -> None:
    from egsi.generation.first_case_hard_gate import (
        first_case_report_commitment,
        verify_first_case_hard_gate,
    )
    from egsi.generation.test_receipt import test_receipt_commitment

    output = _copied_output(tmp_path)
    focused, full = _receipts(output, tmp_path)
    report_path = output / "reports/first-case-hard-gate-v2.json"
    if tamper in {"report_mismatch", "receipt_mismatch"}:
        _, focused, full, report_path = _issue_report(output)
        if tamper == "report_mismatch":
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["hard_gates"]["record_current"] = False
            report["report_commitment_sha256"] = first_case_report_commitment(report)
            report_path.write_text(
                json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        else:
            value = json.loads(focused.read_text(encoding="utf-8"))
            value["code_commitments"]["source_tree_sha256"] = (
                "sha256:" + "0" * 64
            )
            value["receipt_commitment_sha256"] = test_receipt_commitment(value)
            focused.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
    elif tamper in {"record", "record_points_to_repair_response"}:
        record = output / f"enrichment/{CASE_ID}.json"
        value = json.loads(record.read_text(encoding="utf-8"))
        if tamper == "record":
            value["case_id"] = "tampered"
        else:
            from egsi.contracts.enrichment import enrichment_record_commitment

            repair_cache = json.loads(
                (output / "cache/teacher/5aba8cae46ccde2bdcdd0b60b62d57ec8a6c0c267206598f8a013631da241679.json").read_text(
                    encoding="utf-8"
                )
            )
            value["teacher_response_commitment_sha256"] = repair_cache[
                "response_commitment_sha256"
            ]
            value["provider_request_id"] = repair_cache["provider_request_id"]
            value["record_commitment_sha256"] = enrichment_record_commitment(
                value
            )
        record.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    elif tamper == "missing_cache":
        (output / "cache/teacher/32de43d7c2b3af8a97a6669ae79f8931978778f78b06a5798a3510657cc80aac.json").unlink()
    elif tamper in {"unknown_event", "incomplete_lifecycle"}:
        manifests = []
        for path in (output / "audit/teacher").rglob("manifest.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("response_commitment_sha256") == (
                "sha256:66ed04f6157a13ed64706104d8f3e5b20986173c640ed010586830332939baab"
            ):
                manifests.append((path, value))
        assert len(manifests) == 1
        manifest_path, manifest = manifests[0]
        if tamper == "unknown_event":
            items = [
                {"index": 0, "type": "thread.started"},
                {"index": 1, "type": "turn.started"},
                {"index": 2, "type": "mystery.event"},
            ]
        else:
            items = [{"index": 0, "type": "thread.started"}]
        metadata = b"".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
            for item in items
        )
        manifest_path.with_name("events.metadata.jsonl").write_bytes(metadata)
        counts: dict[str, int] = {}
        for item in items:
            counts[item["type"]] = counts.get(item["type"], 0) + 1
        manifest["event_counts"] = dict(sorted(counts.items()))
        manifest["events_metadata_length"] = len(metadata)
        manifest["events_metadata_sha256"] = _sha256(metadata)
        manifest["audit_commitment_sha256"] = _commit(
            manifest, "audit_commitment_sha256"
        )
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    elif tamper == "history_count":
        historical = next(
            path
            for path in (output / "audit/teacher").rglob("manifest.json")
            if json.loads(path.read_text(encoding="utf-8")).get("status")
            == "quarantined"
        )
        shutil.rmtree(historical.parents[1])
    if tamper in {"report_mismatch", "receipt_mismatch"}:
        with pytest.raises(ValueError, match="first-case hard gate"):
            verify_first_case_hard_gate(
                root=ROOT,
                output_root=output,
                case_id=CASE_ID,
                focused_receipt=focused,
                full_receipt=full,
                report_path=report_path,
                mode="verify-only",
            )
    else:
        with patch(
            "egsi.generation.first_case_hard_gate._run_official_receipt_launcher",
            side_effect=_fake_canonical_receipt,
        ):
            with pytest.raises(ValueError, match="first-case hard gate"):
                verify_first_case_hard_gate(
                    root=ROOT,
                    output_root=output,
                    case_id=CASE_ID,
                    focused_receipt=focused,
                    full_receipt=full,
                    report_path=report_path,
                    mode="rerun-tests",
                )


def test_official_verify_only_rejects_exact_reviewer_forge_before_python(
    tmp_path: Path,
) -> None:
    output = tmp_path / "reviewer-forge"
    reports = output / "reports"
    reports.mkdir(parents=True)
    focused = reports / "offline-focused-receipt.json"
    full = reports / "offline-full-receipt.json"
    report = reports / "first-case-hard-gate.json"
    for path, name, count in (
        (focused, "focused", 369),
        (full, "full", 824),
    ):
        path.write_text(
            json.dumps(
                {
                    "schema_version": "7.0",
                    "native_attested": False,
                    "name": name,
                    "passed_count": count,
                    "failed_count": 0,
                    "exit_code": 0,
                    "reviewer_patched_sys_flags": True,
                    "reviewer_patched_runtime_marker": True,
                    "reviewer_patched_subprocess": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
    report.write_text(
        json.dumps(
            {
                "schema_version": "5.1",
                "native_attested": False,
                "status": "FIRST_CASE_GATE_PASSED",
                "hard_gates": {f"forged_gate_{index}": True for index in range(37)},
                "reviewer_direct_import": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    report.chmod(0o600)

    completed = subprocess.run(
        [
            str(ROOT / "scripts/verify_first_case_hard_gate"),
            "--output-root",
            str(output),
            "--case-id",
            CASE_ID,
            "--focused-receipt",
            str(focused),
            "--full-receipt",
            str(full),
            "--report",
            str(report),
            "--mode",
            "verify-only",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 66
    assert completed.stdout == ""
    assert completed.stderr == (
        "native pre-python attestation verification failed\n"
    )
    assert not list(reports.glob("*.native-attestation"))


@pytest.mark.parametrize(
    "tamper",
    [
        "artifact_bytes",
        "signature",
        "key_id",
        "artifact_path",
        "unknown_line",
        "receipt_swap",
        "report_swap",
        "missing",
    ],
)
def test_native_verify_only_rejects_sidecar_tamper_replay_and_swap_pre_python(
    tmp_path: Path,
    tamper: str,
) -> None:
    scripts, output = _synthetic_native_attested_tree(tmp_path)
    reports = output / "reports"
    focused = reports / "offline-focused-receipt.json"
    full = reports / "offline-full-receipt.json"
    report = reports / "first-case-hard-gate.json"
    focused_sidecar = Path(str(focused) + ".native-attestation")
    full_sidecar = Path(str(full) + ".native-attestation")
    report_sidecar = Path(str(report) + ".native-attestation")
    assert all(path.exists() for path in (focused_sidecar, full_sidecar, report_sidecar))
    if tamper == "artifact_bytes":
        focused.write_bytes(focused.read_bytes() + b"\n")
    elif tamper == "signature":
        raw = focused_sidecar.read_text(encoding="ascii")
        focused_sidecar.write_text(
            raw[:-2] + ("0" if raw[-2] != "0" else "1") + "\n",
            encoding="ascii",
        )
    elif tamper == "key_id":
        raw = focused_sidecar.read_text(encoding="ascii")
        focused_sidecar.write_text(
            raw.replace("\nkey_id=", "\nkey_id=0", 1), encoding="ascii"
        )
    elif tamper == "artifact_path":
        raw = focused_sidecar.read_text(encoding="ascii")
        focused_sidecar.write_text(
            raw.replace(
                "artifact=offline-focused-receipt.json",
                "artifact=forged-path.json",
                1,
            ),
            encoding="ascii",
        )
    elif tamper == "unknown_line":
        focused_sidecar.write_text(
            focused_sidecar.read_text(encoding="ascii") + "unknown=1\n",
            encoding="ascii",
        )
    elif tamper == "receipt_swap":
        focused_sidecar.write_bytes(full_sidecar.read_bytes())
    elif tamper == "report_swap":
        report_sidecar.write_bytes(focused_sidecar.read_bytes())
    else:
        focused_sidecar.unlink()
    for path in reports.glob("*.native-attestation"):
        path.chmod(0o600)

    completed = subprocess.run(
        [
            str(scripts / "verify_first_case_hard_gate"),
            "--output-root",
            str(output),
            "--case-id",
            CASE_ID,
            "--focused-receipt",
            str(focused),
            "--full-receipt",
            str(full),
            "--report",
            str(report),
            "--mode",
            "verify-only",
        ],
        cwd=scripts.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 66
    assert completed.stdout == ""
    assert completed.stderr == (
        "native pre-python attestation verification failed\n"
    )


def test_sidecars_from_previous_key_are_stale_for_explicit_new_test_key(
    tmp_path: Path,
) -> None:
    scripts, output = _synthetic_native_attested_tree(tmp_path)
    synthetic_root = scripts.parent
    replacement_key = _temporary_private_key(tmp_path, "replacement.pem")
    built = subprocess.run(
        [
            str(scripts / "rebuild_locked_launchers"),
            "--synthetic-output-dir",
            str(scripts),
            "--test-private-key-pem",
            str(replacement_key),
        ],
        cwd=synthetic_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    focused = output / "reports/offline-focused-receipt.json"
    full = output / "reports/offline-full-receipt.json"
    report = output / "reports/first-case-hard-gate.json"
    completed = subprocess.run(
        [
            str(scripts / "verify_first_case_hard_gate"),
            "--output-root",
            str(output),
            "--case-id",
            CASE_ID,
            "--focused-receipt",
            str(focused),
            "--full-receipt",
            str(full),
            "--report",
            str(report),
            "--mode",
            "verify-only",
        ],
        cwd=synthetic_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 66
    assert completed.stdout == ""
    assert completed.stderr == (
        "native pre-python attestation verification failed\n"
    )
