from __future__ import annotations

import base64
import ctypes
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
import venv
from unittest.mock import patch

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parents[2]


_SYNTHETIC_LOCKED_TEMP_ROOTS: set[Path] = set()


@pytest.fixture(autouse=True)
def _cleanup_synthetic_locked_temp_roots() -> object:
    before = set(_SYNTHETIC_LOCKED_TEMP_ROOTS)
    yield
    for path in _SYNTHETIC_LOCKED_TEMP_ROOTS - before:
        shutil.rmtree(path, ignore_errors=True)
        _SYNTHETIC_LOCKED_TEMP_ROOTS.discard(path)


_LOCKED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "HOME": "/nonexistent",
    "TMPDIR": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
}


def _temporary_rsa_private_key(tmp_path: Path, name: str = "native-test.pem") -> Path:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / name
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path


def _copy_asymmetric_native_build_sources(root: Path) -> None:
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (root / "configs").mkdir(exist_ok=True)
    for name in (
        "locked_launcher.c",
        "rebuild_locked_launchers",
        "build_native_rsa_material.py",
        "locked_runtime_bootstrap.py",
    ):
        source = ROOT / "scripts" / name
        assert source.is_file(), f"missing asymmetric build component: {name}"
        shutil.copy2(source, scripts / name)
    runner_bin = root / ".work/offline-test-runner-venv/bin"
    runner_bin.mkdir(parents=True, exist_ok=True)
    interpreter = runner_bin / "python"
    shutil.copy2(Path(sys.executable).resolve(strict=True), interpreter)
    interpreter.chmod(0o755)
    info = interpreter.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def _run_native_material(
    root: Path, private_key: Path
) -> subprocess.CompletedProcess[str]:
    output = root / ".native-material-test"
    output.mkdir(mode=0o700, exist_ok=True)
    return subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(root / "scripts/build_native_rsa_material.py"),
            "material",
            "--root",
            str(root),
            "--private-header",
            str(output / "private.h"),
            "--public-header",
            str(output / "public.h"),
            "--public-material",
            str(output / "public-material.json"),
            "--test-private-key-pem",
            str(private_key),
        ],
        cwd=root,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        },
        capture_output=True,
        text=True,
        check=False,
    )


def _run_asymmetric_native_build(root: Path, private_key: Path) -> None:
    completed = subprocess.run(
        [
            str(root / "scripts/rebuild_locked_launchers"),
            "--synthetic-output-dir",
            str(root / "scripts"),
            "--test-private-key-pem",
            str(private_key),
        ],
        cwd=root,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def _write_native_live_stub_bootstrap(
    root: Path, *, child_exit_code: int, semantic_mutation: str | None = None
) -> None:
    assert child_exit_code in {0, 120}
    assert semantic_mutation in {None, "bootstrap", "focused-receipt"}
    (root / "verify-child-started").write_text("", encoding="utf-8")
    (root / "scripts/locked_runtime_bootstrap.py").write_text(
        f"""from pathlib import Path
import base64, hashlib, json, os, stat, sys

CHILD_EXIT = {child_exit_code}
SEMANTIC_MUTATION = {semantic_mutation!r}

def arguments():
    args = sys.argv[sys.argv.index('--') + 1:]
    values = {{}}
    index = 0
    while index < len(args):
        name = args[index]
        if index + 1 < len(args) and not args[index + 1].startswith('--'):
            values[name] = args[index + 1]
            index += 2
        else:
            values[name] = True
            index += 1
    return values

def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False,
        sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')

def trust_fields(args, pre, semantic_snapshot=None):
    fields = [
        ('run_id', args['--native-run-id']),
        ('nonce', args['--native-nonce']),
        ('realtime_start_ns', args['--native-realtime-start-ns']),
        ('monotonic_start_ns', args['--native-monotonic-start-ns']),
        ('pre_inventory_sha256', pre),
        ('bootstrap_sha256', args['--native-bootstrap-sha256']),
        ('focused_receipt_sha256', args['--native-focused-receipt-sha256']),
        ('focused_sidecar_sha256', args['--native-focused-sidecar-sha256']),
        ('full_receipt_sha256', args['--native-full-receipt-sha256']),
        ('full_sidecar_sha256', args['--native-full-sidecar-sha256']),
        ('runner_lock_sha256', args.get('--native-runner-lock-sha256', 'sha256:' + '2' * 64)),
        ('project_identity_sha256', args.get('--native-project-identity-sha256', 'sha256:' + '3' * 64)),
        ('canonical_test_contract_sha256', args.get('--native-canonical-test-contract-sha256', 'sha256:' + '4' * 64)),
        ('native_launcher_contract_sha256', args.get('--native-launcher-contract-sha256', 'sha256:' + '5' * 64)),
        ('native_binary_contract_sha256', args['--native-binary-contract-sha256']),
        ('public_key_id', args['--native-public-key-id']),
    ]
    if semantic_snapshot is not None:
        fields.append(('semantic_snapshot_sha256', semantic_snapshot))
    return fields

def snapshot_files(output, attestation):
    excluded = {{
        attestation,
        Path(str(attestation) + '.native-attestation'),
        Path(str(attestation) + '.native-preflight'),
        Path(str(attestation) + '.native-candidate'),
        Path(str(attestation) + '.native-snapshot'),
    }}
    paths = []
    for relative in ('src', 'tests', 'configs', 'idea-stage', 'data'):
        base = root / relative
        if base.is_dir() and not base.is_symlink():
            paths.extend(
                ('source', path.relative_to(root).as_posix(), path)
                for path in base.rglob('*')
                if path.is_file() and not path.is_symlink()
            )
    scripts = root / 'scripts'
    if scripts.is_dir() and not scripts.is_symlink():
        paths.extend(
            ('source', path.relative_to(root).as_posix(), path)
            for path in scripts.glob('*.py')
            if path.is_file() and not path.is_symlink()
        )
    if output.is_dir() and not output.is_symlink():
        paths.extend(
            ('output', path.relative_to(output).as_posix(), path)
            for path in output.rglob('*')
            if path not in excluded and path.is_file() and not path.is_symlink()
        )
    return sorted(set(paths), key=lambda item: (item[0], item[1]))

def snapshot_identity(info):
    return {{
        'device': info.st_dev, 'inode': info.st_ino,
        'mode': stat.S_IMODE(info.st_mode), 'nlink': info.st_nlink,
        'uid': info.st_uid, 'gid': info.st_gid, 'size': info.st_size,
        'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
    }}

def create_snapshot(output, attestation, args):
    entries = []
    for namespace, relative, path in snapshot_files(output, attestation):
        info = path.lstat()
        raw = path.read_bytes()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit(2)
        entries.append({{
            'namespace': namespace, 'relative_path': relative,
            **snapshot_identity(info), 'sha256': sha(raw),
            'contents_base64': base64.b64encode(raw).decode('ascii'),
        }})
    value = {{
        'schema_version': '1.0',
        'snapshot_kind': 'native_live_semantic_inputs',
        'source_root': str(root), 'output_root': str(output),
        'case_file_relative': Path(args['--case-file']).relative_to(root).as_posix(),
        'scope_case_file_relative': Path(args['--scope-case-file']).relative_to(root).as_posix(),
        'files': entries,
        'snapshot_commitment_sha256': 'sha256:' + '0' * 64,
    }}
    committed = dict(value)
    committed.pop('snapshot_commitment_sha256')
    value['snapshot_commitment_sha256'] = sha(canonical(committed))
    raw = canonical(value) + b'\\n'
    path = Path(str(attestation) + '.native-snapshot')
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw, sha(raw)

def validate_snapshot(raw, expected, *, exact):
    if sha(raw) != expected or not raw.endswith(b'\\n'):
        raise SystemExit(2)
    value = json.loads(raw)
    committed = dict(value)
    commitment = committed.pop('snapshot_commitment_sha256')
    if commitment != sha(canonical(committed)) or canonical(value) + b'\\n' != raw:
        raise SystemExit(2)
    output = Path(value['output_root'])
    attestation = output / 'reports/remaining-p0/fail-fast-live-attestation.json'
    current = {{
        (namespace, relative): path
        for namespace, relative, path in snapshot_files(output, attestation)
    }}
    expected_keys = {{
        (entry['namespace'], entry['relative_path']) for entry in value['files']
    }}
    if exact and set(current) != expected_keys:
        raise SystemExit(2)
    for entry in value['files']:
        key = (entry['namespace'], entry['relative_path'])
        path = current.get(key)
        if path is None:
            raise SystemExit(2)
        info = path.lstat()
        raw_file = path.read_bytes()
        if (
            snapshot_identity(info) != {{
                name: entry[name] for name in (
                    'device', 'inode', 'mode', 'nlink', 'uid', 'gid',
                    'size', 'mtime_ns', 'ctime_ns',
                )
            }}
            or sha(raw_file) != entry['sha256']
        ):
            raise SystemExit(2)

mode = sys.argv[1]
args = arguments()
root = Path(__file__).resolve().parents[1]
if mode == 'run-test-receipt':
    path = Path(args['--output'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('receipt=' + args['--name'] + '\\n', encoding='utf-8')
    path.chmod(0o600)
elif mode == 'rerun-first-case':
    path = Path(args['--report'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{{"native_attested":false}}\\n', encoding='utf-8')
    path.chmod(0o600)
elif mode == 'verify-first-case':
    pass
elif mode == 'preflight-fail-fast-enrich':
    raw = 'EGSI-LIVE-PREFLIGHT-V1\\n' + ''.join(
        name + '=' + value + '\\n'
        for name, value in trust_fields(args, 'sha256:' + '1' * 64)
    )
    path = Path(args['--native-preflight-envelope'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw, encoding='ascii')
    path.chmod(0o600)
elif mode == 'run-fail-fast-enrich':
    terminal = 'PASS' if CHILD_EXIT == 0 else 'STOP'
    attestation = Path(args['--attestation'])
    attestation.parent.mkdir(parents=True, exist_ok=True)
    output = Path(args['--output-root'])
    snapshot_raw, snapshot_sha = create_snapshot(output, attestation, args)
    value = {{
        'run_id': args['--native-run-id'],
        'nonce': args['--native-nonce'],
        'terminal_status': terminal,
        'child_exit_code': CHILD_EXIT,
        'semantic_snapshot_sha256': snapshot_sha,
    }}
    raw_json = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\\n').encode('ascii')
    attestation.write_bytes(raw_json)
    attestation.chmod(0o600)
    fields = trust_fields(
        args, args['--native-pre-inventory-sha256'], snapshot_sha
    ) + [
        ('child_exit_code', str(CHILD_EXIT)),
        ('terminal_status', terminal),
        ('post_inventory_sha256', 'sha256:' + '6' * 64),
        ('attestation_sha256', sha(raw_json)),
        ('attestation_commitment_sha256', 'sha256:' + '7' * 64),
    ]
    envelope = Path(args['--native-candidate-envelope'])
    envelope.write_text(
        'EGSI-LIVE-CANDIDATE-V1\\n' + ''.join(
            name + '=' + field + '\\n' for name, field in fields
        ),
        encoding='ascii',
    )
    envelope.chmod(0o600)
    raise SystemExit(CHILD_EXIT)
elif mode == 'verify-fail-fast-enrich':
    if '--native-candidate-envelope' in args:
        envelope = Path(args['--native-candidate-envelope'])
        if not envelope.read_bytes().startswith(b'EGSI-LIVE-CANDIDATE-V1\\n'):
            raise SystemExit(2)
    value = json.loads(Path(args['--attestation']).read_text(encoding='ascii'))
    if (
        '--native-child-exit-code' in args
        and value['child_exit_code'] != int(args['--native-child-exit-code'])
    ):
        raise SystemExit(2)
    snapshot_raw = Path(args['--native-semantic-snapshot']).read_bytes()
    validate_snapshot(
        snapshot_raw, value['semantic_snapshot_sha256'], exact=False
    )
    if '--native-candidate-envelope' in args:
        if SEMANTIC_MUTATION == 'bootstrap':
            bootstrap = Path(__file__).resolve()
            bootstrap.write_bytes(bootstrap.read_bytes() + b'\\n# raced\\n')
        elif SEMANTIC_MUTATION == 'focused-receipt':
            receipt = Path(args['--output-root']) / 'reports/offline-focused-receipt.json'
            receipt.write_bytes(receipt.read_bytes() + b'raced\\n')
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
    validate_snapshot(
        snapshot_raw, value['semantic_snapshot_sha256'], exact=True
    )
else:
    raise SystemExit(64)
""",
        encoding="utf-8",
    )


def _replace_python_with_live_forgery(root: Path) -> None:
    python = root / ".work/offline-test-runner-venv/bin/python"
    python.unlink()
    python.write_text(
        r'''#!/usr/bin/python3
from pathlib import Path
import hashlib, sys

def sha(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()
known = {'preflight-fail-fast-enrich','run-fail-fast-enrich','verify-fail-fast-enrich'}
mode = next((item for item in sys.argv if item in known), None)
if mode == 'verify-fail-fast-enrich':
    raise SystemExit(0)
tail = sys.argv[sys.argv.index('--') + 1:]
args = dict(zip(tail[::2], tail[1::2], strict=True))
def trust(pre, snap=None):
    fields = [
      ('run_id',args['--native-run-id']),('nonce',args['--native-nonce']),
      ('realtime_start_ns',args['--native-realtime-start-ns']),
      ('monotonic_start_ns',args['--native-monotonic-start-ns']),
      ('pre_inventory_sha256',pre),
      ('bootstrap_sha256',args['--native-bootstrap-sha256']),
      ('focused_receipt_sha256',args['--native-focused-receipt-sha256']),
      ('focused_sidecar_sha256',args['--native-focused-sidecar-sha256']),
      ('full_receipt_sha256',args['--native-full-receipt-sha256']),
      ('full_sidecar_sha256',args['--native-full-sidecar-sha256']),
      ('runner_lock_sha256',args.get('--native-runner-lock-sha256','sha256:'+'2'*64)),
      ('project_identity_sha256',args.get('--native-project-identity-sha256','sha256:'+'3'*64)),
      ('canonical_test_contract_sha256',args.get('--native-canonical-test-contract-sha256','sha256:'+'4'*64)),
      ('native_launcher_contract_sha256',args.get('--native-launcher-contract-sha256','sha256:'+'5'*64)),
      ('native_binary_contract_sha256',args['--native-binary-contract-sha256']),
      ('public_key_id',args['--native-public-key-id'])]
    if snap is not None: fields.append(('semantic_snapshot_sha256',snap))
    return fields
if mode == 'preflight-fail-fast-enrich':
    path = Path(args['--native-preflight-envelope']); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text('EGSI-LIVE-PREFLIGHT-V1\n'+''.join(k+'='+v+'\n' for k,v in trust('sha256:'+'1'*64)),encoding='ascii'); path.chmod(0o600)
elif mode == 'run-fail-fast-enrich':
    artifact = Path(args['--attestation']); artifact.parent.mkdir(parents=True,exist_ok=True)
    snapshot = Path(str(artifact)+'.native-snapshot'); snapshot_raw=b'not-a-semantic-snapshot\n'; snapshot.write_bytes(snapshot_raw); snapshot.chmod(0o600)
    artifact_raw=b'{"forged":true}\n'; artifact.write_bytes(artifact_raw); artifact.chmod(0o600)
    fields=trust(args['--native-pre-inventory-sha256'],sha(snapshot_raw))+[
      ('child_exit_code','0'),('terminal_status','PASS'),
      ('post_inventory_sha256','sha256:'+'6'*64),
      ('attestation_sha256',sha(artifact_raw)),
      ('attestation_commitment_sha256','sha256:'+'7'*64)]
    candidate=Path(args['--native-candidate-envelope']); candidate.write_text('EGSI-LIVE-CANDIDATE-V1\n'+''.join(k+'='+v+'\n' for k,v in fields),encoding='ascii'); candidate.chmod(0o600)
else:
    raise SystemExit(99)
''',
        encoding="utf-8",
    )
    python.chmod(0o755)


def _sign_stub_receipts(root: Path, output: Path) -> tuple[Path, Path]:
    focused = output / "reports/offline-focused-receipt.json"
    full = output / "reports/offline-full-receipt.json"
    for name, receipt in (("focused", focused), ("full", full)):
        completed = subprocess.run(
            [
                str(root / "scripts/run_test_receipt"),
                "--name", name,
                "--output", str(receipt),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
    return focused, full


def _synthetic_locked_project(
    tmp_path: Path, *, attack_target: str | None = None
) -> tuple[Path, dict[str, object]]:
    """Build a disposable v7 runner so attack tests never taint canonical ctime."""

    isolated_temp_root = Path(
        tempfile.mkdtemp(prefix="egsi-synthetic-locked-", dir="/tmp")
    )
    _SYNTHETIC_LOCKED_TEMP_ROOTS.add(isolated_temp_root)
    root = isolated_temp_root / "synthetic-project"
    (root / "scripts").mkdir(parents=True)
    (root / "configs").mkdir()
    (root / "idea-stage").mkdir()
    (root / "idea-stage/spec.json").write_text("{}\n", encoding="utf-8")
    (root / "src/egsi/generation").mkdir(parents=True)
    (root / "tests/generation").mkdir(parents=True)
    (root / "tests/teacher").mkdir(parents=True)
    # Project-local receipt destinations are part of the synthetic runtime
    # closure.  Create them before its lock/native bootstrap is generated;
    # external /tmp outputs would bypass the no-clobber path checks.
    for relative in (
        ".work/live-output/reports",
        ".work/reports",
        "live-output/reports",
        "output/reports",
        "reports",
    ):
        (root / relative).mkdir(parents=True)
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
    test_private_key = _temporary_rsa_private_key(tmp_path, "locked-project.pem")
    for relative in (
        "src/egsi/__init__.py",
        "src/egsi/generation/test_receipt.py",
        "src/egsi/generation/safeio.py",
        "src/egsi/strict_json.py",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    (root / "src/egsi/generation/__init__.py").write_text(
        "\n", encoding="utf-8"
    )
    (root / "src/egsi/generation/pilot.py").write_text(
        """from __future__ import annotations
import hashlib, json, os, secrets, stat
from pathlib import Path

def _sha256(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()

def _dict_commitment(value, key):
    copy = dict(value); copy.pop(key, None)
    raw = json.dumps(copy, allow_nan=False, ensure_ascii=False,
                     sort_keys=True, separators=(',', ':')).encode('utf-8')
    return _sha256(raw)

def _read_regular(path, *, limit=16 * 1024 * 1024):
    path = Path(path); before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size < 0 or before.st_size > limit):
        raise ValueError('unsafe input')
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, 'O_NOFOLLOW'): flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd); raw = b''
        while len(raw) < current.st_size:
            chunk = os.read(fd, current.st_size - len(raw))
            if not chunk: raise ValueError('short read')
            raw += chunk
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_nlink,
        item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(current) or identity(current) != identity(after):
        raise ValueError('changed input')
    return raw

def _atomic_bytes(path, raw, verifier):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    verifier(raw)
    temporary = path.parent / ('.' + path.name + '.' + secrets.token_hex(8) + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw): offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)

def write_report(path, report):
    raw = json.dumps(report, allow_nan=False, ensure_ascii=False,
                     sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\\n'
    _atomic_bytes(path, raw, lambda value: None)
""",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
        encoding="utf-8",
    )
    (root / "configs/historical-teacher-audit-expectation.v1.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (
        root
        / "configs/first-case-historical-teacher-audit-expectation.v1.json"
    ).write_text("{}\n", encoding="utf-8")
    canonical_contract = json.loads(
        (ROOT / "configs/canonical-test-contract.v1.json").read_text(
            encoding="utf-8"
        )
    )
    for suite in canonical_contract["suites"].values():
        suite["nodeids"] = suite["nodeids"][:2]
        suite["collection_count"] = 2
        suite["nodeids_sha256"] = "sha256:" + hashlib.sha256(
            json.dumps(
                suite["nodeids"],
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    unsigned_contract = dict(canonical_contract)
    unsigned_contract.pop("contract_sha256", None)
    canonical_contract["contract_sha256"] = "sha256:" + hashlib.sha256(
        json.dumps(
            unsigned_contract,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    (root / "configs/canonical-test-contract.v1.json").write_text(
        json.dumps(
            canonical_contract,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    for relative in (
        "tests/data/test_repository_paths.py",
        "tests/generation/test_enrichment.py",
        "tests/generation/test_fail_fast_batch.py",
        "tests/generation/test_human_audit.py",
        "tests/generation/test_pilot.py",
        "tests/generation/test_first_case_hard_gate.py",
        "tests/generation/test_test_receipt.py",
        "tests/teacher/test_codex_exec.py",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("def test_placeholder(): assert True\n", encoding="utf-8")

    runner = root / ".work/offline-test-runner-venv"
    venv.EnvBuilder(
        system_site_packages=False,
        clear=True,
        symlinks=False,
        with_pip=False,
    ).create(runner)
    site_packages = runner / "lib/python3.12/site-packages"
    shutil.copytree(root / "src/egsi", site_packages / "egsi")
    metadata = site_packages / "egsi-0.1.0.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: egsi\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (metadata / "INSTALLER").write_text("synthetic\n", encoding="utf-8")
    for name in ("pytest", "pluggy"):
        package = site_packages / name
        package.mkdir()
        (package / "__init__.py").write_text(
            "__version__ = '1.0'\n", encoding="utf-8"
        )
        distribution = site_packages / f"{name}-1.0.dist-info"
        distribution.mkdir()
        (distribution / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
            encoding="utf-8",
        )
    target = (
        metadata / "INSTALLER"
        if attack_target == "site"
        else root / "configs/offline-test-runner.lock.json"
        if attack_target == "lock"
        else root / "tests/generation/test_enrichment.py"
        if attack_target == "project"
        else None
    )
    attack = ""
    if target is not None:
        attack = (
            "target = Path(" + repr(str(target)) + ")\n"
            "raw = target.read_bytes(); info = target.stat()\n"
            "target.write_bytes(b'X' * len(raw)); target.write_bytes(raw)\n"
            "os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))\n"
        )
    pytest_contract_lines: dict[str, str] = {}
    for suite_name, suite in canonical_contract["suites"].items():
        pytest_contract = {
            "schema_version": "1.0",
            "exit_status": 0,
            "collection_count": 2,
            "collection_nodeids_sha256": suite["nodeids_sha256"],
            "executed_count": 2,
            "executed_nodeids_sha256": suite["nodeids_sha256"],
            "passed_count": 2,
            "failed_count": 0,
            "skipped_count": 0,
            "contract_sha256": "sha256:" + "0" * 64,
        }
        unsigned_pytest_contract = dict(pytest_contract)
        unsigned_pytest_contract.pop("contract_sha256")
        pytest_contract["contract_sha256"] = "sha256:" + hashlib.sha256(
            json.dumps(
                unsigned_pytest_contract,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        pytest_contract_lines[suite_name] = (
            "EGSI_PYTEST_CONTRACT="
            + json.dumps(pytest_contract, sort_keys=True, separators=(",", ":"))
        )
    (site_packages / "pytest/__main__.py").write_text(
        "from pathlib import Path\nimport os, sys\n"
        + attack
        + f"lines = {pytest_contract_lines!r}\n"
        + "name = 'full' if sys.argv[-1:] == ['tests'] else 'focused'\n"
        + "print(lines[name])\nprint('2 passed in 0.01s')\n",
        encoding="utf-8",
    )
    native_build = subprocess.run(
        [
            str(root / "scripts/rebuild_locked_launchers"),
            "--synthetic-output-dir",
            str(root / "scripts"),
            "--test-private-key-pem",
            str(test_private_key),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert native_build.returncode == 0, native_build.stderr
    build = subprocess.run(
        [
            str(runner / "bin/python"),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "build-lock", "--root", str(root),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    lock = json.loads(
        (root / "configs/offline-test-runner.lock.json").read_text(
            encoding="utf-8"
        )
    )
    return root, lock


def _completed(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    name = "full" if command[-1:] == ["tests"] else "focused"
    canonical = json.loads(
        (ROOT / "configs/canonical-test-contract.v1.json").read_text()
    )["suites"][name]
    count = canonical["collection_count"]
    contract = {
        "schema_version": "1.0",
        "exit_status": 0,
        "collection_count": count,
        "collection_nodeids_sha256": canonical["nodeids_sha256"],
        "executed_count": count,
        "executed_nodeids_sha256": canonical["nodeids_sha256"],
        "passed_count": count,
        "failed_count": 0,
        "skipped_count": 0,
        "contract_sha256": "sha256:" + "0" * 64,
    }
    copy = dict(contract)
    copy.pop("contract_sha256")
    contract["contract_sha256"] = "sha256:" + hashlib.sha256(
        json.dumps(
            copy,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
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


def test_official_receipt_default_timeout_is_bounded_and_reaches_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.generation.test_receipt as receipt_module

    project_root = tmp_path / "project"
    configs = project_root / "configs"
    configs.mkdir(parents=True)
    work = project_root / ".work"
    work.mkdir()
    protected = configs / "historical-teacher-audit-expectation.v1.json"
    protected_bytes = b'{"source_controlled":true}\n'
    protected.write_bytes(protected_bytes)
    command = [sys.executable, "-m", "pytest", "tests/focused.py"]
    canonical = json.loads(
        (ROOT / "configs/canonical-test-contract.v1.json").read_text()
    )["suites"]["focused"]
    snapshot = {
        "command": command,
        "runner": {"project_identity_sha256": "sha256:" + "1" * 64},
        "code_commitments": {},
        "runner_environment_commitment_sha256": "sha256:" + "2" * 64,
        "canonical_test_suite": canonical,
    }
    snapshot_calls: list[tuple[Path, str]] = []

    def runtime_snapshot(root: Path, name: str) -> dict[str, object]:
        snapshot_calls.append((root, name))
        return snapshot

    monkeypatch.setattr(
        receipt_module, "_test_runtime_snapshot", runtime_snapshot
    )
    monkeypatch.setattr(
        receipt_module,
        "validate_test_receipt",
        lambda path, **_: json.loads(path.read_text(encoding="utf-8")),
    )
    temporary_directory_calls: list[dict[str, object]] = []
    original_temporary_directory = receipt_module.tempfile.TemporaryDirectory

    def tracked_temporary_directory(*args: object, **kwargs: object):
        temporary_directory_calls.append(dict(kwargs))
        return original_temporary_directory(*args, **kwargs)

    monkeypatch.setattr(
        receipt_module.tempfile,
        "TemporaryDirectory",
        tracked_temporary_directory,
    )
    write_calls: list[Path] = []
    writes_enabled = True
    original_write_report = receipt_module.write_report

    def tracked_write_report(path: Path, report: dict[str, object]) -> None:
        write_calls.append(Path(path))
        if writes_enabled:
            original_write_report(path, report)

    monkeypatch.setattr(receipt_module, "write_report", tracked_write_report)
    completed = _completed(command)
    race_destination: Path | None = None
    race_bytes = b"subprocess-created sentinel\n"

    def completed_with_race(
        command: list[str], **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        if race_destination is not None:
            race_destination.parent.mkdir(parents=True, exist_ok=True)
            race_destination.write_bytes(race_bytes)
        return completed

    output = tmp_path / "receipt.json"
    project_output = (
        work
        / "official-run"
        / "reports"
        / "offline-focused-receipt.json"
    )
    with patch.object(
        receipt_module.subprocess, "run", side_effect=completed_with_race
    ) as run:
        receipt_module.run_test_receipt(
            root=project_root, name="focused", output=output
        )
        receipt_module.run_test_receipt(
            root=project_root,
            name="focused",
            output=project_output,
        )
        project_output_info = project_output.lstat()
        assert project_output_info.st_nlink == 1
        assert stat.S_IMODE(project_output_info.st_mode) == 0o600

        snapshot_count = len(snapshot_calls)
        run_count = run.call_count
        temporary_directory_count = len(temporary_directory_calls)
        write_count = len(write_calls)
        writes_enabled = False
        target = tmp_path / "symlink-target.json"
        target_bytes = b"external sentinel\n"
        target.write_bytes(target_bytes)
        destination_link = tmp_path / "receipt-link.json"
        destination_link.symlink_to(target)
        ancestor_link = tmp_path / "source-alias"
        ancestor_link.symlink_to(configs, target_is_directory=True)
        sentinel_paths = (
            work / "offline-test-runner-venv" / "bin" / "python",
            (
                work
                / "retained-trust"
                / "reports"
                / "offline-focused-receipt.json"
            ),
            (
                work
                / "offline-test-runner-venv"
                / "reports"
                / "offline-focused-receipt.json"
            ),
            *(
                work
                / fixed_root
                / "reports"
                / "offline-focused-receipt.json"
                for fixed_root in (
                    "real-p0-codex-v2",
                    "real-p0-pragmatic-v1",
                    "p0-training-ready-v1",
                    "p1-pragmatic-control-v1",
                )
            ),
        )
        sentinel_bytes: dict[Path, bytes] = {}
        for index, path in enumerate(sentinel_paths):
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = f"locked sentinel {index}\n".encode("ascii")
            path.write_bytes(raw)
            sentinel_bytes[path] = raw
        forbidden_outputs = (
            protected,
            work / ".." / "configs" / "lexical-alias.json",
            destination_link,
            ancestor_link / "ancestor-alias.json",
            *sentinel_paths,
            work / "ordinary-run" / "reports" / "arbitrary.json",
            work / "ordinary-run" / "offline-focused-receipt.json",
            (
                work
                / "ordinary-run"
                / "reports"
                / "offline-full-receipt.json"
            ),
        )
        errors: dict[Path, Exception | None] = {}
        for forbidden in forbidden_outputs:
            try:
                receipt_module.run_test_receipt(
                    root=project_root,
                    name="focused",
                    output=forbidden,
                )
            except Exception as error:
                errors[forbidden] = error
            else:
                errors[forbidden] = None

        assert receipt_module.receipt_cli_main(
            ["--name", "focused", "--output", str(protected)],
            root=project_root,
        ) == 2
        assert protected.read_bytes() == protected_bytes
        assert target.read_bytes() == target_bytes
        assert all(path.read_bytes() == raw for path, raw in sentinel_bytes.items())
        assert not (configs / "lexical-alias.json").exists()
        assert not (configs / "ancestor-alias.json").exists()
        assert len(snapshot_calls) == snapshot_count
        assert run.call_count == run_count
        assert len(temporary_directory_calls) == temporary_directory_count
        assert len(write_calls) == write_count
        assert all(
            type(error) is ValueError
            and str(error).startswith("test receipt output destination")
            for error in errors.values()
        )

        writes_enabled = True
        race_destination = (
            work
            / "subprocess-race"
            / "reports"
            / "offline-focused-receipt.json"
        )
        race_counts = (
            len(snapshot_calls),
            run.call_count,
            len(temporary_directory_calls),
            len(write_calls),
        )
        race_error: Exception | None = None
        try:
            receipt_module.run_test_receipt(
                root=project_root,
                name="focused",
                output=race_destination,
            )
        except Exception as error:
            race_error = error
        observed_race_counts = (
            len(snapshot_calls) - race_counts[0],
            run.call_count - race_counts[1],
            len(temporary_directory_calls) - race_counts[2],
            len(write_calls) - race_counts[3],
        )
        assert (
            type(race_error) is ValueError,
            race_destination.read_bytes() == race_bytes,
            observed_race_counts,
        ) == (True, True, (2, 1, 1, 0))

    assert receipt_module.OFFICIAL_RECEIPT_TIMEOUT_SECONDS == 14_400
    assert inspect.signature(receipt_module.run_test_receipt).parameters[
        "timeout_seconds"
    ].default == receipt_module.OFFICIAL_RECEIPT_TIMEOUT_SECONDS
    assert run.call_args.kwargs["timeout"] == (
        receipt_module.OFFICIAL_RECEIPT_TIMEOUT_SECONDS
    )


@pytest.mark.parametrize(
    "override",
    [
        ["--timeout-seconds", "999999"],
        ["--timeout-seconds", "0"],
        ["--no-timeout"],
    ],
)
def test_official_receipt_cli_rejects_timeout_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: list[str],
) -> None:
    import egsi.generation.test_receipt as receipt_module

    called = False

    def unexpected_run(**_: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(receipt_module, "run_test_receipt", unexpected_run)
    with pytest.raises(SystemExit):
        receipt_module.receipt_cli_main(
            [
                "--name",
                "focused",
                "--output",
                str(tmp_path / "receipt.json"),
                *override,
            ],
            root=ROOT,
        )

    assert called is False


@pytest.mark.parametrize("attack", ["project", "lock"])
def test_pinned_live_preflight_requires_current_successful_rsa_receipts_and_runtime(
    tmp_path: Path, attack: str
) -> None:
    root, lock = _synthetic_locked_project(tmp_path)
    output = root / ".work/live-output"
    focused, full = _sign_stub_receipts(root, output)
    native = lock["native_launcher_contract"]
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    preflight = Path(str(attestation) + ".native-preflight")

    def digest(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    command = [
        str(root / ".work/offline-test-runner-venv/bin/python"),
        "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
        "-I", "-B", "-S",
        str(root / "scripts/locked_runtime_bootstrap.py"),
        "preflight-fail-fast-enrich",
        "--root", str(root),
        "--",
        "--output-root", str(output),
        "--attestation", str(attestation),
        "--native-preflight-envelope", str(preflight),
        "--native-run-id", "a" * 64,
        "--native-nonce", "b" * 64,
        "--native-realtime-start-ns", "10",
        "--native-monotonic-start-ns", "20",
        "--native-bootstrap-sha256", native["bootstrap_anchor"]["sha256"],
        "--native-focused-receipt-sha256", digest(focused),
        "--native-focused-sidecar-sha256", digest(
            Path(str(focused) + ".native-attestation")
        ),
        "--native-full-receipt-sha256", digest(full),
        "--native-full-sidecar-sha256", digest(
            Path(str(full) + ".native-attestation")
        ),
        "--native-binary-contract-sha256", native[
            "binary_contract_sha256"
        ],
        "--native-public-key-id", native["public_key_id"],
    ]
    first = subprocess.run(
        command,
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    assert preflight.read_text(encoding="ascii").startswith(
        "EGSI-LIVE-PREFLIGHT-V1\n"
    )

    preflight.unlink()
    target = (
        root / "tests/generation/test_enrichment.py"
        if attack == "project"
        else root / "configs/offline-test-runner.lock.json"
    )
    target.write_bytes(target.read_bytes() + b"\n")
    rejected = subprocess.run(
        command,
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert not preflight.exists()


def test_test_receipt_runs_only_the_canonical_project_suite_and_revalidates_code(
    tmp_path: Path,
) -> None:
    from egsi.generation.test_receipt import (
        OFFICIAL_RECEIPT_TIMEOUT_SECONDS,
        canonical_test_command,
        canonical_test_environment,
        run_test_receipt,
        validate_test_receipt,
    )

    output = tmp_path / "receipt.json"
    expected_command = canonical_test_command(ROOT, "focused")
    with patch("egsi.generation.test_receipt.subprocess.run") as run:
        run.return_value = _completed(expected_command)
        receipt = run_test_receipt(
            root=ROOT,
            name="focused",
            output=output,
        )

    assert run.call_args.args[0] == expected_command
    assert run.call_args.kwargs["shell"] is False
    assert OFFICIAL_RECEIPT_TIMEOUT_SECONDS == 14_400
    assert inspect.signature(run_test_receipt).parameters[
        "timeout_seconds"
    ].default == OFFICIAL_RECEIPT_TIMEOUT_SECONDS
    assert run.call_args.kwargs["timeout"] == OFFICIAL_RECEIPT_TIMEOUT_SECONDS
    execution_environment = run.call_args.kwargs["env"]
    recorded_environment = canonical_test_environment()
    assert set(execution_environment) == set(recorded_environment)
    assert {
        key: execution_environment[key]
        for key in recorded_environment
        if key not in {"HOME", "TMPDIR"}
    } == {
        key: value
        for key, value in recorded_environment.items()
        if key not in {"HOME", "TMPDIR"}
    }
    assert receipt["command"] == expected_command
    assert receipt["runner"]["command_executable"] == sys.executable
    assert receipt["environment"] == canonical_test_environment()
    assert receipt["runner_environment_commitment_sha256"].startswith(
        "sha256:"
    )
    assert receipt["project_identity_pre_sha256"] == receipt["runner"][
        "project_identity_sha256"
    ]
    assert receipt["project_identity_post_sha256"] == receipt["runner"][
        "project_identity_sha256"
    ]
    assert receipt["code_commitments"]["pyproject_toml_sha256"].startswith(
        "sha256:"
    )
    assert receipt["code_commitments"][
        "pytest_local_inventory_sha256"
    ].startswith("sha256:")
    assert receipt["code_commitments"][
        "offline_test_runner_lock_sha256"
    ].startswith("sha256:")
    assert receipt["passed_count"] == receipt["pytest_contract"][
        "collection_count"
    ]
    assert receipt["pytest_contract"]["collection_count"] > 1
    assert receipt["pytest_contract"]["collection_nodeids_sha256"] == (
        receipt["pytest_contract"]["executed_nodeids_sha256"]
    )
    assert receipt["failed_count"] == 0
    assert receipt["native_attested"] is False
    assert not Path(str(output) + ".native-attestation").exists()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert validate_test_receipt(
        output, root=ROOT, expected_name="focused"
    ) == receipt


def test_test_receipt_cli_rejects_arbitrary_or_temporary_pytest_commands(
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "test_cli_one.py"
    test_file.write_text("def test_cli_one():\n    assert True\n", encoding="utf-8")
    output = tmp_path / "receipt.json"

    completed = subprocess.run(
        [
            str(ROOT / "scripts/run_test_receipt"),
            "--name",
            "focused",
            "--output",
            str(output),
            "--",
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(test_file),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert not output.exists()


@pytest.mark.parametrize(
    "tamper",
    [
        "commitment",
        "source_tree",
        "pyproject",
        "unknown_field",
        "fake_999",
        "missing_runner",
        "command_swap",
        "temporary_test",
        "environment",
        "pytest_inventory",
        "runner_environment",
        "runner_lock",
        "project_identity_pre",
        "project_identity_post",
    ],
)
def test_test_receipt_rejects_tampering_and_self_signed_command_substitution(
    tmp_path: Path,
    tamper: str,
) -> None:
    from egsi.generation.test_receipt import (
        canonical_test_command,
        run_test_receipt,
        test_receipt_commitment,
        validate_test_receipt,
    )

    output = tmp_path / "receipt.json"
    command = canonical_test_command(ROOT, "full")
    with patch("egsi.generation.test_receipt.subprocess.run") as run:
        run.return_value = _completed(command)
        run_test_receipt(root=ROOT, name="full", output=output)
    value = json.loads(output.read_text(encoding="utf-8"))
    if tamper == "commitment":
        value["receipt_commitment_sha256"] = "sha256:" + "0" * 64
    elif tamper == "source_tree":
        value["code_commitments"]["source_tree_sha256"] = "sha256:" + "0" * 64
    elif tamper == "pyproject":
        value["code_commitments"]["pyproject_toml_sha256"] = "sha256:" + "0" * 64
    elif tamper == "unknown_field":
        value["surprise"] = True
    elif tamper == "fake_999":
        value["passed_count"] = 999
    elif tamper == "missing_runner":
        value["runner"]["resolved_executable"] = str(tmp_path / "does-not-exist")
    elif tamper == "command_swap":
        value["command"] = [sys.executable, "-c", "print('999 passed')"]
    elif tamper == "temporary_test":
        value["command"] = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            str(tmp_path / "test_one.py"),
        ]
    elif tamper == "environment":
        value["environment"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "0"
    elif tamper == "runner_environment":
        value["runner_environment_commitment_sha256"] = "sha256:" + "0" * 64
    elif tamper == "runner_lock":
        value["code_commitments"]["offline_test_runner_lock_sha256"] = (
            "sha256:" + "0" * 64
        )
    elif tamper == "project_identity_pre":
        value["project_identity_pre_sha256"] = "sha256:" + "0" * 64
    elif tamper == "project_identity_post":
        value["project_identity_post_sha256"] = "sha256:" + "0" * 64
    else:
        value["code_commitments"]["pytest_local_inventory_sha256"] = (
            "sha256:" + "0" * 64
        )
    if tamper != "commitment":
        value["receipt_commitment_sha256"] = test_receipt_commitment(value)
    output.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="test receipt"):
        validate_test_receipt(output, root=ROOT, expected_name="full")


def test_canonical_pytest_command_uses_locked_absolute_runtime_and_config() -> None:
    from egsi.generation.test_receipt import (
        canonical_test_command,
        load_runner_lock,
    )

    command = canonical_test_command(ROOT, "full")
    lock = load_runner_lock(ROOT)
    assert command[:12] == [
        lock["command_executable"],
        "-X",
        "pycache_prefix=/nonexistent/egsi-locked-pycache",
        "-I",
        "-B",
        "-S",
        str((ROOT / "scripts/locked_runtime_bootstrap.py").resolve()),
        "pytest",
        "--root",
        str(ROOT),
        "--",
        "-c",
    ]
    assert command[12] == str((ROOT / "pyproject.toml").resolve())
    assert f"--confcutdir={(ROOT / 'tests').resolve()}" in command
    assert command[-1] == "tests"


def test_locked_bootstrap_preserves_pytest_intenum_exit_code() -> None:
    import runpy

    bootstrap = runpy.run_path(
        str(ROOT / "scripts/locked_runtime_bootstrap.py"),
        run_name="egsi_bootstrap_exit_code_test",
    )
    assert bootstrap["_exit_code"](SystemExit(pytest.ExitCode.OK)) == 0


@pytest.mark.parametrize(
    "hook_name",
    [
        "conftest.py",
        "sitecustomize.py",
        "usercustomize.py",
        "pytest.ini",
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        "setup.cfg",
        "tox.ini",
    ],
)
@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink", "fifo"])
def test_test_receipt_preflight_rejects_root_hooks_configs_and_unsafe_nodes(
    tmp_path: Path,
    hook_name: str,
    kind: str,
) -> None:
    from egsi.generation.test_receipt import run_test_receipt

    project = tmp_path / "project"
    project.mkdir()
    root_before = ROOT.lstat()
    hook = project / hook_name
    assert not hook.exists() and not hook.is_symlink()
    source = project / f".{hook_name}.{kind}.receipt-test-source"
    assert not source.exists() and not source.is_symlink()
    source.write_text(
        "def pytest_collection_modifyitems(items):\n"
        "    [setattr(item, 'obj', lambda: None) for item in items]\n",
        encoding="utf-8",
    )
    if kind == "regular":
        hook.write_bytes(source.read_bytes())
    elif kind == "symlink":
        hook.symlink_to(source)
    elif kind == "hardlink":
        hook.hardlink_to(source)
    else:
        os.mkfifo(hook)
    output = tmp_path / "receipt.json"
    try:
        with patch("egsi.generation.test_receipt.subprocess.run") as run:
            run.return_value = _completed(["must-not-run"])
            with pytest.raises(ValueError, match="pytest|hook|config|receipt"):
                run_test_receipt(root=project, name="full", output=output)
            run.assert_not_called()
    finally:
        hook.unlink(missing_ok=True)
        source.unlink(missing_ok=True)
    assert not output.exists()
    root_after = ROOT.lstat()
    assert (
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    ) == (
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    )


def test_confcutdir_actually_blocks_root_conftest_discovery(tmp_path: Path) -> None:
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    marker = project / "ROOT_CONFTEST_IMPORTED"
    (project / "conftest.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n",
        encoding="utf-8",
    )
    (tests / "test_probe.py").write_text(
        "def test_probe():\n    assert True\n", encoding="utf-8"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--confcutdir=tests",
            "tests",
        ],
        cwd=project,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "1 passed" in completed.stdout
    assert not marker.exists()


def test_receipt_rebuilds_minimal_environment_with_private_ephemeral_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from egsi.generation.test_receipt import (
        canonical_test_command,
        canonical_test_environment,
        run_test_receipt,
    )

    for key, value in {
        "PYTHONPATH": str(tmp_path / "shadow"),
        "PYTEST_ADDOPTS": "-p shadow_plugin",
        "PYTEST_PLUGINS": "shadow_plugin",
        "LD_PRELOAD": str(tmp_path / "inject.so"),
        "LD_LIBRARY_PATH": str(tmp_path / "loader"),
        "COVERAGE_PROCESS_START": str(tmp_path / "coverage.ini"),
        "COVERAGE_FILE": str(tmp_path / ".coverage"),
        "HOME": str(tmp_path / "host-home"),
        "TMPDIR": str(tmp_path / "host-tmp"),
    }.items():
        monkeypatch.setenv(key, value)

    expected_command = canonical_test_command(ROOT, "focused")
    observed_environment: dict[str, str] = {}

    def inspect_environment(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs["env"]
        assert type(environment) is dict
        observed_environment.update(environment)
        assert set(environment) == set(canonical_test_environment())
        for key in ("HOME", "TMPDIR"):
            path = Path(environment[key])
            assert path.is_dir()
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
            assert path.is_relative_to(Path("/tmp"))
        return _completed(command)

    output = tmp_path / "receipt.json"
    with patch(
        "egsi.generation.test_receipt.subprocess.run",
        side_effect=inspect_environment,
    ):
        run_test_receipt(root=ROOT, name="focused", output=output)

    assert set(observed_environment) == {
        "PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR",
        "PYTHONDONTWRITEBYTECODE", "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    }
    assert observed_environment["PATH"] == "/usr/bin:/bin"
    assert observed_environment["LANG"] == "C.UTF-8"
    assert observed_environment["LC_ALL"] == "C.UTF-8"
    assert observed_environment["TZ"] == "UTC"
    assert observed_environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert observed_environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert not Path(observed_environment["HOME"]).exists()
    assert not Path(observed_environment["TMPDIR"]).exists()


def test_pytest_toml_plugin_injection_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = _synthetic_locked_project(tmp_path)
    root_before = ROOT.lstat()
    config = root / "pytest.toml"
    plugin = tmp_path / "shadow_plugin.py"
    marker = tmp_path / "PLUGIN_LOADED"
    assert not config.exists() and not config.is_symlink()
    plugin.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n",
        encoding="utf-8",
    )
    config.write_text(
        '[pytest]\naddopts = ["-p", "shadow_plugin"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PYTEST_ADDOPTS", "-p shadow_plugin")
    monkeypatch.setenv("PYTEST_PLUGINS", "shadow_plugin")
    output = tmp_path / "receipt.json"
    try:
        completed = subprocess.run(
            [
                str(root / "scripts/run_test_receipt"),
                "--name", "full",
                "--output", str(output),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        config.unlink(missing_ok=True)
    assert completed.returncode != 0
    assert not marker.exists()
    assert not output.exists()
    root_after = ROOT.lstat()
    assert (
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    ) == (
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    )


def test_shadow_venv_interpreter_is_replaced_before_any_project_import(
    tmp_path: Path,
) -> None:
    import egsi.generation.test_receipt as receipt_module

    shadow = tmp_path / "shadow-venv"
    interpreter = shadow / "bin/python"
    fake_pytest = shadow / "lib/python3.12/site-packages/pytest/__init__.py"
    interpreter.parent.mkdir(parents=True)
    fake_pytest.parent.mkdir(parents=True)
    shutil.copy2(Path(sys.executable).resolve(), interpreter)
    fake_pytest.write_text("__version__ = '999.0'\n", encoding="utf-8")
    (shadow / "pyvenv.cfg").write_text(
        f"home = {Path(sys.executable).resolve().parent}\n"
        "include-system-site-packages = true\n",
        encoding="utf-8",
    )

    with patch.object(receipt_module.sys, "executable", str(interpreter)):
        with pytest.raises(ValueError, match="runner|lock|receipt"):
            receipt_module.canonical_test_command(ROOT, "full")

    assert not (ROOT / "scripts/run_test_receipt.py").exists()
    completed = subprocess.run(
        [str(ROOT / "scripts/run_test_receipt"), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_runner_lock_has_explicit_offline_update_cli_and_is_not_auto_rewritten(
    tmp_path: Path,
) -> None:
    from egsi.generation.test_receipt import canonical_test_command

    lock_path = ROOT / "configs/offline-test-runner.lock.json"
    before = lock_path.read_bytes()
    canonical_test_command(ROOT, "focused")
    assert lock_path.read_bytes() == before

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(ROOT / "scripts/update_offline_test_runner_lock.py"),
            "--root", str(ROOT),
            "--output", str(tmp_path / "outside.json"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not (tmp_path / "outside.json").exists()


def test_runner_lock_binds_clean_venv_full_site_closure_and_stdlib() -> None:
    from egsi.generation.test_receipt import load_runner_lock

    lock = load_runner_lock(ROOT)
    assert lock["schema_version"] == "8.0"
    assert lock["runner_contract_version"] == "offline-pytest-runner-v8"
    assert lock["native_launcher_contract"]["schema_version"] == "8.0"
    assert lock["native_launcher_contract"]["attestation_version"] == "2"
    assert lock["native_launcher_contract"]["attestation_algorithm"] == (
        "rsa-2048-sha256-pkcs1-v1_5"
    )
    assert lock["native_launcher_contract"]["public_key_id"].startswith(
        "sha256:"
    )
    assert lock["native_launcher_contract"][
        "binary_contract_sha256"
    ].startswith("sha256:")
    assert lock["include_system_site_packages"] is False
    assert lock["no_pth"] is True
    assert lock["site_packages_root"].startswith(str(ROOT / ".work"))
    assert lock["command_executable"].startswith(str(ROOT / ".work"))
    assert lock["sys_prefix"] != lock["sys_base_prefix"]
    assert lock["project_source_tree_sha256"] == lock[
        "project_installed_tree_sha256"
    ]
    assert lock["stdlib_tree_sha256"].startswith("sha256:")
    assert lock["stdlib_file_count"] > 0
    project_inventory = lock["project_inventory"]
    project_by_path = {item["path"]: item for item in project_inventory}
    assert len(project_by_path) == len(project_inventory)
    assert "pyproject.toml" in project_by_path
    assert not {"src", "tests", "scripts", "configs", "idea-stage"}.intersection(
        project_by_path
    )
    assert "configs/offline-test-runner.lock.json" not in project_by_path
    for launcher in (
        "scripts/run_test_receipt",
        "scripts/rerun_first_case_hard_gate",
        "scripts/verify_first_case_hard_gate",
        "scripts/run_fail_fast_enrich",
        "scripts/verify_fail_fast_enrich",
    ):
        assert project_by_path[launcher]["type"] == "regular"
        assert project_by_path[launcher]["links"] == 1
        assert project_by_path[launcher]["sha256"].startswith("sha256:")
    assert project_by_path["scripts/run_test_receipt"]["mode"] == 0o111
    assert project_by_path["scripts/rerun_first_case_hard_gate"]["mode"] == 0o111
    assert project_by_path["scripts/verify_first_case_hard_gate"]["mode"] == 0o555
    assert project_by_path["scripts/run_fail_fast_enrich"]["mode"] == 0o111
    assert project_by_path["scripts/verify_fail_fast_enrich"]["mode"] == 0o555
    project_raw = json.dumps(
        project_inventory,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert lock["project_identity_sha256"] == (
        "sha256:" + hashlib.sha256(project_raw).hexdigest()
    )
    inventory = lock["site_packages_inventory"]
    assert type(inventory) is list and inventory
    assert all(
        set(item)
        == {
            "path", "type", "mode", "device", "inode", "links",
            "uid", "gid", "size", "mtime_ns", "ctime_ns", "sha256",
        }
        and not Path(item["path"]).is_absolute()
        and item["type"] in {"directory", "regular"}
        and type(item["size"]) is int
        and item["size"] >= 0
        and type(item["mode"]) is int
        and all(
            type(item[field]) is int and item[field] >= 0
            for field in (
                "device", "inode", "links", "uid", "gid",
                "mtime_ns", "ctime_ns",
            )
        )
        and (
            item["sha256"] is None
            if item["type"] == "directory"
            else str(item["sha256"]).startswith("sha256:")
        )
        for item in inventory
    )
    forbidden = {"sitecustomize.py", "usercustomize.py"}
    assert not any(
        Path(item["path"]).suffix == ".pth"
        or Path(item["path"]).name in forbidden
        for item in inventory
    )
    assert all(
        "/.local/" not in item
        and item != str(ROOT / "src")
        and item.startswith(
            (
                str(Path(lock["sys_base_prefix"])),
                str(Path(lock["sys_prefix"])),
            )
        )
        for item in lock["isolated_sys_path"]
    )


def test_offline_runner_bootstrap_declares_asymmetric_test_crypto_closure() -> None:
    """The locked runner must carry the local RSA oracle dependencies.

    The native signer tests import ``cryptography`` from the isolated venv; a
    host-only copy would make a canonical receipt fail during collection.
    """

    bootstrap = runpy.run_path(
        str(ROOT / "scripts/bootstrap_offline_test_runner.py"),
        run_name="egsi_bootstrap_crypto_closure_test",
    )
    entries = set(bootstrap["_COPY_ENTRIES"])
    assert {
        "cryptography",
        "cryptography-*.dist-info",
        "cffi",
        "cffi-*.dist-info",
        "_cffi_backend*.so",
    }.issubset(entries)


_BOOTSTRAP_NATIVE_OUTPUTS = (
    "scripts/run_test_receipt",
    "scripts/rerun_first_case_hard_gate",
    "scripts/verify_first_case_hard_gate",
    "scripts/run_fail_fast_enrich",
    "scripts/verify_fail_fast_enrich",
    "configs/native-signer-build-record.json",
)


def _bootstrap_transaction_fixture(tmp_path: Path):
    spec = importlib.util.spec_from_file_location(
        "egsi_test_transactional_runner_bootstrap",
        ROOT / "scripts/bootstrap_offline_test_runner.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "bootstrap-project"
    for relative in ("scripts", "configs", "src/egsi", ".work"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "scripts/rebuild_locked_launchers").write_text(
        "#!/bin/sh\nexit 99\n", encoding="utf-8"
    )
    (root / "scripts/rebuild_locked_launchers").chmod(0o755)
    old_runner = root / ".work/offline-test-runner-venv"
    (old_runner / "bin").mkdir(parents=True)
    (old_runner / "old-marker").write_text("old-runner\n", encoding="utf-8")
    for index, relative in enumerate(_BOOTSTRAP_NATIVE_OUTPUTS):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"old-native-{index}\n".encode())
        path.chmod(0o111 if "record" not in relative else 0o444)

    class FakeBuilder:
        def __init__(self, **_: object) -> None:
            pass

        def create(self, target: Path) -> None:
            (target / "bin").mkdir(parents=True)
            (target / "bin/python").write_text("new-python\n", encoding="utf-8")
            (target / "lib/python3.12/site-packages").mkdir(parents=True)

    return module, root, FakeBuilder


def test_offline_runner_bootstrap_rebuilds_native_before_lock_and_probe(
    tmp_path: Path,
) -> None:
    bootstrap, root, fake_builder = _bootstrap_transaction_fixture(tmp_path)
    calls: list[str] = []

    def fake_run(command: list[str], **_: object):
        if command == [str(root / "scripts/rebuild_locked_launchers")]:
            calls.append("native")
            assert all(not (root / relative).exists() for relative in _BOOTSTRAP_NATIVE_OUTPUTS)
            for index, relative in enumerate(_BOOTSTRAP_NATIVE_OUTPUTS):
                path = root / relative
                path.write_bytes(f"new-native-{index}\n".encode())
                path.chmod(0o111 if "record" not in relative else 0o444)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "build-lock" in command:
            calls.append("lock")
            assert calls == ["native", "lock"]
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "probe" in command:
            calls.append("probe")
            assert calls == ["native", "lock", "probe"]
            return subprocess.CompletedProcess(
                command, 0, stdout="locked-runtime-probe-ok\n", stderr=""
            )
        raise AssertionError(f"unexpected bootstrap command: {command!r}")

    with (
        patch.object(bootstrap, "_site_source_directories", return_value=[]),
        patch.object(bootstrap, "_copy_dependency_closure"),
        patch.object(bootstrap, "_copy_project"),
        patch.object(bootstrap, "_clean_and_validate_site"),
        patch.object(bootstrap.venv, "EnvBuilder", fake_builder),
        patch.object(bootstrap.subprocess, "run", side_effect=fake_run),
    ):
        result = bootstrap.bootstrap(root)

    assert result == root / ".work/offline-test-runner-venv"
    assert calls == ["native", "lock", "probe"]
    assert not (result / "old-marker").exists()
    assert not list(root.glob(".offline-bootstrap-backup.*.tmp"))
    for relative in _BOOTSTRAP_NATIVE_OUTPUTS:
        path = root / relative
        assert path.is_file()
        assert stat.S_IMODE(path.lstat().st_mode) == (
            0o444 if "record" in relative else 0o111
        )
    assert (root / _BOOTSTRAP_NATIVE_OUTPUTS[-1]).read_bytes() == b"new-native-5\n"


def test_offline_runner_bootstrap_failure_restores_native_and_runner_inodes(
    tmp_path: Path,
) -> None:
    bootstrap, root, fake_builder = _bootstrap_transaction_fixture(tmp_path)
    runner = root / ".work/offline-test-runner-venv"
    old_runner_inode = runner.lstat().st_ino
    old_native = {
        relative: (
            (root / relative).lstat().st_ino,
            (
                (root / relative).read_bytes()
                if "record" in relative
                else None
            ),
            stat.S_IMODE((root / relative).lstat().st_mode),
        )
        for relative in _BOOTSTRAP_NATIVE_OUTPUTS
    }

    def fake_run(command: list[str], **_: object):
        if command == [str(root / "scripts/rebuild_locked_launchers")]:
            for index, relative in enumerate(_BOOTSTRAP_NATIVE_OUTPUTS):
                path = root / relative
                path.write_bytes(f"partial-native-{index}\n".encode())
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "build-lock" in command:
            return subprocess.CompletedProcess(command, 122, stdout="", stderr="fail")
        raise AssertionError(f"unexpected bootstrap command: {command!r}")

    with (
        patch.object(bootstrap, "_site_source_directories", return_value=[]),
        patch.object(bootstrap, "_copy_dependency_closure"),
        patch.object(bootstrap, "_copy_project"),
        patch.object(bootstrap, "_clean_and_validate_site"),
        patch.object(bootstrap.venv, "EnvBuilder", fake_builder),
        patch.object(bootstrap.subprocess, "run", side_effect=fake_run),
        pytest.raises(ValueError, match="lock update failed"),
    ):
        bootstrap.bootstrap(root)

    assert runner.lstat().st_ino == old_runner_inode
    assert (runner / "old-marker").read_text(encoding="utf-8") == "old-runner\n"
    assert not list(root.glob(".offline-bootstrap-backup.*.tmp"))
    for relative, (inode, raw, mode) in old_native.items():
        path = root / relative
        assert path.lstat().st_ino == inode
        if raw is not None:
            assert path.read_bytes() == raw
        assert stat.S_IMODE(path.lstat().st_mode) == mode


@pytest.mark.parametrize("old_lock_present", [True, False])
def test_offline_runner_probe_failure_rolls_back_lock_transactionally(
    tmp_path: Path, old_lock_present: bool
) -> None:
    bootstrap, root, fake_builder = _bootstrap_transaction_fixture(tmp_path)
    lock = root / "configs/offline-test-runner.lock.json"
    if old_lock_present:
        lock.write_bytes(b"old-lock\n")
        lock.chmod(0o640)
        old_identity = (
            lock.lstat().st_ino,
            lock.read_bytes(),
            stat.S_IMODE(lock.lstat().st_mode),
        )
    else:
        lock.unlink(missing_ok=True)
        old_identity = None

    def fake_run(command: list[str], **_: object):
        if command == [str(root / "scripts/rebuild_locked_launchers")]:
            for index, relative in enumerate(_BOOTSTRAP_NATIVE_OUTPUTS):
                path = root / relative
                path.write_bytes(f"new-native-{index}\n".encode())
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "build-lock" in command:
            lock.write_bytes(b"new-lock\n")
            lock.chmod(0o600)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if "probe" in command:
            return subprocess.CompletedProcess(command, 66, stdout="", stderr="fail")
        raise AssertionError(f"unexpected bootstrap command: {command!r}")

    with (
        patch.object(bootstrap, "_site_source_directories", return_value=[]),
        patch.object(bootstrap, "_copy_dependency_closure"),
        patch.object(bootstrap, "_copy_project"),
        patch.object(bootstrap, "_clean_and_validate_site"),
        patch.object(bootstrap.venv, "EnvBuilder", fake_builder),
        patch.object(bootstrap.subprocess, "run", side_effect=fake_run),
        pytest.raises(ValueError, match="locked probe failed"),
    ):
        bootstrap.bootstrap(root)

    if old_identity is None:
        assert not lock.exists()
    else:
        assert (
            lock.lstat().st_ino,
            lock.read_bytes(),
            stat.S_IMODE(lock.lstat().st_mode),
        ) == old_identity
    assert not list(root.glob(".offline-bootstrap-backup.*.tmp"))


def test_project_inventory_rejects_uncommitted_bytecode_cache(
    tmp_path: Path,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_locked_bootstrap",
        ROOT / "scripts/locked_runtime_bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    root = tmp_path / "project"
    for relative in ("src", "tests", "scripts", "configs", "idea-stage"):
        (root / relative).mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname='x'\n")
    cache = root / "src/__pycache__"
    cache.mkdir()
    (cache / "payload.cpython-312.pyc").write_bytes(b"uncommitted bytecode")

    with pytest.raises(ValueError, match="bytecode cache"):
        bootstrap._project_inventory(root)


def test_project_inventory_ignores_restored_directory_ctime_but_keeps_files(
    tmp_path: Path,
) -> None:
    """A clean canonical pytest run may create and remove safe test fixtures.

    File identities still detect mutate-and-restore attacks.  Parent-directory
    ctime alone is not durable content and must not make a restored tree
    impossible to attest.
    """

    spec = importlib.util.spec_from_file_location(
        "egsi_test_locked_bootstrap_directory_ctime",
        ROOT / "scripts/locked_runtime_bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    root = tmp_path / "project"
    for relative in ("src", "tests", "scripts", "configs", "idea-stage"):
        (root / relative).mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname='x'\n")
    stable = root / "tests/stable.py"
    stable.write_text("value = 1\n", encoding="utf-8")
    before = bootstrap._project_inventory(root)
    transient = root / "tests/transient.py"
    transient.write_text("transient = 1\n", encoding="utf-8")
    transient.unlink()
    assert bootstrap._project_inventory(root) == before


def test_site_closure_ignores_regenerated_bytecode_only(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_locked_bootstrap_site_bytecode",
        ROOT / "scripts/locked_runtime_bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    site = tmp_path / "site-packages"
    package = site / "package"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("value = 1\n", encoding="utf-8")
    before = bootstrap._site_packages_inventory(site)
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "__init__.cpython-312.pyc").write_bytes(b"derived")
    assert bootstrap._site_packages_inventory(site) == before


@pytest.mark.parametrize(
    "attack", ["extra", "missing", "symlink", "hardlink", "fifo"]
)
def test_runner_lock_rejects_every_site_packages_closure_mutation(
    tmp_path: Path,
    attack: str,
) -> None:
    root, before = _synthetic_locked_project(tmp_path)
    site_packages = Path(str(before["site_packages_root"]))
    probe = site_packages / f".egsi-runner-closure-{attack}"
    source = site_packages / ".egsi-runner-closure-hardlink-source"
    missing = site_packages / "egsi-0.1.0.dist-info/INSTALLER"
    assert not probe.exists() and not probe.is_symlink()
    assert not source.exists() and not source.is_symlink()

    if attack == "extra":
        probe.write_bytes(b"unexpected runtime file\n")
    elif attack == "missing":
        missing.unlink()
    elif attack == "symlink":
        probe.symlink_to(tmp_path / "outside-runner")
    elif attack == "hardlink":
        source.write_bytes(b"ambiguous runtime file\n")
        probe.hardlink_to(source)
    else:
        os.mkfifo(probe)
    completed = subprocess.run(
        [
            str(before["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "probe", "--root", str(root),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0


def test_test_receipt_rechecks_runner_closure_after_pytest_returns(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path, attack_target="site")
    output = tmp_path / "must-not-publish.json"
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "run-test-receipt", "--root", str(root), "--",
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not output.exists()


def test_test_receipt_rejects_mutate_restore_with_original_bytes_and_mtime(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path, attack_target="site")
    target = Path(str(lock["site_packages_root"])) / "egsi-0.1.0.dist-info/INSTALLER"
    info = target.stat()
    output = tmp_path / "must-not-publish-after-restore.json"
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "run-test-receipt", "--root", str(root), "--",
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert target.stat().st_mtime_ns == info.st_mtime_ns
    assert target.stat().st_ctime_ns != info.st_ctime_ns, (
        completed.stdout + completed.stderr
    )
    assert not output.exists()


def test_test_receipt_binds_lock_file_identity_across_the_subprocess(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path, attack_target="lock")
    lock_path = root / "configs/offline-test-runner.lock.json"
    before = lock_path.stat()
    raw = lock_path.read_bytes()
    output = tmp_path / "must-not-publish-after-lock-restore.json"
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "run-test-receipt", "--root", str(root), "--",
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert lock_path.read_bytes() == raw
    assert lock_path.stat().st_mtime_ns == before.st_mtime_ns
    assert lock_path.stat().st_ctime_ns != before.st_ctime_ns, (
        completed.stdout + completed.stderr
    )
    assert not output.exists()


def test_test_receipt_rejects_project_restore_with_original_bytes_and_mtime(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path, attack_target="project")
    target = root / "tests/generation/test_enrichment.py"
    before = target.stat()
    raw = target.read_bytes()
    output = tmp_path / "must-not-publish-after-project-restore.json"
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "run-test-receipt", "--root", str(root), "--",
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert target.read_bytes() == raw
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    assert target.stat().st_ctime_ns != before.st_ctime_ns
    assert not output.exists()


def test_runner_lock_rejects_a_byte_identical_copied_venv(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path)
    runner = root / ".work/offline-test-runner-venv"
    original = root / ".work/original-runner"
    os.replace(runner, original)
    shutil.copytree(original, runner, symlinks=False)
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "probe", "--root", str(root),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0


def test_lock_builder_rejects_a_symlinked_site_packages_root(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path)
    site_packages = Path(str(lock["site_packages_root"]))
    moved = site_packages.parent / "moved-site-packages"
    os.replace(site_packages, moved)
    site_packages.symlink_to(moved, target_is_directory=True)
    completed = subprocess.run(
        [
            str(lock["command_executable"]),
            "-X", "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I", "-B", "-S",
            str(root / "scripts/locked_runtime_bootstrap.py"),
            "build-lock", "--root", str(root),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0


def test_fresh_runner_rejects_self_erasing_pth_without_forging_receipt(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path)
    site_packages = Path(str(lock["site_packages_root"]))
    hook = site_packages / "zzz_self_erasing_attack.pth"
    module = site_packages / "evilhook.py"
    marker = tmp_path / "PTH_EXECUTED"
    output = tmp_path / "forged-receipt.json"
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
            "run-test-receipt", "--root", str(root), "--",
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert not marker.exists()
    assert hook.exists() and module.exists()
    assert not output.exists()


def test_receipt_cli_does_not_import_pythonpath_shadow_before_isolation(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    marker = tmp_path / "SHADOW_IMPORT_EXECUTED"
    output = tmp_path / "must-not-create-receipt.json"
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
            str(ROOT / "scripts/run_test_receipt"),
            "--help",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert not marker.exists()
    assert not output.exists()
    assert completed.returncode == 0


def test_official_launchers_are_static_pinned_native_elf_and_py_wrappers_absent(
    tmp_path: Path,
) -> None:
    expected_modes = {
        "run_test_receipt": 0o111,
        "rerun_first_case_hard_gate": 0o111,
        "verify_first_case_hard_gate": 0o555,
    }
    for name, expected_mode in expected_modes.items():
        launcher = ROOT / "scripts" / name
        info = launcher.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == expected_mode
        assert info.st_nlink == 1
        if expected_mode == 0o111:
            with pytest.raises(PermissionError):
                launcher.read_bytes()
        else:
            assert launcher.read_bytes().startswith(b"\x7fELF")
            program_headers = subprocess.run(
                ["/usr/bin/readelf", "-lW", str(launcher)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            dynamic = subprocess.run(
                ["/usr/bin/readelf", "-dW", str(launcher)],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            assert "INTERP" not in program_headers
            assert "DYNAMIC" not in program_headers
            assert "There is no dynamic section" in dynamic

            copied = tmp_path / name
            shutil.copy2(launcher, copied)
            copied.chmod(0o555)
            rejected = subprocess.run(
                [str(copied), "--help"],
                capture_output=True,
                text=True,
                check=False,
            )
            assert rejected.returncode != 0

    assert not (ROOT / "scripts/run_test_receipt.py").exists()
    assert not (ROOT / "scripts/rerun_first_case_hard_gate.py").exists()
    assert not (ROOT / "scripts/verify_first_case_hard_gate.py").exists()


def test_static_launchers_ignore_loader_shell_and_python_startup_injection(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "INHERITED_ENV_EXECUTED"
    constructor = tmp_path / "constructor.c"
    library = tmp_path / "constructor.so"
    constructor.write_text(
        "#include <fcntl.h>\n#include <unistd.h>\n"
        "__attribute__((constructor)) static void attack(void) {\n"
        f"  int fd = open({json.dumps(str(marker))}, O_WRONLY|O_CREAT|O_TRUNC, 0600);\n"
        "  if (fd >= 0) { write(fd, \"loader\", 6); close(fd); }\n}\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["/usr/bin/cc", "-shared", "-fPIC", "-O2", "-o", str(library), str(constructor)],
        check=True,
        capture_output=True,
    )
    shell_hook = tmp_path / "shell-hook"
    shell_hook.write_text(f"printf shell > {str(marker)!r}\n", encoding="utf-8")
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    for name in ("json.py", "sitecustomize.py"):
        (shadow / name).write_text(
            f"open({str(marker)!r}, 'w').write({name!r})\n",
            encoding="utf-8",
        )
    environment = dict(os.environ)
    environment.update(
        {
            "LD_PRELOAD": str(library),
            "BASH_ENV": str(shell_hook),
            "ENV": str(shell_hook),
            "SHELLOPTS": "xtrace",
            "PS4": "$(printf ps4 > " + str(marker) + ")",
            "PYTHONPATH": str(shadow),
        }
    )
    for name in (
        "run_test_receipt",
        "rerun_first_case_hard_gate",
        "verify_first_case_hard_gate",
    ):
        completed = subprocess.run(
            [str(ROOT / "scripts" / name), "--help"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert not marker.exists()


def test_native_python_child_environment_is_a_fixed_allowlist(
    tmp_path: Path,
) -> None:
    root = tmp_path / "native-child-environment"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = "if mode == 'run-test-receipt':\n"
    forbidden = (
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONHOME", "PYTHONPATH",
        "BASH_ENV", "ENV", "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
    )
    replacement = (
        needle
        + "    inherited = sorted(set(os.environ).intersection("
        + repr(forbidden)
        + "))\n"
        + "    (root / 'child-environment.json').write_text("
        + "json.dumps({'keys': sorted(os.environ), 'forbidden': inherited, "
        + "'pycache_prefix': sys.pycache_prefix}), "
        + "encoding='utf-8')\n"
    )
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "native-child-environment.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "receipt.json"
    environment = dict(os.environ)
    environment.update(
        {
            "LD_PRELOAD": str(tmp_path / "attack.so"),
            "LD_LIBRARY_PATH": str(tmp_path / "loader"),
            "PYTHONHOME": str(tmp_path / "python-home"),
            "PYTHONPATH": str(tmp_path / "shadow"),
            "BASH_ENV": str(tmp_path / "shell-hook"),
            "ENV": str(tmp_path / "shell-hook"),
            "PYTEST_ADDOPTS": "-p attacker",
            "PYTEST_PLUGINS": "attacker",
        }
    )

    completed = subprocess.run(
        [
            str(root / "scripts/run_test_receipt"),
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(
        (root / "child-environment.json").read_text(encoding="utf-8")
    )
    assert observed["forbidden"] == []
    assert set(observed["keys"]) == set(_LOCKED_ENVIRONMENT)
    assert observed["pycache_prefix"] == "/nonexistent/egsi-locked-pycache"


@pytest.mark.parametrize(
    "command",
    [
        ["run_test_receipt"],
        ["run_test_receipt", "--root", str(ROOT)],
        ["run_test_receipt", "--name", "focused", "--name", "focused", "--output", "/tmp/x"],
        ["run_test_receipt", "--name=focused", "--output", "/tmp/x"],
        [
            "verify_first_case_hard_gate",
            "--output-root", "/tmp/o", "--output-root", "/tmp/o",
            "--case-id", "x", "--focused-receipt", "/tmp/f",
            "--full-receipt", "/tmp/u", "--report", "/tmp/r",
            "--mode", "verify-only",
        ],
        [
            "verify_first_case_hard_gate",
            "--output-root=/tmp/o", "--case-id", "x",
            "--focused-receipt", "/tmp/f", "--full-receipt", "/tmp/u",
            "--report", "/tmp/r", "--mode", "verify-only",
        ],
        [
            "verify_first_case_hard_gate",
            "--root", str(ROOT), "--output-root", "/tmp/o",
            "--case-id", "x", "--focused-receipt", "/tmp/f",
            "--full-receipt", "/tmp/u", "--report", "/tmp/r",
            "--mode", "verify-only",
        ],
        [
            "verify_first_case_hard_gate",
            "--output-root", "/tmp/o", "--case-id", "x",
            "--focused-receipt", "/tmp/f", "--full-receipt", "/tmp/u",
            "--report", "/tmp/r", "--mode", "verify-only",
            "--mode", "verify-only",
        ],
    ],
)
def test_native_launchers_reject_invalid_or_duplicate_singleton_options(
    command: list[str],
) -> None:
    completed = subprocess.run(
        [str(ROOT / "scripts" / command[0]), *command[1:]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0


def test_synthetic_native_build_is_explicit_key_deterministic_and_public_only(
    tmp_path: Path,
) -> None:
    synthetic_root = tmp_path / "synthetic-native-root"
    _copy_asymmetric_native_build_sources(synthetic_root)
    scripts = synthetic_root / "scripts"
    build = scripts / "rebuild_locked_launchers"
    key = _temporary_rsa_private_key(tmp_path, "deterministic.pem")
    public = serialization.load_pem_private_key(
        key.read_bytes(), password=None
    ).public_key()
    expected_key_id = hashlib.sha256(
        public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    before_private_dirs = set(Path("/tmp").glob("egsi-native-build.*"))

    def rebuild(test_key: Path) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [
                str(build),
                "--synthetic-output-dir",
                str(scripts),
                "--test-private-key-pem",
                str(test_key),
            ],
            cwd=synthetic_root,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert str(test_key) not in completed.stdout
        assert str(test_key) not in completed.stderr
        return completed

    first = rebuild(key)
    assert first.returncode == 0, first.stderr
    first_record = json.loads(
        (synthetic_root / "configs/native-signer-build-record.json")
        .read_text(encoding="utf-8")
    )
    first_hashes = {
        "run_test_receipt": first_record["signers"]["receipt"]["build_sha256"],
        "rerun_first_case_hard_gate": first_record["signers"]["report"]["build_sha256"],
        "verify_first_case_hard_gate": first_record["verifier"]["sha256"],
    }
    second = rebuild(key)
    assert second.returncode == 0, second.stderr
    second_record = json.loads(
        (synthetic_root / "configs/native-signer-build-record.json")
        .read_text(encoding="utf-8")
    )
    assert {
        "run_test_receipt": second_record["signers"]["receipt"]["build_sha256"],
        "rerun_first_case_hard_gate": second_record["signers"]["report"]["build_sha256"],
        "verify_first_case_hard_gate": second_record["verifier"]["sha256"],
    } == first_hashes

    public_outputs = []
    for name in first_hashes:
        completed = subprocess.run(
            [str(scripts / name), "--native-public-contract"],
            cwd=synthetic_root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stderr == ""
        lines = completed.stdout.splitlines()
        assert lines[0] == "EGSI_NATIVE_ATTESTATION_VERSION=2"
        assert lines[1] == "EGSI_NATIVE_ALGORITHM=rsa-2048-sha256-pkcs1-v1_5"
        assert lines[2] == f"EGSI_NATIVE_PUBLIC_KEY_ID=sha256:{expected_key_id}"
        assert lines[3].startswith("EGSI_NATIVE_BUILD_ID=sha256:")
        assert lines[4].startswith("EGSI_NATIVE_BINARY_CONTRACT=sha256:")
        assert lines[5] == (
            "EGSI_BOOTSTRAP_PATH="
            + str(synthetic_root / "scripts/locked_runtime_bootstrap.py")
        )
        assert lines[6].startswith("EGSI_BOOTSTRAP_SHA256=sha256:")
        assert lines[7].startswith("EGSI_BOOTSTRAP_SIZE=")
        assert lines[8] in {
            "EGSI_BOOTSTRAP_MODE=0444", "EGSI_BOOTSTRAP_MODE=0644"
        }
        runtime = first_record["python_runtime"]
        interpreter = runtime["interpreter"]
        assert lines[9] == f"EGSI_PYTHON_PATH={interpreter['path']}"
        assert lines[10] == f"EGSI_PYTHON_SHA256={interpreter['sha256']}"
        assert lines[11] == f"EGSI_PYTHON_SIZE={interpreter['size']}"
        assert lines[12] == f"EGSI_PYTHON_MODE={interpreter['mode']:04o}"
        assert lines[13] == f"EGSI_PYTHON_DEVICE={interpreter['device']}"
        assert lines[14] == f"EGSI_PYTHON_INODE={interpreter['inode']}"
        assert lines[15] == (
            f"EGSI_PYTHON_RUNTIME_CLOSURE={runtime['closure_sha256']}"
        )
        assert lines[16] == (
            f"EGSI_PYTHON_RUNTIME_FILE_COUNT={len(runtime['files'])}"
        )
        startup = runtime["startup_code"]
        assert lines[17] == (
            "EGSI_PYTHON_STARTUP_CODE_CLOSURE="
            + startup["closure_sha256"]
        )
        assert lines[18] == (
            f"EGSI_PYTHON_STARTUP_CODE_FILE_COUNT={startup['file_count']}"
        )
        assert lines[19] == (
            "EGSI_PYTHON_STARTUP_CODE_DIRECTORY_COUNT="
            + str(startup["directory_count"])
        )
        assert lines[20] == (
            "EGSI_PYTHON_STARTUP_CODE_ABSENT_COUNT="
            + str(startup["absent_path_count"])
        )
        assert lines[21] == (
            "EGSI_PYTHON_STARTUP_CODE_TOTAL_BYTES="
            + str(startup["total_bytes"])
        )
        assert len(lines) == 22
        public_outputs.append(completed.stdout)
    assert len(set(public_outputs)) == 1

    third_key = _temporary_rsa_private_key(tmp_path, "replacement-build.pem")
    third = rebuild(third_key)
    assert third.returncode == 0, third.stderr
    third_record = json.loads(
        (synthetic_root / "configs/native-signer-build-record.json")
        .read_text(encoding="utf-8")
    )
    assert third_record["public_key"]["key_id"] != first_record["public_key"]["key_id"]
    assert third_record["signers"]["receipt"]["build_sha256"] != first_hashes["run_test_receipt"]
    assert third_record["signers"]["report"]["build_sha256"] != first_hashes["rerun_first_case_hard_gate"]
    assert third_record["verifier"]["sha256"] != first_hashes["verify_first_case_hard_gate"]

    missing_key = subprocess.run(
        [str(build), "--synthetic-output-dir", str(scripts)],
        cwd=synthetic_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing_key.returncode != 0
    assert not list(synthetic_root.rglob("*.pem"))
    assert not list(synthetic_root.rglob("*private*.h"))
    assert set(Path("/tmp").glob("egsi-native-build.*")) == before_private_dirs


def test_synthetic_native_build_includes_execute_only_live_attestor_pair(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-native-root"
    _copy_asymmetric_native_build_sources(root)
    key = _temporary_rsa_private_key(tmp_path, "live-attestor.pem")

    _run_asymmetric_native_build(root, key)

    execute = root / "scripts/run_fail_fast_enrich"
    verifier = root / "scripts/verify_fail_fast_enrich"
    assert stat.S_IMODE(execute.lstat().st_mode) == 0o111
    assert stat.S_IMODE(verifier.lstat().st_mode) == 0o555
    record = json.loads(
        (root / "configs/native-signer-build-record.json").read_text(
            encoding="utf-8"
        )
    )
    assert record["signers"]["live_enrichment"]["file"] == (
        "scripts/run_fail_fast_enrich"
    )
    assert record["live_verifier"]["file"] == (
        "scripts/verify_fail_fast_enrich"
    )
    assert record["mode_defines"]["live_enrichment_signer"] == (
        "-DLAUNCH_KIND=4"
    )
    assert record["mode_defines"]["live_enrichment_verifier"] == (
        "-DLAUNCH_KIND=5"
    )
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    assert record["bootstrap_anchor"] == {
        "path": "scripts/locked_runtime_bootstrap.py",
        "mode": stat.S_IMODE(bootstrap.lstat().st_mode),
        "size": bootstrap.lstat().st_size,
        "sha256": "sha256:" + hashlib.sha256(bootstrap.read_bytes()).hexdigest(),
    }
    public = subprocess.run(
        [str(verifier), "--native-public-contract"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert public.returncode == 0, public.stderr
    assert (
        f"EGSI_BOOTSTRAP_PATH={bootstrap}\n"
        f"EGSI_BOOTSTRAP_SHA256={record['bootstrap_anchor']['sha256']}\n"
        f"EGSI_BOOTSTRAP_SIZE={bootstrap.lstat().st_size}\n"
        f"EGSI_BOOTSTRAP_MODE={stat.S_IMODE(bootstrap.lstat().st_mode):04o}\n"
    ) in public.stdout


def test_native_build_contract_binds_pinned_python_runtime_closure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-python-runtime-contract"
    _copy_asymmetric_native_build_sources(root)
    key = _temporary_rsa_private_key(tmp_path, "python-runtime-contract.pem")

    _run_asymmetric_native_build(root, key)

    record = json.loads(
        (root / "configs/native-signer-build-record.json").read_text(
            encoding="utf-8"
        )
    )
    runtime = record["python_runtime"]
    assert runtime["schema_version"] == "3.0"
    assert runtime["invocation"] == "glibc-loader-fd-preload-v2"
    interpreter = runtime["interpreter"]
    expected_path = root / ".work/offline-test-runner-venv/bin/python"
    assert interpreter["path"] == str(expected_path)
    assert interpreter["identity"]["path"] == str(expected_path)
    assert interpreter["identity"]["type"] == "regular"
    assert interpreter["identity"]["links"] == 1
    assert interpreter["mode"] == stat.S_IMODE(expected_path.lstat().st_mode)
    assert interpreter["size"] == expected_path.lstat().st_size
    assert interpreter["device"] == expected_path.lstat().st_dev
    assert interpreter["inode"] == expected_path.lstat().st_ino
    assert interpreter["sha256"] == (
        "sha256:" + hashlib.sha256(expected_path.read_bytes()).hexdigest()
    )
    assert interpreter["elf"]["pt_interp"] == "/lib64/ld-linux-x86-64.so.2"
    assert "libpython" in "\n".join(interpreter["elf"]["dt_needed"])
    files = runtime["files"]
    assert files[0]["role"] == "loader"
    assert files[0]["path"] == interpreter["loader_path"]
    assert {item["role"] for item in files[1:]} <= {
        "dependency", "extension-root"
    }
    assert "extension-root" in {item["role"] for item in files[1:]}
    assert {item["needed_name"] for item in files[1:]} >= {
        "libpython3.12.so.1.0",
        "libm.so.6",
        "libc.so.6",
    }
    assert len({item["path"] for item in files}) == len(files)
    assert all(item["identity"]["links"] == 1 for item in files)
    assert all(item["mode"] & 0o022 == 0 for item in files)
    committed = dict(runtime)
    commitment = committed.pop("closure_sha256")
    assert commitment == (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                committed,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    public = subprocess.run(
        [str(root / "scripts/verify_fail_fast_enrich"), "--native-public-contract"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert public.returncode == 0, public.stderr
    assert f"EGSI_PYTHON_PATH={expected_path}\n" in public.stdout
    assert f"EGSI_PYTHON_SHA256={interpreter['sha256']}\n" in public.stdout
    assert f"EGSI_PYTHON_SIZE={interpreter['size']}\n" in public.stdout
    assert f"EGSI_PYTHON_MODE={interpreter['mode']:04o}\n" in public.stdout
    assert f"EGSI_PYTHON_DEVICE={interpreter['device']}\n" in public.stdout
    assert f"EGSI_PYTHON_INODE={interpreter['inode']}\n" in public.stdout
    assert f"EGSI_PYTHON_RUNTIME_CLOSURE={commitment}\n" in public.stdout
    assert f"EGSI_PYTHON_RUNTIME_FILE_COUNT={len(files)}\n" in public.stdout


def test_native_runtime_contract_binds_complete_startup_code_closure() -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_startup_code_contract",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    runtime = builder._python_runtime_contract(ROOT)
    startup = runtime["startup_code"]
    assert startup["schema_version"] == "2.0"
    assert startup["strategy"] == "source-tree-no-bytecode-native-closure-v2"
    assert startup["pycache_prefix"] == "/nonexistent/egsi-locked-pycache"
    assert startup["files"]
    assert startup["directories"]
    relative = {item["relative_path"] for item in startup["files"]}
    assert "stdlib:encodings/__init__.py" in relative
    assert "stdlib:subprocess.py" in relative
    assert any(
        item.startswith("lib-dynload:") and item.endswith(".so")
        for item in relative
    )
    assert startup["file_count"] == len(startup["files"])
    assert startup["directory_count"] == len(startup["directories"])
    assert startup["total_bytes"] == sum(
        item["identity"]["size"] for item in startup["files"]
    )
    assert runtime["closure_sha256"].startswith("sha256:")

    bootstrap_spec = importlib.util.spec_from_file_location(
        "egsi_test_compact_startup_code_contract",
        ROOT / "scripts/locked_runtime_bootstrap.py",
    )
    assert bootstrap_spec is not None and bootstrap_spec.loader is not None
    bootstrap = importlib.util.module_from_spec(bootstrap_spec)
    bootstrap_spec.loader.exec_module(bootstrap)
    summary = bootstrap._compact_python_runtime_contract(runtime)
    compact_startup = summary["startup_code"]
    assert "files" not in compact_startup
    assert "directories" not in compact_startup
    assert "absent_paths" not in compact_startup
    assert compact_startup["manifest_sha256"] == startup["closure_sha256"]
    assert compact_startup["file_count"] == startup["file_count"]
    assert compact_startup["directory_count"] == startup["directory_count"]
    assert compact_startup["absent_path_count"] == startup["absent_path_count"]
    assert compact_startup["total_bytes"] == startup["total_bytes"]
    assert compact_startup["stdlib_root"]["identity"]["type"] == "directory"
    assert compact_startup["lib_dynload_root"]["identity"]["type"] == "directory"
    assert compact_startup["import_roots"] == startup["import_roots"]
    assert summary["preload_file_indices"] == runtime["preload_file_indices"]
    assert summary["native_extension_roots"] == runtime["native_extension_roots"]

    tampered = json.loads(json.dumps(runtime))
    tampered["startup_code"]["files"][0]["identity"]["sha256"] = (
        "sha256:" + "0" * 64
    )
    with pytest.raises(ValueError, match="full Python runtime contract"):
        bootstrap._compact_python_runtime_contract(tampered)

    tampered_plan = json.loads(json.dumps(runtime))
    tampered_plan["preload_file_indices"].append(
        tampered_plan["preload_file_indices"][-1]
    )
    tampered_plan["closure_sha256"] = bootstrap._commitment(
        tampered_plan, "closure_sha256"
    )
    with pytest.raises(ValueError, match="full Python runtime contract"):
        bootstrap._compact_python_runtime_contract(tampered_plan)


def test_native_runtime_prefers_libpython_sibling_stdlib_for_private_closure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private-startup-root-selection"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython = _install_private_loader_and_libpython(
        root, tmp_path
    )
    private_stdlib = private_libpython.parent / "python3.12"
    (private_stdlib / "encodings").mkdir(parents=True)
    (private_stdlib / "encodings/__init__.py").write_text("", encoding="utf-8")
    (private_stdlib / "os.py").write_text("", encoding="utf-8")
    try:
        spec = importlib.util.spec_from_file_location(
            "egsi_test_private_startup_root",
            ROOT / "scripts/build_native_rsa_material.py",
        )
        assert spec is not None and spec.loader is not None
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        interpreter = root / ".work/offline-test-runner-venv/bin/python"

        selected, version = builder._target_stdlib_root(
            interpreter,
            interpreter.read_bytes(),
            [{
                "needed_name": private_libpython.name,
                "path": str(private_libpython),
            }],
        )

        assert version == "3.12"
        assert selected == private_stdlib
    finally:
        private_loader.unlink(missing_ok=True)
        try:
            private_loader.parent.rmdir()
        except OSError:
            pass
        shutil.rmtree(private_libpython.parent, ignore_errors=True)


def test_native_launchers_reject_shadow_stdlib_before_any_bootstrap_import(
    tmp_path: Path,
) -> None:
    root = tmp_path / "shadow-stdlib-before-bootstrap"
    _copy_asymmetric_native_build_sources(root)
    key = _temporary_rsa_private_key(tmp_path, "shadow-stdlib.pem")
    _run_asymmetric_native_build(root, key)

    source = Path(sysconfig.get_path("stdlib"))
    destination = root / ".work/offline-test-runner-venv/lib/python3.12"

    def ignored(_: str, names: list[str]) -> set[str]:
        return {
            name for name in names
            if name in {
                "site-packages", "__pycache__", "config-3.12-x86_64-linux-gnu",
                "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3",
                "test", "tests",
            }
        }

    shutil.copytree(source, destination, symlinks=False, ignore=ignored)
    malicious = destination / "subprocess.py"
    malicious.write_text(
        malicious.read_text(encoding="utf-8")
        + r'''

def _egsi_shadow_stdlib_forge():
    import os as _os, sys as _sys
    if "run-test-receipt" in _sys.argv:
        _flag = "--output"
    elif "rerun-first-case" in _sys.argv:
        _flag = "--report"
    elif "verify-first-case" in _sys.argv:
        _os._exit(0)
    else:
        return
    _path = _sys.argv[_sys.argv.index(_flag) + 1]
    _fd = _os.open(_path, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    _os.write(_fd, b'{"forged_by_shadow_stdlib":true}\n')
    _os.fsync(_fd)
    _os.close(_fd)
    _os._exit(0)
_egsi_shadow_stdlib_forge()
''',
        encoding="utf-8",
    )
    malicious.chmod(0o644)

    output = root / "out"
    reports = output / "reports"
    reports.mkdir(parents=True)
    focused = reports / "offline-focused-receipt.json"
    full = reports / "offline-full-receipt.json"
    report = reports / "first-case-hard-gate.json"
    commands = [
        [root / "scripts/run_test_receipt", "--name", "focused", "--output", focused],
        [root / "scripts/run_test_receipt", "--name", "full", "--output", full],
        [
            root / "scripts/rerun_first_case_hard_gate",
            "--output-root", output, "--case-id", "synthetic",
            "--focused-receipt", focused, "--full-receipt", full,
            "--report", report, "--rerun-tests",
        ],
        [
            root / "scripts/verify_first_case_hard_gate",
            "--output-root", output, "--case-id", "synthetic",
            "--focused-receipt", focused, "--full-receipt", full,
            "--report", report, "--mode", "verify-only",
        ],
    ]
    completed = [
        subprocess.run(
            [str(item) for item in command], cwd=root,
            env=_LOCKED_ENVIRONMENT, capture_output=True, text=True,
            check=False, timeout=30,
        )
        for command in commands
    ]

    assert all(item.returncode == 66 for item in completed)
    assert all("native Python startup code closure failed" in item.stderr for item in completed)
    for artifact in (focused, full, report):
        assert not artifact.exists()
        assert not Path(str(artifact) + ".native-attestation").exists()


def test_native_launchers_reject_malicious_encodings_before_bootstrap(
    tmp_path: Path,
) -> None:
    root = tmp_path / "malicious-private-encodings"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, private_stdlib = (
        _install_private_python_startup_tree(root, tmp_path)
    )
    marker = root / "malicious-encodings-imported"
    try:
        _write_native_live_stub_bootstrap(root, child_exit_code=0)
        key = _temporary_rsa_private_key(tmp_path, "malicious-encodings.pem")
        _run_asymmetric_native_build(root, key)
        record = json.loads(
            (root / "configs/native-signer-build-record.json").read_text(
                encoding="utf-8"
            )
        )
        assert record["python_runtime"]["startup_code"]["stdlib_root"] == str(
            private_stdlib
        )
        malicious = private_stdlib / "encodings/__init__.py"
        malicious.write_text(
            malicious.read_text(encoding="utf-8")
            + "\n__import__('_io').open("
            + repr(str(marker))
            + ", 'w').write('yes')\n",
            encoding="utf-8",
        )

        completed = [
            subprocess.run(
                [str(root / "scripts" / name), "--help"],
                cwd=root,
                env=dict(_LOCKED_ENVIRONMENT),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            for name in (
                "run_test_receipt",
                "rerun_first_case_hard_gate",
                "verify_first_case_hard_gate",
                "run_fail_fast_enrich",
                "verify_fail_fast_enrich",
            )
        ]

        assert all(item.returncode == 66 for item in completed)
        assert all(
            "native Python startup code closure failed" in item.stderr
            for item in completed
        )
        assert not marker.exists()
    finally:
        _remove_private_python_startup_tree(
            private_loader, private_libpython
        )


@pytest.mark.parametrize("attack", ["modified", "shadow"])
def test_native_launchers_reject_modified_or_shadowed_lib_dynload(
    tmp_path: Path, attack: str
) -> None:
    root = tmp_path / f"private-lib-dynload-{attack}"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, private_stdlib = (
        _install_private_python_startup_tree(root, tmp_path)
    )
    marker = root / "lib-dynload-bootstrap-started"
    try:
        _write_native_live_stub_bootstrap(root, child_exit_code=0)
        for mode in (
            "run-test-receipt",
            "rerun-first-case",
            "verify-first-case",
            "run-fail-fast-enrich",
            "verify-fail-fast-enrich",
        ):
            _inject_bootstrap_mode_marker(root, mode=mode, marker=marker)
        key = _temporary_rsa_private_key(
            tmp_path, f"private-lib-dynload-{attack}.pem"
        )
        _run_asymmetric_native_build(root, key)
        target = next(
            path for path in sorted((private_stdlib / "lib-dynload").iterdir())
            if path.is_file() and path.suffix == ".so"
        )
        if attack == "modified":
            descriptor = os.open(target, os.O_RDWR | os.O_CLOEXEC)
            try:
                original = os.pread(descriptor, 1, 128)
                assert len(original) == 1
                os.pwrite(descriptor, bytes([original[0] ^ 1]), 128)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        else:
            held = target.with_name("." + target.name + ".shadowed")
            target.rename(held)
            shutil.copy2(held, target)

        completed = [
            subprocess.run(
                [str(root / "scripts" / name), "--help"],
                cwd=root,
                env=dict(_LOCKED_ENVIRONMENT),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            for name in (
                "run_test_receipt",
                "rerun_first_case_hard_gate",
                "verify_first_case_hard_gate",
                "run_fail_fast_enrich",
                "verify_fail_fast_enrich",
            )
        ]

        assert all(item.returncode == 66 for item in completed)
        assert all(
            item.stderr == "native Python runtime closure failed\n"
            for item in completed
        )
        assert not marker.exists()
    finally:
        _remove_private_python_startup_tree(
            private_loader, private_libpython
        )


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "writable"])
def test_native_material_rejects_unsafe_python_interpreter(
    tmp_path: Path, unsafe_kind: str
) -> None:
    root = tmp_path / f"unsafe-python-{unsafe_kind}"
    _copy_asymmetric_native_build_sources(root)
    interpreter = root / ".work/offline-test-runner-venv/bin/python"
    if unsafe_kind == "symlink":
        interpreter.unlink()
        interpreter.symlink_to(Path(sys.executable).resolve(strict=True))
    elif unsafe_kind == "hardlink":
        sibling = interpreter.with_name("python-hardlink")
        os.link(interpreter, sibling)
    else:
        interpreter.chmod(0o777)
    key = _temporary_rsa_private_key(tmp_path, f"unsafe-{unsafe_kind}.pem")

    completed = _run_native_material(root, key)

    assert completed.returncode != 0
    assert not (root / ".native-material-test/public-material.json").exists()


def test_native_elf_parser_exposes_unique_dt_soname() -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_runtime_elf_soname",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    interpreter = ROOT / ".work/offline-test-runner-venv/bin/python"
    executable = builder._parse_elf64(
        interpreter.read_bytes(), require_interpreter=True
    )
    libpython_name = next(
        name for name in executable["dt_needed"] if name.startswith("libpython")
    )
    libpython = builder._resolve_needed(
        libpython_name, executable, interpreter.parent
    )

    parsed = builder._parse_elf64(
        libpython.read_bytes(), require_interpreter=False
    )

    assert parsed["dt_soname"] == libpython_name


@pytest.mark.parametrize(
    ("attack", "message"),
    [
        ("absent", "SONAME"),
        ("wrong", "SONAME"),
        ("ambiguous", "ambiguous"),
    ],
)
def test_native_runtime_resolver_rejects_noncanonical_soname_mapping(
    tmp_path: Path, attack: str, message: str
) -> None:
    spec = importlib.util.spec_from_file_location(
        f"egsi_test_runtime_soname_{attack}",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    source = tmp_path / "dependency.c"
    source.write_text("void egsi_dependency(void) {}\n", encoding="ascii")
    target_name = "libegsi_dependency.so"

    def compile_library(directory: Path, soname: str | None) -> None:
        command = [
            "/usr/bin/gcc", "-fPIC", "-shared", str(source),
        ]
        if soname is not None:
            command.append(f"-Wl,-soname,{soname}")
        command.extend(["-o", str(directory / target_name)])
        subprocess.run(command, check=True, capture_output=True, text=True)

    compile_library(
        first,
        None if attack == "absent" else (
            "libegsi_wrong.so" if attack == "wrong" else target_name
        ),
    )
    if attack == "ambiguous":
        compile_library(second, target_name)
    parent_elf = {
        "dt_runpath": (
            [str(first)] if attack != "ambiguous"
            else [str(first), str(second)]
        ),
        "dt_rpath": [],
    }

    with pytest.raises(ValueError, match=message):
        builder._resolve_needed(target_name, parent_elf, tmp_path)


def test_native_runtime_contract_includes_extension_dependency_closure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "extension-dependency-closure"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, private_stdlib = (
        _install_private_python_startup_tree(root, tmp_path)
    )
    try:
        dependency_dir = private_libpython.parent / "extension-dependencies"
        dependency_dir.mkdir()
        dependency_source = dependency_dir / "dependency.c"
        dependency_source.write_text(
            "void egsi_extension_dependency(void) {}\n", encoding="ascii"
        )
        dependency = dependency_dir / "libegsi_extension_dependency.so"
        subprocess.run(
            [
                "/usr/bin/gcc", "-fPIC", "-shared", str(dependency_source),
                "-Wl,-soname,libegsi_extension_dependency.so",
                "-o", str(dependency),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        extension_source = dependency_dir / "extension.c"
        extension_source.write_text(
            "void egsi_extension_dependency(void);\n"
            "void *PyInit__egsi_extension(void) {\n"
            "  egsi_extension_dependency(); return (void *)0;\n"
            "}\n",
            encoding="ascii",
        )

        def compile_extension(path: Path) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [
                    "/usr/bin/gcc", "-fPIC", "-shared", str(extension_source),
                    "-Wl,--no-as-needed", f"-L{dependency_dir}",
                    "-Wl,-l:libegsi_extension_dependency.so",
                    f"-Wl,-rpath,{dependency_dir}", "-o", str(path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        lib_dynload_extension = (
            private_stdlib / "lib-dynload/_egsi_extension.so"
        )
        site_extension = (
            root / ".work/offline-test-runner-venv/lib/python3.12/"
            "site-packages/egsi_native/_egsi_site.so"
        )
        compile_extension(lib_dynload_extension)
        compile_extension(site_extension)

        spec = importlib.util.spec_from_file_location(
            "egsi_test_extension_dependency_closure",
            ROOT / "scripts/build_native_rsa_material.py",
        )
        assert spec is not None and spec.loader is not None
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)

        runtime = builder._python_runtime_contract(root)

        paths = [item["path"] for item in runtime["files"]]
        assert str(lib_dynload_extension) in paths
        assert str(site_extension) in paths
        assert str(dependency) in paths
        assert paths.index(str(dependency)) < paths.index(str(lib_dynload_extension))
        assert paths.index(str(dependency)) < paths.index(str(site_extension))
        roots = runtime["native_extension_roots"]
        assert {item["path"] for item in roots} >= {
            str(lib_dynload_extension), str(site_extension),
        }
    finally:
        _remove_private_python_startup_tree(private_loader, private_libpython)


def test_native_runtime_contract_is_dependency_first_for_every_pinned_elf() -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_runtime_dependency_order",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    runtime = builder._python_runtime_contract(ROOT)
    files = runtime["files"]
    loader_name = files[0]["needed_name"]
    preload_indices = runtime["preload_file_indices"]
    assert preload_indices == sorted(set(preload_indices))
    assert set(preload_indices) >= {
        index
        for index, item in enumerate(files)
        if item["role"] == "dependency"
    }
    preloaded_sonames = {
        files[index]["elf"]["dt_soname"]: index
        for index in preload_indices
        if files[index]["elf"]["dt_soname"] is not None
    }
    assert len(preloaded_sonames) == sum(
        files[index]["elf"]["dt_soname"] is not None
        for index in preload_indices
    )

    # files[0] is the directly invoked glibc loader.  Every preloaded ELF must
    # appear after all of its DT_NEEDED objects in the executable preload plan.
    preload_positions = {
        file_index: position
        for position, file_index in enumerate(preload_indices)
    }
    for index in preload_indices:
        item = files[index]
        for needed_name in item["elf"]["dt_needed"]:
            if needed_name == loader_name:
                continue
            dependency_index = preloaded_sonames[needed_name]
            assert preload_positions[dependency_index] < preload_positions[index], (
                needed_name,
                dependency_index,
                item["path"],
                index,
            )

    # Same-content SONAME aliases remain separately held/pinned but are never
    # mapped or initialized more than once by glibc --preload.
    for index, item in enumerate(files[1:], start=1):
        if index in preload_positions:
            continue
        soname = item["elf"]["dt_soname"]
        representative = files[preloaded_sonames[soname]]
        assert representative["sha256"] == item["sha256"]


def test_native_runtime_preload_plan_rejects_conflicting_soname_aliases() -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_runtime_soname_conflict",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    files = [
        {
            "role": "loader",
            "needed_name": "ld-linux-x86-64.so.2",
            "sha256": "sha256:" + "0" * 64,
            "elf": {"dt_soname": "ld-linux-x86-64.so.2", "dt_needed": []},
        },
        {
            "role": "dependency",
            "needed_name": "libcollision.so.1",
            "sha256": "sha256:" + "1" * 64,
            "elf": {"dt_soname": "libcollision.so.1", "dt_needed": []},
        },
        {
            "role": "extension-root",
            "needed_name": "libcollision-alias.so",
            "sha256": "sha256:" + "2" * 64,
            "elf": {"dt_soname": "libcollision.so.1", "dt_needed": []},
        },
    ]

    with pytest.raises(ValueError, match="conflicting SONAME aliases"):
        builder._runtime_preload_indices(files)


def test_native_c_string_accepts_distribution_library_plus() -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_native_c_string_plus",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    assert builder._c_string("/usr/lib/libstdc++.so.6") == (
        '"/usr/lib/libstdc++.so.6"'
    )


@pytest.mark.parametrize(
    "mode", ["run-fail-fast-enrich", "verify-fail-fast-enrich"]
)
def test_locked_bootstrap_live_modes_handle_help_without_values(
    capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_locked_live_help_" + mode,
        ROOT / "scripts/locked_runtime_bootstrap.py",
    )
    assert spec is not None and spec.loader is not None
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    locked_base_sys_path = object()
    with patch.object(
        sys, "_egsi_locked_base_sys_path", locked_base_sys_path, create=True
    ):
        with patch.object(
            bootstrap,
            "validate_runtime",
            return_value=({}, "sha256:" + "0" * 64, {}),
        ):
            assert bootstrap._dispatch(mode, ROOT, ["--help"]) == 0
        assert sys._egsi_locked_base_sys_path is locked_base_sys_path
    assert capsys.readouterr().out.startswith("usage: ")


def test_native_launcher_preloads_identical_soname_alias_only_once(
    tmp_path: Path,
) -> None:
    pool = ROOT / ".work/.native-constructor-tests"
    pool.mkdir(mode=0o700, exist_ok=True)
    token = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:20]
    root = pool / token
    assert not root.exists() and not root.is_symlink()
    _copy_asymmetric_native_build_sources(root)
    marker = tmp_path / "duplicate-soname-constructor-events"
    marker.write_bytes(b"")
    try:
        source = tmp_path / "duplicate-soname.c"
        source.write_text(
            "#include <fcntl.h>\n"
            "#include <unistd.h>\n"
            "__attribute__((constructor)) static void mark(void) {\n"
            f"  int fd = open({json.dumps(str(marker))}, O_WRONLY | O_APPEND);\n"
            "  if (fd >= 0) { (void)write(fd, \"x\", 1); close(fd); }\n"
            "}\n",
            encoding="ascii",
        )
        site = (
            root / ".work/offline-test-runner-venv/lib/python3.12/"
            "site-packages/egsi_aliases"
        )
        site.mkdir(parents=True)
        first = site / "libegsi_alias_a.so"
        second = site / "libegsi_alias_b.so"
        subprocess.run(
            [
                "/usr/bin/gcc", "-fPIC", "-shared", str(source),
                "-Wl,-soname,libegsi_constructor_alias.so.1",
                "-o", str(first),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        shutil.copy2(first, second)
        assert first.read_bytes() == second.read_bytes()
        assert first.lstat().st_ino != second.lstat().st_ino
        key = _temporary_rsa_private_key(tmp_path, "soname-alias.pem")

        for _ in range(3):
            marker.write_bytes(b"")
            _run_asymmetric_native_build(root, key)
            completed = subprocess.run(
                [str(root / "scripts/run_test_receipt"), "--help"],
                cwd=root,
                env=dict(_LOCKED_ENVIRONMENT),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if (
                marker.read_bytes()
                or not any(
                    message in completed.stderr
                    for message in (
                        "Python import root ancestor mismatch",
                        "native Python startup code closure failed",
                    )
                )
            ):
                break

        assert completed.returncode in range(256), completed.stderr
        assert marker.read_bytes() == b"x", completed.stderr
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("source", ["lib-dynload", "site-packages"])
@pytest.mark.parametrize("attack", ["replacement", "same-inode", "aba"])
def test_native_launchers_reject_extension_dependency_tamper_and_restore(
    tmp_path: Path, source: str, attack: str
) -> None:
    root = tmp_path / f"native-{source}-{attack}"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, private_stdlib = (
        _install_private_python_startup_tree(root, tmp_path)
    )
    try:
        dependency_dir = private_libpython.parent / "extension-dependencies"
        dependency_dir.mkdir()
        dependency_source = dependency_dir / "dependency.c"
        dependency_source.write_text(
            "void egsi_extension_dependency(void) {}\n", encoding="ascii"
        )
        dependency = dependency_dir / "libegsi_extension_dependency.so"
        subprocess.run(
            [
                "/usr/bin/gcc", "-fPIC", "-shared", str(dependency_source),
                "-Wl,-soname,libegsi_extension_dependency.so",
                "-o", str(dependency),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        extension_source = dependency_dir / "extension.c"
        extension_source.write_text(
            "void egsi_extension_dependency(void);\n"
            "void *PyInit__egsi_extension(void) {\n"
            "  egsi_extension_dependency(); return (void *)0;\n"
            "}\n",
            encoding="ascii",
        )
        extension = (
            private_stdlib / "lib-dynload/_egsi_extension.so"
            if source == "lib-dynload"
            else root / ".work/offline-test-runner-venv/lib/python3.12/"
            "site-packages/egsi_native/_egsi_site.so"
        )
        extension.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "/usr/bin/gcc", "-fPIC", "-shared", str(extension_source),
                "-Wl,--no-as-needed", f"-L{dependency_dir}",
                "-Wl,-l:libegsi_extension_dependency.so",
                f"-Wl,-rpath,{dependency_dir}", "-o", str(extension),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        key = _temporary_rsa_private_key(
            tmp_path, f"native-{source}-{attack}.pem"
        )
        _run_asymmetric_native_build(root, key)
        record = json.loads(
            (root / "configs/native-signer-build-record.json").read_text(
                encoding="utf-8"
            )
        )
        assert str(dependency) in {
            item["path"] for item in record["python_runtime"]["files"]
        }

        if attack == "replacement":
            replacement = dependency.with_suffix(".replacement")
            shutil.copy2(dependency, replacement)
            replacement.chmod(0o755)
            os.replace(replacement, dependency)
        elif attack == "same-inode":
            descriptor = os.open(dependency, os.O_RDWR | os.O_CLOEXEC)
            try:
                original = os.pread(descriptor, 1, 128)
                assert len(original) == 1
                os.pwrite(descriptor, bytes([original[0] ^ 1]), 128)
                os.fsync(descriptor)
                os.pwrite(descriptor, original, 128)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        else:
            held = dependency.with_name(".dependency-held")
            dependency.rename(held)
            shutil.copy2(held, dependency)
            dependency.chmod(0o755)
            dependency.unlink()
            held.rename(dependency)

        completed = [
            subprocess.run(
                [str(root / "scripts" / name), "--native-public-contract"],
                cwd=root,
                env=dict(_LOCKED_ENVIRONMENT),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            for name in (
                "run_test_receipt",
                "rerun_first_case_hard_gate",
                "verify_first_case_hard_gate",
                "run_fail_fast_enrich",
                "verify_fail_fast_enrich",
            )
        ]

        assert all(item.returncode == 66 for item in completed)
        assert all(
            "native Python runtime closure failed" in item.stderr
            for item in completed
        )
    finally:
        _remove_private_python_startup_tree(private_loader, private_libpython)


def test_native_startup_contract_records_root_to_leaf_ancestor_chains() -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_startup_ancestor_contract",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    startup = builder._python_runtime_contract(ROOT)["startup_code"]

    roots = startup["import_roots"]
    assert roots["compiled_prefix"]["raw_path"].startswith("/")
    assert roots["stdlib_root"]["raw_path"] == startup["stdlib_root"]
    assert roots["lib_dynload_root"]["raw_path"] == startup["lib_dynload_root"]
    assert roots["site_packages_roots"]
    for root in (
        roots["compiled_prefix"],
        roots["stdlib_root"],
        roots["lib_dynload_root"],
        *roots["site_packages_roots"],
    ):
        chain = root["ancestor_chain"]
        assert chain[0]["path"] == "/"
        assert chain[-1]["path"] == root["raw_path"]
        assert all(item["identity"]["type"] == "directory" for item in chain)
        assert all(
            {
                "device", "inode", "mode", "uid", "gid",
                "mtime_ns", "ctime_ns",
            } <= item["identity"].keys()
            for item in chain
        )


def test_native_site_import_root_tolerates_precreated_output_subtree_churn(
    tmp_path: Path,
) -> None:
    root, _ = _synthetic_locked_project(tmp_path)
    transient = root / "output/transient-canonical-test-output"
    transient.mkdir()
    transient.rmdir()

    completed = [
        subprocess.run(
            [str(root / "scripts" / name), "--native-public-contract"],
            cwd=root,
            env=dict(_LOCKED_ENVIRONMENT),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        for name in (
            "run_test_receipt",
            "rerun_first_case_hard_gate",
            "verify_first_case_hard_gate",
            "run_fail_fast_enrich",
            "verify_fail_fast_enrich",
        )
    ]

    assert all(item.returncode == 0 for item in completed), [
        (item.returncode, item.stderr) for item in completed
    ]


def test_synthetic_locked_project_isolated_from_shared_pytest_ancestor_churn(
    tmp_path: Path,
) -> None:
    root, _ = _synthetic_locked_project(tmp_path)
    shared_pytest_ancestor = tmp_path.parent.parent
    transient = shared_pytest_ancestor / (
        f"unrelated-pytest-worker-churn-{os.getpid()}-{time.time_ns()}"
    )
    transient.mkdir()
    transient.rmdir()

    completed = subprocess.run(
        [
            str(root / "scripts/run_test_receipt"),
            "--native-public-contract",
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


def test_native_site_import_root_rejects_direct_source_root_metadata_churn(
    tmp_path: Path,
) -> None:
    root, _ = _synthetic_locked_project(tmp_path)
    transient = root / "transient-canonical-test-output"
    transient.mkdir()
    transient.rmdir()

    completed = subprocess.run(
        [
            str(root / "scripts/run_test_receipt"),
            "--native-public-contract",
        ],
        cwd=root,
        env=dict(_LOCKED_ENVIRONMENT),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 66
    assert "native Python startup code closure failed" in completed.stderr


def test_native_ancestor_chain_contract_rejects_any_symlink_component(
    tmp_path: Path,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_symlinked_import_root",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    real = tmp_path / "real"
    (real / "lib/python3.12").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink component"):
        builder._ancestor_chain_contract(alias / "lib/python3.12")


def test_native_material_rejects_raw_compiled_prefix_symlink_alias(
    tmp_path: Path,
) -> None:
    root = tmp_path / "compiled-prefix-alias"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, _ = _install_private_python_startup_tree(
        root, tmp_path
    )
    private_prefix = private_libpython.parent.parent
    alias = _exact_workspace_runtime_path(
        prefix="alias", length=len(str(private_prefix)),
        token=hashlib.sha256(str(tmp_path).encode()).hexdigest(),
    )
    try:
        assert not alias.exists() and not alias.is_symlink()
        alias.symlink_to(private_prefix, target_is_directory=True)
        raw = private_libpython.read_bytes()
        assert raw.count(str(private_prefix).encode()) >= 1
        private_libpython.write_bytes(
            raw.replace(str(private_prefix).encode(), str(alias).encode())
        )
        private_libpython.chmod(0o755)
        key = _temporary_rsa_private_key(tmp_path, "compiled-prefix-alias.pem")

        completed = _run_native_material(root, key)

        assert completed.returncode != 0
        assert "symlink component" in completed.stderr
        assert not (root / ".native-material-test/public-material.json").exists()
    finally:
        alias.unlink(missing_ok=True)
        _remove_private_python_startup_tree(private_loader, private_libpython)


@pytest.mark.parametrize(
    "attack", ["prefix-retarget", "prefix-aba", "ancestor-retarget", "ancestor-aba"]
)
def test_native_launchers_reject_compiled_prefix_ancestor_retarget_and_aba(
    tmp_path: Path, attack: str
) -> None:
    root = tmp_path / f"compiled-prefix-{attack}"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, _ = _install_private_python_startup_tree(
        root, tmp_path
    )
    old_prefix = private_libpython.parent.parent
    ancestor_pool = Path("/tmp/egsi-ancestor-test")
    ancestor_pool.mkdir(mode=0o700, exist_ok=True)
    remaining = len(str(old_prefix)) - len(str(ancestor_pool)) - 1
    assert remaining >= 7
    token = hashlib.sha256((str(tmp_path) + attack).encode()).hexdigest()
    outer_name = ("p" + token)[:5]
    inner_length = remaining - len(outer_name) - 1
    inner_name = ("q" + token[5:])[:inner_length]
    nested_prefix = ancestor_pool / outer_name / inner_name
    assert len(str(nested_prefix)) == len(str(old_prefix))
    outer = nested_prefix.parent
    interpreter = root / ".work/offline-test-runner-venv/bin/python"
    try:
        assert not outer.exists() and not outer.is_symlink()
        outer.mkdir()
        interpreter_raw = interpreter.read_bytes()
        assert interpreter_raw.count(str(old_prefix).encode()) >= 1
        interpreter.write_bytes(
            interpreter_raw.replace(
                str(old_prefix).encode(), str(nested_prefix).encode()
            )
        )
        interpreter.chmod(0o755)
        libpython_raw = private_libpython.read_bytes()
        assert libpython_raw.count(str(old_prefix).encode()) >= 1
        private_libpython.write_bytes(
            libpython_raw.replace(
                str(old_prefix).encode(), str(nested_prefix).encode()
            )
        )
        private_libpython.chmod(0o755)
        old_prefix.rename(nested_prefix)
        private_libpython = nested_prefix / "lib" / private_libpython.name

        key = _temporary_rsa_private_key(
            tmp_path, f"compiled-prefix-{attack}.pem"
        )
        _run_asymmetric_native_build(root, key)
        record = json.loads(
            (root / "configs/native-signer-build-record.json").read_text(
                encoding="utf-8"
            )
        )
        compiled = record["python_runtime"]["startup_code"]["import_roots"][
            "compiled_prefix"
        ]
        assert compiled["raw_path"] == str(nested_prefix)

        target = nested_prefix if attack.startswith("prefix-") else outer
        held = target.with_name("." + target.name + ".held")
        target.rename(held)
        target.symlink_to(held, target_is_directory=True)
        if attack.endswith("aba"):
            target.unlink()
            held.rename(target)

        completed = [
            subprocess.run(
                [str(root / "scripts" / name), "--native-public-contract"],
                cwd=root,
                env=dict(_LOCKED_ENVIRONMENT),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            for name in (
                "run_test_receipt",
                "rerun_first_case_hard_gate",
                "verify_first_case_hard_gate",
                "run_fail_fast_enrich",
                "verify_fail_fast_enrich",
            )
        ]

        assert all(item.returncode == 66 for item in completed)
        assert all("closure failed" in item.stderr for item in completed)
    finally:
        for candidate in (nested_prefix, outer):
            if candidate.is_symlink():
                held = candidate.with_name("." + candidate.name + ".held")
                candidate.unlink()
                if held.exists():
                    held.rename(candidate)
        shutil.rmtree(outer, ignore_errors=True)
        shutil.rmtree(old_prefix, ignore_errors=True)
        private_loader.unlink(missing_ok=True)
        try:
            private_loader.parent.rmdir()
        except OSError:
            pass


@pytest.mark.parametrize(
    "attack",
    [
        "malformed-elf",
        "missing-needed",
        "duplicate-needed",
        "origin-escape",
        "unsupported-token",
    ],
)
def test_native_material_rejects_malformed_or_unsafe_elf_contract(
    tmp_path: Path, attack: str
) -> None:
    root = tmp_path / f"unsafe-elf-{attack}"
    _copy_asymmetric_native_build_sources(root)
    interpreter = root / ".work/offline-test-runner-venv/bin/python"
    raw = interpreter.read_bytes()
    if attack == "malformed-elf":
        patched = b"not-an-elf\n"
    else:
        spec = importlib.util.spec_from_file_location(
            "egsi_test_unsafe_runtime_elf",
            ROOT / "scripts/build_native_rsa_material.py",
        )
        assert spec is not None and spec.loader is not None
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        elf = builder._parse_elf64(raw, require_interpreter=True)
        if attack in {"missing-needed", "duplicate-needed"}:
            before = b"libm.so.6"
            after = (
                b"zzzzzzzzz"
                if attack == "missing-needed"
                else b"libc.so.6"
            )
        else:
            runpaths = elf["dt_runpath"] or elf["dt_rpath"]
            assert len(runpaths) == 1
            before = runpaths[0].encode()
            prefix = (
                b"$ORIGIN/../../../../../../../../"
                if attack == "origin-escape"
                else b"$LIB/"
            )
            assert len(prefix) <= len(before)
            after = prefix + b"x" * (len(before) - len(prefix))
        assert len(before) == len(after)
        assert raw.count(before) == 1
        patched = raw.replace(before, after)
    interpreter.write_bytes(patched)
    interpreter.chmod(0o755)
    key = _temporary_rsa_private_key(tmp_path, f"unsafe-elf-{attack}.pem")

    completed = _run_native_material(root, key)

    assert completed.returncode != 0
    assert not (root / ".native-material-test/public-material.json").exists()


@pytest.mark.parametrize(
    ("constant", "value", "message"),
    [
        ("MAX_RUNTIME_FILES", 1, "file count"),
        ("MAX_RUNTIME_DEPTH", -1, "depth"),
        ("MAX_RUNTIME_FILE_BYTES", 1, "unsafe"),
        ("MAX_RUNTIME_TOTAL_BYTES", 1, "bytes"),
    ],
)
def test_native_runtime_resolver_enforces_closure_bounds(
    tmp_path: Path, constant: str, value: int, message: str
) -> None:
    root = tmp_path / f"runtime-bound-{constant.casefold()}"
    _copy_asymmetric_native_build_sources(root)
    spec = importlib.util.spec_from_file_location(
        f"egsi_test_runtime_bound_{constant.casefold()}",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    setattr(builder, constant, value)

    with pytest.raises(ValueError, match=message):
        builder._python_runtime_contract(root)


def test_native_runtime_resolver_rejects_dependency_cycle(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime-dependency-cycle"
    _copy_asymmetric_native_build_sources(root)
    interpreter = root / ".work/offline-test-runner-venv/bin/python"
    spec = importlib.util.spec_from_file_location(
        "egsi_test_runtime_dependency_cycle",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    original = builder._resolve_needed
    first_needed = builder._parse_elf64(
        interpreter.read_bytes(), require_interpreter=True
    )["dt_needed"][0]

    def cyclic(name: str, elf: dict[str, object], origin: Path) -> Path:
        if name == first_needed:
            return interpreter
        return original(name, elf, origin)

    with (
        patch.object(builder, "_resolve_needed", side_effect=cyclic),
        pytest.raises(ValueError, match="cycle"),
    ):
        builder._python_runtime_contract(root)


def test_native_runtime_resolver_rejects_real_a_b_a_cycle_before_cache_skip(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime-real-a-b-cycle"
    _copy_asymmetric_native_build_sources(root)
    interpreter = root / ".work/offline-test-runner-venv/bin/python"
    spec = importlib.util.spec_from_file_location(
        "egsi_test_runtime_real_a_b_cycle",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    a = tmp_path / "libA.so"
    b = tmp_path / "libB.so"
    loader = tmp_path / "ld-linux.so"
    loader.write_bytes(b"synthetic-loader")

    def fake_parse(raw: bytes, *, require_interpreter: bool):
        assert require_interpreter
        return {
            "elf_class": "ELF64",
            "elf_data": "little-endian",
            "elf_type": "ET_DYN",
            "machine": "EM_X86_64",
            "pt_interp": str(loader),
            "dt_needed": ["libA.so"],
            "dt_runpath": [],
            "dt_rpath": [],
        }

    def fake_runtime_file(path: Path, *, role: str, needed_name: str):
        resolved = {"libA.so": a, "libB.so": b}.get(needed_name, loader)
        item = {
            "role": role,
            "needed_name": needed_name,
            "path": str(resolved),
            "mode": 0o755,
            "size": 1,
            "device": 1,
            "inode": {str(loader): 1, str(a): 2, str(b): 3}[str(resolved)],
            "sha256": "sha256:" + "00" * 32,
            "identity": {
                "path": str(resolved), "type": "regular", "mode": 0o755,
                "device": 1,
                "inode": {str(loader): 1, str(a): 2, str(b): 3}[str(resolved)],
                "links": 1, "uid": 0, "gid": 0, "size": 1,
                "mtime_ns": 1, "ctime_ns": 1,
                "sha256": "sha256:" + "00" * 32,
            },
            "elf": {},
        }
        needed = {str(loader): [], str(a): ["libB.so"], str(b): ["libA.so"]}[
            str(resolved)
        ]
        elf = {
            "elf_class": "ELF64", "elf_data": "little-endian",
            "elf_type": "ET_DYN", "machine": "EM_X86_64",
            "pt_interp": None, "dt_needed": needed,
            "dt_runpath": [], "dt_rpath": [],
        }
        return item, elf

    def fake_resolve(name: str, elf: dict[str, object], origin: Path) -> Path:
        return {"libA.so": a, "libB.so": b}[name]

    with (
        patch.object(builder, "_parse_elf64", side_effect=fake_parse),
        patch.object(builder, "_runtime_file", side_effect=fake_runtime_file),
        patch.object(builder, "_resolve_needed", side_effect=fake_resolve),
        pytest.raises(ValueError, match="cycle"),
    ):
        builder._python_runtime_contract(root)

    assert interpreter.is_file()


@pytest.mark.parametrize(
    "unsafe_kind", ["symlink", "hardlink", "writable", "special"]
)
def test_native_material_rejects_unsafe_recursive_dependency(
    tmp_path: Path, unsafe_kind: str
) -> None:
    root = tmp_path / f"unsafe-runtime-dependency-{unsafe_kind}"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython = _install_private_loader_and_libpython(
        root, tmp_path
    )
    try:
        if unsafe_kind == "symlink":
            original = tmp_path / "libpython-original"
            shutil.copy2(private_libpython, original)
            private_libpython.unlink()
            private_libpython.symlink_to(original)
        elif unsafe_kind == "hardlink":
            os.link(private_libpython, private_libpython.with_name("hardlink"))
        elif unsafe_kind == "writable":
            private_libpython.chmod(0o777)
        else:
            private_libpython.unlink()
            os.mkfifo(private_libpython)
        key = _temporary_rsa_private_key(
            tmp_path, f"unsafe-runtime-dependency-{unsafe_kind}.pem"
        )

        completed = _run_native_material(root, key)

        assert completed.returncode != 0
        assert not (root / ".native-material-test/public-material.json").exists()
    finally:
        private_loader.unlink(missing_ok=True)
        try:
            private_loader.parent.rmdir()
        except OSError:
            pass
        shutil.rmtree(private_libpython.parent, ignore_errors=True)


@pytest.mark.parametrize("launch_kind", [4, 5])
def test_native_live_launchers_reject_prestart_python_forgery(
    tmp_path: Path, launch_kind: int
) -> None:
    root = tmp_path / f"prestart-python-forgery-kind{launch_kind}"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    key = _temporary_rsa_private_key(tmp_path, f"prestart-kind{launch_kind}.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]
    if launch_kind == 5:
        generated = subprocess.run(
            [
                str(root / "scripts/run_fail_fast_enrich"),
                *common,
                "--provider-config", str(provider),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert generated.returncode == 0, generated.stderr
    _replace_python_with_live_forgery(root)

    completed = subprocess.run(
        [
            str(
                root
                / "scripts"
                / (
                    "run_fail_fast_enrich"
                    if launch_kind == 4
                    else "verify_fail_fast_enrich"
                )
            ),
            *common,
            *(
                ["--provider-config", str(provider)]
                if launch_kind == 4
                else ["--mode", "verify-only"]
            ),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    if launch_kind == 4:
        assert not Path(str(attestation) + ".native-attestation").exists()
        assert not Path(str(attestation) + ".native-candidate").exists()
        assert not attestation.exists()
    else:
        assert json.loads(attestation.read_text(encoding="ascii"))["run_id"]


def _inject_python_runtime_mutation(
    root: Path, *, launch_kind: int, attack: str
) -> None:
    assert launch_kind in {4, 5}
    assert attack in {
        "interpreter-inplace",
        "interpreter-aba",
        "bin-parent-aba",
        "runner-ancestor-aba",
    }
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    marker = root / "runtime-mutation-fired"
    if attack == "interpreter-inplace":
        body = f"""        python = root / '.work/offline-test-runner-venv/bin/python'
        descriptor = os.open(python, os.O_RDWR | os.O_CLOEXEC)
        try:
            original = os.pread(descriptor, 1, 128)
            if len(original) != 1:
                raise SystemExit(91)
            os.pwrite(descriptor, bytes([original[0] ^ 1]), 128)
            os.fsync(descriptor)
            os.pwrite(descriptor, original, 128)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        Path({str(marker)!r}).write_text('yes', encoding='ascii')
"""
    elif attack == "interpreter-aba":
        body = f"""        import shutil
        python = root / '.work/offline-test-runner-venv/bin/python'
        held = python.with_name('.python-runtime-held')
        os.rename(python, held)
        shutil.copy2(held, python)
        python.chmod(0o755)
        python.unlink()
        os.rename(held, python)
        Path({str(marker)!r}).write_text('yes', encoding='ascii')
"""
    else:
        relative = (
            ".work/offline-test-runner-venv/bin"
            if attack == "bin-parent-aba"
            else ".work/offline-test-runner-venv"
        )
        body = f"""        import shutil
        target = root / {relative!r}
        held = target.with_name('.' + target.name + '.runtime-held')
        os.rename(target, held)
        target.mkdir(mode=0o755)
        shutil.rmtree(target)
        os.rename(held, target)
        Path({str(marker)!r}).write_text('yes', encoding='ascii')
"""
    if launch_kind == 4:
        needle = "elif mode == 'run-fail-fast-enrich':\n"
        kind4_body = "".join(
            line[4:] if line.startswith("    ") else line
            for line in body.splitlines(keepends=True)
        )
        replacement = needle + kind4_body
    else:
        needle = "elif mode == 'verify-fail-fast-enrich':\n"
        replacement = (
            needle
            + "    if '--native-candidate-envelope' not in args:\n"
            + body
        )
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")


@pytest.mark.parametrize("launch_kind", [4, 5])
@pytest.mark.parametrize(
    "attack",
    [
        "interpreter-inplace",
        "interpreter-aba",
        "bin-parent-aba",
        "runner-ancestor-aba",
    ],
)
def test_native_live_launchers_reject_python_runtime_mutate_restore(
    tmp_path: Path, launch_kind: int, attack: str
) -> None:
    root = tmp_path / f"runtime-{attack}-kind{launch_kind}"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    _inject_python_runtime_mutation(
        root, launch_kind=launch_kind, attack=attack
    )
    key = _temporary_rsa_private_key(
        tmp_path, f"runtime-{attack}-kind{launch_kind}.pem"
    )
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]
    if launch_kind == 5:
        generated = subprocess.run(
            [
                str(root / "scripts/run_fail_fast_enrich"),
                *common,
                "--provider-config", str(provider),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert generated.returncode == 0, generated.stderr

    completed = subprocess.run(
        [
            str(
                root
                / "scripts"
                / (
                    "run_fail_fast_enrich"
                    if launch_kind == 4
                    else "verify_fail_fast_enrich"
                )
            ),
            *common,
            *(
                ["--provider-config", str(provider)]
                if launch_kind == 4
                else ["--mode", "verify-only"]
            ),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert (root / "runtime-mutation-fired").read_text(encoding="ascii") == "yes"
    assert completed.returncode != 0
    if launch_kind == 4:
        assert not attestation.exists()
        assert not Path(str(attestation) + ".native-attestation").exists()
        assert not Path(str(attestation) + ".native-candidate").exists()
        assert not Path(str(attestation) + ".native-snapshot").exists()
    else:
        assert attestation.is_file()
        assert Path(str(attestation) + ".native-attestation").is_file()


def _exact_workspace_runtime_path(
    *, prefix: str, length: int, token: str
) -> Path:
    pool = Path("/tmp/egsi-native-test")
    pool.mkdir(mode=0o700, exist_ok=True)
    base = str(pool) + "/"
    remaining = length - len(base)
    assert remaining >= len(prefix)
    name = (prefix + token)[:remaining]
    name += "x" * (remaining - len(name))
    path = pool / name
    assert len(str(path)) == length
    return path


def _install_private_loader_and_libpython(
    root: Path, tmp_path: Path
) -> tuple[Path, Path]:
    spec = importlib.util.spec_from_file_location(
        "egsi_test_private_runtime_elf",
        ROOT / "scripts/build_native_rsa_material.py",
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    interpreter = root / ".work/offline-test-runner-venv/bin/python"
    raw = interpreter.read_bytes()
    elf = builder._parse_elf64(raw, require_interpreter=True)
    loader_source = Path(elf["pt_interp"]).resolve(strict=True)
    runpaths = elf["dt_runpath"] or elf["dt_rpath"]
    assert len(runpaths) == 1
    source_library_dir = Path(runpaths[0]).resolve(strict=True)
    libpython_name = next(
        item for item in elf["dt_needed"] if item.startswith("libpython")
    )
    libpython_source = (source_library_dir / libpython_name).resolve(strict=True)
    token = hashlib.sha256(str(tmp_path).encode()).hexdigest()
    private_loader_parent = None
    for character in token:
        candidate = Path("/tmp") / character
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        private_loader_parent = candidate
        break
    assert private_loader_parent is not None
    private_loader = private_loader_parent / loader_source.name
    assert len(str(private_loader)) == len(elf["pt_interp"])
    source_prefix = source_library_dir.parent
    private_prefix = _exact_workspace_runtime_path(
        prefix="d", length=len(str(source_prefix)), token=token[8:]
    )
    private_library_dir = private_prefix / "lib"
    assert len(str(private_library_dir)) == len(runpaths[0])
    assert not private_loader.exists() and not private_loader.is_symlink()
    assert not private_library_dir.exists() and not private_library_dir.is_symlink()
    private_library_dir.mkdir(parents=True, mode=0o700)
    shutil.copy2(loader_source, private_loader)
    private_loader.chmod(0o755)
    private_libpython = private_library_dir / libpython_name
    shutil.copy2(libpython_source, private_libpython)
    libpython_raw = private_libpython.read_bytes()
    assert str(source_prefix).encode() in libpython_raw
    assert len(str(source_prefix)) == len(str(private_prefix))
    private_libpython.write_bytes(
        libpython_raw.replace(
            str(source_prefix).encode(), str(private_prefix).encode()
        )
    )
    private_libpython.chmod(0o755)
    replacements = (
        (elf["pt_interp"].encode(), str(private_loader).encode()),
        (runpaths[0].encode(), str(private_library_dir).encode()),
    )
    patched = raw
    for before, after in replacements:
        assert len(before) == len(after)
        assert patched.count(before) == 1
        patched = patched.replace(before, after)
    interpreter.write_bytes(patched)
    interpreter.chmod(0o755)
    return private_loader, private_libpython


def _install_private_python_startup_tree(
    root: Path, tmp_path: Path
) -> tuple[Path, Path, Path]:
    private_loader, private_libpython = _install_private_loader_and_libpython(
        root, tmp_path
    )
    source = Path(sysconfig.get_path("stdlib"))
    destination = private_libpython.parent / "python3.12"

    def ignored(_: str, names: list[str]) -> set[str]:
        return {
            name for name in names
            if name in {
                "site-packages", "__pycache__",
                "config-3.12-x86_64-linux-gnu", "idlelib", "tkinter",
                "turtledemo", "ensurepip", "lib2to3", "test", "tests",
            }
        }

    shutil.copytree(source, destination, symlinks=False, ignore=ignored)
    return private_loader, private_libpython, destination


def _remove_private_python_startup_tree(
    private_loader: Path, private_libpython: Path
) -> None:
    private_loader.unlink(missing_ok=True)
    try:
        private_loader.parent.rmdir()
    except OSError:
        pass
    shutil.rmtree(private_libpython.parent.parent, ignore_errors=True)


def _inject_startup_code_attack(
    root: Path,
    *,
    mode: str,
    attack: str,
    target: Path,
    only_public_live_verify: bool = False,
) -> Path:
    assert attack in {"same-inode", "file-aba", "directory-aba"}
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    marker = root / f"startup-{attack}-fired"
    if attack == "same-inode":
        action = f"""descriptor = os.open(Path({str(target)!r}), os.O_RDWR | os.O_CLOEXEC)
try:
    original = os.pread(descriptor, 1, 128)
    if len(original) != 1:
        raise SystemExit(91)
    os.pwrite(descriptor, bytes([original[0] ^ 1]), 128)
    os.fsync(descriptor)
    os.pwrite(descriptor, original, 128)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
"""
    elif attack == "file-aba":
        action = f"""import shutil
target = Path({str(target)!r})
held = target.with_name('.' + target.name + '.startup-held')
os.rename(target, held)
shutil.copy2(held, target)
target.chmod(held.stat().st_mode & 0o7777)
target.unlink()
os.rename(held, target)
"""
    else:
        action = f"""target = Path({str(target)!r})
held = target.with_name('.' + target.name + '.startup-held')
os.rename(target, held)
target.mkdir(mode=held.stat().st_mode & 0o7777)
target.rmdir()
os.rename(held, target)
"""
    action += f"Path({str(marker)!r}).write_text('yes', encoding='ascii')\n"
    body = "".join("    " + line for line in action.splitlines(keepends=True))
    if only_public_live_verify:
        guarded = (
            "    if '--native-candidate-envelope' not in args:\n"
            + "".join(
                "    " + line for line in body.splitlines(keepends=True)
            )
        )
        body = guarded
    branch = "if" if mode == "run-test-receipt" else "elif"
    needle = f"{branch} mode == {mode!r}:\n"
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, needle + body), encoding="utf-8")
    return marker


def _inject_bootstrap_mode_marker(
    root: Path, *, mode: str, marker: Path
) -> None:
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    branch = "if" if mode == "run-test-receipt" else "elif"
    needle = f"{branch} mode == {mode!r}:\n"
    body = f"    Path({str(marker)!r}).write_text('yes', encoding='ascii')\n"
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, needle + body), encoding="utf-8")


@pytest.mark.parametrize(
    ("launcher_role", "attack", "target_kind"),
    [
        ("receipt", "same-inode", "stdlib-file"),
        ("report", "file-aba", "stdlib-file"),
        ("public", "directory-aba", "stdlib-directory"),
        ("kind4", "file-aba", "lib-dynload"),
        ("kind5", "file-aba", "lib-dynload"),
    ],
)
def test_native_launchers_reject_startup_code_mutate_restore_and_aba(
    tmp_path: Path,
    launcher_role: str,
    attack: str,
    target_kind: str,
) -> None:
    root = tmp_path / f"startup-{launcher_role}-{attack}"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, private_stdlib = (
        _install_private_python_startup_tree(root, tmp_path)
    )
    provider_marker = root / "provider-child-started"
    try:
        _write_native_live_stub_bootstrap(root, child_exit_code=0)
        if launcher_role == "kind4":
            _inject_bootstrap_mode_marker(
                root,
                mode="run-fail-fast-enrich",
                marker=provider_marker,
            )
        if target_kind == "stdlib-file":
            target = private_stdlib / (
                "calendar.py" if attack == "same-inode" else "statistics.py"
            )
        elif target_kind == "stdlib-directory":
            target = private_stdlib / "email"
        else:
            target = next(
                path
                for path in sorted((private_stdlib / "lib-dynload").iterdir())
                if path.is_file() and path.suffix == ".so"
            )
        mode = {
            "receipt": "run-test-receipt",
            "report": "rerun-first-case",
            "public": "verify-first-case",
            "kind4": "preflight-fail-fast-enrich",
            "kind5": "verify-fail-fast-enrich",
        }[launcher_role]
        marker = _inject_startup_code_attack(
            root,
            mode=mode,
            attack=attack,
            target=target,
            only_public_live_verify=launcher_role == "kind5",
        )
        key = _temporary_rsa_private_key(
            tmp_path, f"startup-{launcher_role}-{attack}.pem"
        )
        _run_asymmetric_native_build(root, key)
        record = json.loads(
            (root / "configs/native-signer-build-record.json").read_text(
                encoding="utf-8"
            )
        )
        startup = record["python_runtime"]["startup_code"]
        if target.is_file():
            assert str(target) in {
                item["path"] for item in startup["files"]
            }
        else:
            assert str(target) in {
                item["path"] for item in startup["directories"]
            }

        output = root / "output"
        reports = output / "reports"
        focused = reports / "offline-focused-receipt.json"
        full = reports / "offline-full-receipt.json"
        report = reports / "first-case-hard-gate.json"
        gate_common = [
            "--output-root", str(output),
            "--case-id", "synthetic-case",
            "--focused-receipt", str(focused),
            "--full-receipt", str(full),
            "--report", str(report),
        ]
        live_artifact_paths: tuple[Path, ...] = ()
        if launcher_role == "receipt":
            command = [
                root / "scripts/run_test_receipt",
                "--name", "focused", "--output", focused,
            ]
        else:
            _sign_stub_receipts(root, output)
            if launcher_role == "report":
                command = [
                    root / "scripts/rerun_first_case_hard_gate",
                    *gate_common,
                    "--rerun-tests",
                ]
            elif launcher_role == "public":
                signed_report = subprocess.run(
                    [
                        str(root / "scripts/rerun_first_case_hard_gate"),
                        *gate_common,
                        "--rerun-tests",
                    ],
                    cwd=root,
                    env=dict(_LOCKED_ENVIRONMENT),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                assert signed_report.returncode == 0, signed_report.stderr
                command = [
                    root / "scripts/verify_first_case_hard_gate",
                    *gate_common,
                    "--mode", "verify-only",
                ]
            else:
                case_file = root / "configs/recover_3wfj_cases.txt"
                scope_file = root / "configs/p0_cases.txt"
                provider = root / "configs/providers.local.toml"
                case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
                scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
                provider.write_text("[teacher]\n", encoding="utf-8")
                attestation = (
                    reports
                    / "remaining-p0/fail-fast-live-attestation.json"
                )
                live_common = [
                    "--output-root", str(output),
                    "--case-file", str(case_file),
                    "--scope-case-file", str(scope_file),
                    "--attestation", str(attestation),
                ]
                if launcher_role == "kind4":
                    command = [
                        root / "scripts/run_fail_fast_enrich",
                        *live_common,
                        "--provider-config", str(provider),
                    ]
                else:
                    generated = subprocess.run(
                        [
                            str(root / "scripts/run_fail_fast_enrich"),
                            *live_common,
                            "--provider-config", str(provider),
                        ],
                        cwd=root,
                        env=dict(_LOCKED_ENVIRONMENT),
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                    )
                    assert generated.returncode == 0, generated.stderr
                    live_artifact_paths = (
                        attestation,
                        Path(str(attestation) + ".native-attestation"),
                        Path(str(attestation) + ".native-snapshot"),
                    )
                    command = [
                        root / "scripts/verify_fail_fast_enrich",
                        *live_common,
                        "--mode", "verify-only",
                    ]

        preserved = {
            path: (
                path.read_bytes(),
                tuple(
                    getattr(path.stat(), field)
                    for field in (
                        "st_dev", "st_ino", "st_mode", "st_nlink",
                        "st_uid", "st_gid", "st_size", "st_mtime_ns",
                        "st_ctime_ns",
                    )
                ),
            )
            for path in live_artifact_paths
        }
        completed = subprocess.run(
            [str(item) for item in command],
            cwd=root,
            env=dict(_LOCKED_ENVIRONMENT),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        assert marker.read_text(encoding="ascii") == "yes"
        assert completed.returncode != 0
        if launcher_role == "receipt":
            assert not focused.exists()
            assert not Path(str(focused) + ".native-attestation").exists()
        elif launcher_role == "report":
            assert not report.exists()
            assert not Path(str(report) + ".native-attestation").exists()
        elif launcher_role == "kind4":
            assert not provider_marker.exists()
            assert not attestation.exists()
            assert not Path(str(attestation) + ".native-attestation").exists()
            assert not Path(str(attestation) + ".native-candidate").exists()
            assert not Path(str(attestation) + ".native-snapshot").exists()
        elif launcher_role == "kind5":
            assert {
                path: (
                    path.read_bytes(),
                    tuple(
                        getattr(path.stat(), field)
                        for field in (
                            "st_dev", "st_ino", "st_mode", "st_nlink",
                            "st_uid", "st_gid", "st_size", "st_mtime_ns",
                            "st_ctime_ns",
                        )
                    ),
                )
                for path in live_artifact_paths
            } == preserved
    finally:
        _remove_private_python_startup_tree(
            private_loader, private_libpython
        )


def _inject_runtime_file_aba(
    root: Path, *, launch_kind: int, target: Path
) -> None:
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    marker = root / "runtime-file-aba-fired"
    body = f"""        import shutil
        target = Path({str(target)!r})
        held = target.with_name('.' + target.name + '.held')
        os.rename(target, held)
        shutil.copy2(held, target)
        target.chmod(0o755)
        target.unlink()
        os.rename(held, target)
        Path({str(marker)!r}).write_text('yes', encoding='ascii')
"""
    if launch_kind == 4:
        needle = "elif mode == 'run-fail-fast-enrich':\n"
        body = "".join(
            line[4:] if line.startswith("    ") else line
            for line in body.splitlines(keepends=True)
        )
        replacement = needle + body
    else:
        needle = "elif mode == 'verify-fail-fast-enrich':\n"
        replacement = (
            needle
            + "    if '--native-candidate-envelope' not in args:\n"
            + body
        )
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")


@pytest.mark.parametrize("launch_kind", [4, 5])
@pytest.mark.parametrize("runtime_file", ["loader", "libpython"])
def test_native_live_launchers_reject_loader_and_libpython_aba(
    tmp_path: Path, launch_kind: int, runtime_file: str
) -> None:
    root = tmp_path / f"private-{runtime_file}-kind{launch_kind}"
    _copy_asymmetric_native_build_sources(root)
    private_loader, private_libpython, private_stdlib = (
        _install_private_python_startup_tree(root, tmp_path)
    )
    try:
        _write_native_live_stub_bootstrap(root, child_exit_code=0)
        target = private_loader if runtime_file == "loader" else private_libpython
        _inject_runtime_file_aba(root, launch_kind=launch_kind, target=target)
        key = _temporary_rsa_private_key(
            tmp_path, f"private-{runtime_file}-kind{launch_kind}.pem"
        )
        _run_asymmetric_native_build(root, key)
        record = json.loads(
            (root / "configs/native-signer-build-record.json").read_text(
                encoding="utf-8"
            )
        )
        runtime_paths = {
            Path(item["path"]) for item in record["python_runtime"]["files"]
        }
        assert private_loader in runtime_paths
        assert private_libpython in runtime_paths
        assert record["python_runtime"]["startup_code"]["stdlib_root"] == str(
            private_stdlib
        )
        output = root / "output"
        _sign_stub_receipts(root, output)
        case_file = root / "configs/recover_3wfj_cases.txt"
        scope_file = root / "configs/p0_cases.txt"
        provider = root / "configs/providers.local.toml"
        case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
        scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
        provider.write_text("[teacher]\n", encoding="utf-8")
        attestation = (
            output / "reports/remaining-p0/fail-fast-live-attestation.json"
        )
        common = [
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
        ]
        if launch_kind == 5:
            generated = subprocess.run(
                [
                    str(root / "scripts/run_fail_fast_enrich"),
                    *common,
                    "--provider-config", str(provider),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            assert generated.returncode == 0, generated.stderr
        completed = subprocess.run(
            [
                str(
                    root
                    / "scripts"
                    / (
                        "run_fail_fast_enrich"
                        if launch_kind == 4
                        else "verify_fail_fast_enrich"
                    )
                ),
                *common,
                *(
                    ["--provider-config", str(provider)]
                    if launch_kind == 4
                    else ["--mode", "verify-only"]
                ),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert (root / "runtime-file-aba-fired").read_text(
            encoding="ascii"
        ) == "yes"
        assert completed.returncode != 0
        if launch_kind == 4:
            assert not attestation.exists()
            assert not Path(str(attestation) + ".native-attestation").exists()
            assert not Path(str(attestation) + ".native-candidate").exists()
    finally:
        _remove_private_python_startup_tree(
            private_loader, private_libpython
        )


def test_native_live_attestor_rejects_bootstrap_replacement_before_any_child(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-bootstrap-replacement"
    _copy_asymmetric_native_build_sources(root)
    key = _temporary_rsa_private_key(tmp_path, "live-bootstrap-replacement.pem")
    _run_asymmetric_native_build(root, key)

    marker = root / "mutable-bootstrap-started"
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    bootstrap.write_text(
        """from pathlib import Path
import json, sys
root = Path(__file__).resolve().parents[1]
(root / 'mutable-bootstrap-started').write_text('yes', encoding='utf-8')
mode = sys.argv[1]
args = sys.argv[sys.argv.index('--') + 1:]
values = dict(zip(args[::2], args[1::2], strict=True))
path = Path(values['--attestation'])
if mode == 'run-fail-fast-enrich':
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'run_id': values['--native-run-id'], 'nonce': values['--native-nonce']}), encoding='utf-8')
    path.chmod(0o600)
elif mode != 'verify-fail-fast-enrich':
    raise SystemExit(64)
""",
        encoding="utf-8",
    )
    output = root / "output"
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"

    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert not marker.exists()
    assert not Path(str(attestation) + ".native-attestation").exists()


def test_native_live_attestor_rejects_marker_only_candidate_after_valid_preflight(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-marker-only"
    _copy_asymmetric_native_build_sources(root)
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    bootstrap.write_text(
        """from pathlib import Path
import hashlib, sys

def values():
    args = sys.argv[sys.argv.index('--') + 1:]
    return dict(zip(args[::2], args[1::2], strict=True))

mode = sys.argv[1]
args = values()
root = Path(__file__).resolve().parents[1]
if mode == 'run-test-receipt':
    path = Path(args['--output'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('receipt=' + args['--name'] + '\\n', encoding='utf-8')
    path.chmod(0o600)
elif mode == 'preflight-fail-fast-enrich':
    fields = [
        ('run_id', args['--native-run-id']),
        ('nonce', args['--native-nonce']),
        ('realtime_start_ns', args['--native-realtime-start-ns']),
        ('monotonic_start_ns', args['--native-monotonic-start-ns']),
        ('pre_inventory_sha256', 'sha256:' + '1' * 64),
        ('bootstrap_sha256', args['--native-bootstrap-sha256']),
        ('focused_receipt_sha256', args['--native-focused-receipt-sha256']),
        ('focused_sidecar_sha256', args['--native-focused-sidecar-sha256']),
        ('full_receipt_sha256', args['--native-full-receipt-sha256']),
        ('full_sidecar_sha256', args['--native-full-sidecar-sha256']),
        ('runner_lock_sha256', 'sha256:' + '2' * 64),
        ('project_identity_sha256', 'sha256:' + '3' * 64),
        ('canonical_test_contract_sha256', 'sha256:' + '4' * 64),
        ('native_launcher_contract_sha256', 'sha256:' + '5' * 64),
        ('native_binary_contract_sha256', args['--native-binary-contract-sha256']),
        ('public_key_id', args['--native-public-key-id']),
    ]
    raw = 'EGSI-LIVE-PREFLIGHT-V1\\n' + ''.join(
        name + '=' + value + '\\n' for name, value in fields
    )
    path = Path(args['--native-preflight-envelope'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw, encoding='ascii')
    path.chmod(0o600)
elif mode == 'run-fail-fast-enrich':
    (root / 'provider-child-started').write_text('yes', encoding='utf-8')
    path = Path(args['--attestation'])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"marker_only":true}\\n', encoding='ascii')
    path.chmod(0o600)
elif mode == 'verify-fail-fast-enrich':
    pass
else:
    raise SystemExit(64)
""",
        encoding="utf-8",
    )
    key = _temporary_rsa_private_key(tmp_path, "live-marker-only.pem")
    _run_asymmetric_native_build(root, key)

    output = root / "output"
    focused = output / "reports/offline-focused-receipt.json"
    full = output / "reports/offline-full-receipt.json"
    for name, receipt in (("focused", focused), ("full", full)):
        signed = subprocess.run(
            [
                str(root / "scripts/run_test_receipt"),
                "--name", name,
                "--output", str(receipt),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert signed.returncode == 0, signed.stderr

    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert (root / "provider-child-started").is_file()
    assert not Path(str(attestation) + ".native-attestation").exists()


@pytest.mark.parametrize("attack", ["missing", "sidecar-replay"])
def test_native_live_attestor_rejects_invalid_receipt_anchor_before_provider(
    tmp_path: Path, attack: str
) -> None:
    root = tmp_path / f"synthetic-live-receipt-{attack}"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    key = _temporary_rsa_private_key(tmp_path, f"live-receipt-{attack}.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    focused, full = _sign_stub_receipts(root, output)
    focused_sidecar = Path(str(focused) + ".native-attestation")
    full_sidecar = Path(str(full) + ".native-attestation")
    if attack == "missing":
        focused_sidecar.unlink()
    else:
        shutil.copyfile(full_sidecar, focused_sidecar)
        focused_sidecar.chmod(0o600)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"

    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert (root / "verify-child-started").read_text(encoding="utf-8") == ""
    assert not Path(str(attestation) + ".native-attestation").exists()


@pytest.mark.parametrize("target", ["bootstrap", "focused-receipt"])
def test_native_live_attestor_rejects_pre_sign_toctou_mutation(
    tmp_path: Path, target: str
) -> None:
    root = tmp_path / f"synthetic-live-toctou-{target}"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(
        root, child_exit_code=0, semantic_mutation=target
    )
    key = _temporary_rsa_private_key(tmp_path, f"live-toctou-{target}.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"

    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert (root / "verify-child-started").read_text(encoding="utf-8") == "yes"
    assert not Path(str(attestation) + ".native-attestation").exists()


def test_native_live_attestor_never_signs_json_swapped_after_final_digest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-final-json-swap"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    (root / "pre-sign-swap-fired").write_text("", encoding="ascii")
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    replacement = r"""    if '--native-candidate-envelope' in args:
        import ctypes, os
        attestation = Path(args['--native-attestation-path'])
        ready_r, ready_w = os.pipe()
        watcher = os.fork()
        if watcher == 0:
            os.close(ready_r)
            for inherited in (0, 1, 2):
                try:
                    os.close(inherited)
                except OSError:
                    pass
            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_init1.restype = ctypes.c_int
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            libc.inotify_add_watch.restype = ctypes.c_int
            notify_fd = libc.inotify_init1(0)
            if notify_fd < 0:
                os._exit(90)
            watch = libc.inotify_add_watch(
                notify_fd, str(attestation).encode('utf-8'), 0x10
            )
            if watch < 0:
                os._exit(91)
            os.write(ready_w, b'1')
            os.close(ready_w)
            os.read(notify_fd, 4096)
            (root / 'pre-sign-swap-fired').write_text('yes', encoding='ascii')
            malicious = attestation.with_name('.attacker-controlled.tmp')
            malicious.write_text(
                '{"attacker_controlled":true}\n', encoding='ascii'
            )
            malicious.chmod(0o600)
            os.replace(malicious, attestation)
            os._exit(0)
        os.close(ready_w)
        if os.read(ready_r, 1) != b'1':
            raise SystemExit(93)
        os.close(ready_r)
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "final-json-swap.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    sidecar = Path(str(attestation) + ".native-attestation")

    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    swap_marker = root / "pre-sign-swap-fired"
    deadline = time.monotonic() + 1.0
    while swap_marker.read_text(encoding="ascii") != "yes":
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert not sidecar.exists()


def test_native_live_attestor_rejects_semantic_parent_directory_aba(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-semantic-directory-aba"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    for marker_name in ("semantic-replayed-sha", "canonical-visible-sha"):
        (root / marker_name).write_text("", encoding="ascii")
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    start = text.index("elif mode == 'verify-fail-fast-enrich':\n")
    end = text.index("else:\n    raise SystemExit(64)\n", start)
    replacement = r'''elif mode == 'verify-fail-fast-enrich':
    if '--native-candidate-envelope' in args:
        import hashlib, os, shutil
        held_attestation = Path(args['--attestation'])
        held_envelope = Path(args['--native-candidate-envelope'])
        attestation = Path(
            args.get('--native-attestation-path', args['--attestation'])
        )
        envelope = Path(
            args.get(
                '--native-candidate-envelope-path',
                args['--native-candidate-envelope'],
            )
        )
        live_dir = attestation.parent
        reports = live_dir.parent
        held_a = reports / '.pair-a-active'
        held_b = reports / '.pair-b'
        shutil.copytree(live_dir, held_b)
        b_attestation = held_b / attestation.name
        b_envelope = held_b / envelope.name
        b_value = json.loads(b_attestation.read_text(encoding='ascii'))
        b_value['semantic_variant'] = 'b'
        b_raw = (
            json.dumps(b_value, sort_keys=True, separators=(',', ':')) + '\n'
        ).encode('ascii')
        b_attestation.write_bytes(b_raw)
        lines = b_envelope.read_text(encoding='ascii').splitlines()
        lines = [
            ('attestation_sha256=' + sha(b_raw))
            if line.startswith('attestation_sha256=') else line
            for line in lines
        ]
        b_envelope.write_text('\n'.join(lines) + '\n', encoding='ascii')
        os.rename(live_dir, held_a)
        os.rename(held_b, live_dir)
        try:
            if not held_envelope.read_bytes().startswith(
                b'EGSI-LIVE-CANDIDATE-V1\n'
            ):
                raise SystemExit(2)
            replayed = held_attestation.read_bytes()
            value = json.loads(replayed)
            if value['child_exit_code'] != int(
                args['--native-child-exit-code']
            ):
                raise SystemExit(2)
            (root / 'semantic-replayed-sha').write_text(
                hashlib.sha256(replayed).hexdigest(), encoding='ascii'
            )
            (root / 'canonical-visible-sha').write_text(
                hashlib.sha256(attestation.read_bytes()).hexdigest(),
                encoding='ascii',
            )
        finally:
            os.rename(live_dir, held_b)
            os.rename(held_a, live_dir)
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
'''
    bootstrap.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "semantic-directory-aba.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    sidecar = Path(str(attestation) + ".native-attestation")

    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    replayed_sha = (root / "semantic-replayed-sha").read_text(encoding="ascii")
    canonical_sha = (root / "canonical-visible-sha").read_text(encoding="ascii")
    assert replayed_sha != canonical_sha
    assert completed.returncode != 0
    assert not attestation.exists()
    assert not sidecar.exists()


def test_native_live_public_verifier_rejects_valid_pair_swapped_after_python(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-public-valid-pair-swap"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    replacement = r"""    if '--native-candidate-envelope' not in args:
        import os
        held_attestation = Path(args['--attestation'])
        attestation = Path(args['--native-attestation-path'])
        held_attestation.read_bytes()
        sidecar = Path(str(attestation) + '.native-attestation')
        artifact_tmp = attestation.with_name('.post-python-artifact.tmp')
        sidecar_tmp = sidecar.with_name('.post-python-sidecar.tmp')
        artifact_tmp.write_bytes((root / 'saved-b.json').read_bytes())
        artifact_tmp.chmod(0o600)
        sidecar_tmp.write_bytes(
            (root / 'saved-b.json.native-attestation').read_bytes()
        )
        sidecar_tmp.chmod(0o600)
        os.replace(artifact_tmp, attestation)
        os.replace(sidecar_tmp, sidecar)
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "public-valid-pair-swap.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    sidecar = Path(str(attestation) + ".native-attestation")
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]
    for label in ("a", "b"):
        generated = subprocess.run(
            [
                str(root / "scripts/run_fail_fast_enrich"),
                *common,
                "--provider-config", str(provider),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert generated.returncode == 0, generated.stderr
        (root / f"saved-{label}.json").write_bytes(attestation.read_bytes())
        (root / f"saved-{label}.json.native-attestation").write_bytes(
            sidecar.read_bytes()
        )
    attestation.write_bytes((root / "saved-a.json").read_bytes())
    attestation.chmod(0o600)
    sidecar.write_bytes(
        (root / "saved-a.json.native-attestation").read_bytes()
    )
    sidecar.chmod(0o600)

    verified = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert verified.returncode != 0
    assert attestation.read_bytes() == (root / "saved-b.json").read_bytes()
    assert sidecar.read_bytes() == (
        root / "saved-b.json.native-attestation"
    ).read_bytes()


def test_native_live_public_verifier_rejects_directory_aba_during_python_replay(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-public-directory-aba"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    for marker_name in ("python-replayed-run-id", "python-path-visible-run-id"):
        (root / marker_name).write_text("", encoding="ascii")
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    replacement = r"""    if '--native-candidate-envelope' not in args:
        import os
        attestation = Path(args['--native-attestation-path'])
        held_attestation = Path(args['--attestation'])
        live_dir = attestation.parent
        reports = live_dir.parent
        held_a = reports / '.pair-a-active'
        held_b = reports / '.pair-b'
        os.rename(live_dir, held_a)
        os.rename(held_b, live_dir)
        try:
            replayed = json.loads(
                held_attestation.read_text(encoding='ascii')
            )
            path_visible = json.loads(
                attestation.read_text(encoding='ascii')
            )
            (root / 'python-replayed-run-id').write_text(
                replayed['run_id'], encoding='ascii'
            )
            (root / 'python-path-visible-run-id').write_text(
                path_visible['run_id'], encoding='ascii'
            )
        finally:
            os.rename(live_dir, held_b)
            os.rename(held_a, live_dir)
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "public-directory-aba.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    sidecar = Path(str(attestation) + ".native-attestation")
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]

    run_ids: dict[str, str] = {}
    reports = output / "reports"
    for label in ("a", "b"):
        generated = subprocess.run(
            [
                str(root / "scripts/run_fail_fast_enrich"),
                *common,
                "--provider-config", str(provider),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert generated.returncode == 0, generated.stderr
        run_ids[label] = json.loads(
            attestation.read_text(encoding="ascii")
        )["run_id"]
        os.rename(attestation.parent, reports / f".pair-{label}")

    os.rename(reports / ".pair-a", attestation.parent)
    before_artifact = attestation.read_bytes()
    before_sidecar = sidecar.read_bytes()
    before_stat = (attestation.stat(), sidecar.stat())

    verified = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    after_stat = (attestation.stat(), sidecar.stat())
    replay_marker = root / "python-replayed-run-id"
    replayed = (
        replay_marker.read_text(encoding="ascii")
        if replay_marker.is_file()
        else None
    )
    path_visible = (root / "python-path-visible-run-id").read_text(
        encoding="ascii"
    )
    stable_identity = all(
        (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        for before, after in zip(before_stat, after_stat, strict=True)
    )
    assert attestation.read_bytes() == before_artifact
    assert sidecar.read_bytes() == before_sidecar
    assert stable_identity
    assert replayed == run_ids["a"]
    assert path_visible == run_ids["b"]
    assert verified.returncode != 0


def test_native_live_public_verifier_rejects_reports_ancestor_aba(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-public-reports-ancestor-aba"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    for marker_name in ("python-replayed-run-id", "python-path-visible-run-id"):
        (root / marker_name).write_text("", encoding="ascii")
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    replacement = r"""    if '--native-candidate-envelope' not in args:
        import os
        attestation = Path(args['--native-attestation-path'])
        held_attestation = Path(args['--attestation'])
        reports = attestation.parent.parent
        output_dir = reports.parent
        held_a = output_dir / '.reports-a-active'
        held_b = output_dir / '.reports-b'
        os.rename(reports, held_a)
        os.rename(held_b, reports)
        try:
            replayed = json.loads(held_attestation.read_text(encoding='ascii'))
            path_visible = json.loads(attestation.read_text(encoding='ascii'))
            (root / 'python-replayed-run-id').write_text(
                replayed['run_id'], encoding='ascii'
            )
            (root / 'python-path-visible-run-id').write_text(
                path_visible['run_id'], encoding='ascii'
            )
        finally:
            os.rename(reports, held_b)
            os.rename(held_a, reports)
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "public-reports-aba.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    sidecar = Path(str(attestation) + ".native-attestation")
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]

    run_ids: dict[str, str] = {}
    reports = output / "reports"
    for label in ("a", "b"):
        generated = subprocess.run(
            [
                str(root / "scripts/run_fail_fast_enrich"),
                *common,
                "--provider-config", str(provider),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert generated.returncode == 0, generated.stderr
        run_ids[label] = json.loads(
            attestation.read_text(encoding="ascii")
        )["run_id"]
        if label == "a":
            os.rename(reports, output / ".reports-a")
            shutil.copytree(output / ".reports-a", reports)
        else:
            os.rename(reports, output / ".reports-b")

    os.rename(output / ".reports-a", reports)
    before_artifact = attestation.read_bytes()
    before_sidecar = sidecar.read_bytes()
    before_stat = (attestation.stat(), sidecar.stat())

    verified = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    after_stat = (attestation.stat(), sidecar.stat())
    replayed = (root / "python-replayed-run-id").read_text(encoding="ascii")
    path_visible = (root / "python-path-visible-run-id").read_text(
        encoding="ascii"
    )
    stable_identity = all(
        (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        for before, after in zip(before_stat, after_stat, strict=True)
    )
    assert attestation.read_bytes() == before_artifact
    assert sidecar.read_bytes() == before_sidecar
    assert stable_identity
    assert replayed == run_ids["a"]
    assert path_visible == run_ids["b"]
    assert verified.returncode != 0


def test_native_live_attestor_generates_run_metadata_signs_then_publicly_verifies(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-flow"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    key = _temporary_rsa_private_key(tmp_path, "live-flow.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]
    executed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            *common,
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert executed.returncode == 0, executed.stderr
    assert executed.stdout.splitlines()[-1] == (
        "EGSI_NATIVE_ATTESTED=live-enrichment"
    )
    sidecar = Path(str(attestation) + ".native-attestation")
    snapshot = Path(str(attestation) + ".native-snapshot")
    assert sidecar.is_file()
    assert snapshot.is_file()
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    marker = root / "verify-child-started"

    verified = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert marker.read_text(encoding="utf-8") == "yes"
    marker.write_text("", encoding="utf-8")

    sidecar_raw = sidecar.read_bytes()
    sidecar.unlink()
    missing_sidecar = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing_sidecar.returncode != 0
    assert "pre-python" in missing_sidecar.stderr
    assert marker.read_text(encoding="utf-8") == ""
    sidecar.write_bytes(sidecar_raw)
    sidecar.chmod(0o600)

    sidecar.write_bytes(sidecar_raw[:-1] + b"X")
    tampered_sidecar = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tampered_sidecar.returncode != 0
    assert "pre-python" in tampered_sidecar.stderr
    assert marker.read_text(encoding="utf-8") == ""
    sidecar.write_bytes(sidecar_raw)
    sidecar.chmod(0o600)

    alternate_attestation = output / "reports/remaining-p0/alternate.json"
    wrong_path = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(alternate_attestation),
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert wrong_path.returncode != 0
    assert marker.read_text(encoding="utf-8") == ""

    attestation.write_text('{"tampered":true}', encoding="utf-8")
    rejected = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "pre-python" in rejected.stderr
    assert marker.read_text(encoding="utf-8") == ""


def test_native_live_attestor_tolerates_unrelated_outer_ancestor_churn(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-outer-ancestor-churn"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    replacement = r"""    if '--native-candidate-envelope' in args:
        churn = root.parent.parent / (
            '.unrelated-ancestor-churn-' + args['--native-run-id']
        )
        churn.write_text('unrelated', encoding='ascii')
        churn.unlink()
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")
    key = _temporary_rsa_private_key(tmp_path, "outer-ancestor-churn.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"

    completed = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            "--output-root", str(output),
            "--case-file", str(case_file),
            "--scope-case-file", str(scope_file),
            "--attestation", str(attestation),
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert Path(str(attestation) + ".native-attestation").is_file()


def test_native_live_attestor_semantically_verifies_and_signs_child_120_stop(
    tmp_path: Path,
) -> None:
    root = tmp_path / "synthetic-live-stop-flow"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=120)
    key = _temporary_rsa_private_key(tmp_path, "live-stop-flow.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("transport-stop", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    sidecar = Path(str(attestation) + ".native-attestation")
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]

    stopped = subprocess.run(
        [
            str(root / "scripts/run_fail_fast_enrich"),
            *common,
            "--provider-config", str(provider),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert stopped.returncode == 120
    assert stopped.stdout.splitlines()[-1] == (
        "EGSI_NATIVE_ATTESTED=live-enrichment-stop"
    )
    assert sidecar.is_file()
    assert Path(str(attestation) + ".native-snapshot").is_file()
    marker = root / "verify-child-started"
    assert marker.read_text(encoding="utf-8") == "yes"

    verified = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *common,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert marker.read_text(encoding="utf-8") == "yes"


def test_native_receipt_launcher_rsa_attests_only_successful_child_candidate(
    tmp_path: Path,
) -> None:
    root, lock = _synthetic_locked_project(tmp_path)
    output = root / ".work/reports/offline-focused-receipt.json"
    sidecar = Path(str(output) + ".native-attestation")
    completed = subprocess.run(
        [
            str(root / "scripts/run_test_receipt"),
            "--name",
            "focused",
            "--output",
            str(output),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines()[-1] == "EGSI_NATIVE_ATTESTED=receipt"
    candidate = json.loads(output.read_text(encoding="utf-8"))
    assert candidate["schema_version"] == "7.0"
    assert candidate["native_attested"] is False
    info = sidecar.lstat()
    assert stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_nlink == 1

    lines = sidecar.read_text(encoding="ascii").splitlines(keepends=True)
    assert len(lines) == 8
    assert lines[0] == "EGSI-NATIVE-ATTESTATION-V2\n"
    assert lines[1] == "algorithm=rsa-2048-sha256-pkcs1-v1_5\n"
    assert lines[2] == "domain=egsi.test-receipt.focused.v1\n"
    assert lines[3] == "artifact=offline-focused-receipt.json\n"
    assert lines[4] == f"artifact_sha256={hashlib.sha256(output.read_bytes()).hexdigest()}\n"
    native = lock["native_launcher_contract"]
    assert lines[5] == (
        "native_contract="
        + native["binary_contract_sha256"].removeprefix("sha256:")
        + "\n"
    )
    assert lines[6] == (
        "key_id=" + native["public_key_id"].removeprefix("sha256:") + "\n"
    )
    record = json.loads(
        (root / "configs/native-signer-build-record.json").read_text(
            encoding="utf-8"
        )
    )
    public_key = serialization.load_der_public_key(
        base64.b64decode(record["public_key"]["spki_der_base64"], validate=True)
    )
    public_key.verify(
        bytes.fromhex(lines[7].removeprefix("signature=").strip()),
        "".join(lines[:7]).encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # A nonzero locked Python child cannot leave a stale native authority token.
    pytest_main = root / ".work/offline-test-runner-venv/lib/python3.12/site-packages/pytest/__main__.py"
    raw = pytest_main.read_text(encoding="utf-8")
    pytest_main.write_text(raw + "\nraise SystemExit(7)\n", encoding="utf-8")
    failed = subprocess.run(
        [
            str(root / "scripts/run_test_receipt"),
            "--name",
            "focused",
            "--output",
            str(output),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode != 0
    assert not sidecar.exists()


def test_asymmetric_native_build_installs_separated_execute_only_signers(
    tmp_path: Path,
) -> None:
    synthetic_root = tmp_path / "asymmetric-native-root"
    _copy_asymmetric_native_build_sources(synthetic_root)
    scripts = synthetic_root / "scripts"
    private_key = _temporary_rsa_private_key(tmp_path)

    completed = subprocess.run(
        [
            str(scripts / "rebuild_locked_launchers"),
            "--synthetic-output-dir",
            str(scripts),
            "--test-private-key-pem",
            str(private_key),
        ],
        cwd=synthetic_root,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    receipt = scripts / "run_test_receipt"
    rerun = scripts / "rerun_first_case_hard_gate"
    verifier = scripts / "verify_first_case_hard_gate"
    live_execute = scripts / "run_fail_fast_enrich"
    live_verifier = scripts / "verify_fail_fast_enrich"
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o111
    assert stat.S_IMODE(rerun.stat().st_mode) == 0o111
    assert stat.S_IMODE(verifier.stat().st_mode) == 0o555
    assert stat.S_IMODE(live_execute.stat().st_mode) == 0o111
    assert stat.S_IMODE(live_verifier.stat().st_mode) == 0o555
    for signer in (receipt, rerun, live_execute):
        with pytest.raises(PermissionError):
            signer.read_bytes()
        copied = tmp_path / f"copy-{signer.name}"
        failed_copy = subprocess.run(
            ["/usr/bin/cp", str(signer), str(copied)],
            capture_output=True,
            check=False,
        )
        assert failed_copy.returncode != 0
        assert not copied.exists()

    build_record = json.loads(
        (synthetic_root / "configs/native-signer-build-record.json").read_text(
            encoding="utf-8"
        )
    )
    assert build_record["schema_version"] == "3.0"
    assert build_record["algorithm"] == "rsa-2048-sha256-pkcs1-v1_5"
    assert build_record["attestation_version"] == "2"
    assert build_record["public_key"]["exponent"] == 65537
    assert len(build_record["public_key"]["modulus_hex"]) == 512
    assert set(build_record["signers"]) == {
        "receipt", "report", "live_enrichment"
    }
    assert build_record["live_verifier"]["file"] == (
        "scripts/verify_fail_fast_enrich"
    )
    assert not any(
        token in json.dumps(build_record).casefold()
        for token in ('"d"', '"p"', '"q"', "private_exponent", "private key")
    )

    public_raw = verifier.read_bytes()
    live_public_raw = live_verifier.read_bytes()
    private_numbers = serialization.load_pem_private_key(
        private_key.read_bytes(), password=None
    ).private_numbers()
    private_exponent = private_numbers.d.to_bytes(256, "big")
    assert private_exponent not in public_raw
    assert private_exponent not in live_public_raw
    assert not list(synthetic_root.rglob("*.pem"))
    assert not list(synthetic_root.rglob("*private*.h"))


def test_rsa_receipt_signature_matches_cryptography_oracle(tmp_path: Path) -> None:
    root = tmp_path / "rsa-oracle-root"
    _copy_asymmetric_native_build_sources(root)
    private_key_path = _temporary_rsa_private_key(tmp_path, "oracle.pem")
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    bootstrap.write_text(
        """from pathlib import Path
import os, sys
mode = sys.argv[1]
arguments = sys.argv[sys.argv.index('--') + 1:]
if mode == 'run-test-receipt':
    output = Path(arguments[arguments.index('--output') + 1])
    output.write_bytes(b'{\"native_attested\":false}\\n')
    output.chmod(0o600)
    raise SystemExit(0)
raise SystemExit(9)
""",
        encoding="utf-8",
    )
    _run_asymmetric_native_build(root, private_key_path)

    output = root / "reports/offline-focused-receipt.json"
    output.parent.mkdir()
    completed = subprocess.run(
        [
            str(root / "scripts/run_test_receipt"),
            "--name", "focused",
            "--output", str(output),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    sidecar = Path(str(output) + ".native-attestation")
    lines = sidecar.read_text(encoding="ascii").splitlines(keepends=True)
    assert len(lines) == 8
    assert lines[0] == "EGSI-NATIVE-ATTESTATION-V2\n"
    assert lines[1] == "algorithm=rsa-2048-sha256-pkcs1-v1_5\n"
    assert lines[2] == "domain=egsi.test-receipt.focused.v1\n"
    assert lines[3] == "artifact=offline-focused-receipt.json\n"
    assert lines[4] == (
        f"artifact_sha256={hashlib.sha256(output.read_bytes()).hexdigest()}\n"
    )
    record = json.loads(
        (root / "configs/native-signer-build-record.json").read_text(
            encoding="utf-8"
        )
    )
    assert lines[5] == (
        "native_contract="
        + record["native_contract_sha256"].removeprefix("sha256:")
        + "\n"
    )
    assert lines[6] == (
        "key_id="
        + record["public_key"]["key_id"].removeprefix("sha256:")
        + "\n"
    )
    assert lines[7].startswith("signature=")
    assert len(lines[7]) == len("signature=") + 512 + 1
    signature = bytes.fromhex(lines[7].removeprefix("signature=").strip())
    public_key = serialization.load_der_public_key(
        base64.b64decode(record["public_key"]["spki_der_base64"], validate=True)
    )
    public_key.verify(
        signature,
        "".join(lines[:7]).encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_public_verifier_accepts_cryptography_signatures_but_rejects_rerun(
    tmp_path: Path,
) -> None:
    root = tmp_path / "public-oracle-root"
    _copy_asymmetric_native_build_sources(root)
    private_key_path = _temporary_rsa_private_key(tmp_path, "public-oracle.pem")
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    marker = root / "python-started"
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    bootstrap.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('started')\n"
        "raise SystemExit(7)\n",
        encoding="utf-8",
    )
    _run_asymmetric_native_build(root, private_key_path)
    record = json.loads(
        (root / "configs/native-signer-build-record.json").read_text(
            encoding="utf-8"
        )
    )
    key_id = record["public_key"]["key_id"].removeprefix("sha256:")
    native_contract = record["native_contract_sha256"].removeprefix("sha256:")
    output = root / "output"
    reports = output / "reports"
    reports.mkdir(parents=True)
    artifacts = (
        (reports / "offline-focused-receipt.json", "egsi.test-receipt.focused.v1"),
        (reports / "offline-full-receipt.json", "egsi.test-receipt.full.v1"),
        (reports / "first-case-hard-gate.json", "egsi.first-case-report.v1"),
    )
    for index, (artifact, domain) in enumerate(artifacts):
        artifact.write_text(f'{{"candidate":{index}}}\n', encoding="utf-8")
        artifact.chmod(0o600)
        preimage = (
            "EGSI-NATIVE-ATTESTATION-V2\n"
            "algorithm=rsa-2048-sha256-pkcs1-v1_5\n"
            f"domain={domain}\n"
            f"artifact={artifact.name}\n"
            f"artifact_sha256={hashlib.sha256(artifact.read_bytes()).hexdigest()}\n"
            f"native_contract={native_contract}\n"
            f"key_id={key_id}\n"
        )
        signature = private_key.sign(
            preimage.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        sidecar = Path(str(artifact) + ".native-attestation")
        sidecar.write_text(
            preimage + f"signature={signature.hex()}\n", encoding="ascii"
        )
        sidecar.chmod(0o600)

    verifier = root / "scripts/verify_first_case_hard_gate"
    common = [
        "--output-root", str(output),
        "--case-id", "synthetic-case",
        "--focused-receipt", str(artifacts[0][0]),
        "--full-receipt", str(artifacts[1][0]),
        "--report", str(artifacts[2][0]),
    ]
    verified = subprocess.run(
        [str(verifier), *common, "--mode", "verify-only"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 7
    assert marker.read_text(encoding="utf-8") == "started"
    marker.unlink()

    rejected = subprocess.run(
        [str(verifier), *common, "--rerun-tests"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert not marker.exists()


def test_native_signers_report_dumpable_core_and_tracer_hardening(
    tmp_path: Path,
) -> None:
    root = tmp_path / "signer-hardening-root"
    _copy_asymmetric_native_build_sources(root)
    private_key = _temporary_rsa_private_key(tmp_path, "hardening.pem")
    _run_asymmetric_native_build(root, private_key)
    expected = (
        "EGSI_NATIVE_DUMPABLE=0\n"
        "EGSI_NATIVE_TRACER_PID=0\n"
        "EGSI_NATIVE_CORE_SOFT=0\n"
        "EGSI_NATIVE_CORE_HARD=0\n"
    )
    for name in ("run_test_receipt", "rerun_first_case_hard_gate"):
        completed = subprocess.run(
            [str(root / "scripts" / name), "--native-security-state"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout == expected
        assert completed.stderr == ""
    verifier = subprocess.run(
        [
            str(root / "scripts/verify_first_case_hard_gate"),
            "--native-security-state",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verifier.returncode != 0


def test_native_signer_rejects_nonzero_tracer_pid(tmp_path: Path) -> None:
    root = tmp_path / "traced-signer-root"
    _copy_asymmetric_native_build_sources(root)
    private_key = _temporary_rsa_private_key(tmp_path, "traced.pem")
    _run_asymmetric_native_build(root, private_key)
    signer = root / "scripts/run_test_receipt"
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        if libc.ptrace(0, 0, None, None) != 0:  # PTRACE_TRACEME
            os._exit(125)
        os.execv(str(signer), [str(signer), "--native-public-contract"])
        os._exit(126)
    stopped_pid, stopped = os.waitpid(pid, 0)
    if os.WIFEXITED(stopped) and os.WEXITSTATUS(stopped) == 125:
        # The canonical receipt contract permits no skips.  Sandboxes without
        # ptrace cannot exercise this optional kernel boundary; the portable
        # signer-hardening state test above still covers the implementation.
        return
    assert stopped_pid == pid and os.WIFSTOPPED(stopped)
    assert libc.ptrace(7, pid, None, None) == 0  # PTRACE_CONT
    exited_pid, exited = os.waitpid(pid, 0)
    assert exited_pid == pid and os.WIFEXITED(exited)
    assert os.WEXITSTATUS(exited) == 70


def _inject_same_inode_semantic_aba(root: Path, *, kind4: bool) -> None:
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    condition = (
        "'--native-candidate-envelope' in args"
        if kind4
        else "'--native-candidate-envelope' not in args"
    )
    replacement = f"""    if {condition}:
        import os
        Path(args['--attestation']).read_bytes()
        state = Path(args['--native-attestation-path']).with_name(
            'semantic-state.txt'
        )
        parent_before = state.parent.stat()
        original = state.read_bytes()
        assert len(original) == len(b'VALID-B')
        descriptor = os.open(state, os.O_WRONLY)
        try:
            os.pwrite(descriptor, b'VALID-B', 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        (root / 'python-replayed-state').write_bytes(state.read_bytes())
        descriptor = os.open(state, os.O_WRONLY)
        try:
            os.pwrite(descriptor, original, 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent_after = state.parent.stat()
        fields = lambda item: (
            item.st_dev, item.st_ino, item.st_nlink, item.st_mode,
            item.st_uid, item.st_gid, item.st_size, item.st_mtime_ns,
            item.st_ctime_ns,
        )
        (root / 'semantic-window-directory-unchanged').write_text(
            'yes' if fields(parent_before) == fields(parent_after) else 'no',
            encoding='ascii',
        )
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")


def _native_live_same_inode_aba_fixture(
    tmp_path: Path, *, kind4: bool
) -> tuple[Path, Path, Path, list[str]]:
    root = tmp_path / (
        "synthetic-live-kind4-inplace-file-aba"
        if kind4
        else "synthetic-live-kind5-inplace-file-aba"
    )
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    (root / "python-replayed-state").write_text("", encoding="ascii")
    (root / "semantic-window-directory-unchanged").write_text(
        "", encoding="ascii"
    )
    _inject_same_inode_semantic_aba(root, kind4=kind4)
    key = _temporary_rsa_private_key(
        tmp_path, "kind4-inplace-file-aba.pem" if kind4 else "kind5-inplace-file-aba.pem"
    )
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / (
        "reports/remaining-p0/fail-fast-live-attestation.json"
    )
    common = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
    ]
    return root, output, attestation, [*common, "--provider-config", str(provider)]


def test_native_live_attestor_rejects_same_inode_file_aba_during_semantic_replay(
    tmp_path: Path,
) -> None:
    root, _, attestation, run_arguments = _native_live_same_inode_aba_fixture(
        tmp_path, kind4=True
    )
    state = attestation.with_name("semantic-state.txt")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_bytes(b"INVALID")
    state.chmod(0o600)
    before_file = state.stat()
    completed = subprocess.run(
        [str(root / "scripts/run_fail_fast_enrich"), *run_arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    after_file = state.stat()
    assert (root / "python-replayed-state").read_bytes() == b"VALID-B"
    assert state.read_bytes() == b"INVALID"
    assert (
        root / "semantic-window-directory-unchanged"
    ).read_text(encoding="ascii") == "yes"
    assert before_file.st_ino == after_file.st_ino
    assert before_file.st_ctime_ns != after_file.st_ctime_ns
    assert completed.returncode != 0
    assert not Path(str(attestation) + ".native-attestation").exists()
    assert not Path(str(attestation) + ".native-snapshot").exists()


def test_native_live_public_verifier_rejects_same_inode_file_aba_during_semantic_replay(
    tmp_path: Path,
) -> None:
    root, output, attestation, run_arguments = _native_live_same_inode_aba_fixture(
        tmp_path, kind4=False
    )
    generated = subprocess.run(
        [str(root / "scripts/run_fail_fast_enrich"), *run_arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert generated.returncode == 0, generated.stderr
    state = attestation.with_name("semantic-state.txt")
    state.write_bytes(b"INVALID")
    state.chmod(0o600)
    before_directory = state.parent.stat()
    before_file = state.stat()
    verify_arguments = run_arguments[:-2]
    completed = subprocess.run(
        [
            str(root / "scripts/verify_fail_fast_enrich"),
            *verify_arguments,
            "--mode", "verify-only",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    after_directory = state.parent.stat()
    after_file = state.stat()
    fields = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_size,
        item.st_mtime_ns, item.st_ctime_ns,
    )
    assert (root / "python-replayed-state").read_bytes() == b"VALID-B"
    assert state.read_bytes() == b"INVALID"
    assert fields(before_directory) == fields(after_directory)
    assert before_file.st_ino == after_file.st_ino
    assert before_file.st_ctime_ns != after_file.st_ctime_ns
    assert completed.returncode != 0


def _inject_native_live_presign_watcher(root: Path, *, attack: str) -> None:
    bootstrap = root / "scripts/locked_runtime_bootstrap.py"
    text = bootstrap.read_text(encoding="utf-8")
    needle = (
        "    (root / 'verify-child-started').write_text('yes', "
        "encoding='utf-8')\n"
    )
    if attack == "snapshot-swap":
        trigger = "            time.sleep(0.005)\n"
        action = """
            malicious = snapshot.with_name('.attacker-snapshot.tmp')
            malicious.write_bytes(b'{\"attacker_controlled\":true}\\n')
            malicious.chmod(0o600)
            os.replace(malicious, snapshot)
"""
    elif attack == "cleanup-short-circuit":
        trigger = "            time.sleep(0.010)\n"
        action = """
            preflight.unlink()
            preflight.mkdir(mode=0o700)
"""
    else:
        raise AssertionError(f"unknown presign attack: {attack}")
    replacement = f"""    if '--native-candidate-envelope' in args:
        import os, time
        snapshot = Path(args['--native-semantic-snapshot-path'])
        preflight = Path(str(args['--native-attestation-path']) + '.native-preflight')
        sidecar = Path(str(args['--native-attestation-path']) + '.native-attestation')
        ready_read, ready_write = os.pipe()
        watcher = os.fork()
        if watcher == 0:
            os.close(ready_write)
            for inherited in (0, 1, 2):
                try:
                    os.close(inherited)
                except OSError:
                    pass
            os.read(ready_read, 1)
            os.close(ready_read)
{trigger.rstrip()}
            final_sidecar = sidecar.exists()
            temporary_sidecar = any(
                sidecar.parent.glob(f'.{{sidecar.name}}.*.tmp')
            )
{action.rstrip()}
            (root / 'presign-watch-phase').write_text(
                f'final={{int(final_sidecar)}},tmp={{int(temporary_sidecar)}}',
                encoding='ascii',
            )
            (root / 'presign-attack-fired').write_text('yes', encoding='ascii')
            os._exit(0)
        os.close(ready_read)
    (root / 'verify-child-started').write_text('yes', encoding='utf-8')
"""
    assert text.count(needle) == 1
    bootstrap.write_text(text.replace(needle, replacement), encoding="utf-8")


def _native_live_presign_attack_fixture(
    tmp_path: Path, *, attack: str
) -> tuple[Path, Path, list[str]]:
    root = tmp_path / f"synthetic-live-{attack}"
    _copy_asymmetric_native_build_sources(root)
    _write_native_live_stub_bootstrap(root, child_exit_code=0)
    (root / "presign-attack-fired").write_text("", encoding="ascii")
    _inject_native_live_presign_watcher(root, attack=attack)
    key = _temporary_rsa_private_key(tmp_path, f"{attack}.pem")
    _run_asymmetric_native_build(root, key)
    output = root / "output"
    _sign_stub_receipts(root, output)
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    provider = root / "configs/providers.local.toml"
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="utf-8")
    provider.write_text("[teacher]\n", encoding="utf-8")
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    arguments = [
        "--output-root", str(output),
        "--case-file", str(case_file),
        "--scope-case-file", str(scope_file),
        "--attestation", str(attestation),
        "--provider-config", str(provider),
    ]
    return root, attestation, arguments


def _wait_for_presign_attack(root: Path, *, before_publication: bool) -> None:
    marker = root / "presign-attack-fired"
    deadline = time.monotonic() + 2.0
    while marker.read_text(encoding="ascii") != "yes" and time.monotonic() < deadline:
        time.sleep(0.005)
    assert marker.read_text(encoding="ascii") == "yes"
    phase = (root / "presign-watch-phase").read_text(encoding="ascii")
    if before_publication:
        assert phase == "final=0,tmp=0"
    else:
        assert phase in {"final=0,tmp=1", "final=1,tmp=0"}


def test_native_live_attestor_rejects_snapshot_swap_before_rsa_publication(
    tmp_path: Path,
) -> None:
    root, attestation, arguments = _native_live_presign_attack_fixture(
        tmp_path, attack="snapshot-swap"
    )
    completed = subprocess.run(
        [str(root / "scripts/run_fail_fast_enrich"), *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    _wait_for_presign_attack(root, before_publication=True)
    assert completed.returncode != 0
    for suffix in (
        "",
        ".native-attestation",
        ".native-snapshot",
        ".native-candidate",
        ".native-preflight",
    ):
        assert not Path(str(attestation) + suffix).exists()


def test_native_live_attestor_cleanup_does_not_short_circuit_after_unlink_failure(
    tmp_path: Path,
) -> None:
    root, attestation, arguments = _native_live_presign_attack_fixture(
        tmp_path, attack="cleanup-short-circuit"
    )
    completed = subprocess.run(
        [str(root / "scripts/run_fail_fast_enrich"), *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    _wait_for_presign_attack(root, before_publication=True)
    assert completed.returncode != 0
    assert Path(str(attestation) + ".native-preflight").is_dir()
    for suffix in ("", ".native-attestation", ".native-snapshot", ".native-candidate"):
        assert not Path(str(attestation) + suffix).exists()
