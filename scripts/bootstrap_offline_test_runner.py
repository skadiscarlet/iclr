#!/usr/bin/env python3
"""Build the dedicated offline pytest venv from already installed local files."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import venv


_RUNNER_RELATIVE = Path(".work/offline-test-runner-venv")
_COPY_ENTRIES = (
    "_pytest",
    "annotated_doc",
    "annotated_doc-*.dist-info",
    "annotated_types",
    "anyio",
    "anyio-*.dist-info",
    "attr",
    "attrs",
    "attrs-*.dist-info",
    "certifi",
    "certifi-*.dist-info",
    "cffi",
    "cffi-*.dist-info",
    "_cffi_backend*.so",
    "cryptography",
    "cryptography-*.dist-info",
    "h11",
    "h11-*.dist-info",
    "httpcore",
    "httpcore-*.dist-info",
    "httpx",
    "httpx-*.dist-info",
    "idna",
    "idna-*.dist-info",
    "iniconfig",
    "iniconfig-*.dist-info",
    "jsonschema",
    "jsonschema-*.dist-info",
    "jsonschema_specifications",
    "jsonschema_specifications-*.dist-info",
    "markdown_it",
    "mdurl",
    "packaging",
    "packaging-*.dist-info",
    "pluggy",
    "pluggy-*.dist-info",
    "pyarrow",
    "pyarrow-*.dist-info",
    "pydantic",
    "pydantic_core",
    "pygments",
    "pygments-*.dist-info",
    "py.py",
    "pytest",
    "pytest-*.dist-info",
    "referencing",
    "referencing-*.dist-info",
    "respx",
    "respx-*.dist-info",
    "rich",
    "rpds",
    "rpds_py-*.dist-info",
    "shellingham",
    "shellingham-*.dist-info",
    "typer",
    "typer-*.dist-info",
    "typing_extensions.py",
    "typing_extensions-*.dist-info",
    "typing_inspection",
)
_FORBIDDEN_NAMES = {"sitecustomize.py", "usercustomize.py"}
_NATIVE_OUTPUT_RELATIVES = tuple(
    Path(item)
    for item in (
        "scripts/run_test_receipt",
        "scripts/rerun_first_case_hard_gate",
        "scripts/verify_first_case_hard_gate",
        "scripts/run_fail_fast_enrich",
        "scripts/verify_fail_fast_enrich",
        "configs/native-signer-build-record.json",
        "configs/offline-test-runner.lock.json",
    )
)


def _site_source_directories() -> list[Path]:
    directories: list[Path] = []
    for item in sys.path:
        if type(item) is not str or Path(item).name != "site-packages":
            continue
        try:
            path = Path(item).resolve(strict=True)
        except FileNotFoundError:
            continue
        if path not in directories:
            directories.append(path)
    if not directories:
        raise ValueError("no local site-packages source is available")
    return directories


def _copy_source(source: Path, destination: Path) -> None:
    ignore = shutil.ignore_patterns(
        "__pycache__",
        "*.pyc",
        "*.pyo",
        "*.pth",
        "sitecustomize.py",
        "usercustomize.py",
    )
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=False, ignore=ignore)
    else:
        shutil.copy2(source, destination, follow_symlinks=True)


def _copy_dependency_closure(sources: list[Path], destination: Path) -> None:
    copied: set[str] = set()
    for pattern in _COPY_ENTRIES:
        matches: list[Path] = []
        for source in sources:
            found = sorted(source.glob(pattern))
            if found:
                matches = found
                break
        if not matches:
            if "*" not in pattern and pattern not in {
                "annotated_types",
                "markdown_it",
                "mdurl",
                "pydantic",
                "pydantic_core",
                "rich",
                "typing_inspection",
            }:
                raise ValueError(f"offline dependency is unavailable: {pattern}")
            continue
        for source in matches:
            if source.name in copied:
                continue
            _copy_source(source, destination / source.name)
            copied.add(source.name)


def _copy_project(root: Path, destination: Path) -> None:
    source = root / "src/egsi"
    _copy_source(source, destination / "egsi")
    metadata = destination / "egsi-0.1.0.dist-info"
    metadata.mkdir(mode=0o755)
    (metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: egsi\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (metadata / "INSTALLER").write_text(
        "offline-source-copy\n", encoding="utf-8"
    )


def _clean_and_validate_site(site_packages: Path) -> None:
    for path in sorted(site_packages.rglob("__pycache__"), reverse=True):
        shutil.rmtree(path)
    for path in sorted(site_packages.rglob("*")):
        if path.name in _FORBIDDEN_NAMES or path.suffix == ".pth":
            raise ValueError("forbidden startup hook in offline runner")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink in offline runner site-packages")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("hardlink in offline runner site-packages")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError("special node in offline runner site-packages")


def _minimal_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HOME": "/nonexistent",
        "TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _remove_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _backup_native_outputs(root: Path, backup: Path) -> list[Path]:
    moved: list[Path] = []
    for relative in _NATIVE_OUTPUT_RELATIVES:
        source = root / relative
        if not _path_exists(source):
            continue
        destination = backup / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.replace(source, destination)
        moved.append(relative)
    return moved


def _restore_native_outputs(
    root: Path, backup: Path, moved: list[Path]
) -> None:
    for relative in _NATIVE_OUTPUT_RELATIVES:
        _remove_path(root / relative)
    for relative in moved:
        source = backup / relative
        if not _path_exists(source):
            raise RuntimeError("native launcher rollback backup is missing")
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, destination)


def bootstrap(root: Path) -> Path:
    root = Path(root).resolve(strict=True)
    sources = _site_source_directories()
    work = root / ".work"
    work.mkdir(mode=0o700, exist_ok=True)
    transaction_pool = work / ".offline-bootstrap-transactions"
    transaction_pool.mkdir(mode=0o700, exist_ok=True)
    target = root / _RUNNER_RELATIVE
    temporary = work / f".offline-test-runner-venv.{secrets.token_hex(8)}.tmp"
    transaction_backup = transaction_pool / secrets.token_hex(8)
    runner_backup = transaction_backup / "runner"
    native_backup = transaction_backup / "native"
    builder = venv.EnvBuilder(
        system_site_packages=False,
        clear=True,
        symlinks=False,
        with_pip=False,
    )
    builder.create(temporary)
    site_packages = temporary / "lib/python3.12/site-packages"
    _copy_dependency_closure(sources, site_packages)
    _copy_project(root, site_packages)
    _clean_and_validate_site(site_packages)
    old_present = target.exists()
    moved_native: list[Path] = []
    transaction_backup.mkdir(mode=0o700)
    try:
        if old_present:
            os.replace(target, runner_backup)
        os.replace(temporary, target)
        moved_native = _backup_native_outputs(root, native_backup)
        native_update = subprocess.run(
            [str(root / "scripts/rebuild_locked_launchers")],
            cwd=root,
            env=_minimal_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
        if native_update.returncode != 0:
            raise ValueError(
                "offline native launcher rebuild failed: "
                + native_update.stderr.strip()
            )
        bootstrap_script = str(root / "scripts/locked_runtime_bootstrap.py")
        update = subprocess.run(
            [
                str(target / "bin/python"),
                "-X",
                "pycache_prefix=/nonexistent/egsi-locked-pycache",
                "-I",
                "-B",
                "-S",
                bootstrap_script,
                "build-lock",
                "--root",
                str(root),
            ],
            cwd=root,
            env=_minimal_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
        if update.returncode != 0:
            raise ValueError(
                "offline runner lock update failed: " + update.stderr.strip()
            )
        probe = subprocess.run(
            [
                str(target / "bin/python"),
                "-X",
                "pycache_prefix=/nonexistent/egsi-locked-pycache",
                "-I",
                "-B",
                "-S",
                bootstrap_script,
                "probe",
                "--root",
                str(root),
            ],
            cwd=root,
            env=_minimal_environment(),
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0 or probe.stdout.strip() != "locked-runtime-probe-ok":
            raise ValueError(
                "offline runner locked probe failed: " + probe.stderr.strip()
            )
    except Exception:
        rollback_error: Exception | None = None
        try:
            _restore_native_outputs(root, native_backup, moved_native)
            _remove_path(target)
            if old_present and _path_exists(runner_backup):
                os.replace(runner_backup, target)
        except Exception as error:
            rollback_error = error
        shutil.rmtree(transaction_backup, ignore_errors=True)
        if rollback_error is not None:
            raise RuntimeError("offline runner rollback failed") from rollback_error
        raise
    else:
        shutil.rmtree(transaction_backup)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        target = bootstrap(arguments.root)
    except (OSError, ValueError):
        return 1
    print(target)
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
