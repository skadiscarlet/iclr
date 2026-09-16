from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/validate_collected_cases_readonly.py"


def _load_wrapper():
    spec = importlib.util.spec_from_file_location("readonly_validator", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _snapshot(root: Path) -> dict[str, tuple[str, int, int, str | None]]:
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        if stat.S_ISREG(info.st_mode):
            kind = "file"
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISDIR(info.st_mode):
            kind = "directory"
            digest = None
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
            digest = str(path.readlink())
        else:
            kind = "special"
            digest = None
        result[relative] = (kind, stat.S_IMODE(info.st_mode), info.st_mtime_ns, digest)
    return result


def test_readonly_wrapper_isolates_destructive_validator_writes(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    module = _load_wrapper()
    root = tmp_path / "repo"
    data = root / "data"
    (data / "scripts").mkdir(parents=True)
    (data / "reports").mkdir()
    (data / "catalog").mkdir()
    original = data / "catalog/input.json"
    original.write_text('{"value":1}\n', encoding="utf-8")
    rename_source = data / "catalog/rename-me.json"
    rename_source.write_text('{"rename":true}\n', encoding="utf-8")
    delete_source = data / "catalog/delete-me.json"
    delete_source.write_text('{"delete":true}\n', encoding="utf-8")
    (data / "reports/original.json").write_text('{"old":true}\n', encoding="utf-8")
    (data / "scripts/validate_collected_cases.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"assert not Path.cwd().is_relative_to(Path({str(root)!r}))\n"
        "me = Path(__file__)\n"
        "Path('data/catalog/input.json').write_text('mutated-shadow')\n"
        "Path('data/catalog/delete-me.json').unlink()\n"
        "Path('data/catalog/rename-me.json').rename('data/catalog/renamed.json')\n"
        "Path('data/catalog/added.json').write_text('new-shadow')\n"
        "Path('data/reports/generated.json').write_text('shadow-only')\n"
        "me.write_text('# mutated shadow validator')\n"
        "print('validator-stdout')\n"
        "print('validator-stderr', file=sys.stderr)\n",
        encoding="utf-8",
    )
    before = _snapshot(data)
    unrelated_cwd = tmp_path / "unrelated-cwd"
    unrelated_cwd.mkdir()
    monkeypatch.chdir(unrelated_cwd)

    assert module.run_readonly(root) == 0

    captured = capsys.readouterr()
    assert "validator-stdout" in captured.out
    assert "validator-stderr" in captured.err
    assert _snapshot(data) == before
    assert not (data / "reports/generated.json").exists()


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_readonly_wrapper_rejects_unsafe_source_entries(tmp_path: Path, kind: str) -> None:
    module = _load_wrapper()
    root = tmp_path / "repo"
    data = root / "data"
    (data / "scripts").mkdir(parents=True)
    (data / "reports").mkdir()
    (data / "scripts/validate_collected_cases.py").write_text("raise SystemExit(0)\n")
    unsafe = data / "unsafe"
    if kind == "symlink":
        unsafe.symlink_to(tmp_path)
    else:
        os.mkfifo(unsafe)

    with pytest.raises(ValueError, match="unsafe source data entry"):
        module.run_readonly(root)
