from __future__ import annotations

import json
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from egsi.teacher import (
    CachedTeacher,
    TeacherRequest,
    TeacherResponse,
    committed_teacher_response,
)
from egsi.teacher.cache import TeacherCache, cache_key


_SPECIAL_ENTRY_PROBE = r"""
import sys
from pathlib import Path

from egsi.teacher import CachedTeacher, TeacherRequest, committed_teacher_response
from egsi.teacher.cache import TeacherCache

mode, root, key, marker = sys.argv[1:]
cache = TeacherCache(Path(root))

def teacher_response(**value):
    model = value["model"]
    return committed_teacher_response(
        requested_model=model,
        provider_response_model=model,
        **value,
    )

class Inner:
    provider = "fake"
    model = "fake-model"

    def generate(self, request):
        Path(marker).write_text("inner-called", encoding="utf-8")
        return teacher_response(
            provider_request_id=None,
            provider=self.provider,
            model=self.model,
            text="{}",
            usage={},
        )

try:
    if mode == "read":
        CachedTeacher(Inner(), cache).generate(
            TeacherRequest(system="system", user="user", schema={"type": "object"})
        )
    else:
        cache.write(
            key,
            teacher_response(
                provider_request_id=None,
                provider="fake",
                model="fake-model",
                text="{}",
                usage={},
            ),
        )
except RuntimeError as error:
    print(str(error))
    raise SystemExit(0)
raise SystemExit(3)
"""


class CountingTeacher:
    provider = "fake"
    model = "fake-model"

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        return teacher_response(
            provider_request_id="provider-id",
            provider=self.provider,
            model=self.model,
            text='{"answer":"ok"}',
            usage={"tokens": 3},
            latency_ms=1.5,
        )


def request(*, schema: dict | None = None) -> TeacherRequest:
    return TeacherRequest(system="system", user="user", schema=schema or {"type": "object"})


def teacher_response(**value) -> TeacherResponse:
    model = value["model"]
    return committed_teacher_response(
        requested_model=model,
        provider_response_model=model,
        **value,
    )


def run_special_entry_probe(
    mode: str, cache_root: Path, key: str, marker: Path
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [
                sys.executable,
                "-c",
                _SPECIAL_ENTRY_PROBE,
                mode,
                str(cache_root),
                key,
                str(marker),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"teacher cache {mode} blocked on a FIFO")


def test_cache_key_changes_for_model_and_schema():
    first = request()
    assert cache_key("fake", "one", first) != cache_key("fake", "two", first)
    assert cache_key("fake", "one", first) != cache_key("fake", "one", request(schema={"type": "array"}))
    assert cache_key("fake", "one", first).startswith("sha256:")


def test_repeated_request_calls_provider_once_and_returns_cached_response(tmp_path: Path):
    upstream = CountingTeacher()
    teacher = CachedTeacher(upstream, TeacherCache(tmp_path))

    first = teacher.generate(request())
    second = teacher.generate(request())

    assert upstream.calls == 1
    assert first.cached is False
    assert second.cached is True
    assert second.text == first.text


def test_corrupt_cache_fails_with_explicit_safe_error(tmp_path: Path):
    upstream = CountingTeacher()
    cache = TeacherCache(tmp_path)
    key = cache_key(upstream.provider, upstream.model, request())
    cache.path_for(key).write_text("not-json", encoding="utf-8")

    with pytest.raises(RuntimeError, match="teacher cache invalid") as raised:
        CachedTeacher(upstream, cache).generate(request())
    assert "not-json" not in str(raised.value)
    assert upstream.calls == 0


def test_atomic_cache_write_leaves_only_final_json(tmp_path: Path):
    cache = TeacherCache(tmp_path)
    key = cache_key("fake", "fake-model", request())
    response = teacher_response(provider_request_id=None, provider="fake", model="fake-model", text="{}", usage={})

    cache.write(key, response)

    path = cache.path_for(key)
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["text"] == "{}"
    assert sorted(child.name for child in tmp_path.iterdir()) == [path.name]


def test_functional_cache_helpers_match_cached_teacher_contract(tmp_path: Path):
    from egsi.teacher.cache import read_cache, request_cache_key, write_cache

    key = request_cache_key("fake", "fake-model", request())
    expected = teacher_response(provider_request_id=None, provider="fake", model="fake-model", text="{}", usage={})
    path = write_cache(tmp_path, key, expected)

    assert path == tmp_path / f"{key.removeprefix('sha256:')}.json"
    assert read_cache(tmp_path, key).cached is True


def test_atomic_replace_keeps_previous_entry_when_replace_fails(tmp_path: Path, monkeypatch):
    import os

    cache = TeacherCache(tmp_path)
    key = cache_key("fake", "fake-model", request())
    old = teacher_response(provider_request_id=None, provider="fake", model="fake-model", text='{"old":true}', usage={})
    new = teacher_response(provider_request_id=None, provider="fake", model="fake-model", text='{"new":true}', usage={})
    cache.write(key, old)
    path = cache.path_for(key)
    old_contents = path.read_text(encoding="utf-8")
    replacements: list[tuple[str, str]] = []

    def fail_after_inspection(
        source, target, *, src_dir_fd: int, dst_dir_fd: int
    ):
        replacements.append((source, target))
        assert src_dir_fd == dst_dir_fd
        assert "/" not in source and "/" not in target
        assert source.endswith(".tmp")
        descriptor = os.open(source, os.O_RDONLY, dir_fd=src_dir_fd)
        try:
            raw = os.read(descriptor, 2 * 1024 * 1024)
        finally:
            os.close(descriptor)
        assert json.loads(raw)["text"] == new.text
        raise OSError("simulated replace failure")

    monkeypatch.setattr("egsi.teacher.cache.os.replace", fail_after_inspection)
    with pytest.raises(RuntimeError, match="teacher cache write failed"):
        cache.write(key, new)

    assert replacements
    assert path.read_text(encoding="utf-8") == old_contents
    assert sorted(child.name for child in tmp_path.iterdir()) == [path.name]

@pytest.mark.parametrize("poison", [{"tokens": -1}, {"tokens": True}, {"tokens": "2"}])
def test_cache_rejects_poisoned_usage_values(tmp_path: Path, poison):
    cache = TeacherCache(tmp_path)
    key = cache_key("fake", "fake-model", request())
    cache.path_for(key).write_text(
        json.dumps({"provider_request_id": None, "provider": "fake", "model": "fake-model", "text": "{}", "usage": poison, "latency_ms": 0.0, "cached": False}),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match=r"^teacher cache invalid$"):
        cache.read(key)


def test_cache_read_rejects_symlinked_entry(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    cache = TeacherCache(cache_root)
    key = cache_key("fake", "fake-model", request())
    external = tmp_path / "external.json"
    external.write_text(
        teacher_response(
            provider_request_id=None,
            provider="fake",
            model="fake-model",
            text="{}",
            usage={},
        ).model_dump_json(),
        encoding="utf-8",
    )
    cache.path_for(key).symlink_to(external)

    with pytest.raises(RuntimeError, match=r"^teacher cache invalid$"):
        cache.read(key)

    assert external.is_file()


def test_cache_write_rejects_symlinked_ancestor_without_external_write(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "cache").symlink_to(outside, target_is_directory=True)
    cache = TeacherCache(tmp_path / "cache" / "teacher")
    key = cache_key("fake", "fake-model", request())
    response = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text="{}",
        usage={},
    )

    with pytest.raises(RuntimeError, match=r"^teacher cache write failed$"):
        cache.write(key, response)

    assert list(outside.rglob("*")) == []


def test_cache_replace_stays_anchored_during_ancestor_swap(
    tmp_path: Path, monkeypatch
) -> None:
    import os

    cache_parent = tmp_path / "cache"
    moved_parent = tmp_path / "cache-before-swap"
    outside = tmp_path / "outside"
    outside.mkdir()
    cache = TeacherCache(cache_parent / "teacher")
    key = cache_key("fake", "fake-model", request())
    old = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text='{"old":true}',
        usage={},
    )
    new = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text='{"new":true}',
        usage={},
    )
    cache.write(key, old)
    real_replace = os.replace
    swaps = 0

    def swap_then_replace(
        source, target, *, src_dir_fd: int, dst_dir_fd: int
    ) -> None:
        nonlocal swaps
        swaps += 1
        cache_parent.rename(moved_parent)
        cache_parent.symlink_to(outside, target_is_directory=True)
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr("egsi.teacher.cache.os.replace", swap_then_replace)

    cache.write(key, new)

    final = moved_parent / "teacher" / cache.path_for(key).name
    assert swaps == 1
    assert json.loads(final.read_text(encoding="utf-8"))["text"] == new.text
    assert list(outside.rglob("*")) == []
    assert not list((moved_parent / "teacher").glob(".*.tmp"))


def test_cache_recovers_postcommit_replace_error_without_temp_residue(
    tmp_path: Path, monkeypatch
) -> None:
    import os

    cache = TeacherCache(tmp_path / "cache")
    key = cache_key("fake", "fake-model", request())
    response = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text='{"committed":true}',
        usage={},
    )
    real_replace = os.replace

    def commit_then_fail(
        source, target, *, src_dir_fd: int, dst_dir_fd: int
    ) -> None:
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        raise OSError("simulated post-commit error")

    monkeypatch.setattr("egsi.teacher.cache.os.replace", commit_then_fail)

    cache.write(key, response)

    assert cache.read(key) == response.model_copy(update={"cached": True})
    assert not list((tmp_path / "cache").glob(".*.tmp"))


def test_cache_read_rejects_hardlinked_or_oversized_entry(tmp_path: Path) -> None:
    import os

    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    cache = TeacherCache(cache_root)
    key = cache_key("fake", "fake-model", request())
    external = tmp_path / "external.json"
    external.write_text("{}", encoding="utf-8")
    os.link(external, cache.path_for(key))

    with pytest.raises(RuntimeError, match=r"^teacher cache invalid$"):
        cache.read(key)

    cache.path_for(key).unlink()
    cache.path_for(key).write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(RuntimeError, match=r"^teacher cache invalid$"):
        cache.read(key)


def test_cache_read_rejects_fifo_without_blocking_or_calling_inner(
    tmp_path: Path,
) -> None:
    import os

    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    cache = TeacherCache(cache_root)
    key = cache_key("fake", "fake-model", request())
    fifo = cache.path_for(key)
    os.mkfifo(fifo, 0o600)
    marker = tmp_path / "inner-called"

    result = run_special_entry_probe("read", cache_root, key, marker)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "teacher cache invalid"
    assert stat.S_ISFIFO(fifo.lstat().st_mode)
    assert not marker.exists()
    assert [entry.name for entry in cache_root.iterdir()] == [fifo.name]


def test_cache_write_rejects_fifo_without_blocking_or_target_side_effect(
    tmp_path: Path,
) -> None:
    import os

    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    cache = TeacherCache(cache_root)
    key = cache_key("fake", "fake-model", request())
    fifo = cache.path_for(key)
    os.mkfifo(fifo, 0o600)
    marker = tmp_path / "inner-called"

    result = run_special_entry_probe("write", cache_root, key, marker)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "teacher cache write failed"
    assert stat.S_ISFIFO(fifo.lstat().st_mode)
    assert not marker.exists()
    assert [entry.name for entry in cache_root.iterdir()] == [fifo.name]


def test_cache_read_retries_once_after_concurrent_atomic_replace(
    tmp_path: Path, monkeypatch
) -> None:
    import os
    import egsi.teacher.cache as cache_module

    cache = TeacherCache(tmp_path / "cache")
    key = cache_key("fake", "fake-model", request())
    old = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text='{"old":true}',
        usage={},
    )
    new = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text='{"new":true}',
        usage={},
    )
    cache.write(key, old)
    target = cache.path_for(key)
    replacement = target.with_name("concurrent-replacement.json")
    replacement.write_text(
        json.dumps(new.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    real_open = os.open
    real_replace = os.replace
    target_opens = 0

    def replace_before_first_target_open(path, flags, *args, **kwargs):
        nonlocal target_opens
        if path == target.name and kwargs.get("dir_fd") is not None:
            target_opens += 1
            if target_opens == 1:
                real_replace(replacement, target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(cache_module.os, "open", replace_before_first_target_open)

    observed = cache.read(key)

    assert observed == new.model_copy(update={"cached": True})
    assert target_opens == 2


def test_cache_read_bounds_retries_during_continuous_inode_churn(
    tmp_path: Path, monkeypatch
) -> None:
    import os
    import egsi.teacher.cache as cache_module

    cache = TeacherCache(tmp_path / "cache")
    key = cache_key("fake", "fake-model", request())
    response = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text='{"version":0}',
        usage={},
    )
    cache.write(key, response)
    target = cache.path_for(key)
    real_open = os.open
    real_replace = os.replace
    target_opens = 0

    def churn_before_every_target_open(path, flags, *args, **kwargs):
        nonlocal target_opens
        if path == target.name and kwargs.get("dir_fd") is not None:
            target_opens += 1
            replacement = target.with_name(f"churn-{target_opens}.json")
            changed = response.model_copy(
                update={"text": json.dumps({"version": target_opens})}
            )
            replacement.write_text(
                json.dumps(
                    changed.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            real_replace(replacement, target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(cache_module.os, "open", churn_before_every_target_open)

    with pytest.raises(RuntimeError, match=r"^teacher cache invalid$"):
        cache.read(key)

    assert target_opens == cache_module._READ_RACE_ATTEMPTS
    assert not list((tmp_path / "cache").glob("churn-*.json"))


def test_cache_write_rejects_tampered_actual_model_commitment(tmp_path: Path) -> None:
    cache = TeacherCache(tmp_path / "cache")
    key = cache_key("fake", "fake-model", request())
    response = teacher_response(
        provider_request_id=None,
        provider="fake",
        model="fake-model",
        text="{}",
        usage={},
    )
    tampered = response.model_copy(
        update={"provider_response_model": "forged-server-revision"}
    )

    with pytest.raises(RuntimeError, match=r"^teacher cache write failed$"):
        cache.write(key, tampered)

    assert not (tmp_path / "cache").exists()


def test_cached_teacher_rejects_committed_wrong_requested_identity(
    tmp_path: Path,
) -> None:
    upstream = CountingTeacher()
    cache = TeacherCache(tmp_path / "cache")
    key = cache_key(upstream.provider, upstream.model, request())
    wrong = teacher_response(
        provider_request_id=None,
        provider=upstream.provider,
        model="different-requested-alias",
        text="{}",
        usage={},
    )
    cache.write(key, wrong)

    with pytest.raises(RuntimeError, match="teacher cache provenance mismatch"):
        CachedTeacher(upstream, cache).generate(request())

    assert upstream.calls == 0
