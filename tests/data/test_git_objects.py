from __future__ import annotations

import io
import os
import shutil
import signal
import stat
import subprocess
import textwrap
import threading
import time
from pathlib import Path

import pytest

from egsi.data import GitObjectStore
from egsi.data import git_objects


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


@pytest.fixture
def bare_repository(tmp_path: Path) -> tuple[Path, str, str]:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    _git("init", "-q", cwd=worktree)
    _git("config", "user.name", "Test User", cwd=worktree)
    _git("config", "user.email", "test@example.invalid", cwd=worktree)
    source = worktree / "src" / "Example.java"
    source.parent.mkdir()
    source.write_text("class Example { }\n", encoding="utf-8")
    context_source = worktree / "src" / "Context.java"
    context_source.write_text(
        "".join(f"line {line:02d}\n" for line in range(1, 21)),
        encoding="utf-8",
    )
    _git("add", ".", cwd=worktree)
    _git("commit", "-qm", "first", cwd=worktree)
    first_commit = _git("rev-parse", "HEAD", cwd=worktree)

    source.write_text("class Example { int version = 2; }\n", encoding="utf-8")
    context_source.write_text(
        "".join(
            "line 10 changed\n" if line == 10 else f"line {line:02d}\n"
            for line in range(1, 21)
        ),
        encoding="utf-8",
    )
    (worktree / "binary.bin").write_bytes(b"ok\xffend")
    _git("add", ".", cwd=worktree)
    _git("commit", "-m", "second", "-q", cwd=worktree)
    second_commit = _git("rev-parse", "HEAD", cwd=worktree)

    bare = tmp_path / "cache.git"
    _git("clone", "--bare", "-q", str(worktree), str(bare))
    return bare, first_commit, second_commit


def test_reads_a_fixed_commit_from_a_bare_cache(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, _ = bare_repository

    store = GitObjectStore(bare)

    assert store.read_text(first_commit, "src/Example.java") == "class Example { }\n"


def test_pinned_commit_does_not_follow_later_history(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, second_commit = bare_repository
    store = GitObjectStore(bare)

    assert store.read_text(first_commit, "src/Example.java") == "class Example { }\n"
    assert store.read_text(second_commit, "src/Example.java") == "class Example { int version = 2; }\n"


def test_canonical_diff_uses_only_pinned_commits_and_bounded_git_options(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, second_commit = bare_repository

    payload = GitObjectStore(bare).canonical_diff(first_commit, second_commit)

    assert b"diff --git a/src/Example.java b/src/Example.java\n" in payload
    assert b"-class Example { }" in payload
    assert b"+class Example { int version = 2; }" in payload
    assert b"diff --git a/binary.bin b/binary.bin\n" in payload


def test_canonical_diff_ignores_bare_repository_local_config_and_includes(
    bare_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    bare, first_commit, second_commit = bare_repository
    store = GitObjectStore(bare)
    clean_payload = store.canonical_diff(first_commit, second_commit)
    included_config = tmp_path / "attacker-controlled.gitconfig"
    included_config.write_text(
        "[diff]\n\tcontext = 0\n\tnoprefix = true\n",
        encoding="utf-8",
    )
    _git("--git-dir", str(bare), "config", "--add", "include.path", str(included_config))

    polluted_payload = store.canonical_diff(first_commit, second_commit)

    assert polluted_payload == clean_payload


def test_canonical_diff_ignores_ambient_user_attributes(
    bare_repository: tuple[Path, str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bare, first_commit, second_commit = bare_repository
    store = GitObjectStore(bare)
    clean_payload = store.canonical_diff(first_commit, second_commit)
    attributes = tmp_path / "xdg" / "git" / "attributes"
    attributes.parent.mkdir(parents=True)
    attributes.write_text("* -diff\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(attributes.parents[1]))

    polluted_payload = store.canonical_diff(first_commit, second_commit)

    assert polluted_payload == clean_payload


def test_canonical_diff_supports_object_store_paths_requiring_git_path_list_quoting(
    bare_repository: tuple[Path, str, str],
) -> None:
    if os.pathsep != ":":
        pytest.skip("POSIX Git alternate path-list regression")
    bare, first_commit, second_commit = bare_repository
    quoted_bare = bare.with_name('cache:with"quote.git')
    bare.rename(quoted_bare)

    payload = GitObjectStore(quoted_bare).canonical_diff(first_commit, second_commit)

    assert b"diff --git a/src/Example.java b/src/Example.java\n" in payload


@pytest.mark.parametrize(
    "commit",
    ["HEAD", "main", "0" * 39, "A" * 40, "0" * 40 + ":src/Example.java"],
)
def test_canonical_diff_rejects_revision_expressions(
    bare_repository: tuple[Path, str, str], commit: str
) -> None:
    bare, first_commit, _ = bare_repository

    with pytest.raises(ValueError, match="commit"):
        GitObjectStore(bare).canonical_diff(first_commit, commit)


@pytest.mark.parametrize(
    "path",
    ["", "/etc/passwd", "../secret", "src/../secret", "src//Example.java", "src/", "src\\Example.java", "src:\\bad", "src/\x00bad"],
)
def test_rejects_unsafe_repository_paths(
    bare_repository: tuple[Path, str, str], path: str
) -> None:
    bare, _, _ = bare_repository

    with pytest.raises(ValueError):
        GitObjectStore.validate_path(path)
    with pytest.raises(ValueError):
        GitObjectStore(bare).contains("0" * 40, path)


def test_rejects_noncanonical_relative_posix_path_instead_of_normalizing() -> None:
    with pytest.raises(ValueError, match="canonical repository-relative POSIX blob path"):
        GitObjectStore.validate_path("./src/./Example.java")


@pytest.mark.parametrize("commit", ["HEAD", "main", "0" * 39, "A" * 40, "0" * 40 + ":src/Example.java"])
def test_rejects_revision_expressions_instead_of_pinned_commits(
    bare_repository: tuple[Path, str, str], commit: str
) -> None:
    bare, _, _ = bare_repository

    with pytest.raises(ValueError):
        GitObjectStore(bare).contains(commit, "src/Example.java")


def test_missing_blob_is_absent_and_read_does_not_expose_git_output(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, _ = bare_repository
    store = GitObjectStore(bare)

    assert store.contains(first_commit, "src/Missing.java") is False
    with pytest.raises(FileNotFoundError, match="src/Missing.java") as error:
        store.read_bytes(first_commit, "src/Missing.java")
    assert "fatal:" not in str(error.value)


def test_directory_is_not_a_readable_blob(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, _ = bare_repository
    store = GitObjectStore(bare)

    assert store.contains(first_commit, "src") is False
    with pytest.raises(FileNotFoundError):
        store.read_bytes(first_commit, "src")


def test_binary_text_decoding_replaces_invalid_utf8(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, _, second_commit = bare_repository
    store = GitObjectStore(bare)

    # The second commit also establishes the binary file below.
    assert store.read_text(second_commit, "binary.bin") == "ok\ufffdend"


def test_enforces_blob_size_before_and_after_read(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, _, second_commit = bare_repository
    store = GitObjectStore(bare)

    assert store.read_bytes(second_commit, "binary.bin", max_bytes=6) == b"ok\xffend"
    with pytest.raises(ValueError, match=r"limit 5 bytes: binary\.bin"):
        store.read_bytes(second_commit, "binary.bin", max_bytes=5)
    for invalid_limit in (0, -1, True):
        with pytest.raises(ValueError):
            store.read_bytes(second_commit, "binary.bin", max_bytes=invalid_limit)


def test_rejects_non_directory_git_cache_paths(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        GitObjectStore(tmp_path / "missing.git")

    file_path = tmp_path / "not-a-directory"
    file_path.write_text("not a git directory", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        GitObjectStore(file_path)


def test_rejects_existing_directory_that_is_not_a_bare_git_store(tmp_path: Path) -> None:
    not_a_repository = tmp_path / "empty-directory"
    not_a_repository.mkdir()

    with pytest.raises(FileNotFoundError):
        GitObjectStore(not_a_repository)


def test_git_cache_guard_rejects_same_inode_pwrite_restore(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, _, _ = bare_repository
    loose_object = next(
        path
        for path in bare.joinpath("objects").glob("*/*")
        if path.is_file() and len(path.parent.name) == 2 and len(path.name) == 38
    )
    loose_object.chmod(loose_object.stat().st_mode | stat.S_IWUSR)
    original = loose_object.read_bytes()
    timestamps = (loose_object.stat().st_atime_ns, loose_object.stat().st_mtime_ns)
    guard = git_objects.GitCacheGuard(bare.parent, bare.name)

    with pytest.raises(ValueError, match="Git cache identity closure changed"):
        with guard.query():
            with loose_object.open("r+b", buffering=0) as stream:
                stream.write(b"X" * len(original))
                stream.seek(0)
                stream.write(original)
            os.utime(loose_object, ns=timestamps)


def test_git_cache_guard_rejects_directory_rename_aba(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, _, _ = bare_repository
    fanout = next(
        path
        for path in bare.joinpath("objects").iterdir()
        if path.is_dir() and len(path.name) == 2
    )
    renamed = fanout.with_name(fanout.name + ".safe")
    guard = git_objects.GitCacheGuard(bare.parent, bare.name)

    with pytest.raises(ValueError, match="Git cache identity closure changed"):
        with guard.query():
            fanout.rename(renamed)
            renamed.rename(fanout)


def test_git_cache_guard_captures_linked_alternate_and_bounds_cycles(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, _, _ = bare_repository
    alternate = bare.parent / "alternate-objects"
    shutil.copytree(bare / "objects", alternate)
    alternates = bare / "objects/info/alternates"
    alternates.parent.mkdir(exist_ok=True)
    alternates.write_text(
        "../../alternate-objects\n.\n", encoding="utf-8"
    )
    linked_object = next(
        path
        for path in alternate.glob("*/*")
        if path.is_file() and len(path.parent.name) == 2 and len(path.name) == 38
    )
    linked_object.chmod(linked_object.stat().st_mode | stat.S_IWUSR)
    original = linked_object.read_bytes()
    timestamps = (linked_object.stat().st_atime_ns, linked_object.stat().st_mtime_ns)
    guard = git_objects.GitCacheGuard(bare.parent, bare.name)
    assert any(
        entry.relative_path.startswith("@alternate:alternate-objects")
        for entry in guard.identity_closure
    )

    with pytest.raises(ValueError, match="Git cache identity closure changed"):
        with guard.query():
            linked_object.write_bytes(b"X" * len(original))
            linked_object.write_bytes(original)
            os.utime(linked_object, ns=timestamps)
    guard.close()


def test_git_cache_guard_enforces_entry_bound_and_closes_descriptors(
    bare_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bare, _, _ = bare_repository
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(8):
        guard = git_objects.GitCacheGuard(bare.parent, bare.name)
        guard.close()
        guard.close()
    assert len(os.listdir("/proc/self/fd")) == before

    monkeypatch.setattr(git_objects, "_GIT_CACHE_MAX_ENTRIES", 1)
    with pytest.raises(ValueError, match="identity closure exceeds its bound"):
        git_objects.GitCacheGuard(bare.parent, bare.name)
    assert len(os.listdir("/proc/self/fd")) == before


def test_git_cache_guard_and_store_contexts_close_on_success_and_query_error(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, _ = bare_repository
    before = len(os.listdir("/proc/self/fd"))

    with git_objects.GitCacheGuard(bare.parent, bare.name) as guard:
        with guard.open_store() as store:
            assert store.contains(first_commit, "src/Example.java") is True
    assert len(os.listdir("/proc/self/fd")) == before

    retained_error: Exception | None = None
    try:
        with git_objects.GitCacheGuard(bare.parent, bare.name) as guard:
            with guard.open_store() as store:
                store.contains("not-a-commit", "src/Example.java")
    except Exception as exc:
        retained_error = exc
    assert isinstance(retained_error, ValueError)
    assert len(os.listdir("/proc/self/fd")) == before


def test_git_cache_guard_queries_use_namespace_local_inherited_fd(
    bare_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bare, first_commit, second_commit = bare_repository
    nonexistent_host_pid = 2_147_483_647
    assert not Path(f"/proc/{nonexistent_host_pid}").exists()
    monkeypatch.setattr(git_objects.os, "getpid", lambda: nonexistent_host_pid)

    with git_objects.GitCacheGuard(bare.parent, bare.name) as guard:
        assert guard._git_dir_path == Path(f"/proc/self/fd/{guard._cache_fd}")
        with guard.open_store() as store:
            assert store.read_bytes(first_commit, "src/Example.java") == (
                b"class Example { }\n"
            )
            assert b"+class Example { int version = 2; }" in store.canonical_diff(
                first_commit, second_commit
            )


def test_closed_guarded_store_rejects_queries_after_descriptor_number_reuse(
    bare_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    bare, first_commit, second_commit = bare_repository
    replacement = tmp_path / "replacement.git"
    shutil.copytree(bare, replacement)
    guard = git_objects.GitCacheGuard(bare.parent, bare.name)
    store = guard.open_store()
    stale_descriptor = store._inherited_directory_fd
    assert type(stale_descriptor) is int
    store.close()
    assert store._closed is True
    assert store._inherited_directory_fd is None

    replacement_descriptor = os.open(replacement, git_objects._directory_flags())
    try:
        if replacement_descriptor != stale_descriptor:
            os.dup2(
                replacement_descriptor,
                stale_descriptor,
                inheritable=False,
            )
        reused = os.fstat(stale_descriptor)
        replacement_identity = replacement.stat()
        assert (reused.st_dev, reused.st_ino) == (
            replacement_identity.st_dev,
            replacement_identity.st_ino,
        )

        queries = (
            lambda: store.contains(first_commit, "src/Example.java"),
            lambda: store.read_bytes(first_commit, "src/Example.java"),
            lambda: store.read_text(first_commit, "src/Example.java"),
            lambda: store.canonical_diff(first_commit, second_commit),
        )
        for query in queries:
            with pytest.raises(ValueError, match="Git object store is closed"):
                query()
    finally:
        os.close(stale_descriptor)
        if replacement_descriptor != stale_descriptor:
            os.close(replacement_descriptor)


def test_closing_unguarded_store_preserves_existing_query_semantics(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, _ = bare_repository
    store = GitObjectStore(bare)

    store.close()

    assert store.contains(first_commit, "src/Example.java") is True


def test_git_cache_guard_open_store_failure_closes_with_retained_traceback(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, _, _ = bare_repository
    (bare / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        encoding="utf-8",
    )
    before = len(os.listdir("/proc/self/fd"))
    retained_error: Exception | None = None
    guard = git_objects.GitCacheGuard(bare.parent, bare.name)

    try:
        guard.open_store()
    except Exception as exc:
        retained_error = exc

    assert isinstance(retained_error, FileNotFoundError)
    assert len(os.listdir("/proc/self/fd")) == before


def test_git_cache_guard_accepts_commondir_alternates_cycle_and_detects_mutation(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "cache.git"
    common = tmp_path / "common"
    alternate = tmp_path / "alternate"
    (cache / "objects").mkdir(parents=True)
    (common / "objects/info").mkdir(parents=True)
    (alternate / "info").mkdir(parents=True)
    (cache / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (cache / "commondir").write_text("../common\n", encoding="ascii")
    (common / "objects/info/alternates").write_text(
        "../../alternate\n", encoding="utf-8"
    )
    (alternate / "info/alternates").write_text(
        "../common/objects\n", encoding="utf-8"
    )
    linked = alternate / "aa" / ("b" * 38)
    linked.parent.mkdir()
    linked.write_bytes(b"linked-object")

    guard = git_objects.GitCacheGuard(tmp_path, "cache.git")
    paths = {entry.relative_path for entry in guard.identity_closure}
    assert "@common:objects" in paths
    assert any(path.startswith("@alternate:alternate") for path in paths)

    with pytest.raises(
        git_objects.GitCacheIntegrityError,
        match="Git cache identity closure changed",
    ):
        with guard.query():
            linked.write_bytes(b"mutated-object")
    guard.close()


def test_git_cache_guard_uses_one_global_entry_and_depth_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "nested/cache.git"
    common = tmp_path / "common"
    (cache / "objects").mkdir(parents=True)
    (common / "objects").mkdir(parents=True)
    (cache / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (cache / "commondir").write_text("../../common\n", encoding="ascii")

    baseline = git_objects.GitCacheGuard(tmp_path, "nested/cache.git")
    total_entries = len(baseline.identity_closure)
    baseline.close()

    monkeypatch.setattr(git_objects, "_GIT_CACHE_MAX_ENTRIES", total_entries - 1)
    with pytest.raises(ValueError, match="identity closure exceeds its bound"):
        git_objects.GitCacheGuard(tmp_path, "nested/cache.git")

    monkeypatch.setattr(git_objects, "_GIT_CACHE_MAX_ENTRIES", total_entries)
    monkeypatch.setattr(git_objects, "_GIT_CACHE_MAX_DEPTH", 1)
    with pytest.raises(ValueError, match="directory depth exceeds its bound"):
        git_objects.GitCacheGuard(tmp_path, "nested/cache.git")


def test_semantic_query_capture_propagates_integrity_failure_without_encoding(
    bare_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bare, _, _ = bare_repository

    monkeypatch.setattr(
        git_objects.GitObjectStore,
        "_is_commit",
        lambda _store, commit: commit,
    )

    def mutate_identity(_store: GitObjectStore, _expression: str) -> bool:
        raw = (bare / "HEAD").read_bytes()
        (bare / "HEAD").write_bytes(raw + b"X")
        (bare / "HEAD").write_bytes(raw)
        return False

    monkeypatch.setattr(git_objects.GitObjectStore, "_is_blob", mutate_identity)

    with git_objects.capture_git_queries({bare: "data/cache.git"}) as entries:
        with git_objects.GitCacheGuard(bare.parent, bare.name) as guard:
            with guard.open_store() as store:
                with pytest.raises(
                    git_objects.GitCacheIntegrityError,
                    match="Git cache identity closure changed",
                ):
                    store.contains("0" * 40, "file.txt")

    assert entries == []


def test_semantic_query_encoder_rejects_integrity_failure() -> None:
    integrity_error = git_objects.GitCacheIntegrityError(
        "Git cache identity closure changed"
    )

    with pytest.raises(git_objects.GitCacheIntegrityError) as raised:
        git_objects._encoded_query_result(
            store_path="data/cache.git",
            operation="contains",
            arguments=("0" * 40, "file.txt"),
            result=integrity_error,
        )

    assert raised.value is integrity_error


def test_verify_git_queries_propagates_integrity_failure_when_valueerror_expected(
    bare_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bare, _, _ = bare_repository
    root = bare.parent
    declared = root / "data/cache.git"
    declared.parent.mkdir()
    bare.rename(declared)
    bare = declared
    with git_objects.capture_git_queries({bare: "data/cache.git"}) as expected:
        with git_objects.GitCacheGuard(root, "data/cache.git") as guard:
            with guard.open_store() as store:
                with pytest.raises(ValueError, match="commit"):
                    store.contains("0" * 40, "file.txt")
    assert expected[0]["error_kind"] == "ValueError"

    mutation_executed = False

    def mutate_during_query(
        _store: GitObjectStore, _commit: str, _path: str
    ) -> bool:
        nonlocal mutation_executed
        raw = (bare / "HEAD").read_bytes()
        (bare / "HEAD").write_bytes(raw + b"X")
        (bare / "HEAD").write_bytes(raw)
        mutation_executed = True
        return False

    monkeypatch.setattr(GitObjectStore, "contains", mutate_during_query)

    with pytest.raises(
        git_objects.GitCacheIntegrityError,
        match="Git cache identity closure changed",
    ):
        git_objects.verify_git_queries(
            root,
            expected,
            store_paths=["data/cache.git"],
        )
    assert mutation_executed is True


def test_ignores_git_replace_refs_for_every_pinned_blob_operation(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, second_commit = bare_repository
    _git("--git-dir", str(bare), "replace", first_commit, second_commit)
    store = GitObjectStore(bare)

    assert store.contains(first_commit, "src/Example.java") is True
    assert store.read_bytes(first_commit, "src/Example.java") == b"class Example { }\n"
    assert store.read_text(first_commit, "src/Example.java") == "class Example { }\n"
    with pytest.raises(FileNotFoundError):
        store.read_bytes(first_commit, "binary.bin")


def _fake_bare_directory(tmp_path: Path) -> Path:
    git_dir = tmp_path / "fake.git"
    (git_dir / "objects").mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return git_dir


def _install_fake_git(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "git"
    executable.write_text(
        "#!/usr/bin/env python3\nimport os\nimport sys\nimport time\n" + textwrap.dedent(body),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")


def _pid_is_running(pid: int) -> bool:
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        state = proc_stat.read_text(encoding="utf-8").split()[2]
    except (FileNotFoundError, IndexError, PermissionError):
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            return False
        return True
    return state not in {"Z", "X"}


def _kill_test_descendant(pid_file: Path) -> None:
    if not pid_file.exists():
        return
    pid = int(pid_file.read_text(encoding="utf-8"))
    if _pid_is_running(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


class _CleanupTrackingProcess:
    def __init__(self) -> None:
        self.args = ["git"]
        self.pid = 424_242
        self.returncode: int | None = None
        self.stdout = io.BytesIO()
        self.wait_timeouts: list[float] = []

    def wait(self, timeout: float) -> int:
        self.wait_timeouts.append(timeout)
        self.returncode = -9
        return self.returncode


def _assert_post_spawn_cleanup(
    process: _CleanupTrackingProcess,
    signals: list[tuple[int, signal.Signals]],
) -> None:
    assert signals == [
        (process.pid, signal.SIGTERM),
        (process.pid, signal.SIGKILL),
    ]
    assert process.wait_timeouts == [
        pytest.approx(git_objects._PROCESS_GROUP_KILL_GRACE_SECONDS)
    ]
    assert process.returncode == -9
    assert process.stdout.closed is True


def test_bounded_read_cleans_up_process_group_when_reader_construction_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _CleanupTrackingProcess()
    signals: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(git_objects.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        git_objects.os,
        "killpg",
        lambda pid, sig: signals.append((pid, sig)),
    )

    def fail_reader_construction(_stream: object, _capacity: int) -> object:
        raise MemoryError("injected reader allocation failure")

    monkeypatch.setattr(git_objects, "_BoundedReader", fail_reader_construction)

    with pytest.raises(MemoryError, match="injected reader allocation failure"):
        git_objects._read_limited(tmp_path, ("show", "object"), 8)

    _assert_post_spawn_cleanup(process, signals)


def test_bounded_read_cleans_up_without_joining_when_thread_start_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _CleanupTrackingProcess()
    signals: list[tuple[int, signal.Signals]] = []
    joins: list[bool] = []
    monkeypatch.setattr(git_objects.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        git_objects.os,
        "killpg",
        lambda pid, sig: signals.append((pid, sig)),
    )
    monkeypatch.setattr(
        git_objects.threading.Thread,
        "start",
        lambda _thread: (_ for _ in ()).throw(RuntimeError("injected start failure")),
    )
    monkeypatch.setattr(
        git_objects.threading.Thread,
        "join",
        lambda _thread, **_kwargs: joins.append(True),
    )

    with pytest.raises(RuntimeError, match="injected start failure"):
        git_objects._read_limited(tmp_path, ("show", "object"), 8)

    _assert_post_spawn_cleanup(process, signals)
    assert joins == []


def test_git_subprocess_environment_is_sanitized_for_all_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        allowed = {
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
        }
        inherited = {key: value for key, value in os.environ.items() if key.startswith("GIT_")}
        alternate = inherited.pop("GIT_ALTERNATE_OBJECT_DIRECTORIES", None)
        if inherited != allowed:
            sys.exit(91)
        if alternate is not None and (
            not alternate.startswith('"')
            or not alternate.endswith('/fake.git/objects"')
            or "redirected-objects" in alternate
        ):
            sys.exit(94)
        if os.environ.get("LC_ALL") != "C" or os.environ.get("LANG") != "C":
            sys.exit(93)
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            print("commit" if len(args[-1]) == 40 else "blob")
        elif "cat-file" in args and "-s" in args:
            print("1")
        elif "show" in args:
            sys.stdout.buffer.write(b"x")
        elif "diff" in args:
            expected = [
                "diff", "--no-ext-diff", "--no-textconv", "--binary",
                "--full-index", "--no-color", "0" * 40, "1" * 40, "--",
            ]
            if args[-len(expected):] != expected:
                sys.exit(92)
            sys.stdout.buffer.write(b"canonical-diff")
        sys.exit(0)
        """,
    )
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "redirected-objects"))
    monkeypatch.setenv("GIT_COMMON_DIR", str(tmp_path / "redirected-common"))
    monkeypatch.setenv("GIT_EXT_SERVICE", str(tmp_path / "must-not-run"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "host-config"))
    monkeypatch.setenv("LC_ALL", "host-locale")
    monkeypatch.setenv("LANG", "host-locale")

    store = GitObjectStore(_fake_bare_directory(tmp_path))

    assert store.contains("0" * 40, "src/Example.java") is True
    assert store.read_bytes("0" * 40, "src/Example.java") == b"x"
    assert store.canonical_diff("0" * 40, "1" * 40) == b"canonical-diff"


def test_canonical_diff_terminates_an_oversized_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            print("commit")
        elif "diff" in args:
            sys.stdout.buffer.write(b"x" * (2 * 1024 * 1024 + 1))
            sys.stdout.flush()
            time.sleep(2)
        """,
    )
    store = GitObjectStore(_fake_bare_directory(tmp_path))

    started = time.monotonic()
    with pytest.raises(ValueError, match="bounded input limit"):
        store.canonical_diff("0" * 40, "1" * 40)
    assert time.monotonic() - started < 1.0


def test_canonical_diff_bounds_commit_type_probe_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            sys.stdout.buffer.write(b"x" * (64 * 1024 + 1))
            sys.stdout.flush()
            time.sleep(2)
        """,
    )
    store = GitObjectStore(_fake_bare_directory(tmp_path))

    started = time.monotonic()
    with pytest.raises(ValueError, match="commit object"):
        store.canonical_diff("0" * 40, "1" * 40)
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize("mode", ["timeout", "nonzero"])
def test_canonical_diff_fails_safely_on_timeout_or_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    behavior = "time.sleep(0.2)" if mode == "timeout" else "sys.exit(17)"
    _install_fake_git(
        monkeypatch,
        tmp_path,
        f"""
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            print("commit")
        elif "diff" in args:
            {behavior}
        """,
    )
    store = GitObjectStore(_fake_bare_directory(tmp_path))
    if mode == "timeout":
        monkeypatch.setattr(git_objects, "_GIT_TIMEOUT_SECONDS", 0.05)

    with pytest.raises(RuntimeError, match="timed out|diff failed") as error:
        store.canonical_diff("0" * 40, "1" * 40)
    assert str(tmp_path) not in str(error.value)


def test_read_bytes_terminates_a_lying_large_stream_at_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            print("commit" if len(args[-1]) == 40 else "blob")
        elif "cat-file" in args and "-s" in args:
            print("1")
        elif "show" in args:
            sys.stdout.buffer.write(b"x" * (1024 * 1024))
            sys.stdout.flush()
            time.sleep(2)
        sys.exit(0)
        """,
    )
    store = GitObjectStore(_fake_bare_directory(tmp_path))

    started = time.monotonic()
    with pytest.raises(ValueError, match=r"limit 8 bytes: src/Example\.java"):
        store.read_bytes("0" * 40, "src/Example.java", max_bytes=8)
    assert time.monotonic() - started < 0.75


def test_git_timeout_raises_a_stable_safe_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        else:
            time.sleep(0.2)
        """,
    )
    store = GitObjectStore(_fake_bare_directory(tmp_path))
    monkeypatch.setattr(git_objects, "_GIT_TIMEOUT_SECONDS", 0.05)

    with pytest.raises(RuntimeError, match="git command timed out") as error:
        store.contains("0" * 40, "src/Example.java")
    assert "src/Example.java" not in str(error.value)
    assert "git --" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_metadata_timeout_kills_stdout_inheriting_descendant_within_bounded_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "metadata-descendant.pid"
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        import subprocess
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            stdin=subprocess.DEVNULL,
        )
        with open(os.environ["EGSI_TEST_PIDFILE"], "w", encoding="utf-8") as stream:
            stream.write(str(child.pid))
        sys.exit(0)
        """,
    )
    monkeypatch.setenv("EGSI_TEST_PIDFILE", str(pid_file))
    # Leave enough budget for an isolated Python shebang to start and publish
    # the descendant PID before exercising the inherited-pipe timeout path.
    monkeypatch.setattr(git_objects, "_GIT_TIMEOUT_SECONDS", 0.15)

    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="git command timed out"):
            git_objects._run_text(
                _fake_bare_directory(tmp_path),
                "rev-parse",
                "--is-bare-repository",
            )
        elapsed = time.monotonic() - started
        pid = int(pid_file.read_text(encoding="utf-8"))
        assert elapsed <= 0.8
        assert _pid_is_running(pid) is False
    finally:
        _kill_test_descendant(pid_file)


def test_canonical_diff_timeout_kills_stdout_inheriting_descendant_within_bounded_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "diff-descendant.pid"
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            print("commit")
        elif "diff" in args:
            import subprocess
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                stdin=subprocess.DEVNULL,
            )
            with open(os.environ["EGSI_TEST_PIDFILE"], "w", encoding="utf-8") as stream:
                stream.write(str(child.pid))
        sys.exit(0)
        """,
    )
    monkeypatch.setenv("EGSI_TEST_PIDFILE", str(pid_file))
    store = GitObjectStore(_fake_bare_directory(tmp_path))
    monkeypatch.setattr(git_objects, "_GIT_TIMEOUT_SECONDS", 0.15)

    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            store.canonical_diff("0" * 40, "1" * 40)
        elapsed = time.monotonic() - started
        pid = int(pid_file.read_text(encoding="utf-8"))
        assert elapsed <= 0.8
        assert _pid_is_running(pid) is False
    finally:
        _kill_test_descendant(pid_file)


def test_resolves_git_directory_and_ignores_ambient_git_redirects(
    bare_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bare, first_commit, _ = bare_repository
    monkeypatch.chdir(bare.parent)
    monkeypatch.setenv("GIT_DIR", str(bare.parent / "not-the-cache.git"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(bare.parent / "not-objects"))

    store = GitObjectStore(Path(bare.name))

    assert store.git_dir == bare.resolve(strict=True)
    assert store.read_text(first_commit, "src/Example.java") == "class Example { }\n"


def test_rejects_tree_and_tag_object_ids_as_pinned_commits(
    bare_repository: tuple[Path, str, str],
) -> None:
    bare, first_commit, _ = bare_repository
    tree = _git("--git-dir", str(bare), "rev-parse", f"{first_commit}^{{tree}}")
    _git("--git-dir", str(bare), "config", "user.name", "Test User")
    _git("--git-dir", str(bare), "config", "user.email", "test@example.invalid")
    _git("--git-dir", str(bare), "tag", "-a", "-m", "tag", "v1", first_commit)
    tag = _git("--git-dir", str(bare), "rev-parse", "refs/tags/v1")
    store = GitObjectStore(bare)

    for object_id in (tree, tag):
        with pytest.raises(ValueError, match="commit"):
            store.contains(object_id, "src/Example.java")
        with pytest.raises(ValueError, match="commit"):
            store.read_bytes(object_id, "src/Example.java")


def test_git_start_failure_does_not_retain_sensitive_exception_context(
    bare_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    bare, _, _ = bare_repository
    sentinel = f"{bare}/sentinel-oid-path"

    def fail_to_start(*_args: object, **_kwargs: object) -> object:
        raise OSError(sentinel)

    monkeypatch.setattr(git_objects.subprocess, "Popen", fail_to_start)

    with pytest.raises(RuntimeError, match="git command failed") as error:
        GitObjectStore(bare)
    assert sentinel not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_bounded_reader_needs_no_file_descriptor_or_select_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MemoryOnlyProcess:
        def __init__(self, args: list[str], *, text: bool, **_kwargs: object) -> None:
            self.args = args
            self.returncode = 0
            self._text = text
            if "rev-parse" in args:
                output: str | bytes = "true\n"
            elif "cat-file" in args and "-t" in args:
                output = "commit\n" if len(args[-1]) == 40 else "blob\n"
            elif "cat-file" in args and "-s" in args:
                output = "1\n"
            elif "show" in args:
                output = b"x" * 20
            else:
                output = ""
            self.stdout = io.StringIO(output) if text else io.BytesIO(output)

        def communicate(self, **_kwargs: object) -> tuple[str, str]:
            return self.stdout.getvalue(), ""

        def poll(self) -> int:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15

        def kill(self) -> None:
            self.returncode = -9

        def wait(self, **_kwargs: object) -> int:
            return self.returncode

    monkeypatch.setattr(git_objects.subprocess, "Popen", MemoryOnlyProcess)
    store = GitObjectStore(_fake_bare_directory(tmp_path))

    with pytest.raises(ValueError, match=r"limit 8 bytes: src/Example\.java"):
        store.read_bytes("0" * 40, "src/Example.java", max_bytes=8)


def test_read_uses_object_size_not_caller_limit_for_reader_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_git(
        monkeypatch,
        tmp_path,
        """
        args = sys.argv[1:]
        if "rev-parse" in args:
            print("true")
        elif "cat-file" in args and "-t" in args:
            print("commit" if len(args[-1]) == 40 else "blob")
        elif "cat-file" in args and "-s" in args:
            print("1")
        elif "show" in args:
            sys.stdout.buffer.write(b"x")
        """,
    )
    capacities: list[int] = []

    class ThreadStub:
        def join(self, *_args: object, **_kwargs: object) -> None:
            return None

        def is_alive(self) -> bool:
            return False

    class ImmediateReader:
        def __init__(self, _stream: object, capacity: int) -> None:
            capacities.append(capacity)
            self.finished = threading.Event()
            self.finished.set()
            self.failed = False
            self.overflow = False
            self.thread = ThreadStub()

        def start(self) -> None:
            return None

        def bytes(self) -> bytes:
            return b"x"

    monkeypatch.setattr(git_objects, "_BoundedReader", ImmediateReader)
    store = GitObjectStore(_fake_bare_directory(tmp_path))

    assert store.read_bytes("0" * 40, "src/Example.java", max_bytes=100 * 1024 * 1024) == b"x"
    assert capacities == [2]


def test_bounded_read_uses_one_deadline_across_reader_and_process_waits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wait_timeouts: list[float] = []

    class Finished:
        def wait(self, *, timeout: float) -> bool:
            return True

    class ThreadStub:
        def join(self, *_args: object, **_kwargs: object) -> None:
            return None

        def is_alive(self) -> bool:
            return False

    class ImmediateReader:
        def __init__(self, _stream: object, _capacity: int) -> None:
            self.finished = Finished()
            self.failed = False
            self.overflow = False
            self.thread = ThreadStub()

        def start(self) -> None:
            return None

        def bytes(self) -> bytes:
            return b"x"

    class Stream:
        def close(self) -> None:
            return None

    class Process:
        args = ["git"]
        returncode = 0
        stdout = Stream()

        def poll(self) -> int:
            return self.returncode

        def wait(self, timeout: float) -> int:
            wait_timeouts.append(timeout)
            return self.returncode

    monkeypatch.setattr(git_objects, "_BoundedReader", ImmediateReader)
    monkeypatch.setattr(git_objects.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monotonic_values = iter([100.0, 100.04, 100.05])
    monkeypatch.setattr(git_objects.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(git_objects, "_GIT_TIMEOUT_SECONDS", 0.1)

    assert git_objects._read_limited(tmp_path, ("show", "object"), 8) == b"x"
    assert wait_timeouts == [pytest.approx(0.05)]
