"""Oracle-only teacher-context contracts."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from egsi.contracts.case import CaseManifest
from egsi.data.context import OracleContext, bounded, build_oracle_context

context_module = importlib.import_module("egsi.data.context")


COMMIT = "a" * 40


def _run(*args: str, cwd: Path, env: dict[str, str] | None = None) -> str:
    process_env = os.environ.copy()
    if env is not None:
        process_env.update(env)
    return subprocess.run(
        args,
        cwd=cwd,
        env=process_env,
        check=True,
        text=True,
        capture_output=True,
    ).stdout


def _write_case(
    root: Path,
    *,
    locations: list[dict[str, object]] | None = None,
    files: dict[str, str] | None = None,
    patch: str | None = None,
) -> CaseManifest:
    artifact = root / "data/artifacts/case"
    (artifact / "views").mkdir(parents=True)
    (artifact / "advisory").mkdir()
    (artifact / "patch").mkdir()
    (root / "data/cache/git").mkdir(parents=True)
    source = root / "source"
    source.mkdir()
    _run("git", "init", "-q", cwd=source)
    _run("git", "config", "user.email", "test@example.invalid", cwd=source)
    _run("git", "config", "user.name", "test", cwd=source)
    if files is None:
        files = {"a.txt": "alpha\n", "dir/b.txt": "beta\n"}
    for relative, text in files.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    _run("git", "add", ".", cwd=source)
    _run(
        "git", "commit", "-qm", "initial", cwd=source,
        env={
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00 +0000",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00 +0000",
        },
    )
    commit = _run("git", "rev-parse", "HEAD", cwd=source).strip()
    bare = root / "data/cache/git/test.git"
    _run("git", "clone", "-q", "--bare", str(source), str(bare), cwd=root)

    advisory = '{"title":"advisory"}'
    if patch is None:
        patch = (
            "diff --git a/a.txt b/a.txt\n"
            "--- a/a.txt\n"
            "+++ b/a.txt\n"
            "@@ -1,1 +1,1 @@\n"
            "-alpha\n"
            "+fixed\n"
        )
    (artifact / "advisory/raw.json").write_text(advisory, encoding="utf-8")
    (artifact / "patch/fix.patch").write_text(patch, encoding="utf-8")
    oracle = {
        "case_id": "case",
        "cwe": "CWE-79",
        "repository": {
            "upstream_id": "owner/repo",
            "vulnerable_commit": commit,
            "fixed_commit": commit,
        },
        "advisory_path": "data/artifacts/case/advisory/raw.json",
        "patch_path": "data/artifacts/case/patch/fix.patch",
    }
    (artifact / "views/oracle_view.json").write_text(json.dumps(oracle), encoding="utf-8")
    manifest = {
        "resolution": {
            "cache_path": "data/cache/git/test.git",
            "vulnerable_commit": commit,
            "fixed_commit": commit,
        }
    }
    (artifact / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    raw_case = {
        "schema_version": "1.0", "case_id": "case", "evidence_tier": "T1",
        "family": "source_to_sink", "cwe_normalized_primary": "CWE-79", "split": "train",
        "repository": {"url": "https://example.invalid/repo", "upstream_id": "owner/repo", "vulnerable_commit": commit, "fixed_commit": commit},
        "artifacts": {"patch_path": "data/artifacts/case/patch/fix.patch", "proof_obligations_path": "x", "manifest_path": "data/artifacts/case/manifest.json"},
        "views": {"oracle_view_path": "data/artifacts/case/views/oracle_view.json", "policy_view_path": "x", "redaction_manifest_sha256": "sha256:" + "0" * 64},
        "affected_locations": locations if locations is not None else [{"path": "dir/b.txt"}, {"path": "a.txt"}, {"path": "a.txt"}, {"path": "missing.txt"}],
    }
    return CaseManifest.model_validate(raw_case)


def _add_fixed_revision(root: Path, case: CaseManifest) -> CaseManifest:
    source = root / "source"
    (source / "a.txt").write_text("fixed\n", encoding="utf-8")
    _run("git", "add", "a.txt", cwd=source)
    _run(
        "git", "commit", "-qm", "fixed", cwd=source,
        env={
            "GIT_AUTHOR_DATE": "2000-01-02T00:00:00 +0000",
            "GIT_COMMITTER_DATE": "2000-01-02T00:00:00 +0000",
        },
    )
    fixed_commit = _run("git", "rev-parse", "HEAD", cwd=source).strip()
    bare = root / "data/cache/git/test.git"
    _run("git", "push", "-q", str(bare), "HEAD:refs/heads/master", cwd=source)
    manifest_path = root / case.artifacts.manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resolution"]["fixed_commit"] = fixed_commit
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    oracle_path = root / case.views.oracle_view_path
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle["repository"]["fixed_commit"] = fixed_commit
    oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
    return CaseManifest.model_validate(
        {
            **case.model_dump(mode="json"),
            "repository": {
                **case.repository.model_dump(mode="json"),
                "fixed_commit": fixed_commit,
            },
        }
    )


def test_build_context_from_bare_repo_is_bounded_and_hashes_canonical_render(tmp_path: Path) -> None:
    case = _write_case(tmp_path)

    context = build_oracle_context(tmp_path, case)

    assert context.case_id == "case"
    assert list(context.source_files) == ["a.txt", "dir/b.txt"]
    assert context.advisory == '{"title":"advisory"}'
    assert context.patch.startswith("diff --git")
    assert len(context.render()) <= 64_000
    assert context.sha256 == "sha256:" + hashlib.sha256(context.render().encode("utf-8")).hexdigest()
    assert "sha256" not in json.loads(context.render())


def test_bounded_handles_limits_unicode_and_escaping() -> None:
    assert bounded("abc", 0) == ""
    assert bounded("abc", -3) == ""
    assert bounded("é😀", 3) == "é😀"
    value = bounded("abcdefghij", 9)
    assert len(value) <= 9
    assert value != "abcdefghij"
    assert bounded('"\\\n' * 20, 8) == bounded('"\\\n' * 20, 8)


def test_context_rejects_tampered_digest_and_extra_fields() -> None:
    fields = dict(case_id="c", repository="r", vulnerable_commit=COMMIT, family="authorization", cwe="CWE-79", advisory="a", patch="p", source_files={}, sha256="sha256:" + "0" * 64)
    with pytest.raises(ValidationError):
        OracleContext(**fields)
    valid = OracleContext.create(**{key: value for key, value in fields.items() if key != "sha256"})
    with pytest.raises(ValidationError):
        OracleContext.model_validate({**valid.model_dump(), "extra": 1})


@pytest.mark.parametrize("total_chars", [False, 0, -1, 10])
def test_build_rejects_invalid_or_impossibly_small_total_budget(tmp_path: Path, total_chars: int) -> None:
    case = _write_case(tmp_path)
    with pytest.raises(ValueError):
        build_oracle_context(tmp_path, case, total_chars=total_chars)


def test_build_rejects_path_traversal_and_symlink_escape(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    oracle_path = tmp_path / case.views.oracle_view_path
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle["advisory_path"] = "../outside"
    oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
    with pytest.raises(ValueError):
        build_oracle_context(tmp_path, case)

    case = _write_case(tmp_path / "second")
    artifact = (tmp_path / "second/data/artifacts/case")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (artifact / "advisory/raw.json").unlink()
    (artifact / "advisory/raw.json").symlink_to(outside)
    with pytest.raises(ValueError):
        build_oracle_context(tmp_path / "second", case)


def test_metadata_that_cannot_fit_budget_fails_explicitly(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    with pytest.raises(ValueError, match="metadata"):
        build_oracle_context(tmp_path, case, total_chars=100)


def test_deterministic_context_ignores_location_order_and_missing_sources(tmp_path: Path) -> None:
    first = _write_case(tmp_path / "one", locations=[{"path": "dir/b.txt"}, {"path": "missing"}, {"path": "a.txt"}])
    time.sleep(1.1)
    second = _write_case(
        tmp_path / "two",
        locations=[{"path": "a.txt"}, {"path": "missing"}, {"path": "dir/b.txt"}, {"path": "a.txt"}],
    )
    one = build_oracle_context(tmp_path / "one", first)
    two = build_oracle_context(tmp_path / "two", second)
    assert one.source_files == two.source_files
    assert one.render() == two.render()
    assert one.sha256 == two.sha256


def test_real_catalog_first_case_builds_when_external_artifacts_are_available() -> None:
    root = Path(__file__).parents[2]
    catalog = root / "data/catalog/cases.jsonl"
    if not catalog.exists():
        pytest.skip("external catalog is unavailable")
    case = CaseManifest.model_validate_json(catalog.read_text(encoding="utf-8").splitlines()[0])
    try:
        context = build_oracle_context(root, case)
    except ValueError as exc:
        pytest.skip(f"external artifacts are unavailable: {exc}")
    assert context.advisory
    assert context.patch
    assert len(context.render()) <= 64_000
    assert context.sha256 == "sha256:" + hashlib.sha256(context.render().encode("utf-8")).hexdigest()


def test_bounded_small_truncation_limit_is_marker_prefix() -> None:
    marker = "\n...[deterministically truncated]...\n"
    assert bounded("abcdefgh", 4) == marker[:4]


def test_context_source_files_are_deeply_immutable_and_copy_cannot_stale_digest() -> None:
    context = OracleContext.create(
        case_id="c", repository="r", vulnerable_commit=COMMIT,
        family="authorization", cwe="CWE-79", advisory="a", patch="p",
        source_files={"a.txt": "source"},
    )
    with pytest.raises(TypeError):
        context.source_files["x.txt"] = "mutated"  # type: ignore[index]
    with pytest.raises(ValidationError):
        context.model_copy(update={"source_files": {"x.txt": "mutated"}})
    copied = context.model_copy(deep=True)
    assert copied.source_files == context.source_files
    assert copied.sha256 == context.sha256


def test_build_rejects_git_objects_symlink_escaping_allowed_boundary(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    bare = tmp_path / "data/cache/git/test.git"
    outside = tmp_path.parent / f"{tmp_path.name}-outside-objects"
    outside.mkdir()
    objects = bare / "objects"
    objects.rename(bare / "objects.real")
    objects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="Git cache"):
        build_oracle_context(tmp_path, case)


def test_build_accepts_root_data_symlink_mount(tmp_path: Path) -> None:
    backing = tmp_path / "backing"
    case = _write_case(backing)
    root = tmp_path / "mounted"
    root.mkdir()
    (root / "data").symlink_to(backing / "data", target_is_directory=True)

    context = build_oracle_context(root, case)

    assert context.case_id == "case"


def test_context_does_not_share_or_expose_mutable_source_file_state() -> None:
    import copy
    from dataclasses import FrozenInstanceError

    source_files = {"a.txt": "before"}
    context = OracleContext.create(
        case_id="c", repository="r", vulnerable_commit=COMMIT,
        family="authorization", cwe="CWE-79", advisory="a", patch="p",
        source_files=source_files,
    )
    source_files["a.txt"] = "after"
    assert context.source_files["a.txt"] == "before"
    with pytest.raises(FrozenInstanceError):
        context.source_files._items = ()  # type: ignore[misc]
    assert not hasattr(context.source_files, "__dict__")
    for clone in (copy.copy(context), copy.deepcopy(context)):
        assert clone.render() == context.render()
        assert clone.sha256 == context.sha256

@pytest.mark.parametrize("relative", ["objects/aa", "objects/pack"])
def test_build_rejects_git_object_store_descendant_symlink_escape(
    tmp_path: Path, relative: str
) -> None:
    case = _write_case(tmp_path)
    bare = tmp_path / "data/cache/git/test.git"
    target = bare / relative
    target.mkdir(exist_ok=True)
    outside = tmp_path.parent / f"{tmp_path.name}-{target.name}-outside"
    outside.mkdir()
    target.rmdir()
    target.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="Git cache"):
        build_oracle_context(tmp_path, case)



def test_build_rejects_oracle_cwe_mismatch(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    path = tmp_path / case.views.oracle_view_path
    oracle = json.loads(path.read_text(encoding="utf-8"))
    oracle["cwe"] = "CWE-89"
    path.write_text(json.dumps(oracle), encoding="utf-8")

    with pytest.raises(ValueError, match="oracle metadata"):
        build_oracle_context(tmp_path, case)


def test_build_rejects_oracle_patch_path_mismatch(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    alternate = tmp_path / "data/artifacts/case/patch/alternate.patch"
    alternate.write_text("different patch", encoding="utf-8")
    path = tmp_path / case.views.oracle_view_path
    oracle = json.loads(path.read_text(encoding="utf-8"))
    oracle["patch_path"] = "data/artifacts/case/patch/alternate.patch"
    path.write_text(json.dumps(oracle), encoding="utf-8")

    with pytest.raises(ValueError, match="patch path"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "malformed",
    ['[' * 3_000 + 'invalid' + ']' * 3_000, '{"integer":' + "1" * 5_000 + "}"],
    ids=["deep-nesting", "oversized-integer"],
)
def test_build_normalizes_pathological_json_parse_errors(tmp_path: Path, malformed: str) -> None:
    case = _write_case(tmp_path)
    (tmp_path / case.views.oracle_view_path).write_text(malformed, encoding="utf-8")

    with pytest.raises(ValueError, match="^declared JSON file is malformed$") as error:
        build_oracle_context(tmp_path, case)
    assert error.value.__cause__ is None


def test_build_rejects_excess_locations_before_any_git_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _write_case(tmp_path, locations=[{"path": f"src/{index}.txt"} for index in range(257)])
    calls = 0

    class UnexpectedGitStore:
        def __init__(self, *_: object) -> None:
            nonlocal calls
            calls += 1
            raise AssertionError("Git must not be initialized")

    monkeypatch.setattr(context_module, "GitObjectStore", UnexpectedGitStore)
    with pytest.raises(ValueError, match="affected location"):
        build_oracle_context(tmp_path, case)
    assert calls == 0


def test_context_v2_declares_versioned_patch_hunk_policy(tmp_path: Path) -> None:
    case = _write_case(tmp_path)

    context = build_oracle_context(tmp_path, case)

    assert context.context_version == "2.0"
    assert context.selection_policy_id == "patch-hunk-v1"


def test_context_v2_commits_raw_inputs_blobs_and_ordered_chunks(tmp_path: Path) -> None:
    case = _write_case(tmp_path)
    raw_patch = (tmp_path / case.artifacts.patch_path).read_bytes()

    context = build_oracle_context(tmp_path, case)

    assert [chunk.path for chunk in context.source_chunks] == ["a.txt", "dir/b.txt"]
    assert all(chunk.text_sha256 == "sha256:" + hashlib.sha256(chunk.text.encode()).hexdigest()
               for chunk in context.source_chunks)
    receipt = context.selection_receipt
    assert receipt.algorithm_version == "patch-hunk-v1"
    assert receipt.schema_version == "1.1"
    assert receipt.effective_patch_source == "raw"
    assert receipt.raw_patch_sha256 == "sha256:" + hashlib.sha256(raw_patch).hexdigest()
    assert receipt.raw_patch_byte_count == len(raw_patch)
    assert receipt.effective_patch_sha256 == receipt.raw_patch_sha256
    assert receipt.effective_patch_byte_count == receipt.raw_patch_byte_count
    assert [(blob.path, blob.availability) for blob in receipt.source_blobs] == [
        ("a.txt", "available"),
        ("dir/b.txt", "available"),
        ("missing.txt", "missing"),
    ]
    assert [blob.selection_reason for blob in receipt.source_blobs] == [
        "patch_hunk",
        "affected_location",
        "affected_location",
    ]
    canonical = receipt.model_dump(mode="json", exclude={"receipt_commitment_sha256"})
    expected = "sha256:" + hashlib.sha256(json.dumps(
        canonical, allow_nan=False, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"),
    ).encode()).hexdigest()
    assert receipt.receipt_commitment_sha256 == expected


def test_valid_raw_patch_never_invokes_canonical_diff_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _write_case(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("valid raw patch invoked fallback")

    monkeypatch.setattr(context_module.GitObjectStore, "canonical_diff", forbidden)

    context = build_oracle_context(tmp_path, case)

    assert context.selection_receipt.effective_patch_source == "raw"


def test_structurally_corrupt_raw_patch_uses_pinned_canonical_diff(
    tmp_path: Path,
) -> None:
    corrupt = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n"
        "+++ b/a.txt\n"
        "@@ -1,2 +1,1 @@\n"
        "-alpha\n"
        "+fixed\n"
    )
    case = _add_fixed_revision(tmp_path, _write_case(tmp_path, patch=corrupt))
    raw_patch = (tmp_path / case.artifacts.patch_path).read_bytes()

    context = build_oracle_context(tmp_path, case)

    receipt = context.selection_receipt
    assert receipt.schema_version == "1.1"
    assert receipt.effective_patch_source == "canonical_git_diff"
    assert receipt.raw_patch_sha256 == "sha256:" + hashlib.sha256(raw_patch).hexdigest()
    assert receipt.raw_patch_byte_count == len(raw_patch)
    assert receipt.effective_patch_sha256 != receipt.raw_patch_sha256
    assert receipt.effective_patch_byte_count > 0
    assert context.patch.startswith("diff --git")
    assert "@@ -1 +1 @@" in context.patch


def test_manifest_resolution_commits_must_match_the_case_manifest(
    tmp_path: Path,
) -> None:
    case = _write_case(tmp_path)
    manifest_path = tmp_path / case.artifacts.manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resolution"]["fixed_commit"] = "b" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="resolution"):
        build_oracle_context(tmp_path, case)


def test_receipt_rejects_effective_patch_commitment_tampering(tmp_path: Path) -> None:
    context = build_oracle_context(tmp_path, _write_case(tmp_path))
    payload = context.model_dump(mode="python")
    payload["selection_receipt"]["effective_patch_byte_count"] += 1

    with pytest.raises(ValidationError, match="commitment"):
        OracleContext.model_validate(payload)


@pytest.mark.parametrize(
    "fallback",
    [
        lambda *_args: b"not a diff\n",
        lambda *_args: b"x" * (2 * 1024 * 1024 + 1),
        lambda *_args: (_ for _ in ()).throw(RuntimeError("git command timed out")),
        lambda *_args: (_ for _ in ()).throw(RuntimeError("canonical Git diff failed")),
    ],
    ids=["corrupt", "oversize", "timeout", "nonzero"],
)
def test_canonical_fallback_failures_leave_context_failed_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback
) -> None:
    corrupt = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,2 +1,1 @@\n-alpha\n+fixed\n"
    )
    case = _add_fixed_revision(tmp_path, _write_case(tmp_path, patch=corrupt))
    monkeypatch.setattr(context_module.GitObjectStore, "canonical_diff", fallback)

    with pytest.raises(ValueError, match="hunk line counts"):
        build_oracle_context(tmp_path, case)


def test_fallback_rejects_a_fixed_oid_that_is_not_a_commit_in_the_cache(
    tmp_path: Path,
) -> None:
    corrupt = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,2 +1,1 @@\n-alpha\n+fixed\n"
    )
    case = _write_case(tmp_path, patch=corrupt)
    absent = "b" * 40
    case = CaseManifest.model_validate(
        {
            **case.model_dump(mode="json"),
            "repository": {
                **case.repository.model_dump(mode="json"),
                "fixed_commit": absent,
            },
        }
    )
    oracle_path = tmp_path / case.views.oracle_view_path
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    oracle["repository"]["fixed_commit"] = absent
    oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
    manifest_path = tmp_path / case.artifacts.manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resolution"]["fixed_commit"] = absent
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="hunk line counts"):
        build_oracle_context(tmp_path, case)


def test_patch_hunk_windows_use_old_lines_and_merge_overlaps(tmp_path: Path) -> None:
    source = "".join(f"line-{line}\n" for line in range(1, 201))
    patch = (
        "diff --git a/src/Main.java b/src/Main.java\n"
        "--- a/src/Main.java\n"
        "+++ b/src/Main.java\n"
        "@@ -60,1 +60,1 @@\n-line-60\n+fixed-60\n"
        "@@ -100,1 +100,1 @@\n-line-100\n+fixed-100\n"
    )
    case = _write_case(
        tmp_path,
        files={"src/Main.java": source},
        patch=patch,
        locations=[{"path": "src/Main.java"}],
    )

    context = build_oracle_context(tmp_path, case)

    assert len(context.source_chunks) == 1
    chunk = context.source_chunks[0]
    assert (chunk.path, chunk.start_line, chunk.end_line) == ("src/Main.java", 20, 140)
    assert chunk.text.startswith("line-20\n")
    assert chunk.text.endswith("line-140\n")
    assert chunk.truncated_before and chunk.truncated_after
    assert context.source_files["src/Main.java"] == chunk.text
    assert context.selection_receipt.source_blobs[0].hunk_count == 2


def test_fixture_teacher_accepts_patch_only_new_file_context(tmp_path: Path) -> None:
    patch = (
        "diff --git a/src/New.java b/src/New.java\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/src/New.java\n"
        "@@ -0,0 +1,1 @@\n+new line\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])
    context = build_oracle_context(tmp_path, case)
    assert len(context.source_files) == 0
    assert context.source_files == {}

    from egsi.teacher.base import TeacherRequest
    from egsi.teacher.fixture import FixtureTeacher
    from egsi.teacher.prompts import enrichment_request
    from egsi.generation.enrichment import _prompt_vocabulary, allowed_action_values

    system, user, schema = enrichment_request(
        context,
        _prompt_vocabulary(allowed_action_values(Path("."))),
        repair_attempt=0,
    )
    response = FixtureTeacher().generate(
        TeacherRequest(system=system, user=user, schema=schema)
    )
    payload = json.loads(response.text)
    assert payload["locations"][0]["path"] == "src/New.java"
    assert payload["trace"][0]["target_kind"] == "repository"


def test_large_raw_patch_and_source_are_bounded_but_fully_committed(tmp_path: Path) -> None:
    patch_prefix = (
        b"diff --git a/src/Large.java b/src/Large.java\n"
        b"--- a/src/Large.java\n+++ b/src/Large.java\n"
        b"@@ -1,1 +1,1 @@\n-line-1\n+fixed\n"
    )
    remaining_patch_bytes = (2 * 1024 * 1024) - len(patch_prefix)
    filler_line = b"x" * 60_000 + b"\n"
    raw_patch = (
        patch_prefix
        + filler_line * (remaining_patch_bytes // len(filler_line))
        + b"x" * (remaining_patch_bytes % len(filler_line))
    )
    source_prefix = "".join(f"line-{line}\n" for line in range(1, 101))
    source = source_prefix + "x" * ((4 * 1024 * 1024) - len(source_prefix.encode()))
    case = _write_case(
        tmp_path,
        files={"src/Large.java": source},
        patch=raw_patch.decode(),
        locations=[{"path": "src/Large.java"}],
    )

    context = build_oracle_context(tmp_path, case)

    assert len(context.patch) <= 24_000
    assert len(context.render()) <= 64_000
    assert context.selection_receipt.raw_patch_byte_count == 2 * 1024 * 1024
    blob = context.selection_receipt.source_blobs[0]
    assert blob.blob_byte_count == 4 * 1024 * 1024
    assert blob.blob_sha256 == "sha256:" + hashlib.sha256(source.encode()).hexdigest()
    assert context.source_chunks[0].end_line == 41


@pytest.mark.parametrize("kind", ["patch", "source"])
def test_raw_input_hard_limits_reject_one_extra_byte(tmp_path: Path, kind: str) -> None:
    patch = (
        "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,1 +1,1 @@\n-a\n+fixed\n"
    )
    files = {"a.txt": "a\n"}
    if kind == "patch":
        patch += "x" * ((2 * 1024 * 1024 + 1) - len(patch.encode()))
    else:
        files = {"a.txt": "x" * (4 * 1024 * 1024 + 1)}
    case = _write_case(tmp_path, files=files, patch=patch, locations=[{"path": "a.txt"}])

    with pytest.raises(ValueError):
        build_oracle_context(tmp_path, case)


def test_patch_files_are_prioritized_and_hunks_are_selected_round_robin(tmp_path: Path) -> None:
    lines = "".join(f"line-{line}\n" for line in range(1, 8001))

    def section(path: str, starts: list[int]) -> str:
        return (
            f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            + "".join(
                f"@@ -{start},1 +{start},1 @@\n-old\n+new\n" for start in starts
            )
        )

    patch = (
        section("tests/Test.java", [30])
        + section("src/A.java", [50 + 100 * index for index in range(70)])
        + section("src/B.java", [40])
    )
    case = _write_case(
        tmp_path,
        files={"tests/Test.java": lines, "src/A.java": lines, "src/B.java": lines},
        patch=patch,
        locations=[],
    )

    context = build_oracle_context(tmp_path, case)

    assert [chunk.path for chunk in context.source_chunks[:3]] == [
        "src/A.java",
        "src/B.java",
        "tests/Test.java",
    ]
    assert context.selection_receipt.omitted_hunk_count >= 8
    assert len(context.selection_receipt.selected_chunks) <= 64


def test_candidate_file_limit_records_omissions(tmp_path: Path) -> None:
    files = {f"src/F{index:02}.java": "line\n" for index in range(35)}
    patch = "".join(
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n+++ b/{path}\n"
        "@@ -1,1 +1,1 @@\n-line\n+fixed\n"
        for path in files
    )
    case = _write_case(tmp_path, files=files, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    assert len(context.selection_receipt.source_blobs) == 32
    assert context.selection_receipt.omitted_file_count == 3


def test_rename_delete_new_only_and_missing_blob_availability(tmp_path: Path) -> None:
    patch = (
        "diff --git a/old.java b/renamed.java\n"
        "similarity index 90%\nrename from old.java\nrename to renamed.java\n"
        "--- a/old.java\n+++ b/renamed.java\n"
        "@@ -1,1 +1,1 @@\n-old\n+renamed\n"
        "diff --git a/deleted.java b/deleted.java\n"
        "deleted file mode 100644\n--- a/deleted.java\n+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n-delete\n"
        "diff --git a/new.java b/new.java\n"
        "new file mode 100644\n--- /dev/null\n+++ b/new.java\n"
        "@@ -0,0 +1,1 @@\n+new\n"
        "diff --git a/missing.java b/missing.java\n"
        "--- a/missing.java\n+++ b/missing.java\n"
        "@@ -1,1 +1,1 @@\n-missing\n+fixed\n"
    )
    case = _write_case(
        tmp_path,
        files={"old.java": "old\n", "deleted.java": "delete\n"},
        patch=patch,
        locations=[],
    )

    context = build_oracle_context(tmp_path, case)

    availability = {
        blob.path: (blob.availability, blob.patch_new_path)
        for blob in context.selection_receipt.source_blobs
    }
    assert availability == {
        "old.java": ("available", "renamed.java"),
        "deleted.java": ("available", None),
        "new.java": ("new_only", "new.java"),
        "missing.java": ("missing", "missing.java"),
    }
    assert context.selection_receipt.new_only_paths == ("new.java",)
    assert context.selection_receipt.missing_paths == ("missing.java",)


@pytest.mark.parametrize(
    "patch",
    [
        "diff --git a/../../escape b/../../escape\n",
        "diff --git a/a.txt b/a.txt\nGIT binary patch\nliteral 1\nA\n",
        "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ malformed @@\n",
    ],
)
def test_unsafe_malformed_or_binary_patch_fails_closed(tmp_path: Path, patch: str) -> None:
    case = _write_case(tmp_path, patch=patch)
    with pytest.raises(ValueError):
        build_oracle_context(tmp_path, case)


def test_unicode_quoted_paths_and_compact_canonical_render_are_deterministic(tmp_path: Path) -> None:
    path = "src/é file.java"
    source = '前缀 "\\ 😀\n第二行\n'
    patch = (
        f'diff --git "a/{path}" "b/{path}"\n'
        f'--- "a/{path}"\n+++ "b/{path}"\n'
        '@@ -1,1 +1,1 @@\n-前缀 "\\ 😀\n+修复\n'
    )
    case = _write_case(tmp_path, files={path: source}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)
    rendered = context.render()

    assert context.source_chunks[0].path == path
    assert rendered == json.dumps(
        json.loads(rendered), allow_nan=False, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    )
    assert "前缀" in rendered and "😀" in rendered


def test_git_c_quoted_utf8_paths_are_decoded_before_validation(tmp_path: Path) -> None:
    path = "src/é.java"
    quoted = '"a/src/\\303\\251.java"'
    quoted_new = '"b/src/\\303\\251.java"'
    patch = (
        f"diff --git {quoted} {quoted_new}\n"
        f"--- {quoted}\n+++ {quoted_new}\n"
        "@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    case = _write_case(tmp_path, files={path: "old\n"}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    assert context.source_chunks[0].path == path


def test_multi_file_traditional_unified_diff_is_parsed_deterministically(tmp_path: Path) -> None:
    patch = (
        "--- a/one.txt\n+++ b/one.txt\n"
        "@@ -1,1 +1,1 @@\n-one\n+ONE\n"
        "--- a/two.txt\n+++ b/two.txt\n"
        "@@ -1,1 +1,1 @@\n-two\n+TWO\n"
    )
    case = _write_case(
        tmp_path,
        files={"one.txt": "one\n", "two.txt": "two\n"},
        patch=patch,
        locations=[],
    )

    context = build_oracle_context(tmp_path, case)

    assert [chunk.path for chunk in context.source_chunks] == ["one.txt", "two.txt"]


def test_apostrophe_in_unquoted_git_path_is_not_treated_as_shell_syntax(tmp_path: Path) -> None:
    path = "src/foo'bar.java"
    patch = (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        "@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    case = _write_case(tmp_path, files={path: "old\n"}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    assert context.source_chunks[0].path == path


def test_patch_touched_test_file_precedes_affected_only_production_overflow(tmp_path: Path) -> None:
    patched = "tests/Patched.java"
    affected = [f"src/F{index:02}.java" for index in range(32)]
    files = {patched: "old\n", **{path: "line\n" for path in affected}}
    patch = (
        f"diff --git a/{patched} b/{patched}\n"
        f"--- a/{patched}\n+++ b/{patched}\n"
        "@@ -1,1 +1,1 @@\n-old\n+fixed\n"
    )
    case = _write_case(
        tmp_path,
        files=files,
        patch=patch,
        locations=[{"path": path} for path in affected],
    )

    context = build_oracle_context(tmp_path, case)

    selected_paths = {blob.path for blob in context.selection_receipt.source_blobs}
    assert patched in selected_paths
    assert context.selection_receipt.omitted_file_count == 1


def test_conflicting_git_and_unified_file_headers_fail_closed(tmp_path: Path) -> None:
    patch = (
        "diff --git a/A.java b/A.java\n"
        "--- a/B.java\n+++ b/B.java\n"
        "@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    case = _write_case(tmp_path, files={"A.java": "old\n", "B.java": "old\n"}, patch=patch)

    with pytest.raises(ValueError, match="header"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "patch",
    ["GIT binary patch\nliteral 1\nA\n", "@@ -1,1 +1,1 @@\n-old\n+new\n"],
)
def test_orphan_structural_patch_markers_fail_closed(tmp_path: Path, patch: str) -> None:
    case = _write_case(tmp_path, patch=patch)
    with pytest.raises(ValueError):
        build_oracle_context(tmp_path, case)


def test_orphan_new_file_header_fails_closed(tmp_path: Path) -> None:
    case = _write_case(tmp_path, patch="+++ b/a.txt\n")

    with pytest.raises(ValueError, match="header"):
        build_oracle_context(tmp_path, case)


def test_git_diff_with_unpaired_old_header_fails_closed(tmp_path: Path) -> None:
    patch = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n"
    case = _write_case(tmp_path, patch=patch)

    with pytest.raises(ValueError, match="header"):
        build_oracle_context(tmp_path, case)


def test_hunk_rejects_extra_addition_after_declared_counts_are_exhausted(
    tmp_path: Path,
) -> None:
    patch = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,1 +1,1 @@\n-alpha\n+fixed\n+orphan-extra\n"
    )
    case = _write_case(tmp_path, patch=patch)

    with pytest.raises(ValueError, match="hunk"):
        build_oracle_context(tmp_path, case)


def test_new_file_dev_null_header_requires_matching_diff_identity(tmp_path: Path) -> None:
    patch = (
        "diff --git a/A.java b/B.java\n"
        "--- /dev/null\n+++ b/B.java\n"
        "@@ -0,0 +1,1 @@\n+new\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    with pytest.raises(ValueError, match="header"):
        build_oracle_context(tmp_path, case)


def test_extended_index_metadata_requires_a_git_object_id_pair(tmp_path: Path) -> None:
    patch = (
        "diff --git a/empty.txt b/empty.txt\n"
        "new file mode 100644\n"
        "index garbage\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    with pytest.raises(ValueError, match="index"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "mode, index_line, old_header, new_header, hunk",
    [
        (
            "new file mode 100644",
            "index 0000000..e69de29",
            "--- a/a.txt",
            "+++ b/a.txt",
            "@@ -1,1 +1,1 @@\n-alpha\n+fixed",
        ),
        (
            "deleted file mode 100644",
            "index e69de29..0000000",
            "--- a/a.txt",
            "+++ b/a.txt",
            "@@ -1,1 +1,1 @@\n-alpha\n+fixed",
        ),
    ],
    ids=["new-file-with-old-side", "deleted-file-with-new-side"],
)
def test_file_creation_or_deletion_mode_requires_the_dev_null_side(
    tmp_path: Path,
    mode: str,
    index_line: str,
    old_header: str,
    new_header: str,
    hunk: str,
) -> None:
    patch = (
        "diff --git a/a.txt b/a.txt\n"
        f"{mode}\n{index_line}\n{old_header}\n{new_header}\n{hunk}\n"
    )
    case = _write_case(tmp_path, files={"a.txt": "alpha\n"}, patch=patch, locations=[])

    with pytest.raises(ValueError, match="metadata"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "patch",
    [
        "+orphan\n",
        "diff --git a/a.txt b/a.txt\n+orphan\n",
    ],
    ids=["plain-orphan-body", "git-diff-orphan-body"],
)
def test_patch_body_line_outside_hunk_fails_closed(tmp_path: Path, patch: str) -> None:
    case = _write_case(tmp_path, patch=patch)

    with pytest.raises(ValueError, match="outside.*hunk"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "patch",
    [
        "",
        "arbitrary advisory-like plain text\n",
        "\\ No newline at end of file\n",
    ],
    ids=["empty", "plain-text", "orphan-no-newline-marker"],
)
def test_context_v2_requires_a_complete_unified_diff_section(
    tmp_path: Path, patch: str
) -> None:
    case = _write_case(tmp_path, patch=patch)

    with pytest.raises(ValueError, match="unified diff"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "body",
    [
        "\\ No newline at end of file\n-alpha\n+fixed\n",
        "-alpha\n\\ No newline at end of file\n\\ No newline at end of file\n+fixed\n",
        "-alpha\n+fixed\n\n\\ No newline at end of file\n",
    ],
    ids=["first-hunk-line", "consecutive", "isolated-after-blank"],
)
def test_no_newline_marker_must_immediately_follow_one_hunk_body_line(
    tmp_path: Path, body: str
) -> None:
    patch = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,1 +1,1 @@\n"
        + body
    )
    case = _write_case(tmp_path, patch=patch)

    with pytest.raises(ValueError, match="newline marker"):
        build_oracle_context(tmp_path, case)


def test_legal_no_newline_markers_do_not_change_hunk_line_counts(
    tmp_path: Path,
) -> None:
    patch = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,1 +1,1 @@\n"
        "-alpha\n"
        "\\ No newline at end of file\n"
        "+fixed\n"
        "\\ No newline at end of file\n"
    )
    case = _write_case(tmp_path, patch=patch)

    context = build_oracle_context(tmp_path, case)

    assert context.selection_receipt.source_blobs[0].hunk_count == 1


def test_complete_git_extended_rename_without_hunks_is_accepted(tmp_path: Path) -> None:
    patch = (
        "diff --git a/old.txt b/new.txt\n"
        "similarity index 100%\n"
        "rename from old.txt\n"
        "rename to new.txt\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    blob = context.selection_receipt.source_blobs[0]
    assert (blob.path, blob.patch_new_path, blob.hunk_count, blob.selection_reason) == (
        "old.txt",
        "new.txt",
        0,
        "metadata_only",
    )
    assert context.source_chunks == ()


@pytest.mark.parametrize(
    "metadata",
    [
        "similarity index 101%",
        "similarity index 01%",
        "similarity index 1.5%",
        "dissimilarity index -1%",
    ],
)
def test_extended_similarity_percentages_use_canonical_zero_to_one_hundred_format(
    tmp_path: Path, metadata: str
) -> None:
    patch = (
        "diff --git a/old.txt b/new.txt\n"
        f"{metadata}\n"
        "rename from old.txt\n"
        "rename to new.txt\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    with pytest.raises(ValueError, match="index metadata"):
        build_oracle_context(tmp_path, case)


def test_extended_section_cannot_mix_rename_and_copy_metadata(tmp_path: Path) -> None:
    patch = (
        "diff --git a/old.txt b/new.txt\n"
        "similarity index 100%\n"
        "rename from old.txt\n"
        "rename to new.txt\n"
        "copy from old.txt\n"
        "copy to new.txt\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    with pytest.raises(ValueError, match="rename.*copy|copy.*rename"):
        build_oracle_context(tmp_path, case)


@pytest.mark.parametrize(
    "metadata",
    [
        "rename to new.txt\nrename from old.txt",
        "copy to new.txt\ncopy from old.txt",
        "similarity index 90%\nsimilarity index 90%\nrename from old.txt\nrename to new.txt",
        "similarity score 90%\nrename from old.txt\nrename to new.txt",
    ],
    ids=["rename-order", "copy-order", "duplicate-similarity", "unknown-git-metadata"],
)
def test_extended_metadata_order_duplicates_and_git_like_unknowns_fail_closed(
    tmp_path: Path, metadata: str
) -> None:
    patch = f"diff --git a/old.txt b/new.txt\n{metadata}\n"
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    with pytest.raises(ValueError, match="metadata"):
        build_oracle_context(tmp_path, case)


def test_mixed_text_and_git_binary_patch_records_binary_without_source_chunk(
    tmp_path: Path,
) -> None:
    patch = (
        "diff --git a/a.txt b/a.txt\n"
        "--- a/a.txt\n+++ b/a.txt\n"
        "@@ -1,1 +1,1 @@\n-alpha\n+fixed\n"
        "diff --git a/a.bin b/a.bin\n"
        "index f76dd238ade08917e6712764a16a22005a50573d..ce542efaa5124a0437f0c4db329d7ec4b7ba70a7 100644\n"
        "GIT binary patch\n"
        "literal 1\n"
        "Icmewl0096200000\n"
        "\n"
        "literal 1\n"
        "IcmZPo000310RR91\n"
    )
    case = _write_case(
        tmp_path,
        files={"a.txt": "alpha\n", "a.bin": "old\n"},
        patch=patch,
        locations=[],
    )

    context = build_oracle_context(tmp_path, case)

    assert [chunk.path for chunk in context.source_chunks] == ["a.txt"]
    binary = next(
        blob for blob in context.selection_receipt.source_blobs if blob.path == "a.bin"
    )
    assert (binary.selection_reason, binary.hunk_count, binary.availability) == (
        "binary_patch",
        0,
        "available",
    )


def test_git_binary_patch_can_rename_while_changing_contents(tmp_path: Path) -> None:
    patch = (
        "diff --git a/old.bin b/new.bin\n"
        "similarity index 93%\n"
        "rename from old.bin\n"
        "rename to new.bin\n"
        "index 06d7405020018ddf3cacee90fd4af10487da3d20..dbba09bb2653b5189cab408a775f0141767b78e3 100644\n"
        "GIT binary patch\n"
        "delta 12\n"
        "TcmZqRXyBNT!uWq9<7{RC8|eg9\n"
        "\n"
        "literal 1024\n"
        "RcmZP=1*0J_8UiCW1ONm800961\n"
    )
    case = _write_case(
        tmp_path,
        files={"old.bin": "old binary fixture\n"},
        patch=patch,
        locations=[],
    )

    context = build_oracle_context(tmp_path, case)

    blob = context.selection_receipt.source_blobs[0]
    assert (blob.path, blob.patch_new_path, blob.selection_reason) == (
        "old.bin",
        "new.bin",
        "binary_patch",
    )
    assert context.source_chunks == ()


def test_binary_files_summary_splits_git_quoted_paths_not_embedded_and_text(
    tmp_path: Path,
) -> None:
    path = "src/é and x.bin"
    old = '"a/src/\\303\\251 and x.bin"'
    new = '"b/src/\\303\\251 and x.bin"'
    patch = (
        f"diff --git {old} {new}\n"
        "index f76dd238ade08917e6712764a16a22005a50573d..ce542efaa5124a0437f0c4db329d7ec4b7ba70a7 100644\n"
        f"Binary files {old} and {new} differ\n"
    )
    case = _write_case(tmp_path, files={path: "old\n"}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    blob = context.selection_receipt.source_blobs[0]
    assert (blob.path, blob.selection_reason) == (path, "binary_patch")
    assert context.source_chunks == ()


def test_binary_summary_scans_embedded_and_delimiters_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "src/" + " and ".join(f"part{index}" for index in range(200)) + ".bin"
    old = f'"a/{path}"'
    new = f'"b/{path}"'
    patch = (
        f"diff --git {old} {new}\n"
        "index f76dd238ade08917e6712764a16a22005a50573d..ce542efaa5124a0437f0c4db329d7ec4b7ba70a7 100644\n"
        f"Binary files {old} and {new} differ\n"
    )
    calls = 0
    real_patch_path = context_module._patch_path

    def counted_patch_path(value: str, prefix: str) -> str | None:
        nonlocal calls
        calls += 1
        return real_patch_path(value, prefix)

    monkeypatch.setattr(context_module, "_patch_path", counted_patch_path)

    parsed = context_module._parse_patch(patch.encode())

    assert (parsed[0].old_path, parsed[0].new_path) == (path, path)
    assert calls == 4


def test_binary_summary_scanner_preserves_c_escaped_quotes(tmp_path: Path) -> None:
    path = 'src/a" and b.bin'
    old = '"a/src/a\\" and b.bin"'
    new = '"b/src/a\\" and b.bin"'
    patch = (
        f"diff --git {old} {new}\n"
        "index f76dd238ade08917e6712764a16a22005a50573d..ce542efaa5124a0437f0c4db329d7ec4b7ba70a7 100644\n"
        f"Binary files {old} and {new} differ\n"
    )
    case = _write_case(tmp_path, files={path: "old\n"}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    assert context.selection_receipt.source_blobs[0].path == path


def test_patch_parser_rejects_an_oversized_single_line() -> None:
    patch = (
        ("x" * 65_537)
        + "\ndiff --git a/a.txt b/a.txt\n"
        + "--- a/a.txt\n+++ b/a.txt\n"
        + "@@ -1,1 +1,1 @@\n-alpha\n+fixed\n"
    )

    with pytest.raises(ValueError, match="line.*limit"):
        context_module._parse_patch(patch.encode())


def test_complete_empty_new_file_extended_diff_is_patch_only(tmp_path: Path) -> None:
    patch = (
        "diff --git a/empty.txt b/empty.txt\n"
        "new file mode 100644\n"
        "index 0000000..e69de29\n"
    )
    case = _write_case(tmp_path, files={"old.txt": "old\n"}, patch=patch, locations=[])

    context = build_oracle_context(tmp_path, case)

    assert len(context.source_chunks) == 0
    assert context.selection_receipt.new_only_paths == ("empty.txt",)


def test_receipt_and_chunk_manifest_tampering_is_rejected(tmp_path: Path) -> None:
    context = build_oracle_context(tmp_path, _write_case(tmp_path))
    payload = context.model_dump(mode="python")
    assert OracleContext.model_validate(payload) == context
    payload["selection_receipt"]["omitted_file_count"] += 1
    with pytest.raises(ValidationError):
        OracleContext.model_validate(payload)

    payload = context.model_dump(mode="python")
    payload["source_chunks"][0]["text"] += "tamper"
    with pytest.raises(ValidationError):
        OracleContext.model_validate(payload)


def test_direct_context_construction_cannot_bypass_evidence_limits() -> None:
    with pytest.raises(ValidationError):
        OracleContext.create(
            case_id="c", repository="r", vulnerable_commit=COMMIT,
            family="authorization", cwe="CWE-79", advisory="a" * 12_001,
            patch="p", source_files={},
        )

def test_requested_render_budget_is_enforced_below_global_cap(tmp_path: Path) -> None:
    source = "".join(f"line-{line}-{'x' * 100}\n" for line in range(1, 500))
    case = _write_case(tmp_path, files={"a.txt": source}, locations=[{"path": "a.txt"}])

    context = build_oracle_context(tmp_path, case, total_chars=5_000)

    assert len(context.render()) <= 5_000


def test_build_oracle_context_closes_guard_fds_with_retained_failure_traceback(
    tmp_path: Path,
) -> None:
    case = _write_case(tmp_path)
    (tmp_path / "data/cache/git/test.git/config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        encoding="utf-8",
    )
    before = len(os.listdir("/proc/self/fd"))
    retained_error: Exception | None = None

    try:
        build_oracle_context(tmp_path, case)
    except Exception as exc:
        retained_error = exc

    assert isinstance(retained_error, ValueError)
    assert len(os.listdir("/proc/self/fd")) == before
