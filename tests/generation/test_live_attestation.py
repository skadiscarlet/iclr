"""Native live fail-fast attestation inventory and replay bindings."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from egsi.contracts.case import CaseManifest, load_case_catalog
from egsi.data.context import build_oracle_context
from egsi.data.git_objects import GitObjectStore
from egsi.generation.live_attestation import (
    build_live_attestation,
    create_live_semantic_snapshot,
    inventory_snapshot,
    materialize_live_semantic_snapshot,
    publish_live_candidate_envelope,
    verify_live_candidate_envelope,
    verify_live_candidate_envelope_bytes,
    verify_live_attestation_binding,
    verify_live_semantic_snapshot_against_live,
    verify_locked_live_enrichment,
)


TRUST_ANCHORS = {
    "bootstrap_sha256": "sha256:" + "9" * 64,
    "bootstrap_size": 62326,
    "bootstrap_mode": 0o644,
    "focused_receipt_sha256": "sha256:" + "a" * 64,
    "focused_sidecar_sha256": "sha256:" + "b" * 64,
    "full_receipt_sha256": "sha256:" + "c" * 64,
    "full_sidecar_sha256": "sha256:" + "d" * 64,
    "runner_lock_sha256": "sha256:" + "e" * 64,
    "project_identity_sha256": "sha256:" + "f" * 64,
    "canonical_test_contract_sha256": "sha256:" + "0" * 64,
    "native_launcher_contract_sha256": "sha256:" + "1" * 64,
}


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _git(*arguments: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def _external_semantic_case(
    tmp_path: Path, *, name: str
) -> tuple[Path, Path, Path, Path, Path, CaseManifest]:
    """One external-data fixture with a real bare store and unrelated bulk."""

    root = tmp_path / f"{name}-root"
    external = tmp_path / f"{name}-external-data"
    output = tmp_path / f"{name}-output"
    configs = root / "configs"
    configs.mkdir(parents=True)
    external.mkdir()
    (root / "data").symlink_to(external, target_is_directory=True)
    case_file = configs / "recover_cases.txt"
    scope_file = configs / "p0_cases.txt"
    case_file.write_text("case-a\n", encoding="ascii")
    scope_file.write_text("case-a\n", encoding="ascii")

    worktree = tmp_path / f"{name}-worktree"
    worktree.mkdir()
    _git("init", "-q", cwd=worktree)
    _git("config", "user.email", "test@example.invalid", cwd=worktree)
    _git("config", "user.name", "test", cwd=worktree)
    (worktree / "Vulnerable.java").write_text(
        "class Vulnerable {}\n", encoding="utf-8"
    )
    _git("add", ".", cwd=worktree)
    _git("commit", "-qm", "vulnerable", cwd=worktree)
    commit = _git("rev-parse", "HEAD", cwd=worktree)
    bare = external / "cache/git/example.git"
    bare.parent.mkdir(parents=True)
    _git("clone", "-q", "--bare", str(worktree), str(bare), cwd=tmp_path)

    artifact = external / "artifacts/case-a"
    (artifact / "views").mkdir(parents=True)
    (artifact / "advisory").mkdir()
    (artifact / "patch").mkdir()
    (artifact / "labels").mkdir()
    (artifact / "advisory/raw.json").write_text(
        '{"title":"external advisory"}', encoding="utf-8"
    )
    (artifact / "patch/fix.patch").write_text(
        "diff --git a/Vulnerable.java b/Vulnerable.java\n"
        "--- a/Vulnerable.java\n"
        "+++ b/Vulnerable.java\n"
        "@@ -1,1 +1,1 @@\n"
        "-class Vulnerable {}\n"
        "+class Fixed {}\n",
        encoding="utf-8",
    )
    _write(
        artifact / "views/oracle_view.json",
        {
            "case_id": "case-a",
            "cwe": "CWE-79",
            "repository": {
                "upstream_id": "example/repo",
                "vulnerable_commit": commit,
                "fixed_commit": commit,
            },
            "advisory_path": "data/artifacts/case-a/advisory/raw.json",
            "patch_path": "data/artifacts/case-a/patch/fix.patch",
        },
    )
    _write(
        artifact / "manifest.json",
        {
            "resolution": {
                "cache_path": "data/cache/git/example.git",
                "vulnerable_commit": commit,
                "fixed_commit": commit,
            }
        },
    )
    _write(artifact / "views/policy_view.json", {"case_id": "case-a"})
    _write(artifact / "labels/proof_obligations.json", {"obligations": []})
    unrelated = external / "unrelated/sentinel.bin"
    unrelated.parent.mkdir()
    unrelated.write_bytes(b"must-not-enter-the-semantic-snapshot")
    raw_case = {
        "schema_version": "1.0",
        "case_id": "case-a",
        "evidence_tier": "T1",
        "family": "source_to_sink",
        "cwe_normalized_primary": "CWE-79",
        "split": "train",
        "repository": {
            "url": "https://example.invalid/repo",
            "upstream_id": "example/repo",
            "vulnerable_commit": commit,
            "fixed_commit": commit,
        },
        "artifacts": {
            "patch_path": "data/artifacts/case-a/patch/fix.patch",
            "proof_obligations_path": (
                "data/artifacts/case-a/labels/proof_obligations.json"
            ),
            "manifest_path": "data/artifacts/case-a/manifest.json",
            "test_paths": [],
        },
        "views": {
            "oracle_view_path": "data/artifacts/case-a/views/oracle_view.json",
            "policy_view_path": "data/artifacts/case-a/views/policy_view.json",
            "redaction_manifest_sha256": "sha256:" + "0" * 64,
        },
        "affected_locations": [{"path": "Vulnerable.java"}],
    }
    catalog = external / "catalog/cases.jsonl"
    catalog.parent.mkdir()
    catalog.write_text(
        json.dumps(raw_case, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    state = output / "reports/remaining-p0/semantic-state.txt"
    state.parent.mkdir(parents=True)
    state.write_bytes(b"INVALID")
    return (
        root,
        external,
        output,
        case_file,
        scope_file,
        CaseManifest.model_validate(raw_case),
    )


def _semantic_snapshot_path(output: Path) -> Path:
    return Path(
        str(output / "reports/remaining-p0/fail-fast-live-attestation.json")
        + ".native-snapshot"
    )


def _recommit_semantic_snapshot(value: dict[str, object]) -> tuple[bytes, str]:
    committed = dict(value)
    committed.pop("snapshot_commitment_sha256", None)
    commitment_raw = json.dumps(
        committed, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    value["snapshot_commitment_sha256"] = (
        "sha256:" + hashlib.sha256(commitment_raw).hexdigest()
    )
    raw = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return raw, "sha256:" + hashlib.sha256(raw).hexdigest()


def test_live_semantic_snapshot_pins_external_data_transitive_closure_only(
    tmp_path: Path,
) -> None:
    root, external, output, case_file, scope_file, case = _external_semantic_case(
        tmp_path, name="external-closure"
    )
    live_context = build_oracle_context(root, case)
    snapshot = _semantic_snapshot_path(output)

    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=snapshot,
    )

    value = verify_live_semantic_snapshot_against_live(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    )
    assert value["schema_version"] == "2.0"
    assert value["external_data_boundary"]["mount_kind"] == "external_symlink"
    assert value["external_data_boundary"]["symlink_target"] == str(external)
    source_paths = {
        item["relative_path"]
        for item in value["files"]
        if item["namespace"] == "source"
    }
    assert "data/catalog/cases.jsonl" in source_paths
    assert "data/artifacts/case-a/views/oracle_view.json" in source_paths
    assert "data/unrelated/sentinel.bin" not in source_paths
    assert value["git_query_closure"]

    with materialize_live_semantic_snapshot(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    ) as (replay_root, _, _, _):
        replay_case = load_case_catalog(
            replay_root / "data/catalog/cases.jsonl"
        )[0]
        assert build_oracle_context(replay_root, replay_case) == live_context
        assert not (replay_root / "data/unrelated/sentinel.bin").exists()
        assert not any(
            (replay_root / "data/cache/git/example.git/objects").iterdir()
        )


def test_live_semantic_snapshot_materializes_selected_git_store_with_zero_queries(
    tmp_path: Path,
) -> None:
    root, external, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="zero-query-store"
    )
    (external / "artifacts/case-a/patch/fix.patch").write_text(
        "diff --git a/New.java b/New.java\n"
        "new file mode 100644\n"
        "index 0000000..e69de29\n"
        "--- /dev/null\n"
        "+++ b/New.java\n"
        "@@ -0,0 +1 @@\n"
        "+class New {}\n",
        encoding="utf-8",
    )
    catalog = external / "catalog/cases.jsonl"
    raw_case = json.loads(catalog.read_text(encoding="utf-8"))
    raw_case["affected_locations"] = []
    catalog.write_text(
        json.dumps(raw_case, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    case = load_case_catalog(catalog)[0]
    live_context = build_oracle_context(root, case)

    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )
    value = verify_live_semantic_snapshot_against_live(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    )
    assert value["git_query_closure"] == []
    assert value["git_store_paths"] == ["data/cache/git/example.git"]

    with materialize_live_semantic_snapshot(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    ) as (replay_root, _, _, _):
        replay_store = replay_root / "data/cache/git/example.git"
        assert (replay_store / "HEAD").is_file()
        assert (replay_store / "objects").is_dir()
        assert not any((replay_store / "objects").iterdir())
        replay_case = load_case_catalog(
            replay_root / "data/catalog/cases.jsonl"
        )[0]
        assert build_oracle_context(replay_root, replay_case) == live_context


def test_live_semantic_snapshot_rejects_query_outside_selected_git_store_paths(
    tmp_path: Path,
) -> None:
    root, _, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="query-outside-store-map"
    )
    raw, _ = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )
    value = json.loads(raw)
    assert value["git_query_closure"]
    value["git_store_paths"] = []
    tampered, digest = _recommit_semantic_snapshot(value)

    with pytest.raises(ValueError, match="Git query closure"):
        verify_live_semantic_snapshot_against_live(
            tampered,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )


def test_live_semantic_snapshot_rejects_nonconsumer_git_store_set(
    tmp_path: Path,
) -> None:
    root, _, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="extra-store-map"
    )
    raw, _ = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )
    value = json.loads(raw)
    value["git_store_paths"] = [
        "data/cache/git",
        "data/cache/git/example.git",
    ]
    tampered, digest = _recommit_semantic_snapshot(value)

    with pytest.raises(ValueError, match="closure changed"):
        verify_live_semantic_snapshot_against_live(
            tampered,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )


@pytest.mark.parametrize("descendant_kind", ["escaping_symlink", "fifo"])
def test_live_semantic_snapshot_rejects_consumer_invalid_git_store_descendant(
    tmp_path: Path, descendant_kind: str
) -> None:
    root, external, output, case_file, scope_file, case = _external_semantic_case(
        tmp_path, name=f"git-store-descendant-{descendant_kind}"
    )
    build_oracle_context(root, case)
    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )

    descendant = external / "cache/git/example.git/objects/attacker-node"
    if descendant_kind == "escaping_symlink":
        outside = tmp_path / "outside-object"
        outside.write_bytes(b"not a Git object")
        descendant.symlink_to(outside)
    else:
        os.mkfifo(descendant)

    with pytest.raises(ValueError, match="Git cache") as consumer_error:
        build_oracle_context(root, case)
    with pytest.raises(ValueError, match="Git cache") as verifier_error:
        verify_live_semantic_snapshot_against_live(
            raw,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )
    assert str(verifier_error.value) == str(consumer_error.value)


def test_live_semantic_snapshot_rechecks_git_store_descendants_after_queries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, external, output, case_file, scope_file, case = _external_semantic_case(
        tmp_path, name="git-store-descendant-post-query"
    )
    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )
    descendant = external / "cache/git/example.git/objects/post-query-fifo"
    original_read_bytes = GitObjectStore.read_bytes
    mutated = False

    def mutate_after_read(
        store: GitObjectStore,
        commit: str,
        path: str,
        max_bytes: int = 1_000_000,
    ) -> bytes:
        nonlocal mutated
        result = original_read_bytes(store, commit, path, max_bytes=max_bytes)
        if not mutated:
            os.mkfifo(descendant)
            mutated = True
        return result

    monkeypatch.setattr(GitObjectStore, "read_bytes", mutate_after_read)
    with pytest.raises(ValueError, match="unsupported special file") as verifier_error:
        verify_live_semantic_snapshot_against_live(
            raw,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )
    assert mutated
    with pytest.raises(ValueError, match="unsupported special file") as consumer_error:
        build_oracle_context(root, case)
    assert str(verifier_error.value) == str(consumer_error.value)


def test_live_semantic_snapshot_rejects_loose_object_symlink_aba_during_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, external, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="git-object-symlink-aba"
    )
    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )
    objects = external / "cache/git/example.git/objects"
    outside = tmp_path / "outside-objects"
    shutil.copytree(objects, outside)
    loose_objects = sorted(
        path
        for path in objects.glob("*/*")
        if path.is_file() and len(path.parent.name) == 2 and len(path.name) == 38
    )
    assert loose_objects

    original_read_bytes = GitObjectStore.read_bytes
    mutated = False

    def swap_to_escaping_symlinks_then_restore(
        store: GitObjectStore,
        commit: str,
        path: str,
        max_bytes: int = 1_000_000,
    ) -> bytes:
        nonlocal mutated
        swaps: list[tuple[Path, Path]] = []
        try:
            for loose_object in loose_objects:
                saved = loose_object.with_name(loose_object.name + ".safe")
                loose_object.rename(saved)
                loose_object.symlink_to(outside / loose_object.relative_to(objects))
                swaps.append((loose_object, saved))
            mutated = True
            return original_read_bytes(store, commit, path, max_bytes=max_bytes)
        finally:
            for loose_object, saved in reversed(swaps):
                loose_object.unlink()
                saved.rename(loose_object)

    monkeypatch.setattr(
        GitObjectStore, "read_bytes", swap_to_escaping_symlinks_then_restore
    )
    with pytest.raises(
        ValueError,
        match="Git cache identity closure changed",
    ):
        verify_live_semantic_snapshot_against_live(
            raw,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )
    assert mutated
    assert all(not path.is_symlink() for path in loose_objects)
    assert not any(objects.rglob("*.safe"))


@pytest.mark.parametrize(
    "ignored_extra",
    [
        "data/unrelated/sentinel.bin",
        {"data/unrelated/sentinel.bin": "ignored extension key"},
        "data/ is a descriptive prefix, not a declared artifact path",
    ],
    ids=["extra-value", "extra-key", "descriptive-data-prefix"],
)
def test_live_semantic_snapshot_does_not_dereference_case_extensions(
    tmp_path: Path,
    ignored_extra: object,
) -> None:
    root, external, output, case_file, scope_file, case_before = (
        _external_semantic_case(tmp_path, name="ignored-case-extension")
    )
    catalog = external / "catalog/cases.jsonl"
    raw_case = json.loads(catalog.read_text(encoding="utf-8"))
    raw_case["ignored_extra"] = ignored_extra
    catalog.write_text(
        json.dumps(raw_case, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    case_after = CaseManifest.model_validate(raw_case)
    context_before = build_oracle_context(root, case_before)
    context_after = build_oracle_context(root, case_after)
    assert context_after == context_before

    sentinel = external / "unrelated/sentinel.bin"
    original = sentinel.read_bytes()
    sentinel.write_bytes(b"semantically-irrelevant-mutated-bytes")
    assert build_oracle_context(root, case_after) == context_after
    sentinel.write_bytes(original)

    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=_semantic_snapshot_path(output),
    )
    value = verify_live_semantic_snapshot_against_live(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    )
    source_paths = {
        item["relative_path"]
        for item in value["files"]
        if item["namespace"] == "source"
    }
    assert "data/unrelated/sentinel.bin" not in source_paths
    with materialize_live_semantic_snapshot(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    ) as (replay_root, _, _, _):
        assert not (replay_root / "data/unrelated/sentinel.bin").exists()


def test_live_semantic_snapshot_rejects_external_data_target_swap(
    tmp_path: Path,
) -> None:
    root, external, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="external-swap"
    )
    snapshot = _semantic_snapshot_path(output)
    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=snapshot,
    )
    replacement = tmp_path / "external-swap-replacement"
    replacement.mkdir()
    data_mount = root / "data"
    data_mount.unlink()
    data_mount.symlink_to(replacement, target_is_directory=True)

    with pytest.raises(ValueError, match="external data boundary changed"):
        verify_live_semantic_snapshot_against_live(
            raw,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )


def test_live_semantic_snapshot_rejects_nested_external_data_symlink_escape(
    tmp_path: Path,
) -> None:
    root, external, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="external-nested-symlink"
    )
    oracle = external / "artifacts/case-a/views/oracle_view.json"
    outside = tmp_path / "attacker-oracle.json"
    outside.write_bytes(oracle.read_bytes())
    oracle.unlink()
    oracle.symlink_to(outside)

    with pytest.raises(ValueError, match="data closure contains a symlink"):
        create_live_semantic_snapshot(
            root=root,
            output_root=output,
            case_file=case_file,
            scope_case_file=scope_file,
            snapshot_path=_semantic_snapshot_path(output),
        )


def test_live_semantic_snapshot_rejects_selected_external_data_fifo_without_blocking(
    tmp_path: Path,
) -> None:
    root, external, output, case_file, scope_file, _ = _external_semantic_case(
        tmp_path, name="external-fifo"
    )
    patch = external / "artifacts/case-a/patch/fix.patch"
    patch.unlink()
    os.mkfifo(patch)

    with pytest.raises(ValueError, match="data closure contains a special node"):
        create_live_semantic_snapshot(
            root=root,
            output_root=output,
            case_file=case_file,
            scope_case_file=scope_file,
            snapshot_path=_semantic_snapshot_path(output),
        )


def test_live_semantic_snapshot_is_canonical_materializable_and_ctime_bound(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    output = tmp_path / "output"
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    case_file.parent.mkdir(parents=True)
    case_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="ascii")
    scope_file.write_text("ghsa-3wfj-vh84-732p\n", encoding="ascii")
    state = output / "reports/remaining-p0/semantic-state.txt"
    state.parent.mkdir(parents=True)
    state.write_bytes(b"INVALID")
    state.chmod(0o600)
    snapshot = Path(
        str(
            output
            / "reports/remaining-p0/fail-fast-live-attestation.json"
        )
        + ".native-snapshot"
    )

    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=snapshot,
    )

    assert snapshot.read_bytes() == raw
    assert snapshot.stat().st_mode & 0o777 == 0o600
    value = verify_live_semantic_snapshot_against_live(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    )
    assert value["schema_version"] == "2.0"
    assert value["snapshot_kind"] == "native_live_semantic_inputs"
    with materialize_live_semantic_snapshot(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    ) as (_, replay_output, replay_case, replay_scope):
        assert replay_case.read_bytes() == case_file.read_bytes()
        assert replay_scope.read_bytes() == scope_file.read_bytes()
        assert (
            replay_output / "reports/remaining-p0/semantic-state.txt"
        ).read_bytes() == b"INVALID"

    before = state.stat()
    descriptor = os.open(state, os.O_WRONLY)
    try:
        os.pwrite(descriptor, b"VALID-B", 0)
        os.fsync(descriptor)
        os.pwrite(descriptor, b"INVALID", 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.utime(state, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert state.read_bytes() == b"INVALID"
    assert state.stat().st_ino == before.st_ino
    assert state.stat().st_ctime_ns != before.st_ctime_ns
    with pytest.raises(ValueError, match="ordinary file changed"):
        verify_live_semantic_snapshot_against_live(
            raw,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )


def test_live_semantic_snapshot_preserves_output_invocation_directory_mtime_order(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    output = tmp_path / "output"
    case_file = root / "configs/recover_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    case_file.parent.mkdir(parents=True)
    case_file.write_text("case-a\n", encoding="ascii")
    scope_file.write_text("case-a\n", encoding="ascii")
    invocation_times = {
        "invocation-newer": 1_700_000_000_000_000_003,
        "invocation-older": 1_700_000_000_000_000_001,
    }
    request_hash = "a" * 64
    for invocation, mtime_ns in invocation_times.items():
        manifest = (
            output
            / "audit/teacher"
            / request_hash
            / invocation
            / "attempt-00/manifest.json"
        )
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(b"{}")
        invocation_root = manifest.parent.parent
        os.utime(invocation_root, ns=(mtime_ns, mtime_ns))
        assert invocation_root.stat().st_mtime_ns == mtime_ns

    snapshot = _semantic_snapshot_path(output)
    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=snapshot,
    )

    with materialize_live_semantic_snapshot(
        raw,
        expected_sha256=digest,
        source_root=root,
        output_root=output,
    ) as (_, replay_output, _, _):
        replay_times = {
            invocation: (
                replay_output / "audit/teacher" / request_hash / invocation
            ).stat().st_mtime_ns
            for invocation in invocation_times
        }
        assert replay_times == invocation_times
        assert sorted(replay_times, key=replay_times.get) == [
            "invocation-older",
            "invocation-newer",
        ]


def test_live_semantic_snapshot_rejects_bundle_tamper_and_live_file_set_change(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    output = tmp_path / "output"
    case_file = root / "configs/recover_3wfj_cases.txt"
    scope_file = root / "configs/p0_cases.txt"
    case_file.parent.mkdir(parents=True)
    case_file.write_text("case-a\n", encoding="ascii")
    scope_file.write_text("case-a\n", encoding="ascii")
    _write(output / "reports/enrichment-summary.json", {"status": "ok"})
    snapshot = Path(
        str(
            output
            / "reports/remaining-p0/fail-fast-live-attestation.json"
        )
        + ".native-snapshot"
    )
    raw, digest = create_live_semantic_snapshot(
        root=root,
        output_root=output,
        case_file=case_file,
        scope_case_file=scope_file,
        snapshot_path=snapshot,
    )

    with pytest.raises(ValueError, match="snapshot bytes"):
        verify_live_semantic_snapshot_against_live(
            raw[:-2] + b"X\n",
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )
    _write(output / "reports/remaining-p0/uncommitted.json", {"new": True})
    with pytest.raises(ValueError, match="file set changed"):
        verify_live_semantic_snapshot_against_live(
            raw,
            expected_sha256=digest,
            source_root=root,
            output_root=output,
        )


def test_live_attestation_binds_exact_created_attempt_and_outputs(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    case_id = "ghsa-3wfj-vh84-732p"
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    response_commitment = "sha256:" + "8" * 64
    cache_path = "cache/teacher/current.json"
    _write(
        output / manifest,
        {"status": "committed", "response_commitment_sha256": response_commitment},
    )
    _write(
        output / cache_path,
        {"text": "{}", "response_commitment_sha256": response_commitment},
    )
    _write(output / f"enrichment/{case_id}.json", {"case_id": case_id})
    _write(output / "enrichment/_batch-provenance.json", {"stage": "p"})
    _write(output / "reports/enrichment-summary.json", {"stage": "s"})
    _write(
        output / "reports/remaining-p0/fail-fast-report.json",
        {"report_commitment_sha256": "sha256:" + "2" * 64},
    )
    post = inventory_snapshot(output)
    value = build_live_attestation(
        output_root=output,
        case_file_sha256="sha256:" + "3" * 64,
        scope_case_file_sha256="sha256:" + "4" * 64,
        requested_case_ids=[case_id],
        current_manifest_paths=[manifest],
        current_response_commitments=[response_commitment],
        current_cache_paths=[cache_path],
        run_id="a" * 64,
        nonce="b" * 64,
        realtime_start_ns=10,
        monotonic_start_ns=20,
        realtime_end_ns=30,
        monotonic_end_ns=40,
        child_exit_code=0,
        recovery_mode="explicit_reattestation",
        target_reason="native_live_attestation_for_prompt_v2_3",
        **TRUST_ANCHORS,
        native_contract_sha256="sha256:" + "5" * 64,
        public_key_id="sha256:" + "6" * 64,
        provider_executable_identities=["sha256:" + "7" * 64],
        pre_inventory=pre,
        post_inventory=post,
    )

    verify_live_attestation_binding(value, output_root=output)
    assert value["delta"]["created"]
    assert value["pre_inventory_sha256"] != value["post_inventory_sha256"]


def test_live_candidate_envelope_binds_exact_json_and_native_fields(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    case_id = "ghsa-3wfj-vh84-732p"
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    response = "sha256:" + "8" * 64
    cache = "cache/teacher/current.json"
    _write(output / manifest, {"status": "committed"})
    _write(output / cache, {"response_commitment_sha256": response})
    _write(output / "enrichment/_batch-provenance.json", {"stage": "p"})
    _write(output / "reports/enrichment-summary.json", {"stage": "s"})
    _write(output / "reports/remaining-p0/fail-fast-report.json", {"stage": "r"})
    post = inventory_snapshot(output)
    value = build_live_attestation(
        output_root=output,
        case_file_sha256="sha256:" + "3" * 64,
        scope_case_file_sha256="sha256:" + "4" * 64,
        requested_case_ids=[case_id],
        current_manifest_paths=[manifest],
        current_response_commitments=[response],
        current_cache_paths=[cache],
        run_id="a" * 64,
        nonce="b" * 64,
        realtime_start_ns=10,
        monotonic_start_ns=20,
        realtime_end_ns=30,
        monotonic_end_ns=40,
        child_exit_code=0,
        recovery_mode="explicit_reattestation",
        target_reason="native_live_attestation_for_prompt_v2_3",
        **TRUST_ANCHORS,
        native_contract_sha256="sha256:" + "5" * 64,
        public_key_id="sha256:" + "6" * 64,
        provider_executable_identities=["sha256:" + "7" * 64],
        pre_inventory=pre,
        post_inventory=post,
    )
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    _write(attestation, value)
    attestation.chmod(0o600)
    envelope = Path(str(attestation) + ".native-candidate")

    publish_live_candidate_envelope(
        envelope, attestation_path=attestation, value=value
    )
    verify_live_candidate_envelope(
        envelope, attestation_path=attestation, value=value
    )
    raw = envelope.read_bytes()
    held_attestation_raw = attestation.read_bytes()
    verify_live_candidate_envelope_bytes(
        raw, attestation_raw=held_attestation_raw, value=value
    )
    assert raw.startswith(b"EGSI-LIVE-CANDIDATE-V1\n")
    assert raw.endswith(
        (
            "attestation_commitment_sha256="
            + value["attestation_commitment_sha256"]
            + "\n"
        ).encode("ascii")
    )

    attestation.write_text('{"detached":true}\n', encoding="ascii")
    attestation.chmod(0o600)
    verify_live_candidate_envelope_bytes(
        raw, attestation_raw=held_attestation_raw, value=value
    )
    with pytest.raises(ValueError, match="candidate"):
        verify_live_candidate_envelope(
            envelope, attestation_path=attestation, value=value
        )


def test_live_attestation_binds_terminal_transport_stop_without_cache(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    case_id = "ghsa-3wfj-vh84-732p"
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    executable_identity = "sha256:" + "7" * 64
    _write(
        output / manifest,
        {
            "status": "quarantined",
            "failure_code": "provider_failure_event",
            "response_commitment_sha256": None,
            "provider_response_model": None,
            "usage": None,
            "executable_identity_commitment_sha256": executable_identity,
        },
    )
    (output / manifest).with_name("events.metadata.jsonl").write_text(
        '{"index":0,"type":"thread.started"}\n'
        '{"index":1,"type":"turn.started"}\n'
        '{"index":2,"type":"error"}\n',
        encoding="utf-8",
    )
    _write(
        (output / manifest).with_name("quarantine.json"),
        {
            "schema_version": "1.0",
            "status": "quarantined",
            "failure_code": "provider_failure_event",
            "positive_transition_written": False,
        },
    )
    _write(output / f"enrichment/failures/{case_id}.json", {"error_kind": "transport"})
    _write(output / "enrichment/_batch-provenance.json", {"stage": "p"})
    _write(
        output / "reports/enrichment-summary.json",
        {"status": "REMAINING_P0_CASE_RECOVERY_STOPPED"},
    )
    _write(
        output / "reports/remaining-p0/fail-fast-report.json",
        {"status": "REMAINING_P0_CASE_RECOVERY_STOPPED"},
    )
    post = inventory_snapshot(output)

    value = build_live_attestation(
        output_root=output,
        case_file_sha256="sha256:" + "3" * 64,
        scope_case_file_sha256="sha256:" + "4" * 64,
        requested_case_ids=[case_id],
        current_manifest_paths=[manifest],
        current_response_commitments=[None],
        current_cache_paths=[None],
        run_id="a" * 64,
        nonce="b" * 64,
        realtime_start_ns=10,
        monotonic_start_ns=20,
        realtime_end_ns=30,
        monotonic_end_ns=40,
        child_exit_code=120,
        recovery_mode="explicit_reattestation",
        target_reason="native_live_attestation_for_prompt_v2_3",
        **TRUST_ANCHORS,
        native_contract_sha256="sha256:" + "5" * 64,
        public_key_id="sha256:" + "6" * 64,
        provider_executable_identities=[executable_identity],
        pre_inventory=pre,
        post_inventory=post,
    )

    verify_live_attestation_binding(value, output_root=output)
    assert value["terminal_status"] == "STOP"
    assert value["child_exit_code"] == 120
    assert value["current_response_commitments"] == [None]
    assert value["current_cache_paths"] == [None]


def test_live_attestation_rejects_preexisting_attempt_even_with_old_mtime(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/fake/attempt-00/manifest.json"
    _write(output / manifest, {"fabricated": True})
    os.utime(output / manifest, ns=(946684800_000_000_000,) * 2)
    pre = inventory_snapshot(output)
    post = inventory_snapshot(output)

    with pytest.raises(ValueError, match="prebaseline"):
        build_live_attestation(
            output_root=output,
            case_file_sha256="sha256:" + "3" * 64,
            scope_case_file_sha256="sha256:" + "4" * 64,
            requested_case_ids=["ghsa-3wfj-vh84-732p"],
            current_manifest_paths=[manifest],
            current_response_commitments=["sha256:" + "8" * 64],
            current_cache_paths=["cache/teacher/current.json"],
            run_id="a" * 64,
            nonce="b" * 64,
            realtime_start_ns=10,
            monotonic_start_ns=20,
            realtime_end_ns=30,
            monotonic_end_ns=40,
            child_exit_code=0,
            recovery_mode="explicit_reattestation",
            target_reason="native_live_attestation_for_prompt_v2_3",
            **TRUST_ANCHORS,
            native_contract_sha256="sha256:" + "5" * 64,
            public_key_id="sha256:" + "6" * 64,
            provider_executable_identities=["sha256:" + "7" * 64],
            pre_inventory=pre,
            post_inventory=post,
        )


def test_live_attestation_rejects_recommitted_delta_or_run_id(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    response_commitment = "sha256:" + "8" * 64
    cache_path = "cache/teacher/current.json"
    _write(
        output / manifest,
        {"status": "committed", "response_commitment_sha256": response_commitment},
    )
    _write(
        output / cache_path,
        {"response_commitment_sha256": response_commitment},
    )
    _write(output / "enrichment/_batch-provenance.json", {"stage": "p"})
    _write(output / "reports/enrichment-summary.json", {"stage": "s"})
    _write(output / "reports/remaining-p0/fail-fast-report.json", {"stage": "r"})
    post = inventory_snapshot(output)
    value = build_live_attestation(
        output_root=output,
        case_file_sha256="sha256:" + "3" * 64,
        scope_case_file_sha256="sha256:" + "4" * 64,
        requested_case_ids=["ghsa-3wfj-vh84-732p"],
        current_manifest_paths=[manifest],
        current_response_commitments=[response_commitment],
        current_cache_paths=[cache_path],
        run_id="a" * 64,
        nonce="b" * 64,
        realtime_start_ns=10,
        monotonic_start_ns=20,
        realtime_end_ns=30,
        monotonic_end_ns=40,
        child_exit_code=0,
        recovery_mode="explicit_reattestation",
        target_reason="native_live_attestation_for_prompt_v2_3",
        **TRUST_ANCHORS,
        native_contract_sha256="sha256:" + "5" * 64,
        public_key_id="sha256:" + "6" * 64,
        provider_executable_identities=["sha256:" + "7" * 64],
        pre_inventory=pre,
        post_inventory=post,
    )
    value["run_id"] = "c" * 64

    with pytest.raises(ValueError, match="attestation"):
        verify_live_attestation_binding(value, output_root=output)


def test_live_inventory_rejects_symlinked_or_hardlinked_evidence(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    outside = tmp_path / "outside"
    _write(outside / "manifest.json", {"fabricated": True})
    (output / "audit").mkdir(parents=True)
    (output / "audit/teacher").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="unsafe|symlink"):
        inventory_snapshot(output)

    (output / "audit/teacher").unlink()
    original = output / "audit/teacher/original.json"
    _write(original, {"fabricated": True})
    os.link(original, output / "audit/teacher/copy.json")
    with pytest.raises(ValueError, match="unsafe|hardlink"):
        inventory_snapshot(output)


def test_bootstrap_pre_snapshot_exactly_matches_runtime_snapshot(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    _write(output / "audit/teacher/a/manifest.json", {"status": "committed"})
    _write(output / "cache/teacher/a.json", {"text": "{}"})
    _write(output / "enrichment/case.json", {"case_id": "case"})
    _write(output / "reports/remaining-p0/fail-fast-report.json", {"status": "ok"})
    _write(output / "reports/enrichment-summary.json", {"status": "ok"})
    _write(
        output / "reports/remaining-p0/fail-fast-live-attestation.json",
        {"excluded": True},
    )
    _write(
        output
        / "reports/remaining-p0/fail-fast-live-attestation.json.native-attestation",
        {"excluded": True},
    )
    bootstrap = runpy.run_path(
        str(Path(__file__).resolve().parents[2] / "scripts/locked_runtime_bootstrap.py"),
        run_name="egsi_live_snapshot_contract_test",
    )

    assert bootstrap["_live_inventory_snapshot"](output) == inventory_snapshot(output)


def test_bootstrap_pre_snapshot_rejects_symlinked_evidence_root(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    outside = tmp_path / "outside"
    _write(outside / "manifest.json", {"fabricated": True})
    (output / "audit").mkdir(parents=True)
    (output / "audit/teacher").symlink_to(outside, target_is_directory=True)
    bootstrap = runpy.run_path(
        str(Path(__file__).resolve().parents[2] / "scripts/locked_runtime_bootstrap.py"),
        run_name="egsi_live_snapshot_symlink_test",
    )

    with pytest.raises(ValueError, match="unsafe|symlink"):
        bootstrap["_live_inventory_snapshot"](output)


def test_live_attestation_requires_all_public_batch_artifacts(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    response_commitment = "sha256:" + "8" * 64
    cache_path = "cache/teacher/current.json"
    _write(
        output / manifest,
        {"status": "committed", "response_commitment_sha256": response_commitment},
    )
    _write(
        output / cache_path,
        {"response_commitment_sha256": response_commitment},
    )
    post = inventory_snapshot(output)

    with pytest.raises(ValueError, match="artifact"):
        build_live_attestation(
            output_root=output,
            case_file_sha256="sha256:" + "3" * 64,
            scope_case_file_sha256="sha256:" + "4" * 64,
            requested_case_ids=["ghsa-3wfj-vh84-732p"],
            current_manifest_paths=[manifest],
            current_response_commitments=[response_commitment],
            current_cache_paths=[cache_path],
            run_id="a" * 64,
            nonce="b" * 64,
            realtime_start_ns=10,
            monotonic_start_ns=20,
            realtime_end_ns=30,
            monotonic_end_ns=40,
            child_exit_code=0,
            recovery_mode="explicit_reattestation",
            target_reason="native_live_attestation_for_prompt_v2_3",
            **TRUST_ANCHORS,
            native_contract_sha256="sha256:" + "5" * 64,
            public_key_id="sha256:" + "6" * 64,
            provider_executable_identities=["sha256:" + "7" * 64],
            pre_inventory=pre,
            post_inventory=post,
        )


def test_live_attestation_rejects_preexisting_current_response_cache(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    response_commitment = "sha256:" + "8" * 64
    cache_path = "cache/teacher/" + "9" * 64 + ".json"
    _write(
        output / cache_path,
        {"response_commitment_sha256": response_commitment},
    )
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    _write(
        output / manifest,
        {"response_commitment_sha256": response_commitment},
    )
    _write(output / "enrichment/_batch-provenance.json", {"stage": "p"})
    _write(output / "reports/enrichment-summary.json", {"stage": "s"})
    _write(output / "reports/remaining-p0/fail-fast-report.json", {"stage": "r"})
    post = inventory_snapshot(output)

    with pytest.raises(ValueError, match="cache.*prebaseline"):
        build_live_attestation(
            output_root=output,
            case_file_sha256="sha256:" + "3" * 64,
            scope_case_file_sha256="sha256:" + "4" * 64,
            requested_case_ids=["ghsa-3wfj-vh84-732p"],
            current_manifest_paths=[manifest],
            current_response_commitments=[response_commitment],
            current_cache_paths=[cache_path],
            run_id="a" * 64,
            nonce="b" * 64,
            realtime_start_ns=10,
            monotonic_start_ns=20,
            realtime_end_ns=30,
            monotonic_end_ns=40,
            child_exit_code=0,
            recovery_mode="explicit_reattestation",
            target_reason="native_live_attestation_for_prompt_v2_3",
            **TRUST_ANCHORS,
            native_contract_sha256="sha256:" + "5" * 64,
            public_key_id="sha256:" + "6" * 64,
            provider_executable_identities=["sha256:" + "7" * 64],
            pre_inventory=pre,
            post_inventory=post,
        )


def test_locked_live_verifier_rechecks_inventory_after_semantic_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    output = tmp_path / "output"
    case_id = "ghsa-3wfj-vh84-732p"
    case_file = root / "case.txt"
    scope_file = root / "scope.txt"
    case_file.parent.mkdir(parents=True)
    case_file.write_text(case_id + "\n", encoding="utf-8")
    scope_file.write_text(case_id + "\n", encoding="utf-8")
    contract = "sha256:" + "5" * 64
    key_id = "sha256:" + "6" * 64
    _write(
        root / "configs/native-signer-build-record.json",
        {
            "native_contract_sha256": contract,
            "public_key": {"key_id": key_id},
        },
    )
    pre = inventory_snapshot(output)
    manifest = "audit/teacher/sha256:" + "1" * 64 + "/run/attempt-00/manifest.json"
    executable_identity = "sha256:" + "7" * 64
    response_commitment = "sha256:" + "8" * 64
    cache_path = "cache/teacher/current.json"
    _write(
        output / manifest,
        {
            "status": "committed",
            "executable_identity_commitment_sha256": executable_identity,
            "response_commitment_sha256": response_commitment,
        },
    )
    _write(
        output / cache_path,
        {"response_commitment_sha256": response_commitment},
    )
    _write(output / "enrichment/_batch-provenance.json", {"stage": "p"})
    _write(output / "reports/enrichment-summary.json", {"stage": "s"})
    report_path = output / "reports/remaining-p0/fail-fast-report.json"
    _write(report_path, {"stage": "r"})
    post = inventory_snapshot(output)
    from egsi.generation.pilot import _read_regular, _sha256

    value = build_live_attestation(
        output_root=output,
        case_file_sha256=_sha256(_read_regular(case_file, limit=64 * 1024)),
        scope_case_file_sha256=_sha256(
            _read_regular(scope_file, limit=64 * 1024)
        ),
        requested_case_ids=[case_id],
        current_manifest_paths=[manifest],
        current_response_commitments=[response_commitment],
        current_cache_paths=[cache_path],
        run_id="a" * 64,
        nonce="b" * 64,
        realtime_start_ns=10,
        monotonic_start_ns=20,
        realtime_end_ns=30,
        monotonic_end_ns=40,
        child_exit_code=0,
        recovery_mode="explicit_reattestation",
        target_reason="native_live_attestation_for_prompt_v2_3",
        **TRUST_ANCHORS,
        native_contract_sha256=contract,
        public_key_id=key_id,
        provider_executable_identities=[executable_identity],
        pre_inventory=pre,
        post_inventory=post,
    )
    attestation = output / "reports/remaining-p0/fail-fast-live-attestation.json"
    _write(attestation, value)
    replayed = SimpleNamespace(
        current_attempts=[SimpleNamespace(manifest_path=manifest)],
        recovery_mode="explicit_reattestation",
        target_reason="native_live_attestation_for_prompt_v2_3",
        status="REMAINING_P0_CASE_RECOVERED_AWAITING_REVIEW",
    )

    def mutate_during_replay(**_: object) -> SimpleNamespace:
        _write(report_path, {"stage": "raced"})
        return replayed

    monkeypatch.setattr(
        "egsi.generation.fail_fast_batch.verify_fail_fast_report",
        mutate_during_replay,
    )

    with pytest.raises(ValueError, match="attestation|inventory"):
        verify_locked_live_enrichment(
            root=root,
            output_root=output,
            case_file=case_file,
            scope_case_file=scope_file,
            attestation_path=attestation,
        )
