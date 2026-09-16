"""Tests for policy-facing bootstrap seed redaction."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from egsi.contracts.case import CaseManifest, load_case_catalog
from egsi.generation.redaction import (
    FORBIDDEN_KEYS,
    MAX_DEPTH,
    MAX_NODES,
    build_policy_seed,
    key_hits,
    policy_case_id,
    sha,
    verify_policy_seed,
)

CATALOG_PATH = Path(__file__).parents[2] / "data/catalog/cases.jsonl"


def _first_case() -> CaseManifest:
    return load_case_catalog(CATALOG_PATH)[0]


def test_real_case_generates_exact_bootstrap_seed_and_hash_manifest() -> None:
    case = _first_case()

    seed, manifest = build_policy_seed(case)

    assert seed == {
        "schema_version": "1.0",
        "case_id": policy_case_id(case),
        "state": "BOOTSTRAP",
        "repository": {
            "upstream_id": case.repository.upstream_id,
            "vulnerable_commit": case.repository.vulnerable_commit,
        },
        "budget": {
            "seconds": 900,
            "tool_calls": 20,
            "tokens": 16000,
            "analysis_units": 20.0,
        },
        "bounded_history": [],
        "unknowns": ["entrypoint", "security_invariant", "guard", "impact"],
    }
    assert key_hits(seed) == set()
    serialized_output = json.dumps({"seed": seed, "manifest": manifest}, ensure_ascii=False)
    assert case.cwe_normalized_primary not in serialized_output
    assert case.case_id not in serialized_output
    assert case.repository.fixed_commit not in serialized_output
    assert manifest == {
        "schema_version": "1.0",
        "case_id": policy_case_id(case),
        "policy_sha256": sha(seed),
        "forbidden_key_hits": [],
        "forbidden_keys": sorted(FORBIDDEN_KEYS),
    }
    assert verify_policy_seed(seed, manifest, case)

    seed["repository"]["upstream_id"] = "mutated-policy-copy"
    assert case.repository.upstream_id != "mutated-policy-copy"


def test_key_hits_recurses_through_nested_mapping_and_list() -> None:
    value = {
        "safe": [{"nested": {"cwe": "CWE-79"}}],
        "items": [{"authorization": {"ok": False}}],
    }

    assert key_hits(value) == {"cwe", "authorization"}
    assert key_hits({"safe": "cwe", "value": "fixed_commit"}) == set()


def test_case_extension_oracles_do_not_leak_into_whitelisted_seed() -> None:
    case = _first_case()
    case.model_extra["cwe"] = "CWE-999"
    case.repository.model_extra["advisory"] = {"fixed_commit": "oracle-secret"}
    case.model_extra["authorization"] = {"gold_locations": ["src/secret"]}

    seed, manifest = build_policy_seed(case)
    encoded_seed = json.dumps(seed, ensure_ascii=False)
    encoded_manifest = json.dumps(manifest, ensure_ascii=False)

    assert key_hits(seed) == set()
    assert "CWE-999" not in encoded_seed + encoded_manifest
    assert "oracle-secret" not in encoded_seed + encoded_manifest
    assert "src/secret" not in encoded_seed + encoded_manifest
    assert verify_policy_seed(seed, manifest, case)


@pytest.mark.parametrize("field", ["case_id", "upstream_id", "vulnerable_commit"])
def test_build_rejects_policy_scalar_that_smuggles_fixed_commit(field: str) -> None:
    case = _first_case().model_copy(deep=True)
    fixed = case.repository.fixed_commit
    if field == "case_id":
        case.case_id = fixed
    elif field == "upstream_id":
        case.repository.upstream_id = fixed
    else:
        case.repository.vulnerable_commit = fixed

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_key_hits_handles_non_string_keys_depth_and_cycles_safely() -> None:
    cyclic: dict[object, object] = {1: {"cwe": "CWE-1"}}
    cyclic["self"] = cyclic
    nested: object = {"root": cyclic}
    for _ in range(MAX_DEPTH - 4):
        nested = {"next": nested}

    assert key_hits(nested) == {"cwe"}
    assert key_hits(({"aliases": []},)) == {"aliases"}


@pytest.mark.parametrize(
    "value",
    [
        {"root": {"next": {"too_deep": {}}}},
        {"root": [{"x": {"y": {}}}]},
    ],
)
def test_key_hits_depth_limit_is_explicit(value: object) -> None:
    nested = value
    for _ in range(MAX_DEPTH):
        nested = {"next": nested}
    with pytest.raises(ValueError, match="limit"):
        key_hits(nested)


def test_key_hits_rejects_wide_input_without_copying_it_all() -> None:
    wide = {str(index): None for index in range(MAX_NODES + 1)}

    with pytest.raises(ValueError, match="limit"):
        key_hits(wide)


def test_sha_is_canonical_for_key_order_and_unicode_and_rejects_invalid_values() -> None:
    left = {"z": "雪", "a": [1, {"x": True}]}
    right = {"a": [1, {"x": True}], "z": "雪"}

    assert sha(left) == sha(right)
    assert sha(left).startswith("sha256:") and len(sha(left)) == 71
    with pytest.raises(ValueError):
        sha({"bad": float("nan")})
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError):
        sha(cyclic)
    with pytest.raises(ValueError):
        sha({"not-json": {1, 2}})
    with pytest.raises(ValueError):
        sha({1: "would otherwise collide"})
    with pytest.raises(ValueError):
        sha({True: "would otherwise collide"})
    with pytest.raises(ValueError):
        sha({None: "would otherwise collide"})


def test_verify_requires_case_anchor_and_rejects_self_consistent_tampering() -> None:
    case = _first_case()
    seed, manifest = build_policy_seed(case)
    altered = copy.deepcopy(seed)
    altered["budget"]["tokens"] = 1

    assert not verify_policy_seed(altered, manifest, case)
    assert verify_policy_seed(seed, manifest, case)

    altered_manifest = copy.deepcopy(manifest)
    altered_manifest["policy_sha256"] = sha(altered)
    assert not verify_policy_seed(altered, altered_manifest, case)


def test_verify_rejects_oversized_untrusted_seed_before_expensive_copying() -> None:
    case = _first_case()
    seed, manifest = build_policy_seed(case)
    seed["bounded_history"] = [{str(index): None for index in range(MAX_NODES + 1)}]

    assert not verify_policy_seed(seed, manifest, case)


def test_all_real_cases_are_redacted_hashed_deterministically_and_uniquely() -> None:
    cases = load_case_catalog(CATALOG_PATH)
    digests: set[str] = set()
    for case in cases:
        seed, manifest = build_policy_seed(case)
        repeat_seed, repeat_manifest = build_policy_seed(case)
        assert seed == repeat_seed
        assert manifest == repeat_manifest
        assert key_hits(seed) == set()
        assert verify_policy_seed(seed, manifest, case)
        digests.add(manifest["policy_sha256"])

    assert len(cases) == 300
    assert len(digests) == len(cases)

@pytest.mark.parametrize(
    "path_order",
    [("advisory", "safe"), ("safe", "advisory")],
)
def test_build_rejects_oracle_scalar_in_shared_container_regardless_of_path_order(
    path_order: tuple[str, str],
) -> None:
    case = _first_case().model_copy(deep=True)
    case.case_id = "oracle-secret"
    shared = {"identifier": "oracle-secret"}
    case.model_extra.clear()
    for path in path_order:
        case.model_extra[path] = shared

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)

@pytest.mark.parametrize("field", ["case_id", "upstream_id", "vulnerable_commit"])
def test_build_rejects_each_emitted_scalar_when_it_matches_affected_location(
    field: str,
) -> None:
    case = _first_case().model_copy(deep=True)
    affected_path = "b" * 40
    case.affected_locations = [{"path": affected_path}]
    if field == "case_id":
        case.case_id = affected_path
    elif field == "upstream_id":
        case.repository.upstream_id = affected_path
    else:
        case.repository.vulnerable_commit = affected_path

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


@pytest.mark.parametrize(
    "source_name, source_value",
    [
        ("family", "source_to_sink"),
        ("evidence_tier", "T1"),
        ("split", "train"),
        ("artifact_manifest", "data/artifacts/oracle-manifest.json"),
        ("artifact_poc", "https://example.invalid/oracle-poc"),
        ("artifact_test_path", "tests/oracle.py"),
        ("policy_view", "data/views/policy-oracle.json"),
        ("redaction_hash", "sha256:" + "a" * 64),
        ("cwe", "CWE-79"),
    ],
)
def test_build_rejects_other_explicit_oracle_source_scalars(
    source_name: str, source_value: str,
) -> None:
    case = _first_case().model_copy(deep=True)
    if source_name == "family":
        case.family = source_value
    elif source_name == "evidence_tier":
        case.evidence_tier = source_value
    elif source_name == "split":
        case.split = source_value
    elif source_name == "artifact_manifest":
        case.artifacts.manifest_path = source_value
    elif source_name == "artifact_poc":
        case.artifacts.poc_url = source_value
    elif source_name == "artifact_test_path":
        case.artifacts.test_paths = [source_value]
    elif source_name == "policy_view":
        case.views.policy_view_path = source_value
    elif source_name == "redaction_hash":
        case.views.redaction_manifest_sha256 = source_value
    else:
        case.cwe_normalized_primary = source_value
    case.case_id = source_value

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_prefix_containing_fixed_commit() -> None:
    case = _first_case().model_copy(deep=True)
    case.case_id = "prefix-" + case.repository.fixed_commit

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_upstream_identifier_containing_fixed_commit() -> None:
    case = _first_case().model_copy(deep=True)
    case.repository.upstream_id = "owner/" + case.repository.fixed_commit

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_casefolded_cwe_substring() -> None:
    case = _first_case().model_copy(deep=True)
    case.cwe_normalized_primary = "CWE-79"
    case.case_id = "finding-cwe-79"

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_unknown_extra_scalar_smuggled_into_case_id() -> None:
    case = _first_case().model_copy(deep=True)
    case.model_extra["oracle_label"] = "unknown-secret"
    case.case_id = "prefix-unknown-secret"

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_nfkc_casefold_equivalent_unknown_extra_scalar() -> None:
    case = _first_case().model_copy(deep=True)
    case.model_extra["oracle_label"] = "ＦｉＸＥＤ"
    case.case_id = "prefix-fixed"

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_lone_surrogate_in_emitted_oracle_comparison() -> None:
    case = _first_case().model_copy(deep=True)
    case.case_id = "bad\ud800id"

    with pytest.raises(ValueError):
        build_policy_seed(case)


def test_build_rejects_nfkc_casefolded_exact_only_family_collision() -> None:
    case = _first_case().model_copy(deep=True)
    case.family = "ＳＯＵＲＣＥ＿ＴＯ＿ＳＩＮＫ"
    case.case_id = "source_to_sink"

    with pytest.raises(ValueError, match="oracle"):
        build_policy_seed(case)


def test_build_rejects_lone_surrogate_in_exact_only_oracle_scalar() -> None:
    case = _first_case().model_copy(deep=True)
    case.family = "bad\ud800family"

    with pytest.raises(ValueError):
        build_policy_seed(case)


def test_build_rejects_aggregate_top_extension_nodes_over_global_limit() -> None:
    case = _first_case().model_copy(deep=True)
    case.model_extra.clear()
    # Each subtree is individually below MAX_NODES; together they are not.
    case.model_extra["one"] = ["alpha"] * (MAX_NODES - 2)
    case.model_extra["two"] = ["beta"] * (MAX_NODES - 2)

    with pytest.raises(ValueError, match="limit"):
        build_policy_seed(case)


def test_build_visits_shared_top_extension_subtree_once_per_classification() -> None:
    class SinglePassList(list[str]):
        traversals = 0

        def __iter__(self):
            type(self).traversals += 1
            if type(self).traversals > 1:
                raise AssertionError("shared subtree was traversed more than once")
            return super().__iter__()

    case = _first_case().model_copy(deep=True)
    case.model_extra.clear()
    shared = SinglePassList(["opaque-extra"])
    case.model_extra["one"] = shared
    case.model_extra["two"] = shared

    seed, manifest = build_policy_seed(case)
    assert manifest["policy_sha256"] == sha(seed)
    assert SinglePassList.traversals == 1


def test_build_counts_each_shared_top_extension_edge_against_global_limit() -> None:
    case = _first_case().model_copy(deep=True)
    case.model_extra.clear()
    shared: list[str] = []
    for index in range(MAX_NODES + 1):
        case.model_extra[f"edge-{index}"] = shared

    with pytest.raises(ValueError, match="limit"):
        build_policy_seed(case)
