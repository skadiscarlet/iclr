"""Build deliberately minimal policy-facing bootstrap seeds.

This module is the one-way boundary between a complete :class:`CaseManifest`
and the data handed to a policy.  It constructs the public view from an
explicit whitelist; it never serializes a case then tries to redact it.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import EnrichmentRecord


FORBIDDEN_KEYS = frozenset({
    "cwe",
    "cwe_normalized_primary",
    "aliases",
    "advisory",
    "fixed_commit",
    "patch",
    "gold_locations",
    "gold_proof_obligations",
    "authorization_model",
    "authorization",
})

# These limits bound traversal of untrusted policy payloads.  They are large
# enough for fixed BOOTSTRAP artifacts while preventing a wide/deep extension
# object from becoming an allocator or recursion attack.
MAX_NODES = 4_096
MAX_DEPTH = 128

_SEED_KEYS = frozenset({
    "schema_version",
    "case_id",
    "state",
    "repository",
    "budget",
    "bounded_history",
    "unknowns",
})
_REPOSITORY_KEYS = frozenset({"upstream_id", "vulnerable_commit"})
_BUDGET = {
    "seconds": 900,
    "tool_calls": 20,
    "tokens": 16000,
    "analysis_units": 20.0,
}
_UNKNOWNS = ["entrypoint", "security_invariant", "guard", "impact"]
_MANIFEST_KEYS = frozenset({
    "schema_version",
    "case_id",
    "policy_sha256",
    "forbidden_key_hits",
    "forbidden_keys",
})
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ORACLE_PATH_TOKENS = (
    "cwe",
    "alias",
    "advisory",
    "fixed",
    "patch",
    "proof",
    "gold",
    "authorization",
)
_MAX_EMITTED_UTF8_BYTES = 512


def _walk_limited(value: object, *, collect_hits: bool) -> set[str]:
    """Iteratively traverse mappings/lists/tuples under explicit limits."""

    hits: set[str] = set()
    pending: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    queued = 1

    while pending:
        current, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise ValueError("redaction traversal limit exceeded: maximum depth")
        if not isinstance(current, (Mapping, list, tuple)):
            continue
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)

        if isinstance(current, Mapping):
            children = current.items()
        else:
            children = ((None, child) for child in current)
        for key, child in children:
            if collect_hits and isinstance(key, str) and key in FORBIDDEN_KEYS:
                hits.add(key)
            queued += 1
            if queued > MAX_NODES:
                raise ValueError("redaction traversal limit exceeded: maximum nodes")
            pending.append((child, depth + 1))

    return hits


def key_hits(value: object) -> set[str]:
    """Return forbidden *mapping keys* found anywhere in ``value``.

    Values are deliberately not matched: a repository identifier or case id
    may legitimately be the string ``"cwe"``.  The iterative traversal is
    cycle-safe and has node/depth limits for untrusted input.
    """

    return _walk_limited(value, collect_hits=True)


def _validate_json_scalar(value: object) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    raise ValueError("value is not canonical JSON")


def _validate_json_shape(value: object) -> None:
    """Reject non-string keys/cycles before canonical JSON serialization."""

    pending: list[tuple[object, bool]] = [(value, False)]
    active: set[int] = set()
    completed: set[int] = set()

    while pending:
        current, leaving = pending.pop()
        if not isinstance(current, (Mapping, list, tuple)):
            _validate_json_scalar(current)
            continue
        marker = id(current)
        if leaving:
            active.remove(marker)
            completed.add(marker)
            continue
        if marker in active:
            raise ValueError("value is not canonical JSON")
        if marker in completed:
            continue

        active.add(marker)
        pending.append((current, True))
        if isinstance(current, Mapping):
            children: object = current.items()
            for key, child in children:  # type: ignore[union-attr]
                if not isinstance(key, str):
                    raise ValueError("canonical JSON object keys must be strings")
                if isinstance(child, (Mapping, list, tuple)):
                    pending.append((child, False))
                else:
                    _validate_json_scalar(child)
        else:
            for child in current:
                if isinstance(child, (Mapping, list, tuple)):
                    pending.append((child, False))
                else:
                    _validate_json_scalar(child)


def sha(value: object) -> str:
    """Hash JSON using the repository's canonical policy-view encoding."""

    try:
        _validate_json_shape(value)
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ValueError("value is not canonical JSON") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _valid_emitted_text(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > _MAX_EMITTED_UTF8_BYTES:
        return False
    try:
        return len(value.encode("utf-8", "strict")) <= _MAX_EMITTED_UTF8_BYTES
    except UnicodeError:
        return False


def _seed_is_exact(seed: object) -> bool:
    """Validate the closed BOOTSTRAP seed shape without accepting extensions."""

    if type(seed) is not dict or len(seed) != len(_SEED_KEYS) or set(seed) != _SEED_KEYS:
        return False
    repository = seed.get("repository")
    budget = seed.get("budget")
    unknowns = seed.get("unknowns")
    history = seed.get("bounded_history")
    if not _valid_emitted_text(seed.get("case_id")):
        return False
    if seed.get("schema_version") != "1.0" or seed.get("state") != "BOOTSTRAP":
        return False
    if type(repository) is not dict or len(repository) != len(_REPOSITORY_KEYS) or set(repository) != _REPOSITORY_KEYS:
        return False
    if not all(_valid_emitted_text(repository.get(name)) for name in _REPOSITORY_KEYS):
        return False
    if not _COMMIT_RE.fullmatch(repository["vulnerable_commit"]):
        return False
    if type(budget) is not dict or len(budget) != len(_BUDGET) or budget != _BUDGET:
        return False
    if type(history) is not list or len(history) != 0:
        return False
    return type(unknowns) is list and len(unknowns) == len(_UNKNOWNS) and unknowns == _UNKNOWNS


def _is_oracle_path_key(key: object) -> bool:
    return isinstance(key, str) and any(token in key.lower() for token in _ORACLE_PATH_TOKENS)


def _oracle_path_scalars(value: object) -> set[str]:
    """Collect scalar values only under labelled oracle-only extension paths."""

    scalars: set[str] = set()
    pending: list[tuple[object, bool, int]] = [(value, False, 0)]
    seen: set[int] = set()
    queued = 1

    while pending:
        current, oracle_path, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise ValueError("oracle scalar traversal limit exceeded: maximum depth")
        if isinstance(current, str):
            if oracle_path:
                scalars.add(current)
            continue
        if not isinstance(current, (Mapping, list, tuple)):
            continue
        # A shared container may be reached through both safe and oracle paths.
        # The traversal state, not object identity alone, determines whether its
        # scalar descendants are oracle-only.
        marker = (id(current), oracle_path)
        if marker in seen:
            continue
        seen.add(marker)

        if isinstance(current, Mapping):
            children = ((child, oracle_path or _is_oracle_path_key(key)) for key, child in current.items())
        else:
            children = ((child, oracle_path) for child in current)
        for child, child_oracle_path in children:
            queued += 1
            if queued > MAX_NODES:
                raise ValueError("oracle scalar traversal limit exceeded: maximum nodes")
            pending.append((child, child_oracle_path, depth + 1))

    return scalars


def _all_scalar_strings(value: object) -> set[str]:
    """Collect every string scalar from a designated oracle-only source."""

    scalars: set[str] = set()
    pending: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    queued = 1

    while pending:
        current, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise ValueError("oracle scalar traversal limit exceeded: maximum depth")
        if isinstance(current, str):
            scalars.add(current)
            continue
        if not isinstance(current, (Mapping, list, tuple)):
            continue
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)

        children = current.values() if isinstance(current, Mapping) else current
        for child in children:
            queued += 1
            if queued > MAX_NODES:
                raise ValueError("oracle scalar traversal limit exceeded: maximum nodes")
            pending.append((child, depth + 1))

    return scalars


def _normalised_scalar(value: str) -> str:
    """Return a comparison form while rejecting malformed Unicode safely."""

    try:
        value.encode("utf-8", "strict")
        return unicodedata.normalize("NFKC", value).casefold()
    except UnicodeError as exc:
        raise ValueError("oracle scalar is not valid UTF-8 text") from exc


def policy_case_id(case: CaseManifest) -> str:
    """Return an opaque deterministic handle instead of an advisory identifier."""

    return "case-" + hashlib.sha256(
        json.dumps(
            [case.case_id, case.repository.upstream_id, case.repository.vulnerable_commit],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    ).hexdigest()[:24]


def _top_extension_scalar_sets(case: CaseManifest) -> tuple[set[str], set[str]]:
    """Traverse all top-level extras under one state-sensitive node budget."""

    extra = case.model_extra or {}
    if not isinstance(extra, Mapping):
        raise ValueError("oracle scalar traversal requires mapping extensions")

    exact_only: set[str] = set()
    substring_sensitive: set[str] = set()
    case_id = _normalised_scalar(case.case_id)
    upstream_id = _normalised_scalar(case.repository.upstream_id)
    vulnerable_commit = _normalised_scalar(case.repository.vulnerable_commit)

    # States capture semantic path classification.  Sharing a container under
    # two generic roots visits it once; sharing it under generic and advisory
    # roots visits both relevant classifications without path-order bypasses.
    ROOT_STATES = {
        "advisory": "advisory_map",
        "aliases": "case_identity",
        "revision_resolution": "revision_map",
        "split_groups": "split_groups_map",
        "dedup": "dedup_map",
        "status": "exact_low",
        "build": "build_map",
    }
    pending: list[tuple[object, str, int, bool]] = [(extra, "root", 0, True)]
    scheduled: set[tuple[int, str]] = {(id(extra), "root")}
    processed = 0

    def count_node() -> None:
        nonlocal processed
        processed += 1
        if processed > MAX_NODES:
            raise ValueError("oracle scalar traversal limit exceeded: maximum nodes")

    def classify_scalar(value: str, state: str) -> None:
        if state == "case_identity" and _normalised_scalar(value) == case_id:
            return
        if state == "vulnerable_identity" and _normalised_scalar(value) == vulnerable_commit:
            return
        if state == "upstream_identity" and _normalised_scalar(value) == upstream_id:
            return
        if state == "exact_low":
            exact_only.add(value)
            return
        substring_sensitive.add(value)

    def child_state(parent_state: str, key: str, is_root: bool) -> str:
        if is_root:
            return ROOT_STATES.get(key, "generic")
        if parent_state == "advisory_map":
            return "case_identity" if key in {"ghsa_id", "osv_id"} else "generic"
        if parent_state == "revision_map":
            return "vulnerable_identity" if key in {"vulnerable_parent", "all_parents"} else "generic"
        if parent_state == "split_groups_map":
            if key == "repository":
                return "upstream_identity"
            return "exact_low" if key == "project_family" else "generic"
        if parent_state == "dedup_map":
            return "exact_low" if key == "project_family" else "generic"
        if parent_state == "build_map":
            return "exact_low" if key == "status" else "generic"
        return parent_state

    while pending:
        current, state, depth, is_root = pending.pop()
        if depth > MAX_DEPTH:
            raise ValueError("oracle scalar traversal limit exceeded: maximum depth")
        count_node()
        if isinstance(current, str):
            classify_scalar(current, state)
            continue
        if not isinstance(current, (Mapping, list, tuple)):
            continue

        if isinstance(current, Mapping):
            children = ((str(key), child) for key, child in current.items())
        else:
            children = ((str(index), child) for index, child in enumerate(current))
        for key, child in children:
            # Charge every enumerated edge before checking scheduled state: a
            # million aliases to one object must not evade the global budget.
            count_node()
            next_state = child_state(state, key, is_root)
            if isinstance(child, str):
                classify_scalar(child, next_state)
                continue
            if not isinstance(child, (Mapping, list, tuple)):
                continue
            marker = (id(child), next_state)
            if marker in scheduled:
                continue
            scheduled.add(marker)
            pending.append((child, next_state, depth + 1, False))

    return exact_only, substring_sensitive


def _oracle_scalar_sets(case: CaseManifest) -> tuple[set[str], set[str]]:
    """Return (exact-only, substring-sensitive) non-policy source scalars."""

    # Low-entropy categorical labels are exact-only: treating ``train`` or
    # ``T1`` as substrings would spuriously reject ordinary repository IDs.
    exact_only = {
        case.family,
        case.evidence_tier,
        case.split,
        case.artifacts.poc_status,
    }
    substring_sensitive = {
        case.cwe_normalized_primary,
        case.repository.fixed_commit,
        case.artifacts.patch_path,
        case.artifacts.proof_obligations_path,
        case.artifacts.manifest_path,
        case.views.oracle_view_path,
        case.views.policy_view_path,
        case.views.redaction_manifest_sha256,
    }
    if case.artifacts.poc_url is not None:
        substring_sensitive.add(case.artifacts.poc_url)

    # Artifacts, views, affected locations, and their extensions are all
    # oracle-only; repository extensions are also deny-by-default.  Unlike
    # top-level catalog metadata, none have a safe identifier alias contract.
    for source in (
        case.artifacts.test_paths,
        case.artifacts.model_extra or {},
        case.views.model_extra or {},
        case.affected_locations,
        case.repository.model_extra or {},
    ):
        substring_sensitive.update(_all_scalar_strings(source))

    top_exact, top_substrings = _top_extension_scalar_sets(case)
    exact_only.update(top_exact)
    substring_sensitive.update(top_substrings)
    return exact_only, substring_sensitive


def _assert_no_oracle_scalar_smuggling(case: CaseManifest) -> None:
    vulnerable_commit = case.repository.vulnerable_commit
    fixed_commit = case.repository.fixed_commit
    if vulnerable_commit == fixed_commit:
        raise ValueError("policy seed oracle scalar collision: vulnerable_commit equals fixed_commit")

    # Continue validating the raw catalog identity for collision safety even
    # though only its opaque local handle crosses the policy boundary.
    emitted = (
        case.case_id,
        policy_case_id(case),
        case.repository.upstream_id,
        vulnerable_commit,
    )
    if not all(_valid_emitted_text(value) for value in emitted):
        raise ValueError("policy seed emitted scalar has invalid UTF-8 or length")
    if not _COMMIT_RE.fullmatch(vulnerable_commit):
        raise ValueError("policy seed vulnerable_commit has invalid format")

    exact_only, substring_sensitive = _oracle_scalar_sets(case)
    normalised_emitted = tuple(_normalised_scalar(value) for value in emitted)
    normalised_exact_only = {_normalised_scalar(value) for value in exact_only}
    if any(value in normalised_exact_only for value in normalised_emitted):
        raise ValueError("policy seed oracle scalar collision")
    for oracle in substring_sensitive:
        normalised_oracle = _normalised_scalar(oracle)
        if normalised_oracle and any(normalised_oracle in value for value in normalised_emitted):
            raise ValueError("policy seed oracle scalar collision")


def build_policy_seed(case: CaseManifest) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a minimal BOOTSTRAP seed plus its hash-linked redaction manifest.

    Only fields named below are emitted from ``case``.  This is intentionally a
    construction whitelist rather than ``model_dump()`` followed by deletion,
    because CaseManifest admits future extension fields.
    """

    _assert_no_oracle_scalar_smuggling(case)
    seed: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": policy_case_id(case),
        "state": "BOOTSTRAP",
        "repository": {
            "upstream_id": case.repository.upstream_id,
            "vulnerable_commit": case.repository.vulnerable_commit,
        },
        "budget": dict(_BUDGET),
        "bounded_history": [],
        "unknowns": list(_UNKNOWNS),
    }
    hits = key_hits(seed)
    if hits or not _seed_is_exact(seed):
        raise ValueError("policy seed contains forbidden or invalid fields")

    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": seed["case_id"],
        "policy_sha256": sha(seed),
        "forbidden_key_hits": [],
        "forbidden_keys": sorted(FORBIDDEN_KEYS),
    }
    manifest_hits = key_hits(manifest)
    if manifest_hits or len(manifest) != len(_MANIFEST_KEYS) or set(manifest) != _MANIFEST_KEYS:
        raise ValueError("redaction manifest contains forbidden or invalid fields")
    return seed, manifest


def policy_value_hits(
    case: CaseManifest,
    record: EnrichmentRecord,
    value: object,
) -> set[str]:
    """Detect normalized oracle values in policy artifacts without exposing them."""

    if not isinstance(case, CaseManifest) or not isinstance(record, EnrichmentRecord):
        raise ValueError("policy leakage anchors are invalid")
    exact_only, substring_sensitive = _oracle_scalar_sets(case)
    substring_sensitive.update({case.case_id, record.case_id})
    for scalar in _all_scalar_strings(record.payload.model_dump(mode="json")):
        if len(_normalised_scalar(scalar)) >= 8:
            substring_sensitive.add(scalar)
        else:
            exact_only.add(scalar)

    # These values are reconstructed locally or explicitly permitted public
    # inputs.  They are safe only as values; the key-level checker remains
    # independent and still rejects oracle-labelled object paths.
    from .candidates import (
        OPERATION_PROFILE,
        POLICY_CANONICALIZER_VERSION,
        TARGET_KINDS,
        expected_evidence_type,
    )

    allowed = {
        case.repository.upstream_id,
        case.repository.vulnerable_commit,
        policy_case_id(case),
        POLICY_CANONICALIZER_VERSION,
        "patch_grounded_bc",
        "patch_grounded",
        "PATCH_GROUNDED_LABEL_RECORDED",
        *OPERATION_PROFILE,
        *TARGET_KINDS,
        *FORBIDDEN_KEYS,
        *_UNKNOWNS,
    }
    allowed.update(profile[0] for profile in OPERATION_PROFILE.values())
    allowed.update(profile[1] for profile in OPERATION_PROFILE.values())
    allowed.update(
        expected_evidence_type(operation, target_kind)
        for operation in OPERATION_PROFILE
        for target_kind in TARGET_KINDS
    )
    allowed.update(item.path for item in record.payload.locations)
    allowed.update(
        item.target_id for item in record.payload.trace if item.target_kind == "path"
    )
    normalized_allowed = {_normalised_scalar(item) for item in allowed}
    normalized_exact = {
        normalized
        for item in exact_only
        if (normalized := _normalised_scalar(item))
        and normalized not in normalized_allowed
    }
    normalized_substrings = {
        normalized
        for item in substring_sensitive
        if (normalized := _normalised_scalar(item))
        and normalized not in normalized_allowed
    }

    hits: set[str] = set()
    for emitted in _all_scalar_strings(value):
        normalized_emitted = _normalised_scalar(emitted)
        if normalized_emitted in normalized_allowed:
            continue
        matched = normalized_emitted in normalized_exact or any(
            secret in normalized_emitted for secret in normalized_substrings
        )
        if matched:
            hits.add("sha256:" + hashlib.sha256(normalized_emitted.encode()).hexdigest())
    return hits


def _manifest_has_exact_shape(manifest: object) -> bool:
    if type(manifest) is not dict or len(manifest) != len(_MANIFEST_KEYS) or set(manifest) != _MANIFEST_KEYS:
        return False
    forbidden_hits = manifest.get("forbidden_key_hits")
    forbidden_keys = manifest.get("forbidden_keys")
    policy_sha = manifest.get("policy_sha256")
    return (
        manifest.get("schema_version") == "1.0"
        and isinstance(manifest.get("case_id"), str)
        and isinstance(policy_sha, str)
        and len(policy_sha) == 71
        and type(forbidden_hits) is list
        and len(forbidden_hits) == 0
        and type(forbidden_keys) is list
        and len(forbidden_keys) == len(FORBIDDEN_KEYS)
        and forbidden_keys == sorted(FORBIDDEN_KEYS)
    )


def verify_policy_seed(seed: object, manifest: object, case: CaseManifest) -> bool:
    """Verify an issued seed against a trusted case anchor, not self-consistency."""

    # Cheap fixed-size shape tests run before any traversal or equality work.
    if not _seed_is_exact(seed) or not _manifest_has_exact_shape(manifest):
        return False
    try:
        if key_hits(seed) or key_hits(manifest):
            return False
        expected_seed, expected_manifest = build_policy_seed(case)
    except ValueError:
        return False
    return seed == expected_seed and manifest == expected_manifest and manifest["policy_sha256"] == sha(seed)
