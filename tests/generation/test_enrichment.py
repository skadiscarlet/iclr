"""Teacher enrichment generation is quarantined until semantic validation passes."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import warnings
from pathlib import Path

import pytest

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import EnrichmentPayload, EnrichmentRecord
from egsi.generation.enrichment import (
    EnrichmentRunner,
    allowed_action_values,
    possible_prompt_hashes,
    validate_payload,
)
from egsi.teacher import TeacherRequest, TeacherResponse, committed_teacher_response
from egsi.teacher.prompts import PROMPT_VERSION, PROOF_TEMPLATES, SYSTEM, enrichment_request


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True).stdout


def case_root(tmp_path: Path, *, family: str = "source_to_sink") -> tuple[CaseManifest, Path]:
    """A pinned vulnerable/fixed bare repository and all declared oracle inputs."""
    artifacts = tmp_path / "data/artifacts/case"
    (tmp_path / "idea-stage").mkdir(parents=True)
    (tmp_path / "idea-stage/ACTION_DSL.schema.json").write_text(json.dumps({
        "properties": {
            "goal": {"enum": ["CHECK_GUARD_OR_SANITIZER"]},
            "operation": {"enum": ["find_guard"]},
            "tool_class": {"enum": ["repository_index"]},
        },
        "$defs": {"target": {"properties": {"kind": {"enum": ["path"]}}}},
    }), encoding="utf-8")
    (artifacts / "views").mkdir(parents=True)
    (artifacts / "advisory").mkdir()
    (artifacts / "patch").mkdir()
    source = tmp_path / "source"
    source.mkdir()
    _git("git", "init", "-q", cwd=source)
    _git("git", "config", "user.email", "test@example.invalid", cwd=source)
    _git("git", "config", "user.name", "test", cwd=source)
    (source / "vuln.java").write_text("class Vulnerable {}\n", encoding="utf-8")
    (source / "z-primary.java").write_text("class ZPrimary {}\n", encoding="utf-8")
    (source / "a-primary.java").write_text("class APrimary {}\n", encoding="utf-8")
    _git("git", "add", ".", cwd=source)
    _git("git", "commit", "-qm", "vulnerable", cwd=source)
    vulnerable = _git("git", "rev-parse", "HEAD", cwd=source).strip()
    (source / "fixed.java").write_text("class Fixed {} // patch secret\n", encoding="utf-8")
    _git("git", "add", ".", cwd=source)
    _git("git", "commit", "-qm", "fixed", cwd=source)
    fixed = _git("git", "rev-parse", "HEAD", cwd=source).strip()
    bare = tmp_path / "data/cache/git/repo.git"
    bare.parent.mkdir(parents=True)
    _git("git", "clone", "-q", "--bare", str(source), str(bare), cwd=tmp_path)
    (artifacts / "advisory/raw.json").write_text('{"title":"advisory secret"}', encoding="utf-8")
    raw_patch = _git("git", "diff", "--binary", vulnerable, fixed, cwd=source)
    (artifacts / "patch/fix.patch").write_text(raw_patch, encoding="utf-8")
    (artifacts / "views/oracle_view.json").write_text(json.dumps({
        "case_id": "case", "cwe": "CWE-79",
        "repository": {
            "upstream_id": "example/repo",
            "vulnerable_commit": vulnerable,
            "fixed_commit": fixed,
        },
        "advisory_path": "data/artifacts/case/advisory/raw.json",
        "patch_path": "data/artifacts/case/patch/fix.patch",
    }), encoding="utf-8")
    (artifacts / "manifest.json").write_text(json.dumps({
        "resolution": {
            "cache_path": "data/cache/git/repo.git",
            "vulnerable_commit": vulnerable,
            "fixed_commit": fixed,
        }
    }), encoding="utf-8")
    return CaseManifest.model_validate({
        "schema_version": "1.0", "case_id": "case", "evidence_tier": "T1", "family": family,
        "cwe_normalized_primary": "CWE-79", "split": "train",
        "repository": {"url": "https://example.invalid", "upstream_id": "example/repo", "vulnerable_commit": vulnerable, "fixed_commit": fixed},
        "artifacts": {"patch_path": "data/artifacts/case/patch/fix.patch", "proof_obligations_path": "x", "manifest_path": "data/artifacts/case/manifest.json"},
        "views": {"oracle_view_path": "data/artifacts/case/views/oracle_view.json", "policy_view_path": "x", "redaction_manifest_sha256": "sha256:" + "0" * 64},
        "affected_locations": [{"path": "vuln.java"}],
    }), bare


def raw_payload(family: str, *, location: str = "vuln.java", trace_path: str = "vuln.java", **trace: str) -> str:
    value: dict[str, object] = {
        "family": family, "hypothesis": "A patch-grounded hypothesis.",
        "locations": [
            {
                "path": location,
                "symbol": "Vulnerable",
                "start_line": 1,
                "end_line": 1,
                "role": "guard",
            }
        ],
        "obligations": [{"obligation_id": "O-1", "kind": "guard", "description": "Check the guard.", "status": "unknown"}],
        "trace": [
            {
                "step_id": "S-1",
                "goal": "CHECK_GUARD_OR_SANITIZER",
                "operation": "find_guard",
                "target_kind": "path",
                "target_id": trace_path,
                "target_location": trace_path,
                "resolves_unknowns": ["O-1"],
                "expected_evidence_type": "source_location",
                "tool_class": "repository_index",
                "reason_tags": [],
                **trace,
            }
        ],
        "authorization": None, "limitations": ["runtime impact remains unknown"],
    }
    if family == "authorization":
        value["authorization"] = {"attacker_principal": "unknown", "victim_principal": "unknown", "action": "unknown", "resource": "unknown", "expected_relation": "unknown", "actual_check": "unknown", "observable_impact": "unknown"}
    return json.dumps(value, sort_keys=True)


class SequenceTeacher:
    provider = "mock"
    model = "mock-1"
    provider_response_model = "mock-actual-v1"

    def __init__(self, values: list[object]) -> None:
        self.values = iter(values)
        self.requests: list[TeacherRequest] = []

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.requests.append(request)
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return teacher_response(
            provider_request_id=str(len(self.requests)), provider=self.provider,
            model=self.model, provider_response_model=self.provider_response_model,
            text=str(value), usage={"output_tokens": 7}, latency_ms=1.9
        )


def teacher_response(**value) -> TeacherResponse:
    model = value["model"]
    return committed_teacher_response(
        requested_model=model,
        provider_response_model=value.pop("provider_response_model", model),
        **value,
    )


def prompt_vocabulary(root: Path) -> dict[str, set[str]]:
    allowed = allowed_action_values(root)
    return {
        key: allowed[key]
        for key in ("goals", "operations", "target_kinds", "tool_classes")
    }


def prompt_context(root: Path, case: CaseManifest):
    from egsi.data.context import build_oracle_context

    return build_oracle_context(root, case)


def test_prompt_schema_constrains_exact_action_enums_without_mutating_contract_schema(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)
    context = prompt_context(tmp_path, case)
    vocabulary = prompt_vocabulary(tmp_path)
    original = EnrichmentPayload.model_json_schema()

    _, user, schema = enrichment_request(
        context, vocabulary, repair_error=None, repair_attempt=0
    )

    expected_fields = {
        "goal": "goals",
        "operation": "operations",
        "target_kind": "target_kinds",
        "tool_class": "tool_classes",
    }
    properties = schema["$defs"]["TraceStep"]["properties"]
    for field, vocabulary_key in expected_fields.items():
        assert properties[field] == {
            "type": "string",
            "enum": sorted(vocabulary[vocabulary_key]),
        }
    encoded_schema = json.dumps(schema, sort_keys=True)
    assert '"title"' not in encoded_schema and '"default"' not in encoded_schema
    for node in (
        value
        for value in [schema, *schema["$defs"].values()]
        if value.get("type") == "object"
    ):
        assert node["additionalProperties"] is False
        assert node["required"] == sorted(node.get("properties", {}))
    envelope = json.loads(user)
    assert PROMPT_VERSION == envelope["prompt_version"] == "2.3"
    assert "canonical repo-relative POSIX blob path" in envelope[
        "repository_path_instruction"
    ]
    assert "flow/control/data-path descriptions are forbidden" in envelope[
        "repository_path_instruction"
    ]
    assert envelope["schema"] == schema
    assert envelope["action_vocabulary"] == {
        key: sorted(values) for key, values in vocabulary.items()
    }
    assert envelope["repair_attempt"] == 0
    assert set(envelope["repair_feedback"]) == {"flags", "instruction"}
    assert envelope["repair_feedback"]["flags"] == {
        "structured_output_invalid": False,
        "semantic_validation_failed": False,
        "canonical_path_invalid": False,
        "provenance_validation_failed": False,
    }
    assert "这些字段只能逐字选枚举，不能写自然语言" in envelope[
        "action_vocabulary_instruction"
    ]
    assert EnrichmentPayload.model_json_schema() == original

    location = schema["$defs"]["EnrichedLocation"]
    assert location["required"] == sorted(location["properties"])
    assert location["properties"]["path"]["type"] == "string"
    assert location["properties"]["symbol"]["type"] == "string"
    assert location["properties"]["start_line"] == {
        "minimum": 1,
        "type": "integer",
    }
    assert location["properties"]["end_line"] == {
        "minimum": 1,
        "type": "integer",
    }


def test_prompt_vocabulary_is_sorted_and_rejects_non_exact_or_unbounded_values(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)
    context = prompt_context(tmp_path, case)
    vocabulary = {
        "goals": {"Z", "A"},
        "operations": {"z", "a"},
        "target_kinds": {"symbol", "path"},
        "tool_classes": {"static_query", "repository_index"},
    }
    _, user, _ = enrichment_request(context, vocabulary, repair_attempt=0)
    assert json.loads(user)["action_vocabulary"] == {
        "goals": ["A", "Z"],
        "operations": ["a", "z"],
        "target_kinds": ["path", "symbol"],
        "tool_classes": ["repository_index", "static_query"],
    }

    class DictSubclass(dict):
        pass

    invalid_values: list[object] = [
        DictSubclass(vocabulary),
        {**vocabulary, "extra": {"x"}},
        {**vocabulary, "goals": []},
        {**vocabulary, "goals": set()},
        {**vocabulary, "goals": {""}},
        {**vocabulary, "goals": {"x" * 257}},
        {**vocabulary, "goals": {f"g-{index}" for index in range(257)}},
    ]
    for invalid in invalid_values:
        with pytest.raises((TypeError, ValueError)):
            enrichment_request(context, invalid, repair_attempt=0)  # type: ignore[arg-type]


def test_repair_attempt_changes_prompt_hash_and_feedback_is_fixed_categories_only(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)
    context = prompt_context(tmp_path, case)
    vocabulary = prompt_vocabulary(tmp_path)

    first = enrichment_request(
        context,
        vocabulary,
        repair_error="semantic_validation_failed",
        repair_attempt=1,
    )
    second = enrichment_request(
        context,
        vocabulary,
        repair_error="semantic_validation_failed",
        repair_attempt=2,
    )
    first_envelope, second_envelope = json.loads(first[1]), json.loads(second[1])
    assert first_envelope["repair_attempt"] == 1
    assert second_envelope["repair_attempt"] == 2
    assert first_envelope["repair_feedback"] == second_envelope["repair_feedback"]
    assert set(first_envelope["repair_feedback"]) == {"flags", "instruction"}
    assert set(first_envelope["repair_feedback"]["flags"]) == {
        "structured_output_invalid",
        "semantic_validation_failed",
        "canonical_path_invalid",
        "provenance_validation_failed",
    }
    assert hashlib.sha256((first[0] + first[1]).encode()).digest() != hashlib.sha256(
        (second[0] + second[1]).encode()
    ).digest()


def test_teacher_response_metadata_is_a_bounded_repair_category(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)
    context = prompt_context(tmp_path, case)
    vocabulary = prompt_vocabulary(tmp_path)

    _, user, _ = enrichment_request(
        context,
        vocabulary,
        repair_error="invalid_teacher_response_metadata",
        repair_attempt=1,
    )

    feedback = json.loads(user)["repair_feedback"]
    assert feedback["flags"]["provenance_validation_failed"] is True
    assert sum(feedback["flags"].values()) == 1
    assert "response contract" in feedback["instruction"]


def test_record_validation_error_repairs_three_times_then_writes_failure_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.generation.enrichment as module

    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher([raw_payload(case.family)] * 3)

    def reject_record(**_value: object):
        return module.EnrichmentRecord.model_validate({})

    monkeypatch.setattr(module, "committed_enrichment_record", reject_record)

    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(
            case, tmp_path / "output"
        )

    receipt = json.loads(
        (tmp_path / "output/failures/case.json").read_text(encoding="utf-8")
    )
    assert len(teacher.requests) == receipt["attempts"] == 3
    assert receipt["failed_attempt"] == 3
    assert receipt["error_kind"] == "teacher_response_metadata_invalid"
    assert not (tmp_path / "output/case.json").exists()


def test_canonical_path_repair_feedback_is_dedicated_and_provider_text_free(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)
    context = prompt_context(tmp_path, case)
    vocabulary = prompt_vocabulary(tmp_path)

    _, user, _ = enrichment_request(
        context,
        vocabulary,
        repair_error="invalid_canonical_path",
        repair_attempt=1,
    )

    feedback = json.loads(user)["repair_feedback"]
    assert feedback["flags"]["canonical_path_invalid"] is True
    assert feedback["flags"]["semantic_validation_failed"] is False
    assert "canonical repo-relative POSIX blob path" in feedback["instruction"]
    assert "provider" not in feedback["instruction"].lower()


def test_dsl_constrained_schema_rejects_natural_language_and_accepts_enum_values(
    tmp_path: Path,
) -> None:
    from jsonschema import Draft202012Validator

    case, _ = case_root(tmp_path)
    context = prompt_context(tmp_path, case)
    vocabulary = prompt_vocabulary(tmp_path)
    _, _, schema = enrichment_request(context, vocabulary, repair_attempt=0)
    validator = Draft202012Validator(schema)
    valid = json.loads(raw_payload(case.family))
    invalid = json.loads(raw_payload(case.family))
    invalid["trace"][0].update(
        {
            "goal": "Find and inspect the security guard",
            "operation": "Inspect the source code around the patch",
            "target_kind": "Java method",
            "tool_class": "code navigation",
        }
    )
    assert list(validator.iter_errors(valid)) == []
    assert {tuple(error.path) for error in validator.iter_errors(invalid)} == {
        ("trace", 0, "goal"),
        ("trace", 0, "operation"),
        ("trace", 0, "target_kind"),
        ("trace", 0, "tool_class"),
    }


@pytest.mark.parametrize(
    "raw",
    [
        '{"family":"source_to_sink","family":"source_to_sink"}',
        '{"trace":{"goal":"A","goal":"A"}}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        '{"value":1e400}',
    ],
)
def test_strict_teacher_json_parser_rejects_duplicate_keys_and_nonfinite_constants(
    raw: str,
) -> None:
    import egsi.generation.enrichment as module

    parser = getattr(module, "_strict_json_loads", None)
    assert parser is not None
    with pytest.raises(ValueError, match="strict JSON"):
        parser(raw, max_bytes=1_048_576)


@pytest.mark.parametrize("duplicate_level", ["root", "nested"])
def test_duplicate_key_teacher_output_fails_closed_without_receipt_echo(
    tmp_path: Path, duplicate_level: str
) -> None:
    case, _ = case_root(tmp_path)
    raw = raw_payload(case.family)
    if duplicate_level == "root":
        raw = raw[:-1] + ',"family":"source_to_sink"}'
    else:
        raw = raw.replace(
            '"goal": "CHECK_GUARD_OR_SANITIZER"',
            '"goal": "CHECK_GUARD_OR_SANITIZER", '
            '"goal": "CHECK_GUARD_OR_SANITIZER"',
            1,
        )
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw]), max_repairs=0).run(
            case, tmp_path / "output"
        )
    receipt = (tmp_path / "output/failures/case.json").read_text(encoding="utf-8")
    assert json.loads(receipt)["error_kind"] == "structured_invalid"
    assert "CHECK_GUARD_OR_SANITIZER" not in receipt


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_teacher_output_fails_closed_without_receipt_echo(
    tmp_path: Path, constant: str
) -> None:
    case, _ = case_root(tmp_path)
    raw = raw_payload(case.family).replace(
        '"start_line": 1', f'"start_line": {constant}', 1
    )
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw]), max_repairs=0).run(
            case, tmp_path / "output"
        )
    receipt = (tmp_path / "output/failures/case.json").read_text(encoding="utf-8")
    assert json.loads(receipt)["error_kind"] == "structured_invalid"
    assert constant not in receipt


def test_action_dsl_schema_read_accepts_exact_limit_and_rejects_oversize_before_json(
    tmp_path: Path,
) -> None:
    case_root(tmp_path)
    path = tmp_path / "idea-stage/ACTION_DSL.schema.json"
    base = path.read_bytes()
    limit = 1_048_576
    path.write_bytes(base + b" " * (limit - len(base)))
    assert allowed_action_values(tmp_path)["goals"] == {
        "CHECK_GUARD_OR_SANITIZER"
    }

    path.write_bytes(base + b" " * (limit + 1 - len(base)))
    with pytest.raises(
        ValueError, match="ACTION_DSL schema is unavailable or malformed"
    ):
        allowed_action_values(tmp_path)


def test_bounded_schema_reader_opens_nonblocking_before_regular_file_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.generation.enrichment as module

    observed: dict[str, int] = {}

    def reject_open(path: Path, flags: int) -> int:
        del path
        observed["flags"] = flags
        raise OSError

    monkeypatch.setattr(module.os, "open", reject_open)
    with pytest.raises(ValueError, match="bounded regular-file read failed"):
        module._read_bounded_regular(tmp_path / "schema.json", limit=1_048_576)

    assert observed["flags"] & os.O_NONBLOCK


def test_runner_uses_three_unique_attempt_prompts_and_possible_hashes_cover_them(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)
    invalid = raw_payload(case.family, location="missing.java")
    teacher = SequenceTeacher([invalid, invalid, invalid])
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(
            case, tmp_path / "output"
        )

    request_hashes = {
        "sha256:"
        + hashlib.sha256((request.system + request.user).encode("utf-8")).hexdigest()
        for request in teacher.requests
    }
    envelopes = [json.loads(request.user) for request in teacher.requests]
    vocabulary = prompt_vocabulary(tmp_path)
    possible = possible_prompt_hashes(prompt_context(tmp_path, case), vocabulary)
    assert len(teacher.requests) == len(request_hashes) == 3
    assert [envelope["repair_attempt"] for envelope in envelopes] == [0, 1, 2]
    assert request_hashes <= possible
    assert len(possible) == 9


def test_cached_teacher_cannot_collapse_three_repair_attempts_to_one_cache_key(
    tmp_path: Path,
) -> None:
    from egsi.teacher import CachedTeacher

    case, _ = case_root(tmp_path)
    invalid = raw_payload(case.family, location="missing.java")
    underlying = SequenceTeacher([invalid, invalid, invalid])
    cached = CachedTeacher(underlying, tmp_path / "teacher-cache")
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, cached, max_repairs=2).run(
            case, tmp_path / "output"
        )
    assert len(underlying.requests) == 3
    assert len(list((tmp_path / "teacher-cache").glob("*.json"))) == 3


def test_not_json_repairs_once_then_atomically_writes_record(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher(["not-json", raw_payload(case.family)])
    record = EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(case, tmp_path / "output")
    assert len(teacher.requests) == 2
    assert record.validation.valid and record.structured_output_valid
    assert record.model == record.requested_model == "mock-1"
    assert record.provider_response_model == "mock-actual-v1"
    assert record.teacher_response_commitment_sha256.startswith("sha256:")
    assert record.latency_ms == 1
    assert EnrichmentRecord.model_validate_json((tmp_path / "output/case.json").read_text()) == record
    assert not list((tmp_path / "output").glob(".*.tmp"))
    repaired_envelope = json.loads(teacher.requests[1].user)
    assert repaired_envelope["repair_attempt"] == 1
    assert repaired_envelope["repair_feedback"]["flags"] == {
        "structured_output_invalid": True,
        "semantic_validation_failed": False,
        "canonical_path_invalid": False,
        "provenance_validation_failed": False,
    }


def test_semantic_invalid_exhausts_to_safe_quarantine(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher([raw_payload(case.family, location="missing.java")] * 3)
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(case, tmp_path / "output")
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert len(teacher.requests) == 3
    assert not (tmp_path / "output/case.json").exists()
    assert receipt["positive_transition_written"] is False
    assert receipt["validation"]["invalid_locations"] == [
        "sha256:" + hashlib.sha256(b"missing.java").hexdigest()
    ]
    assert "advisory secret" not in json.dumps(receipt) and "patch secret" not in json.dumps(receipt)


def test_exact_json_and_code_fences_are_not_accepted(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher(["```json\n" + raw_payload(case.family) + "\n```"])
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=0).run(case, tmp_path / "output")
    assert len(teacher.requests) == 1


def test_transport_error_is_terminal_and_receipt_is_redacted(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher([RuntimeError("API_KEY=top-secret"), raw_payload(case.family)])
    with pytest.raises(RuntimeError, match="teacher transport failure"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=1).run(case, tmp_path / "output")
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert len(teacher.requests) == 1
    assert receipt["error_kind"] == "transport" and "top-secret" not in json.dumps(receipt)


def test_failed_atomic_success_keeps_previous_record_and_no_temporary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    target = output / "case.json"
    teacher = SequenceTeacher([raw_payload(case.family)])
    import egsi.generation.enrichment as module
    monkeypatch.setattr(
        module.os,
        "replace",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no replace")),
    )
    with pytest.raises(RuntimeError, match="fatal"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=0).run(case, output)
    assert not target.exists()
    assert not list(output.glob(".*.tmp"))


def test_enrichment_replace_exception_after_commit_is_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    import egsi.generation.enrichment as module

    real_replace = module.os.replace

    def commit_then_raise(*args: object, **kwargs: object) -> None:
        real_replace(*args, **kwargs)
        raise OSError("reported after commit")

    monkeypatch.setattr(module.os, "replace", commit_then_raise)
    record = EnrichmentRunner(
        tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0
    ).run(case, output)

    assert EnrichmentRecord.model_validate_json(
        (output / "case.json").read_bytes()
    ) == record
    assert not list(output.glob(".*.tmp"))


def test_anchored_atomic_precommit_error_preserves_old_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from egsi.generation.safeio import AnchoredDirectory
    import egsi.generation.safeio as safeio

    target = tmp_path / "record.json"
    target.write_bytes(b"old")
    monkeypatch.setattr(
        safeio.os,
        "replace",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("precommit")),
    )
    with AnchoredDirectory(tmp_path) as output:
        with pytest.raises(OSError, match="precommit"):
            output.atomic_bytes(Path("record.json"), b"new", limit=16)

    assert target.read_bytes() == b"old"
    assert not list(tmp_path.glob(".*.tmp"))


def test_anchored_atomic_replace_ambiguous_result_is_fatal_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from egsi.generation.safeio import AnchoredDirectory
    import egsi.generation.safeio as safeio

    target = tmp_path / "record.json"
    target.write_bytes(b"old")
    real_replace = safeio.os.replace

    def ambiguous(source: str, destination: str, **kwargs: object) -> None:
        real_replace(source, destination, **kwargs)
        fd = safeio.os.open(
            destination,
            safeio.os.O_WRONLY | safeio.os.O_TRUNC,
            dir_fd=kwargs["dst_dir_fd"],
        )
        try:
            safeio.os.write(fd, b"third")
        finally:
            safeio.os.close(fd)
        raise OSError("ambiguous")

    monkeypatch.setattr(safeio.os, "replace", ambiguous)
    with AnchoredDirectory(tmp_path) as output:
        with pytest.raises(RuntimeError, match="ambiguous"):
            output.atomic_bytes(Path("record.json"), b"new", limit=16)

    assert target.read_bytes() == b"third"
    assert not list(tmp_path.glob(".*.tmp"))


def test_anchored_atomic_rechecks_destination_token_before_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from egsi.generation.safeio import AnchoredDirectory
    import egsi.generation.safeio as safeio

    target = tmp_path / "record.json"
    target.write_bytes(b"old")
    replacement = tmp_path / "concurrent.json"
    replacement.write_bytes(b"concurrent")
    real_fsync = safeio.os.fsync
    real_replace = safeio.os.replace
    swapped = False

    def swap_after_temp_fsync(fd: int) -> None:
        nonlocal swapped
        real_fsync(fd)
        if not swapped:
            real_replace(replacement, target)
            swapped = True

    monkeypatch.setattr(safeio.os, "fsync", swap_after_temp_fsync)
    with AnchoredDirectory(tmp_path) as output:
        with pytest.raises(RuntimeError, match="changed before replace"):
            output.atomic_bytes(Path("record.json"), b"new", limit=16)

    assert swapped is True
    assert target.read_bytes() == b"concurrent"
    assert not list(tmp_path.glob(".*.tmp"))


def test_successful_retry_clears_stale_failure_receipt(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    output.joinpath("failures").mkdir(parents=True)
    output.joinpath("failures/case.json").write_text('{"old_failure":true}\n', encoding="utf-8")
    EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert not (output / "failures/case.json").exists()


def test_malformed_action_schema_fails_without_teacher_call(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    (tmp_path / "idea-stage/ACTION_DSL.schema.json").write_text("[]", encoding="utf-8")
    teacher = SequenceTeacher([])
    with pytest.raises(RuntimeError, match="preparation failed"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=0).run(case, tmp_path / "output")
    assert teacher.requests == []
    assert not (tmp_path / "output/failures/case.json").exists()


def test_action_schema_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    case_root(root)
    external = tmp_path / "external-action-dsl.json"
    external.write_text((root / "idea-stage/ACTION_DSL.schema.json").read_text(encoding="utf-8"), encoding="utf-8")
    declared = root / "idea-stage/ACTION_DSL.schema.json"
    declared.unlink()
    declared.symlink_to(external)
    with pytest.raises(ValueError, match="unavailable or malformed"):
        allowed_action_values(root)


def test_semantic_diagnostics_are_complete_and_deterministic(tmp_path: Path) -> None:
    case, bare = case_root(tmp_path)
    raw = json.loads(raw_payload("authorization", location="missing.java", trace_path="fixed.java", goal="BAD", operation="bad", target_kind="path", tool_class="bad"))
    raw["trace"].append({"step_id": "S-2", "goal": "CHECK_GUARD_OR_SANITIZER", "operation": "find_guard", "target_kind": "bad", "target_id": "x", "expected_evidence_type": "source_location", "tool_class": "repository_index"})
    payload = EnrichmentPayload.model_validate(raw)
    from egsi.data.git_objects import GitObjectStore
    validation = validate_payload(case, payload, GitObjectStore(bare), allowed_action_values(tmp_path))
    assert validation.family_mismatch
    assert validation.invalid_locations == ["missing.java"]
    assert validation.invalid_trace_locations == ["fixed.java"]
    assert validation.invalid_goals == ["BAD"]
    assert validation.invalid_operations == ["bad"]
    assert validation.invalid_target_kinds == ["bad"]
    assert validation.invalid_tool_classes == ["bad"]


def test_fixed_only_location_and_trace_path_are_rejected(tmp_path: Path) -> None:
    case, bare = case_root(tmp_path)
    value = json.loads(
        raw_payload(case.family, location="fixed.java", trace_path="fixed.java")
    )
    value["locations"][0]["symbol"] = "Fixed"
    payload = EnrichmentPayload.model_validate(value)
    from egsi.data.git_objects import GitObjectStore
    validation = validate_payload(case, payload, GitObjectStore(bare), allowed_action_values(tmp_path))
    assert validation.invalid_locations == ["fixed.java"]
    assert validation.invalid_trace_locations == ["fixed.java"]


@pytest.mark.parametrize("missing_field", ["start_line", "end_line", "symbol"])
def test_v22_grounded_location_requires_lines_and_symbol(
    tmp_path: Path, missing_field: str
) -> None:
    case, bare = case_root(tmp_path)
    value = json.loads(raw_payload(case.family))
    value["locations"][0][missing_field] = None
    from egsi.data.git_objects import GitObjectStore

    validation = validate_payload(
        case,
        EnrichmentPayload.model_validate(value),
        GitObjectStore(bare),
        allowed_action_values(tmp_path),
    )

    assert validation.invalid_locations == ["vuln.java"]


@pytest.mark.parametrize(
    ("location_path", "trace_path", "target_location"),
    [
        ("./vuln.java", "vuln.java", "vuln.java"),
        ("vuln.java", "./vuln.java", "./vuln.java"),
        ("vuln.java", "vuln.java", "./vuln.java"),
        ("vuln.java", "vuln.java", "fixed.java"),
    ],
)
def test_all_enrichment_path_fields_require_canonical_vulnerable_blob_paths(
    tmp_path: Path,
    location_path: str,
    trace_path: str,
    target_location: str,
) -> None:
    case, bare = case_root(tmp_path)
    value = json.loads(
        raw_payload(case.family, location=location_path, trace_path=trace_path)
    )
    value["trace"][0]["target_location"] = target_location
    payload = EnrichmentPayload.model_validate(value)
    from egsi.data.git_objects import GitObjectStore

    validation = validate_payload(
        case, payload, GitObjectStore(bare), allowed_action_values(tmp_path)
    )

    assert validation.valid is False
    assert validation.invalid_locations or validation.invalid_trace_locations


def test_location_lines_must_fit_vulnerable_blob_and_symbol_must_match_nearby(
    tmp_path: Path,
) -> None:
    case, bare = case_root(tmp_path)
    from egsi.data.git_objects import GitObjectStore

    def checked(**updates: object):
        value = json.loads(raw_payload(case.family))
        value["locations"][0].update(updates)
        return validate_payload(
            case,
            EnrichmentPayload.model_validate(value),
            GitObjectStore(bare),
            allowed_action_values(tmp_path),
        )

    assert checked(start_line=1, end_line=1, symbol="example.Vulnerable").valid
    assert checked(start_line=2, end_line=2).invalid_locations
    assert checked(start_line=1, end_line=1, symbol="example.Missing").invalid_locations


def test_real_3wfj_transport_connection_method_and_lines_validate() -> None:
    from egsi.contracts.case import load_case_catalog
    from egsi.generation.enrichment import _load_store

    root = Path(__file__).resolve().parents[2]
    case = next(
        item
        for item in load_case_catalog(root / "data/catalog/cases.jsonl")
        if item.case_id == "ghsa-3wfj-vh84-732p"
    )
    path = (
        "activemq-broker/src/main/java/org/apache/activemq/broker/"
        "TransportConnection.java"
    )
    payload = EnrichmentPayload.model_validate(
        {
            "family": case.family,
            "hypothesis": "A patch-grounded hypothesis.",
            "locations": [
                {
                    "path": path,
                    "symbol": "org.apache.activemq.broker.TransportConnection.processControlCommand",
                    "start_line": 1536,
                    "end_line": 1542,
                    "role": "guard",
                }
            ],
            "obligations": [
                {
                    "obligation_id": "O-1",
                    "kind": "guard",
                    "description": "Check the guard.",
                    "status": "unknown",
                }
            ],
            "trace": [
                {
                    "step_id": "S-1",
                    "goal": "CHECK_GUARD_OR_SANITIZER",
                    "operation": "find_guard",
                    "target_kind": "path",
                    "target_id": path,
                    "target_location": path,
                    "resolves_unknowns": ["O-1"],
                    "expected_evidence_type": "source_location",
                    "tool_class": "repository_index",
                    "reason_tags": [],
                }
            ],
            "authorization": None,
            "limitations": ["runtime impact remains unknown"],
        }
    )

    validation = validate_payload(
        case, payload, _load_store(root, case), allowed_action_values(root)
    )

    assert validation.valid is True


def test_patch_only_fixture_uses_receipt_priority_order_and_skips_missing_paths(
    tmp_path: Path,
) -> None:
    case, bare = case_root(tmp_path)
    from egsi.data.git_objects import GitObjectStore
    from egsi.teacher.fixture import FixtureTeacher

    context = {
        "family": case.family,
        "repository": case.repository.upstream_id,
        "source_files": {},
        "selection_receipt": {
            "source_blobs": [
                {
                    "path": "fixed.java",
                    "availability": "new_only",
                    "selection_reason": "affected_location",
                },
                {
                    "path": "missing.java",
                    "availability": "missing",
                    "selection_reason": "patch_hunk",
                },
                {
                    "path": "z-primary.java",
                    "availability": "available",
                    "selection_reason": "binary_patch",
                },
                {
                    "path": "a-primary.java",
                    "availability": "available",
                    "selection_reason": "metadata_only",
                },
            ]
        },
    }
    request = TeacherRequest(
        system=SYSTEM,
        user=json.dumps(
            {
                "context": context,
                "action_vocabulary": {
                    key: sorted(values)
                    for key, values in prompt_vocabulary(tmp_path).items()
                },
            }
        ),
        schema={},
    )

    response = FixtureTeacher().generate(request)
    payload = EnrichmentPayload.model_validate_json(response.text)
    validation = validate_payload(
        case,
        payload,
        GitObjectStore(bare),
        allowed_action_values(tmp_path),
    )

    assert payload.locations[0].path == "z-primary.java"
    assert validation.valid is True


def test_prompt_and_hash_are_deterministic(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    from egsi.data.context import build_oracle_context
    context = build_oracle_context(tmp_path, case)
    vocabulary = prompt_vocabulary(tmp_path)
    first = enrichment_request(context, vocabulary, repair_attempt=0)
    second = enrichment_request(context, vocabulary, repair_attempt=0)
    assert first == second and first[0] == SYSTEM
    assert json.loads(first[1])["context"] == json.loads(context.render())
    teacher = SequenceTeacher([raw_payload(case.family)])
    record = EnrichmentRunner(tmp_path, teacher, max_repairs=0).run(case, tmp_path / "output")
    assert record.prompt_sha256 == "sha256:" + hashlib.sha256((first[0] + first[1]).encode("utf-8")).hexdigest()


def test_prompt_v22_envelope_invalidates_pre_v22_teacher_cache_key(tmp_path: Path) -> None:
    from egsi.data.context import build_oracle_context
    from egsi.teacher.base import TeacherRequest
    from egsi.teacher.cache import cache_key

    case, _ = case_root(tmp_path)
    context = build_oracle_context(tmp_path, case)
    system, user, schema = enrichment_request(
        context, prompt_vocabulary(tmp_path), repair_attempt=0
    )
    envelope = json.loads(user)

    assert envelope["prompt_version"] == "2.3"
    assert envelope["context_version"] == "2.0"
    assert envelope["selection_policy_id"] == "patch-hunk-v1"
    old_envelope = dict(envelope)
    old_envelope.pop("prompt_version")
    old_envelope.pop("context_version")
    old_envelope.pop("selection_policy_id")
    old_request = TeacherRequest(
        system=system,
        user=json.dumps(old_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        schema=schema,
    )
    new_request = TeacherRequest(system=system, user=user, schema=schema)
    assert cache_key("fixture", "fixture-v1", old_request) != cache_key(
        "fixture", "fixture-v1", new_request
    )


def test_frozen_v22_reconstructs_the_preserved_live_request_hash() -> None:
    from egsi.data.context import build_oracle_context
    from egsi.generation.enrichment import _prompt_vocabulary
    from egsi.generation.pilot import catalog_index
    from egsi.teacher.base import TeacherRequest, teacher_request_hash
    from egsi.teacher.prompts import enrichment_request_v22

    root = Path(__file__).resolve().parents[2]
    case = catalog_index(root)["ghsa-3wfj-vh84-732p"]
    context = build_oracle_context(root, case)
    vocabulary = _prompt_vocabulary(allowed_action_values(root))
    system, user, schema = enrichment_request_v22(
        context, vocabulary, repair_error=None, repair_attempt=0
    )

    assert json.loads(user)["prompt_version"] == "2.2"
    assert teacher_request_hash(
        TeacherRequest(
            system=system,
            user=user,
            schema=schema,
            temperature=0.0,
            max_tokens=8192,
        )
    ) == "sha256:3ff08b742a87a01533425742332ca34b6adb3330b543e52db72da157adc7f4a3"


def test_proof_templates_match_the_planned_text_exactly() -> None:
    assert PROOF_TEMPLATES == {
        "source_to_sink": [
            "establish an externally influenced source",
            "establish a path from source to security-sensitive sink",
            "check the required sanitizer or validation invariant",
            "keep runtime impact unknown at T1",
        ],
        "authorization": [
            "identify attacker and victim principals",
            "identify the action and protected resource",
            "state the expected subject-resource relation",
            "locate the actual guard and keep runtime impact unknown at T1",
        ],
    }


def test_committed_record_must_equal_the_intended_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    import egsi.generation.enrichment as module
    original = module._atomic_json_write

    def corrupt_success(path: Path, value: dict[str, object]) -> None:
        original(path, value)
        if path.parent.name != "failures":
            damaged = json.loads(path.read_text(encoding="utf-8"))
            damaged["model"] = "corrupted-but-schema-valid"
            path.write_text(json.dumps(damaged), encoding="utf-8")

    monkeypatch.setattr(module, "_atomic_json_write", corrupt_success)
    output = tmp_path / "output"
    with pytest.raises(RuntimeError, match="output integrity failure"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert (output / "failures/case.json").exists()
    assert not (output / "case.json").exists()


def test_precommit_fsync_failure_preserves_old_record_and_cleans_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    target = output / "case.json"
    import egsi.generation.enrichment as module
    monkeypatch.setattr(module.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("precommit")))
    with pytest.raises(RuntimeError, match="positive output write failed"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert not target.exists()
    assert not list(output.glob(".*.tmp"))


def test_post_replace_directory_fsync_failure_is_best_effort_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    import egsi.generation.enrichment as module
    original = module.os.fsync
    calls = 0

    def fail_only_directory_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory sync")
        original(fd)

    monkeypatch.setattr(module.os, "fsync", fail_only_directory_fsync)
    output = tmp_path / "output"
    record = EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    committed = EnrichmentRecord.model_validate_json((output / "case.json").read_text())
    assert calls >= 2 and committed == record
    assert record.structured_output_valid is True and record.validation.valid is True


def test_postcommit_read_error_removes_untrusted_positive_before_failure_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    import egsi.generation.enrichment as module
    original_read = module._read_existing_record

    def fail_only_committed_output(path: Path) -> str:
        if path == output / "case.json":
            raise OSError("read committed artifact")
        return original_read(path)

    monkeypatch.setattr(module, "_read_existing_record", fail_only_committed_output)
    with pytest.raises(RuntimeError, match="output integrity failure"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert not (output / "case.json").exists()
    assert json.loads((output / "failures/case.json").read_text())["positive_transition_written"] is False


def test_postcommit_malformed_record_removes_untrusted_positive_before_failure_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    import egsi.generation.enrichment as module
    original = module._atomic_json_write

    def corrupt_to_malformed(path: Path, value: dict[str, object]) -> None:
        original(path, value)
        if path.parent.name != "failures":
            path.write_text("{not-json", encoding="utf-8")

    monkeypatch.setattr(module, "_atomic_json_write", corrupt_to_malformed)
    with pytest.raises(RuntimeError, match="output integrity failure"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert not (output / "case.json").exists()
    assert json.loads((output / "failures/case.json").read_text())["positive_transition_written"] is False


def test_untrusted_positive_cleanup_failure_is_fatal_without_misleading_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    import egsi.generation.enrichment as module
    original_write = module._atomic_json_write

    def corrupt_to_malformed(path: Path, value: dict[str, object]) -> None:
        original_write(path, value)
        if path.parent.name != "failures":
            path.write_text("{not-json", encoding="utf-8")

    original_remove = module._remove_output_file

    def fail_target_cleanup(path: Path) -> None:
        if path == output / "case.json":
            raise OSError("cannot remove")
        original_remove(path)

    monkeypatch.setattr(module, "_atomic_json_write", corrupt_to_malformed)
    monkeypatch.setattr(module, "_remove_output_file", fail_target_cleanup)
    with pytest.raises(RuntimeError, match="fatal: untrusted positive cleanup failed"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert not (output / "failures/case.json").exists()


def test_oversized_response_is_repaired_without_echoing_body(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    secret = "LEAK-ME-" + "x" * (1_048_576 + 1)
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, SequenceTeacher([secret]), max_repairs=0).run(case, tmp_path / "output")
    receipt = (tmp_path / "output/failures/case.json").read_text()
    assert "LEAK-ME" not in receipt


def test_full_dsl_conditional_and_unknown_references_make_step_invalid(tmp_path: Path) -> None:
    case, bare = case_root(tmp_path)
    raw = json.loads(raw_payload(case.family))
    raw["trace"][0].update({"operation": "terminate", "goal": "CONTROL_SEARCH", "resolves_unknowns": ["missing"]})
    payload = EnrichmentPayload.model_validate(raw)
    from egsi.data.git_objects import GitObjectStore
    validation = validate_payload(case, payload, GitObjectStore(bare), allowed_action_values(tmp_path))
    assert validation.valid is False and validation.invalid_operations == ["terminate"]


def test_validate_payload_deduplicates_git_contains_calls(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    raw = json.loads(raw_payload(case.family))
    raw["locations"] *= 256
    raw["trace"] = [dict(raw["trace"][0], step_id=f"S-{index}") for index in range(256)]
    payload = EnrichmentPayload.model_validate(raw)

    class Store:
        def __init__(self) -> None: self.calls = 0
        def contains(self, commit: str, path: str) -> bool:
            self.calls += 1
            return True
        def read_text(self, commit: str, path: str, *, max_bytes: int) -> str:
            del commit, path, max_bytes
            return "class Vulnerable {}\n"

    store = Store()
    assert validate_payload(case, payload, store, allowed_action_values(tmp_path)).valid
    assert store.calls == 1


def test_validate_payload_propagates_git_cache_integrity_failure(
    tmp_path: Path,
) -> None:
    from egsi.data import git_objects

    case, _ = case_root(tmp_path)
    payload = EnrichmentPayload.model_validate(json.loads(raw_payload(case.family)))

    class Store:
        def contains(self, commit: str, path: str) -> bool:
            del commit, path
            raise ValueError("Git cache identity closure changed")

        def read_text(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("unreachable")

    with pytest.raises(
        git_objects.GitCacheIntegrityError,
        match="Git cache identity closure changed",
    ):
        validate_payload(case, payload, Store(), allowed_action_values(tmp_path))


@pytest.mark.parametrize("existing", [False, True], ids=["new-response", "reuse"])
def test_git_cache_integrity_failure_is_fatal_without_extra_provider_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
) -> None:
    from egsi.data import git_objects
    import egsi.generation.enrichment as enrichment_module

    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    if existing:
        EnrichmentRunner(
            tmp_path,
            SequenceTeacher([raw_payload(case.family)]),
            max_repairs=0,
        ).run(case, output)

    class Store:
        def __init__(self) -> None:
            self.closed = False

        def contains(self, commit: str, path: str) -> bool:
            del commit, path
            raise git_objects.GitCacheIntegrityError(
                "Git cache identity closure changed"
            )

        def read_text(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("unreachable")

        def close(self) -> None:
            self.closed = True

    store = Store()
    monkeypatch.setattr(enrichment_module, "_load_store", lambda root, item: store)
    teacher = SequenceTeacher(
        [] if existing else [raw_payload(case.family), raw_payload(case.family)]
    )

    with pytest.raises(RuntimeError, match="fatal: local Git cache integrity failure"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(case, output)

    assert len(teacher.requests) == (0 if existing else 1)
    assert store.closed is True


def test_enrichment_closes_git_store_across_success_reuse_and_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import egsi.generation.enrichment as enrichment_module

    case, _ = case_root(tmp_path)
    before = len(os.listdir("/proc/self/fd"))
    output = tmp_path / "output"
    original_load = enrichment_module._load_store
    tracked: list[object] = []

    class TrackingStore:
        def __init__(self, inner: object) -> None:
            self.inner = inner
            self.closed = False

        def __getattr__(self, name: str) -> object:
            return getattr(self.inner, name)

        def close(self) -> None:
            self.closed = True
            self.inner.close()

    def load(root: Path, item: CaseManifest) -> TrackingStore:
        store = TrackingStore(original_load(root, item))
        tracked.append(store)
        return store

    monkeypatch.setattr(enrichment_module, "_load_store", load)

    EnrichmentRunner(
        tmp_path,
        SequenceTeacher([raw_payload(case.family)]),
        max_repairs=0,
    ).run(case, output)
    assert tracked[-1].closed is True
    assert len(os.listdir("/proc/self/fd")) == before

    no_call = SequenceTeacher([])
    EnrichmentRunner(tmp_path, no_call, max_repairs=0).run(case, output)
    assert no_call.requests == []
    assert tracked[-1].closed is True
    assert len(os.listdir("/proc/self/fd")) == before

    EnrichmentRunner(
        tmp_path,
        SequenceTeacher(["not-json", raw_payload(case.family)]),
        max_repairs=1,
    ).run(case, tmp_path / "repaired")
    assert tracked[-1].closed is True
    assert len(os.listdir("/proc/self/fd")) == before


def test_output_failure_symlink_is_rejected_without_external_write(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    output, external = tmp_path / "output", tmp_path / "external"
    output.mkdir(); external.mkdir()
    (output / "failures").symlink_to(external, target_is_directory=True)
    with pytest.raises(RuntimeError, match="unsafe output boundary"):
        EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert list(external.iterdir()) == []


def test_forged_teacher_provenance_is_terminal_without_positive(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher([raw_payload(case.family)])
    teacher.model = "expected"
    original_generate = teacher.generate
    def forged(request: TeacherRequest) -> TeacherResponse:
        response = original_generate(request)
        return response.model_copy(update={"model": "forged"})
    teacher.generate = forged  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="provenance"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(case, tmp_path / "output")
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert receipt["error_kind"] == "provenance" and not (tmp_path / "output/case.json").exists()


@pytest.mark.parametrize(
    "update",
    [
        {"provider_response_model": "forged-actual-revision"},
        {"provider_response_model": 7},
        {"provider_request_id": object()},
        {"usage": {"tokens": -1}},
        {"response_commitment_sha256": "sha256:" + "0" * 64},
    ],
)
def test_forged_teacher_response_commitment_is_terminal_without_positive(
    tmp_path: Path, update: dict[str, object]
) -> None:
    case, _ = case_root(tmp_path)
    teacher = SequenceTeacher([raw_payload(case.family)])
    original_generate = teacher.generate

    def forged(request: TeacherRequest) -> TeacherResponse:
        response = original_generate(request)
        # Pydantic model_copy deliberately bypasses validation; the runner is
        # therefore responsible for revalidating this untrusted boundary.
        return response.model_copy(update=update)

    teacher.generate = forged  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="provenance"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=2).run(
            case, tmp_path / "output"
        )
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert receipt["error_kind"] == "provenance"
    assert not (tmp_path / "output/case.json").exists()


def test_teacher_dump_failure_is_bounded_provenance_without_field_access(
    tmp_path: Path,
) -> None:
    case, _ = case_root(tmp_path)

    class UndumpableResponse:
        def model_dump(self, *, mode: str):
            assert mode == "json"
            raise RuntimeError("DYNAMIC_DUMP_SECRET")

        def __getattribute__(self, name: str):
            if name == "model_dump":
                return object.__getattribute__(self, name)
            raise AssertionError(f"field accessed before strict dump: {name}")

    class Teacher:
        provider = "mock"
        model = "mock-1"

        def generate(self, request: TeacherRequest):
            return UndumpableResponse()

    with pytest.raises(RuntimeError, match="provenance") as raised:
        EnrichmentRunner(tmp_path, Teacher(), max_repairs=0).run(
            case, tmp_path / "output"
        )
    assert "DYNAMIC_DUMP_SECRET" not in str(raised.value)
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert receipt["error_kind"] == "provenance"
    assert "DYNAMIC_DUMP_SECRET" not in json.dumps(receipt)
    assert not (tmp_path / "output/case.json").exists()


@pytest.mark.parametrize("dump_kind", ["constructed", "dict_subclass"])
def test_teacher_dump_requires_an_exact_plain_dict_before_field_access(
    tmp_path: Path, dump_kind: str
) -> None:
    case, _ = case_root(tmp_path)
    valid = teacher_response(
        provider_request_id="id", provider="mock", model="mock-1",
        text=raw_payload(case.family), usage={},
    )

    class DictSubclass(dict):
        pass

    class ResponseProxy:
        def model_dump(self, *, mode: str):
            assert mode == "json"
            if dump_kind == "constructed":
                return valid.model_copy(
                    update={"provider_response_model": "forged-actual"}
                )
            return DictSubclass(valid.model_dump(mode="json"))

        def __getattribute__(self, name: str):
            if name == "model_dump":
                return object.__getattribute__(self, name)
            raise AssertionError(f"field accessed after invalid dump: {name}")

    class Teacher:
        provider = "mock"
        model = "mock-1"
        def generate(self, request: TeacherRequest):
            return ResponseProxy()

    with pytest.raises(RuntimeError, match="provenance"):
        EnrichmentRunner(tmp_path, Teacher(), max_repairs=0).run(
            case, tmp_path / "output"
        )
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert receipt["error_kind"] == "provenance"
    assert not (tmp_path / "output/case.json").exists()


def test_teacher_dump_and_validation_warnings_do_not_leak_provider_repr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case, _ = case_root(tmp_path)
    secret = "DYNAMIC_WARNING_REPR_SECRET"

    class ResponseProxy:
        def model_dump(self, *, mode: str):
            warnings.warn(secret)
            return {"not": "a teacher response"}

    class Teacher:
        provider = "mock"
        model = "mock-1"
        def generate(self, request: TeacherRequest):
            return ResponseProxy()

    with pytest.raises(RuntimeError, match="provenance"):
        EnrichmentRunner(tmp_path, Teacher(), max_repairs=0).run(
            case, tmp_path / "output"
        )
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
    receipt = (tmp_path / "output/failures/case.json").read_text()
    assert secret not in receipt
    assert json.loads(receipt)["error_kind"] == "provenance"


def test_existing_case_symlink_is_fatal_without_reading_external_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output, external = tmp_path / "output", tmp_path / "external.json"
    output.mkdir()
    external.write_text('{"sentinel":"external"}', encoding="utf-8")
    (output / "case.json").symlink_to(external)
    original = Path.read_text
    def forbid_external(self: Path, *args: object, **kwargs: object) -> str:
        if self == external:
            raise AssertionError("external target was read")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", forbid_external)
    with pytest.raises(RuntimeError, match="unsafe existing positive"):
        EnrichmentRunner(tmp_path, SequenceTeacher([]), max_repairs=0).run(case, output)


def test_output_ancestor_swap_after_boundary_check_has_zero_outside_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    outside = tmp_path / "outside"
    detached = tmp_path / "detached-output"
    output.mkdir()
    outside.mkdir()

    import egsi.generation.enrichment as module

    original_prepare = module._safe_preparation
    swapped = False

    def swap_after_output_anchor(root: Path, manifest: CaseManifest):
        nonlocal swapped
        result = original_prepare(root, manifest)
        output.rename(detached)
        output.symlink_to(outside, target_is_directory=True)
        swapped = True
        return result

    monkeypatch.setattr(module, "_safe_preparation", swap_after_output_anchor)
    record = EnrichmentRunner(
        tmp_path,
        SequenceTeacher([raw_payload(case.family)]),
        max_repairs=0,
    ).run(case, output)

    assert swapped is True
    assert record.case_id == case.case_id
    assert list(outside.iterdir()) == []
    assert EnrichmentRecord.model_validate_json(
        (detached / "case.json").read_bytes()
    ) == record


@pytest.mark.parametrize("kind", ["hardlink", "fifo"])
def test_existing_hardlink_or_fifo_is_rejected_without_read_or_block(
    tmp_path: Path,
    kind: str,
) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    target = output / "case.json"
    external = tmp_path / "external.json"
    external.write_text("sentinel", encoding="utf-8")
    if kind == "hardlink":
        os.link(external, target)
    else:
        os.mkfifo(target)
    teacher = SequenceTeacher([])

    with pytest.raises(RuntimeError, match="unsafe existing positive"):
        EnrichmentRunner(tmp_path, teacher, max_repairs=0).run(case, output)

    assert teacher.requests == []
    assert external.read_text(encoding="utf-8") == "sentinel"


def test_reuse_revalidates_existing_payload_and_provider_before_returning(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    initial_teacher = SequenceTeacher([raw_payload(case.family)])
    record = EnrichmentRunner(tmp_path, initial_teacher, max_repairs=0).run(case, output)
    corrupted = record.model_dump(mode="json")
    corrupted["provider"] = "forged"
    corrupted["payload"]["locations"][0]["path"] = "missing-secret.java"
    (output / "case.json").write_text(json.dumps(corrupted), encoding="utf-8")
    replacement = SequenceTeacher([raw_payload(case.family)])
    fresh = EnrichmentRunner(tmp_path, replacement, max_repairs=0).run(case, output)
    assert len(replacement.requests) == 1
    assert fresh.provider == replacement.provider and fresh.payload.locations[0].path == "vuln.java"
    assert list((output / "quarantine").glob("case.*.json"))


def test_reuse_quarantines_a_format_valid_but_unreachable_prompt_hash(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    record = EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    forged = record.model_dump(mode="json")
    forged["prompt_sha256"] = "sha256:" + "f" * 64
    (output / "case.json").write_text(json.dumps(forged), encoding="utf-8")
    replacement = SequenceTeacher([raw_payload(case.family)])
    EnrichmentRunner(tmp_path, replacement, max_repairs=0).run(case, output)
    assert len(replacement.requests) == 1
    assert list((output / "quarantine").glob("case.*.json"))


def test_a_real_repaired_prompt_hash_is_reusable(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"
    repaired = EnrichmentRunner(tmp_path, SequenceTeacher(["not-json", raw_payload(case.family)]), max_repairs=1).run(case, output)
    no_call_teacher = SequenceTeacher([])
    reused = EnrichmentRunner(tmp_path, no_call_teacher, max_repairs=1).run(case, output)
    assert reused == repaired and no_call_teacher.requests == []


def test_terminal_receipt_tracks_the_actual_last_stage_and_prior_validation(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    invalid = raw_payload(case.family, location="missing.java")
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(tmp_path, SequenceTeacher([invalid, "not-json"]), max_repairs=1).run(case, tmp_path / "output")
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert receipt["error_kind"] == "structured_invalid"
    assert receipt["failed_attempt"] == 2 and receipt["validation_attempt"] == 1


def test_oversized_existing_record_is_quarantined_without_content_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, _ = case_root(tmp_path)
    output = tmp_path / "output"; output.mkdir()
    target = output / "case.json"; target.write_bytes(b"x" * (2_097_153))
    original_text, original_bytes = Path.read_text, Path.read_bytes
    def forbid(self: Path, *args: object, **kwargs: object):
        if self == target: raise AssertionError("oversized content read")
        return original_text(self, *args, **kwargs)
    def forbid_bytes(self: Path, *args: object, **kwargs: object):
        if self == target: raise AssertionError("oversized content hashed")
        return original_bytes(self, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", forbid)
    monkeypatch.setattr(Path, "read_bytes", forbid_bytes)
    import egsi.generation.enrichment as module
    (output / "quarantine").mkdir()
    module._quarantine_existing(target, output / "quarantine", "case", oversized=True)
    monkeypatch.setattr(Path, "read_text", original_text)
    monkeypatch.setattr(Path, "read_bytes", original_bytes)
    fresh = EnrichmentRunner(tmp_path, SequenceTeacher([raw_payload(case.family)]), max_repairs=0).run(case, output)
    assert fresh.validation.valid and list((output / "quarantine").glob("case.oversized-*.json"))


def test_oversized_teacher_request_id_is_terminal_without_positive(tmp_path: Path) -> None:
    case, _ = case_root(tmp_path)
    class Teacher:
        provider = "mock"; model = "mock-1"
        def generate(self, request: TeacherRequest) -> TeacherResponse:
            return teacher_response(provider_request_id="x" * (3 * 1024 * 1024), provider=self.provider,
                                   model=self.model, text=raw_payload(case.family), usage={})
    with pytest.raises(RuntimeError, match="teacher_response_metadata"):
        EnrichmentRunner(tmp_path, Teacher(), max_repairs=0).run(case, tmp_path / "output")
    assert not (tmp_path / "output/case.json").exists()


@pytest.mark.parametrize("field", ["provider", "model", "provider_request_id", "usage_key"])
def test_surrogate_teacher_metadata_is_a_bounded_provenance_failure(tmp_path: Path, field: str) -> None:
    case, _ = case_root(tmp_path)
    class Teacher:
        provider = "mock" if field != "provider" else "\ud800"
        model = "mock-1" if field != "model" else "\ud800"
        def generate(self, request: TeacherRequest) -> TeacherResponse:
            # Deliberately bypass the strict constructor: this test exercises the
            # runner's boundary handling for an untrusted Teacher implementation.
            return TeacherResponse.model_construct(
                provider_request_id="\ud800" if field == "provider_request_id" else "id",
                provider=self.provider, model=self.model, requested_model=self.model,
                provider_response_model=self.model, text=raw_payload(case.family),
                usage={"\ud800" if field == "usage_key" else "tokens": 1},
                latency_ms=0.0, cached=False,
                response_commitment_sha256="sha256:" + "0" * 64,
            )
    with pytest.raises(RuntimeError, match="provenance"):
        EnrichmentRunner(tmp_path, Teacher(), max_repairs=0).run(case, tmp_path / "output")
    receipt = json.loads((tmp_path / "output/failures/case.json").read_text())
    assert receipt["error_kind"] == "provenance"


def test_first_real_catalog_case_runs_end_to_end_with_fixture_teacher(tmp_path: Path) -> None:
    """This is deliberately local: it reads the catalog/cache but makes no network call."""
    from egsi.contracts.case import load_case_catalog

    from egsi.teacher.fixture import FixtureTeacher

    root = Path(__file__).resolve().parents[2]
    case = load_case_catalog(root / "data/catalog/cases.jsonl")[0]
    record = EnrichmentRunner(root, FixtureTeacher(), max_repairs=0).run(case, tmp_path)
    assert record.case_id == case.case_id and record.validation.valid
    assert (tmp_path / f"{case.case_id}.json").exists()


@pytest.mark.parametrize("value", [True, -1, 1.0, "1", 99])
def test_invalid_max_repairs_is_rejected(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError):
        EnrichmentRunner(tmp_path, SequenceTeacher([]), max_repairs=value)  # type: ignore[arg-type]


def test_atomic_json_serialization_error_leaves_no_temporary_file(tmp_path: Path) -> None:
    import egsi.generation.enrichment as module

    target = tmp_path / "record.json"
    with pytest.raises(TypeError):
        module._atomic_json_write(target, {"not_json": object()})

    assert not target.exists()
    assert list(tmp_path.glob(".*.tmp")) == []
