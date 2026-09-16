"""Deterministic offline teacher used only for contract and pilot validation."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
import re
from typing import Any

from .base import TeacherRequest, TeacherResponse, committed_teacher_response


class FixtureTeacher:
    """Emit minimal patch-grounded payloads without any dynamic assertion."""

    provider = "fixture"
    model = "fixture-v1"
    requested_model = "fixture-v1"
    provider_response_model = "fixture-v1"

    def __init__(self) -> None:
        self.calls = 0
        self.close_calls = 0

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        envelope: Any = json.loads(request.user)
        if type(envelope) is not dict or type(envelope.get("context")) is not dict:
            raise ValueError("fixture teacher requires a canonical context envelope")
        context = envelope["context"]
        vocabulary = envelope.get("action_vocabulary")
        expected_vocabulary_fields = {
            "goals",
            "operations",
            "target_kinds",
            "tool_classes",
        }
        if (
            type(vocabulary) is not dict
            or set(vocabulary) != expected_vocabulary_fields
            or any(
                type(vocabulary[field]) is not list
                or not vocabulary[field]
                or vocabulary[field] != sorted(vocabulary[field])
                or any(type(value) is not str or not value for value in vocabulary[field])
                for field in expected_vocabulary_fields
            )
        ):
            raise ValueError("fixture teacher requires canonical action vocabulary")
        source_files = context.get("source_files")
        if type(source_files) is not dict:
            raise ValueError("fixture teacher requires a source-files compatibility view")
        if any(type(path) is not str or not path for path in source_files):
            raise ValueError("fixture teacher source paths are invalid")
        vulnerable_source = bool(source_files)
        if vulnerable_source:
            path = sorted(source_files)[0]
        else:
            receipt = context.get("selection_receipt")
            blobs = receipt.get("source_blobs") if type(receipt) is dict else None
            primary_reasons = {"patch_hunk", "binary_patch", "metadata_only"}
            primary_path: tuple[str, bool] | None = None
            affected_path: tuple[str, bool] | None = None
            if type(blobs) is list:
                for item in blobs:
                    if type(item) is not dict:
                        continue
                    candidate = item.get("path")
                    availability = item.get("availability")
                    reason = item.get("selection_reason")
                    if (
                        type(candidate) is not str
                        or not candidate
                        or availability not in {"available", "new_only"}
                    ):
                        continue
                    if reason in primary_reasons and primary_path is None:
                        primary_path = (candidate, availability == "available")
                    elif reason == "affected_location" and affected_path is None:
                        affected_path = (candidate, availability == "available")
            selected = primary_path or affected_path
            if selected is None:
                raise ValueError(
                    "fixture teacher requires a semantically available receipt path"
                )
            path, vulnerable_source = selected
        source_text = source_files.get(path) if vulnerable_source else None
        grounded_line = 1
        source_line_offset = 0
        if type(source_text) is str:
            source_chunks = context.get("source_chunks")
            if type(source_chunks) is not list:
                raise ValueError("fixture teacher requires canonical source chunks")
            selected_chunk = next(
                (
                    item
                    for item in source_chunks
                    if type(item) is dict
                    and item.get("path") == path
                    and type(item.get("text")) is str
                    and type(item.get("start_line")) is int
                    and not isinstance(item.get("start_line"), bool)
                    and item["start_line"] >= 1
                ),
                None,
            )
            if selected_chunk is None:
                raise ValueError("fixture teacher cannot bind source to a canonical chunk")
            source_text = selected_chunk["text"]
            source_line_offset = selected_chunk["start_line"] - 1
        grounded_symbol: str | None = None
        if type(source_text) is str:
            for index, line in enumerate(source_text.splitlines(), start=1):
                identifiers = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", line)
                if identifiers:
                    grounded_line = source_line_offset + index
                    grounded_symbol = identifiers[-1]
                    break
        if grounded_symbol is None:
            stem_parts = re.findall(
                r"[A-Za-z0-9_$]+", PurePosixPath(path).stem
            )
            grounded_symbol = "".join(part[:1].upper() + part[1:] for part in stem_parts)
        if not grounded_symbol:
            raise ValueError("fixture teacher cannot ground the selected location")
        family = context.get("family")
        if family == "authorization":
            role = "resource"
            goal = "CHECK_SECURITY_INVARIANT"
            operation = "check_auth_relation"
            target_kind = "resource"
            target_id = "security-resource"
            evidence_type = "authorization_relation"
            tool_class = "semantic_model"
            authorization = {
                "attacker_principal": "requesting_user",
                "victim_principal": "resource_owner",
                "action": "access",
                "resource": "target_resource",
                "expected_relation": "requester is authorized for target resource",
                "actual_check": "unknown",
                "observable_impact": "unauthorized resource access remains unconfirmed",
            }
        elif family == "source_to_sink":
            role = "guard"
            goal = "CHECK_GUARD_OR_SANITIZER"
            operation = "find_guard"
            target_kind = "path" if vulnerable_source else "repository"
            target_id = path if vulnerable_source else str(context.get("repository", "repository"))
            evidence_type = "source_location" if vulnerable_source else "patch_context"
            tool_class = "repository_index"
            authorization = None
        else:
            raise ValueError("fixture teacher requires a supported family")

        selected_action = {
            "goals": goal,
            "operations": operation,
            "target_kinds": target_kind,
            "tool_classes": tool_class,
        }
        if any(
            value not in vocabulary[field]
            for field, value in selected_action.items()
        ):
            raise ValueError("fixture action is absent from the prompt vocabulary")

        payload = {
            "family": family,
            "hypothesis": "Inspect the patch-grounded security path without asserting dynamic confirmation.",
            "locations": [
                {
                    "path": path,
                    "symbol": grounded_symbol,
                    "start_line": grounded_line,
                    "end_line": grounded_line,
                    "role": role,
                }
            ],
            "obligations": [
                {
                    "obligation_id": "O-1",
                    "kind": "security_invariant",
                    "description": "Establish the missing or incomplete security relation.",
                    "status": "unknown",
                }
            ],
            "trace": [
                {
                    "step_id": "S-1",
                    "goal": goal,
                    "operation": operation,
                    "target_kind": target_kind,
                    "target_id": target_id,
                    "target_location": path,
                    "resolves_unknowns": ["O-1"],
                    "expected_evidence_type": evidence_type,
                    "tool_class": tool_class,
                    "reason_tags": ["fixture", "patch_grounded"],
                }
            ],
            "authorization": authorization,
            "limitations": [
                "Fixture output is for offline contract tests only; runtime impact remains unknown."
            ],
        }
        return committed_teacher_response(
            provider_request_id=f"fixture-{self.calls}",
            provider=self.provider,
            model=self.model,
            requested_model=self.requested_model,
            provider_response_model=self.provider_response_model,
            text=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            latency_ms=0.0,
        )

    def close(self) -> None:
        self.close_calls += 1
