"""Case manifest contracts and JSONL catalog loading."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class _AllowExtraModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class RepositoryRef(_AllowExtraModel):
    url: str
    upstream_id: str
    vulnerable_commit: str
    fixed_commit: str

    @field_validator("vulnerable_commit", "fixed_commit")
    @classmethod
    def validate_commit(cls, value: str) -> str:
        if not _COMMIT_RE.fullmatch(value):
            raise ValueError("commit must be a lowercase 40-character hexadecimal SHA-1")
        return value


class ArtifactRefs(_AllowExtraModel):
    patch_path: str
    proof_obligations_path: str
    manifest_path: str
    poc_status: Literal[
        "not_collected", "url_only", "available_unverified", "adapted", "replayed"
    ] = "not_collected"
    poc_url: str | None = None
    test_paths: list[str] = Field(default_factory=list)


class ViewRefs(_AllowExtraModel):
    oracle_view_path: str
    policy_view_path: str
    redaction_manifest_sha256: Annotated[
        str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")
    ]


class CaseManifest(_AllowExtraModel):
    schema_version: Literal["1.0"]
    case_id: str
    evidence_tier: Literal["T0", "T1", "T2", "T3"]
    family: Literal["source_to_sink", "authorization"]
    cwe_normalized_primary: Annotated[
        str, StringConstraints(pattern=r"^CWE-[0-9]+$")
    ]
    split: Literal["train", "dev", "time_ood_test"]
    repository: RepositoryRef
    artifacts: ArtifactRefs
    views: ViewRefs
    affected_locations: list[dict[str, Any]] = Field(default_factory=list)


def load_case_catalog(path: Path) -> list[CaseManifest]:
    """Load and validate a UTF-8 JSONL case catalog, skipping blank lines."""

    cases: list[CaseManifest] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            try:
                cases.append(CaseManifest.model_validate_json(raw_line))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: invalid case manifest") from exc
    return cases
