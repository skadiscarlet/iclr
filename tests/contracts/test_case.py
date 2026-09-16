"""Contract tests for the case manifest models and catalog loader."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from egsi.contracts.case import CaseManifest, load_case_catalog


CATALOG_PATH = Path(__file__).parents[2] / "data/catalog/cases.jsonl"


def test_load_real_catalog_and_preserve_extension_fields() -> None:
    cases = load_case_catalog(CATALOG_PATH)

    assert len(cases) == 300
    first = cases[0]
    assert len(first.repository.vulnerable_commit) == 40
    assert first.artifacts.patch_path.endswith("fix.patch")
    assert "split_groups" in first.model_extra


def test_repository_commit_must_be_lowercase_full_sha1() -> None:
    first = json.loads(CATALOG_PATH.read_text(encoding="utf-8").splitlines()[0])
    first["repository"]["vulnerable_commit"] = "deadbeef"

    with pytest.raises(ValidationError):
        CaseManifest.model_validate(first)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("cwe_normalized_primary", "CWE-"),
    ],
)
def test_manifest_rejects_invalid_scalar_contracts(field: str, value: str) -> None:
    first = json.loads(CATALOG_PATH.read_text(encoding="utf-8").splitlines()[0])
    first[field] = value

    with pytest.raises(ValidationError):
        CaseManifest.model_validate(first)


def test_manifest_rejects_invalid_poc_status() -> None:
    first = json.loads(CATALOG_PATH.read_text(encoding="utf-8").splitlines()[0])
    first["artifacts"]["poc_status"] = "unknown"

    with pytest.raises(ValidationError):
        CaseManifest.model_validate(first)


def test_manifest_rejects_invalid_redaction_digest() -> None:
    first = json.loads(CATALOG_PATH.read_text(encoding="utf-8").splitlines()[0])
    first["views"]["redaction_manifest_sha256"] = "sha256:" + "A" * 64

    with pytest.raises(ValidationError):
        CaseManifest.model_validate(first)


@pytest.mark.parametrize(
    "commit",
    ["deadbeef", "A" * 40, "g" * 40],
)
def test_repository_commit_rejects_invalid_revision_forms(commit: str) -> None:
    first = json.loads(CATALOG_PATH.read_text(encoding="utf-8").splitlines()[0])
    first["repository"]["vulnerable_commit"] = commit

    with pytest.raises(ValidationError):
        CaseManifest.model_validate(first)


def test_loader_skips_blank_lines_and_reports_jsonl_line(tmp_path: Path) -> None:
    first = CATALOG_PATH.read_text(encoding="utf-8").splitlines()[0]
    path = tmp_path / "cases.jsonl"
    path.write_text(first + "\n\nnot-json\n", encoding="utf-8")

    with pytest.raises(ValueError) as error:
        load_case_catalog(path)

    assert f"{path}:3" in str(error.value)
    assert error.value.__cause__ is not None
