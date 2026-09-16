"""Deterministic full-catalog validation for Context V2 teacher evidence."""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from egsi.contracts.case import CaseManifest, load_case_catalog
from egsi.data.context import _read_bytes_file, build_oracle_context


_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EXPECTED_CATALOG_SIZE = 300
_EXPECTED_LIST_SIZES = {"p0": 10, "p1": 30}
_CANONICAL_MAX_CHARS = 64_000


def _failure_category(error: Exception) -> str:
    """Map arbitrary exceptions to stable labels without serializing details."""

    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, PermissionError):
        return "permission"
    if isinstance(error, FileNotFoundError):
        return "not_found"
    if isinstance(error, UnicodeError):
        return "encoding"
    if isinstance(error, OSError):
        return "io"
    if isinstance(error, TypeError):
        return "type"
    if isinstance(error, ValueError):
        return "validation"
    if isinstance(error, RuntimeError):
        return "runtime"
    return "error"


def _read_frozen_ids(root: Path, name: str) -> tuple[list[str], bool]:
    try:
        raw = _read_bytes_file(root, f"configs/{name}_cases.txt", 1_000_000)
        text = raw.decode("utf-8")
    except (OSError, UnicodeError, ValueError):
        return [], False
    values = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    values = [value for value in values if value]
    valid = bool(values) and all(_CASE_ID_RE.fullmatch(value) for value in values)
    return values, valid


def _frozen_list_report(
    root: Path,
    name: str,
    cases_by_id: dict[str, CaseManifest],
) -> dict[str, Any]:
    ids, syntax_valid = _read_frozen_ids(root, name)
    duplicates = sorted(value for value, count in Counter(ids).items() if count > 1)
    missing = sorted(set(ids) - set(cases_by_id))
    time_ood_overlap = sorted(
        case_id
        for case_id in set(ids) & set(cases_by_id)
        if cases_by_id[case_id].split == "time_ood_test"
    )
    expected_count = _EXPECTED_LIST_SIZES[name]
    valid = (
        syntax_valid
        and len(ids) == expected_count
        and not duplicates
        and not missing
        and not time_ood_overlap
    )
    return {
        "ids": ids,
        "expected_count": expected_count,
        "actual_count": len(ids),
        "duplicate_case_ids": duplicates,
        "missing_case_ids": missing,
        "time_ood_overlap": time_ood_overlap,
        "valid": valid,
    }


def _length_summary(lengths: list[int]) -> dict[str, int | float | None]:
    if not lengths:
        return {"min": None, "median": None, "p95": None, "max": None}
    ordered = sorted(lengths)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    median = statistics.median(ordered)
    return {
        "min": ordered[0],
        "median": median,
        "p95": ordered[p95_index],
        "max": ordered[-1],
    }


def validate_contexts(
    *,
    catalog: Path,
    root: Path,
    repeat: int = 2,
    max_chars: int = _CANONICAL_MAX_CHARS,
    report_path: Path | None = None,
) -> dict[str, Any]:
    """Build every catalog context repeatedly and return a fail-closed gate report."""

    if not isinstance(catalog, Path) or not isinstance(root, Path):
        raise ValueError("catalog and root must be pathlib paths")
    if not isinstance(repeat, int) or isinstance(repeat, bool) or not 2 <= repeat <= 10:
        raise ValueError("repeat must be between 2 and 10")
    if (
        not isinstance(max_chars, int)
        or isinstance(max_chars, bool)
        or not 1 <= max_chars <= _CANONICAL_MAX_CHARS
    ):
        raise ValueError("max_chars must be between 1 and 64000")
    if report_path is not None and not isinstance(report_path, Path):
        raise ValueError("report_path must be a pathlib path")

    cases = load_case_catalog(catalog)
    cases_by_id = {case.case_id: case for case in cases}
    duplicate_catalog_ids = sorted(
        value for value, count in Counter(case.case_id for case in cases).items() if count > 1
    )
    failures: dict[str, set[str]] = defaultdict(set)
    failed_case_indexes: set[int] = set()
    snapshots: dict[int, list[tuple[str, str, str]]] = defaultdict(list)
    first_contexts: dict[int, Any] = {}

    for _repeat_index in range(repeat):
        for case_index, case in enumerate(cases):
            try:
                context = build_oracle_context(root, case, total_chars=max_chars)
                rendered = context.render()
                if context.context_version != "2.0":
                    raise ValueError("unexpected context version")
                if len(rendered) > max_chars or len(rendered) > _CANONICAL_MAX_CHARS:
                    raise ValueError("context render exceeds validation limit")
                snapshot = (
                    rendered,
                    context.sha256,
                    context.selection_receipt.receipt_commitment_sha256,
                )
                snapshots[case_index].append(snapshot)
                first_contexts.setdefault(case_index, context)
            except Exception as error:
                failures[_failure_category(error)].add(case.case_id)
                failed_case_indexes.add(case_index)

    mismatch_ids: set[str] = set()
    consistent = 0
    fully_built_indexes: set[int] = set()
    for case_index, case in enumerate(cases):
        observed = snapshots.get(case_index, [])
        mismatched = len(observed) >= 2 and any(
            value != observed[0] for value in observed[1:]
        )
        if mismatched:
            mismatch_ids.add(case.case_id)
        if case_index not in failed_case_indexes and len(observed) == repeat:
            fully_built_indexes.add(case_index)
        if (
            case_index in fully_built_indexes
            and not mismatched
        ):
            consistent += 1

    if len(fully_built_indexes) + len(failed_case_indexes) != len(cases):
        raise RuntimeError("context validation accounting invariant failed")
    failed_case_ids = sorted(
        {cases[index].case_id for index in failed_case_indexes}
    )
    built_contexts = [
        first_contexts[index] for index in sorted(fully_built_indexes)
    ]
    lengths = [len(context.render()) for context in built_contexts]
    patch_sources = Counter(
        context.selection_receipt.effective_patch_source
        for context in built_contexts
    )
    selection_totals = {
        "omitted_files": sum(
            context.selection_receipt.omitted_file_count
            for context in built_contexts
        ),
        "omitted_hunks": sum(
            context.selection_receipt.omitted_hunk_count
            for context in built_contexts
        ),
        "missing_paths": sum(
            len(context.selection_receipt.missing_paths)
            for context in built_contexts
        ),
        "new_only_paths": sum(
            len(context.selection_receipt.new_only_paths)
            for context in built_contexts
        ),
        "binary_files": sum(
            blob.selection_reason == "binary_patch"
            for context in built_contexts
            for blob in context.selection_receipt.source_blobs
        ),
    }
    split_counts = Counter(case.split for case in cases)
    frozen_lists = {
        name: _frozen_list_report(root, name, cases_by_id)
        for name in ("p0", "p1")
    }
    frozen_lists["p0"]["subset_of_p1"] = set(
        frozen_lists["p0"]["ids"]
    ).issubset(set(frozen_lists["p1"]["ids"]))
    frozen_lists["p0"]["valid"] = bool(
        frozen_lists["p0"]["valid"] and frozen_lists["p0"]["subset_of_p1"]
    )

    overall_valid = (
        len(cases) == _EXPECTED_CATALOG_SIZE
        and not duplicate_catalog_ids
        and len(fully_built_indexes) == _EXPECTED_CATALOG_SIZE
        and not failed_case_indexes
        and consistent == _EXPECTED_CATALOG_SIZE
        and not mismatch_ids
        and all(value["valid"] for value in frozen_lists.values())
        and bool(lengths)
        and max(lengths) <= max_chars
        and max(lengths) <= _CANONICAL_MAX_CHARS
    )
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "validator_version": "context-v2-gate-v1",
        "context_version": "2.0",
        "requested": len(cases),
        "built": len(fully_built_indexes),
        "failed": len(failed_case_indexes),
        "failed_case_ids": failed_case_ids,
        "failure_categories": {
            category: sorted(case_ids)
            for category, case_ids in sorted(failures.items())
        },
        "catalog_duplicate_case_ids": duplicate_catalog_ids,
        "length_chars": _length_summary(lengths),
        "repeat_consistency": {
            "requested_repeats": repeat,
            "consistent": consistent,
            "hash_mismatch_case_ids": sorted(mismatch_ids),
        },
        "patch_sources": {
            "canonical_git_diff": patch_sources.get("canonical_git_diff", 0),
            "raw": patch_sources.get("raw", 0),
        },
        "selection_totals": selection_totals,
        "split_counts": {
            split: split_counts.get(split, 0)
            for split in ("train", "dev", "time_ood_test")
        },
        "frozen_lists": frozen_lists,
        "overall_valid": overall_valid,
    }

    if report_path is not None:
        from egsi.generation.pilot import write_report

        write_report(report_path, report)
    return report
