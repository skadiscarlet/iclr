"""Strictly aggregate a verified P0 package with a live P1 delta."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from egsi.contracts.enrichment import EnrichmentRecord
from egsi.contracts.trajectory import EpisodeEvent, T1Transition
from egsi.generation.pilot import (
    _dict_commitment,
    _episode_metrics,
    _read_regular,
    _remove_regular_if_present,
    _record_is_current,
    _sha256,
    _validate_case_ids,
    catalog_index,
    read_case_ids,
    write_report,
)
from egsi.generation.redaction import policy_case_id
from egsi.generation.replay import replay_events
from egsi.generation.safeio import AnchoredDirectory, BatchLock, active_batch_lock
from egsi.generation.training_ready import (
    ArtifactManifest as BaseArtifactManifest,
    CoverageReport as BaseCoverageReport,
    HumanAuditPacket as BaseHumanAuditPacket,
    TrajectoryReport as BaseTrajectoryReport,
    _artifact_kind,
    _load_batch_control_plane,
    _reject_root_overlap,
    _validate_batch_failure,
    _validate_batch_record,
    _validate_historical_v21,
    _write_exact,
)
from egsi.generation.trajectory import (
    compile_t1_episode,
    compile_t1_episode_frozen_v21,
    episode_commitment,
    read_parquet,
    write_jsonl,
    write_parquet,
)


_MAX_RECORD_BYTES = 2 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_BASE_COVERAGE = "reports/p0-coverage-provenance.json"
_P1_COVERAGE = "reports/p1-coverage-provenance.json"
_TRAJECTORY = "reports/trajectory-validation.json"
_AUDIT_JSON = "reports/human-audit-packet.json"
_AUDIT_MD = "reports/human-audit-packet.md"
_MANIFEST = "reports/artifact-manifest.json"
_MANIFEST_SIDECAR = "reports/artifact-manifest.json.sha256"
_PARQUET = "trajectories/train.parquet"
_OWNERSHIP = ".egsi-incremental-training-ready-owner.json"
_MAX_OWNERSHIP_BYTES = 1024 * 1024
_BASE_DIRECTORIES = ("enrichment", "episodes", "trajectories", "reports")
_EPISODE_ARTIFACT_RE = re.compile(
    r"^episodes/(EP-[0-9a-f]{32})\.(events|transitions)\.jsonl$"
)
_FIXED_OUTPUT_PATHS = frozenset(
    {
        _PARQUET,
        _P1_COVERAGE,
        _TRAJECTORY,
        _AUDIT_JSON,
        _AUDIT_MD,
        _MANIFEST,
        _MANIFEST_SIDECAR,
    }
)
_TRUSTED_P0_BASE_MANIFEST_SHA256 = (
    "sha256:2891fad8e9af6e8b5ee6000f49a822ee9fc22ff9e1514fef480b848983c6c1d3"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class BaseLineage(_StrictModel):
    base_manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_kind: Literal["historical_v21", "pragmatic_batch", "none"]
    source_root: str | None
    source_relative_path: str | None
    source_file_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    record_commitment_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )


class CoverageCase(_StrictModel):
    case_id: str
    status: Literal["success", "failed", "gap"]
    source_kind: Literal["base_training_ready", "pragmatic_batch", "none"]
    source_root: str | None
    source_relative_path: str | None
    source_file_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    record_commitment_sha256: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    output_relative_path: str | None
    reason: str | None
    base_lineage: BaseLineage | None = None

    @model_validator(mode="after")
    def consistent_status(self) -> "CoverageCase":
        if self.status == "success" and (
            self.record_commitment_sha256 is None
            or self.output_relative_path != f"enrichment/{self.case_id}.json"
            or self.reason is not None
        ):
            raise ValueError("successful coverage entry is incomplete")
        if self.status != "success" and (
            self.output_relative_path is not None
            or self.record_commitment_sha256 is not None
            or not self.reason
        ):
            raise ValueError("excluded coverage entry is inconsistent")
        if (self.source_kind == "base_training_ready") is (
            self.base_lineage is None
        ):
            raise ValueError("base lineage presence is inconsistent")
        return self


class CoverageReport(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["p1_coverage_provenance"] = "p1_coverage_provenance"
    requested: Literal[30] = 30
    base_requested: Literal[10] = 10
    incremental_requested: Literal[20] = 20
    success: int = Field(ge=0, le=30)
    failed: int = Field(ge=0, le=30)
    gap: int = Field(ge=0, le=30)
    requested_case_ids: list[str] = Field(min_length=30, max_length=30)
    base_case_ids: list[str] = Field(min_length=10, max_length=10)
    incremental_case_ids: list[str] = Field(min_length=20, max_length=20)
    success_case_ids: list[str]
    failed_case_ids: list[str]
    gap_case_ids: list[str]
    cases: list[CoverageCase] = Field(min_length=30, max_length=30)
    conservation_valid: Literal[True] = True

    @model_validator(mode="after")
    def conserve(self) -> "CoverageReport":
        if self.success + self.failed + self.gap != self.requested:
            raise ValueError("coverage conservation failed")
        if [case.case_id for case in self.cases] != self.requested_case_ids:
            raise ValueError("coverage order mismatch")
        expected = {
            status: [case.case_id for case in self.cases if case.status == status]
            for status in ("success", "failed", "gap")
        }
        if (
            self.success_case_ids != expected["success"]
            or self.failed_case_ids != expected["failed"]
            or self.gap_case_ids != expected["gap"]
            or self.success != len(expected["success"])
            or self.failed != len(expected["failed"])
            or self.gap != len(expected["gap"])
        ):
            raise ValueError("coverage status summary mismatch")
        return self


class TrajectoryReport(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["incremental_training_ready_trajectory"] = (
        "incremental_training_ready_trajectory"
    )
    requested: Literal[30] = 30
    processed: int = Field(ge=0, le=30)
    skipped: int = Field(ge=0, le=30)
    processed_case_ids: list[str]
    skipped_case_ids: list[str]
    transitions: int = Field(ge=0)
    parquet_file: str | None
    event_files: list[str]
    transition_files: list[str]
    policy_oracle_leakage: int = Field(ge=0)
    nonzero_t1_rewards: int = Field(ge=0)
    selected_illegal_actions: int = Field(ge=0)
    event_replay_passed: int = Field(ge=0)
    internal_invariant_failure: bool

    @model_validator(mode="after")
    def conserve(self) -> "TrajectoryReport":
        if self.processed + self.skipped != self.requested:
            raise ValueError("trajectory conservation failed")
        if (
            len(self.processed_case_ids) != self.processed
            or len(self.skipped_case_ids) != self.skipped
            or len(self.event_files) != self.processed
            or len(self.transition_files) != self.processed
            or self.event_replay_passed != self.processed
        ):
            raise ValueError("trajectory summary mismatch")
        if (self.parquet_file is None) is (self.transitions != 0):
            raise ValueError("trajectory Parquet presence mismatch")
        expected_failure = any(
            value != 0
            for value in (
                self.policy_oracle_leakage,
                self.nonzero_t1_rewards,
                self.selected_illegal_actions,
            )
        )
        if self.internal_invariant_failure is not expected_failure:
            raise ValueError("trajectory invariant summary mismatch")
        return self


class HumanAuditPacket(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["pragmatic_p1_human_audit"] = "pragmatic_p1_human_audit"
    requested: Literal[30] = 30
    training_samples: int = Field(ge=0, le=30)
    training_case_ids: list[str]
    excluded_case_ids: list[str]
    automated_gate_passed: bool
    informational_thresholds: dict[str, int]
    cases: list[dict[str, Any]] = Field(min_length=30, max_length=30)


class ArtifactEntry(_StrictModel):
    relative_path: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)
    kind: str
    case_id: str


class ArtifactManifest(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["incremental_training_ready_artifacts"] = (
        "incremental_training_ready_artifacts"
    )
    requested_case_ids: list[str] = Field(min_length=30, max_length=30)
    processed_case_ids: list[str]
    artifacts: list[ArtifactEntry]
    artifact_commitment_sha256: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )


class OutputOwnershipMarker(_StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    stage: Literal["incremental_training_ready_output_ownership"] = (
        "incremental_training_ready_output_ownership"
    )
    requested_case_ids: list[str] = Field(min_length=30, max_length=30)
    owned_relative_paths: list[str] = Field(min_length=7, max_length=1024)
    ownership_commitment_sha256: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )


@dataclass(frozen=True)
class _BaseEpisode:
    case_id: str
    record: EnrichmentRecord
    record_raw: bytes
    event_relative: str
    event_raw: bytes
    events: list[EpisodeEvent]
    transition_relative: str
    transition_raw: bytes
    transitions: list[T1Transition]
    lineage: BaseLineage


@dataclass(frozen=True)
class _BasePackage:
    manifest_sha256: str
    episodes: dict[str, _BaseEpisode]


@dataclass(frozen=True)
class _IncrementalEpisode:
    record: EnrichmentRecord
    record_raw: bytes
    source_relative: str
    transitions: list[T1Transition]
    events: list[EpisodeEvent]
    event_relative: str
    transition_relative: str
    metrics: tuple[int, int, int]


@dataclass(frozen=True)
class _OutputOwnershipState:
    owned_paths: frozenset[str]
    observed_paths: frozenset[str]
    observed_directories: frozenset[str]
    marker_present: bool


def _parse_jsonl(raw: bytes, kind: type[EpisodeEvent] | type[T1Transition]) -> list[Any]:
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 1024:
        raise ValueError("JSONL artifact is empty or oversized")
    return [kind.model_validate_json(line) for line in lines]


def _safe_relative(value: str) -> bool:
    if type(value) is not str:
        return False
    path = PurePosixPath(value)
    return bool(
        not path.is_absolute()
        and path.parts
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _inventory(root: Path) -> set[str]:
    try:
        with AnchoredDirectory(
            root,
            subdirectories=_BASE_DIRECTORIES,
            create=False,
        ) as artifacts:
            try:
                artifacts.stat_regular(Path(".egsi-batch.lock"))
            except FileNotFoundError:
                pass
            result = set(artifacts.list_regular())
            for directory in _BASE_DIRECTORIES:
                result.update(
                    f"{directory}/{name}"
                    for name in artifacts.list_regular(directory)
                )
            return result
    except Exception:
        raise ValueError("artifact tree is unsafe") from None


def _scan_output_tree(output_root: Path) -> tuple[set[str], set[str]]:
    active = active_batch_lock(output_root)
    if active is None or active.root_fd is None:
        raise RuntimeError("incremental output scan requires the active batch lock")
    directories: set[str] = set()
    files: set[str] = set()
    try:
        for name in os.listdir(active.root_fd):
            info = os.stat(name, dir_fd=active.root_fd, follow_symlinks=False)
            if name == ".egsi-batch.lock":
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError
                continue
            if name == _OWNERSHIP:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError
                files.add(name)
                continue
            if name not in _BASE_DIRECTORIES or not stat.S_ISDIR(info.st_mode):
                raise ValueError
            directory_fd = active.open_relative_directory((name,), create=False)
            try:
                opened = os.fstat(directory_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                ):
                    raise ValueError
                for child in os.listdir(directory_fd):
                    child_info = os.stat(
                        child,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(child_info.st_mode)
                        or child_info.st_nlink != 1
                    ):
                        raise ValueError
                    files.add(f"{name}/{child}")
                after = os.stat(
                    name,
                    dir_fd=active.root_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(after.st_mode)
                    or (after.st_dev, after.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    raise ValueError
            finally:
                os.close(directory_fd)
            directories.add(name)
        return directories, files
    except Exception:
        raise ValueError("incremental output ownership tree is unsafe") from None


def _validate_owned_output_paths(relative_paths: list[str], ids: list[str]) -> None:
    if (
        relative_paths != sorted(relative_paths)
        or len(relative_paths) != len(set(relative_paths))
        or not _FIXED_OUTPUT_PATHS.issubset(relative_paths)
        or any(not _safe_relative(relative) for relative in relative_paths)
    ):
        raise ValueError
    allowed_records = {f"enrichment/{case_id}.json" for case_id in ids}
    event_ids: set[str] = set()
    transition_ids: set[str] = set()
    for relative in relative_paths:
        if relative in _FIXED_OUTPUT_PATHS or relative in allowed_records:
            continue
        match = _EPISODE_ARTIFACT_RE.fullmatch(relative)
        if match is None:
            raise ValueError
        (event_ids if match.group(2) == "events" else transition_ids).add(
            match.group(1)
        )
    if event_ids != transition_ids:
        raise ValueError


def _legacy_output_ownership(
    output_root: Path,
    ids: list[str],
    directories: set[str],
    observed_paths: set[str],
) -> _OutputOwnershipState:
    if directories != set(_BASE_DIRECTORIES):
        raise ValueError
    manifest_raw = _read_regular(
        output_root / _MANIFEST,
        limit=_MAX_ARTIFACT_BYTES,
    )
    sidecar_raw = _read_regular(output_root / _MANIFEST_SIDECAR, limit=80)
    manifest = ArtifactManifest.model_validate_json(manifest_raw)
    manifest_value = manifest.model_dump(mode="json")
    relative_paths = [entry.relative_path for entry in manifest.artifacts]
    owned_paths = sorted({*relative_paths, _MANIFEST, _MANIFEST_SIDECAR})
    _validate_owned_output_paths(owned_paths, ids)
    processed = set(manifest.processed_case_ids)
    if (
        manifest.requested_case_ids != ids
        or manifest.processed_case_ids
        != [case_id for case_id in ids if case_id in processed]
        or len(processed) != len(manifest.processed_case_ids)
        or relative_paths != sorted(relative_paths)
        or len(relative_paths) != len(set(relative_paths))
        or set(owned_paths) != observed_paths
        or _dict_commitment(manifest_value, "artifact_commitment_sha256")
        != manifest.artifact_commitment_sha256
        or sidecar_raw != (_sha256(manifest_raw) + "\n").encode("ascii")
    ):
        raise ValueError
    for entry in manifest.artifacts:
        raw = _read_regular(
            output_root / entry.relative_path,
            limit=_MAX_ARTIFACT_BYTES,
        )
        kind, default_case = _artifact_kind(entry.relative_path)
        if entry.relative_path.startswith("episodes/"):
            case_valid = entry.case_id in processed
        else:
            case_valid = entry.case_id == default_case
        if (
            not raw
            or len(raw) != entry.size_bytes
            or _sha256(raw) != entry.sha256
            or entry.kind != kind
            or not case_valid
        ):
            raise ValueError
    return _OutputOwnershipState(
        owned_paths=frozenset(owned_paths),
        observed_paths=frozenset(observed_paths),
        observed_directories=frozenset(directories),
        marker_present=False,
    )


def _preflight_output_ownership(
    output_root: Path,
    ids: list[str],
) -> _OutputOwnershipState:
    try:
        directories, observed_paths = _scan_output_tree(output_root)
        marker_present = _OWNERSHIP in observed_paths
        business_paths = observed_paths - {_OWNERSHIP}
        if marker_present:
            raw = _read_regular(
                output_root / _OWNERSHIP,
                limit=_MAX_OWNERSHIP_BYTES,
            )
            marker = OutputOwnershipMarker.model_validate_json(raw)
            marker_value = marker.model_dump(mode="json")
            _validate_owned_output_paths(marker.owned_relative_paths, ids)
            owned_paths = frozenset(marker.owned_relative_paths)
            if (
                marker.requested_case_ids != ids
                or _dict_commitment(
                    marker_value,
                    "ownership_commitment_sha256",
                )
                != marker.ownership_commitment_sha256
                or not business_paths.issubset(owned_paths)
            ):
                raise ValueError
            return _OutputOwnershipState(
                owned_paths=owned_paths,
                observed_paths=frozenset(observed_paths),
                observed_directories=frozenset(directories),
                marker_present=True,
            )
        if not directories and not business_paths:
            return _OutputOwnershipState(
                owned_paths=frozenset(),
                observed_paths=frozenset(),
                observed_directories=frozenset(),
                marker_present=False,
            )
        return _legacy_output_ownership(
            output_root,
            ids,
            directories,
            business_paths,
        )
    except Exception:
        raise ValueError("incremental output ownership is invalid") from None


def _write_output_ownership(
    output_root: Path,
    ids: list[str],
    owned_paths: set[str],
) -> None:
    relative_paths = sorted(owned_paths)
    _validate_owned_output_paths(relative_paths, ids)
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "incremental_training_ready_output_ownership",
        "requested_case_ids": ids,
        "owned_relative_paths": relative_paths,
        "ownership_commitment_sha256": "sha256:" + "0" * 64,
    }
    value["ownership_commitment_sha256"] = _dict_commitment(
        value,
        "ownership_commitment_sha256",
    )
    marker = OutputOwnershipMarker.model_validate(value)
    write_report(output_root / _OWNERSHIP, marker.model_dump(mode="json"))


def _clear_incremental_owned_output(
    output_root: Path,
    ids: list[str],
    *,
    state: _OutputOwnershipState | None = None,
) -> None:
    current = _preflight_output_ownership(output_root, ids) if state is None else state
    for relative in sorted(current.owned_paths):
        _remove_regular_if_present(output_root / relative)


def _claim_incremental_output(
    output_root: Path,
    ids: list[str],
    planned_paths: set[str],
    initial: _OutputOwnershipState,
) -> None:
    current = _preflight_output_ownership(output_root, ids)
    if current != initial:
        raise ValueError("incremental output ownership changed during build")
    _write_output_ownership(
        output_root,
        ids,
        set(current.owned_paths).union(planned_paths),
    )
    _clear_incremental_owned_output(output_root, ids, state=current)
    _directories, remaining = _scan_output_tree(output_root)
    if remaining != {_OWNERSHIP}:
        raise ValueError("incremental output ownership changed during cleanup")
    _write_output_ownership(output_root, ids, planned_paths)


def _validate_base_package(
    root: Path,
    base_root: Path,
    p0_ids: list[str],
    catalog: dict[str, Any],
) -> _BasePackage:
    try:
        coverage_raw = _read_regular(base_root / _BASE_COVERAGE)
        trajectory_raw = _read_regular(base_root / _TRAJECTORY)
        audit_raw = _read_regular(base_root / _AUDIT_JSON)
        manifest_raw = _read_regular(base_root / _MANIFEST)
        sidecar_raw = _read_regular(base_root / _MANIFEST_SIDECAR, limit=80)
        coverage = BaseCoverageReport.model_validate_json(coverage_raw)
        trajectory = BaseTrajectoryReport.model_validate_json(trajectory_raw)
        audit = BaseHumanAuditPacket.model_validate_json(audit_raw)
        manifest = BaseArtifactManifest.model_validate_json(manifest_raw)
        manifest_sha = _sha256(manifest_raw)
        if (
            manifest_sha != _TRUSTED_P0_BASE_MANIFEST_SHA256
            or sidecar_raw != (manifest_sha + "\n").encode("ascii")
        ):
            raise ValueError
        if (
            coverage.requested_case_ids != p0_ids
            or coverage.success_case_ids != p0_ids
            or coverage.success != 10
            or coverage.failed != 0
            or coverage.gap != 0
            or any(case.status != "success" for case in coverage.cases)
            or trajectory.requested != 10
            or trajectory.processed != 10
            or trajectory.skipped != 0
            or trajectory.processed_case_ids != p0_ids
            or trajectory.skipped_case_ids != []
            or trajectory.parquet_file != _PARQUET
            or trajectory.policy_oracle_leakage != 0
            or trajectory.nonzero_t1_rewards != 0
            or trajectory.selected_illegal_actions != 0
            or trajectory.event_replay_passed != 10
            or trajectory.internal_invariant_failure is not False
            or len(trajectory.event_files) != 10
            or len(trajectory.transition_files) != 10
            or audit.training_samples != 10
            or audit.training_case_ids != p0_ids
            or audit.excluded_case_ids != []
            or audit.automated_gate_passed is not True
            or audit.cases
            != [case.model_dump(mode="json") for case in coverage.cases]
            or manifest.requested_case_ids != p0_ids
            or manifest.processed_case_ids != p0_ids
            or _dict_commitment(
                manifest.model_dump(mode="json"),
                "artifact_commitment_sha256",
            )
            != manifest.artifact_commitment_sha256
        ):
            raise ValueError

        expected_paths = {
            *(f"enrichment/{case_id}.json" for case_id in p0_ids),
            *trajectory.event_files,
            *trajectory.transition_files,
            _PARQUET,
            _BASE_COVERAGE,
            _TRAJECTORY,
            _AUDIT_JSON,
            _AUDIT_MD,
        }
        entries = manifest.artifacts
        relative_paths = [entry.relative_path for entry in entries]
        if (
            relative_paths != sorted(relative_paths)
            or len(relative_paths) != len(set(relative_paths))
            or set(relative_paths) != expected_paths
            or any(not _safe_relative(relative) for relative in relative_paths)
        ):
            raise ValueError
        event_case = dict(zip(trajectory.event_files, p0_ids, strict=True))
        transition_case = dict(
            zip(trajectory.transition_files, p0_ids, strict=True)
        )
        for entry in entries:
            raw = _read_regular(
                base_root / entry.relative_path,
                limit=_MAX_ARTIFACT_BYTES,
            )
            kind, default_case = _artifact_kind(entry.relative_path)
            expected_case = event_case.get(
                entry.relative_path,
                transition_case.get(entry.relative_path, default_case),
            )
            if (
                not raw
                or _sha256(raw) != entry.sha256
                or entry.kind != kind
                or entry.case_id != expected_case
            ):
                raise ValueError
        expected_inventory = {
            *expected_paths,
            _MANIFEST,
            _MANIFEST_SIDECAR,
        }
        observed_inventory = _inventory(base_root)
        if observed_inventory - {".egsi-batch.lock"} != expected_inventory:
            raise ValueError

        parquet_rows = read_parquet(base_root / _PARQUET)
        all_transitions: list[T1Transition] = []
        episodes: dict[str, _BaseEpisode] = {}
        episode_ids: set[str] = set()
        for case_id, event_relative, transition_relative, coverage_case in zip(
            p0_ids,
            trajectory.event_files,
            trajectory.transition_files,
            coverage.cases,
            strict=True,
        ):
            record_relative = f"enrichment/{case_id}.json"
            record_raw = _read_regular(
                base_root / record_relative,
                limit=_MAX_RECORD_BYTES,
            )
            record = EnrichmentRecord.model_validate_json(record_raw)
            event_raw = _read_regular(
                base_root / event_relative,
                limit=_MAX_ARTIFACT_BYTES,
            )
            transition_raw = _read_regular(
                base_root / transition_relative,
                limit=_MAX_ARTIFACT_BYTES,
            )
            events = _parse_jsonl(event_raw, EpisodeEvent)
            transitions = _parse_jsonl(transition_raw, T1Transition)
            episode_id = transitions[0].episode_id
            expected_policy_case_id = policy_case_id(catalog[case_id])
            if (
                record.case_id != case_id
                or record.generation_mode != "live"
                or record.validation.valid is not True
                or coverage_case.output_relative_path != record_relative
                or coverage_case.source_file_sha256 != _sha256(record_raw)
                or coverage_case.record_commitment_sha256
                != record.record_commitment_sha256
                or not all(item.episode_id == episode_id for item in transitions)
                or not all(item.episode_id == episode_id for item in events)
                or event_relative != f"episodes/{episode_id}.events.jsonl"
                or transition_relative
                != f"episodes/{episode_id}.transitions.jsonl"
                or episode_id in episode_ids
                or not all(
                    item.state.get("case_id") == expected_policy_case_id
                    for item in transitions
                )
                or events[0].payload.get("policy_seed", {}).get("case_id")
                != expected_policy_case_id
            ):
                raise ValueError
            if coverage_case.source_kind == "historical_v21":
                if _validate_historical_v21(
                    root, catalog[case_id], record_raw
                ) != record:
                    raise ValueError
                expected_transitions, expected_events = (
                    compile_t1_episode_frozen_v21(
                        catalog[case_id], record, root=root
                    )
                )
            else:
                if not _record_is_current(root, catalog[case_id], record):
                    raise ValueError
                expected_transitions, expected_events = compile_t1_episode(
                    catalog[case_id], record, root=root
                )
            if transitions != expected_transitions or events != expected_events:
                raise ValueError
            commitment = episode_commitment(transitions, events)
            replay = replay_events(
                events,
                transitions,
                expected_commitment_sha256=commitment,
            )
            metrics = _episode_metrics(
                catalog[case_id], record, transitions, events
            )
            if replay.get("closed") is not True or metrics != (0, 0, 0):
                raise ValueError
            episode_ids.add(episode_id)
            all_transitions.extend(transitions)
            episodes[case_id] = _BaseEpisode(
                case_id=case_id,
                record=record,
                record_raw=record_raw,
                event_relative=event_relative,
                event_raw=event_raw,
                events=events,
                transition_relative=transition_relative,
                transition_raw=transition_raw,
                transitions=transitions,
                lineage=BaseLineage(
                    base_manifest_sha256=manifest_sha,
                    source_kind=coverage_case.source_kind,
                    source_root=coverage_case.source_root,
                    source_relative_path=coverage_case.source_relative_path,
                    source_file_sha256=coverage_case.source_file_sha256,
                    record_commitment_sha256=(
                        coverage_case.record_commitment_sha256
                    ),
                ),
            )
        if (
            parquet_rows != all_transitions
            or trajectory.transitions != len(all_transitions)
        ):
            raise ValueError
        return _BasePackage(manifest_sha256=manifest_sha, episodes=episodes)
    except Exception:
        raise ValueError("base training-ready package is invalid") from None


def _load_incremental_control(root: Path, batch_root: Path, ids: list[str]):
    try:
        control = _load_batch_control_plane(root, batch_root, ids)
        if control is None or control.state.generation_mode != "live":
            raise ValueError
        return control
    except Exception:
        raise ValueError("incremental pragmatic batch provenance is invalid") from None


def _excluded_case(
    *,
    case_id: str,
    status: Literal["failed", "gap"],
    source_kind: Literal["pragmatic_batch", "none"],
    source_root: Path | None,
    source_relative_path: str | None,
    source_file_sha256: str | None,
    reason: str,
) -> CoverageCase:
    return CoverageCase(
        case_id=case_id,
        status=status,
        source_kind=source_kind,
        source_root=None if source_root is None else str(source_root),
        source_relative_path=source_relative_path,
        source_file_sha256=source_file_sha256,
        record_commitment_sha256=None,
        output_relative_path=None,
        reason=reason,
        base_lineage=None,
    )


def _read_incremental_terminal_artifact(
    batch_root: Path,
    relative: str,
) -> tuple[bytes | None, bool]:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or len(path.parts) not in {1, 2}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("incremental artifact path is unsafe")
    subdirectories = () if len(path.parts) == 1 else (path.parts[0],)
    try:
        with AnchoredDirectory(
            batch_root / "enrichment",
            subdirectories=subdirectories,
            create=False,
        ) as artifacts:
            return artifacts.read_regular(Path(relative), limit=_MAX_RECORD_BYTES), False
    except FileNotFoundError:
        return None, False
    except OverflowError:
        return None, True


def _build_locked(
    *,
    root: Path,
    ids: list[str],
    p0_ids: list[str],
    incremental_ids: list[str],
    base_root: Path,
    incremental_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    output_ownership = _preflight_output_ownership(output_root, ids)
    catalog = catalog_index(root)
    if any(case_id not in catalog for case_id in ids):
        raise ValueError("P1 case is absent from the catalog")
    base = _validate_base_package(root, base_root, p0_ids, catalog)
    control = _load_incremental_control(root, incremental_root, incremental_ids)
    state_by_id = {case.case_id: case for case in control.state.cases}

    coverage_by_id: dict[str, CoverageCase] = {}
    incremental_records: dict[str, tuple[EnrichmentRecord, bytes, str]] = {}
    for case_id in incremental_ids:
        case_state = state_by_id[case_id]
        artifact = control.artifacts[case_id]
        relative = f"enrichment/{artifact.relative_path}"
        if case_state.terminal_status == "success":
            raw, oversized = _read_incremental_terminal_artifact(
                incremental_root,
                artifact.relative_path,
            )
            if raw is None:
                coverage_by_id[case_id] = _excluded_case(
                    case_id=case_id,
                    status="gap",
                    source_kind="pragmatic_batch",
                    source_root=incremental_root,
                    source_relative_path=relative,
                    source_file_sha256=None,
                    reason=(
                        "batch_record_provenance_invalid"
                        if oversized
                        else "batch_result_missing"
                    ),
                )
                continue
            try:
                record = _validate_batch_record(
                    root,
                    catalog[case_id],
                    raw,
                    control,
                )
            except ValueError:
                coverage_by_id[case_id] = _excluded_case(
                    case_id=case_id,
                    status="gap",
                    source_kind="pragmatic_batch",
                    source_root=incremental_root,
                    source_relative_path=relative,
                    source_file_sha256=_sha256(raw),
                    reason="batch_record_provenance_invalid",
                )
                continue
            incremental_records[case_id] = (record, raw, relative)
            continue
        raw, _oversized = _read_incremental_terminal_artifact(
            incremental_root,
            artifact.relative_path,
        )
        if raw is None:
            coverage_by_id[case_id] = _excluded_case(
                case_id=case_id,
                status="gap",
                source_kind="pragmatic_batch",
                source_root=incremental_root,
                source_relative_path=relative,
                source_file_sha256=None,
                reason="batch_failure_provenance_invalid",
            )
            continue
        try:
            receipt, failure_raw = _validate_batch_failure(
                control,
                case_state,
                raw=raw,
            )
        except ValueError:
            coverage_by_id[case_id] = _excluded_case(
                case_id=case_id,
                status="gap",
                source_kind="pragmatic_batch",
                source_root=incremental_root,
                source_relative_path=relative,
                source_file_sha256=_sha256(raw),
                reason="batch_failure_provenance_invalid",
            )
            continue
        coverage_by_id[case_id] = _excluded_case(
            case_id=case_id,
            status="failed",
            source_kind="pragmatic_batch",
            source_root=incremental_root,
            source_relative_path=relative,
            source_file_sha256=_sha256(failure_raw),
            reason=receipt.error_kind,
        )

    incremental_episodes: dict[str, _IncrementalEpisode] = {}
    used_episode_ids = {
        episode.transitions[0].episode_id for episode in base.episodes.values()
    }
    used_episode_paths = {
        relative
        for episode in base.episodes.values()
        for relative in (episode.event_relative, episode.transition_relative)
    }
    for case_id in incremental_ids:
        candidate = incremental_records.get(case_id)
        if candidate is None:
            continue
        record, raw, source_relative = candidate
        try:
            transitions, events = compile_t1_episode(
                catalog[case_id], record, root=root
            )
            commitment = episode_commitment(transitions, events)
            replay = replay_events(
                events,
                transitions,
                expected_commitment_sha256=commitment,
            )
            case_metrics = _episode_metrics(
                catalog[case_id], record, transitions, events
            )
            if replay.get("closed") is not True or case_metrics != (0, 0, 0):
                raise ValueError("incremental trajectory invariant failed")
        except Exception:
            coverage_by_id[case_id] = _excluded_case(
                case_id=case_id,
                status="gap",
                source_kind="pragmatic_batch",
                source_root=incremental_root,
                source_relative_path=source_relative,
                source_file_sha256=_sha256(raw),
                reason="trajectory_compile_failed",
            )
            continue
        episode_id = transitions[0].episode_id
        event_relative = f"episodes/{episode_id}.events.jsonl"
        transition_relative = f"episodes/{episode_id}.transitions.jsonl"
        paths = {event_relative, transition_relative}
        if episode_id in used_episode_ids or used_episode_paths.intersection(paths):
            raise ValueError("episode ID/path collision")
        used_episode_ids.add(episode_id)
        used_episode_paths.update(paths)
        incremental_episodes[case_id] = _IncrementalEpisode(
            record=record,
            record_raw=raw,
            source_relative=source_relative,
            transitions=transitions,
            events=events,
            event_relative=event_relative,
            transition_relative=transition_relative,
            metrics=case_metrics,
        )

    planned_success_ids = [
        case_id
        for case_id in ids
        if case_id in base.episodes or case_id in incremental_episodes
    ]
    planned_paths = {
        *_FIXED_OUTPUT_PATHS,
        *(f"enrichment/{case_id}.json" for case_id in planned_success_ids),
        *(
            relative
            for episode in base.episodes.values()
            for relative in (episode.event_relative, episode.transition_relative)
        ),
        *(
            relative
            for episode in incremental_episodes.values()
            for relative in (episode.event_relative, episode.transition_relative)
        ),
    }
    _claim_incremental_output(
        output_root,
        ids,
        planned_paths,
        output_ownership,
    )

    transitions_all: list[T1Transition] = []
    event_files: list[str] = []
    transition_files: list[str] = []
    leakage = 0
    nonzero = 0
    illegal = 0
    replay_passed = 0

    for case_id in ids:
        if case_id in base.episodes:
            episode = base.episodes[case_id]
            _write_exact(
                output_root / f"enrichment/{case_id}.json",
                episode.record_raw,
            )
            _write_exact(
                output_root / episode.event_relative,
                episode.event_raw,
            )
            _write_exact(
                output_root / episode.transition_relative,
                episode.transition_raw,
            )
            coverage_by_id[case_id] = CoverageCase(
                case_id=case_id,
                status="success",
                source_kind="base_training_ready",
                source_root=str(base_root),
                source_relative_path=f"enrichment/{case_id}.json",
                source_file_sha256=_sha256(episode.record_raw),
                record_commitment_sha256=(
                    episode.record.record_commitment_sha256
                ),
                output_relative_path=f"enrichment/{case_id}.json",
                reason=None,
                base_lineage=episode.lineage,
            )
            transitions_all.extend(episode.transitions)
            event_files.append(episode.event_relative)
            transition_files.append(episode.transition_relative)
            replay_passed += 1
            continue

        episode = incremental_episodes.get(case_id)
        if episode is None:
            continue
        record = episode.record
        raw = episode.record_raw
        source_relative = episode.source_relative
        transitions = episode.transitions
        events = episode.events
        event_relative = episode.event_relative
        transition_relative = episode.transition_relative
        case_metrics = episode.metrics
        try:
            write_jsonl(output_root / event_relative, events)
            write_jsonl(output_root / transition_relative, transitions)
            _write_exact(output_root / f"enrichment/{case_id}.json", raw)
            if (
                _parse_jsonl(
                    _read_regular(output_root / event_relative), EpisodeEvent
                )
                != events
                or _parse_jsonl(
                    _read_regular(output_root / transition_relative),
                    T1Transition,
                )
                != transitions
                or _read_regular(
                    output_root / f"enrichment/{case_id}.json",
                    limit=_MAX_RECORD_BYTES,
                )
                != raw
            ):
                raise ValueError("incremental artifact readback mismatch")
        except Exception:
            for relative in (
                f"enrichment/{case_id}.json",
                event_relative,
                transition_relative,
            ):
                _remove_regular_if_present(output_root / relative)
            raise
        coverage_by_id[case_id] = CoverageCase(
            case_id=case_id,
            status="success",
            source_kind="pragmatic_batch",
            source_root=str(incremental_root),
            source_relative_path=source_relative,
            source_file_sha256=_sha256(raw),
            record_commitment_sha256=record.record_commitment_sha256,
            output_relative_path=f"enrichment/{case_id}.json",
            reason=None,
            base_lineage=None,
        )
        transitions_all.extend(transitions)
        event_files.append(event_relative)
        transition_files.append(transition_relative)
        leakage += case_metrics[0]
        nonzero += case_metrics[1]
        illegal += case_metrics[2]
        replay_passed += 1

    coverage_cases = [coverage_by_id[case_id] for case_id in ids]
    success_ids = [case.case_id for case in coverage_cases if case.status == "success"]
    failed_ids = [case.case_id for case in coverage_cases if case.status == "failed"]
    gap_ids = [case.case_id for case in coverage_cases if case.status == "gap"]
    coverage = CoverageReport(
        success=len(success_ids),
        failed=len(failed_ids),
        gap=len(gap_ids),
        requested_case_ids=ids,
        base_case_ids=p0_ids,
        incremental_case_ids=incremental_ids,
        success_case_ids=success_ids,
        failed_case_ids=failed_ids,
        gap_case_ids=gap_ids,
        cases=coverage_cases,
    )
    coverage_value = coverage.model_dump(mode="json")
    write_report(output_root / _P1_COVERAGE, coverage_value)

    parquet_path = output_root / _PARQUET
    if transitions_all:
        write_parquet(parquet_path, transitions_all)
        if read_parquet(parquet_path) != transitions_all:
            raise RuntimeError("incremental training Parquet readback mismatch")
        parquet_file: str | None = _PARQUET
    else:
        parquet_file = None
    trajectory = TrajectoryReport(
        processed=len(success_ids),
        skipped=30 - len(success_ids),
        processed_case_ids=success_ids,
        skipped_case_ids=[case_id for case_id in ids if case_id not in success_ids],
        transitions=len(transitions_all),
        parquet_file=parquet_file,
        event_files=event_files,
        transition_files=transition_files,
        policy_oracle_leakage=leakage,
        nonzero_t1_rewards=nonzero,
        selected_illegal_actions=illegal,
        event_replay_passed=replay_passed,
        internal_invariant_failure=any(
            value != 0 for value in (leakage, nonzero, illegal)
        ),
    )
    trajectory_value = trajectory.model_dump(mode="json")
    write_report(output_root / _TRAJECTORY, trajectory_value)

    audit = HumanAuditPacket(
        training_samples=len(success_ids),
        training_case_ids=success_ids,
        excluded_case_ids=[case_id for case_id in ids if case_id not in success_ids],
        automated_gate_passed=(
            trajectory.internal_invariant_failure is False
            and trajectory.event_replay_passed == len(success_ids)
            and trajectory.processed == len(success_ids)
        ),
        informational_thresholds={
            "base_expected": 10,
            "incremental_expected": 20,
        },
        cases=[case.model_dump(mode="json") for case in coverage_cases],
    )
    audit_value = audit.model_dump(mode="json")
    write_report(output_root / _AUDIT_JSON, audit_value)
    markdown_lines = [
        "# Pragmatic P1 Incremental Human Audit Packet",
        "",
        f"Training samples: {len(success_ids)}/30",
        "",
        "| Case | Status | Source | Reason |",
        "|---|---|---|---|",
        *(
            f"| {case.case_id} | {case.status} | {case.source_kind} | {case.reason or '-'} |"
            for case in coverage_cases
        ),
        "",
        "Coverage thresholds are informational; only structurally valid, replay-closed successes become training samples.",
        "",
    ]
    _write_exact(
        output_root / _AUDIT_MD,
        "\n".join(markdown_lines).encode("utf-8"),
    )

    artifact_paths = [
        *(f"enrichment/{case_id}.json" for case_id in success_ids),
        *event_files,
        *transition_files,
        *([_PARQUET] if transitions_all else []),
        _P1_COVERAGE,
        _TRAJECTORY,
        _AUDIT_JSON,
        _AUDIT_MD,
    ]
    episode_case = dict(zip(event_files, success_ids, strict=True))
    episode_case.update(dict(zip(transition_files, success_ids, strict=True)))
    entries: list[ArtifactEntry] = []
    for relative in sorted(artifact_paths):
        raw = _read_regular(output_root / relative, limit=_MAX_ARTIFACT_BYTES)
        kind, default_case = _artifact_kind(relative)
        entries.append(
            ArtifactEntry(
                relative_path=relative,
                sha256=_sha256(raw),
                size_bytes=len(raw),
                kind=kind,
                case_id=episode_case.get(relative, default_case),
            )
        )
    manifest_value: dict[str, Any] = {
        "schema_version": "1.0",
        "stage": "incremental_training_ready_artifacts",
        "requested_case_ids": ids,
        "processed_case_ids": success_ids,
        "artifacts": [entry.model_dump(mode="json") for entry in entries],
        "artifact_commitment_sha256": "sha256:" + "0" * 64,
    }
    manifest_value["artifact_commitment_sha256"] = _dict_commitment(
        manifest_value, "artifact_commitment_sha256"
    )
    manifest = ArtifactManifest.model_validate(manifest_value)
    write_report(output_root / _MANIFEST, manifest.model_dump(mode="json"))
    manifest_sha = _sha256(_read_regular(output_root / _MANIFEST))
    _write_exact(
        output_root / _MANIFEST_SIDECAR,
        (manifest_sha + "\n").encode("ascii"),
    )
    final_ownership = _preflight_output_ownership(output_root, ids)
    if final_ownership.observed_paths != frozenset({*planned_paths, _OWNERSHIP}):
        raise ValueError("incremental output inventory is incomplete")
    return coverage_value


def _build_or_clear(**kwargs: Any) -> dict[str, Any]:
    output_root = kwargs["output_root"]
    try:
        return _build_locked(**kwargs)
    except Exception:
        try:
            _clear_incremental_owned_output(output_root, kwargs["ids"])
        except Exception:
            pass
        raise


def build_incremental_training_ready(
    *,
    root: Path,
    case_ids: list[str],
    base_package_root: Path,
    incremental_batch_root: Path,
    incremental_case_ids: list[str],
    output_root: Path,
) -> dict[str, Any]:
    """Build fixed P1 artifacts without invoking a teacher or mutating sources."""

    root = Path(root)
    base_root = Path(base_package_root)
    incremental_root = Path(incremental_batch_root)
    output_root = Path(output_root)
    _reject_root_overlap(output_root, base_root, incremental_root)
    ids = _validate_case_ids(case_ids)
    incremental_ids = _validate_case_ids(incremental_case_ids)
    p0_ids = read_case_ids(root / "configs/p0_cases.txt")
    frozen_p1_ids = read_case_ids(root / "configs/p1_cases.txt")
    expected_incremental = [
        case_id for case_id in frozen_p1_ids if case_id not in p0_ids
    ]
    if (
        ids != frozen_p1_ids
        or len(ids) != 30
        or len(p0_ids) != 10
        or incremental_ids != expected_incremental
        or len(incremental_ids) != 20
        or set(p0_ids).intersection(incremental_ids)
        or set(p0_ids).union(incremental_ids) != set(ids)
    ):
        raise ValueError("incremental training-ready case lists are invalid")
    build_kwargs = {
        "root": root,
        "ids": ids,
        "p0_ids": p0_ids,
        "incremental_ids": incremental_ids,
        "base_root": base_root,
        "incremental_root": incremental_root,
        "output_root": output_root,
    }
    if active_batch_lock(output_root) is not None:
        return _build_or_clear(**build_kwargs)
    with BatchLock(output_root):
        return _build_or_clear(**build_kwargs)
