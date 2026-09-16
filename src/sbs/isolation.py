"""Actor/evaluator root isolation. Reads never cross the actor root."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from sbs.errors import (
    EvaluatorReadError,
    HashMismatchError,
    MissingEvidenceError,
    PathEscapeError,
    StaleEvidenceError,
    UnauthorizedEvidenceError,
)
from sbs.schema import CaseView, EvidenceRecord, Observation, sha256_bytes


def _is_relative_posix(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and "\\" not in value
        and not any(part in {"", ".", ".."} for part in path.parts)
    )


class IsolatedStore:
    """File reader bound to one actor root. Evaluator roots are unreadable."""

    def __init__(
        self,
        actor_root: Path,
        evaluator_root: Path | None = None,
    ) -> None:
        self.actor_root = Path(actor_root).resolve()
        self.evaluator_root = (
            Path(evaluator_root).resolve() if evaluator_root is not None else None
        )
        self.read_paths: list[Path] = []

    def resolve_actor_path(self, relative: str) -> Path:
        if not _is_relative_posix(relative):
            raise PathEscapeError("path must be a relative POSIX path without '..'")
        resolved = (self.actor_root / relative).resolve()
        try:
            resolved.relative_to(self.actor_root)
        except ValueError as exc:
            raise PathEscapeError("path escapes actor root") from exc
        if self.evaluator_root is not None:
            try:
                resolved.relative_to(self.evaluator_root)
            except ValueError:
                pass
            else:
                raise EvaluatorReadError("path is inside the evaluator root")
        return resolved

    def read_bytes(self, relative: str) -> bytes:
        path = self.resolve_actor_path(relative)
        self.read_paths.append(path)
        if self.evaluator_root is not None:
            try:
                path.relative_to(self.evaluator_root)
            except ValueError:
                pass
            else:
                raise EvaluatorReadError("refusing evaluator-root read")
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise MissingEvidenceError(f"missing actor path: {relative}") from exc

    def read_text(self, relative: str) -> str:
        return self.read_bytes(relative).decode("utf-8")

    def evaluator_was_read(self) -> bool:
        if self.evaluator_root is None:
            return False
        for path in self.read_paths:
            try:
                path.relative_to(self.evaluator_root)
                return True
            except ValueError:
                continue
        return False

    def load_evidence_record(self, evidence_id: str) -> EvidenceRecord:
        relative = f"evidence/{evidence_id}.json"
        payload = self.read_text(relative)
        return EvidenceRecord.model_validate_json(payload)

    def read_evidence(
        self,
        case: CaseView,
        evidence_id: str,
        *,
        expected_generation: str | None = None,
    ) -> tuple[EvidenceRecord, Observation]:
        if evidence_id not in case.allowed_evidence_ids:
            raise UnauthorizedEvidenceError(
                f"evidence_id {evidence_id!r} is not on the allow-list"
            )
        try:
            record = self.load_evidence_record(evidence_id)
        except MissingEvidenceError as exc:
            raise MissingEvidenceError(
                f"allow-listed evidence {evidence_id!r} is missing"
            ) from exc
        if record.evidence_id != evidence_id:
            raise HashMismatchError("evidence_id does not match filename")
        body = self.read_bytes(record.relative_read_path)
        digest = sha256_bytes(body)
        if digest != record.content_sha256:
            raise HashMismatchError(
                f"hash mismatch for {evidence_id}: {digest} != {record.content_sha256}"
            )
        if (
            expected_generation is not None
            and record.generation_id is not None
            and record.generation_id != expected_generation
        ):
            raise StaleEvidenceError(
                f"stale evidence {evidence_id}: generation "
                f"{record.generation_id} != {expected_generation}"
            )
        if (
            record.generation_id is not None
            and expected_generation is None
            and record.generation_id.endswith("-stale")
        ):
            raise StaleEvidenceError(f"stale evidence {evidence_id}")
        try:
            text = body.decode("utf-8")
            parseable = True
        except UnicodeError:
            text = None
            parseable = False
        observation = Observation(
            evidence_id=evidence_id,
            material=text,
            parseable=parseable,
            provenance=record.display_path,
            uncertainty="none" if parseable else "not_found_unparseable",
            found=parseable,
        )
        return record, observation


def load_case_view(store: IsolatedStore) -> CaseView:
    from sbs.schema import parse_case_view
    import json

    payload: Any = json.loads(store.read_text("case.json"))
    return parse_case_view(payload)
