"""Bounded, deterministic oracle-only context for teacher enrichment.

The returned object is deliberately separate from policy-facing inputs.  It may
contain the advisory, patch, and vulnerable source, so callers must not feed it
to a policy or deployment agent.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_serializer,
    field_validator,
    model_validator,
)

from egsi.contracts.case import CaseManifest
from egsi.data.git_objects import GitCacheGuard, GitObjectStore, validate_path


_CWE_RE = re.compile(r"^CWE-[0-9]+$")
_TRUNCATION_MARKER = "\n...[deterministically truncated]...\n"
_ADVISORY_LIMIT = 12_000
_PATCH_LIMIT = 24_000
_RAW_PATCH_MAX_BYTES = 2 * 1024 * 1024
_PATCH_LINE_MAX_BYTES = 64 * 1024
_SOURCE_BLOB_MAX_BYTES = 4 * 1024 * 1024
_CANONICAL_RENDER_MAX_CHARS = 64_000
_HUNK_CONTEXT_LINES = 40
_MAX_SELECTED_FILES = 32
_MAX_SELECTED_HUNKS = 64
MAX_AFFECTED_LOCATIONS = 256


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def bounded(text: str, limit: int) -> str:
    """Return a deterministic head/tail summary that never exceeds *limit*.

    For limits shorter than the marker itself, a prefix is the only possible
    bounded representation; otherwise the full marker separates equal-ish head
    and tail portions.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError("limit must be an integer")
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit < len(_TRUNCATION_MARKER):
        return _TRUNCATION_MARKER[:limit]
    remaining = limit - len(_TRUNCATION_MARKER)
    head_length = (remaining + 1) // 2
    tail_length = remaining - head_length
    tail = text[-tail_length:] if tail_length else ""
    return text[:head_length] + _TRUNCATION_MARKER + tail


@dataclass(frozen=True, slots=True)
class _FrozenSourceFiles(Mapping[str, str]):
    """A compact immutable mapping, deliberately not a ``dict`` subclass."""

    _items: tuple[tuple[str, str], ...]

    def __init__(self, value: Mapping[str, str]) -> None:
        if not isinstance(value, Mapping):
            raise TypeError("source_files must be a mapping")
        items: list[tuple[str, str]] = []
        for path, text in value.items():
            if not isinstance(path, str) or not isinstance(text, str):
                raise TypeError("source_files must map strings to strings")
            validate_path(path)
            items.append((path, text))
        object.__setattr__(self, "_items", tuple(sorted(items)))

    def __getitem__(self, key: str) -> str:
        for path, text in self._items:
            if path == key:
                return text
        raise KeyError(key)

    def __iter__(self):
        return (path for path, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return NotImplemented


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class SourceChunk(_FrozenModel):
    """One ordered vulnerable-source excerpt selected by the patch policy."""

    path: StrictStr = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: StrictStr
    text_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: StrictStr = Field(min_length=1)
    truncated_before: bool
    truncated_after: bool

    @model_validator(mode="after")
    def _valid_chunk(self) -> "SourceChunk":
        validate_path(self.path)
        if self.end_line < self.start_line:
            raise ValueError("source chunk line range is reversed")
        if self.text_sha256 != _sha256(self.text.encode("utf-8")):
            raise ValueError("source chunk text hash does not match")
        return self

    @classmethod
    def create(
        cls,
        *,
        path: str,
        start_line: int,
        end_line: int,
        text: str,
        reason: str,
        truncated_before: bool,
        truncated_after: bool,
    ) -> "SourceChunk":
        return cls(
            path=path,
            start_line=start_line,
            end_line=end_line,
            text=text,
            text_sha256=_sha256(text.encode("utf-8")),
            reason=reason,
            truncated_before=truncated_before,
            truncated_after=truncated_after,
        )


class SourceBlobReceipt(_FrozenModel):
    path: StrictStr = Field(min_length=1)
    availability: Literal["available", "missing", "new_only"]
    selection_reason: Literal[
        "patch_hunk", "binary_patch", "metadata_only", "affected_location"
    ]
    blob_sha256: StrictStr | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    blob_byte_count: int | None = Field(
        default=None, ge=0, le=_SOURCE_BLOB_MAX_BYTES
    )
    patch_old_path: StrictStr | None = None
    patch_new_path: StrictStr | None = None
    hunk_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _valid_blob_receipt(self) -> "SourceBlobReceipt":
        validate_path(self.path)
        for candidate in (self.patch_old_path, self.patch_new_path):
            if candidate is not None:
                validate_path(candidate)
        has_commitment = self.blob_sha256 is not None and self.blob_byte_count is not None
        if (self.availability == "available") != has_commitment:
            raise ValueError("available source blobs require a full blob commitment")
        if self.availability != "available" and (
            self.blob_sha256 is not None or self.blob_byte_count is not None
        ):
            raise ValueError("unavailable source blobs cannot carry a blob commitment")
        if (self.selection_reason == "patch_hunk") != (self.hunk_count > 0):
            raise ValueError("source blob selection reason conflicts with hunk count")
        return self


class SelectedChunkReceipt(_FrozenModel):
    path: StrictStr = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: StrictStr = Field(min_length=1)
    truncated_before: bool
    truncated_after: bool

    @model_validator(mode="after")
    def _valid_range(self) -> "SelectedChunkReceipt":
        validate_path(self.path)
        if self.end_line < self.start_line:
            raise ValueError("selected chunk line range is reversed")
        return self


class SelectionReceipt(_FrozenModel):
    """Self-committing receipt for deterministic source selection."""

    schema_version: Literal["1.1"] = "1.1"
    algorithm_version: Literal["patch-hunk-v1"] = "patch-hunk-v1"
    raw_patch_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    raw_patch_byte_count: int = Field(ge=0, le=_RAW_PATCH_MAX_BYTES)
    effective_patch_source: Literal["raw", "canonical_git_diff"]
    effective_patch_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effective_patch_byte_count: int = Field(ge=0, le=_RAW_PATCH_MAX_BYTES)
    patch_evidence_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    patch_evidence_char_count: int = Field(ge=0, le=_PATCH_LIMIT)
    source_blobs: tuple[SourceBlobReceipt, ...]
    selected_chunks: tuple[SelectedChunkReceipt, ...]
    missing_paths: tuple[StrictStr, ...] = ()
    new_only_paths: tuple[StrictStr, ...] = ()
    omitted_file_count: int = Field(default=0, ge=0)
    omitted_hunk_count: int = Field(default=0, ge=0)
    receipt_commitment_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _verify_commitment(self) -> "SelectionReceipt":
        if self.effective_patch_source == "raw" and (
            self.effective_patch_sha256 != self.raw_patch_sha256
            or self.effective_patch_byte_count != self.raw_patch_byte_count
        ):
            raise ValueError("raw effective patch commitment does not match raw artifact")
        if len(self.source_blobs) > _MAX_SELECTED_FILES:
            raise ValueError("selection receipt exceeds file limit")
        for path in (*self.missing_paths, *self.new_only_paths):
            validate_path(path)
        if tuple(sorted(set(self.missing_paths))) != self.missing_paths:
            raise ValueError("missing paths must be sorted and unique")
        if tuple(sorted(set(self.new_only_paths))) != self.new_only_paths:
            raise ValueError("new-only paths must be sorted and unique")
        payload = self.model_dump(
            mode="json", exclude={"receipt_commitment_sha256"}
        )
        if self.receipt_commitment_sha256 != _sha256(
            _canonical_json(payload).encode("utf-8")
        ):
            raise ValueError("selection receipt commitment does not match")
        return self

    @classmethod
    def create(cls, **values: Any) -> "SelectionReceipt":
        payload = dict(values)
        payload.setdefault("schema_version", "1.1")
        payload.setdefault("algorithm_version", "patch-hunk-v1")
        payload["source_blobs"] = tuple(payload.get("source_blobs", ()))
        payload["selected_chunks"] = tuple(payload.get("selected_chunks", ()))
        payload["missing_paths"] = tuple(payload.get("missing_paths", ()))
        payload["new_only_paths"] = tuple(payload.get("new_only_paths", ()))
        normalized = {
            key: (
                [item.model_dump(mode="json") for item in value]
                if key in {"source_blobs", "selected_chunks"}
                else list(value)
                if key in {"missing_paths", "new_only_paths"}
                else value
            )
            for key, value in payload.items()
            if key != "receipt_commitment_sha256"
        }
        payload["receipt_commitment_sha256"] = _sha256(
            _canonical_json(normalized).encode("utf-8")
        )
        return cls.model_validate(payload)


def _source_files_from_chunks(chunks: tuple[SourceChunk, ...]) -> dict[str, str]:
    grouped: dict[str, list[str]] = {}
    for chunk in chunks:
        grouped.setdefault(chunk.path, []).append(chunk.text)
    separator = "\n...[omitted vulnerable source lines]...\n"
    return {path: separator.join(texts) for path, texts in grouped.items()}


def _selection_receipt(
    *,
    raw_patch: bytes,
    effective_patch: bytes,
    effective_patch_source: Literal["raw", "canonical_git_diff"],
    patch_evidence: str,
    source_blobs: tuple[SourceBlobReceipt, ...],
    chunks: tuple[SourceChunk, ...],
    omitted_file_count: int,
    omitted_hunk_count: int,
) -> SelectionReceipt:
    selected = tuple(
        SelectedChunkReceipt(
            path=chunk.path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            text_sha256=chunk.text_sha256,
            reason=chunk.reason,
            truncated_before=chunk.truncated_before,
            truncated_after=chunk.truncated_after,
        )
        for chunk in chunks
    )
    return SelectionReceipt.create(
        raw_patch_sha256=_sha256(raw_patch),
        raw_patch_byte_count=len(raw_patch),
        effective_patch_source=effective_patch_source,
        effective_patch_sha256=_sha256(effective_patch),
        effective_patch_byte_count=len(effective_patch),
        patch_evidence_sha256=_sha256(patch_evidence.encode("utf-8")),
        patch_evidence_char_count=len(patch_evidence),
        source_blobs=source_blobs,
        selected_chunks=selected,
        missing_paths=tuple(
            sorted(blob.path for blob in source_blobs if blob.availability == "missing")
        ),
        new_only_paths=tuple(
            sorted(blob.path for blob in source_blobs if blob.availability == "new_only")
        ),
        omitted_file_count=omitted_file_count,
        omitted_hunk_count=omitted_hunk_count,
    )


class OracleContext(BaseModel):
    """Immutable, hashable teacher-only context with a self-verifying digest."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, arbitrary_types_allowed=True)

    context_version: Literal["2.0"] = "2.0"
    selection_policy_id: Literal["patch-hunk-v1"] = "patch-hunk-v1"
    case_id: StrictStr = Field(min_length=1)
    repository: StrictStr = Field(min_length=1)
    vulnerable_commit: StrictStr = Field(pattern=r"^[0-9a-f]{40}$")
    family: Literal["source_to_sink", "authorization"]
    cwe: StrictStr = Field(pattern=r"^CWE-[0-9]+$")
    advisory: StrictStr = Field(max_length=_ADVISORY_LIMIT)
    patch: StrictStr = Field(max_length=_PATCH_LIMIT)
    source_chunks: tuple[SourceChunk, ...]
    source_files: _FrozenSourceFiles
    selection_receipt: SelectionReceipt
    sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("source_files", mode="before")
    @classmethod
    def _freeze_source_files(cls, value: object) -> _FrozenSourceFiles:
        if isinstance(value, _FrozenSourceFiles):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("source_files must be a mapping")
        return _FrozenSourceFiles(value)

    @field_serializer("source_files")
    def _serialize_source_files(self, value: _FrozenSourceFiles) -> dict[str, str]:
        return dict(value.items())

    @model_validator(mode="after")
    def _verify_digest(self) -> "OracleContext":
        expected_chunks = tuple(
            SelectedChunkReceipt(
                path=chunk.path,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                text_sha256=chunk.text_sha256,
                reason=chunk.reason,
                truncated_before=chunk.truncated_before,
                truncated_after=chunk.truncated_after,
            )
            for chunk in self.source_chunks
        )
        if expected_chunks != self.selection_receipt.selected_chunks:
            raise ValueError("source chunks do not match the selection receipt")
        expected_files = _source_files_from_chunks(self.source_chunks)
        if dict(self.source_files.items()) != expected_files:
            raise ValueError("source_files does not match the ordered source chunks")
        if self.selection_receipt.patch_evidence_sha256 != _sha256(
            self.patch.encode("utf-8")
        ):
            raise ValueError("patch evidence does not match the selection receipt")
        if self.selection_receipt.patch_evidence_char_count != len(self.patch):
            raise ValueError("patch evidence length does not match the selection receipt")
        if len(self.render()) > _CANONICAL_RENDER_MAX_CHARS:
            raise ValueError("canonical context render exceeds 64000 characters")
        expected = _sha256(self.render().encode("utf-8"))
        if self.sha256 != expected:
            raise ValueError("sha256 must match canonical render")
        return self

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        repository: str,
        vulnerable_commit: str,
        family: Literal["source_to_sink", "authorization"],
        cwe: str,
        advisory: str,
        patch: str,
        source_files: Mapping[str, str],
        source_chunks: tuple[SourceChunk, ...] | list[SourceChunk] | None = None,
        selection_receipt: SelectionReceipt | None = None,
    ) -> "OracleContext":
        frozen_source_files = _FrozenSourceFiles(source_files)
        if source_chunks is None:
            generated: list[SourceChunk] = []
            for path, text in frozen_source_files.items():
                line_count = max(1, len(text.splitlines()))
                generated.append(
                    SourceChunk.create(
                        path=path,
                        start_line=1,
                        end_line=line_count,
                        text=text,
                        reason="compatibility-source",
                        truncated_before=False,
                        truncated_after=False,
                    )
                )
            source_chunks = tuple(generated)
        else:
            source_chunks = tuple(source_chunks)
        if selection_receipt is None:
            blobs = tuple(
                SourceBlobReceipt(
                    path=path,
                    availability="available",
                    selection_reason="affected_location",
                    blob_sha256=_sha256(text.encode("utf-8")),
                    blob_byte_count=len(text.encode("utf-8")),
                    hunk_count=0,
                )
                for path, text in frozen_source_files.items()
            )
            selection_receipt = _selection_receipt(
                raw_patch=patch.encode("utf-8"),
                effective_patch=patch.encode("utf-8"),
                effective_patch_source="raw",
                patch_evidence=patch,
                source_blobs=blobs,
                chunks=source_chunks,
                omitted_file_count=0,
                omitted_hunk_count=0,
            )
        payload: dict[str, Any] = {
            "context_version": "2.0",
            "selection_policy_id": "patch-hunk-v1",
            "case_id": case_id,
            "repository": repository,
            "vulnerable_commit": vulnerable_commit,
            "family": family,
            "cwe": cwe,
            "advisory": advisory,
            "patch": patch,
            "source_chunks": source_chunks,
            "source_files": frozen_source_files,
            "selection_receipt": selection_receipt,
        }
        draft = cls.model_construct(**payload, sha256="")
        payload["sha256"] = _sha256(draft.render().encode("utf-8"))
        return cls.model_validate(payload)

    def render(self) -> str:
        """The sole canonical serialization used by context hashing."""

        return _canonical_json(self.model_dump(mode="json", exclude={"sha256"}))

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> "OracleContext":
        """Revalidate copies so updates cannot retain a stale digest or mutable map."""

        del deep  # Immutable fields need no special deep-copy semantics.
        payload = self.model_dump()
        if update:
            payload.update(update)
        return type(self).model_validate(payload)

    def copy(self, *, include: object = None, exclude: object = None, update: Mapping[str, Any] | None = None, deep: bool = False) -> "OracleContext":
        """Compatibility wrapper with the same invariant-preserving semantics."""

        del include, exclude
        return self.model_copy(update=update, deep=deep)

    def __copy__(self) -> "OracleContext":
        return self.model_copy()

    def __deepcopy__(self, memo: dict[int, object]) -> "OracleContext":
        del memo
        return self.model_copy(deep=True)

    def __hash__(self) -> int:
        return hash(self.sha256)


def _relative_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise ValueError("path must be a non-empty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or "\x00" in value:
        raise ValueError("path must remain inside the declared root")
    if path.as_posix() in {"", "."}:
        raise ValueError("path must name a file")
    return path.parts


def _safe_declared_path(root: Path, value: object, *, kind: str) -> tuple[Path, Path]:
    """Resolve a declared path and return it with its permitted realpath boundary."""

    parts = _relative_path(value)
    try:
        root = root.resolve(strict=True)
    except (OSError, FileNotFoundError) as exc:
        raise ValueError("root must exist") from exc

    data_mount = root / "data"
    if parts[0] == "data" and data_mount.is_symlink():
        try:
            boundary = data_mount.resolve(strict=True)
        except (OSError, FileNotFoundError) as exc:
            raise ValueError("declared data mount is unavailable") from exc
        candidate = boundary.joinpath(*parts[1:])
    else:
        boundary = root
        candidate = root.joinpath(*parts)

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, FileNotFoundError) as exc:
        raise ValueError("declared required file is unavailable") from exc
    try:
        resolved.relative_to(boundary)
    except ValueError as exc:
        raise ValueError("declared path escapes its allowed root") from exc
    if kind == "file" and not resolved.is_file():
        raise ValueError("declared path must name a regular file")
    if kind == "directory" and not resolved.is_dir():
        raise ValueError("declared path must name a directory")
    return resolved, boundary


def _safe_file(root: Path, value: object) -> Path:
    """Resolve a declared regular file without permitting symlink escapes."""

    return _safe_declared_path(root, value, kind="file")[0]


def _safe_directory(root: Path, value: object) -> tuple[Path, Path]:
    return _safe_declared_path(root, value, kind="directory")


def _read_utf8_file(root: Path, value: object, max_bytes: int) -> str:
    return _read_bytes_file(root, value, max_bytes).decode("utf-8", errors="replace")


def _read_bytes_file(root: Path, value: object, max_bytes: int) -> bytes:
    path = _safe_file(root, value)
    try:
        with path.open("rb") as handle:
            payload = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ValueError("unable to read required file") from exc
    if len(payload) > max_bytes:
        raise ValueError("required file exceeds bounded input limit")
    return payload


def _read_json(root: Path, value: object) -> dict[str, Any]:
    text = _read_utf8_file(root, value, max_bytes=1_000_000)
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("declared JSON file is malformed") from None
    if not isinstance(parsed, dict):
        raise ValueError("declared JSON document must be an object")
    return parsed


def _required_mapping(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"required object {key!r} is malformed")
    return value


def _required_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"required string {key!r} is malformed")
    return value


def _affected_paths(case: CaseManifest) -> list[str]:
    paths: set[str] = set()
    for location in case.affected_locations:
        if not isinstance(location, dict) or not isinstance(location.get("path"), str):
            raise ValueError("affected location path is malformed")
        paths.add(validate_path(location["path"]))
    if len(paths) > MAX_AFFECTED_LOCATIONS:
        raise ValueError(
            f"affected location cardinality exceeds {MAX_AFFECTED_LOCATIONS}"
        )
    return sorted(paths)


_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$"
)
_INDEX_RE = re.compile(
    r"^index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})(?: [0-7]{6})?$"
)
_SIMILARITY_RE = re.compile(r"(?:0|[1-9][0-9]?|100)%")
_GIT_EXTENDED_METADATA_RE = re.compile(
    r"^(?:similarity|dissimilarity|rename|copy|old mode|new mode|"
    r"new file mode|deleted file mode|index)\b"
)
_NO_NEWLINE_MARKER = "\\ No newline at end of file"
_GIT_BINARY_BLOCK_RE = re.compile(r"^(?:literal|delta) [0-9]+$")
_GIT_BASE85 = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+-;<=>?@^_`{|}~"
)


@dataclass(frozen=True, slots=True)
class _PatchHunk:
    order: int
    old_start: int
    old_count: int
    new_start: int
    new_count: int


@dataclass(frozen=True, slots=True)
class _PatchFile:
    order: int
    old_path: str | None
    new_path: str | None
    hunks: tuple[_PatchHunk, ...]
    binary_patch: bool


@dataclass(frozen=True, slots=True)
class _Candidate:
    path: str
    patch_old_path: str | None
    patch_new_path: str | None
    patch_order: int | None
    new_only: bool
    hunks: tuple[_PatchHunk, ...]
    selection_reason: Literal[
        "patch_hunk", "binary_patch", "metadata_only", "affected_location"
    ]


@dataclass(frozen=True, slots=True)
class _ChunkPlan:
    order: int
    chunk: SourceChunk
    represented_hunks: int


def _patch_path(value: str, prefix: str) -> str | None:
    """Decode one Git patch path and reject unsafe repository traversal."""

    token = value.strip()
    if token == "/dev/null":
        return None
    if token.startswith('"'):
        if len(token) < 2 or not token.endswith('"'):
            raise ValueError("patch path quoting is malformed")
        token = token[1:-1]
    else:
        token = token.split("\t", 1)[0]
    if "\\" in token:
        token = _decode_git_c_path(token)
    if token.startswith(prefix):
        token = token[len(prefix) :]
    return validate_path(token)


def _decode_git_c_path(value: str) -> str:
    """Decode the C escapes emitted by Git's default ``core.quotePath`` mode."""

    output = bytearray()
    simple = {
        "a": 7,
        "b": 8,
        "t": 9,
        "n": 10,
        "v": 11,
        "f": 12,
        "r": 13,
        '"': 34,
        "\\": 92,
    }
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            output.extend(character.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise ValueError("patch path quoting is malformed")
        escaped = value[index]
        if escaped in "01234567":
            end = index
            while end < len(value) and end < index + 3 and value[end] in "01234567":
                end += 1
            output.append(int(value[index:end], 8))
            index = end
            continue
        if escaped not in simple:
            raise ValueError("patch path quoting is malformed")
        output.append(simple[escaped])
        index += 1
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("patch path is not valid UTF-8") from None


def _git_diff_path_tokens(line: str) -> tuple[str, str]:
    """Split the two paths in ``diff --git`` using Git, not shell, quoting."""

    value = line[len("diff --git ") :]
    tokens: list[str] = []
    index = 0
    while len(tokens) < 2:
        while index < len(value) and value[index].isspace():
            index += 1
        if index >= len(value):
            raise ValueError("patch diff header is malformed")
        start = index
        if value[index] == '"':
            index += 1
            escaped = False
            while index < len(value):
                character = value[index]
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    index += 1
                    break
                index += 1
            else:
                raise ValueError("patch diff header is malformed")
            if index < len(value) and not value[index].isspace():
                raise ValueError("patch diff header is malformed")
        else:
            while index < len(value) and not value[index].isspace():
                index += 1
        tokens.append(value[start:index])
    if value[index:].strip():
        raise ValueError("patch diff header is malformed")
    return tokens[0], tokens[1]


def _git_binary_encoded_line(line: str) -> bool:
    """Validate one Git base85 line without materializing binary contents."""

    if not line:
        return False
    if "A" <= line[0] <= "Z":
        decoded_bytes = ord(line[0]) - ord("A") + 1
    elif "a" <= line[0] <= "z":
        decoded_bytes = ord(line[0]) - ord("a") + 27
    else:
        return False
    encoded = line[1:]
    return (
        len(encoded) == 5 * ((decoded_bytes + 3) // 4)
        and all(character in _GIT_BASE85 for character in encoded)
    )


def _consume_git_binary_patch(lines: list[str], index: int) -> int:
    """Consume the two bounded forward/reverse blocks in a Git binary patch."""

    for block_index in range(2):
        if index >= len(lines) or _GIT_BINARY_BLOCK_RE.fullmatch(lines[index]) is None:
            raise ValueError("Git binary patch block header is malformed")
        index += 1
        encoded_lines = 0
        separator_seen = False
        while index < len(lines):
            line = lines[index]
            if not line:
                separator_seen = True
                index += 1
                break
            if line.startswith("diff --git "):
                break
            if not _git_binary_encoded_line(line):
                raise ValueError("Git binary patch payload is malformed")
            encoded_lines += 1
            index += 1
        if encoded_lines == 0:
            raise ValueError("Git binary patch payload is empty")
        if block_index == 0 and not separator_seen:
            raise ValueError("Git binary patch blocks are not separated")
    if index < len(lines) and _GIT_BINARY_BLOCK_RE.fullmatch(lines[index]):
        raise ValueError("Git binary patch has extra blocks")
    return index


def _binary_summary_path_tokens(value: str) -> tuple[str, str]:
    """Split one binary summary at its sole unquoted, unescaped delimiter."""

    delimiter = " and "
    split_at: int | None = None
    in_quotes = False
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            in_quotes = not in_quotes
        elif not in_quotes and value.startswith(delimiter, index):
            if split_at is not None:
                raise ValueError("binary patch summary delimiter is ambiguous")
            split_at = index
            index += len(delimiter)
            continue
        index += 1
    if escaped or in_quotes or split_at is None:
        raise ValueError("binary patch summary quoting is malformed")
    old_token = value[:split_at]
    new_token = value[split_at + len(delimiter) :]
    if not old_token or not new_token:
        raise ValueError("binary patch summary paths are missing")
    return old_token, new_token


def _parse_patch(raw_patch: bytes) -> tuple[_PatchFile, ...]:
    """Parse bounded unified diff metadata without trusting paths or hunk counts."""

    if len(raw_patch) > _RAW_PATCH_MAX_BYTES:
        raise ValueError("patch exceeds bounded input limit")
    if any(
        len(line) > _PATCH_LINE_MAX_BYTES for line in raw_patch.splitlines()
    ):
        raise ValueError("patch line exceeds bounded line limit")
    if b"\x00" in raw_patch:
        raise ValueError("binary patch is not valid source context")
    text = raw_patch.decode("utf-8", errors="replace")
    lines = text.splitlines()
    files: list[_PatchFile] = []
    current: dict[str, Any] | None = None
    hunk_order = 0

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        if current["binary"] and (
            not current["has_diff"]
            or not current["index_seen"]
            or current["headers_complete"]
            or current["hunks"]
        ):
            raise ValueError("binary patch metadata conflicts")
        if current["header_old_seen"] != current["header_new_seen"]:
            raise ValueError("patch file header pair is incomplete")
        if (current["rename_from"] is None) != (current["rename_to"] is None):
            raise ValueError("patch rename metadata is incomplete")
        if (current["copy_from"] is None) != (current["copy_to"] is None):
            raise ValueError("patch copy metadata is incomplete")
        if current["rename_from"] is not None and current["copy_from"] is not None:
            raise ValueError("patch rename and copy metadata conflict")
        if current["old_mode"] != current["new_mode"]:
            raise ValueError("patch mode metadata is incomplete")
        if current["new_file_mode"] and current["deleted_file_mode"]:
            raise ValueError("patch file mode metadata conflicts")
        if (current["new_file_mode"] or current["deleted_file_mode"]) and any(
            (
                current["old_mode"],
                current["new_mode"],
                current["rename_from"] is not None,
                current["copy_from"] is not None,
            )
        ):
            raise ValueError("patch file mode metadata conflicts")
        if current["new_file_mode"]:
            if current["index_seen"] and not set(current["index_old_oid"]) == {"0"}:
                raise ValueError("patch new-file metadata conflicts with index")
            if current["header_old_seen"] and current["header_old"] is not None:
                raise ValueError("patch new-file metadata conflicts with file headers")
            if any(hunk.old_start != 0 or hunk.old_count != 0 for hunk in current["hunks"]):
                raise ValueError("patch new-file metadata conflicts with hunks")
        if current["deleted_file_mode"]:
            if current["index_seen"] and not set(current["index_new_oid"]) == {"0"}:
                raise ValueError("patch delete-file metadata conflicts with index")
            if current["header_new_seen"] and current["header_new"] is not None:
                raise ValueError("patch delete-file metadata conflicts with file headers")
            if any(hunk.new_start != 0 or hunk.new_count != 0 for hunk in current["hunks"]):
                raise ValueError("patch delete-file metadata conflicts with hunks")
        rename_complete = current["rename_from"] is not None
        copy_complete = current["copy_from"] is not None
        empty_new_complete = current["new_file_mode"] and current["index_seen"]
        empty_delete_complete = current["deleted_file_mode"] and current["index_seen"]
        mode_complete = current["old_mode"] and current["new_mode"]
        extended_complete = any(
            (
                rename_complete,
                copy_complete,
                empty_new_complete,
                empty_delete_complete,
                mode_complete,
            )
        )
        if not current["hunks"] and not extended_complete and not current["binary"]:
            raise ValueError("patch file section is not a complete unified diff")
        if extended_complete and not current["has_diff"]:
            raise ValueError("extended patch metadata requires a diff header")
        old_path = current["header_old"]
        new_path = current["header_new"]
        if current["header_old_seen"]:
            if old_path is None and new_path is None:
                raise ValueError("patch file headers cannot both name /dev/null")
            if current["has_diff"]:
                diff_old = current["diff_old"]
                diff_new = current["diff_new"]
                if old_path is None:
                    if diff_old != new_path or diff_new != new_path:
                        raise ValueError("patch new-file headers conflict")
                elif new_path is None:
                    if diff_old != old_path or diff_new != old_path:
                        raise ValueError("patch delete-file headers conflict")
                elif diff_old != old_path or diff_new != new_path:
                    raise ValueError("patch file headers conflict")
        else:
            old_path = current["diff_old"]
            new_path = current["diff_new"]
        if rename_complete and (
            current["rename_from"] != current["diff_old"]
            or current["rename_to"] != current["diff_new"]
        ):
            raise ValueError("patch rename metadata conflicts with diff paths")
        if copy_complete and (
            current["copy_from"] != current["diff_old"]
            or current["copy_to"] != current["diff_new"]
        ):
            raise ValueError("patch copy metadata conflicts with diff paths")
        if empty_new_complete:
            if current["diff_old"] != current["diff_new"]:
                raise ValueError("patch new-file metadata conflicts with diff paths")
            old_path = None
            new_path = current["diff_new"]
        elif empty_delete_complete:
            if current["diff_old"] != current["diff_new"]:
                raise ValueError("patch delete-file metadata conflicts with diff paths")
            old_path = current["diff_old"]
            new_path = None
        if current["hunks"] and not current["headers_complete"]:
            raise ValueError("patch hunk is missing file headers")
        if old_path is not None or new_path is not None:
            files.append(
                _PatchFile(
                    order=current["order"],
                    old_path=old_path,
                    new_path=new_path,
                    hunks=tuple(current["hunks"]),
                    binary_patch=current["binary"],
                )
            )
        current = None

    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("diff --git "):
            finish()
            old_token, new_token = _git_diff_path_tokens(line)
            current = {
                "order": len(files),
                "diff_old": _patch_path(old_token, "a/"),
                "diff_new": _patch_path(new_token, "b/"),
                "has_diff": True,
                "header_old": None,
                "header_new": None,
                "header_old_seen": False,
                "header_new_seen": False,
                "headers_complete": False,
                "binary": False,
                "rename_from": None,
                "rename_to": None,
                "copy_from": None,
                "copy_to": None,
                "similarity_seen": False,
                "dissimilarity_seen": False,
                "old_mode": False,
                "new_mode": False,
                "new_file_mode": False,
                "deleted_file_mode": False,
                "index_seen": False,
                "index_old_oid": None,
                "index_new_oid": None,
                "hunks": [],
            }
            index += 1
            continue
        if current is None and line.startswith("--- "):
            current = {
                "order": len(files),
                "diff_old": None,
                "diff_new": None,
                "has_diff": False,
                "header_old": _patch_path(line[4:], "a/"),
                "header_new": None,
                "header_old_seen": True,
                "header_new_seen": False,
                "headers_complete": False,
                "binary": False,
                "rename_from": None,
                "rename_to": None,
                "copy_from": None,
                "copy_to": None,
                "similarity_seen": False,
                "dissimilarity_seen": False,
                "old_mode": False,
                "new_mode": False,
                "new_file_mode": False,
                "deleted_file_mode": False,
                "index_seen": False,
                "index_old_oid": None,
                "index_new_oid": None,
                "hunks": [],
            }
            index += 1
            continue
        if current is None and line.startswith("+++ "):
            raise ValueError("patch new-file header is out of order")
        if current is None and line == _NO_NEWLINE_MARKER:
            raise ValueError("patch newline marker requires a unified diff hunk")
        if current is None and (
            line == "GIT binary patch"
            or (line.startswith("Binary files ") and line.endswith(" differ"))
            or line.startswith("@@")
        ):
            raise ValueError("patch structural marker is out of order")
        if current is None and line and line[0] in {"+", "-"}:
            raise ValueError("patch body appears outside a declared hunk")
        if current is None:
            index += 1
            continue
        if current["binary"]:
            if line:
                raise ValueError("binary patch has trailing content")
            index += 1
            continue
        if line == _NO_NEWLINE_MARKER:
            raise ValueError("patch newline marker appears outside a hunk body")
        if (
            line.startswith("--- ")
            and current["headers_complete"]
            and current["hunks"]
            and not current["has_diff"]
        ):
            finish()
            current = {
                "order": len(files),
                "diff_old": None,
                "diff_new": None,
                "has_diff": False,
                "header_old": _patch_path(line[4:], "a/"),
                "header_new": None,
                "header_old_seen": True,
                "header_new_seen": False,
                "headers_complete": False,
                "binary": False,
                "rename_from": None,
                "rename_to": None,
                "copy_from": None,
                "copy_to": None,
                "similarity_seen": False,
                "dissimilarity_seen": False,
                "old_mode": False,
                "new_mode": False,
                "new_file_mode": False,
                "deleted_file_mode": False,
                "index_seen": False,
                "index_old_oid": None,
                "index_new_oid": None,
                "hunks": [],
            }
            index += 1
            continue
        if line.startswith("--- "):
            if current["header_old_seen"]:
                raise ValueError("patch old-file header is duplicated")
            current["header_old"] = _patch_path(line[4:], "a/")
            current["header_old_seen"] = True
            index += 1
            continue
        if line.startswith("+++ "):
            if not current["header_old_seen"] or current["header_new_seen"]:
                raise ValueError("patch new-file header is out of order")
            current["header_new"] = _patch_path(line[4:], "b/")
            current["header_new_seen"] = True
            current["headers_complete"] = True
            index += 1
            continue
        similarity_markers = {
            "similarity index ": "similarity_seen",
            "dissimilarity index ": "dissimilarity_seen",
        }
        matched_similarity = False
        for marker, key in similarity_markers.items():
            if line.startswith(marker):
                if (
                    current["header_old_seen"]
                    or current["index_seen"]
                    or current["similarity_seen"]
                    or current["dissimilarity_seen"]
                    or current["rename_from"] is not None
                    or current["copy_from"] is not None
                    or _SIMILARITY_RE.fullmatch(line[len(marker) :]) is None
                ):
                    raise ValueError(
                        "patch similarity index metadata is malformed, duplicated, or out of order"
                    )
                current[key] = True
                matched_similarity = True
                break
        if matched_similarity:
            index += 1
            continue
        metadata_paths = {
            "rename from ": "rename_from",
            "rename to ": "rename_to",
            "copy from ": "copy_from",
            "copy to ": "copy_to",
        }
        matched_metadata = False
        for marker, key in metadata_paths.items():
            if line.startswith(marker):
                family = "rename" if key.startswith("rename_") else "copy"
                other = "copy" if family == "rename" else "rename"
                from_key = f"{family}_from"
                if (
                    current["header_old_seen"]
                    or current["index_seen"]
                    or current[key] is not None
                    or current[f"{other}_from"] is not None
                    or current[f"{other}_to"] is not None
                    or (key.endswith("_to") and current[from_key] is None)
                ):
                    raise ValueError(
                        "patch rename/copy path metadata is conflicting, duplicated, or out of order"
                    )
                current[key] = _patch_path(line[len(marker) :], "")
                matched_metadata = True
                break
        if matched_metadata:
            index += 1
            continue
        if line.startswith("old mode "):
            if (
                current["header_old_seen"]
                or current["index_seen"]
                or current["old_mode"]
                or current["new_mode"]
                or current["similarity_seen"]
                or current["dissimilarity_seen"]
                or current["rename_from"] is not None
                or current["copy_from"] is not None
                or not re.fullmatch(r"[0-7]{6}", line[9:])
            ):
                raise ValueError("patch old-mode metadata is malformed")
            current["old_mode"] = True
            index += 1
            continue
        if line.startswith("new mode "):
            if (
                current["header_old_seen"]
                or current["index_seen"]
                or not current["old_mode"]
                or current["new_mode"]
                or current["similarity_seen"]
                or current["dissimilarity_seen"]
                or current["rename_from"] is not None
                or current["copy_from"] is not None
                or not re.fullmatch(r"[0-7]{6}", line[9:])
            ):
                raise ValueError("patch new-mode metadata is malformed")
            current["new_mode"] = True
            index += 1
            continue
        if line.startswith("new file mode "):
            if (
                current["header_old_seen"]
                or current["index_seen"]
                or current["new_file_mode"]
                or current["deleted_file_mode"]
                or current["old_mode"]
                or current["new_mode"]
                or current["similarity_seen"]
                or current["dissimilarity_seen"]
                or current["rename_from"] is not None
                or current["copy_from"] is not None
                or not re.fullmatch(r"[0-7]{6}", line[14:])
            ):
                raise ValueError("patch new-file mode metadata is malformed")
            current["new_file_mode"] = True
            index += 1
            continue
        if line.startswith("deleted file mode "):
            if (
                current["header_old_seen"]
                or current["index_seen"]
                or current["deleted_file_mode"]
                or current["new_file_mode"]
                or current["old_mode"]
                or current["new_mode"]
                or current["similarity_seen"]
                or current["dissimilarity_seen"]
                or current["rename_from"] is not None
                or current["copy_from"] is not None
                or not re.fullmatch(r"[0-7]{6}", line[18:])
            ):
                raise ValueError("patch deleted-file mode metadata is malformed")
            current["deleted_file_mode"] = True
            index += 1
            continue
        if line.startswith("index "):
            match = _INDEX_RE.fullmatch(line)
            if current["header_old_seen"] or current["index_seen"] or match is None:
                raise ValueError("patch index metadata is malformed or duplicated")
            current["index_seen"] = True
            current["index_old_oid"] = match.group(1)
            current["index_new_oid"] = match.group(2)
            index += 1
            continue
        if line == "GIT binary patch":
            current["binary"] = True
            index = _consume_git_binary_patch(lines, index + 1)
            continue
        if line.startswith("Binary files ") and line.endswith(" differ"):
            expected_old = None if current["new_file_mode"] else current["diff_old"]
            expected_new = None if current["deleted_file_mode"] else current["diff_new"]
            value = line[len("Binary files ") : -len(" differ")]
            old_token, new_token = _binary_summary_path_tokens(value)
            old_path = _patch_path(old_token, "a/")
            new_path = _patch_path(new_token, "b/")
            if old_path != expected_old or new_path != expected_new:
                raise ValueError("binary patch summary conflicts with diff paths")
            current["binary"] = True
            index += 1
            continue
        if _GIT_EXTENDED_METADATA_RE.match(line):
            raise ValueError("patch extended metadata is malformed or unknown")
        if line.startswith("@@"):
            match = _HUNK_RE.fullmatch(line)
            if match is None:
                raise ValueError("patch hunk header is malformed")
            if not current["headers_complete"]:
                raise ValueError("patch hunk is missing file headers")
            old_count = int(match.group(2) or "1")
            new_count = int(match.group(4) or "1")
            old_seen = 0
            new_seen = 0
            marker_allowed = False
            index += 1
            while index < len(lines):
                body = lines[index]
                if body == _NO_NEWLINE_MARKER:
                    if not marker_allowed:
                        raise ValueError(
                            "patch newline marker must immediately follow a hunk body line"
                        )
                    marker_allowed = False
                    index += 1
                    continue
                if old_seen == old_count and new_seen == new_count:
                    trailing = body
                    if (
                        trailing.startswith("diff --git ")
                        or trailing.startswith("@@")
                        or (not current["has_diff"] and trailing.startswith("--- "))
                    ):
                        break
                    if trailing and trailing[0] in {" ", "+", "-"}:
                        raise ValueError("patch hunk body exceeds declared line counts")
                    break
                if body.startswith("diff --git ") or body.startswith("@@"):
                    break
                if not body or body[0] not in {" ", "+", "-"}:
                    raise ValueError("patch hunk body is malformed")
                if body[0] in {" ", "-"}:
                    old_seen += 1
                if body[0] in {" ", "+"}:
                    new_seen += 1
                if old_seen > old_count or new_seen > new_count:
                    raise ValueError("patch hunk body exceeds declared line counts")
                marker_allowed = True
                index += 1
            if old_seen != old_count or new_seen != new_count:
                raise ValueError("patch hunk line counts do not match its header")
            current["hunks"].append(
                _PatchHunk(
                    order=hunk_order,
                    old_start=int(match.group(1)),
                    old_count=old_count,
                    new_start=int(match.group(3)),
                    new_count=new_count,
                )
            )
            hunk_order += 1
            continue
        if line and line[0] in {"+", "-"}:
            raise ValueError("patch body appears outside a declared hunk")
        index += 1
    finish()
    if not files:
        raise ValueError("patch must contain a complete unified diff file section")
    return tuple(files)


def _is_low_priority_path(path: str) -> bool:
    parts = {part.casefold() for part in PurePosixPath(path).parts}
    return bool(parts & {"test", "tests", "example", "examples", "doc", "docs"})


def _candidate_files(
    patch_files: tuple[_PatchFile, ...], affected_paths: list[str]
) -> tuple[_Candidate, ...]:
    candidates: dict[str, _Candidate] = {}
    for patched in patch_files:
        path = patched.old_path if patched.old_path is not None else patched.new_path
        if path is None:
            continue
        previous = candidates.get(path)
        hunks = patched.hunks if previous is None else previous.hunks + patched.hunks
        binary_patch = patched.binary_patch or (
            previous is not None and previous.selection_reason == "binary_patch"
        )
        selection_reason: Literal[
            "patch_hunk", "binary_patch", "metadata_only", "affected_location"
        ] = (
            "patch_hunk"
            if hunks
            else "binary_patch"
            if binary_patch
            else "metadata_only"
        )
        candidates[path] = _Candidate(
            path=path,
            patch_old_path=patched.old_path,
            patch_new_path=patched.new_path,
            patch_order=patched.order if previous is None else previous.patch_order,
            new_only=patched.old_path is None,
            hunks=hunks,
            selection_reason=selection_reason,
        )
    for path in affected_paths:
        if path not in candidates:
            candidates[path] = _Candidate(
                path=path,
                patch_old_path=None,
                patch_new_path=None,
                patch_order=None,
                new_only=False,
                hunks=(),
                selection_reason="affected_location",
            )
    return tuple(
        sorted(
            candidates.values(),
            key=lambda item: (
                item.patch_order is None,
                _is_low_priority_path(item.path),
                item.patch_order if item.patch_order is not None else 0,
                item.path,
            ),
        )
    )


def _round_robin_hunks(
    candidates: tuple[_Candidate, ...], limit: int
) -> tuple[tuple[int, _PatchHunk], ...]:
    selected: list[tuple[int, _PatchHunk]] = []
    offsets = [0] * len(candidates)
    while len(selected) < limit:
        advanced = False
        for candidate_index, candidate in enumerate(candidates):
            offset = offsets[candidate_index]
            if offset < len(candidate.hunks):
                selected.append((candidate_index, candidate.hunks[offset]))
                offsets[candidate_index] += 1
                advanced = True
                if len(selected) == limit:
                    break
        if not advanced:
            break
    return tuple(selected)


def _chunk_plans(
    candidates: tuple[_Candidate, ...],
    sources: dict[int, str],
    selected_hunks: tuple[tuple[int, _PatchHunk], ...],
) -> tuple[_ChunkPlan, ...]:
    scheduled: dict[int, list[tuple[int, _PatchHunk]]] = {}
    for schedule_order, (candidate_index, hunk) in enumerate(selected_hunks):
        scheduled.setdefault(candidate_index, []).append((schedule_order, hunk))
    plans: list[_ChunkPlan] = []
    fallback_order = len(selected_hunks)
    for candidate_index, candidate in enumerate(candidates):
        if candidate_index not in sources:
            continue
        text = sources[candidate_index]
        lines = text.splitlines(keepends=True)
        if not lines:
            continue
        windows: list[tuple[int, int, int, list[int]]] = []
        entries = scheduled.get(candidate_index, [])
        if entries:
            for schedule_order, hunk in sorted(entries, key=lambda item: item[1].old_start):
                focus_start = max(1, hunk.old_start)
                focus_end = max(focus_start, hunk.old_start + max(1, hunk.old_count) - 1)
                if hunk.old_count > 0 and (
                    hunk.old_start < 1 or focus_end > len(lines)
                ):
                    raise ValueError("patch hunk falls outside the vulnerable blob")
                start = max(1, focus_start - _HUNK_CONTEXT_LINES)
                end = min(len(lines), focus_end + _HUNK_CONTEXT_LINES)
                windows.append((start, end, schedule_order, [hunk.order]))
        elif candidate.selection_reason == "affected_location":
            windows.append((1, min(len(lines), 2 * _HUNK_CONTEXT_LINES + 1), fallback_order + candidate_index, []))
        merged: list[tuple[int, int, int, list[int]]] = []
        for start, end, order, hunk_ids in sorted(windows):
            if merged and start <= merged[-1][1] + 1:
                old_start, old_end, old_order, old_ids = merged[-1]
                merged[-1] = (
                    old_start,
                    max(old_end, end),
                    min(old_order, order),
                    old_ids + hunk_ids,
                )
            else:
                merged.append((start, end, order, list(hunk_ids)))
        for start, end, order, hunk_ids in merged:
            reason = (
                "patch-old-hunks:" + ",".join(str(value) for value in sorted(hunk_ids))
                if hunk_ids
                else "affected-location-fallback"
            )
            plans.append(
                _ChunkPlan(
                    order=order,
                    chunk=SourceChunk.create(
                        path=candidate.path,
                        start_line=start,
                        end_line=end,
                        text="".join(lines[start - 1 : end]),
                        reason=reason,
                        truncated_before=start > 1,
                        truncated_after=end < len(lines),
                    ),
                    represented_hunks=len(hunk_ids),
                )
            )
    return tuple(sorted(plans, key=lambda item: (item.order, item.chunk.path, item.chunk.start_line)))


def build_oracle_context(
    root: Path, case: CaseManifest, total_chars: int = 64_000
) -> OracleContext:
    """Build a bounded teacher-only context from a pinned case and bare Git cache."""

    if not isinstance(total_chars, int) or isinstance(total_chars, bool) or total_chars <= 0:
        raise ValueError("total_chars must be a positive integer")
    root = Path(root)

    oracle = _read_json(root, case.views.oracle_view_path)
    manifest = _read_json(root, case.artifacts.manifest_path)
    repository = _required_mapping(oracle, "repository")
    resolution = _required_mapping(manifest, "resolution")
    case_id = _required_string(oracle, "case_id")
    oracle_repository = _required_string(repository, "upstream_id")
    commit = _required_string(repository, "vulnerable_commit")
    fixed_commit = _required_string(repository, "fixed_commit")
    resolution_vulnerable_commit = _required_string(
        resolution, "vulnerable_commit"
    )
    resolution_fixed_commit = _required_string(resolution, "fixed_commit")
    cwe = _required_string(oracle, "cwe")
    advisory_path = _required_string(oracle, "advisory_path")
    patch_path = _required_string(oracle, "patch_path")
    cache_path = _required_string(resolution, "cache_path")

    if (
        case_id != case.case_id
        or oracle_repository != case.repository.upstream_id
        or commit != case.repository.vulnerable_commit
        or fixed_commit != case.repository.fixed_commit
        or cwe != case.cwe_normalized_primary
        or not _CWE_RE.fullmatch(cwe)
    ):
        raise ValueError("oracle metadata does not match the case manifest")
    if (
        resolution_vulnerable_commit != case.repository.vulnerable_commit
        or resolution_fixed_commit != case.repository.fixed_commit
    ):
        raise ValueError("manifest resolution commits do not match the case manifest")
    if _safe_file(root, patch_path) != _safe_file(root, case.artifacts.patch_path):
        raise ValueError("oracle patch path does not match the case manifest")
    paths = _affected_paths(case)
    raw_patch = _read_bytes_file(root, patch_path, _RAW_PATCH_MAX_BYTES)
    # Bind the complete cache identity closure to every real Git query.
    cache_guard = GitCacheGuard(root, cache_path)
    try:
        try:
            store = cache_guard.open_store()
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            raise ValueError("declared Git cache is unavailable") from exc

        effective_patch = raw_patch
        effective_patch_source: Literal["raw", "canonical_git_diff"] = "raw"
        try:
            patch_files = _parse_patch(raw_patch)
        except ValueError as raw_parse_error:
            try:
                effective_patch = store.canonical_diff(commit, fixed_commit)
                patch_files = _parse_patch(effective_patch)
            except (FileNotFoundError, RuntimeError, ValueError):
                # Parser diagnostics are fixed built-in strings and preserve the
                # original strict-parser failure when recovery is unavailable.
                raise ValueError(str(raw_parse_error)) from None
            effective_patch_source = "canonical_git_diff"

        candidates = _candidate_files(patch_files, paths)
        selected_candidates = candidates[:_MAX_SELECTED_FILES]
        omitted_file_count = len(candidates) - len(selected_candidates)

        blob_receipts: list[SourceBlobReceipt] = []
        source_texts: dict[int, str] = {}
        for candidate_index, candidate in enumerate(selected_candidates):
            if candidate.new_only:
                blob_receipts.append(
                    SourceBlobReceipt(
                        path=candidate.path,
                        availability="new_only",
                        selection_reason=candidate.selection_reason,
                        patch_old_path=candidate.patch_old_path,
                        patch_new_path=candidate.patch_new_path,
                        hunk_count=len(candidate.hunks),
                    )
                )
                continue
            try:
                source_bytes = store.read_bytes(
                    commit, candidate.path, max_bytes=_SOURCE_BLOB_MAX_BYTES
                )
            except FileNotFoundError:
                blob_receipts.append(
                    SourceBlobReceipt(
                        path=candidate.path,
                        availability="missing",
                        selection_reason=candidate.selection_reason,
                        patch_old_path=candidate.patch_old_path,
                        patch_new_path=candidate.patch_new_path,
                        hunk_count=len(candidate.hunks),
                    )
                )
                continue
            except (RuntimeError, ValueError) as exc:
                raise ValueError(
                    f"unable to read bounded source file: {candidate.path}"
                ) from exc
            blob_receipts.append(
                SourceBlobReceipt(
                    path=candidate.path,
                    availability="available",
                    selection_reason=candidate.selection_reason,
                    blob_sha256=_sha256(source_bytes),
                    blob_byte_count=len(source_bytes),
                    patch_old_path=candidate.patch_old_path,
                    patch_new_path=candidate.patch_new_path,
                    hunk_count=len(candidate.hunks),
                )
            )
            if candidate.selection_reason in {"patch_hunk", "affected_location"}:
                source_texts[candidate_index] = source_bytes.decode(
                    "utf-8", errors="replace"
                )

        selected_hunks = _round_robin_hunks(
            selected_candidates, _MAX_SELECTED_HUNKS
        )
        total_hunks = sum(len(item.hunks) for item in candidates)
        omitted_hunks = total_hunks - len(selected_hunks)
        plans = _chunk_plans(selected_candidates, source_texts, selected_hunks)
        advisory_source = _read_utf8_file(
            root, advisory_path, _ADVISORY_LIMIT * 4
        )
        patch_source = effective_patch.decode("utf-8", errors="replace")
        render_limit = min(total_chars, _CANONICAL_RENDER_MAX_CHARS)

        def assemble(
            advisory: str,
            patch: str,
            chunks: tuple[SourceChunk, ...],
            omitted_hunk_count: int,
        ) -> OracleContext:
            source_files = _source_files_from_chunks(chunks)
            receipt = _selection_receipt(
                raw_patch=raw_patch,
                effective_patch=effective_patch,
                effective_patch_source=effective_patch_source,
                patch_evidence=patch,
                source_blobs=tuple(blob_receipts),
                chunks=chunks,
                omitted_file_count=omitted_file_count,
                omitted_hunk_count=omitted_hunk_count,
            )
            return OracleContext.create(
                case_id=case_id,
                repository=oracle_repository,
                vulnerable_commit=commit,
                family=case.family,
                cwe=cwe,
                advisory=advisory,
                patch=patch,
                source_files=source_files,
                source_chunks=chunks,
                selection_receipt=receipt,
            )

        def within_limit(
            advisory: str,
            patch: str,
            chunks: tuple[SourceChunk, ...],
            omitted_hunk_count: int,
        ) -> OracleContext | None:
            try:
                candidate = assemble(advisory, patch, chunks, omitted_hunk_count)
            except ValueError:
                return None
            return candidate if len(candidate.render()) <= render_limit else None

        if within_limit("", "", (), omitted_hunks) is None:
            raise ValueError("context metadata exceeds total_chars")

        advisory = ""
        patch = ""

        def fit_scalar(text: str, maximum: int, *, field: str) -> str:
            low, high, best = 0, min(maximum, len(text)), 0
            while low <= high:
                middle = (low + high) // 2
                candidate = bounded(text, middle)
                candidate_context = within_limit(
                    candidate if field == "advisory" else advisory,
                    candidate if field == "patch" else patch,
                    (),
                    omitted_hunks,
                )
                if candidate_context is not None:
                    best = middle
                    low = middle + 1
                else:
                    high = middle - 1
            return bounded(text, best)

        # Patch evidence drives source selection, so it gets the bounded budget first.
        patch = fit_scalar(patch_source, _PATCH_LIMIT, field="patch")
        advisory = fit_scalar(advisory_source, _ADVISORY_LIMIT, field="advisory")

        chosen: list[SourceChunk] = []
        chosen_plans: list[_ChunkPlan] = []
        effective_omitted_hunks = omitted_hunks
        for plan in plans:
            candidate_chunks = tuple([*chosen, plan.chunk])
            candidate_context = within_limit(
                advisory, patch, candidate_chunks, effective_omitted_hunks
            )
            if candidate_context is not None:
                chosen.append(plan.chunk)
                chosen_plans.append(plan)
            else:
                effective_omitted_hunks += plan.represented_hunks

        context = within_limit(
            advisory, patch, tuple(chosen), effective_omitted_hunks
        )
        while context is None and chosen:
            removed = chosen_plans.pop()
            chosen.pop()
            effective_omitted_hunks += removed.represented_hunks
            context = within_limit(
                advisory, patch, tuple(chosen), effective_omitted_hunks
            )
        if context is None:
            raise ValueError("context exceeds total_chars")
        return context
    finally:
        cache_guard.close()
