"""Isolated, fail-closed ``codex exec`` teacher adapter."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import threading
import time
import tomllib
from typing import Any
from urllib.parse import urlsplit

from egsi.config import CodexExecProviderConfig
from egsi.generation.safeio import AnchoredDirectory, open_directory_fd

from .base import (
    TeacherRequest,
    TeacherResponse,
    canonical_teacher_request_bytes,
    committed_teacher_response,
    teacher_request_hash,
    teacher_request_value,
)
from .output_schema import StrictOutputSchemaError, normalize_strict_output_schema


_MAX_CONFIG_BYTES = 1_048_576
_MAX_PROMPT_BYTES = 2_097_152
_MAX_SYSTEM_BYTES = 1_048_576
_MAX_SCHEMA_BYTES = 1_048_576
_MAX_STDOUT_BYTES = 2_097_152
_MAX_STDERR_BYTES = 8_388_608
_MAX_STDERR_CAPTURE_BYTES = 65_536
_MAX_JSONL_LINE_BYTES = 262_144
_MAX_JSON_EVENTS = 256
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 4096
_MAX_FINAL_BYTES = 1_048_576
_MAX_AUDIT_BYTES = 2_097_152
_MAX_SCHEMA_FINGERPRINT_BYTES = 1_048_576
_MAX_SCHEMA_FINGERPRINT_CHARS = _MAX_SCHEMA_FINGERPRINT_BYTES // 4
_MAX_SCHEMA_CONTAINER_ITEMS = 2048
_MAX_CANONICAL_REQUEST_BYTES = (
    _MAX_PROMPT_BYTES + _MAX_SYSTEM_BYTES + _MAX_SCHEMA_BYTES
)
_MAX_CANONICAL_STRING_CHARS = _MAX_PROMPT_BYTES
_MAX_TYPE_TAG_BYTES = 1024
_MAX_NONCANONICAL_FULL_TEXT_CHARS = 262_144
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_NONCANONICAL_TEXT_WINDOW_CHARS = 4096
_PROVIDER_OUTPUT_SCHEMA_TRANSFORM = "codex-strict-required-v1"
_INT64_MAX = (1 << 63) - 1
_USAGE_FIELDS = {
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
}
_PROVIDER_FIELDS = (
    "name",
    "base_url",
    "wire_api",
    "requires_openai_auth",
    "supports_websockets",
)
_WIRE_APIS = {"responses", "chat"}
_KNOWN_EVENT_TYPES = {
    "thread.started", "turn.started", "item.completed", "turn.completed",
    "item.started", "item.updated", "error", "turn.failed",
}
_KNOWN_ITEM_TYPES = {
    "agent_message", "reasoning", "command_execution", "file_change",
    "mcp_tool_call", "collab_tool_call", "web_search", "todo_list", "error",
}
_SAFE_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_PROXY_ENV = {
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
}


class _InvocationFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


_ExecutableToken = tuple[int, int, int, int, int, int, int]


def _executable_token(info: os.stat_result) -> _ExecutableToken:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _executable_stat_value(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "nlink": info.st_nlink,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _validate_executable_info(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > _MAX_EXECUTABLE_BYTES
        or info.st_mode & 0o111 == 0
    ):
        raise OSError("executable metadata invalid")


def _read_executable_digest(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(descriptor, min(1_048_576, expected_size - offset), offset)
        if not chunk:
            raise OSError("executable truncated")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, expected_size):
        raise OSError("executable grew during read")
    return "sha256:" + digest.hexdigest()


def _open_verified_executable(
    config: CodexExecProviderConfig,
) -> tuple[int, _ExecutableToken, dict[str, int], str]:
    path = Path(config.executable)
    if path.resolve(strict=True) != path:
        raise OSError("executable path is not canonical")
    before = path.lstat()
    _validate_executable_info(before)
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        observed = os.fstat(descriptor)
        _validate_executable_info(observed)
        if _executable_token(before) != _executable_token(observed):
            raise OSError("executable identity changed before verification")
        digest = _read_executable_digest(descriptor, observed.st_size)
        after = os.fstat(descriptor)
        if _executable_token(observed) != _executable_token(after):
            raise OSError("executable identity changed during verification")
        if digest != config.executable_sha256:
            raise OSError("executable digest mismatch")
        return descriptor, _executable_token(after), _executable_stat_value(after), digest
    except Exception:
        os.close(descriptor)
        raise


def _require_executable_unchanged(
    path: Path, descriptor: int, expected: _ExecutableToken
) -> None:
    path_info = path.lstat()
    descriptor_info = os.fstat(descriptor)
    _validate_executable_info(path_info)
    _validate_executable_info(descriptor_info)
    if (
        stat.S_ISLNK(path_info.st_mode)
        or _executable_token(path_info) != expected
        or _executable_token(descriptor_info) != expected
    ):
        raise _InvocationFailure("executable_identity_changed")


def _executable_identity_commitment(
    *, executable_sha256: str, executable_stat: dict[str, int], cli_version: str
) -> str:
    return _sha256(
        _canonical_json(
            {
                "executable_id": "codex-cli",
                "executable_sha256": executable_sha256,
                "executable_stat": executable_stat,
                "cli_version": cli_version,
            }
        )
    )


class _SchemaProjectionLimit(Exception):
    pass


class _SchemaNoncanonical(Exception):
    pass


def _check_container_budget(
    *, size: int, visited_nodes: int, child_nodes_per_item: int, depth: int
) -> None:
    remaining_nodes = _MAX_JSON_NODES - visited_nodes
    if (
        size > _MAX_SCHEMA_CONTAINER_ITEMS
        or size * child_nodes_per_item > remaining_nodes
        or (size > 0 and depth >= _MAX_JSON_DEPTH)
    ):
        raise _SchemaProjectionLimit


@dataclass
class _SchemaProjectionState:
    digest: Any = field(default_factory=hashlib.sha256)
    nodes: int = 0
    emitted_bytes: int = 0

    def enter(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise _SchemaProjectionLimit

    def emit(self, raw: bytes) -> None:
        if len(raw) > _MAX_SCHEMA_FINGERPRINT_BYTES - self.emitted_bytes:
            raise _SchemaProjectionLimit
        self.emitted_bytes += len(raw)
        self.digest.update(len(raw).to_bytes(8, "big"))
        self.digest.update(raw)


def _safe_type_component(value_type: type, attribute: str) -> bytes:
    try:
        value = type.__getattribute__(value_type, attribute)
    except BaseException:
        return b"unavailable"
    if type(value) is not str:
        return b"invalid"
    try:
        raw = str.encode(value, "utf-8", errors="surrogatepass")
    except BaseException:
        return b"unavailable"
    if len(raw) > _MAX_TYPE_TAG_BYTES:
        return b"oversized"
    return raw


def _project_schema_value(
    value: object, state: _SchemaProjectionState, *, depth: int
) -> None:
    state.enter(depth)
    value_type = type(value)
    if value_type is dict:
        size = dict.__len__(value)
        _check_container_budget(
            size=size,
            visited_nodes=state.nodes,
            child_nodes_per_item=2,
            depth=depth,
        )
        state.emit(b"dict")
        all_keys_are_strings = True
        cumulative_key_chars = 0
        estimated_key_bytes = 0
        remaining_fingerprint_bytes = (
            _MAX_SCHEMA_FINGERPRINT_BYTES - state.emitted_bytes
        )
        for key in value:
            if type(key) is not str:
                all_keys_are_strings = False
                continue
            key_chars = str.__len__(key)
            if key_chars > _MAX_SCHEMA_FINGERPRINT_CHARS:
                raise _SchemaProjectionLimit
            cumulative_key_chars += key_chars
            estimated_key_bytes += key_chars * 4 + len(b"str")
            if (
                cumulative_key_chars > _MAX_SCHEMA_FINGERPRINT_CHARS
                or estimated_key_bytes > remaining_fingerprint_bytes
            ):
                raise _SchemaProjectionLimit
        if not all_keys_are_strings:
            state.emit(b"unsupported-dict-key")
            return
        keys = sorted(value)
        state.emit(size.to_bytes(8, "big"))
        for key in keys:
            _project_schema_value(key, state, depth=depth + 1)
            _project_schema_value(value[key], state, depth=depth + 1)
    elif value_type is list or value_type is tuple:
        size = (
            list.__len__(value) if value_type is list else tuple.__len__(value)
        )
        _check_container_budget(
            size=size,
            visited_nodes=state.nodes,
            child_nodes_per_item=1,
            depth=depth,
        )
        state.emit(b"list" if value_type is list else b"tuple")
        state.emit(size.to_bytes(8, "big"))
        for item in value:
            _project_schema_value(item, state, depth=depth + 1)
    elif value_type is str:
        if str.__len__(value) > _MAX_SCHEMA_FINGERPRINT_CHARS:
            raise _SchemaProjectionLimit
        raw = str.encode(value, "utf-8", errors="surrogatepass")
        state.emit(b"str")
        state.emit(raw)
    elif value_type is bool:
        state.emit(b"bool-true" if value else b"bool-false")
    elif value is None:
        state.emit(b"none")
    elif value_type is int:
        state.emit(b"int-negative" if value < 0 else b"int-nonnegative")
        magnitude = -value if value < 0 else value
        width = max(1, (int.bit_length(magnitude) + 7) // 8)
        if width > _MAX_SCHEMA_FINGERPRINT_BYTES:
            raise _SchemaProjectionLimit
        state.emit(int.to_bytes(magnitude, width, "big"))
    elif value_type is float:
        if math.isnan(value):
            state.emit(b"float-nan")
        elif value == math.inf:
            state.emit(b"float-positive-infinity")
        elif value == -math.inf:
            state.emit(b"float-negative-infinity")
        else:
            state.emit(b"float-finite")
            state.emit(struct.pack(">d", value))
    else:
        state.emit(b"unsupported")
        state.emit(_safe_type_component(value_type, "__module__"))
        state.emit(_safe_type_component(value_type, "__qualname__"))


def _safe_schema_projection_fingerprint(value: object) -> bytes:
    state = _SchemaProjectionState()
    try:
        _project_schema_value(value, state, depth=1)
    except _SchemaProjectionLimit:
        return b"projection-limit-v1"
    except BaseException:
        return b"projection-error-v1"
    return b"projection-sha256-v1:" + state.digest.digest()


@dataclass
class _CanonicalPreflightState:
    nodes: int = 0
    estimated_bytes: int = 0

    def enter(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise _SchemaProjectionLimit

    def add_bytes(self, count: int) -> None:
        if count > _MAX_CANONICAL_REQUEST_BYTES - self.estimated_bytes:
            raise _SchemaProjectionLimit
        self.estimated_bytes += count


def _preflight_canonical_value(
    value: object, state: _CanonicalPreflightState, *, depth: int
) -> None:
    state.enter(depth)
    value_type = type(value)
    if value_type is dict:
        size = dict.__len__(value)
        _check_container_budget(
            size=size,
            visited_nodes=state.nodes,
            child_nodes_per_item=2,
            depth=depth,
        )
        state.add_bytes(2 + size * 2)
        if any(type(key) is not str for key in value):
            raise _SchemaNoncanonical
        for key, item in value.items():
            _preflight_canonical_value(key, state, depth=depth + 1)
            _preflight_canonical_value(item, state, depth=depth + 1)
    elif value_type is list:
        size = list.__len__(value)
        _check_container_budget(
            size=size,
            visited_nodes=state.nodes,
            child_nodes_per_item=1,
            depth=depth,
        )
        state.add_bytes(2 + size)
        for item in value:
            _preflight_canonical_value(item, state, depth=depth + 1)
    elif value_type is str:
        size = str.__len__(value)
        if size > _MAX_CANONICAL_STRING_CHARS:
            raise _SchemaProjectionLimit
        state.add_bytes(2 + size * 6)
    elif value_type is bool:
        state.add_bytes(4 if value else 5)
    elif value is None:
        state.add_bytes(4)
    elif value_type is int:
        magnitude = -value if value < 0 else value
        bits = int.bit_length(magnitude)
        decimal_digits_upper_bound = 1 if bits == 0 else (bits * 30103) // 100000 + 1
        state.add_bytes(decimal_digits_upper_bound + (1 if value < 0 else 0))
    elif value_type is float:
        if not math.isfinite(value):
            raise _SchemaNoncanonical
        state.add_bytes(32)
    else:
        raise _SchemaNoncanonical


def _bounded_canonical_preflight(value: object) -> bool:
    state = _CanonicalPreflightState()
    try:
        _preflight_canonical_value(value, state, depth=1)
    except BaseException:
        return False
    return True


def _normalize_provider_output_schema(value: object) -> dict[str, Any]:
    if not _bounded_canonical_preflight(value):
        raise _InvocationFailure("provider_schema_limit")
    try:
        normalized = normalize_strict_output_schema(value)
    except StrictOutputSchemaError:
        raise _InvocationFailure("provider_schema_unsupported") from None
    except BaseException:
        raise _InvocationFailure("provider_schema_unsupported") from None
    if not _bounded_canonical_preflight(normalized):
        raise _InvocationFailure("provider_schema_limit")
    return normalized


def _digest_length_prefixed(digest: Any, raw: bytes) -> None:
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)


def _update_bounded_text_fingerprint(
    digest: Any, *, field_tag: bytes, value: object
) -> None:
    _digest_length_prefixed(digest, field_tag)
    if type(value) is not str:
        _digest_length_prefixed(digest, b"unsupported-text-type")
        return
    char_length = str.__len__(value)
    digest.update(char_length.to_bytes(8, "big"))
    if char_length <= _MAX_NONCANONICAL_FULL_TEXT_CHARS:
        _digest_length_prefixed(digest, b"str-full")
        _digest_length_prefixed(
            digest, str.encode(value, "utf-8", errors="surrogatepass")
        )
        return
    _digest_length_prefixed(digest, b"str-windowed")
    prefix = str.__getitem__(
        value, slice(0, _NONCANONICAL_TEXT_WINDOW_CHARS)
    )
    suffix = str.__getitem__(
        value, slice(-_NONCANONICAL_TEXT_WINDOW_CHARS, None)
    )
    if (
        str.__len__(prefix) > _NONCANONICAL_TEXT_WINDOW_CHARS
        or str.__len__(suffix) > _NONCANONICAL_TEXT_WINDOW_CHARS
    ):
        _digest_length_prefixed(digest, b"window-limit")
        return
    _digest_length_prefixed(
        digest, str.encode(prefix, "utf-8", errors="surrogatepass")
    )
    _digest_length_prefixed(
        digest, str.encode(suffix, "utf-8", errors="surrogatepass")
    )


def _noncanonical_request_hash(request: TeacherRequest, model: str) -> str:
    """Hash an invalid request without serializing any raw field into audit."""

    digest = hashlib.sha256(b"egsi-codex-exec-noncanonical-schema-v1\0")
    for field_tag, value in (
        (b"model", model),
        (b"system", request.system),
        (b"user", request.user),
    ):
        _update_bounded_text_fingerprint(
            digest, field_tag=field_tag, value=value
        )
    schema_fingerprint = _safe_schema_projection_fingerprint(request.schema)
    digest.update(len(schema_fingerprint).to_bytes(8, "big"))
    digest.update(schema_fingerprint)
    return "sha256:" + digest.hexdigest()


def _validate_private_regular(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise OSError("private file metadata invalid")


def _secure_open_at(directory: Path, name: str, *, limit: int, read: bool) -> bytearray | None:
    """Open one current-owner 0600 regular file through an anchored parent."""

    directory_fd = open_directory_fd(directory, create=False)
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _validate_private_regular(before)
        if before.st_size > limit:
            raise OSError("private file too large")
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        observed = os.fstat(descriptor)
        _validate_private_regular(observed)
        if (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
            raise OSError("private file identity changed")
        if not read:
            return None
        raw = bytearray()
        remaining = observed.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise OSError("private file truncated")
            raw.extend(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns)
        ):
            raise OSError("private file changed during read")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _clear_bytes(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _validated_provider_table(
    document: object, config: CodexExecProviderConfig
) -> dict[str, str | bool]:
    if not isinstance(document, dict):
        raise OSError("provider config root invalid")
    providers = document.get("model_providers")
    if not isinstance(providers, dict):
        raise OSError("missing model providers")
    selected = providers.get(config.model_provider)
    if not isinstance(selected, dict):
        raise OSError("missing selected model provider")
    allowed: dict[str, str | bool] = {}
    for key in selected:
        lowered = str(key).lower()
        if key not in _PROVIDER_FIELDS and any(
            marker in lowered
            for marker in ("secret", "token", "credential", "password", "api_key", "header", "authorization")
        ):
            raise OSError("secret provider field is forbidden")
    for key in _PROVIDER_FIELDS:
        value = selected.get(key)
        if key in {"requires_openai_auth", "supports_websockets"}:
            if type(value) is not bool:
                raise OSError("provider boolean field invalid")
        else:
            if type(value) is not str or not value.strip():
                raise OSError("provider string field invalid")
            value = value.strip()
        allowed[key] = value
    if allowed["wire_api"] not in _WIRE_APIS:
        raise OSError("unknown provider wire API")
    parsed = urlsplit(str(allowed["base_url"]))
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise OSError("provider base URL invalid")
    return allowed


def _provider_table_and_auth(
    config: CodexExecProviderConfig,
) -> tuple[dict[str, str | bool], bytearray]:
    if not _SAFE_PROVIDER_ID.fullmatch(config.model_provider):
        raise OSError("invalid model provider id")
    raw = _secure_open_at(config.codex_home, "config.toml", limit=_MAX_CONFIG_BYTES, read=True)
    if raw is None:
        raise OSError("missing private input")
    try:
        auth = _secure_open_at(config.codex_home, "auth.json", limit=_MAX_CONFIG_BYTES, read=True)
    except Exception:
        _clear_bytes(raw)
        raise
    if auth is None:
        _clear_bytes(raw)
        raise OSError("missing private input")
    try:
        try:
            document = tomllib.loads(raw.decode("utf-8"))
        finally:
            _clear_bytes(raw)
        return _validated_provider_table(document, config), auth
    except Exception:
        _clear_bytes(auth)
        raise


@dataclass(frozen=True)
class _PrivateLayout:
    root: Path
    home: Path
    codex_home: Path
    workspace: Path
    tmp: Path
    xdg_config: Path
    xdg_cache: Path
    xdg_data: Path
    xdg_state: Path
    xdg_runtime: Path


def _private_layout(
    *, working_root: Path | None, auth: bytearray, include_workspace: bool
) -> _PrivateLayout:
    root = Path(tempfile.mkdtemp(prefix=".egsi-codex-", dir=working_root))
    try:
        os.chmod(root, 0o700)
        names = {
            "home": "home",
            "codex_home": "codex-home",
            "workspace": "workspace",
            "tmp": "tmp",
            "xdg_config": "xdg-config",
            "xdg_cache": "xdg-cache",
            "xdg_data": "xdg-data",
            "xdg_state": "xdg-state",
            "xdg_runtime": "xdg-runtime",
        }
        paths = {key: root / name for key, name in names.items()}
        for key, path in paths.items():
            if key == "workspace" and not include_workspace:
                path.mkdir(mode=0o700)
            else:
                path.mkdir(mode=0o700)
        _write_private(paths["codex_home"] / "auth.json", auth)
        return _PrivateLayout(root=root, **paths)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def _remove_private_root(root: Path) -> None:
    shutil.rmtree(root)
    if os.path.lexists(root):
        raise OSError("private root cleanup incomplete")


def _subprocess_environment(
    config: CodexExecProviderConfig, *, private: _PrivateLayout
) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in ("PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        value = os.environ.get(key)
        if value is not None:
            result[key] = value
    if config.inherit_proxy_env:
        for key in _PROXY_ENV:
            value = os.environ.get(key)
            if value is not None:
                result[key] = value
    result.update(
        {
            "HOME": str(private.home),
            "CODEX_HOME": str(private.codex_home),
            "TMPDIR": str(private.tmp),
            "XDG_CONFIG_HOME": str(private.xdg_config),
            "XDG_CACHE_HOME": str(private.xdg_cache),
            "XDG_DATA_HOME": str(private.xdg_data),
            "XDG_STATE_HOME": str(private.xdg_state),
            "XDG_RUNTIME_DIR": str(private.xdg_runtime),
        }
    )
    return result


def _toml_value(value: str | bool | int) -> str:
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    return json.dumps(value, ensure_ascii=False)


def _write_private(path: Path, raw: bytes | bytearray) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _json_shape(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise _InvocationFailure("json_shape_limit")
        if isinstance(current, dict):
            for key, item in current.items():
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


@dataclass
class _JsonlState:
    output_limit: int
    phase: str = "initial"
    thread_id: str | None = None
    final_text: str | None = None
    usage: dict[str, int] | None = None
    agent_messages: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    counts: Counter[str] = field(default_factory=Counter)

    def consume(self, raw: bytes) -> None:
        if len(self.events) >= _MAX_JSON_EVENTS:
            raise _InvocationFailure("event_count_limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _InvocationFailure("stdout_non_utf8") from None
        try:
            value = json.loads(
                text,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_json_constant,
                parse_float=_finite_json_float,
            )
        except (json.JSONDecodeError, RecursionError, ValueError):
            raise _InvocationFailure("malformed_jsonl") from None
        _json_shape(value)
        if not isinstance(value, dict) or type(value.get("type")) is not str:
            raise _InvocationFailure("malformed_event")
        event_type = value["type"]
        metadata: dict[str, Any] = {
            "index": len(self.events),
            "type": event_type if event_type in _KNOWN_EVENT_TYPES else "unknown",
        }
        if event_type == "item.completed":
            item = value.get("item")
            item_type = item.get("type") if isinstance(item, dict) else None
            metadata["item_type"] = (
                item_type if item_type in _KNOWN_ITEM_TYPES else "unknown"
            )
        self.events.append(metadata)
        self.counts[metadata["type"]] += 1
        if self.phase == "answered" and event_type != "turn.completed":
            item = value.get("item")
            if (
                event_type == "item.completed"
                and isinstance(item, dict)
                and item.get("type") == "agent_message"
            ):
                raise _InvocationFailure("ambiguous_agent_message")
            raise _InvocationFailure("invalid_event_order")
        if event_type == "thread.started":
            if self.phase != "initial" or type(value.get("thread_id")) is not str or not value["thread_id"]:
                raise _InvocationFailure("invalid_event_order")
            if len(value["thread_id"].encode("utf-8")) > 1024:
                raise _InvocationFailure("thread_id_limit")
            self.thread_id = value["thread_id"]
            self.phase = "thread"
        elif event_type == "turn.started":
            if self.phase != "thread":
                raise _InvocationFailure("invalid_event_order")
            self.phase = "turn"
        elif event_type == "item.completed":
            if self.phase != "turn" or not isinstance(value.get("item"), dict):
                raise _InvocationFailure("invalid_event_order")
            item = value["item"]
            item_type = item.get("type")
            if item_type == "agent_message":
                if self.agent_messages != 0:
                    raise _InvocationFailure("ambiguous_agent_message")
                message = item.get("text")
                if type(message) is not str:
                    raise _InvocationFailure("invalid_agent_message")
                if len(message.encode("utf-8")) > self.output_limit:
                    raise _InvocationFailure("output_limit")
                self.final_text = message
                self.agent_messages += 1
                self.phase = "answered"
            elif item_type != "reasoning":
                raise _InvocationFailure("forbidden_item_event")
        elif event_type == "turn.completed":
            if self.phase != "answered" or self.agent_messages != 1:
                raise _InvocationFailure("invalid_event_order")
            usage = value.get("usage")
            if not isinstance(usage, dict) or set(usage) != _USAGE_FIELDS:
                raise _InvocationFailure("invalid_usage")
            if any(type(count) is not int or count < 0 or count > _INT64_MAX for count in usage.values()):
                raise _InvocationFailure("invalid_usage")
            self.usage = dict(usage)
            self.phase = "completed"
        elif event_type in {"error", "turn.failed"}:
            raise _InvocationFailure("provider_failure_event")
        else:
            raise _InvocationFailure("unknown_event")

    def finish(self) -> None:
        if self.phase != "completed" or self.thread_id is None or self.final_text is None or self.usage is None:
            raise _InvocationFailure("incomplete_event_stream")


@dataclass
class _StreamResult:
    length: int = 0
    digest: Any = field(default_factory=hashlib.sha256)
    prefix: bytearray = field(default_factory=bytearray)
    done: threading.Event = field(default_factory=threading.Event)
    failure: _InvocationFailure | None = None


def _stdout_reader(stream: Any, result: _StreamResult, state: _JsonlState) -> None:
    pending = bytearray()
    try:
        while True:
            chunk = os.read(stream.fileno(), 65_536)
            if not chunk:
                break
            result.length += len(chunk)
            result.digest.update(chunk)
            if result.length > _MAX_STDOUT_BYTES:
                raise _InvocationFailure("stdout_total_limit")
            pending.extend(chunk)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    break
                line = bytes(pending[:newline])
                del pending[: newline + 1]
                if not line or len(line) > _MAX_JSONL_LINE_BYTES:
                    raise _InvocationFailure("stdout_line_limit")
                state.consume(line)
            if len(pending) > _MAX_JSONL_LINE_BYTES:
                raise _InvocationFailure("stdout_line_limit")
        if pending:
            state.consume(bytes(pending))
    except _InvocationFailure as error:
        result.failure = error
    except Exception:
        result.failure = _InvocationFailure("stdout_reader_failure")
    finally:
        result.done.set()


def _stderr_reader(stream: Any, result: _StreamResult) -> None:
    try:
        while True:
            chunk = os.read(stream.fileno(), 65_536)
            if not chunk:
                break
            result.length += len(chunk)
            result.digest.update(chunk)
            remaining = _MAX_STDERR_CAPTURE_BYTES - len(result.prefix)
            if remaining > 0:
                result.prefix.extend(chunk[:remaining])
            if result.length > _MAX_STDERR_BYTES:
                raise _InvocationFailure("stderr_total_limit")
    except _InvocationFailure as error:
        result.failure = error
    except Exception:
        result.failure = _InvocationFailure("stderr_reader_failure")
    finally:
        result.done.set()


def _stdin_writer(stream: Any, raw: bytes, result: _StreamResult) -> None:
    try:
        stream.write(raw)
        stream.flush()
    except Exception:
        result.failure = _InvocationFailure("stdin_writer_failure")
    finally:
        try:
            stream.close()
        except Exception:
            pass
        result.done.set()


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(
    process: subprocess.Popen[bytes], *, grace: float = 0.2, reap_timeout: float = 0.8
) -> bool:
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    term_deadline = time.monotonic() + grace
    while _process_group_exists(pgid) and time.monotonic() < term_deadline:
        time.sleep(0.01)
    if _process_group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    reap_deadline = time.monotonic() + reap_timeout
    while _process_group_exists(pgid) and time.monotonic() < reap_deadline:
        time.sleep(0.01)
    return not _process_group_exists(pgid)


def _close_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass


def _sanitize_stream_result(result: _StreamResult) -> None:
    _clear_bytes(result.prefix)
    result.failure = None


def _small_stream_reader(stream: Any, result: _StreamResult, limit: int) -> None:
    try:
        while True:
            chunk = os.read(stream.fileno(), 4096)
            if not chunk:
                break
            result.length += len(chunk)
            result.digest.update(chunk)
            if result.length > limit:
                raise _InvocationFailure("version_output_limit")
            result.prefix.extend(chunk)
    except _InvocationFailure as error:
        result.failure = error
    except Exception:
        result.failure = _InvocationFailure("version_reader_failure")
    finally:
        result.done.set()


def _probe_cli_version(
    config: CodexExecProviderConfig,
    *,
    private: _PrivateLayout,
    executable_fd: int,
    executable_token: _ExecutableToken,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    stdout = _StreamResult()
    stderr = _StreamResult()
    threads: list[threading.Thread] = []
    deadline = time.monotonic() + min(10.0, config.timeout_seconds)
    try:
        _require_executable_unchanged(
            Path(config.executable), executable_fd, executable_token
        )
        process = subprocess.Popen(
            [os.fspath(config.executable), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_subprocess_environment(config, private=private),
            shell=False,
            start_new_session=True,
            executable=f"/proc/self/fd/{executable_fd}",
            pass_fds=(executable_fd,),
        )
        if process.stdout is None or process.stderr is None:
            raise _InvocationFailure("version_pipe_failure")
        threads = [
            threading.Thread(target=_small_stream_reader, args=(process.stdout, stdout, 4096), daemon=True),
            threading.Thread(target=_small_stream_reader, args=(process.stderr, stderr, 4096), daemon=True),
        ]
        for thread in threads:
            thread.start()
        while True:
            failure = stdout.failure or stderr.failure
            if failure is not None:
                raise failure
            returncode = process.poll()
            if returncode is not None and stdout.done.is_set() and stderr.done.is_set():
                if returncode != 0:
                    raise _InvocationFailure("version_nonzero_exit")
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _InvocationFailure("version_timeout")
            stdout.done.wait(min(0.01, remaining))
        for thread in threads:
            thread.join(timeout=max(0.0, min(0.5, deadline - time.monotonic())))
        if any(thread.is_alive() for thread in threads):
            raise _InvocationFailure("version_reader_reap_failure")
        failure = stdout.failure or stderr.failure
        if failure is not None:
            raise failure
        if not _terminate_process_group(process):
            raise _InvocationFailure("version_process_group_reap_failure")
        _require_executable_unchanged(
            Path(config.executable), executable_fd, executable_token
        )
        return bytes(stdout.prefix)
    except _InvocationFailure:
        if process is not None:
            if not _terminate_process_group(process):
                raise _InvocationFailure("version_process_group_reap_failure") from None
        raise
    except Exception:
        if process is not None:
            if not _terminate_process_group(process):
                raise _InvocationFailure("version_process_group_reap_failure") from None
        raise _InvocationFailure("version_lifecycle_failure") from None
    finally:
        if process is not None:
            _close_pipes(process)
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        _require_executable_unchanged(
            Path(config.executable), executable_fd, executable_token
        )


def _bounded_output_limit(max_tokens: int) -> int:
    return min(_MAX_FINAL_BYTES, max(64, max_tokens * 16))


def _safe_last_message(path: Path, *, limit: int) -> bytes:
    raw = _secure_open_at(path.parent, path.name, limit=limit, read=True)
    if raw is None:
        raise _InvocationFailure("last_message_missing")
    return raw


def _redacted_argv(argv: list[str]) -> list[str]:
    result: list[str] = ["<executable>"]
    redact_next = {"--output-schema", "--output-last-message", "--cd", "-c"}
    hidden = False
    for item in argv[1:]:
        if hidden:
            result.append("<redacted>")
            hidden = False
        else:
            result.append(item)
            hidden = item in redact_next
    return result


def _audit_commitment(value: dict[str, Any]) -> str:
    copy = dict(value)
    copy.pop("audit_commitment_sha256", None)
    return _sha256(_canonical_json(copy))


def _verify_json(raw: bytes) -> None:
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("audit object invalid")


class CodexExecTeacher:
    """Execute a pinned Codex CLI in a private, tool-denied workspace."""

    provider = "codex_exec"

    def __init__(
        self,
        config: CodexExecProviderConfig,
        *,
        audit_root: Path | str,
        working_root: Path | str | None = None,
    ) -> None:
        self.config = config
        self.model = config.model
        self.audit_root = Path(audit_root).absolute()
        self.working_root = None if working_root is None else Path(working_root).absolute()
        self._closed = False
        self._lock = threading.Lock()
        self._auth = bytearray()
        self._executable_fd = -1
        try:
            if self.working_root is not None:
                working_fd = open_directory_fd(self.working_root, create=True)
                os.close(working_fd)
            self._provider, self._auth = _provider_table_and_auth(config)
            (
                self._executable_fd,
                self._executable_token,
                self.executable_stat,
                self.executable_sha256,
            ) = _open_verified_executable(config)
            private = _private_layout(
                working_root=self.working_root,
                auth=self._auth,
                include_workspace=False,
            )
            try:
                expected = f"codex-cli {config.expected_cli_version}".encode("ascii")
                if _probe_cli_version(
                    config,
                    private=private,
                    executable_fd=self._executable_fd,
                    executable_token=self._executable_token,
                ).strip() != expected:
                    raise OSError("CLI version mismatch")
            finally:
                _remove_private_root(private.root)
        except Exception:
            _clear_bytes(self._auth)
            if self._executable_fd >= 0:
                os.close(self._executable_fd)
                self._executable_fd = -1
            raise RuntimeError("codex exec teacher initialization failed") from None
        self.cli_version = config.expected_cli_version
        self.executable_id = "codex-cli"
        self.executable_identity_commitment_sha256 = (
            _executable_identity_commitment(
                executable_sha256=self.executable_sha256,
                executable_stat=self.executable_stat,
                cli_version=self.cli_version,
            )
        )
        self.cache_identity = self.executable_identity_commitment_sha256

    def _command(self, system: Path, schema: Path, last: Path, workspace: Path) -> list[str]:
        provider_prefix = f"model_providers.{self.config.model_provider}"
        overrides: list[str] = [
            f"model_instructions_file={_toml_value(str(system))}",
            "web_search=disabled",
            f"model_provider={_toml_value(self.config.model_provider)}",
        ]
        overrides.extend(
            f"{provider_prefix}.{key}={_toml_value(value)}"
            for key, value in self._provider.items()
        )
        overrides.extend(
            [
                f"{provider_prefix}.request_max_retries={self.config.max_retries}",
                f"{provider_prefix}.stream_max_retries={self.config.max_retries}",
                "features.shell_tool=false",
                "features.unified_exec=false",
                "features.view_image=false",
                "features.multi_agent=false",
                "features.apps=false",
                "features.plugins=false",
                "features.default_mode_request_user_input=false",
                "features.goals=false",
            ]
        )
        argv = [
            os.fspath(self.config.executable),
            "exec",
            "--strict-config",
            "--json",
            "--color",
            "never",
            "--output-schema",
            str(schema),
            "--output-last-message",
            str(last),
            "--model",
            self.model,
            "--sandbox",
            "read-only",
            "--ephemeral",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "--cd",
            str(workspace),
        ]
        for override in overrides:
            argv.extend(("-c", override))
        argv.append("-")
        return argv

    def _run(
        self,
        argv: list[str],
        prompt: bytes,
        state: _JsonlState,
        private: _PrivateLayout,
        stdout: _StreamResult,
        stderr: _StreamResult,
    ) -> int:
        writer = _StreamResult()
        process: subprocess.Popen[bytes] | None = None
        threads: list[threading.Thread] = []
        deadline = time.monotonic() + self.config.timeout_seconds
        try:
            _require_executable_unchanged(
                Path(self.config.executable),
                self._executable_fd,
                self._executable_token,
            )
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_subprocess_environment(self.config, private=private),
                shell=False,
                start_new_session=True,
                executable=f"/proc/self/fd/{self._executable_fd}",
                pass_fds=(self._executable_fd,),
            )
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise _InvocationFailure("pipe_construction_failure")
            threads = [
                threading.Thread(target=_stdout_reader, args=(process.stdout, stdout, state), daemon=True),
                threading.Thread(target=_stderr_reader, args=(process.stderr, stderr), daemon=True),
                threading.Thread(target=_stdin_writer, args=(process.stdin, prompt, writer), daemon=True),
            ]
            for thread in threads:
                thread.start()
            while True:
                failure = stdout.failure or stderr.failure or writer.failure
                if failure is not None:
                    raise failure
                returncode = process.poll()
                if returncode is not None and stdout.done.is_set() and stderr.done.is_set() and writer.done.is_set():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _InvocationFailure("timeout")
                stdout.done.wait(min(0.01, remaining))
            for thread in threads:
                thread.join(timeout=max(0.0, min(0.5, deadline - time.monotonic())))
            if any(thread.is_alive() for thread in threads):
                raise _InvocationFailure("reader_reap_failure")
            failure = stdout.failure or stderr.failure or writer.failure
            if failure is not None:
                raise failure
            if not _terminate_process_group(process):
                raise _InvocationFailure("process_group_reap_failure")
            _require_executable_unchanged(
                Path(self.config.executable),
                self._executable_fd,
                self._executable_token,
            )
            return process.returncode
        except _InvocationFailure:
            if process is not None:
                if not _terminate_process_group(process):
                    raise _InvocationFailure("process_group_reap_failure") from None
            raise
        except Exception:
            if process is not None:
                if not _terminate_process_group(process):
                    raise _InvocationFailure("process_group_reap_failure") from None
            raise _InvocationFailure("process_lifecycle_failure") from None
        finally:
            if process is not None:
                _close_pipes(process)
            for thread in threads:
                if thread.is_alive():
                    thread.join(timeout=0.5)
            _require_executable_unchanged(
                Path(self.config.executable),
                self._executable_fd,
                self._executable_token,
            )

    def _attempt_directory(self, request_hash: str) -> tuple[Path, AnchoredDirectory]:
        request_root = self.audit_root / request_hash
        descriptor = open_directory_fd(request_root, create=True)
        try:
            for counter in range(256):
                invocation_id = f"{secrets.token_hex(16)}-{counter:02x}"
                try:
                    os.mkdir(invocation_id, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    continue
                invocation_fd = os.open(
                    invocation_id,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                try:
                    os.mkdir("attempt-00", 0o700, dir_fd=invocation_fd)
                    attempt_fd = os.open(
                        "attempt-00",
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=invocation_fd,
                    )
                    try:
                        attempt_path = request_root / invocation_id / "attempt-00"
                        anchor = AnchoredDirectory.from_fd(attempt_path, attempt_fd)
                    finally:
                        os.close(attempt_fd)
                finally:
                    os.close(invocation_fd)
                return attempt_path, anchor
        finally:
            os.close(descriptor)
        raise RuntimeError("audit invocation allocation failed")

    def _write_audit(
        self,
        directory: AnchoredDirectory,
        *,
        manifest: dict[str, Any],
        events: list[dict[str, Any]],
        failure_code: str | None,
    ) -> None:
        metadata = b"".join(_canonical_json(event) + b"\n" for event in events)
        manifest["events_metadata_length"] = len(metadata)
        manifest["events_metadata_sha256"] = _sha256(metadata)
        manifest["audit_commitment_sha256"] = _audit_commitment(manifest)
        quarantine = None
        if failure_code is not None:
            quarantine = _canonical_json(
                {
                    "schema_version": "1.0",
                    "status": "quarantined",
                    "failure_code": failure_code,
                    "positive_transition_written": False,
                }
            )
        try:
            directory.atomic_bytes(Path("events.metadata.jsonl"), metadata, limit=_MAX_AUDIT_BYTES)
            if quarantine is not None:
                directory.atomic_bytes(
                    Path("quarantine.json"), quarantine, limit=_MAX_AUDIT_BYTES, verifier=_verify_json
                )
            directory.atomic_bytes(
                Path("manifest.json"), _canonical_json(manifest), limit=_MAX_AUDIT_BYTES, verifier=_verify_json
            )
        except Exception:
            for name in ("manifest.json", "quarantine.json", "events.metadata.jsonl"):
                try:
                    directory.unlink_regular(Path(name), missing_ok=True)
                except Exception:
                    pass
            raise RuntimeError("codex exec audit commit failed") from None

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        with self._lock:
            if self._closed:
                request = None
                self = None
                raise RuntimeError("codex exec teacher is closed") from None
            request_is_canonical = True
            request_value = teacher_request_value(request)
            request_raw = b""
            try:
                if not _bounded_canonical_preflight(request_value):
                    raise _SchemaNoncanonical
                request_raw = canonical_teacher_request_bytes(request)
                request_hash = teacher_request_hash(request)
            except Exception:
                request_is_canonical = False
                request_hash = _noncanonical_request_hash(request, self.model)
            try:
                attempt, audit_directory = self._attempt_directory(request_hash)
            except Exception:
                request = None
                request_value = None
                request_raw = b""
                self = None
                raise RuntimeError("codex exec audit commit failed") from None
            started = time.perf_counter()
            state = _JsonlState(output_limit=_bounded_output_limit(request.max_tokens))
            stdout = _StreamResult()
            stderr = _StreamResult()
            argv: list[str] = [os.fspath(self.config.executable)]
            exit_code: int | None = None
            failure_code: str | None = None
            response: TeacherResponse | None = None
            private_root: Path | None = None
            prompt = b""
            schema_raw = b""
            provider_schema_raw = b""
            provider_schema_ready = False
            normalized_schema: dict[str, Any] | None = None
            system_raw = b""
            last_raw = b""
            private: _PrivateLayout | None = None
            workspace: Path | None = None
            system_path: Path | None = None
            schema_path: Path | None = None
            last_path: Path | None = None
            try:
                if not request_is_canonical:
                    raise _InvocationFailure("noncanonical_request")
                prompt = (
                    request.user
                    + f"\n\n[EGSI output budget hint: at most {request.max_tokens} tokens.]"
                ).encode("utf-8")
                schema_raw = _canonical_json(request.schema)
                normalized_schema = _normalize_provider_output_schema(request.schema)
                if not _bounded_canonical_preflight(normalized_schema):
                    raise _InvocationFailure("provider_schema_limit")
                provider_schema_raw = _canonical_json(normalized_schema)
                system_raw = request.system.encode("utf-8")
                if request.temperature != 0.0:
                    raise _InvocationFailure("nonzero_temperature")
                if (
                    len(prompt) > _MAX_PROMPT_BYTES
                    or len(system_raw) > _MAX_SYSTEM_BYTES
                    or len(schema_raw) > _MAX_SCHEMA_BYTES
                    or len(provider_schema_raw) > _MAX_SCHEMA_BYTES
                ):
                    raise _InvocationFailure("request_size_limit")
                provider_schema_ready = True
                private = _private_layout(
                    working_root=self.working_root,
                    auth=self._auth,
                    include_workspace=True,
                )
                private_root = private.root
                workspace = private.workspace
                system_path = private_root / "system.md"
                schema_path = private_root / "schema.json"
                last_path = private_root / "last-message.txt"
                _write_private(system_path, system_raw)
                _write_private(schema_path, provider_schema_raw)
                _write_private(last_path, b"")
                argv = self._command(system_path, schema_path, last_path, workspace)
                exit_code = self._run(
                    argv, prompt, state, private, stdout, stderr
                )
                if exit_code != 0:
                    raise _InvocationFailure("nonzero_exit")
                state.finish()
                last_raw = _safe_last_message(last_path, limit=state.output_limit)
                if state.final_text is None or last_raw != state.final_text.encode("utf-8"):
                    raise _InvocationFailure("last_message_mismatch")
                if state.thread_id is None or state.usage is None:
                    raise _InvocationFailure("incomplete_event_stream")
                response = committed_teacher_response(
                    provider_request_id=state.thread_id,
                    provider=self.provider,
                    model=self.model,
                    requested_model=self.model,
                    provider_response_model="unreported",
                    text=state.final_text,
                    usage=state.usage,
                    latency_ms=max(0.0, (time.perf_counter() - started) * 1000.0),
                    cached=False,
                )
            except _InvocationFailure as error:
                failure_code = error.code
            except Exception:
                failure_code = "internal_failure"
            finally:
                if private_root is not None:
                    try:
                        _remove_private_root(private_root)
                    except Exception:
                        failure_code = "temporary_cleanup_failure"
                        response = None
            latency_ms = (
                response.latency_ms
                if response is not None
                else max(0.0, (time.perf_counter() - started) * 1000.0)
            )
            manifest: dict[str, Any] = {
                "schema_version": "1.0",
                "provider": self.provider,
                "model": self.model,
                "requested_model": self.model,
                "provider_response_model": "unreported" if response is not None else None,
                "cli_version": self.cli_version,
                "executable_id": self.executable_id,
                "executable_sha256": self.executable_sha256,
                "executable_stat": self.executable_stat,
                "executable_identity_commitment_sha256": (
                    self.executable_identity_commitment_sha256
                ),
                "request_hash": request_hash,
                "invocation_id": attempt.parent.name,
                "attempt": 0,
                "status": "committed" if response is not None and failure_code is None else "quarantined",
                "failure_code": failure_code,
                "redacted_argv": _redacted_argv(argv),
                "stdin_length": len(prompt),
                "stdin_sha256": _sha256(prompt),
                "system_length": len(system_raw),
                "system_sha256": _sha256(system_raw),
                "schema_length": len(schema_raw),
                "schema_sha256": _sha256(schema_raw),
                "provider_output_schema_transform": _PROVIDER_OUTPUT_SCHEMA_TRANSFORM,
                "provider_output_schema_length": (
                    len(provider_schema_raw) if provider_schema_ready else None
                ),
                "provider_output_schema_sha256": (
                    _sha256(provider_schema_raw) if provider_schema_ready else None
                ),
                "stdout_length": stdout.length,
                "stdout_sha256": "sha256:" + stdout.digest.hexdigest(),
                "stderr_length": stderr.length,
                "stderr_sha256": "sha256:" + stderr.digest.hexdigest(),
                "stderr_truncated_in_memory": stderr.length > len(stderr.prefix),
                "exit_code": exit_code if exit_code is not None and exit_code >= 0 else None,
                "signal": -exit_code if exit_code is not None and exit_code < 0 else None,
                "event_counts": dict(sorted(state.counts.items())),
                "usage": None if response is None else response.usage,
                "latency_ms": latency_ms,
                "max_tokens": request.max_tokens,
                "max_tokens_enforced_by_cli": False,
                "response_length": None if response is None else len(response.text.encode("utf-8")),
                "response_sha256": None if response is None else _sha256(response.text.encode("utf-8")),
                "response_commitment_sha256": None if response is None else response.response_commitment_sha256,
            }
            audit_failed = False
            try:
                self._write_audit(
                    audit_directory,
                    manifest=manifest,
                    events=state.events,
                    failure_code=failure_code,
                )
            except Exception:
                audit_failed = True
            finally:
                try:
                    audit_directory.close()
                except Exception:
                    audit_failed = True
            if audit_failed or response is None or failure_code is not None:
                nonzero_temperature = failure_code == "nonzero_temperature"
                _sanitize_stream_result(stdout)
                _sanitize_stream_result(stderr)
                state.final_text = None
                state.thread_id = None
                request = None
                request_value = None
                request_raw = b""
                prompt = b""
                schema_raw = b""
                provider_schema_raw = b""
                normalized_schema = None
                system_raw = b""
                last_raw = b""
                private = None
                private_root = None
                workspace = None
                system_path = None
                schema_path = None
                last_path = None
                argv = []
                attempt = None
                audit_directory = None
                manifest = None
                response = None
                self = None
                if audit_failed:
                    raise RuntimeError("codex exec audit commit failed") from None
                if nonzero_temperature:
                    raise ValueError("codex exec requires zero temperature") from None
                raise RuntimeError("codex exec teacher generation failed") from None
            return response

    def close(self) -> None:
        with self._lock:
            if self._auth:
                _clear_bytes(self._auth)
            if self._executable_fd >= 0:
                os.close(self._executable_fd)
                self._executable_fd = -1
            self._closed = True

    def __enter__(self) -> "CodexExecTeacher":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
