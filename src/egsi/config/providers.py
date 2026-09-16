"""Provider configuration loading and validation."""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr, ValidationError, field_serializer, field_validator


class ProviderConfigError(Exception):
    """Safe, non-sensitive provider configuration failure."""


class ProviderConfig(BaseModel):
    """Configuration for one OpenAI-compatible or Anthropic provider."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    kind: Literal["openai_compatible", "anthropic"] = "openai_compatible"
    base_url: HttpUrl
    api_key: SecretStr
    model: str
    timeout_seconds: float = Field(default=180.0, gt=0, strict=True)
    max_retries: int = Field(default=3, ge=0, le=10, strict=True)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False):
        if update is None:
            return super().model_copy(deep=deep)
        data = self.model_dump(mode="python")
        data.update(dict(update))
        return type(self).model_validate(data)

    @field_validator("model")
    @classmethod
    def model_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("model must not be blank")
        return value

    @field_validator("api_key")
    @classmethod
    def api_key_not_blank(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("api_key must not be blank")
        return value


class CodexExecProviderConfig(BaseModel):
    """Configuration for the isolated local ``codex exec`` teacher."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    kind: Literal["codex_exec"] = "codex_exec"
    model: str
    codex_home: Path
    model_provider: str
    executable: Path
    executable_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_cli_version: Literal["0.150.1"] = "0.150.1"
    timeout_seconds: float = Field(default=600.0, gt=0, strict=True)
    max_retries: int = Field(default=3, ge=0, le=10, strict=True)
    inherit_proxy_env: bool = Field(default=True, strict=True)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False):
        if update is None:
            return super().model_copy(deep=deep)
        data = self.model_dump(mode="python")
        data.update(dict(update))
        return type(self).model_validate(data)

    @field_validator("model", "model_provider", "expected_cli_version")
    @classmethod
    def string_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("expected_cli_version")
    @classmethod
    def cli_version_is_plain(cls, value: str) -> str:
        if value != "0.150.1":
            raise ValueError("expected_cli_version is pinned")
        return value

    @field_validator("codex_home")
    @classmethod
    def codex_home_is_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("codex_home must be absolute")
        return value

    @field_validator("executable")
    @classmethod
    def executable_is_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("executable must be absolute")
        return value


ProviderEntry: TypeAlias = Annotated[
    ProviderConfig | CodexExecProviderConfig,
    Field(discriminator="kind"),
]


class _FrozenProviders(Mapping[str, ProviderEntry]):
    """A genuinely immutable, dict-like provider mapping."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, ProviderEntry] = ()):
        if hasattr(self, "_values"):
            raise TypeError("provider mapping is immutable")
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError("provider mapping is immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError("provider mapping is immutable")

    def __getitem__(self, key: str) -> ProviderConfig:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return repr(dict(self._values))

    def __setitem__(self, key: str, value: ProviderEntry) -> None:
        raise TypeError("provider mapping is immutable")

    def __delitem__(self, key: str) -> None:
        raise TypeError("provider mapping is immutable")

    def clear(self) -> None:
        raise TypeError("provider mapping is immutable")

    def update(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("provider mapping is immutable")

    def __copy__(self):
        return _FrozenProviders(self._values)

    def __deepcopy__(self, memo):
        return _FrozenProviders(self._values)

    def __reduce__(self):
        return (_FrozenProviders, (dict(self._values),))


class ProviderRegistry(BaseModel):
    """Named provider configurations and the currently selected provider."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    active_provider: str
    providers: Mapping[str, ProviderEntry] = Field(min_length=1)

    @field_validator("active_provider")
    @classmethod
    def active_provider_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("active_provider must not be blank")
        return value

    @field_validator("providers")
    @classmethod
    def provider_names_not_blank(cls, value: Mapping[str, ProviderEntry]) -> Mapping[str, ProviderEntry]:
        result: dict[str, ProviderEntry] = {}
        for name, config in value.items():
            clean = name.strip()
            if not clean:
                raise ValueError("provider name must not be blank")
            if clean in result:
                raise ValueError("provider names must be unique after stripping")
            result[clean] = config
        return _FrozenProviders(result)

    @field_serializer("providers")
    def serialize_providers(self, value: Mapping[str, ProviderEntry]) -> dict[str, ProviderEntry]:
        return dict(value)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False):
        if update is None:
            return super().model_copy(deep=deep)
        data = self.model_dump(mode="python")
        data.update(dict(update))
        return type(self).model_validate(data)

    @property
    def active(self) -> ProviderEntry:
        try:
            return self.providers[self.active_provider]
        except KeyError as exc:
            raise KeyError(f"unknown active provider: {self.active_provider}") from exc


def resolve_provider_path(cli_path: Path | str | None = None) -> Path:
    """Resolve configuration path in CLI, environment, then user-default order."""

    if cli_path is not None:
        return Path(cli_path).expanduser()
    if env_path := os.environ.get("EGSI_PROVIDER_CONFIG"):
        return Path(env_path).expanduser()
    return (Path.home() / ".config" / "egsi" / "providers.toml").expanduser()


def _load_provider_config_helper(config_path: Path) -> tuple[ProviderRegistry | None, str | None]:
    """Perform all fallible work and return only safe results/codes."""

    registry: ProviderRegistry | None = None
    error_code: str | None = None
    try:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
            error_code = "unsupported secure-open platform"
        else:
            fd = os.open(config_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                mode = stat.S_IMODE(info.st_mode)
                if not stat.S_ISREG(info.st_mode):
                    error_code = "non-regular file"
                elif hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                    error_code = "owner mismatch"
                elif mode != 0o600:
                    error_code = f"permissions mode {mode:#o}"
                else:
                    with os.fdopen(fd, "rb") as handle:
                        fd = -1
                        data: Any = tomllib.load(handle)
                    registry = ProviderRegistry.model_validate(data)
                    registry.active
            finally:
                if fd >= 0:
                    os.close(fd)
    except KeyError:
        error_code = "unknown active provider"
        registry = None
    except (OSError, tomllib.TOMLDecodeError, ValidationError, TypeError, ValueError):
        error_code = "OS, parse, or validation error"
        registry = None
    return registry, error_code


def load_provider_config(path: Path | str | None = None) -> ProviderRegistry:
    """Read a permission-restricted TOML provider registry and validate it."""

    config_path = resolve_provider_path(path)
    registry, error_code = _load_provider_config_helper(config_path)
    if error_code is not None or registry is None:
        raise ProviderConfigError(f"provider config invalid ({config_path}): {error_code}") from None
    return registry
