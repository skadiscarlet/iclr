from pathlib import Path

import pytest
from pydantic import ValidationError

from egsi.config import (
    CodexExecProviderConfig,
    ProviderConfig,
    ProviderRegistry,
    load_provider_config,
    ProviderConfigError,
    resolve_provider_path,
)


def _toml(path: Path, *, timeout=180, retries=3) -> Path:
    path.write_text(
        f'''active_provider = "openai"\n\n[providers.openai]\nkind = "openai_compatible"\nbase_url = "https://api.example.test/v1"\napi_key = "test-secret-key"\nmodel = "test-model"\ntimeout_seconds = {timeout}\nmax_retries = {retries}\n''',
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_loads_secure_toml_and_redacts_secret(tmp_path: Path):
    config = load_provider_config(_toml(tmp_path / "providers.toml"))

    assert config.active.model == "test-model"
    assert config.providers["openai"].api_key.get_secret_value() == "test-secret-key"
    assert "test-secret-key" not in repr(config)
    assert "test-secret-key" not in config.model_dump_json()


def test_rejects_world_or_group_readable_config(tmp_path: Path):
    path = _toml(tmp_path / "providers.toml")
    path.chmod(0o644)

    with pytest.raises(ProviderConfigError, match="permission"):
        load_provider_config(path)


def test_provider_path_priority_cli_then_environment_then_home(tmp_path: Path, monkeypatch):
    cli = tmp_path / "cli.toml"
    env = tmp_path / "env.toml"
    home = tmp_path / "home"
    monkeypatch.setenv("EGSI_PROVIDER_CONFIG", str(env))
    monkeypatch.setenv("HOME", str(home))

    assert resolve_provider_path("~/cli.toml") == Path.home() / "cli.toml"
    assert resolve_provider_path(cli) == cli
    assert resolve_provider_path() == env
    monkeypatch.setenv("EGSI_PROVIDER_CONFIG", "~/env.toml")
    assert resolve_provider_path() == Path.home() / "env.toml"
    monkeypatch.setenv("EGSI_PROVIDER_CONFIG", str(env))

    monkeypatch.delenv("EGSI_PROVIDER_CONFIG")
    assert resolve_provider_path() == home / ".config" / "egsi" / "providers.toml"


def test_unknown_active_provider_raises_key_error():
    registry = ProviderRegistry(
        active_provider="missing",
        providers={"openai": ProviderConfig(model="model", base_url="https://example.test", api_key="key")},
    )

    with pytest.raises(KeyError, match="unknown active provider"):
        _ = registry.active


@pytest.mark.parametrize(
    ("field", "value"),
    [("timeout_seconds", 0), ("timeout_seconds", -1), ("max_retries", -1), ("max_retries", 11)],
)
def test_rejects_invalid_retry_and_timeout_values(field, value):
    with pytest.raises(ValidationError) as error:
        ProviderConfig(
            base_url="https://example.test", api_key="key", model="model", **{field: value}
        )
    assert error.value.errors()[0]["loc"] == (field,)


def test_provider_models_are_frozen_and_redact_invalid_secret():
    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    with pytest.raises(ValidationError):
        config.api_key = "changed"
    assert "changed" not in repr(config)
    assert "changed" not in config.model_dump_json()


def test_loader_errors_never_expose_secret(tmp_path: Path):
    for extra in ("api_key = {token = \"SECRET\"}", "apikey = \"SECRET\""):
        path = tmp_path / "bad.toml"
        path.write_text(
            '[providers.openai]\nbase_url="https://example.test"\nmodel="m"\n' + extra + '\nactive_provider="openai"\n',
            encoding="utf-8",
        )
        path.chmod(0o600)
        with pytest.raises(ProviderConfigError) as error:
            load_provider_config(path)
        assert "SECRET" not in str(error.value)
        assert "SECRET" not in repr(error.value)
        assert error.value.__cause__ is None


def test_loader_rejects_symlink_directory_and_non_0600_modes(tmp_path: Path):
    target = _toml(tmp_path / "target.toml")
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    with pytest.raises(ProviderConfigError):
        load_provider_config(link)
    directory = tmp_path / "directory.toml"
    directory.mkdir()
    directory.chmod(0o700)
    with pytest.raises(ProviderConfigError):
        load_provider_config(directory)
    for mode in (0o400, 0o644, 0o700):
        path = _toml(tmp_path / f"{mode:o}.toml")
        path.chmod(mode)
        with pytest.raises(ProviderConfigError):
            load_provider_config(path)


def test_loader_rejects_blank_fields_and_empty_providers(tmp_path: Path):
    cases = [
        'active_provider=" "\n[providers.openai]\nbase_url="https://example.test"\napi_key="key"\nmodel="m"',
        'active_provider="openai"\n[providers.openai]\nbase_url="https://example.test"\napi_key="   "\nmodel="m"',
        'active_provider="openai"\n[providers.openai]\nbase_url="https://example.test"\napi_key="key"\nmodel=" "',
        'active_provider="openai"\n[providers.openai]\nbase_url="https://example.test"\napi_key="key"\nmodel="m"\n',
    ]
    cases[-1] = 'active_provider="openai"\nproviders = {}'
    for index, body in enumerate(cases):
        path = tmp_path / f"blank-{index}.toml"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises(ProviderConfigError):
            load_provider_config(path)


def test_loader_unknown_active_is_safe_error(tmp_path: Path):
    path = _toml(tmp_path / "unknown.toml")
    path.write_text(path.read_text().replace('active_provider = "openai"', 'active_provider = "missing"'))
    with pytest.raises(ProviderConfigError, match="unknown active provider"):
        load_provider_config(path)


def _write_bad_secret_toml(path: Path, extra: str) -> None:
    path.write_text(
        'active_provider="openai"\n[providers.openai]\nbase_url="https://example.test"\nmodel="m"\n' + extra + '\n',
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_loader_traceback_never_retains_secret_in_failure(tmp_path: Path):
    for index, kind in enumerate((0, 1)):
        path = tmp_path / f"trace-{index}.toml"
        _write_bad_secret_toml(path, 'api_key = {token = "TRACE_SECRET"}' if kind == 0 else 'apikey = "TRACE_SECRET"')
        with pytest.raises(ProviderConfigError) as raised:
            load_provider_config(path)
        error = raised.value
        assert error.__cause__ is None
        assert error.__context__ is None
        assert "TRACE_SECRET" not in repr(error)
        tb = error.__traceback__
        while tb:
            values = tuple(tb.tb_frame.f_locals.values())
            assert all("TRACE_SECRET" not in repr(value) for value in values)
            tb = tb.tb_next


def test_provider_mapping_is_immutable():
    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    registry = ProviderRegistry(active_provider="openai", providers={"openai": config})
    with pytest.raises(TypeError):
        registry.providers["new"] = config
    with pytest.raises(TypeError):
        del registry.providers["openai"]
    with pytest.raises(TypeError):
        registry.providers.clear()
    with pytest.raises(TypeError):
        registry.providers.update({"new": config})
    assert registry.active is config
    assert registry.model_dump()["providers"]["openai"]["model"] == "model"
    assert "\"key\"" not in registry.model_dump_json()

@pytest.mark.parametrize("field", ["timeout_seconds", "max_retries"])
@pytest.mark.parametrize("value", [True, False])
def test_rejects_boolean_numeric_settings(field, value):
    with pytest.raises(ValidationError) as error:
        ProviderConfig(
            base_url="https://example.test", api_key="key", model="model", **{field: value}
        )
    assert error.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("value", [0.5, 1.5])
def test_accepts_positive_fractional_timeout(value):
    config = ProviderConfig(
        base_url="https://example.test", api_key="key", model="model", timeout_seconds=value
    )
    assert config.timeout_seconds == value


def test_provider_mapping_cannot_be_mutated_via_dict_primitives_or_init():
    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    registry = ProviderRegistry(active_provider="openai", providers={"openai": config})
    with pytest.raises(TypeError):
        dict.__setitem__(registry.providers, "injected", config)
    with pytest.raises(TypeError):
        registry.providers.__init__({"injected": config})


def test_provider_mapping_copy_deepcopy_model_copy_and_pickle_are_safe():
    import copy
    import pickle

    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    registry = ProviderRegistry(active_provider="openai", providers={"openai": config})
    for copied in (copy.copy(registry.providers), copy.deepcopy(registry.providers)):
        assert dict(copied) == {"openai": config}
    cloned = registry.model_copy(deep=True)
    assert cloned.active.model == "model"
    restored = pickle.loads(pickle.dumps(registry.providers))
    assert dict(restored) == {"openai": config}
    assert "SecretStr('key')" not in repr(restored)
    assert "SecretStr('key')" not in repr(registry)
    assert '"key"' not in str(registry.model_dump())
    assert '"key"' not in registry.model_dump_json()


def test_provider_mapping_internal_storage_cannot_be_reassigned():
    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    registry = ProviderRegistry(active_provider="openai", providers={"openai": config})
    with pytest.raises((AttributeError, TypeError)):
        registry.providers._values = {"injected": config}
    with pytest.raises((AttributeError, TypeError)):
        del registry.providers._values


def test_model_copy_update_revalidates_and_freezes_provider_mapping():
    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    registry = ProviderRegistry(active_provider="openai", providers={"openai": config})
    cloned = registry.model_copy(update={"providers": {"other": config}, "active_provider": "other"})
    assert cloned.active is cloned.providers["other"]
    with pytest.raises(TypeError):
        cloned.providers["injected"] = config
    with pytest.raises(ValidationError):
        registry.model_copy(update={"providers": {}})


def test_provider_config_model_copy_revalidates_and_preserves_secret_type():
    config = ProviderConfig(base_url="https://example.test", api_key="SENTINEL", model="model")
    cloned = config.model_copy(update={"model": "updated"})
    assert cloned.model == "updated"
    assert isinstance(cloned.api_key, type(config.api_key))
    assert "SENTINEL" not in repr(cloned)
    assert "SENTINEL" not in cloned.model_dump_json()
    updated_secret = config.model_copy(update={"api_key": "SENTINEL"})
    assert updated_secret.api_key.get_secret_value() == "SENTINEL"
    assert "SENTINEL" not in repr(updated_secret)
    assert "SENTINEL" not in updated_secret.model_dump_json()
    for update in (
        {"api_key": {"token": "SENTINEL"}},
        {"kind": "invalid"},
        {"model": "   "},
        {"timeout_seconds": True},
        {"max_retries": False},
        {"extra_field": "value"},
    ):
        with pytest.raises(ValidationError):
            config.model_copy(update=update)


def test_provider_default_timeout_is_float():
    config = ProviderConfig(base_url="https://example.test", api_key="key", model="model")
    assert config.timeout_seconds == 180.0
    assert isinstance(config.timeout_seconds, float)


def test_codex_exec_config_is_discriminated_and_has_secure_defaults(tmp_path: Path):
    executable = tmp_path / "codex"
    executable.write_bytes(b"codex")
    path = tmp_path / "providers.toml"
    path.write_text(
        "\n".join(
            [
                'active_provider = "codex"',
                "[providers.codex]",
                'kind = "codex_exec"',
                'model = "gpt-test"',
                f'codex_home = "{tmp_path / "codex-home"}"',
                'model_provider = "provider-id"',
                f'executable = "{executable}"',
                'executable_sha256 = "sha256:' + "0" * 64 + '"',
            ]
        ) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    registry = load_provider_config(path)

    assert isinstance(registry.active, CodexExecProviderConfig)
    assert registry.active.executable == executable
    assert registry.active.executable_sha256 == "sha256:" + "0" * 64
    assert registry.active.expected_cli_version == "0.150.1"
    assert registry.active.timeout_seconds == 600.0
    assert registry.active.max_retries == 3
    assert registry.active.inherit_proxy_env is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0), ("max_retries", -1), ("max_retries", 11),
        ("inherit_proxy_env", 1), ("expected_cli_version", "latest"),
        ("model_provider", " "), ("executable", " "),
        ("executable", "relative/codex"),
        ("executable_sha256", "0" * 64),
    ],
)
def test_codex_exec_config_rejects_invalid_values(tmp_path: Path, field: str, value: object):
    values = {
        "kind": "codex_exec",
        "model": "model",
        "codex_home": tmp_path,
        "model_provider": "provider",
        "executable": tmp_path / "codex",
        "executable_sha256": "sha256:" + "0" * 64,
        field: value,
    }
    with pytest.raises(ValidationError):
        CodexExecProviderConfig.model_validate(values)


def test_codex_exec_config_rejects_relative_codex_home():
    with pytest.raises(ValidationError):
        CodexExecProviderConfig(
            model="model",
            codex_home=Path("relative/codex-home"),
            model_provider="provider",
            executable="/usr/bin/codex",
            executable_sha256="sha256:" + "0" * 64,
        )


def test_codex_exec_model_copy_revalidates_updates(tmp_path: Path):
    config = CodexExecProviderConfig(
        model="model", codex_home=tmp_path, model_provider="provider",
        executable=tmp_path / "codex", executable_sha256="sha256:" + "0" * 64,
    )
    assert config.model_copy(update={"model": "updated"}).model == "updated"
    for update in (
        {"model": " "},
        {"max_retries": 11},
        {"inherit_proxy_env": 1},
        {"codex_home": Path("relative")},
        {"extra": "value"},
    ):
        with pytest.raises(ValidationError):
            config.model_copy(update=update)


@pytest.mark.parametrize("version", ["0.150.0", "0.150.2", "1.0.0", "0.150.1 "])
def test_codex_exec_expected_version_is_hard_pinned(tmp_path: Path, version: str):
    with pytest.raises(ValidationError):
        CodexExecProviderConfig(
            model="model",
            codex_home=tmp_path,
            model_provider="provider",
            executable=tmp_path / "codex",
            executable_sha256="sha256:" + "0" * 64,
            expected_cli_version=version,
        )
