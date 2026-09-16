from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import signal
import stat
import threading
import time

import pytest

from egsi.config import CodexExecProviderConfig
from egsi.teacher import CodexExecTeacher, TeacherRequest
from egsi.teacher import CachedTeacher


def _codex_home(tmp_path: Path, *, provider_extra: str = "") -> Path:
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(
        "\n".join(
            [
                '[model_providers.test-provider]',
                'name = "Test Provider"',
                'base_url = "https://provider.example/v1"',
                'wire_api = "responses"',
                "requires_openai_auth = true",
                "supports_websockets = false",
                provider_extra,
            ]
        ),
        encoding="utf-8",
    )
    (home / "auth.json").write_text('{"token":"AUTH_SECRET_VALUE"}', encoding="utf-8")
    for name in ("config.toml", "auth.json"):
        (home / name).chmod(0o600)
    return home


def _fake_codex(tmp_path: Path, body: str) -> Path:
    executable = tmp_path / "fake-codex"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, stat, subprocess, sys, time\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('codex-cli 0.150.1')\n"
        "    raise SystemExit(0)\n"
        + body,
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _config(home: Path, executable: Path, **updates: object) -> CodexExecProviderConfig:
    values: dict[str, object] = {
        "kind": "codex_exec",
        "model": "fake-model",
        "codex_home": home,
        "model_provider": "test-provider",
        "executable": str(executable),
        "executable_sha256": "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest(),
        "timeout_seconds": 2.0,
        "max_retries": 2,
    }
    values.update(updates)
    return CodexExecProviderConfig.model_validate(values)


def _request(**updates: object) -> TeacherRequest:
    values: dict[str, object] = {
        "system": "PRIVATE SYSTEM",
        "user": "PRIVATE USER",
        "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        "temperature": 0.0,
        "max_tokens": 128,
    }
    values.update(updates)
    return TeacherRequest.model_validate(values)


def _tree_snapshot(root: Path) -> dict[str, tuple[int, int, int, str | None]]:
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        result[str(path.relative_to(root))] = (
            stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, digest
        )
    return result


def _assert_process_gone(pid: int) -> None:
    for _ in range(150):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    try:
        os.kill(pid, signal.SIGKILL)
    finally:
        pytest.fail(f"process {pid} survived process-group cleanup")


def _normal_body(capture: Path | None = None, *, message: str = '{"ok":true}') -> str:
    capture_code = ""
    if capture is not None:
        capture_code = f"""
schema_path=sys.argv[sys.argv.index('--output-schema')+1]
last_path=sys.argv[sys.argv.index('--output-last-message')+1]
system_override=next(sys.argv[i+1] for i,v in enumerate(sys.argv) if v == '-c' and sys.argv[i+1].startswith('model_instructions_file='))
system_path=json.loads(system_override.split('=',1)[1])
pathlib.Path({str(capture)!r}).write_text(json.dumps({{
    'argv':sys.argv[1:], 'stdin':prompt, 'env':dict(os.environ),
    'modes':{{p:oct(stat.S_IMODE(pathlib.Path(p).stat().st_mode)) for p in [system_path,schema_path,last_path]}}
}}, sort_keys=True), encoding='utf-8')
"""
    return f"""
prompt=sys.stdin.read()
message={message!r}
last=pathlib.Path(sys.argv[sys.argv.index('--output-last-message')+1])
last.write_text(message, encoding='utf-8')
{capture_code}
events=[
 {{'type':'thread.started','thread_id':'thread-123'}},
 {{'type':'turn.started'}},
 {{'type':'item.completed','item':{{'id':'r','type':'reasoning','text':'not audited'}}}},
 {{'type':'item.completed','item':{{'id':'m','type':'agent_message','text':message}}}},
 {{'type':'turn.completed','usage':{{'input_tokens':11,'cached_input_tokens':2,'cache_write_input_tokens':3,'output_tokens':4,'reasoning_output_tokens':5}}}},
]
for event in events: print(json.dumps(event), flush=True)
print('normal warning', file=sys.stderr, flush=True)
"""


def test_successful_lifecycle_uses_stdin_private_files_and_redacted_audit(tmp_path: Path) -> None:
    capture = tmp_path / "capture.json"
    executable = _fake_codex(tmp_path, _normal_body(capture))
    home = _codex_home(tmp_path)
    audit = tmp_path / "audit"
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    teacher = CodexExecTeacher(_config(home, executable), audit_root=audit, working_root=work)

    response = teacher.generate(_request())

    assert response.provider == "codex_exec"
    assert response.provider_request_id == "thread-123"
    assert response.provider_response_model == "unreported"
    assert response.text == '{"ok":true}'
    assert response.usage == {
        "input_tokens": 11,
        "cached_input_tokens": 2,
        "cache_write_input_tokens": 3,
        "output_tokens": 4,
        "reasoning_output_tokens": 5,
    }
    captured = json.loads(capture.read_text(encoding="utf-8"))
    argv = captured["argv"]
    assert argv[0] == "exec"
    for required in (
        "--strict-config", "--json", "--output-schema", "--output-last-message",
        "--sandbox", "read-only", "--ephemeral", "--ignore-user-config",
        "--ignore-rules", "--skip-git-repo-check", "--cd",
    ):
        assert required in argv
    assert argv[-1] == "-"
    overrides = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "-c"]
    assert "model_providers.test-provider.request_max_retries=2" in overrides
    assert "model_providers.test-provider.stream_max_retries=2" in overrides
    assert not any(value.startswith("request_max_retries=") for value in overrides)
    assert not any(value.startswith("stream_max_retries=") for value in overrides)
    assert "features.goals=false" in overrides
    assert not any(value.startswith("disabled_tools=") for value in overrides)
    assert captured["stdin"].startswith("PRIVATE USER")
    assert "PRIVATE SYSTEM" not in "\0".join(argv)
    assert "PRIVATE USER" not in "\0".join(argv)
    assert "AUTH_SECRET_VALUE" not in "\0".join(argv)
    assert set(captured["modes"].values()) == {"0o600"}
    assert captured["env"]["CODEX_HOME"] != str(home)
    assert not Path(captured["env"]["CODEX_HOME"]).exists()
    assert not any(work.iterdir())

    manifests = list(audit.glob("*/*/attempt-00/manifest.json"))
    assert len(manifests) == 1
    attempt = manifests[0].parent
    assert (attempt / "events.metadata.jsonl").is_file()
    assert not (attempt / "quarantine.json").exists()
    audit_raw = "\n".join(path.read_text(encoding="utf-8") for path in attempt.iterdir())
    for secret in ("PRIVATE SYSTEM", "PRIVATE USER", "AUTH_SECRET_VALUE", "not audited", response.text):
        assert secret not in audit_raw


def test_enrichment_schema_normalization_is_strict_recursive_and_nonmutating() -> None:
    import copy
    import egsi.teacher.codex_exec as module
    from egsi.contracts.enrichment import EnrichmentPayload

    original = EnrichmentPayload.model_json_schema()
    before = copy.deepcopy(original)
    normalizer = getattr(module, "_normalize_provider_output_schema", None)
    assert normalizer is not None

    normalized = normalizer(original)

    assert original == before
    for node in _object_schema_nodes(normalized):
        properties = node.get("properties", {})
        assert node["additionalProperties"] is False
        assert node["required"] == sorted(properties)
    encoded = json.dumps(normalized, sort_keys=True)
    assert '"default"' not in encoded
    assert '"title"' not in encoded

    root_properties = normalized["properties"]
    assert "authorization" in normalized["required"]
    assert {branch.get("type") for branch in root_properties["authorization"]["anyOf"]} >= {
        "null"
    }
    assert "limitations" in normalized["required"]
    trace = normalized["$defs"]["TraceStep"]
    assert "resolves_unknowns" in trace["required"]
    assert "reason_tags" in trace["required"]
    authorization = normalized["$defs"]["AuthorizationSemantics"]
    assert authorization["required"] == sorted(authorization["properties"])


def test_provider_schema_normalization_is_canonical_across_property_insertion_order() -> None:
    import egsi.teacher.codex_exec as module

    first = {
        "type": "object",
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
    }
    second = {
        "properties": {"b": {"type": "integer"}, "a": {"type": "string"}},
        "type": "object",
    }
    assert module._canonical_json(first) == module._canonical_json(second)

    first_normalized = module._normalize_provider_output_schema(first)
    second_normalized = module._normalize_provider_output_schema(second)

    assert first_normalized["required"] == ["a", "b"]
    assert second_normalized["required"] == ["a", "b"]
    assert first_normalized == second_normalized
    first_raw = module._canonical_json(first_normalized)
    second_raw = module._canonical_json(second_normalized)
    assert first_raw == second_raw
    assert module._sha256(first_raw) == module._sha256(second_raw)


@pytest.mark.parametrize(
    "bad_schema_kind", ["unknown", "bad-type", "cycle", "deep", "oversized"]
)
def test_provider_schema_normalization_rejects_noncanonical_and_bounded_failures(
    bad_schema_kind: str,
) -> None:
    import egsi.teacher.codex_exec as module

    if bad_schema_kind == "unknown":
        schema: dict = {
            "type": "object", "properties": {}, "unknownKeyword": True
        }
    elif bad_schema_kind == "bad-type":
        schema = {"type": None}
    elif bad_schema_kind == "cycle":
        schema = {"type": "object", "properties": {}}
        schema["properties"]["self"] = schema
    elif bad_schema_kind == "deep":
        child: dict = {"type": "string"}
        for _ in range(40):
            child = {"anyOf": [child]}
        schema = child
    else:
        schema = {
            "type": "object",
            "properties": {f"field_{index}": {"type": "string"} for index in range(3000)},
        }
    normalizer = getattr(module, "_normalize_provider_output_schema", None)
    assert normalizer is not None

    with pytest.raises(module._InvocationFailure, match="provider_schema"):
        normalizer(schema)


def test_fake_cli_receives_normalized_enrichment_schema_and_audit_commitment(
    tmp_path: Path,
) -> None:
    import copy
    from egsi.contracts.enrichment import EnrichmentPayload

    capture = tmp_path / "provider-schema.json"
    validator = f"""
schema_path=pathlib.Path(sys.argv[sys.argv.index('--output-schema')+1])
schema=json.loads(schema_path.read_text(encoding='utf-8'))
def check_schema(value):
    if isinstance(value, dict):
        assert 'default' not in value and 'title' not in value
        if value.get('type') == 'object':
            properties=value.get('properties', {{}})
            assert value.get('additionalProperties') is False
            assert len(value.get('required', [])) == len(properties)
            assert set(value.get('required', [])) == set(properties)
        for item in value.values(): check_schema(item)
    elif isinstance(value, list):
        for item in value: check_schema(item)
check_schema(schema)
pathlib.Path({str(capture)!r}).write_bytes(schema_path.read_bytes())
"""
    schema = EnrichmentPayload.model_json_schema()
    original = copy.deepcopy(schema)
    teacher = _teacher_for_body(tmp_path, validator + _normal_body())

    response = teacher.generate(_request(schema=schema))

    assert response.text == '{"ok":true}'
    assert schema == original
    normalized_raw = capture.read_bytes()
    normalized = json.loads(normalized_raw)
    assert all(
        set(node["required"]) == set(node.get("properties", {}))
        for node in _object_schema_nodes(normalized)
    )
    manifest_path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    original_raw = json.dumps(
        original, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert manifest["schema_length"] == len(original_raw)
    assert manifest["schema_sha256"] == "sha256:" + hashlib.sha256(original_raw).hexdigest()
    assert manifest["provider_output_schema_transform"] == "codex-strict-required-v1"
    assert manifest["provider_output_schema_length"] == len(normalized_raw)
    assert manifest["provider_output_schema_sha256"] == (
        "sha256:" + hashlib.sha256(normalized_raw).hexdigest()
    )


def test_enrichment_envelope_request_and_fake_codex_use_one_identical_schema(
    tmp_path: Path,
) -> None:
    """The model must see the exact schema enforced by ``--output-schema``."""

    import copy
    import egsi.teacher.codex_exec as codex_module
    from egsi.contracts.case import load_case_catalog
    from egsi.contracts.enrichment import EnrichmentPayload
    from egsi.data.context import build_oracle_context
    from egsi.generation.enrichment import _prompt_vocabulary, allowed_action_values
    from egsi.teacher.output_schema import normalize_strict_output_schema
    from egsi.teacher.prompts import enrichment_request

    root = Path(__file__).resolve().parents[2]
    case = load_case_catalog(root / "data/catalog/cases.jsonl")[0]
    context = build_oracle_context(root, case)
    vocabulary = _prompt_vocabulary(allowed_action_values(root))
    base_schema = EnrichmentPayload.model_json_schema()
    base_before = copy.deepcopy(base_schema)
    system, user, request_schema = enrichment_request(
        context, vocabulary, repair_attempt=0
    )
    request = TeacherRequest(
        system=system,
        user=user,
        schema=request_schema,
        temperature=0.0,
        max_tokens=8192,
    )
    capture = tmp_path / "schema-equality.json"
    body = f"""
prompt=sys.stdin.read()
envelope=json.loads(prompt.split('\\n\\n[EGSI output budget hint:',1)[0])
schema_path=pathlib.Path(sys.argv[sys.argv.index('--output-schema')+1])
provider_schema=json.loads(schema_path.read_text(encoding='utf-8'))
pathlib.Path({str(capture)!r}).write_text(json.dumps({{
    'envelope_schema':envelope['schema'],
    'provider_schema':provider_schema,
}},sort_keys=True),encoding='utf-8')
message='{{"ok":true}}'
last=pathlib.Path(sys.argv[sys.argv.index('--output-last-message')+1])
last.write_text(message,encoding='utf-8')
for event in [
 {{'type':'thread.started','thread_id':'thread-schema-equality'}},
 {{'type':'turn.started'}},
 {{'type':'item.completed','item':{{'id':'m','type':'agent_message','text':message}}}},
 {{'type':'turn.completed','usage':{{'input_tokens':1,'cached_input_tokens':0,'cache_write_input_tokens':0,'output_tokens':1,'reasoning_output_tokens':0}}}},
]: print(json.dumps(event),flush=True)
"""

    response = _teacher_for_body(tmp_path, body).generate(request)
    captured = json.loads(capture.read_text(encoding="utf-8"))

    assert response.text == '{"ok":true}'
    assert captured["envelope_schema"] == request.schema
    assert captured["provider_schema"] == request.schema
    assert codex_module._normalize_provider_output_schema(request.schema) == request.schema
    assert normalize_strict_output_schema(request.schema) == request.schema
    assert (
        codex_module._normalize_provider_output_schema(
            codex_module._normalize_provider_output_schema(request.schema)
        )
        == request.schema
    )
    assert EnrichmentPayload.model_json_schema() == base_before == base_schema
    encoded = json.dumps(request.schema, sort_keys=True)
    assert '"title"' not in encoded and '"default"' not in encoded
    for node in _object_schema_nodes(request.schema):
        assert node["additionalProperties"] is False
        assert node["required"] == sorted(node.get("properties", {}))
    trace = request.schema["$defs"]["TraceStep"]["properties"]
    assert trace["goal"]["enum"] == sorted(vocabulary["goals"])
    assert trace["operation"]["enum"] == sorted(vocabulary["operations"])
    assert trace["target_kind"]["enum"] == sorted(vocabulary["target_kinds"])
    assert trace["tool_class"]["enum"] == sorted(vocabulary["tool_classes"])
    manifest_path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_length"] == manifest["provider_output_schema_length"]
    assert manifest["schema_sha256"] == manifest["provider_output_schema_sha256"]


def test_constructor_pins_cli_version_and_secure_codex_files(tmp_path: Path) -> None:
    executable = _fake_codex(tmp_path, _normal_body())
    home = _codex_home(tmp_path)
    (home / "auth.json").chmod(0o644)

    with pytest.raises(RuntimeError, match="codex exec teacher initialization failed"):
        CodexExecTeacher(_config(home, executable), audit_root=tmp_path / "audit")

    (home / "auth.json").chmod(0o600)
    wrong = tmp_path / "wrong-codex"
    wrong.write_text("#!/bin/sh\necho 'codex-cli 0.149.0'\n", encoding="utf-8")
    wrong.chmod(0o700)
    with pytest.raises(RuntimeError, match="codex exec teacher initialization failed"):
        CodexExecTeacher(_config(home, wrong), audit_root=tmp_path / "audit")


def test_constructor_rejects_version_spoof_when_executable_sha_does_not_match(
    tmp_path: Path,
) -> None:
    executable = _fake_codex(tmp_path, _normal_body())
    config = _config(
        _codex_home(tmp_path),
        executable,
        executable_sha256="sha256:" + "0" * 64,
    )

    with pytest.raises(RuntimeError, match="initialization failed"):
        CodexExecTeacher(config, audit_root=tmp_path / "audit")


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_constructor_rejects_ambiguous_executable_links(
    tmp_path: Path, link_kind: str
) -> None:
    executable = _fake_codex(tmp_path, _normal_body())
    linked = tmp_path / "linked-codex"
    if link_kind == "symlink":
        linked.symlink_to(executable)
    else:
        os.link(executable, linked)

    with pytest.raises(RuntimeError, match="initialization failed"):
        CodexExecTeacher(
            _config(_codex_home(tmp_path), linked),
            audit_root=tmp_path / "audit",
        )


def test_replacement_after_initialization_fails_closed_before_launch(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "replacement-called"
    executable = _fake_codex(tmp_path, _normal_body())
    teacher = CodexExecTeacher(
        _config(_codex_home(tmp_path), executable),
        audit_root=tmp_path / "audit",
    )
    replacement = tmp_path / "replacement"
    replacement.write_text(
        "#!/bin/sh\ntouch " + str(marker) + "\necho 'codex-cli 0.150.1'\n",
        encoding="utf-8",
    )
    replacement.chmod(0o700)
    os.replace(replacement, executable)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    assert marker.exists() is False


def test_manifest_binds_executable_sha_stat_and_identity_commitment(
    tmp_path: Path,
) -> None:
    executable = _fake_codex(tmp_path, _normal_body())
    teacher = CodexExecTeacher(
        _config(_codex_home(tmp_path), executable),
        audit_root=tmp_path / "audit",
    )

    teacher.generate(_request())

    manifest_path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["executable_id"] == "codex-cli"
    assert manifest["executable_sha256"] == (
        "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
    )
    assert set(manifest["executable_stat"]) == {
        "device",
        "inode",
        "mode",
        "nlink",
        "size",
        "mtime_ns",
        "ctime_ns",
    }
    identity = {
        "executable_id": manifest["executable_id"],
        "executable_sha256": manifest["executable_sha256"],
        "executable_stat": manifest["executable_stat"],
        "cli_version": manifest["cli_version"],
    }
    expected = "sha256:" + hashlib.sha256(
        json.dumps(
            identity,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert manifest["executable_identity_commitment_sha256"] == expected


def test_cached_teacher_key_binds_verified_executable_identity(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    home = _codex_home(tmp_path)
    first_executable = _fake_codex(
        tmp_path, _normal_body(message='{"generation":1}')
    )
    first = CachedTeacher(
        CodexExecTeacher(
            _config(home, first_executable),
            audit_root=tmp_path / "audit-first",
        ),
        cache,
    )
    first_response = first.generate(_request())
    first.close()

    second_executable = tmp_path / "second-codex"
    second_executable.write_text(
        first_executable.read_text(encoding="utf-8").replace(
            '{"generation":1}', '{"generation":2}'
        ),
        encoding="utf-8",
    )
    second_executable.chmod(0o700)
    second = CachedTeacher(
        CodexExecTeacher(
            _config(home, second_executable),
            audit_root=tmp_path / "audit-second",
        ),
        cache,
    )

    second_response = second.generate(_request())
    second.close()

    assert first_response.text == '{"generation":1}'
    assert second_response.text == '{"generation":2}'
    assert len(list(cache.glob("*.json"))) == 2


def test_version_probe_timeout_kills_grandchild_without_hanging(tmp_path: Path) -> None:
    pid_path = tmp_path / "version-grandchild.pid"
    release_path = tmp_path / "release-version-probe"
    executable = tmp_path / "hanging-version"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib,signal,subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])\n"
        f"pid_path=pathlib.Path({str(pid_path)!r})\n"
        "pid_tmp=pid_path.with_suffix('.tmp')\n"
        "pid_tmp.write_text(str(child.pid), encoding='ascii')\n"
        "pid_tmp.replace(pid_path)\n"
        f"while not pathlib.Path({str(release_path)!r}).exists(): time.sleep(0.005)\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    started = time.monotonic()
    errors: list[BaseException] = []

    def initialize() -> None:
        try:
            CodexExecTeacher(
                _config(_codex_home(tmp_path), executable, timeout_seconds=0.75),
                audit_root=tmp_path / "audit",
            )
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=initialize, daemon=True)
    worker.start()
    publication_deadline = time.monotonic() + 0.5
    while (
        not pid_path.exists()
        and worker.is_alive()
        and time.monotonic() < publication_deadline
    ):
        time.sleep(0.005)
    published_pid = (
        pid_path.read_text(encoding="ascii") if pid_path.exists() else None
    )
    release_path.touch()
    worker.join(timeout=2.0)

    assert published_pid is not None, "version helper did not publish grandchild pid"
    assert not worker.is_alive(), "version probe initialization hung"
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert str(errors[0]) == "codex exec teacher initialization failed"
    assert time.monotonic() - started < 2.0
    pid = int(published_pid)
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        finally:
            pytest.fail("version-probe grandchild survived cleanup")


def test_version_probe_rechecks_late_reader_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.teacher.codex_exec as module

    executable = _fake_codex(tmp_path, _normal_body())
    home = _codex_home(tmp_path)
    original = module._small_stream_reader

    def late_failure(stream, result, limit):
        original(stream, result, limit)
        time.sleep(0.03)
        result.failure = module._InvocationFailure("late_version_reader_failure")

    monkeypatch.setattr(module, "_small_stream_reader", late_failure)

    with pytest.raises(RuntimeError, match=r"^codex exec teacher initialization failed$"):
        CodexExecTeacher(_config(home, executable), audit_root=tmp_path / "audit")


def test_nonzero_temperature_is_rejected_without_invoking_cli(tmp_path: Path) -> None:
    marker = tmp_path / "called"
    executable = _fake_codex(tmp_path, f"pathlib.Path({str(marker)!r}).touch()\n")
    teacher = CodexExecTeacher(
        _config(_codex_home(tmp_path), executable), audit_root=tmp_path / "audit"
    )

    with pytest.raises(ValueError, match="temperature"):
        teacher.generate(_request(temperature=0.1))

    assert not marker.exists()


def _teacher_for_body(tmp_path: Path, body: str, **config_updates: object) -> CodexExecTeacher:
    return CodexExecTeacher(
        _config(_codex_home(tmp_path), _fake_codex(tmp_path, body), **config_updates),
        audit_root=tmp_path / "audit",
        working_root=tmp_path,
    )


def _failure_body(event_source: str) -> str:
    return f"""
sys.stdin.read()
print(json.dumps({{'type':'thread.started','thread_id':'thread-fail'}}), flush=True)
print(json.dumps({{'type':'turn.started'}}), flush=True)
{event_source}
"""


def _raw_stream_body(
    stdout_raw: bytes,
    stderr_raw: bytes,
    *, last_message: str | None = None,
    tail: str = "",
) -> str:
    last_code = ""
    if last_message is not None:
        last_code = f"""
last=pathlib.Path(sys.argv[sys.argv.index('--output-last-message')+1])
last.write_text({last_message!r}, encoding='utf-8')
"""
    return f"""
sys.stdin.buffer.read()
{last_code}
sys.stdout.buffer.write({stdout_raw!r}); sys.stdout.buffer.flush()
sys.stderr.buffer.write({stderr_raw!r}); sys.stderr.buffer.flush()
{tail}
"""


def _jsonl_bytes(events: list[dict]) -> bytes:
    return b"".join(json.dumps(event).encode("utf-8") + b"\n" for event in events)


def _object_schema_nodes(value: object):
    if type(value) is dict:
        if value.get("type") == "object":
            yield value
        for item in value.values():
            yield from _object_schema_nodes(item)
    elif type(value) is list:
        for item in value:
            yield from _object_schema_nodes(item)


@pytest.mark.parametrize(
    "item_type",
    [
        "command_execution", "file_change", "mcp_tool_call", "collab_tool_call",
        "web_search", "todo_list", "error", "unknown_tool",
    ],
)
def test_tool_and_unknown_item_events_fail_closed_and_quarantine(
    tmp_path: Path, item_type: str
) -> None:
    teacher = _teacher_for_body(
        tmp_path,
        _failure_body(
            f"print(json.dumps({{'type':'item.completed','item':{{'type':{item_type!r}}}}}), flush=True)"
        ),
    )

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    quarantines = list((tmp_path / "audit").glob("*/*/attempt-00/quarantine.json"))
    assert len(quarantines) == 1
    receipt = json.loads(quarantines[0].read_text(encoding="utf-8"))
    assert receipt["failure_code"] == "forbidden_item_event"
    assert receipt["positive_transition_written"] is False
    metadata = [
        json.loads(line)
        for line in (quarantines[0].parent / "events.metadata.jsonl").read_text().splitlines()
    ]
    assert metadata[-1]["type"] == "item.completed"
    expected_item_type = item_type if item_type != "unknown_tool" else "unknown"
    assert metadata[-1]["item_type"] == expected_item_type


def test_forbidden_event_audit_retains_actual_stdout_and_stderr_metrics(
    tmp_path: Path,
) -> None:
    stdout_raw = _jsonl_bytes(
        [
            {"type": "thread.started", "thread_id": "metric-thread"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "command_execution"}},
        ]
    )
    stderr_raw = b"FORBIDDEN_EVENT_STDERR\n"
    teacher = _teacher_for_body(
        tmp_path, _raw_stream_body(stdout_raw, stderr_raw)
    )

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request())

    manifest_path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["failure_code"] == "forbidden_item_event"
    assert manifest["stdout_length"] == len(stdout_raw)
    assert manifest["stdout_sha256"] == "sha256:" + hashlib.sha256(stdout_raw).hexdigest()
    assert manifest["stderr_length"] == len(stderr_raw)
    assert manifest["stderr_sha256"] == "sha256:" + hashlib.sha256(stderr_raw).hexdigest()
    assert manifest["stderr_truncated_in_memory"] is False


def test_timeout_audit_retains_actual_stdout_and_stderr_metrics(tmp_path: Path) -> None:
    stdout_raw = _jsonl_bytes(
        [{"type": "thread.started", "thread_id": "timeout-metric-thread"}]
    )
    stderr_raw = b"TIMEOUT_STDERR\n"
    teacher = _teacher_for_body(
        tmp_path,
        _raw_stream_body(stdout_raw, stderr_raw, tail="time.sleep(60)"),
        timeout_seconds=0.15,
    )

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request())

    manifest_path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["failure_code"] == "timeout"
    assert manifest["stdout_length"] == len(stdout_raw)
    assert manifest["stdout_sha256"] == "sha256:" + hashlib.sha256(stdout_raw).hexdigest()
    assert manifest["stderr_length"] == len(stderr_raw)
    assert manifest["stderr_sha256"] == "sha256:" + hashlib.sha256(stderr_raw).hexdigest()
    assert manifest["stderr_truncated_in_memory"] is False


def test_reader_failure_audit_retains_actual_stdout_and_stderr_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.teacher.codex_exec as module

    message = '{"ok":true}'
    stdout_raw = _jsonl_bytes(
        [
            {"type": "thread.started", "thread_id": "reader-metric-thread"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "agent_message", "text": message}},
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 1,
                    "cached_input_tokens": 0,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 1,
                    "reasoning_output_tokens": 0,
                },
            },
        ]
    )
    stderr_raw = b"READER_FAILURE_STDERR\n"
    original = module._stderr_reader

    def fail_after_read(stream, result):
        original(stream, result)
        result.failure = module._InvocationFailure("injected_reader_failure")

    monkeypatch.setattr(module, "_stderr_reader", fail_after_read)
    teacher = _teacher_for_body(
        tmp_path,
        _raw_stream_body(stdout_raw, stderr_raw, last_message=message),
    )

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request())

    manifest_path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["failure_code"] == "injected_reader_failure"
    assert manifest["stdout_length"] == len(stdout_raw)
    assert manifest["stdout_sha256"] == "sha256:" + hashlib.sha256(stdout_raw).hexdigest()
    assert manifest["stderr_length"] == len(stderr_raw)
    assert manifest["stderr_sha256"] == "sha256:" + hashlib.sha256(stderr_raw).hexdigest()
    assert manifest["stderr_truncated_in_memory"] is False


def test_generation_failure_traceback_does_not_retain_sensitive_generate_locals(
    tmp_path: Path,
) -> None:
    system_secret = "TRACEBACK_SYSTEM_SECRET"
    user_secret = "TRACEBACK_USER_SECRET"
    stderr_secret = b"TRACEBACK_STDERR_SECRET\n"
    stdout_raw = _jsonl_bytes(
        [
            {"type": "thread.started", "thread_id": "traceback-thread"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "command_execution"}},
        ]
    )
    teacher = _teacher_for_body(
        tmp_path, _raw_stream_body(stdout_raw, stderr_secret)
    )
    request = _request(system=system_secret, user=user_secret)

    try:
        teacher.generate(request)
    except RuntimeError as error:
        assert str(error) == "codex exec teacher generation failed"
        assert error.__cause__ is None
        assert error.__suppress_context__ is True
        traceback = error.__traceback__
        generate_locals = None
        while traceback is not None:
            if traceback.tb_frame.f_code.co_name == "generate":
                generate_locals = traceback.tb_frame.f_locals
                break
            traceback = traceback.tb_next
        assert generate_locals is not None
        assert generate_locals.get("self") is None
        assert generate_locals.get("request") is None
        assert generate_locals.get("request_value") is None
        for name in (
            "prompt", "system_raw", "schema_raw", "request_raw", "last_raw"
        ):
            assert generate_locals.get(name) in (None, b"")
        for name in ("stdout", "stderr"):
            stream = generate_locals.get(name)
            assert stream is None or bytes(stream.prefix) == b""
        state = generate_locals.get("state")
        assert state is None or state.final_text is None
        local_bytes = [
            bytes(value)
            for value in generate_locals.values()
            if type(value) in {bytes, bytearray}
        ]
        local_text = [
            value for value in generate_locals.values() if type(value) is str
        ]
        for secret in (
            system_secret.encode(), user_secret.encode(), stderr_secret.strip(),
            b"AUTH_SECRET_VALUE",
        ):
            assert all(secret not in value for value in local_bytes)
            assert all(secret.decode() not in value for value in local_text)
    else:
        pytest.fail("generation failure was not raised")


@pytest.mark.parametrize(
    "event",
    [
        {"type": "item.started", "item": {"type": "agent_message", "text": "x"}},
        {"type": "item.updated", "item": {"type": "reasoning"}},
        {"type": "turn.failed"},
        {"type": "error", "message": "PRIVATE PROVIDER ERROR"},
        {"type": "surprise.event"},
    ],
)
def test_unknown_and_provider_failure_events_are_rejected(tmp_path: Path, event: dict) -> None:
    teacher = _teacher_for_body(
        tmp_path,
        _failure_body(f"print({json.dumps(json.dumps(event))}, flush=True)"),
    )

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    raw = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "audit").glob("*/*/attempt-00/*")
    )
    assert "PRIVATE PROVIDER ERROR" not in raw


@pytest.mark.parametrize(
    "payload",
    [
        "sys.stdout.buffer.write(b'{bad json}\\n'); sys.stdout.flush()",
        "sys.stdout.buffer.write(b'\\xff\\n'); sys.stdout.flush()",
        "print('x'*300000, flush=True)",
        "print(json.dumps({'type':'unknown','deep':" + "[" * 40 + "0" + "]" * 40 + "}), flush=True)",
    ],
)
def test_malformed_nonutf8_oversized_and_deep_json_fail_closed(
    tmp_path: Path, payload: str
) -> None:
    teacher = _teacher_for_body(tmp_path, "sys.stdin.read()\n" + payload + "\n")

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    assert len(list((tmp_path / "audit").glob("*/*/attempt-00/quarantine.json"))) == 1


def test_too_many_events_fail_closed(tmp_path: Path) -> None:
    body = """
sys.stdin.read()
print(json.dumps({'type':'thread.started','thread_id':'t'}), flush=True)
print(json.dumps({'type':'turn.started'}), flush=True)
for i in range(300):
    print(json.dumps({'type':'item.completed','item':{'type':'reasoning','text':'x'}}), flush=True)
"""
    teacher = _teacher_for_body(tmp_path, body)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())


@pytest.mark.parametrize(
    "raw_event",
    [
        '{"type":"item.completed","item":{"type":"agent_message","text":"OK"},"x":1,"x":2}',
        '{"type":"item.completed","item":{"type":"reasoning","text":"x"},"x":NaN}',
        '{"type":"item.completed","item":{"type":"reasoning","text":"x"},"x":1e400}',
    ],
)
def test_duplicate_keys_and_nonfinite_json_are_malformed(
    tmp_path: Path, raw_event: str
) -> None:
    body = f"""
sys.stdin.read()
last=pathlib.Path(sys.argv[sys.argv.index('--output-last-message')+1])
last.write_text('OK', encoding='utf-8')
print(json.dumps({{'type':'thread.started','thread_id':'t'}}), flush=True)
print(json.dumps({{'type':'turn.started'}}), flush=True)
print({raw_event!r}, flush=True)
print(json.dumps({{'type':'item.completed','item':{{'type':'agent_message','text':'OK'}}}}), flush=True)
print(json.dumps({{'type':'turn.completed','usage':{{'input_tokens':0,'cached_input_tokens':0,'cache_write_input_tokens':0,'output_tokens':0,'reasoning_output_tokens':0}}}}), flush=True)
"""
    teacher = _teacher_for_body(tmp_path, body)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    quarantine = next((tmp_path / "audit").glob("*/*/attempt-00/quarantine.json"))
    assert json.loads(quarantine.read_text())["failure_code"] == "malformed_jsonl"


@pytest.mark.parametrize("bad_value", [True, -1, 1 << 63, 1.5, "1", None])
def test_usage_requires_exact_nonbool_int64_fields(tmp_path: Path, bad_value: object) -> None:
    usage = {
        "input_tokens": bad_value,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }
    body = _normal_body().replace(
        "{'input_tokens':11,'cached_input_tokens':2,'cache_write_input_tokens':3,'output_tokens':4,'reasoning_output_tokens':5}",
        repr(usage),
    )
    teacher = _teacher_for_body(tmp_path, body)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())


def test_usage_rejects_missing_or_extra_fields(tmp_path: Path) -> None:
    for index, usage in enumerate(
        [
            {"input_tokens": 0},
            {
                "input_tokens": 0, "cached_input_tokens": 0, "cache_write_input_tokens": 0,
                "output_tokens": 0, "reasoning_output_tokens": 0, "extra": 0,
            },
        ]
    ):
        case = tmp_path / str(index)
        case.mkdir()
        body = _normal_body().replace(
            "{'input_tokens':11,'cached_input_tokens':2,'cache_write_input_tokens':3,'output_tokens':4,'reasoning_output_tokens':5}",
            repr(usage),
        )
        with pytest.raises(RuntimeError, match="generation failed"):
            _teacher_for_body(case, body).generate(_request())


@pytest.mark.parametrize("last_action", ["last.unlink()", "last.write_text('different', encoding='utf-8')"])
def test_last_message_missing_or_mismatch_fails_closed(tmp_path: Path, last_action: str) -> None:
    body = _normal_body().replace("last.write_text(message, encoding='utf-8')", last_action)
    teacher = _teacher_for_body(tmp_path, body)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())


def test_nonzero_exit_fails_despite_valid_events(tmp_path: Path) -> None:
    teacher = _teacher_for_body(tmp_path, _normal_body() + "raise SystemExit(7)\n")

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())


def test_second_agent_message_is_ambiguous_and_quarantined(tmp_path: Path) -> None:
    body = _normal_body().replace(
        "{'type':'turn.completed','usage':",
        "{'type':'item.completed','item':{'type':'agent_message','text':message}},\n {'type':'turn.completed','usage':",
    )
    teacher = _teacher_for_body(tmp_path, body)

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request())

    quarantine = next((tmp_path / "audit").glob("*/*/attempt-00/quarantine.json"))
    assert json.loads(quarantine.read_text())["failure_code"] == "ambiguous_agent_message"


def test_reasoning_after_agent_message_is_quarantined(tmp_path: Path) -> None:
    body = _normal_body().replace(
        "{'type':'turn.completed','usage':",
        "{'type':'item.completed','item':{'type':'reasoning','text':'late'}},\n {'type':'turn.completed','usage':",
    )
    teacher = _teacher_for_body(tmp_path, body)

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request())

    quarantine = next((tmp_path / "audit").glob("*/*/attempt-00/quarantine.json"))
    assert json.loads(quarantine.read_text())["failure_code"] == "invalid_event_order"


def test_close_is_idempotent_and_generate_after_close_is_rejected(tmp_path: Path) -> None:
    teacher = _teacher_for_body(tmp_path, _normal_body())
    teacher.close()
    teacher.close()

    with pytest.raises(RuntimeError, match="closed"):
        teacher.generate(_request())


def test_cached_teacher_does_not_run_codex_again_on_cache_hit(tmp_path: Path) -> None:
    count = tmp_path / "count"
    increment = f"""
count=pathlib.Path({str(count)!r})
count.write_text(str(int(count.read_text())+1) if count.exists() else '1')
"""
    inner = _teacher_for_body(tmp_path, increment + _normal_body())
    teacher = CachedTeacher(inner, tmp_path / "cache")

    first = teacher.generate(_request())
    second = teacher.generate(_request())

    assert first.cached is False
    assert second.cached is True
    assert count.read_text() == "1"


def test_selected_provider_unknown_benign_fields_are_not_injected_or_audited(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "capture.json"
    executable = _fake_codex(tmp_path, _normal_body(capture))
    home = _codex_home(tmp_path, provider_extra='ambient = "PRIVATE_AMBIENT"')
    teacher = CodexExecTeacher(_config(home, executable), audit_root=tmp_path / "audit")

    teacher.generate(_request())

    captured = capture.read_text(encoding="utf-8")
    audits = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "audit").glob("*/*/attempt-00/*")
    )
    assert "PRIVATE_AMBIENT" not in captured
    assert "PRIVATE_AMBIENT" not in audits


def test_environment_secrets_are_not_forwarded_or_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "PRIVATE_ENV_SECRET_VALUE"
    monkeypatch.setenv("EGSI_PRIVATE_TOKEN", secret)
    capture = tmp_path / "capture.json"
    teacher = CodexExecTeacher(
        _config(_codex_home(tmp_path), _fake_codex(tmp_path, _normal_body(capture))),
        audit_root=tmp_path / "audit",
    )

    teacher.generate(_request())

    assert secret not in capture.read_text(encoding="utf-8")
    assert secret not in "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "audit").glob("*/*/attempt-00/*")
    )


def test_private_codex_home_copies_auth_then_deletes_all_state_and_clears_on_close(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "capture.json"
    home = _codex_home(tmp_path)
    before = _tree_snapshot(home)
    body = """
private_codex=pathlib.Path(os.environ['CODEX_HOME'])
auth=private_codex/'auth.json'
assert auth.read_text(encoding='utf-8') == '{"token":"AUTH_SECRET_VALUE"}'
assert stat.S_IMODE(auth.stat().st_mode) == 0o600
(private_codex/'state.sqlite').write_bytes(b'sqlite-state')
os.environ['FAKE_AUTH_COPY_OK']='yes'
""" + _normal_body(capture)
    teacher = CodexExecTeacher(
        _config(home, _fake_codex(tmp_path, body)),
        audit_root=tmp_path / "audit",
    )
    assert bytes(teacher._auth) == b'{"token":"AUTH_SECRET_VALUE"}'

    teacher.generate(_request())

    captured = json.loads(capture.read_text(encoding="utf-8"))
    assert captured["env"]["FAKE_AUTH_COPY_OK"] == "yes"
    private_paths = [
        captured["env"]["HOME"], captured["env"]["CODEX_HOME"],
        captured["env"]["XDG_CONFIG_HOME"], captured["env"]["XDG_CACHE_HOME"],
        captured["env"]["XDG_DATA_HOME"], captured["env"]["XDG_STATE_HOME"],
        captured["env"]["XDG_RUNTIME_DIR"],
    ]
    assert len(set(private_paths)) == len(private_paths)
    assert all(not Path(path).exists() for path in private_paths)
    assert not Path(captured["env"]["CODEX_HOME"]).parent.exists()
    assert _tree_snapshot(home) == before
    teacher.close()
    assert bytes(teacher._auth) == b""


def test_missing_working_root_is_securely_created_and_cleaned(tmp_path: Path) -> None:
    working = tmp_path / "nested" / "work"
    teacher = CodexExecTeacher(
        _config(_codex_home(tmp_path), _fake_codex(tmp_path, _normal_body())),
        audit_root=tmp_path / "audit",
        working_root=working,
    )

    teacher.generate(_request())

    assert working.is_dir()
    assert list(working.iterdir()) == []


def test_audit_symlink_fails_before_cli_and_does_not_write_target(tmp_path: Path) -> None:
    marker = tmp_path / "called"
    outside = tmp_path / "outside"
    outside.mkdir()
    audit = tmp_path / "audit"
    audit.symlink_to(outside, target_is_directory=True)
    executable = _fake_codex(tmp_path, f"pathlib.Path({str(marker)!r}).touch()\n")
    teacher = CodexExecTeacher(_config(_codex_home(tmp_path), executable), audit_root=audit)

    with pytest.raises(RuntimeError, match="audit commit failed"):
        teacher.generate(_request())

    assert not marker.exists()
    assert list(outside.iterdir()) == []


def test_audit_atomic_error_prevents_success_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.teacher.codex_exec as module

    teacher = _teacher_for_body(tmp_path, _normal_body())

    def fail(*args, **kwargs):
        raise OSError("PRIVATE ATOMIC ERROR")

    monkeypatch.setattr(module.AnchoredDirectory, "atomic_bytes", fail)

    with pytest.raises(RuntimeError, match="audit commit failed") as error:
        teacher.generate(_request())
    assert "PRIVATE ATOMIC ERROR" not in str(error.value)


def test_quarantine_write_failure_never_leaves_manifest_commit_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.teacher.codex_exec as module

    teacher = _teacher_for_body(
        tmp_path,
        _failure_body(
            "print(json.dumps({'type':'item.completed','item':{'type':'command_execution'}}), flush=True)"
        ),
    )
    original = module.AnchoredDirectory.atomic_bytes

    def fail_quarantine(self, relative, raw, **kwargs):
        if relative.name == "quarantine.json":
            raise OSError("PRIVATE QUARANTINE FAILURE")
        return original(self, relative, raw, **kwargs)

    monkeypatch.setattr(module.AnchoredDirectory, "atomic_bytes", fail_quarantine)

    with pytest.raises(RuntimeError, match=r"^codex exec audit commit failed$"):
        teacher.generate(_request())

    attempts = list((tmp_path / "audit").glob("*/*/attempt-00"))
    assert len(attempts) == 1
    assert not (attempts[0] / "manifest.json").exists()


def test_manifest_binds_request_invocation_attempt_and_response_commitment(tmp_path: Path) -> None:
    teacher = _teacher_for_body(tmp_path, _normal_body())

    response = teacher.generate(_request())

    path = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["request_hash"] == path.parents[2].name
    assert manifest["invocation_id"] == path.parents[1].name
    assert manifest["attempt"] == 0
    assert manifest["response_commitment_sha256"] == response.response_commitment_sha256
    assert manifest["latency_ms"] == response.latency_ms
    assert manifest["max_tokens_enforced_by_cli"] is False
    metadata = (path.parent / "events.metadata.jsonl").read_bytes()
    import hashlib
    assert manifest["events_metadata_length"] == len(metadata)
    assert manifest["events_metadata_sha256"] == "sha256:" + hashlib.sha256(metadata).hexdigest()
    committed = dict(manifest)
    commitment = committed.pop("audit_commitment_sha256")
    canonical = json.dumps(
        committed, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert commitment == "sha256:" + hashlib.sha256(canonical).hexdigest()


def test_output_bytes_are_bounded_from_max_tokens(tmp_path: Path) -> None:
    teacher = _teacher_for_body(tmp_path, _normal_body(message="x" * 100))

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request(max_tokens=1))


@pytest.mark.parametrize(
    "request_value",
    [
        _request(schema={"type": "object", "x": float("nan")}),
        _request(user="bad-surrogate-\ud800"),
    ],
)
def test_noncanonical_request_is_quarantined_and_does_not_leak_anchor(
    tmp_path: Path, request_value: TeacherRequest
) -> None:
    marker = tmp_path / "called"
    teacher = _teacher_for_body(tmp_path, f"pathlib.Path({str(marker)!r}).touch()\n")

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(request_value)

    assert not marker.exists()
    assert len(list((tmp_path / "audit").glob("*/*/attempt-00/quarantine.json"))) == 1


def test_noncanonical_schema_hashing_never_calls_repr_or_leaks_dynamic_error(tmp_path: Path) -> None:
    secret = "PRIVATE_REPR_SECRET"

    class NoRepr:
        def __repr__(self) -> str:
            raise AssertionError(secret)

    teacher = _teacher_for_body(tmp_path, _normal_body())
    request_value = _request(schema={"type": "object", "x": NoRepr()})

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$") as error:
        teacher.generate(request_value)

    assert secret not in str(error.value)
    raw = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "audit").glob("*/*/attempt-00/*")
    )
    assert secret not in raw


def test_noncanonical_schema_fingerprint_distinguishes_invalid_safe_values() -> None:
    import egsi.teacher.codex_exec as module

    class Unsupported:
        pass

    projected_values = [
        None,
        False,
        True,
        0,
        1,
        "1",
        0.0,
        -0.0,
        1.5,
        [1],
        (1,),
        {"a": 1},
        {"a": 2},
        float("nan"),
        float("inf"),
        float("-inf"),
        Unsupported(),
    ]
    hashes = {
        module._noncanonical_request_hash(
            _request(schema={"invalid": float("nan"), "value": value}),
            "fake-model",
        )
        for value in projected_values
    }

    assert len(hashes) == len(projected_values)


def test_noncanonical_schema_fingerprint_partitions_audit_request_roots(
    tmp_path: Path,
) -> None:
    import egsi.teacher.codex_exec as module

    class Unsupported:
        pass

    teacher = _teacher_for_body(tmp_path, _normal_body())
    requests = [
        _request(schema={"bad": float("nan")}),
        _request(schema={"bad": Unsupported()}),
    ]
    for request in requests:
        with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
            teacher.generate(request)

    expected = {
        module._noncanonical_request_hash(request, "fake-model")
        for request in requests
    }
    actual = {path.name for path in (tmp_path / "audit").glob("sha256:*")}
    assert actual == expected


@pytest.mark.parametrize("text_size", [2_000_000, 8_000_000])
def test_noncanonical_request_hash_uses_bounded_windows_for_large_text(
    text_size: int,
) -> None:
    import gc
    import tracemalloc
    import egsi.teacher.codex_exec as module

    large_user = "P" + "x" * (text_size - 2) + "S"
    request = _request(user=large_user)
    gc.collect()
    tracemalloc.start()
    try:
        request_hash = module._noncanonical_request_hash(request, "fake-model")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert request_hash.startswith("sha256:")
    assert peak < 512_000


def test_noncanonical_schema_fingerprint_is_sorted_protocol_free_and_type_only() -> None:
    import egsi.teacher.codex_exec as module

    secret = "PRIVATE_SCHEMA_PROTOCOL_SECRET"

    class HostileMeta(type):
        def __getattribute__(cls, name: str):
            if name in {"__module__", "__name__", "__qualname__"}:
                raise AssertionError(secret)
            return super().__getattribute__(name)

    class Hostile(metaclass=HostileMeta):
        def __init__(self, value: str) -> None:
            self.value = value

        def __repr__(self) -> str:
            raise AssertionError(secret)

        def __str__(self) -> str:
            raise AssertionError(secret)

    class Other:
        pass

    def request_hash(schema: dict) -> str:
        return module._noncanonical_request_hash(_request(schema=schema), "fake-model")

    ordered_a = {"z": float("nan"), "a": {"y": 2, "x": 1}}
    ordered_b = {"a": {"x": 1, "y": 2}, "z": float("nan")}
    assert request_hash(ordered_a) == request_hash(ordered_b)
    assert request_hash({"bad": Hostile("first")}) == request_hash(
        {"bad": Hostile("second")}
    )
    assert request_hash({"bad": Hostile("first")}) != request_hash(
        {"bad": Other()}
    )


def test_noncanonical_schema_fingerprint_uses_fixed_tags_for_projection_limits() -> None:
    import egsi.teacher.codex_exec as module

    def request_hash(schema: dict) -> str:
        return module._noncanonical_request_hash(_request(schema=schema), "fake-model")

    deep_a: object = "a"
    deep_b: object = "b"
    for _ in range(40):
        deep_a = [deep_a]
        deep_b = [deep_b]
    assert request_hash({"bad": deep_a}) == request_hash({"bad": deep_b})
    assert request_hash({"bad": deep_a}) != request_hash({"bad": [["a"]]})

    wide_a = list(range(5000))
    wide_b = list(reversed(wide_a))
    assert request_hash({"bad": wide_a}) == request_hash({"bad": wide_b})
    assert request_hash({"bad": wide_a}) != request_hash({"bad": [0, 1, 2]})


def test_schema_fingerprint_rejects_large_dict_before_sorting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins
    import egsi.teacher.codex_exec as module

    value = {f"key-{index}": index for index in range(10_000)}
    original = builtins.sorted
    calls = 0

    def sorted_spy(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(builtins, "sorted", sorted_spy)
    fingerprint = module._safe_schema_projection_fingerprint(value)

    assert fingerprint == b"projection-limit-v1"
    assert calls == 0


def test_schema_fingerprint_rejects_oversized_common_prefix_keys_before_sorting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins
    import egsi.teacher.codex_exec as module

    prefix = "x" * 262_145
    value = {prefix + "a": 1, prefix + "b": 2}
    original = builtins.sorted
    calls = 0

    def sorted_spy(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(builtins, "sorted", sorted_spy)
    fingerprint = module._safe_schema_projection_fingerprint(value)

    assert fingerprint == b"projection-limit-v1"
    assert calls == 0


@pytest.mark.parametrize("container_type", [list, tuple])
def test_schema_fingerprint_rejects_large_sequence_before_descent(
    monkeypatch: pytest.MonkeyPatch, container_type: type
) -> None:
    import egsi.teacher.codex_exec as module

    original = module._project_schema_value
    calls = 0

    def projection_spy(value, state, *, depth):
        nonlocal calls
        calls += 1
        return original(value, state, depth=depth)

    monkeypatch.setattr(module, "_project_schema_value", projection_spy)
    fingerprint = module._safe_schema_projection_fingerprint(
        container_type(range(10_000))
    )

    assert fingerprint == b"projection-limit-v1"
    assert calls == 1


def test_schema_fingerprint_rejects_large_string_by_character_cap() -> None:
    import egsi.teacher.codex_exec as module

    assert (
        module._safe_schema_projection_fingerprint("x" * 300_000)
        == b"projection-limit-v1"
    )


@pytest.mark.parametrize(
    "large_value",
    [list(range(10_000)), "x" * 800_000],
    ids=["large-list", "large-string"],
)
def test_generate_preflights_structure_before_canonical_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, large_value: object
) -> None:
    import egsi.teacher.codex_exec as module

    marker = tmp_path / "called"
    teacher = _teacher_for_body(
        tmp_path,
        f"pathlib.Path({str(marker)!r}).touch()\n" + _normal_body(),
    )
    original = module._canonical_json
    request_serializations = 0

    def canonical_spy(value):
        nonlocal request_serializations
        if type(value) is dict and "system" in value and "schema" in value:
            request_serializations += 1
        return original(value)

    monkeypatch.setattr(module, "_canonical_json", canonical_spy)

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request(schema={"large": large_value}))

    assert request_serializations == 0
    assert not marker.exists()


@pytest.mark.parametrize(
    "provider_extra",
    ['api_key = "SECRET"', 'wire_api = "unknown"'],
)
def test_secret_provider_fields_and_unknown_wire_api_are_rejected(
    tmp_path: Path, provider_extra: str
) -> None:
    executable = _fake_codex(tmp_path, _normal_body())
    home = _codex_home(tmp_path, provider_extra=provider_extra)

    with pytest.raises(RuntimeError, match="initialization failed"):
        CodexExecTeacher(_config(home, executable), audit_root=tmp_path / "audit")


def test_timeout_kills_term_ignoring_grandchild(tmp_path: Path) -> None:
    pid_path = tmp_path / "grandchild.pid"
    body = f"""
child=subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
pathlib.Path({str(pid_path)!r}).write_text(str(child.pid), encoding='ascii')
time.sleep(60)
"""
    teacher = _teacher_for_body(tmp_path, body, timeout_seconds=0.15)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    pid = int(pid_path.read_text(encoding="ascii"))
    try:
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            pytest.fail("grandchild survived timeout process-group cleanup")
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_reader_start_failure_kills_child_and_quarantines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.teacher.codex_exec as module

    pid_path = tmp_path / "child.pid"
    body = f"""
pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding='ascii')
time.sleep(60)
"""
    teacher = _teacher_for_body(tmp_path, body)
    real_start = module.threading.Thread.start
    starts = 0

    def fail_second(self):
        nonlocal starts
        starts += 1
        if starts == 2:
            raise RuntimeError("PRIVATE THREAD ERROR")
        return real_start(self)

    monkeypatch.setattr(module.threading.Thread, "start", fail_second)

    with pytest.raises(RuntimeError, match="generation failed"):
        teacher.generate(_request())

    if pid_path.exists():
        pid = int(pid_path.read_text(encoding="ascii"))
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            pytest.fail("child survived reader start failure")
    raw = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "audit").glob("*/*/attempt-00/*")
    )
    assert "PRIVATE THREAD ERROR" not in raw


@pytest.mark.parametrize("reader_name", ["_stdout_reader", "_stderr_reader"])
def test_late_reader_failure_after_done_blocks_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader_name: str
) -> None:
    import egsi.teacher.codex_exec as module

    teacher = _teacher_for_body(tmp_path, _normal_body())
    original = getattr(module, reader_name)

    def fail_after_done(stream, result, *args):
        original(stream, result, *args)
        time.sleep(0.03)
        result.failure = module._InvocationFailure("late_reader_failure")

    monkeypatch.setattr(module, reader_name, fail_after_done)

    with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
        teacher.generate(_request())

    manifest = next((tmp_path / "audit").glob("*/*/attempt-00/manifest.json"))
    assert json.loads(manifest.read_text())["status"] == "quarantined"


@pytest.mark.parametrize("exit_code", [0, 7])
def test_direct_exit_always_cleans_detached_stdio_grandchild(
    tmp_path: Path, exit_code: int
) -> None:
    pid_path = tmp_path / "detached-stdio-child.pid"
    spawn = f"""
child=subprocess.Popen(
    [sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
pathlib.Path({str(pid_path)!r}).write_text(str(child.pid), encoding='ascii')
"""
    body = spawn + _normal_body() + (f"raise SystemExit({exit_code})\n" if exit_code else "")
    teacher = _teacher_for_body(tmp_path, body)

    if exit_code:
        with pytest.raises(RuntimeError, match=r"^codex exec teacher generation failed$"):
            teacher.generate(_request())
    else:
        assert teacher.generate(_request()).text == '{"ok":true}'

    _assert_process_gone(int(pid_path.read_text(encoding="ascii")))


def test_audit_stays_on_original_anchor_during_ancestor_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import egsi.teacher.codex_exec as module

    audit = tmp_path / "audit"
    moved = tmp_path / "audit-before-swap"
    real_from_fd = module.AnchoredDirectory.from_fd
    swapped = False

    def swap_then_adopt(path, descriptor):
        nonlocal swapped
        if not swapped:
            audit.rename(moved)
            audit.mkdir()
            swapped = True
        return real_from_fd(path, descriptor)

    teacher = CodexExecTeacher(
        _config(_codex_home(tmp_path), _fake_codex(tmp_path, _normal_body())),
        audit_root=audit,
    )
    monkeypatch.setattr(module.AnchoredDirectory, "from_fd", swap_then_adopt)

    teacher.generate(_request())

    assert swapped is True
    assert len(list(moved.glob("*/*/attempt-00/manifest.json"))) == 1
    assert list(audit.rglob("*")) == []
