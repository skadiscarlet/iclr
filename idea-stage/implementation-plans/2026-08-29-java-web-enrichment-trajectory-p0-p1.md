# Java Web P0/P1 Enrichment and T1 Trajectory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable, tested pipeline that converts the existing 300 patch-grounded Java Web cases into validated teacher enrichments, redacted policy inputs, honest zero-reward T1 BC trajectories, replayable event logs, and P0/P1 reports.

**Architecture:** A provider-neutral teacher layer reads a bounded oracle context assembled from pinned Git objects, advisory metadata, patch hunks, and affected source files. Its strict structured output is validated against real paths and the existing Action DSL, then split into oracle labels and redacted policy-facing records. A deterministic compiler turns the label-side trace skeleton into candidate-ranking transitions tagged `patch_grounded_bc`; T1 transitions never receive dynamic Facts, certificates, or terminal vulnerability reward.

**Tech Stack:** Python 3.11+, Pydantic 2, httpx, jsonschema, PyArrow, Typer, pytest, respx, standard-library `tomllib`, Git CLI.

**Canonical design:** `idea-stage/JAVA_WEB_TRAINING_PIPELINE_DESIGN.md`

---

## Scope and Working Constraints

This plan implements roadmap Phase A only. It does not build Java projects, run PoCs, execute CodeQL, train a model, calculate dynamic reward, or launch a remote GPU job.

The current checkout has an empty `.git/` directory and is not a valid Git worktree. Each task still contains the exact intended commit command. Run commit steps only after execution occurs in a real writable Git worktree; do not initialize or replace the mounted `.git/` directory. Until then, preserve task-boundary file hashes in the implementation log.

The project `data` path is a symlink outside the workspace write root. Tests must use `tmp_path`. Pilot commands write to `.work/p0` and `.work/p1` first; copying accepted results to `data/derived` is a separate explicit operation when that target is writable.

## File Map

```text
pyproject.toml                              package/dependency/test configuration
.gitignore                                  secrets, caches, work outputs
configs/providers.example.toml              provider configuration example
configs/p0_cases.txt                        frozen ten-case smoke set
configs/p1_cases.txt                        frozen thirty-case pilot set
src/egsi/cli.py                             Typer entry point
src/egsi/contracts/case.py                  tolerant reader for current case catalog
src/egsi/contracts/enrichment.py            strict teacher output and validation records
src/egsi/contracts/trajectory.py            strict T1 event/transition records
src/egsi/config/providers.py                TOML loading and key redaction
src/egsi/teacher/base.py                    provider-neutral request/response protocol
src/egsi/teacher/openai_compatible.py       OpenAI-compatible HTTP adapter
src/egsi/teacher/anthropic.py               Anthropic Messages HTTP adapter
src/egsi/teacher/cache.py                   prompt/schema/model content cache
src/egsi/teacher/prompts.py                 deterministic enrichment prompts
src/egsi/teacher/fixture.py                 offline contract-test teacher (never promoted)
src/egsi/data/git_objects.py                safe reads from pinned bare Git objects
src/egsi/data/context.py                    bounded oracle context construction
src/egsi/generation/enrichment.py           retry, parse, validate, persist orchestration
src/egsi/generation/redaction.py            oracle/policy split and leakage gate
src/egsi/generation/candidates.py            deterministic legal candidate compiler
src/egsi/generation/trajectory.py            T1 BC transition and event compilation
src/egsi/generation/replay.py                deterministic event replay and validation
src/egsi/generation/pilot.py                 restartable P0/P1 orchestration and reports
scripts/validate_collected_cases_readonly.py read-only wrapper for the external data validator
tests/                                      unit and integration tests
```

### Task 1: Bootstrap the Python Package

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `src/egsi/__init__.py`
- Create: `tests/test_package.py`

- [ ] **Step 1: Write the failing import/version test**

```python
# tests/test_package.py
from egsi import __version__


def test_package_version() -> None:
    assert __version__ == "0.1.0"
```

- [ ] **Step 2: Run the test and verify that package import fails**

Run: `python -m pytest tests/test_package.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'egsi'`.

- [ ] **Step 3: Add package metadata and minimal module**

```toml
# pyproject.toml
[build-system]
requires = ["hatchling>=1.25,<2"]
build-backend = "hatchling.build"

[project]
name = "egsi"
version = "0.1.0"
description = "Evidence-guided Java Web investigation training pipeline"
requires-python = ">=3.11"
dependencies = [
  "httpx>=0.27,<1",
  "jsonschema>=4.23,<5",
  "pyarrow>=17,<24",
  "pydantic>=2.9,<3",
  "typer>=0.12,<1",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.3,<10",
  "pytest-cov>=5,<8",
  "respx>=0.21,<1",
]

[project.scripts]
egsi = "egsi.cli:app"

[tool.hatch.build.targets.wheel]
packages = ["src/egsi"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --import-mode=importlib"
```

```gitignore
# .gitignore
__pycache__/
*.py[cod]
.pytest_cache/
.coverage
htmlcov/
.venv/
.work/
dist/
build/
*.egg-info/
configs/providers.local.toml
data/derived/cache/teacher/
```

```python
# src/egsi/__init__.py
__version__ = "0.1.0"
```

- [ ] **Step 4: Install editable dependencies and run the test**

Run: `python -m pip install -e '.[dev]' && python -m pytest tests/test_package.py -q`

Expected: `1 passed`.

- [ ] **Step 5: Commit the bootstrap**

```bash
git add pyproject.toml .gitignore src/egsi/__init__.py tests/test_package.py
git commit -m "build: bootstrap EGSI enrichment package"
```

### Task 2: Load Existing Case Manifests Without Losing Provenance

**Files:**
- Create: `src/egsi/contracts/__init__.py`
- Create: `src/egsi/contracts/case.py`
- Create: `tests/contracts/test_case.py`

- [ ] **Step 1: Write tests against a real catalog row and malformed revisions**

```python
# tests/contracts/test_case.py
import json
from pathlib import Path

import pytest

import pytest
from pydantic import ValidationError

from egsi.contracts.case import CaseManifest, load_case_catalog


def test_load_real_catalog_preserves_extra_provenance() -> None:
    cases = load_case_catalog(Path("data/catalog/cases.jsonl"))
    assert len(cases) == 300
    case = cases[0]
    assert len(case.repository.vulnerable_commit) == 40
    assert case.artifacts.patch_path.endswith("fix.patch")
    assert case.model_extra and "split_groups" in case.model_extra


def test_reject_short_commit() -> None:
    raw = json.loads(Path("data/catalog/cases.jsonl").read_text().splitlines()[0])
    raw["repository"]["vulnerable_commit"] = "deadbeef"
    with pytest.raises(ValidationError):
        CaseManifest.model_validate(raw)
```

- [ ] **Step 2: Run the tests and verify missing contract failure**

Run: `python -m pytest tests/contracts/test_case.py -q`

Expected: FAIL importing `egsi.contracts.case`.

- [ ] **Step 3: Implement tolerant input contracts and JSONL loader**

```python
# src/egsi/contracts/__init__.py
from .case import CaseManifest, load_case_catalog

__all__ = ["CaseManifest", "load_case_catalog"]
```

```python
# src/egsi/contracts/case.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

HEX40 = re.compile(r"^[0-9a-f]{40}$")


class RepositoryRef(BaseModel):
    model_config = ConfigDict(extra="allow")
    url: str
    upstream_id: str
    vulnerable_commit: str
    fixed_commit: str

    @field_validator("vulnerable_commit", "fixed_commit")
    @classmethod
    def full_sha(cls, value: str) -> str:
        if not HEX40.fullmatch(value):
            raise ValueError("revision must be a lowercase full 40-hex SHA")
        return value


class ArtifactRefs(BaseModel):
    model_config = ConfigDict(extra="allow")
    patch_path: str
    proof_obligations_path: str
    manifest_path: str
    poc_status: str = "not_collected"
    poc_url: str | None = None
    test_paths: list[str] = Field(default_factory=list)


class ViewRefs(BaseModel):
    model_config = ConfigDict(extra="allow")
    oracle_view_path: str
    policy_view_path: str
    redaction_manifest_sha256: str


class CaseManifest(BaseModel):
    model_config = ConfigDict(extra="allow")
    schema_version: str
    case_id: str
    evidence_tier: Literal["T0", "T1", "T2", "T3"]
    family: Literal["source_to_sink", "authorization"]
    cwe_normalized_primary: str
    split: Literal["train", "dev", "time_ood_test"]
    repository: RepositoryRef
    artifacts: ArtifactRefs
    views: ViewRefs
    affected_locations: list[dict[str, Any]] = Field(default_factory=list)


def load_case_catalog(path: Path) -> list[CaseManifest]:
    result: list[CaseManifest] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            result.append(CaseManifest.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"invalid case manifest at {path}:{number}: {exc}") from exc
    return result
```

- [ ] **Step 4: Run contract tests**

Run: `python -m pytest tests/contracts/test_case.py -q`

Expected: `2 passed`.

- [ ] **Step 5: Commit case contracts**

```bash
git add src/egsi/contracts tests/contracts/test_case.py
git commit -m "feat: load patch-grounded case manifests"
```

### Task 3: Define Strict Enrichment and T1 Trajectory Contracts

**Files:**
- Create: `src/egsi/contracts/enrichment.py`
- Create: `src/egsi/contracts/trajectory.py`
- Create: `tests/contracts/test_enrichment.py`
- Create: `tests/contracts/test_trajectory.py`

- [ ] **Step 1: Write tests that forbid teacher Facts/rewards and non-zero T1 rewards**

```python
# tests/contracts/test_enrichment.py
import pytest
from pydantic import ValidationError

from egsi.contracts.enrichment import EnrichmentPayload


def test_teacher_payload_forbids_fact_field() -> None:
    with pytest.raises(ValidationError):
        EnrichmentPayload.model_validate({
            "family": "authorization",
            "hypothesis": "a guard may be missing",
            "locations": [],
            "obligations": [],
            "trace": [],
            "facts": ["confirmed"],
        })


def test_authorization_payload_requires_explicit_relation() -> None:
    with pytest.raises(ValidationError, match="authorization semantics"):
        EnrichmentPayload.model_validate({
            "family": "authorization",
            "hypothesis": "the resource relation may be unchecked",
            "locations": [{"path": "src/A.java", "role": "guard"}],
            "obligations": [{"obligation_id": "O-1", "kind": "authorization",
                             "description": "establish subject-resource relation"}],
            "trace": [{"step_id": "S-1", "goal": "CHECK_SECURITY_INVARIANT",
                       "operation": "check_auth_relation", "target_kind": "resource",
                       "target_id": "record", "resolves_unknowns": ["O-1"],
                       "expected_evidence_type": "authorization_relation",
                       "tool_class": "semantic_model"}],
            "authorization": None,
        })
```

```python
# tests/contracts/test_trajectory.py
import pytest
from pydantic import ValidationError

from egsi.contracts.trajectory import RewardVector


def test_patch_grounded_reward_must_be_zero() -> None:
    with pytest.raises(ValidationError):
        RewardVector(label_scope="patch_grounded_bc", terminal=1.0)
```

- [ ] **Step 2: Run tests and verify missing model failures**

Run: `python -m pytest tests/contracts/test_enrichment.py tests/contracts/test_trajectory.py -q`

Expected: FAIL importing both modules.

- [ ] **Step 3: Implement exact structured teacher models**

```python
# src/egsi/contracts/enrichment.py
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnrichedLocation(StrictModel):
    path: str = Field(min_length=1)
    symbol: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    role: Literal["entry", "source", "propagation", "guard", "sink", "resource", "identity", "impact"]


class AuthorizationSemantics(StrictModel):
    attacker_principal: str = "unknown"
    victim_principal: str = "unknown"
    action: str = "unknown"
    resource: str = "unknown"
    expected_relation: str = "unknown"
    actual_check: str = "unknown"
    observable_impact: str = "unknown"


class ProofObligation(StrictModel):
    obligation_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    description: str = Field(min_length=1)
    status: Literal["unknown"] = "unknown"


class TraceStep(StrictModel):
    step_id: str = Field(min_length=1)
    goal: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    target_kind: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    target_location: str | None = None
    resolves_unknowns: list[str] = Field(default_factory=list)
    expected_evidence_type: str = Field(min_length=1)
    tool_class: str = Field(min_length=1)
    reason_tags: list[str] = Field(default_factory=list)


class EnrichmentPayload(StrictModel):
    family: Literal["source_to_sink", "authorization"]
    hypothesis: str = Field(min_length=1)
    locations: list[EnrichedLocation] = Field(min_length=1)
    obligations: list[ProofObligation] = Field(min_length=1)
    trace: list[TraceStep] = Field(min_length=1)
    authorization: AuthorizationSemantics | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def family_semantics(self) -> "EnrichmentPayload":
        if self.family == "authorization" and self.authorization is None:
            raise ValueError("authorization semantics are required for authorization cases")
        if self.family == "source_to_sink" and self.authorization is not None:
            raise ValueError("authorization semantics are forbidden for source-to-sink cases")
        return self


class EnrichmentValidation(StrictModel):
    valid: bool
    family_mismatch: bool = False
    invalid_locations: list[str] = Field(default_factory=list)
    invalid_trace_locations: list[str] = Field(default_factory=list)
    invalid_goals: list[str] = Field(default_factory=list)
    invalid_operations: list[str] = Field(default_factory=list)
    invalid_target_kinds: list[str] = Field(default_factory=list)
    invalid_tool_classes: list[str] = Field(default_factory=list)


class EnrichmentRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    provider: str
    model: str
    provider_request_id: str | None = None
    prompt_sha256: str
    source_context_sha256: str
    temperature: float = 0.0
    max_tokens: int = Field(default=8192, gt=0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    usage: dict[str, int] = Field(default_factory=dict)
    structured_output_valid: bool = True
    payload: EnrichmentPayload
    validation: EnrichmentValidation
```

```python
# src/egsi/contracts/trajectory.py
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RewardVector(StrictModel):
    label_scope: Literal["patch_grounded_bc"]
    terminal: float = 0.0
    verified_proof_delta: float = 0.0
    counter_evidence: float = 0.0
    contradiction_resolution: float = 0.0
    normalized_cost: float = 0.0

    @model_validator(mode="after")
    def no_synthetic_reward(self) -> "RewardVector":
        values = (self.terminal, self.verified_proof_delta, self.counter_evidence,
                  self.contradiction_resolution, self.normalized_cost)
        if any(value != 0.0 for value in values):
            raise ValueError("patch_grounded_bc reward components must be zero")
        return self


class VerifierDecision(StrictModel):
    accepted: bool
    label_scope: Literal["patch_grounded_bc"]
    checks: list[str] = Field(default_factory=list)


class T1Transition(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    episode_id: str
    state_version: int = Field(ge=0)
    state: dict[str, Any]
    candidate_actions: list[dict[str, Any]]
    legal_mask: list[bool]
    selected_action: dict[str, Any]
    observation: dict[str, Any]
    evidence_delta: dict[str, Any]
    verifier_decision: VerifierDecision
    reward_vector: RewardVector
    next_state_version: int = Field(ge=1)
    done: bool

    @model_validator(mode="after")
    def consistent(self) -> "T1Transition":
        if self.next_state_version != self.state_version + 1:
            raise ValueError("state versions must be consecutive")
        if len(self.candidate_actions) != len(self.legal_mask):
            raise ValueError("candidate_actions and legal_mask lengths differ")
        if self.selected_action not in self.candidate_actions:
            raise ValueError("selected action is not a candidate")
        index = self.candidate_actions.index(self.selected_action)
        if not self.legal_mask[index]:
            raise ValueError("selected action is illegal")
        return self


class EpisodeEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    sequence: int = Field(ge=0)
    episode_id: str
    event_type: Literal[
        "EPISODE_STARTED", "HYPOTHESIS_CREATED", "ACTION_PROPOSED",
        "ACTION_SELECTED", "PATCH_GROUNDED_LABEL_RECORDED", "EPISODE_CLOSED"
    ]
    payload: dict[str, Any]
    previous_event_sha256: str | None = None
    event_sha256: str
```

- [ ] **Step 4: Run strict contract tests**

Run: `python -m pytest tests/contracts/test_enrichment.py tests/contracts/test_trajectory.py -q`

Expected: `3 passed`.

- [ ] **Step 5: Commit structured contracts**

```bash
git add src/egsi/contracts/enrichment.py src/egsi/contracts/trajectory.py tests/contracts
git commit -m "feat: define strict enrichment and T1 trajectory contracts"
```

### Task 4: Load Provider Keys From a Permission-Checked TOML File

**Files:**
- Create: `configs/providers.example.toml`
- Create: `src/egsi/config/__init__.py`
- Create: `src/egsi/config/providers.py`
- Create: `tests/config/test_providers.py`

- [ ] **Step 1: Write config, priority, and redaction tests**

```python
# tests/config/test_providers.py
from pathlib import Path

import pytest

from egsi.config.providers import load_provider_config


def test_load_and_redact_provider(tmp_path: Path) -> None:
    path = tmp_path / "providers.toml"
    path.write_text(
        'active_provider="openai"\n'
        '[providers.openai]\n'
        'kind="openai_compatible"\n'
        'base_url="https://example.test/v1"\n'
        'api_key="secret-value"\n'
        'model="gpt-test"\n'
        'timeout_seconds=30\n'
        'max_retries=2\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    config = load_provider_config(path)
    assert config.active.api_key.get_secret_value() == "secret-value"
    assert "secret-value" not in repr(config)


def test_reject_world_readable_secret_file(tmp_path: Path) -> None:
    path = tmp_path / "providers.toml"
    path.write_text('active_provider="x"\n[providers.x]\nbase_url="https://x"\napi_key="k"\nmodel="m"')
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        load_provider_config(path)
```

- [ ] **Step 2: Run and verify missing config module failure**

Run: `python -m pytest tests/config/test_providers.py -q`

Expected: FAIL importing `egsi.config.providers`.

- [ ] **Step 3: Implement TOML loading with `0600` enforcement**

```toml
# configs/providers.example.toml
active_provider = "openai"

[providers.openai]
kind = "openai_compatible"
base_url = "https://api.openai.com/v1"
api_key = "replace-me"
model = "gpt-5.6-sol"
timeout_seconds = 180
max_retries = 3

[providers.anthropic]
kind = "anthropic"
base_url = "https://api.anthropic.com"
api_key = "replace-me"
model = "claude-opus-5"
timeout_seconds = 180
max_retries = 3
```

```python
# src/egsi/config/__init__.py
from .providers import ProviderConfig, ProviderRegistry, load_provider_config

__all__ = ["ProviderConfig", "ProviderRegistry", "load_provider_config"]
```

```python
# src/egsi/config/providers.py
from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["openai_compatible", "anthropic"] = "openai_compatible"
    base_url: HttpUrl
    api_key: SecretStr
    model: str
    timeout_seconds: float = Field(default=180, gt=0)
    max_retries: int = Field(default=3, ge=0, le=10)


class ProviderRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active_provider: str
    providers: dict[str, ProviderConfig]

    @property
    def active(self) -> ProviderConfig:
        if self.active_provider not in self.providers:
            raise KeyError(f"unknown active provider: {self.active_provider}")
        return self.providers[self.active_provider]


def resolve_provider_path(cli_path: Path | None = None) -> Path:
    if cli_path is not None:
        return cli_path
    if value := os.environ.get("EGSI_PROVIDER_CONFIG"):
        return Path(value)
    return Path.home() / ".config" / "egsi" / "providers.toml"


def load_provider_config(path: Path | None = None) -> ProviderRegistry:
    resolved = resolve_provider_path(path)
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"provider config must be mode 0600, found {mode:04o}")
    with resolved.open("rb") as handle:
        return ProviderRegistry.model_validate(tomllib.load(handle))
```

- [ ] **Step 4: Run config tests**

Run: `python -m pytest tests/config/test_providers.py -q`

Expected: `2 passed`.

- [ ] **Step 5: Commit provider configuration support**

```bash
git add configs/providers.example.toml src/egsi/config tests/config
git commit -m "feat: load provider keys from protected TOML config"
```

### Task 5: Implement Provider-Neutral Structured Teacher Calls and Cache

**Files:**
- Create: `src/egsi/teacher/__init__.py`
- Create: `src/egsi/teacher/base.py`
- Create: `src/egsi/teacher/openai_compatible.py`
- Create: `src/egsi/teacher/anthropic.py`
- Create: `src/egsi/teacher/cache.py`
- Create: `tests/teacher/test_adapters.py`
- Create: `tests/teacher/test_cache.py`

- [ ] **Step 1: Write HTTP contract and cache-key tests**

```python
# tests/teacher/test_adapters.py
import httpx

from egsi.config.providers import ProviderConfig
from egsi.teacher.base import TeacherRequest
from egsi.teacher.openai_compatible import OpenAICompatibleTeacher


def test_openai_adapter_never_returns_api_key() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["authorization"] == "Bearer secret"
        if calls == 1:
            return httpx.Response(500, json={"error": "retry"})
        return httpx.Response(200, json={"id": "r1", "choices": [{"message": {"content": '{"ok":true}'}}], "usage": {"total_tokens": 7}})
    config = ProviderConfig(base_url="https://example.test/v1", api_key="secret", model="m", max_retries=1)
    teacher = OpenAICompatibleTeacher(config, transport=httpx.MockTransport(handler))
    response = teacher.generate(TeacherRequest(system="s", user="u", schema={"type": "object"}))
    assert response.text == '{"ok":true}'
    assert "secret" not in response.model_dump_json()
    assert calls == 2
```

```python
# tests/teacher/test_cache.py
from pathlib import Path

from egsi.teacher.base import TeacherRequest, TeacherResponse
from egsi.teacher.cache import CachedTeacher, request_cache_key


class CountingTeacher:
    provider = "mock"
    model = "mock-1"

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        return TeacherResponse(provider_request_id="one", provider=self.provider, model=self.model,
                               text='{"ok":true}', usage={"total_tokens": 3})


def test_cache_key_changes_with_model_and_schema() -> None:
    request = TeacherRequest(system="s", user="prompt", schema={"type": "object"})
    a = request_cache_key("p", "m1", request)
    b = request_cache_key("p", "m2", request)
    assert a != b
    assert a.startswith("sha256:")


def test_cached_teacher_avoids_duplicate_provider_call(tmp_path: Path) -> None:
    inner = CountingTeacher()
    teacher = CachedTeacher(inner, tmp_path)
    request = TeacherRequest(system="s", user="u", schema={"type": "object"})
    assert teacher.generate(request).cached is False
    assert teacher.generate(request).cached is True
    assert inner.calls == 1
```

- [ ] **Step 2: Run and verify missing teacher modules**

Run: `python -m pytest tests/teacher/test_adapters.py tests/teacher/test_cache.py -q`

Expected: FAIL importing `egsi.teacher` modules.

- [ ] **Step 3: Implement the common protocol, adapters, and atomic cache**

```python
# src/egsi/teacher/base.py
from __future__ import annotations

from typing import Any, Protocol

import httpx

from pydantic import BaseModel, ConfigDict, Field


class TeacherRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    system: str
    user: str
    schema: dict[str, Any]
    temperature: float = 0.0
    max_tokens: int = Field(default=8192, gt=0)


class TeacherResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider_request_id: str | None
    provider: str
    model: str
    text: str
    usage: dict[str, int]
    latency_ms: float = Field(default=0.0, ge=0.0)
    cached: bool = False


class Teacher(Protocol):
    provider: str
    model: str

    def generate(self, request: TeacherRequest) -> TeacherResponse: ...


def post_json(client: httpx.Client, url: str, headers: dict[str, str], payload: dict[str, Any],
              max_retries: int) -> httpx.Response:
    for attempt in range(max_retries + 1):
        try:
            response = client.post(url, headers=headers, json=payload)
        except httpx.TransportError as exc:
            if attempt < max_retries:
                continue
            raise RuntimeError(f"teacher transport failed after {attempt + 1} attempts: {type(exc).__name__}") from None
        if (response.status_code in {408, 409, 425, 429} or response.status_code >= 500) and attempt < max_retries:
            continue
        if response.is_error:
            raise RuntimeError(f"teacher HTTP status {response.status_code}")
        return response
    raise AssertionError("unreachable retry loop")
```

```python
# src/egsi/teacher/openai_compatible.py
from __future__ import annotations

import time

import httpx

from egsi.config.providers import ProviderConfig
from .base import TeacherRequest, TeacherResponse, post_json


class OpenAICompatibleTeacher:
    provider = "openai_compatible"

    def __init__(self, config: ProviderConfig, transport: httpx.BaseTransport | None = None):
        self.config = config
        self.model = config.model
        self.client = httpx.Client(timeout=config.timeout_seconds, transport=transport)

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        url = str(self.config.base_url).rstrip("/") + "/chat/completions"
        started = time.perf_counter()
        response = post_json(self.client, url, headers={
            "authorization": f"Bearer {self.config.api_key.get_secret_value()}",
            "content-type": "application/json",
        }, payload={
            "model": self.config.model,
            "messages": [{"role": "system", "content": request.system}, {"role": "user", "content": request.user}],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "egsi_enrichment", "strict": True, "schema": request.schema}},
        }, max_retries=self.config.max_retries)
        body = response.json()
        return TeacherResponse(provider_request_id=body.get("id"), provider="openai_compatible",
                               model=self.config.model, text=body["choices"][0]["message"]["content"],
                               usage={k: int(v) for k, v in body.get("usage", {}).items() if isinstance(v, int)},
                               latency_ms=(time.perf_counter() - started) * 1000)
```

```python
# src/egsi/teacher/anthropic.py
from __future__ import annotations

import time

import httpx

from egsi.config.providers import ProviderConfig
from .base import TeacherRequest, TeacherResponse, post_json


class AnthropicTeacher:
    provider = "anthropic"

    def __init__(self, config: ProviderConfig, transport: httpx.BaseTransport | None = None):
        self.config = config
        self.model = config.model
        self.client = httpx.Client(timeout=config.timeout_seconds, transport=transport)

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        url = str(self.config.base_url).rstrip("/") + "/v1/messages"
        started = time.perf_counter()
        response = post_json(self.client, url, headers={
            "x-api-key": self.config.api_key.get_secret_value(),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }, payload={"model": self.config.model, "system": request.system,
                 "messages": [{"role": "user", "content": request.user}],
                 "temperature": request.temperature, "max_tokens": request.max_tokens},
            max_retries=self.config.max_retries)
        body = response.json()
        text = "".join(block.get("text", "") for block in body["content"] if block.get("type") == "text")
        return TeacherResponse(provider_request_id=body.get("id"), provider="anthropic",
                               model=self.config.model, text=text,
                               usage={k: int(v) for k, v in body.get("usage", {}).items() if isinstance(v, int)},
                               latency_ms=(time.perf_counter() - started) * 1000)
```

```python
# src/egsi/teacher/cache.py
import hashlib
import json
import os
from pathlib import Path

from .base import Teacher, TeacherRequest, TeacherResponse


def request_cache_key(provider: str, model: str, request: TeacherRequest) -> str:
    raw = json.dumps({"provider": provider, "model": model, "request": request.model_dump(mode="json")},
                     sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def cache_path(root: Path, key: str) -> Path:
    return root / (key.removeprefix("sha256:") + ".json")


def read_cache(root: Path, key: str) -> TeacherResponse | None:
    path = cache_path(root, key)
    if not path.exists():
        return None
    return TeacherResponse.model_validate_json(path.read_text(encoding="utf-8")).model_copy(update={"cached": True})


def write_cache(root: Path, key: str, value: TeacherResponse) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    target = cache_path(root, key)
    temporary = target.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(value.model_dump_json() + "\n", encoding="utf-8")
    temporary.replace(target)
    return target


class CachedTeacher:
    def __init__(self, inner: Teacher, root: Path):
        self.inner, self.root = inner, root
        self.provider, self.model = inner.provider, inner.model

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        key = request_cache_key(self.provider, self.model, request)
        if cached := read_cache(self.root, key):
            return cached
        response = self.inner.generate(request)
        write_cache(self.root, key, response)
        return response
```

```python
# src/egsi/teacher/__init__.py
from .anthropic import AnthropicTeacher
from .base import Teacher, TeacherRequest, TeacherResponse
from .cache import CachedTeacher
from .openai_compatible import OpenAICompatibleTeacher

__all__ = ["AnthropicTeacher", "CachedTeacher", "OpenAICompatibleTeacher",
           "Teacher", "TeacherRequest", "TeacherResponse"]
```

- [ ] **Step 4: Run teacher tests**

Run: `python -m pytest tests/teacher -q`

Expected: `3 passed`; no assertion/log contains the test API key outside the outbound authorization header, and the second identical request is served from cache.

- [ ] **Step 5: Commit teacher transport**

```bash
git add src/egsi/teacher tests/teacher
git commit -m "feat: add structured teacher adapters and request cache"
```

### Task 6: Read Pinned Source Files Safely From Bare Git Caches

**Files:**
- Create: `src/egsi/data/__init__.py`
- Create: `src/egsi/data/git_objects.py`
- Create: `tests/data/test_git_objects.py`

- [ ] **Step 1: Write a test using a temporary bare Git repository**

```python
# tests/data/test_git_objects.py
import subprocess
from pathlib import Path

import pytest

from egsi.data.git_objects import GitObjectStore


def run(*args: str, cwd: Path) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def test_show_pinned_file_and_reject_traversal(tmp_path: Path) -> None:
    work = tmp_path / "work"; work.mkdir()
    run("git", "init", "-q", cwd=work)
    run("git", "config", "user.email", "test@example.test", cwd=work)
    run("git", "config", "user.name", "Test", cwd=work)
    (work / "A.java").write_text("class A {}\n")
    run("git", "add", "A.java", cwd=work); run("git", "commit", "-qm", "one", cwd=work)
    commit = run("git", "rev-parse", "HEAD", cwd=work)
    bare = tmp_path / "repo.git"; run("git", "clone", "-q", "--bare", str(work), str(bare), cwd=tmp_path)
    store = GitObjectStore(bare)
    assert store.read_text(commit, "A.java") == "class A {}\n"
    with pytest.raises(ValueError):
        store.read_text(commit, "../secret")
```

- [ ] **Step 2: Run and verify missing Git reader failure**

Run: `python -m pytest tests/data/test_git_objects.py -q`

Expected: FAIL importing `egsi.data.git_objects`.

- [ ] **Step 3: Implement safe `git cat-file/show` access**

```python
# src/egsi/data/git_objects.py
from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath


class GitObjectStore:
    def __init__(self, git_dir: Path):
        if not git_dir.is_dir():
            raise FileNotFoundError(git_dir)
        self.git_dir = git_dir

    @staticmethod
    def validate_path(path: str) -> str:
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or ".." in parsed.parts or not parsed.parts:
            raise ValueError(f"unsafe repository path: {path}")
        return parsed.as_posix()

    def _git(self, *args: str) -> bytes:
        return subprocess.check_output(["git", f"--git-dir={self.git_dir}", *args], stderr=subprocess.STDOUT)

    def contains(self, commit: str, path: str) -> bool:
        safe = self.validate_path(path)
        result = subprocess.run(["git", f"--git-dir={self.git_dir}", "cat-file", "-e", f"{commit}:{safe}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    def read_bytes(self, commit: str, path: str, max_bytes: int = 1_000_000) -> bytes:
        safe = self.validate_path(path)
        data = self._git("show", f"{commit}:{safe}")
        if len(data) > max_bytes:
            raise ValueError(f"repository object exceeds {max_bytes} bytes: {safe}")
        return data

    def read_text(self, commit: str, path: str, max_bytes: int = 1_000_000) -> str:
        return self.read_bytes(commit, path, max_bytes).decode("utf-8", errors="replace")
```

```python
# src/egsi/data/__init__.py
from .git_objects import GitObjectStore

__all__ = ["GitObjectStore"]
```

- [ ] **Step 4: Run Git object tests**

Run: `python -m pytest tests/data/test_git_objects.py -q`

Expected: `1 passed`.

- [ ] **Step 5: Commit Git object reader**

```bash
git add src/egsi/data tests/data/test_git_objects.py
git commit -m "feat: read bounded files from pinned Git objects"
```

### Task 7: Build a Bounded, Hashable Oracle Context

**Files:**
- Create: `src/egsi/data/context.py`
- Create: `tests/data/test_context.py`

- [ ] **Step 1: Write tests for bounds, content hash, and required sources**

```python
# tests/data/test_context.py
from pathlib import Path

from egsi.contracts.case import load_case_catalog
from egsi.data.context import build_oracle_context


def test_real_case_context_is_bounded_and_hashable() -> None:
    case = load_case_catalog(Path("data/catalog/cases.jsonl"))[0]
    context = build_oracle_context(Path.cwd(), case, total_chars=64_000)
    assert context.case_id == case.case_id
    assert context.patch
    assert context.advisory
    assert len(context.render()) <= 64_000
    assert context.sha256.startswith("sha256:")
```

- [ ] **Step 2: Run and verify missing context builder failure**

Run: `python -m pytest tests/data/test_context.py -q`

Expected: FAIL importing `egsi.data.context`.

- [ ] **Step 3: Implement deterministic context assembly**

```python
# src/egsi/data/context.py
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from egsi.contracts.case import CaseManifest
from .git_objects import GitObjectStore


class OracleContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    repository: str
    vulnerable_commit: str
    family: str
    cwe: str
    advisory: str
    patch: str
    source_files: dict[str, str]
    sha256: str

    def render(self) -> str:
        return json.dumps(self.model_dump(exclude={"sha256"}), sort_keys=True, ensure_ascii=False)


def bounded(text: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    marker = "\n...[deterministically truncated]...\n"
    if limit <= len(marker):
        return marker[:limit]
    left = (limit - len(marker)) // 2
    right = limit - len(marker) - left
    return text[:left] + marker + text[-right:]


def build_oracle_context(root: Path, case: CaseManifest, total_chars: int = 64_000) -> OracleContext:
    oracle = json.loads((root / case.views.oracle_view_path).read_text(encoding="utf-8"))
    manifest = json.loads((root / case.artifacts.manifest_path).read_text(encoding="utf-8"))
    cache = root / manifest["resolution"]["cache_path"]
    store = GitObjectStore(cache)
    advisory = bounded((root / oracle["advisory_path"]).read_text(encoding="utf-8"), 12_000)
    patch = bounded((root / oracle["patch_path"]).read_text(encoding="utf-8"), 24_000)
    remaining = max(0, total_chars - len(advisory) - len(patch) - 4_000)
    locations = [item["path"] for item in case.affected_locations if item.get("path")]
    per_file = min(16_000, remaining // max(1, len(locations)))
    sources = {path: bounded(store.read_text(case.repository.vulnerable_commit, path), per_file)
               for path in sorted(set(locations)) if store.contains(case.repository.vulnerable_commit, path)}
    body = {"case_id": case.case_id, "repository": case.repository.upstream_id,
            "vulnerable_commit": case.repository.vulnerable_commit,
            "family": case.family, "cwe": case.cwe_normalized_primary,
            "advisory": advisory, "patch": patch, "source_files": sources}
    rendered = json.dumps(body, sort_keys=True, ensure_ascii=False)
    while len(rendered) > total_chars and sources:
        path = max(sources, key=lambda item: len(sources[item]))
        excess = len(rendered) - total_chars
        old = sources[path]
        sources[path] = bounded(old, max(0, len(old) - excess - 128))
        if sources[path] == old:
            del sources[path]
        rendered = json.dumps(body, sort_keys=True, ensure_ascii=False)
    if len(rendered) > total_chars:
        raise ValueError(f"oracle context metadata exceeds total_chars={total_chars}")
    digest = "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return OracleContext(**body, sha256=digest)
```

- [ ] **Step 4: Run bounded-context tests**

Run: `python -m pytest tests/data/test_context.py -q`

Expected: `1 passed`.

- [ ] **Step 5: Commit context construction**

```bash
git add src/egsi/data/context.py tests/data/test_context.py
git commit -m "feat: build bounded oracle contexts from patches and source"
```

### Task 8: Generate and Validate Teacher Enrichments

**Files:**
- Create: `src/egsi/teacher/prompts.py`
- Create: `src/egsi/generation/__init__.py`
- Create: `src/egsi/generation/enrichment.py`
- Create: `tests/generation/test_enrichment.py`

- [ ] **Step 1: Write tests for exact JSON parsing, repair count, path validation, and atomic output**

```python
# tests/generation/test_enrichment.py
import json
from pathlib import Path

from egsi.contracts.case import load_case_catalog
from egsi.generation.enrichment import EnrichmentRunner
from egsi.teacher.base import TeacherRequest, TeacherResponse


class SequenceTeacher:
    def __init__(self, responses: list[str]): self.responses = iter(responses); self.calls = 0
    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        return TeacherResponse(provider_request_id=str(self.calls), provider="mock", model="mock-1",
                               text=next(self.responses), usage={})


def payload(case_family: str, path: str) -> str:
    return json.dumps({"family": case_family, "hypothesis": "inspect the patch-grounded security path",
        "locations": [{"path": path, "symbol": None, "start_line": None, "end_line": None, "role": "guard"}],
        "obligations": [{"obligation_id": "O-1", "kind": "guard", "description": "establish guard", "status": "unknown"}],
        "trace": [{"step_id": "S-1", "goal": "CHECK_GUARD_OR_SANITIZER", "operation": "find_guard",
                   "target_kind": "path", "target_id": path, "target_location": path,
                   "resolves_unknowns": ["O-1"], "expected_evidence_type": "source_location",
                   "tool_class": "repository_index", "reason_tags": ["patch_grounded"]}],
        "authorization": None, "limitations": []})


def test_repair_once_then_write_valid_record(tmp_path: Path) -> None:
    case = load_case_catalog(Path("data/catalog/cases.jsonl"))[0]
    path = case.affected_locations[0]["path"]
    teacher = SequenceTeacher(["not-json", payload(case.family, path)])
    runner = EnrichmentRunner(Path.cwd(), teacher, max_repairs=2)
    record = runner.run(case, tmp_path)
    assert teacher.calls == 2
    assert record.validation.valid
    assert (tmp_path / f"{case.case_id}.json").exists()


def test_semantically_invalid_output_is_quarantined_not_positive(tmp_path: Path) -> None:
    case = load_case_catalog(Path("data/catalog/cases.jsonl"))[0]
    teacher = SequenceTeacher([payload(case.family, "does/not/exist.java")] * 3)
    with pytest.raises(ValueError, match="remained invalid"):
        EnrichmentRunner(Path.cwd(), teacher, max_repairs=2).run(case, tmp_path)
    assert not (tmp_path / f"{case.case_id}.json").exists()
    assert (tmp_path / "failures" / f"{case.case_id}.json").exists()
```

- [ ] **Step 2: Run and verify missing enrichment service**

Run: `python -m pytest tests/generation/test_enrichment.py -q`

Expected: FAIL importing `egsi.generation.enrichment`.

- [ ] **Step 3: Implement deterministic prompts and enrichment runner**

```python
# src/egsi/teacher/prompts.py
import json

from egsi.contracts.enrichment import EnrichmentPayload
from egsi.data.context import OracleContext

SYSTEM = """You reconstruct patch-grounded Java Web audit labels. Return one JSON object matching the supplied schema. You may emit hypotheses, unknown proof obligations, locations, and typed trace steps. Never emit facts, rewards, certificates, exploit success, shell commands, or markdown."""

PROOF_TEMPLATES = {
    "source_to_sink": [
        "establish an externally influenced source",
        "establish a path from source to security-sensitive sink",
        "check the required sanitizer or validation invariant",
        "keep runtime impact unknown at T1",
    ],
    "authorization": [
        "identify attacker and victim principals",
        "identify the action and protected resource",
        "state the expected subject-resource relation",
        "locate the actual guard and keep runtime impact unknown at T1",
    ],
}


def enrichment_request(context: OracleContext, repair_error: str | None = None) -> tuple[str, str, dict]:
    schema = EnrichmentPayload.model_json_schema()
    user = json.dumps({"task": "Recover the minimal investigation trace justified by this oracle-only context.",
                       "context": json.loads(context.render()),
                       "proof_template": PROOF_TEMPLATES[context.family], "schema": schema,
                       "repair_error": repair_error}, ensure_ascii=False, sort_keys=True)
    return SYSTEM, user, schema
```

```python
# src/egsi/generation/enrichment.py
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import EnrichmentPayload, EnrichmentRecord, EnrichmentValidation
from egsi.data.context import build_oracle_context
from egsi.data.git_objects import GitObjectStore
from egsi.teacher.base import Teacher, TeacherRequest
from egsi.teacher.prompts import enrichment_request


def allowed_action_values(root: Path) -> dict[str, set[str]]:
    schema = json.loads((root / "idea-stage/ACTION_DSL.schema.json").read_text())
    return {
        "goals": set(schema["properties"]["goal"]["enum"]),
        "operations": set(schema["properties"]["operation"]["enum"]),
        "target_kinds": set(schema["$defs"]["target"]["properties"]["kind"]["enum"]),
        "tool_classes": set(schema["properties"]["tool_class"]["enum"]),
    }


def validate_payload(case: CaseManifest, payload: EnrichmentPayload, store: GitObjectStore,
                     vocabulary: dict[str, set[str]]) -> EnrichmentValidation:
    def exists_at_either_revision(path: str) -> bool:
        return store.contains(case.repository.vulnerable_commit, path) or store.contains(case.repository.fixed_commit, path)

    invalid_locations = sorted({loc.path for loc in payload.locations if not exists_at_either_revision(loc.path)})
    invalid_trace_locations = sorted({
        step.target_id for step in payload.trace
        if step.target_kind == "path" and not store.contains(case.repository.vulnerable_commit, step.target_id)
    })
    invalid_goals = sorted({step.goal for step in payload.trace if step.goal not in vocabulary["goals"]})
    invalid_operations = sorted({step.operation for step in payload.trace if step.operation not in vocabulary["operations"]})
    invalid_kinds = sorted({step.target_kind for step in payload.trace if step.target_kind not in vocabulary["target_kinds"]})
    invalid_tools = sorted({step.tool_class for step in payload.trace if step.tool_class not in vocabulary["tool_classes"]})
    family_mismatch = payload.family != case.family
    invalid = family_mismatch or any((invalid_locations, invalid_trace_locations, invalid_goals,
                                      invalid_operations, invalid_kinds, invalid_tools))
    return EnrichmentValidation(valid=not invalid, family_mismatch=family_mismatch,
                                invalid_locations=invalid_locations,
                                invalid_trace_locations=invalid_trace_locations,
                                invalid_goals=invalid_goals,
                                invalid_operations=invalid_operations,
                                invalid_target_kinds=invalid_kinds,
                                invalid_tool_classes=invalid_tools)


def write_failure(output_dir: Path, case_id: str, attempts: int, error: str,
                  validation: EnrichmentValidation | None) -> None:
    target = output_dir / "failures" / f"{case_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    value = {"schema_version": "1.0", "case_id": case_id, "attempts": attempts,
             "error": error[:2000], "validation": validation.model_dump() if validation else None,
             "positive_transition_written": False}
    temporary = target.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(target)


class EnrichmentRunner:
    def __init__(self, root: Path, teacher: Teacher, max_repairs: int = 2):
        self.root, self.teacher, self.max_repairs = root, teacher, max_repairs

    def run(self, case: CaseManifest, output_dir: Path) -> EnrichmentRecord:
        context = build_oracle_context(self.root, case)
        manifest = json.loads((self.root / case.artifacts.manifest_path).read_text())
        store = GitObjectStore(self.root / manifest["resolution"]["cache_path"])
        vocabulary = allowed_action_values(self.root)
        prompt_error: str | None = None
        payload: EnrichmentPayload | None = None
        validation: EnrichmentValidation | None = None
        last_validation: EnrichmentValidation | None = None
        response = None
        prompt_sha = ""
        attempts = 0
        for attempts in range(1, self.max_repairs + 2):
            system, user, schema = enrichment_request(context, prompt_error)
            prompt_sha = "sha256:" + hashlib.sha256((system + user).encode()).hexdigest()
            try:
                response = self.teacher.generate(TeacherRequest(system=system, user=user, schema=schema))
                raw = json.loads(response.text)
                payload = EnrichmentPayload.model_validate(raw)
                validation = validate_payload(case, payload, store, vocabulary)
                last_validation = validation
                if not validation.valid:
                    raise ValueError(validation.model_dump_json())
                break
            except Exception as exc:
                prompt_error = f"{type(exc).__name__}: {str(exc)[:1800]}"
                payload = None
                validation = None
        if payload is None or response is None or validation is None:
            error = f"teacher output remained invalid after {attempts} attempts: {prompt_error}"
            write_failure(output_dir, case.case_id, attempts, error, last_validation)
            raise ValueError(error)
        record = EnrichmentRecord(case_id=case.case_id, provider=response.provider, model=response.model,
                                  provider_request_id=response.provider_request_id,
                                  prompt_sha256=prompt_sha, source_context_sha256=context.sha256,
                                  temperature=0.0, max_tokens=8192,
                                  latency_ms=response.latency_ms, usage=response.usage,
                                  structured_output_valid=True,
                                  payload=payload, validation=validation)
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / f"{case.case_id}.json"; temp = target.with_suffix(f".tmp.{os.getpid()}")
        temp.write_text(record.model_dump_json(indent=2) + "\n"); temp.replace(target)
        return record
```

```python
# src/egsi/generation/__init__.py
from .enrichment import EnrichmentRunner

__all__ = ["EnrichmentRunner"]
```

- [ ] **Step 4: Run enrichment tests**

Run: `python -m pytest tests/generation/test_enrichment.py -q`

Expected: `2 passed`.

- [ ] **Step 5: Commit enrichment runner**

```bash
git add src/egsi/teacher/prompts.py src/egsi/generation tests/generation/test_enrichment.py
git commit -m "feat: generate and validate patch-grounded enrichments"
```

### Task 9: Redact Oracle Labels Into Policy-Facing Seeds

**Files:**
- Create: `src/egsi/generation/redaction.py`
- Create: `tests/generation/test_redaction.py`

- [ ] **Step 1: Write leakage and hash-link tests**

```python
# tests/generation/test_redaction.py
import json
from pathlib import Path

from egsi.contracts.case import load_case_catalog
from egsi.generation.redaction import FORBIDDEN_KEYS, build_policy_seed


def all_keys(value):
    if isinstance(value, dict):
        return set(value) | set().union(*(all_keys(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(all_keys(v) for v in value), set())
    return set()


def test_policy_seed_contains_no_oracle_fields() -> None:
    case = load_case_catalog(Path("data/catalog/cases.jsonl"))[0]
    seed, manifest = build_policy_seed(case)
    assert not (all_keys(seed) & FORBIDDEN_KEYS)
    assert manifest["policy_sha256"].startswith("sha256:")
    assert manifest["forbidden_key_hits"] == []
```

- [ ] **Step 2: Run and verify missing redaction module**

Run: `python -m pytest tests/generation/test_redaction.py -q`

Expected: FAIL importing `egsi.generation.redaction`.

- [ ] **Step 3: Implement recursive leakage scan and policy seed**

```python
# src/egsi/generation/redaction.py
import hashlib
import json
from typing import Any

from egsi.contracts.case import CaseManifest

FORBIDDEN_KEYS = {"cwe", "cwe_normalized_primary", "aliases", "advisory", "fixed_commit", "patch",
                  "gold_locations", "gold_proof_obligations", "authorization_model", "authorization"}


def key_hits(value: Any) -> set[str]:
    if isinstance(value, dict):
        return (set(value) & FORBIDDEN_KEYS) | set().union(*(key_hits(v) for v in value.values()), set())
    if isinstance(value, list):
        return set().union(*(key_hits(v) for v in value), set())
    return set()


def sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_policy_seed(case: CaseManifest) -> tuple[dict[str, Any], dict[str, Any]]:
    seed = {"schema_version": "1.0", "case_id": case.case_id, "state": "BOOTSTRAP",
            "repository": {"upstream_id": case.repository.upstream_id,
                           "vulnerable_commit": case.repository.vulnerable_commit},
            "budget": {"seconds": 900, "tool_calls": 20, "tokens": 16000, "analysis_units": 20.0},
            "bounded_history": [], "unknowns": ["entrypoint", "security_invariant", "guard", "impact"]}
    hits = sorted(key_hits(seed))
    if hits:
        raise ValueError(f"policy seed contains oracle keys: {hits}")
    return seed, {"schema_version": "1.0", "case_id": case.case_id,
                  "policy_sha256": sha(seed), "forbidden_key_hits": hits,
                  "forbidden_keys": sorted(FORBIDDEN_KEYS)}
```

- [ ] **Step 4: Run redaction tests**

Run: `python -m pytest tests/generation/test_redaction.py -q`

Expected: `1 passed`.

- [ ] **Step 5: Commit redaction gate**

```bash
git add src/egsi/generation/redaction.py tests/generation/test_redaction.py
git commit -m "feat: enforce oracle policy redaction boundary"
```

### Task 10: Compile Trace Steps Into Legal Candidate Sets

**Files:**
- Create: `src/egsi/generation/candidates.py`
- Create: `tests/generation/test_candidates.py`

- [ ] **Step 1: Write candidate-membership, schema, mask, and cap tests**

```python
# tests/generation/test_candidates.py
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from egsi.contracts.enrichment import TraceStep
from egsi.generation.candidates import compile_candidates


def test_selected_action_is_legal_schema_valid_candidate() -> None:
    step = TraceStep(step_id="S-1", goal="CHECK_GUARD_OR_SANITIZER", operation="find_guard",
                     target_kind="path", target_id="src/A.java", target_location="src/A.java",
                     resolves_unknowns=["O-1"], expected_evidence_type="source_location",
                     tool_class="repository_index", reason_tags=[])
    actions, mask, selected = compile_candidates("case-1", "episode-1", "branch-1", step)
    schema = json.loads(Path("idea-stage/ACTION_DSL.schema.json").read_text())
    validator = Draft202012Validator(schema)
    for action, legal in zip(actions, mask, strict=True):
        assert legal is (not list(validator.iter_errors(action)))
    validator.validate(selected)
    assert selected in actions
    assert mask[actions.index(selected)] is True
    assert sum(mask) >= 4
    assert len(actions) <= 64
```

- [ ] **Step 2: Run and verify missing candidate compiler**

Run: `python -m pytest tests/generation/test_candidates.py -q`

Expected: FAIL importing `egsi.generation.candidates`.

- [ ] **Step 3: Implement deterministic action binding and alternatives**

```python
# src/egsi/generation/candidates.py
import hashlib
import json
from copy import deepcopy

from egsi.contracts.enrichment import TraceStep

from pathlib import Path

from jsonschema import Draft202012Validator


OPERATION_PROFILE = {
    "find_source": ("ESTABLISH_ATTACKER_CONTROL", "repository_index", None),
    "find_sink": ("ESTABLISH_IMPACT", "repository_index", None),
    "trace_flow": ("ESTABLISH_REACHABILITY", "graph_query", None),
    "find_guard": ("CHECK_GUARD_OR_SANITIZER", "repository_index", None),
    "find_sanitizer": ("CHECK_GUARD_OR_SANITIZER", "repository_index", None),
    "trace_identity": ("CHECK_SECURITY_INVARIANT", "graph_query", None),
    "check_auth_relation": ("CHECK_SECURITY_INVARIANT", "semantic_model", ("resource", "security-resource")),
    "check_ownership": ("CHECK_SECURITY_INVARIANT", "semantic_model", ("resource", "security-resource")),
    "compare_peer": ("FALSIFY_HYPOTHESIS", "repository_index", None),
    "falsify_hypothesis": ("FALSIFY_HYPOTHESIS", "semantic_model", ("hypothesis", "H-1")),
    "backtrack": ("CONTROL_SEARCH", "control_only", ("checkpoint", "initial")),
    "terminate": ("CONTROL_SEARCH", "control_only", ("episode", None)),
}

ALTERNATIVES = tuple(OPERATION_PROFILE)


def action_id(episode_id: str, operation: str, target_id: str) -> str:
    digest = hashlib.sha256(f"{episode_id}\0{operation}\0{target_id}".encode()).hexdigest()[:16]
    return f"A-{digest}"


def make_action(episode_id: str, branch_id: str, step: TraceStep, operation: str) -> dict:
    if operation == step.operation:
        goal, tool_class = step.goal, step.tool_class
        target_kind, target_id = step.target_kind, step.target_id
        target_override = None
    else:
        goal, tool_class, target_override = OPERATION_PROFILE[operation]
        target_kind, target_id = step.target_kind, step.target_id
        if target_override is not None:
            target_kind, target_id = target_override
            if target_id is None:
                target_id = episode_id
    expected = step.expected_evidence_type
    if operation in {"backtrack", "terminate"}:
        expected = "control_decision"
    action = {"schema_version": "1.0", "action_id": action_id(episode_id, operation, target_id),
              "episode_id": episode_id, "branch_id": branch_id, "actor_role": "policy_selector",
              "hypothesis_id": "H-1", "obligation_id": step.resolves_unknowns[0] if step.resolves_unknowns else None,
              "goal": goal,
              "operation": operation, "target": {"kind": target_kind, "id": target_id,
              "location": step.target_location if target_override is None else None, "version": None}, "arguments": {},
              "resolves_unknowns": step.resolves_unknowns if operation == step.operation else [],
              "preconditions": [], "expected_evidence_type": expected,
              "tool_class": tool_class,
              "budget_cap": {"seconds": 120.0, "tool_calls": 1, "tokens": 2000, "analysis_units": 1.0},
              "fallback_operations": [], "idempotency_key": "sha256:" + hashlib.sha256(
                  json.dumps([episode_id, branch_id, operation, target_id], separators=(",", ":")).encode()).hexdigest(),
              "metadata": {"label_scope": "patch_grounded_bc"}}
    return action


def compile_candidates(case_id: str, episode_id: str, branch_id: str, step: TraceStep) -> tuple[list[dict], list[bool], dict]:
    operations = [step.operation] + [op for op in ALTERNATIVES if op != step.operation]
    actions = [make_action(episode_id, branch_id, step, op) for op in operations[:64]]
    selected = actions[0]
    schema = json.loads(Path("idea-stage/ACTION_DSL.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    legal_mask = [not list(validator.iter_errors(action)) for action in actions]
    if not legal_mask[0]:
        errors = [error.message for error in validator.iter_errors(selected)]
        raise ValueError(f"teacher-selected action is not legal Action DSL: {errors}")
    return actions, legal_mask, deepcopy(selected)
```

- [ ] **Step 4: Run Action DSL candidate tests**

Run: `python -m pytest tests/generation/test_candidates.py -q`

Expected: `1 passed`.

- [ ] **Step 5: Commit candidate compiler**

```bash
git add src/egsi/generation/candidates.py tests/generation/test_candidates.py
git commit -m "feat: compile legal T1 candidate action sets"
```

### Task 11: Compile, Persist, and Replay Honest T1 Episodes

**Files:**
- Create: `src/egsi/generation/trajectory.py`
- Create: `src/egsi/generation/replay.py`
- Create: `tests/generation/test_trajectory_compile.py`
- Create: `tests/generation/test_replay.py`
- Create: `tests/fixtures/enrichment-valid.json`

- [ ] **Step 1: Write zero-reward compilation and tamper-detection tests**

```python
# tests/generation/test_trajectory_compile.py
import json
from pathlib import Path

from egsi.contracts.case import load_case_catalog
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.generation.trajectory import compile_t1_episode


def test_compile_t1_has_no_terminal_reward(tmp_path: Path) -> None:
    record = EnrichmentRecord.model_validate_json((Path("tests/fixtures/enrichment-valid.json")).read_text())
    case = next(item for item in load_case_catalog(Path("data/catalog/cases.jsonl"))
                if item.case_id == record.case_id)
    transitions, events = compile_t1_episode(case, record)
    assert transitions
    assert all(t.reward_vector.terminal == 0 for t in transitions)
    assert all(t.verifier_decision.label_scope == "patch_grounded_bc" for t in transitions)
    assert all(sum(t.legal_mask) >= 4 for t in transitions)
    assert events[-1].event_type == "EPISODE_CLOSED"
    assert events[-1].payload["dynamic_verdict"] == "not_applicable"
```

```python
# tests/generation/test_replay.py
from pathlib import Path

import pytest

from egsi.contracts.case import load_case_catalog
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.generation.replay import replay_events
from egsi.generation.trajectory import compile_t1_episode


def test_replay_rejects_broken_hash_chain() -> None:
    record = EnrichmentRecord.model_validate_json(Path("tests/fixtures/enrichment-valid.json").read_text())
    case = next(item for item in load_case_catalog(Path("data/catalog/cases.jsonl"))
                if item.case_id == record.case_id)
    _, events = compile_t1_episode(case, record)
    data = [event.model_copy(deep=True) for event in events]
    data[1].previous_event_sha256 = "sha256:bad"
    with pytest.raises(ValueError, match="hash chain"):
        replay_events(data)
```

```json
{
  "schema_version": "1.0",
  "case_id": "ghsa-2m8h-fgr8-2q9w",
  "provider": "fixture",
  "model": "fixture-v1",
  "provider_request_id": "fixture-1",
  "prompt_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "source_context_sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "temperature": 0.0,
  "max_tokens": 8192,
  "latency_ms": 0.0,
  "usage": {},
  "structured_output_valid": true,
  "payload": {
    "family": "source_to_sink",
    "hypothesis": "A request-controlled path may reach resource lookup without a complete traversal guard.",
    "locations": [
      {
        "path": "spring-webmvc/src/main/java/org/springframework/web/servlet/ResourceServlet.java",
        "symbol": null,
        "start_line": null,
        "end_line": null,
        "role": "guard"
      }
    ],
    "obligations": [
      {
        "obligation_id": "O-1",
        "kind": "guard",
        "description": "Establish whether traversal segments are rejected before resource lookup.",
        "status": "unknown"
      }
    ],
    "trace": [
      {
        "step_id": "S-1",
        "goal": "CHECK_GUARD_OR_SANITIZER",
        "operation": "find_guard",
        "target_kind": "path",
        "target_id": "spring-webmvc/src/main/java/org/springframework/web/servlet/ResourceServlet.java",
        "target_location": "spring-webmvc/src/main/java/org/springframework/web/servlet/ResourceServlet.java",
        "resolves_unknowns": ["O-1"],
        "expected_evidence_type": "source_location",
        "tool_class": "repository_index",
        "reason_tags": ["patch_grounded"]
      }
    ],
    "authorization": null,
    "limitations": ["No build, test, or PoC evidence is asserted at T1."]
  },
  "validation": {
    "valid": true,
    "family_mismatch": false,
    "invalid_locations": [],
    "invalid_trace_locations": [],
    "invalid_goals": [],
    "invalid_operations": [],
    "invalid_target_kinds": [],
    "invalid_tool_classes": []
  }
}
```

- [ ] **Step 2: Run and verify missing compiler/replay failures**

Run: `python -m pytest tests/generation/test_trajectory_compile.py tests/generation/test_replay.py -q`

Expected: FAIL importing trajectory/replay modules.

- [ ] **Step 3: Implement event hashing, transition compilation, JSONL, and Parquet writers**

```python
# src/egsi/generation/trajectory.py
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from egsi.contracts.case import CaseManifest
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.contracts.trajectory import EpisodeEvent, RewardVector, T1Transition, VerifierDecision
from .candidates import compile_candidates
from .redaction import build_policy_seed


def event_hash(sequence: int, episode_id: str, event_type: str, payload: dict, previous: str | None) -> str:
    raw = json.dumps({"sequence": sequence, "episode_id": episode_id, "event_type": event_type,
                      "payload": payload, "previous_event_sha256": previous}, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def make_event(sequence: int, episode_id: str, event_type: str, payload: dict, previous: str | None) -> EpisodeEvent:
    return EpisodeEvent(sequence=sequence, episode_id=episode_id, event_type=event_type, payload=payload,
                        previous_event_sha256=previous,
                        event_sha256=event_hash(sequence, episode_id, event_type, payload, previous))


def compile_t1_episode(case: CaseManifest, enrichment: EnrichmentRecord) -> tuple[list[T1Transition], list[EpisodeEvent]]:
    if enrichment.case_id != case.case_id:
        raise ValueError("enrichment case_id does not match case manifest")
    if not enrichment.validation.valid:
        raise ValueError("invalid enrichment cannot produce a positive T1 transition")
    episode_id = f"EP-{case.case_id}-{enrichment.prompt_sha256[-12:]}"
    seed, redaction_manifest = build_policy_seed(case)
    events = [make_event(0, episode_id, "EPISODE_STARTED", {"policy_seed": seed,
              "redaction": redaction_manifest}, None)]
    events.append(make_event(1, episode_id, "HYPOTHESIS_CREATED", {"hypothesis_id": "H-1",
                  "label_scope": "patch_grounded_bc"}, events[-1].event_sha256))
    transitions: list[T1Transition] = []
    state = dict(seed); state["state"] = "SELECT_ACTION"; state["hypothesis_id"] = "H-1"
    for index, step in enumerate(enrichment.payload.trace):
        actions, mask, selected = compile_candidates(case.case_id, episode_id, "B-1", step)
        events.append(make_event(len(events), episode_id, "ACTION_PROPOSED", {"actions": actions}, events[-1].event_sha256))
        events.append(make_event(len(events), episode_id, "ACTION_SELECTED", {"action_id": selected["action_id"]}, events[-1].event_sha256))
        transition = T1Transition(episode_id=episode_id, state_version=index, state=state,
            candidate_actions=actions, legal_mask=mask, selected_action=selected,
            observation={"type": "oracle_label_only", "label_scope": "patch_grounded_bc", "receipt": None},
            evidence_delta={"facts": [], "claims": [], "resolved_unknowns": []},
            verifier_decision=VerifierDecision(accepted=enrichment.validation.valid,
                label_scope="patch_grounded_bc", checks=["schema", "location", "action_dsl", "redaction"]),
            reward_vector=RewardVector(label_scope="patch_grounded_bc"), next_state_version=index + 1,
            done=index == len(enrichment.payload.trace) - 1)
        transitions.append(transition)
        events.append(make_event(len(events), episode_id, "PATCH_GROUNDED_LABEL_RECORDED",
                      {"state_version": index, "action_id": selected["action_id"]}, events[-1].event_sha256))
        state = {**state, "last_action_id": selected["action_id"], "state_version": index + 1}
    events.append(make_event(len(events), episode_id, "EPISODE_CLOSED",
                  {"outcome": "LABEL_SEQUENCE_COMPLETE", "dynamic_verdict": "not_applicable"}, events[-1].event_sha256))
    return transitions, events


def write_jsonl(path: Path, values: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    temporary.write_text("".join(value.model_dump_json() + "\n" for value in values), encoding="utf-8")
    temporary.replace(path)


def write_parquet(path: Path, transitions: list[T1Transition]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(item.model_dump_json()) for item in transitions]
    temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    pq.write_table(pa.Table.from_pylist(rows), temporary, compression="zstd")
    temporary.replace(path)
```

```python
# src/egsi/generation/replay.py
from egsi.contracts.trajectory import EpisodeEvent
from .trajectory import event_hash


def replay_events(events: list[EpisodeEvent]) -> dict:
    previous = None
    state = {"closed": False, "selected_actions": []}
    for expected_sequence, event in enumerate(events):
        if event.sequence != expected_sequence:
            raise ValueError("non-consecutive event sequence")
        if event.previous_event_sha256 != previous:
            raise ValueError("broken event hash chain")
        want = event_hash(event.sequence, event.episode_id, event.event_type, event.payload, previous)
        if event.event_sha256 != want:
            raise ValueError("invalid event content hash")
        if event.event_type == "ACTION_SELECTED":
            state["selected_actions"].append(event.payload["action_id"])
        if event.event_type == "EPISODE_CLOSED":
            state["closed"] = True
        previous = event.event_sha256
    if not state["closed"]:
        raise ValueError("episode is not closed")
    return state
```

- [ ] **Step 4: Add the exact valid fixture and run compile/replay tests**

Run: `python -m pytest tests/generation/test_trajectory_compile.py tests/generation/test_replay.py -q`

Expected: all tests PASS. Inspect the generated transition and confirm every reward component is `0.0` and `dynamic_verdict` is absent from transitions or `not_applicable` in the closing event.

- [ ] **Step 5: Commit trajectory compiler and replay**

```bash
git add src/egsi/generation/trajectory.py src/egsi/generation/replay.py tests/generation tests/fixtures/enrichment-valid.json
git commit -m "feat: compile replayable zero-reward T1 trajectories"
```

### Task 12: Add Working Single-Case CLI Commands and Batch Result Contracts

**Files:**
- Create: `src/egsi/cli.py`
- Create: `src/egsi/generation/batch.py`
- Create: `tests/test_cli.py`
- Create: `tests/generation/test_batch.py`

- [ ] **Step 1: Write CLI help, dry-run, and per-case failure tests**

```python
# tests/test_cli.py
from typer.testing import CliRunner

from egsi.cli import app


def test_cli_exposes_phase_a_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ["validate-catalog", "show-context", "enrich"]:
        assert command in result.stdout
```

```python
# tests/generation/test_batch.py
from egsi.generation.batch import BatchResult


def test_batch_result_keeps_failures() -> None:
    result = BatchResult(processed=["a"], failed={"b": "invalid JSON"})
    assert result.processed == ["a"]
    assert result.failed == {"b": "invalid JSON"}
```

- [ ] **Step 2: Run and verify missing CLI/batch modules**

Run: `python -m pytest tests/test_cli.py tests/generation/test_batch.py -q`

Expected: FAIL importing `egsi.cli` or `egsi.generation.batch`.

- [ ] **Step 3: Implement CLI and batch result contracts**

```python
# src/egsi/generation/batch.py
from pydantic import BaseModel, ConfigDict, Field


class BatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    processed: list[str] = Field(default_factory=list)
    failed: dict[str, str] = Field(default_factory=dict)
```

```python
# src/egsi/cli.py
from __future__ import annotations

import json
from pathlib import Path

import typer

from egsi.config.providers import load_provider_config
from egsi.contracts.case import load_case_catalog
from egsi.data.context import build_oracle_context
from egsi.teacher.anthropic import AnthropicTeacher
from egsi.teacher.cache import CachedTeacher
from egsi.teacher.openai_compatible import OpenAICompatibleTeacher

app = typer.Typer(no_args_is_help=True)


def find_case(catalog: Path, case_id: str):
    for case in load_case_catalog(catalog):
        if case.case_id == case_id:
            return case
    raise typer.BadParameter(f"unknown case_id: {case_id}")


@app.command("validate-catalog")
def validate_catalog(catalog: Path = Path("data/catalog/cases.jsonl")) -> None:
    cases = load_case_catalog(catalog)
    typer.echo(json.dumps({"valid": True, "cases": len(cases)}, sort_keys=True))


@app.command("show-context")
def show_context(case_id: str, catalog: Path = Path("data/catalog/cases.jsonl"),
                 root: Path = Path(".")) -> None:
    context = build_oracle_context(root, find_case(catalog, case_id))
    typer.echo(context.render())


def build_teacher(config_path: Path, cache_root: Path):
    registry = load_provider_config(config_path); config = registry.active
    inner = AnthropicTeacher(config) if config.kind == "anthropic" else OpenAICompatibleTeacher(config)
    return CachedTeacher(inner, cache_root)


@app.command("enrich")
def enrich(case_id: str, provider_config: Path, output_root: Path,
           catalog: Path = Path("data/catalog/cases.jsonl"), root: Path = Path("."), dry_run: bool = False) -> None:
    case = find_case(catalog, case_id)
    if dry_run:
        context = build_oracle_context(root, case)
        typer.echo(json.dumps({"case_id": case_id, "context_sha256": context.sha256,
                              "context_chars": len(context.render()), "network_called": False}, sort_keys=True))
        return
    from egsi.generation.enrichment import EnrichmentRunner
    record = EnrichmentRunner(root, build_teacher(provider_config, output_root / "cache/teacher")).run(
        case, output_root / "enrichment")
    typer.echo(record.model_dump_json())


```

- [ ] **Step 4: Run CLI tests and a real dry run**

Run:

```bash
python -m pytest tests/test_cli.py tests/generation/test_batch.py -q
egsi validate-catalog
egsi enrich ghsa-25gv-mvm7-5h3h --provider-config configs/providers.example.toml --output-root .work/p0 --dry-run
```

Expected: tests pass; catalog prints `{"cases": 300, "valid": true}`; dry run prints `network_called=false` and a context hash without exposing an API key.

- [ ] **Step 5: Commit CLI surface**

```bash
git add src/egsi/cli.py src/egsi/generation/batch.py tests/test_cli.py tests/generation/test_batch.py
git commit -m "feat: expose Phase A validation and enrichment CLI"
```

### Task 13: Run P0/P1 as Restartable Batches and Emit Honest Reports

**Files:**
- Create: `configs/p0_cases.txt`
- Create: `configs/p1_cases.txt`
- Create: `src/egsi/teacher/fixture.py`
- Create: `src/egsi/generation/pilot.py`
- Modify: `src/egsi/cli.py`
- Create: `tests/generation/test_pilot.py`
- Create: `tests/integration/test_phase_a.py`
- Create: `scripts/validate_collected_cases_readonly.py`
- Modify: `data/README.md` only after accepted outputs are copied to writable `data/derived`
- Modify: `MANIFEST.md` after P0/P1 artifacts exist

- [ ] **Step 1: Pin the ten-case P0 and deterministic thirty-case P1 lists**

```text
# configs/p0_cases.txt
ghsa-2m8h-fgr8-2q9w
ghsa-3wfj-vh84-732p
ghsa-2j4q-9fff-236j
ghsa-25gv-mvm7-5h3h
ghsa-3hrc-f439-727g
ghsa-2h63-qp69-fwvw
ghsa-268v-2qq7-84pf
ghsa-2hfj-jv6q-762v
ghsa-2hw2-62cp-p9p7
ghsa-3297-944x-j7x7
```

`configs/p1_cases.txt` contains exactly three train cases for each A-family CWE and four train cases for each B-family CWE: 18 source-to-sink cases, 12 authorization cases, and 30 distinct upstream repositories.

```text
# configs/p1_cases.txt
ghsa-2m8h-fgr8-2q9w
ghsa-2q4p-f6gf-mqr5
ghsa-32xf-jwmv-9hf3
ghsa-3wfj-vh84-732p
ghsa-4m7p-55jm-3vwv
ghsa-4qw8-pgpr-p9mq
ghsa-2j4q-9fff-236j
ghsa-3p62-6fjh-3p5h
ghsa-3pqg-4rqg-pg9g
ghsa-25gv-mvm7-5h3h
ghsa-2chv-87wj-pjv2
ghsa-4rjf-mxfm-98h5
ghsa-3hrc-f439-727g
ghsa-4jx2-hvqw-93j9
ghsa-4rj6-9pjh-882r
ghsa-2h63-qp69-fwvw
ghsa-3p8v-w8mr-m3x8
ghsa-3v67-545x-ffc3
ghsa-268v-2qq7-84pf
ghsa-2hfj-jv6q-762v
ghsa-5993-wwpg-m92c
ghsa-76v2-48w6-crxr
ghsa-2hw2-62cp-p9p7
ghsa-3g4c-hjhr-73rj
ghsa-3hg6-c7f8-3348
ghsa-5wm5-8q42-rhxg
ghsa-3297-944x-j7x7
ghsa-32mf-57h2-64x9
ghsa-3jq8-jg75-rqv6
ghsa-3w85-5p9g-h334
```

- [ ] **Step 2: Write offline pilot and restart tests using a deterministic fixture teacher**

```python
# tests/integration/test_phase_a.py
from pathlib import Path
from collections import Counter

from egsi.contracts.case import load_case_catalog
from egsi.generation.pilot import read_case_ids, run_pilot
from egsi.teacher.fixture import FixtureTeacher


def test_offline_p0_produces_valid_report(tmp_path: Path) -> None:
    report = run_pilot(root=Path.cwd(), case_ids=read_case_ids(Path("configs/p0_cases.txt")),
                       output_root=tmp_path, teacher=FixtureTeacher())
    assert report["requested"] == 10
    assert report["processed"] + report["failed"] == 10
    assert report["policy_oracle_leakage"] == 0
    assert report["nonzero_t1_rewards"] == 0
    assert report["selected_illegal_actions"] == 0
    assert (tmp_path / "reports/pilot-summary.json").exists()


def test_p1_case_file_has_frozen_quotas_and_no_time_ood() -> None:
    ids = read_case_ids(Path("configs/p1_cases.txt"))
    catalog = {case.case_id: case for case in load_case_catalog(Path("data/catalog/cases.jsonl"))}
    cases = [catalog[item] for item in ids]
    assert len(cases) == 30
    assert Counter(case.family for case in cases) == {"source_to_sink": 18, "authorization": 12}
    assert Counter(case.cwe_normalized_primary for case in cases) == {
        "CWE-22": 3, "CWE-78": 3, "CWE-79": 3, "CWE-89": 3,
        "CWE-611": 3, "CWE-918": 3, "CWE-639": 4, "CWE-862": 4, "CWE-863": 4,
    }
    assert len({case.repository.upstream_id for case in cases}) == 30
    assert all(case.split == "train" for case in cases)
```

```python
# tests/generation/test_pilot.py
from pathlib import Path

from egsi.generation.pilot import read_case_ids, run_enrichment_batch
from egsi.teacher.fixture import FixtureTeacher


def test_case_file_ignores_comments_and_restart_reuses_valid_record(tmp_path: Path) -> None:
    case_file = tmp_path / "cases.txt"
    case_file.write_text("# one train case\nghsa-2m8h-fgr8-2q9w\n", encoding="utf-8")
    case_ids = read_case_ids(case_file)
    teacher = FixtureTeacher()
    first = run_enrichment_batch(Path.cwd(), case_ids, tmp_path / "out", teacher)
    second = run_enrichment_batch(Path.cwd(), case_ids, tmp_path / "out", teacher)
    assert first["processed"] == 1
    assert second["processed"] == 1
    assert second["cache_reused"] == 1
    assert teacher.calls == 1
```

- [ ] **Step 3: Run and verify missing pilot orchestration**

Run: `python -m pytest tests/integration/test_phase_a.py -q`

Expected: FAIL importing `egsi.generation.pilot` or `egsi.teacher.fixture`.

- [ ] **Step 4: Implement the fixture teacher, restartable enrichment, trajectory compilation, and aggregate validation**

```python
# src/egsi/teacher/fixture.py
import json

from .base import TeacherRequest, TeacherResponse


class FixtureTeacher:
    provider = "fixture"
    model = "fixture-v1"

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, request: TeacherRequest) -> TeacherResponse:
        self.calls += 1
        envelope = json.loads(request.user)
        context = envelope["context"]
        family = context["family"]
        paths = sorted(context["source_files"])
        if not paths:
            raise ValueError("fixture teacher requires at least one vulnerable source path")
        path = paths[0]
        authorization = None
        if family == "authorization":
            operation, goal, target_kind = "check_auth_relation", "CHECK_SECURITY_INVARIANT", "resource"
            evidence_type = "authorization_relation"
            authorization = {
                "attacker_principal": "requesting_user",
                "victim_principal": "resource_owner",
                "action": "access",
                "resource": "target_resource",
                "expected_relation": "requester is authorized for target resource",
                "actual_check": "unknown",
                "observable_impact": "unauthorized resource access",
            }
        else:
            operation, goal, target_kind = "find_guard", "CHECK_GUARD_OR_SANITIZER", "path"
            evidence_type = "source_location"
        payload = {
            "family": family,
            "hypothesis": "Inspect the patch-grounded security path without asserting dynamic confirmation.",
            "locations": [{"path": path, "symbol": None, "start_line": None,
                           "end_line": None, "role": "guard"}],
            "obligations": [{"obligation_id": "O-1", "kind": "security_invariant",
                             "description": "Establish the missing or incomplete security relation.",
                             "status": "unknown"}],
            "trace": [{"step_id": "S-1", "goal": goal, "operation": operation,
                       "target_kind": target_kind, "target_id": path,
                       "target_location": path, "resolves_unknowns": ["O-1"],
                       "expected_evidence_type": evidence_type,
                       "tool_class": "semantic_model" if family == "authorization" else "repository_index",
                       "reason_tags": ["fixture", "patch_grounded"]}],
            "authorization": authorization,
            "limitations": ["Fixture output is for offline contract tests only."],
        }
        return TeacherResponse(provider_request_id=f"fixture-{self.calls}", provider=self.provider,
                               model=self.model, text=json.dumps(payload, sort_keys=True), usage={})
```

```python
# src/egsi/generation/pilot.py
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from egsi.contracts.case import load_case_catalog
from egsi.contracts.enrichment import EnrichmentRecord
from egsi.generation.enrichment import EnrichmentRunner
from egsi.generation.replay import replay_events
from egsi.generation.trajectory import compile_t1_episode, write_jsonl, write_parquet
from egsi.generation.redaction import key_hits
from egsi.teacher.base import Teacher


def read_case_ids(path: Path) -> list[str]:
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            result.append(value)
    if len(result) != len(set(result)):
        raise ValueError(f"duplicate case ID in {path}")
    return result


def catalog_index(root: Path) -> dict[str, object]:
    return {case.case_id: case for case in load_case_catalog(root / "data/catalog/cases.jsonl")}


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_enrichment_batch(root: Path, case_ids: list[str], output_root: Path, teacher: Teacher) -> dict:
    catalog = catalog_index(root)
    processed, failures, reused, records = [], {}, 0, []
    for case_id in case_ids:
        try:
            case = catalog[case_id]
            if case.split == "time_ood_test":
                raise ValueError("P0/P1 cannot consume time_ood_test cases")
            enrichment_path = output_root / "enrichment" / f"{case_id}.json"
            if enrichment_path.exists():
                enrichment = EnrichmentRecord.model_validate_json(enrichment_path.read_text())
                if not enrichment.validation.valid:
                    raise ValueError("cached enrichment is not valid")
                reused += 1
            else:
                enrichment = EnrichmentRunner(root, teacher).run(case, output_root / "enrichment")
            records.append(enrichment)
            processed.append(case_id)
        except Exception as exc:
            failures[case_id] = f"{type(exc).__name__}: {exc}"[:4000]
    families = Counter(catalog[item].family for item in processed)
    cwes = Counter(catalog[item].cwe_normalized_primary for item in processed)
    providers = Counter(record.provider + ":" + record.model for record in records)
    usage = Counter()
    for record in records:
        usage.update(record.usage)
    invalid_location_cases = 0
    for case_id in failures:
        receipt = output_root / "enrichment/failures" / f"{case_id}.json"
        if not receipt.exists():
            continue
        validation = json.loads(receipt.read_text(encoding="utf-8")).get("validation") or {}
        if validation.get("invalid_locations") or validation.get("invalid_trace_locations"):
            invalid_location_cases += 1
    report = {"schema_version": "1.0", "stage": "enrichment", "requested": len(case_ids),
              "processed": len(processed), "failed": len(failures), "cache_reused": reused,
              "processed_case_ids": processed, "failures": failures,
              "structured_parse_rate": len(processed) / len(case_ids) if case_ids else 0.0,
              "family_counts": dict(families), "cwe_counts": dict(cwes),
              "provider_model_counts": dict(providers),
              "prompt_hashes": sorted({record.prompt_sha256 for record in records}),
              "total_latency_ms": sum(record.latency_ms for record in records),
              "usage": dict(usage), "invalid_location_cases": invalid_location_cases,
              "invalid_location_rate": invalid_location_cases / len(case_ids) if case_ids else 0.0}
    write_report(output_root / "reports/enrichment-summary.json", report)
    return report


def compile_trajectory_batch(root: Path, case_ids: list[str], input_root: Path, output_root: Path) -> dict:
    catalog = catalog_index(root)
    processed, failures, transitions_all = [], {}, []
    replay_passed = leakage = nonzero_rewards = illegal_selected = 0
    event_files = []
    for case_id in case_ids:
        try:
            case = catalog[case_id]
            if case.split == "time_ood_test":
                raise ValueError("P0/P1 cannot consume time_ood_test cases")
            enrichment = EnrichmentRecord.model_validate_json((input_root / f"{case_id}.json").read_text())
            transitions, events = compile_t1_episode(case, enrichment)
            replay_events(events)
            replay_passed += 1
            for transition in transitions:
                leakage += len(key_hits({"state": transition.state,
                                         "candidate_actions": transition.candidate_actions,
                                         "observation": transition.observation,
                                         "evidence_delta": transition.evidence_delta}))
                nonzero_rewards += any(value != 0.0 for key, value in transition.reward_vector.model_dump().items()
                                       if key != "label_scope")
                selected_index = transition.candidate_actions.index(transition.selected_action)
                illegal_selected += not transition.legal_mask[selected_index]
            episode_id = transitions[0].episode_id
            event_path = output_root / "episodes" / f"{episode_id}.events.jsonl"
            write_jsonl(event_path, events)
            write_jsonl(output_root / "episodes" / f"{episode_id}.transitions.jsonl", transitions)
            event_files.append(str(event_path.relative_to(output_root)))
            transitions_all.extend(transitions)
            processed.append(case_id)
        except Exception as exc:
            failures[case_id] = f"{type(exc).__name__}: {exc}"[:4000]
    if transitions_all:
        write_parquet(output_root / "trajectories/train.parquet", transitions_all)
    report = {"schema_version": "1.0", "stage": "trajectory", "requested": len(case_ids),
              "processed": len(processed),
              "failed": len(failures), "processed_case_ids": processed, "failures": failures,
              "transitions": len(transitions_all), "event_files": event_files,
              "policy_oracle_leakage": leakage, "nonzero_t1_rewards": nonzero_rewards,
              "selected_illegal_actions": illegal_selected, "event_replay_passed": replay_passed,
              "dynamic_verdict": "not_applicable"}
    write_report(output_root / "reports/trajectory-validation.json", report)
    return report


def run_pilot(root: Path, case_ids: list[str], output_root: Path, teacher: Teacher) -> dict:
    enrichment = run_enrichment_batch(root, case_ids, output_root, teacher)
    trajectory = compile_trajectory_batch(root, case_ids, output_root / "enrichment", output_root)
    report = {**trajectory, "enrichment": enrichment,
              "requested": len(case_ids), "processed": trajectory["processed"],
              "failed": trajectory["failed"]}
    write_report(output_root / "reports/pilot-summary.json", report)
    return report
```

Replace `src/egsi/cli.py` with this complete command surface:

```python
# src/egsi/cli.py
from __future__ import annotations

import json
from pathlib import Path

import typer

from egsi.config.providers import load_provider_config
from egsi.contracts.case import load_case_catalog
from egsi.data.context import build_oracle_context
from egsi.generation.pilot import compile_trajectory_batch, read_case_ids, run_enrichment_batch
from egsi.teacher.anthropic import AnthropicTeacher
from egsi.teacher.cache import CachedTeacher
from egsi.teacher.fixture import FixtureTeacher
from egsi.teacher.openai_compatible import OpenAICompatibleTeacher

app = typer.Typer(no_args_is_help=True)


def find_case(catalog: Path, case_id: str):
    for case in load_case_catalog(catalog):
        if case.case_id == case_id:
            return case
    raise typer.BadParameter(f"unknown case_id: {case_id}")


def build_teacher(config_path: Path | None, cache_root: Path, fixture_teacher: bool = False):
    if fixture_teacher:
        return FixtureTeacher()
    if config_path is None:
        raise typer.BadParameter("--provider-config is required unless --fixture-teacher is set")
    registry = load_provider_config(config_path)
    config = registry.active
    inner = AnthropicTeacher(config) if config.kind == "anthropic" else OpenAICompatibleTeacher(config)
    return CachedTeacher(inner, cache_root)


@app.command("validate-catalog")
def validate_catalog(catalog: Path = Path("data/catalog/cases.jsonl")) -> None:
    cases = load_case_catalog(catalog)
    typer.echo(json.dumps({"valid": True, "cases": len(cases)}, sort_keys=True))


@app.command("show-context")
def show_context(case_id: str, catalog: Path = Path("data/catalog/cases.jsonl"),
                 root: Path = Path(".")) -> None:
    typer.echo(build_oracle_context(root, find_case(catalog, case_id)).render())


@app.command("enrich")
def enrich(case_id: str, output_root: Path, provider_config: Path | None = None,
           catalog: Path = Path("data/catalog/cases.jsonl"), root: Path = Path("."),
           dry_run: bool = False, fixture_teacher: bool = False) -> None:
    case = find_case(catalog, case_id)
    if dry_run:
        context = build_oracle_context(root, case)
        typer.echo(json.dumps({"case_id": case_id, "context_sha256": context.sha256,
                              "context_chars": len(context.render()), "network_called": False}, sort_keys=True))
        return
    report = run_enrichment_batch(root, [case_id], output_root,
                                  build_teacher(provider_config, output_root / "cache/teacher", fixture_teacher))
    typer.echo(json.dumps(report, sort_keys=True))


@app.command("batch-enrich")
def batch_enrich(case_file: Path, output_root: Path, provider_config: Path | None = None,
                 root: Path = Path("."), fixture_teacher: bool = False) -> None:
    report = run_enrichment_batch(root, read_case_ids(case_file), output_root,
                                  build_teacher(provider_config, output_root / "cache/teacher", fixture_teacher))
    typer.echo(json.dumps(report, sort_keys=True))


@app.command("compile-trajectories")
def compile_trajectories(case_file: Path, input_root: Path, output_root: Path,
                         root: Path = Path(".")) -> None:
    report = compile_trajectory_batch(root, read_case_ids(case_file), input_root, output_root)
    invariant_failure = any(report[key] != 0 for key in
                            ("policy_oracle_leakage", "nonzero_t1_rewards", "selected_illegal_actions"))
    typer.echo(json.dumps(report, sort_keys=True))
    if invariant_failure:
        raise typer.Exit(1)
```

- [ ] **Step 5: Run the complete offline suite and P0**

Run:

```bash
python -m pytest -q
egsi batch-enrich --case-file configs/p0_cases.txt --fixture-teacher --output-root .work/p0
egsi compile-trajectories --case-file configs/p0_cases.txt \
  --input-root .work/p0/enrichment --output-root .work/p0
```

Expected:

- all tests pass;
- P0 requests 10 cases;
- `processed + failed = 10`;
- leakage and non-zero T1 reward counts are zero;
- every failure contains an explicit error rather than disappearing;
- event replay passes for every processed case.
- fixture-provider outputs stay under `.work/p0` and are never promoted into the training corpus.

- [ ] **Step 6: Run live-teacher P0 only after creating the real `0600` provider file**

Run:

```bash
install -d -m 700 "$HOME/.config/egsi"
install -m 600 configs/providers.local.toml "$HOME/.config/egsi/providers.toml"
egsi batch-enrich --case-file configs/p0_cases.txt \
  --provider-config "$HOME/.config/egsi/providers.toml" \
  --output-root .work/p0-live
egsi compile-trajectories --case-file configs/p0_cases.txt \
  --input-root .work/p0-live/enrichment --output-root .work/p0-live
```

Expected: `reports/enrichment-summary.json` and `reports/trajectory-validation.json` exist; structured parse rate, failures, provider/model counts, prompt hashes, token usage, and latency are reported. No key appears in `grep -R` over `.work/p0-live`.

- [ ] **Step 7: Review P0, then run the frozen 30-case P1 list from Step 1**

Run:

```bash
sha256sum configs/p1_cases.txt > .work/p1-case-list.sha256
egsi batch-enrich --case-file configs/p1_cases.txt \
  --provider-config "$HOME/.config/egsi/providers.toml" \
  --output-root .work/p1
egsi compile-trajectories --case-file configs/p1_cases.txt \
  --input-root .work/p1/enrichment --output-root .work/p1
python -m pytest tests/integration/test_phase_a.py -q
```

Expected: P1 retains all successes and failures, provides A/B/CWE/provider counts, and does not modify the frozen 40-case Time-OOD set.

- [ ] **Step 8: Copy only accepted outputs when `data/derived` is writable**

Run:

```bash
python - <<'PY'
import hashlib
import shutil
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def promote_tree(source: Path, destination: Path) -> None:
    for item in sorted(source.rglob("*")):
        if not item.is_file():
            continue
        target = destination / item.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if digest(target) != digest(item):
                raise SystemExit(f"refusing to overwrite different content: {target}")
            continue
        shutil.copy2(item, target)
        if digest(target) != digest(item):
            raise SystemExit(f"post-copy hash mismatch: {target}")


promote_tree(Path(".work/p1/enrichment"), Path("data/derived/enrichment"))
promote_tree(Path(".work/p1/episodes"), Path("data/derived/episodes"))
promote_tree(Path(".work/p1/trajectories"), Path("data/derived/trajectories"))
source_report = Path(".work/p1/reports/enrichment-summary.json")
target_report = Path("data/reports/enrichment-p1-summary.json")
target_report.parent.mkdir(parents=True, exist_ok=True)
if target_report.exists() and digest(target_report) != digest(source_report):
    raise SystemExit(f"refusing to overwrite different content: {target_report}")
if not target_report.exists():
    shutil.copy2(source_report, target_report)
assert digest(target_report) == digest(source_report)
PY
```

Expected: destination hashes equal source hashes. Do not use `--delete`; do not overwrite a different existing content hash.

- [ ] **Step 9: Add a repository-owned read-only collection validator wrapper**

```python
# scripts/validate_collected_cases_readonly.py
#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    root = Path.cwd().resolve()
    source_data = root / "data"
    validator = source_data / "scripts/validate_collected_cases.py"
    with tempfile.TemporaryDirectory(prefix="egsi-collection-validation-") as directory:
        shadow_root = Path(directory)
        shadow_data = shadow_root / "data"
        shadow_data.mkdir()
        for child in source_data.iterdir():
            destination = shadow_data / child.name
            if child.name == "reports":
                destination.mkdir()
            else:
                destination.symlink_to(child.resolve(), target_is_directory=child.is_dir())
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source_data / "scripts")
        result = subprocess.run([sys.executable, str(validator)], cwd=shadow_root,
                                env=environment, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
```

Run:

```bash
before=$(sha256sum data/reports/collection-validation.json | cut -d' ' -f1)
python scripts/validate_collected_cases_readonly.py
after=$(sha256sum data/reports/collection-validation.json | cut -d' ' -f1)
test "$before" = "$after"
```

Expected: exit code 0 and JSON output containing `"valid": true` and `"errors": []`; the external `data/reports/collection-validation.json` hash is unchanged.

- [ ] **Step 10: Update documentation and manifest with observed facts only**

Add to `data/README.md`:

- exact P0/P1 requested, processed, and failed counts;
- provider/model and prompt hash, but no API key;
- output paths and hashes;
- statement that all Phase-A trajectories are T1 `patch_grounded_bc` with zero dynamic reward;
- explicit list of deferred T2/T3 work.

Add corresponding versioned/fixed output rows to `MANIFEST.md`.

- [ ] **Step 11: Commit Phase A pilot**

```bash
git add configs/p0_cases.txt configs/p1_cases.txt scripts/validate_collected_cases_readonly.py \
  src/egsi/generation/pilot.py src/egsi/teacher/fixture.py src/egsi/cli.py \
  tests data/README.md MANIFEST.md
git commit -m "feat: deliver P0 P1 patch-grounded trajectory pipeline"
```

## Final Phase-A Verification

Run:

```bash
python -m pytest --cov=egsi --cov-report=term-missing -q
egsi validate-catalog
python data/scripts/validate_catalog.py
python scripts/validate_collected_cases_readonly.py
grep -RInE 'api_key[[:space:]]*=|Bearer[[:space:]]+|x-api-key' \
  .work/p1 data/derived data/reports 2>/dev/null
sha256sum configs/p0_cases.txt configs/p1_cases.txt \
  .work/p1/reports/enrichment-summary.json \
  .work/p1/reports/trajectory-validation.json
```

Expected:

- all unit/integration tests pass;
- both existing catalog validators report valid with zero errors;
- secret scan has no hit containing a real key;
- P1 report is internally consistent;
- all accepted transitions parse as `T1Transition`;
- all rewards are zero and all label scopes are `patch_grounded_bc`;
- every processed episode replays to `closed=True`;
- no Time-OOD case appears in P0/P1.

## Phase-A Completion Record

Create `idea-stage/implementation-plans/2026-08-29-java-web-enrichment-trajectory-p0-p1-results.md` after execution. It must record commands, exact outputs, file hashes, failure cases, observed teacher costs/latency, deviations from this plan, and the decision to proceed, revise, or stop before Phase B.
