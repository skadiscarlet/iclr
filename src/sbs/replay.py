"""Offline fixture replay: INIT → REPRESENT → READ_ALLOWED_EVIDENCE → UPDATE → FINISH/UNRESOLVED."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbs.errors import ReplayConfigError
from sbs.isolation import IsolatedStore, load_case_view
from sbs.schema import (
    AuditState,
    Decision,
    Observation,
    ReplayScript,
    RunManifest,
    SmokeConfig,
    TERMINAL_FINISH,
    TERMINAL_UNRESOLVED,
    canonical_json_bytes,
    parse_smoke_config,
    sha256_bytes,
)
from sbs.scorer import require_scorer_unavailable
from sbs.views import build_views, views_share_evidence


SEMANTIC_MANIFEST_DROP = frozenset({"started_at", "finished_at"})


def load_smoke_config(path: Path) -> SmokeConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    config = parse_smoke_config(payload)
    if config.model_calls_allowed != 0:
        raise ReplayConfigError("model_calls_allowed must be 0")
    if config.compute_detection_metrics:
        raise ReplayConfigError("compute_detection_metrics must be false")
    if config.mode != "fixture_replay":
        raise ReplayConfigError("mode must be fixture_replay")
    require_scorer_unavailable()
    return config


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _apply_update(state: AuditState, update) -> None:
    hypothesis = next(
        item for item in state.hypotheses if item.hypothesis_id == update.hypothesis_id
    )
    for ref in update.add_support:
        if ref not in hypothesis.support_refs:
            hypothesis.support_refs.append(ref)
    for ref in update.add_counter:
        if ref not in hypothesis.counter_refs:
            hypothesis.counter_refs.append(ref)
    for item in update.add_unknowns:
        if item not in hypothesis.unknowns:
            hypothesis.unknowns.append(item)
        if item not in state.unresolved_items:
            state.unresolved_items.append(item)
    for item in update.remove_unknowns:
        hypothesis.unknowns = [u for u in hypothesis.unknowns if u != item]
        state.unresolved_items = [u for u in state.unresolved_items if u != item]
    if update.status is not None:
        hypothesis.status = update.status
    if update.terminal is not None:
        _terminate(state, update.terminal, update.termination_reason)


def _terminate(state: AuditState, terminal: str, reason: str | None) -> None:
    if terminal == TERMINAL_UNRESOLVED and reason == "budget_exhausted":
        if any(h.status == "refuted" for h in state.hypotheses):
            pass
        for hypothesis in state.hypotheses:
            if hypothesis.status in {"supported", "refuted"}:
                hypothesis.status = "unresolved"
    state.terminal = terminal  # type: ignore[assignment]
    state.termination_reason = reason
    hypothesis = state.hypotheses[0]
    if terminal == TERMINAL_UNRESOLVED:
        verdict = "unresolved"
        hypothesis.status = "unresolved"
    elif hypothesis.status == "supported":
        verdict = "supported"
    elif hypothesis.status == "refuted":
        verdict = "refuted"
    else:
        verdict = "unresolved"
        state.terminal = TERMINAL_UNRESOLVED
        if state.termination_reason is None:
            state.termination_reason = "insufficient_material"
    state.decision = Decision(
        verdict=verdict,  # type: ignore[arg-type]
        applies_to_hypothesis_id=hypothesis.hypothesis_id,
        not_a_global_safety_guarantee=True,
    )


def replay_case(
    actor_root: Path,
    config: SmokeConfig,
    *,
    evaluator_root: Path | None = None,
) -> dict[str, Any]:
    require_scorer_unavailable()
    store = IsolatedStore(actor_root, evaluator_root=evaluator_root)
    case = load_case_view(store)
    if case.split != config.split:
        raise ReplayConfigError("case split does not match config split")
    script = ReplayScript.model_validate_json(store.read_text("script.json"))
    if script.script_kind != "fixture_script":
        raise ReplayConfigError("R01 updates must be fixture_script, not model inference")
    state = AuditState(
        observed_evidence=[],
        hypotheses=[script.initial_hypothesis.model_copy(deep=True)],
        unresolved_items=list(script.initial_hypothesis.unknowns),
        remaining_budget=config.max_observations,
        inspection_history=["INIT", "REPRESENT"],
        terminal=None,
        termination_reason=None,
        decision=None,
    )
    observations: list[Observation] = []
    if config.evidence_order != "frozen":
        raise ReplayConfigError("evidence_order must be frozen")
    for evidence_id in script.observation_order:
        if state.terminal is not None:
            break
        if state.remaining_budget <= 0:
            _terminate(state, TERMINAL_UNRESOLVED, "budget_exhausted")
            state.inspection_history.append("UNRESOLVED")
            break
        state.inspection_history.append("READ_ALLOWED_EVIDENCE")
        _record, observation = store.read_evidence(case, evidence_id)
        state.remaining_budget -= 1
        state.observed_evidence.append(evidence_id)
        observations.append(observation)
        state.inspection_history.append("UPDATE")
        update = script.updates.get(evidence_id)
        if update is not None:
            _apply_update(state, update)
    if state.terminal is None:
        if state.remaining_budget <= 0:
            _terminate(state, TERMINAL_UNRESOLVED, "budget_exhausted")
        else:
            _terminate(state, TERMINAL_UNRESOLVED, "insufficient_material")
        state.inspection_history.append(state.terminal or "UNRESOLVED")
    elif state.terminal == TERMINAL_FINISH:
        state.inspection_history.append("FINISH")
    history, sbs = build_views(case, state, observations)
    if not views_share_evidence(history, sbs):
        raise RuntimeError("HistoryView and SBSView diverged")
    if store.evaluator_was_read():
        raise RuntimeError("replay read evaluator data")
    return {
        "case": case,
        "state": state,
        "history": history,
        "sbs": sbs,
        "observations": observations,
        "store": store,
        "script_kind": script.script_kind,
    }


def _semantic_dump(model: Any) -> dict[str, Any]:
    payload = model.model_dump(mode="json")
    for key in SEMANTIC_MANIFEST_DROP:
        payload.pop(key, None)
    return payload


def semantic_outputs(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "history": _semantic_dump(result["history"]),
        "sbs": _semantic_dump(result["sbs"]),
        "state": _semantic_dump(result["state"]),
    }


def material_hash(fixtures_root: Path) -> str:
    parts: list[bytes] = []
    for path in sorted(fixtures_root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(fixtures_root).as_posix()
            parts.append(rel.encode("utf-8"))
            parts.append(path.read_bytes())
    return sha256_bytes(b"\n".join(parts))


def replay_fixtures(
    config: SmokeConfig,
    fixtures_root: Path,
    out_dir: Path,
    *,
    code_sha: str | None = None,
    config_sha256: str | None = None,
    evaluator_root: Path | None = None,
) -> RunManifest:
    started = _now()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_index: dict[str, str] = {}
    terminals: list[str] = []
    for case_dir in sorted(p for p in fixtures_root.iterdir() if p.is_dir()):
        result = replay_case(
            case_dir,
            config,
            evaluator_root=(evaluator_root / case_dir.name)
            if evaluator_root is not None
            else None,
        )
        terminal = result["state"].terminal
        if terminal not in {TERMINAL_FINISH, TERMINAL_UNRESOLVED}:
            raise ReplayConfigError(f"illegal terminal {terminal}")
        terminals.append(str(terminal))
        case_out = out_dir / case_dir.name
        case_out.mkdir(parents=True, exist_ok=True)
        history_path = case_out / "history.json"
        sbs_path = case_out / "sbs.json"
        state_path = case_out / "state.json"
        history_path.write_text(
            result["history"].model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        sbs_path.write_text(
            result["sbs"].model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        state_path.write_text(
            result["state"].model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        output_index[f"{case_dir.name}/history"] = history_path.as_posix()
        output_index[f"{case_dir.name}/sbs"] = sbs_path.as_posix()
        output_index[f"{case_dir.name}/state"] = state_path.as_posix()
    finished = _now()
    cfg_hash = config_sha256 or sha256_bytes(
        canonical_json_bytes(config.model_dump(mode="json"))
    )
    manifest = RunManifest(
        mode=config.mode,
        seed=config.seed,
        split=config.split,
        representations=list(config.representations),
        evidence_order=config.evidence_order,
        max_observations=config.max_observations,
        model_calls=0,
        model_calls_allowed=config.model_calls_allowed,
        compute_detection_metrics=False,
        detection_metrics=None,
        detection_metrics_status="not_evaluated",
        training_loss=None,
        q_accuracy=None,
        value_scorer_available=False,
        code_sha=code_sha,
        config_sha256=cfg_hash,
        material_sha256=material_hash(fixtures_root),
        output_index=output_index,
        exit_status="ok",
        started_at=started,
        finished_at=finished,
    )
    (out_dir / "run_manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def redacted_manifest(manifest: RunManifest) -> dict[str, Any]:
    payload = manifest.model_dump(mode="json")
    # Keep only relative output names; drop absolute host paths if any slipped in.
    payload["output_index"] = {
        key: Path(value).as_posix().replace("\\", "/")
        for key, value in payload["output_index"].items()
    }
    return payload
