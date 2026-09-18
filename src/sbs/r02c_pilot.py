"""R02C frozen-pilot runtime: strict contracts, E0 gate, actor-only reads."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from sbs.errors import BindingError, PilotBudgetError, PilotConfigError, RoundCompleteError
from sbs.isolation import IsolatedStore, assert_real_model_actor_root, load_case_view
from sbs.output_contract import parse_response, reference_id_errors
from sbs.pilot import (
    HARD_TOTAL,
    RequestLedger,
    _now,
    _visible_after_read,
    _write_json,
)
from sbs.prompts import compare_final_prompts, render_fair_prompts
from sbs.r02c_prepare import FORBIDDEN_RELATIVE, validate_r02c_manifest
from sbs.r02c_state import (
    PRE_SUCCESS,
    EpisodeMemory,
    apply_history_note,
    apply_r02c_final,
    apply_sbs_card,
    parse_and_check,
)
from sbs.schema import (
    AuditState,
    FrozenPilotManifest,
    Hypothesis,
    R02CPilotConfig,
    VisibleEvidence,
    canonical_json_bytes,
    load_instance_manifest_payload,
    parse_r02c_pilot_config,
    sha256_bytes,
    sha256_text,
)
from sbs.tokens import CharChatTokenCounter, count_chat_tokens


FINAL_POLARITY_TEXT = (
    "Evaluate the failure proposition stated in hypothesis, not the overall safety "
    "of the project. \"supported\" means the supplied evidence supports this specific "
    "requirement-failure proposition. \"refuted\" means supplied counter-evidence "
    "contradicts this specific proposition. \"unresolved\" means the available evidence "
    "does not settle it. Never use true/false, safe/unsafe, yes/no, or numeric labels. "
    "Return one complete JSON object only; all six keys are required. All reference, "
    "unknowns and limitations fields are arrays of strings. Do not invent IDs."
)
HISTORY_FORM_READ_CONTRACT = (
    "Return one complete JSON object only with a single key \"note\": a concise account "
    "of what is known, what changed, and what remains uncertain. Do not include verdict "
    "or extra keys. Do not invent evidence IDs."
)
SBS_FORM_READ_CONTRACT = (
    "Return one complete JSON object only with keys entities, requirement, hypothesis, "
    "support_refs, counter_refs, unknowns, limitations. This object atomically replaces "
    "the live SBS card. unknowns=[] clears previous unknowns. Do not include verdict. "
    "Reference arrays must be strings of already observed evidence IDs. Do not invent IDs."
)
SYSTEM_TEXT = (
    "You inspect one pinned source snapshot. Use only the supplied public evidence. "
    "Do not invent identifiers."
)
TASK_CAP = 48
PROJECT_CAP = 192
WALL_SECONDS = 3600


def contract_instruction(representation: str, step: str) -> tuple[str, str]:
    if step == "final":
        return "final", FINAL_POLARITY_TEXT
    if representation == "sbs":
        return "sbs_note", SBS_FORM_READ_CONTRACT
    return "history_note", HISTORY_FORM_READ_CONTRACT


def load_r02c_config(path: Path) -> R02CPilotConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    config = parse_r02c_pilot_config(payload)
    if config.mode != "frozen_model_pilot":
        raise PilotConfigError("mode must be frozen_model_pilot")
    if config.paid_budget_usd != 0:
        raise PilotConfigError("paid_budget_usd must be 0")
    if config.enable_training or config.enable_branch_rollouts:
        raise PilotConfigError("training and branch rollouts are disabled")
    if config.model.get("trust_remote_code") is not False:
        raise PilotConfigError("trust_remote_code must be false")
    if int(config.project_request_cap) != PROJECT_CAP:
        raise PilotConfigError("project_request_cap must be 192")
    if int(config.task_request_cap) > TASK_CAP:
        raise PilotConfigError("task_request_cap must be <= 48")
    if config.document_kind != "locked_runnable_config":
        raise PilotConfigError("R02C lock must be locked_runnable_config, not a template")
    return config


def load_legacy_consumed(workspace: Path, config: R02CPilotConfig) -> int:
    path = workspace / config.legacy_accounting_snapshot_relative_path
    if not path.is_file():
        return 38
    payload = json.loads(path.read_text(encoding="utf-8"))
    return int(
        payload.get("conservative_consumed_for_new_call_limit")
        or payload.get("reconciled_consumed_upper")
        or 38
    )


def round_status_path(workspace: Path, config: R02CPilotConfig) -> Path:
    return workspace / Path(config.request_ledger_relative_path).parent / "round_status.json"


def open_r02c_ledger(workspace: Path, config: R02CPilotConfig) -> RequestLedger:
    path = workspace / config.request_ledger_relative_path
    return RequestLedger(path, hard_total=PROJECT_CAP)


def reserve_r02c(
    ledger: RequestLedger,
    record: dict[str, Any],
    *,
    legacy: int,
    task_cap: int = TASK_CAP,
    project_cap: int = PROJECT_CAP,
) -> int:
    new = ledger.consumed()
    if new >= task_cap:
        raise PilotBudgetError("R02C new reservation cap 48 reached")
    if legacy + new + 1 > project_cap:
        raise PilotBudgetError("project conservative consumed+reserved cap 192 reached")
    return ledger.reserve(record)


def load_frozen_model(spec: dict[str, Any]) -> Any:
    from sbs.pilot import FrozenModel

    return FrozenModel(
        str(spec["repo_id"]),
        str(spec["resolved_revision"]),
        str(spec.get("device") or "cpu"),
        str(spec.get("dtype") or "float32"),
    )


def tokenizer_of(model: Any):
    tok = getattr(model, "tokenizer", None)
    if tok is not None and hasattr(tok, "apply_chat_template"):
        return tok
    counter = getattr(model, "counter", None)
    if counter is not None and hasattr(counter, "apply_chat_template"):
        return counter
    return CharChatTokenCounter()


def assert_sent_visible_bodies_match(history_meta: dict[str, Any], sbs_meta: dict[str, Any]) -> None:
    """Cross-condition check on the actually sent public body, not unclipped objects."""

    from sbs.errors import FairnessError

    if history_meta.get("visible_body_sha256") != sbs_meta.get("visible_body_sha256"):
        raise FairnessError("sent visible body bytes differ across representations")
    if history_meta.get("visible_body_sha256") is None:
        raise FairnessError("sent visible body hash missing")


def _note_within_budget(notes: str, tokenizer, budget: int) -> tuple[str, bool]:
    if notes == PRE_SUCCESS:
        return notes, False
    if tokenizer.count(notes) <= budget:
        return notes, False
    return notes, True


def _cache_key(
    *,
    model_id: str,
    revision: str,
    generation_id: str,
    instance_id: str,
    representation: str,
    step: str,
    token_ids_sha: str,
) -> str:
    return sha256_text(
        "\n".join(
            [model_id, revision, generation_id, instance_id, representation, step, token_ids_sha]
        )
    )


def invoke_model(
    model: Any,
    messages: list[dict[str, str]],
    *,
    max_new_tokens: int,
    seed: int,
    max_input_tokens: int,
) -> dict[str, Any]:
    tok = tokenizer_of(model)
    n_ids, ids, method = count_chat_tokens(tok, messages, add_generation_prompt=True)
    token_sha = sha256_bytes(canonical_json_bytes(ids))
    if n_ids > max_input_tokens:
        return {
            "blocked": "context_insufficient",
            "text": "",
            "input_tokens": n_ids,
            "output_tokens": 0,
            "count_method": method,
            "input_token_ids_sha256": token_sha,
            "request_sha256": sha256_text(json.dumps(messages, sort_keys=True)),
        }
    if hasattr(model, "generate_chat"):
        gen = model.generate_chat(
            messages,
            max_new_tokens=max_new_tokens,
            seed=seed,
            max_input_tokens=max_input_tokens,
        )
    else:
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
        gen = model.generate(prompt, max_new_tokens, seed)
    gen.setdefault("input_tokens", n_ids)
    gen.setdefault("count_method", method)
    gen.setdefault("input_token_ids_sha256", token_sha)
    return gen


def _logical_generate(
    *,
    model: Any,
    messages: list[dict[str, str]],
    contract: str,
    contract_text: str,
    observed_ids: set[str],
    ledger: RequestLedger,
    legacy: int,
    out_dir: Path,
    stem: str,
    seed: int,
    max_new_tokens: int,
    max_input_tokens: int,
    phase: str,
    meta: dict[str, Any],
    cache: dict[str, dict[str, Any]],
    cache_key: str,
    wall_deadline: float,
) -> dict[str, Any]:
    if time.time() > wall_deadline:
        raise PilotBudgetError("inference wall clock cap reached")
    if cache_key in cache:
        hit = dict(cache[cache_key])
        hit["cached"] = True
        hit["new_reservation"] = False
        return hit

    def _one(msgs: list[dict[str, str]], attempt: str) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        seq = reserve_r02c(
            ledger,
            {
                "phase": phase,
                "attempt": attempt,
                "prompt_sha256": sha256_text(json.dumps(msgs, sort_keys=True)),
                **{k: meta.get(k) for k in ("instance_id", "representation", "step", "case_id")},
            },
            legacy=legacy,
        )
        started = _now()
        raw_path = out_dir / f"{stem}_{attempt}.txt"
        row: dict[str, Any] = {
            "seq": seq,
            "attempt": attempt,
            "started_at": started,
            "cached": False,
            "new_reservation": True,
        }
        try:
            gen = invoke_model(
                model,
                msgs,
                max_new_tokens=max_new_tokens,
                seed=seed,
                max_input_tokens=max_input_tokens,
            )
            raw = gen.get("text") or ""
            raw_path.write_text(raw, encoding="utf-8")
            row.update(
                {
                    "finished_at": _now(),
                    "raw_relative": raw_path.name,
                    "raw_sha256": sha256_text(raw),
                    "input_tokens": gen.get("input_tokens"),
                    "output_tokens": gen.get("output_tokens"),
                    "request_sha256": gen.get("request_sha256"),
                    "input_token_ids_sha256": gen.get("input_token_ids_sha256"),
                    "count_method": gen.get("count_method"),
                    "blocked": gen.get("blocked"),
                }
            )
            if gen.get("blocked"):
                row["schema_valid"] = False
                row["accepted"] = False
                row["error_codes"] = [gen["blocked"]]
                return row
            parsed, extra = parse_and_check(raw, contract, observed_ids=observed_ids)
            row["envelope"] = parsed.envelope
            row["json_status"] = parsed.json_status
            row["schema_status"] = parsed.schema_status
            row["error_codes"] = list(parsed.error_codes) + list(extra)
            row["schema_valid"] = parsed.accepted
            row["reference_valid"] = parsed.accepted and not extra
            row["accepted"] = parsed.accepted and not extra
            row["payload"] = parsed.payload if row["accepted"] else None
            row["public_summary"] = parsed.public_summary()
        except Exception as exc:
            if not raw_path.exists():
                raw_path.write_text("", encoding="utf-8")
            err_path = out_dir / f"{stem}_{attempt}.error.json"
            _write_json(
                err_path,
                {"error": type(exc).__name__, "seq": seq, "attempt": attempt},
            )
            row.update(
                {
                    "finished_at": _now(),
                    "accepted": False,
                    "schema_valid": False,
                    "error": type(exc).__name__,
                    "error_path": err_path.name,
                    "raw_relative": raw_path.name if raw_path.exists() else None,
                }
            )
        return row

    first = _one(messages, "first_attempt")
    if first.get("accepted"):
        cache[cache_key] = first
        first["used_attempt"] = "first_attempt"
        return first
    if first.get("blocked") == "context_insufficient":
        first["used_attempt"] = "first_attempt"
        return first
    repair_user = (
        "Previous output failed the output contract. Error codes: "
        f"{first.get('error_codes')}. Full contract follows. "
        f"{contract_text} Return one complete JSON object only. "
        "Do not copy gold answers; none are provided."
    )
    repair_messages = [
        *messages,
        {"role": "assistant", "content": Path(out_dir / f"{stem}_first_attempt.txt").read_text(encoding="utf-8") if (out_dir / f"{stem}_first_attempt.txt").is_file() else ""},
        {"role": "user", "content": repair_user},
    ]
    second = _one(repair_messages, "schema_reprompt")
    combined = {
        "first_attempt": first,
        "schema_reprompt": second,
        "used_attempt": "schema_reprompt",
        "accepted": bool(second.get("accepted")),
        "payload": second.get("payload"),
        "error_codes": second.get("error_codes"),
        "schema_valid": second.get("schema_valid"),
        "reference_valid": second.get("reference_valid"),
        "raw_sha256": second.get("raw_sha256"),
        "seq": second.get("seq"),
        "cached": False,
        "new_reservation": True,
        "comparable_changed": first.get("raw_sha256") != second.get("raw_sha256"),
    }
    if combined["accepted"]:
        cache[cache_key] = combined
    return combined


def _e0_messages(case: dict[str, Any]) -> tuple[list[dict[str, str]], str, set[str]]:
    contract = case["response_contract"]
    instruction = {
        "history_note": HISTORY_FORM_READ_CONTRACT,
        "sbs_note": SBS_FORM_READ_CONTRACT,
        "final": FINAL_POLARITY_TEXT,
    }[contract]
    evidence_lines = []
    ids: set[str] = set()
    for item in case.get("evidence") or []:
        ids.add(item["evidence_id"])
        evidence_lines.append(
            f"### {item['evidence_id']}\npath: {item.get('display_path')}\n"
            f"{item.get('material')}\n"
        )
    user = (
        f"REQUIREMENT: {case.get('requirement')}\n"
        f"HYPOTHESIS_TO_EVALUATE: {case.get('hypothesis_to_evaluate')}\n"
        f"{case.get('instruction')}\n"
        f"{''.join(evidence_lines)}\n"
        f"{instruction}\n"
    )
    messages = [
        {"role": "system", "content": SYSTEM_TEXT},
        {"role": "user", "content": user},
    ]
    return messages, contract, ids


def run_e0(
    *,
    workspace: Path,
    config: R02CPilotConfig,
    model: Any,
    ledger: RequestLedger,
    legacy: int,
    out_dir: Path,
    cache: dict[str, dict[str, Any]],
    wall_deadline: float,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_path = workspace / config.e0_cases_relative_path
    eval_path = workspace / config.e0_evaluator_relative_path
    cases = [
        json.loads(line)
        for line in cases_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expectations = json.loads(eval_path.read_text(encoding="utf-8"))
    results = []
    first_pass_ok = 0
    after_ok = 0
    finals: dict[str, dict[str, Any]] = {}
    for case in cases:
        messages, contract, ids = _e0_messages(case)
        tok = tokenizer_of(model)
        _n, ids_list, _how = count_chat_tokens(tok, messages, add_generation_prompt=True)
        key = _cache_key(
            model_id=str(config.model.get("repo_id")),
            revision=str(config.model.get("resolved_revision")),
            generation_id="e0",
            instance_id=case["case_id"],
            representation=contract,
            step="e0",
            token_ids_sha=sha256_bytes(canonical_json_bytes(ids_list)),
        )
        row = _logical_generate(
            model=model,
            messages=messages,
            contract=contract,
            contract_text={
                "history_note": HISTORY_FORM_READ_CONTRACT,
                "sbs_note": SBS_FORM_READ_CONTRACT,
                "final": FINAL_POLARITY_TEXT,
            }[contract],
            observed_ids=ids,
            ledger=ledger,
            legacy=legacy,
            out_dir=out_dir,
            stem=case["case_id"],
            seed=config.seed,
            max_new_tokens=config.max_new_tokens,
            max_input_tokens=config.max_input_tokens_including_chat,
            phase="E0",
            meta={"case_id": case["case_id"]},
            cache=cache,
            cache_key=key,
            wall_deadline=wall_deadline,
        )
        first = row.get("first_attempt") or row
        if first.get("accepted") and row.get("used_attempt") == "first_attempt":
            first_pass_ok += 1
            after_ok += 1
        elif row.get("accepted"):
            after_ok += 1
        if contract == "final" and row.get("accepted"):
            finals[case["case_id"]] = row.get("payload") or {}
        results.append(
            {
                "case_id": case["case_id"],
                "contract": contract,
                "accepted": row.get("accepted"),
                "used_attempt": row.get("used_attempt"),
                "error_codes": row.get("error_codes") or first.get("error_codes"),
                "schema_valid": row.get("schema_valid") or first.get("schema_valid"),
                "reference_valid": row.get("reference_valid"),
                "seq": row.get("seq") or first.get("seq"),
            }
        )
        _write_json(out_dir / f"{case['case_id']}.json", row)
    all_schema = all(r.get("accepted") for r in results)
    expected_finals = (expectations.get("expected_final") or {})
    compared = [
        cid
        for cid in expected_finals
        if cid in finals
    ]
    all_wrong = (
        len(compared) == len(expected_finals) == 3
        and all(
            finals[cid].get("verdict") != expected_finals[cid].get("verdict")
            for cid in compared
        )
    )
    if not all_schema:
        gate = "e0_schema_or_refs_failed"
        open_e1 = False
    elif all_wrong:
        gate = "basic_reasoning_probe_failed"
        open_e1 = False
    else:
        gate = "open_e1"
        open_e1 = True
    return {
        "phase": "E0",
        "cases": results,
        "first_pass_valid": first_pass_ok,
        "after_reprompt_valid": after_ok,
        "all_schema_and_refs_valid": all_schema,
        "basic_reasoning_all_wrong": all_wrong,
        "gate": gate,
        "open_e1": open_e1,
        "requests": sum(
            1
            + (1 if (out_dir / f"{c['case_id']}_schema_reprompt.txt").is_file() else 0)
            for c in cases
        ),
    }


def run_instance_episode_r02c(
    *,
    workspace: Path,
    instance_rel: str,
    representation: str,
    model: Any,
    ledger: RequestLedger,
    legacy: int,
    out_dir: Path,
    config: R02CPilotConfig,
    cache: dict[str, dict[str, Any]],
    wall_deadline: float,
    forbidden: list[Path],
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    actor = workspace / instance_rel
    for banned in forbidden:
        try:
            actor.resolve().relative_to(banned.resolve())
        except (ValueError, OSError):
            continue
        else:
            raise PilotConfigError("refusing forbidden evaluator path")
    assert_real_model_actor_root(actor)
    store = IsolatedStore(actor, evaluator_root=None)
    case = load_case_view(store)
    man = load_instance_manifest_payload(
        json.loads((actor / "manifest.json").read_text(encoding="utf-8"))
    )
    instance_id = man.instance_id
    generation = man.generation_id
    observed: dict[str, VisibleEvidence] = {}
    evidence_ids = list(case.allowed_evidence_ids)
    unread = list(evidence_ids)
    memory = EpisodeMemory(representation=representation)  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        hypothesis_id="h-primary",
        entities=["not_initialized"],
        security_relation=PRE_SUCCESS,
        relation_source="not_initialized",
        unknowns=["The applicable requirement has not yet been established."],
        status="open",
    )
    state = AuditState(
        observed_evidence=[],
        hypotheses=[hypothesis],
        unresolved_items=list(hypothesis.unknowns),
        remaining_budget=4,
        inspection_history=["INIT"],
        terminal=None,
        termination_reason=None,
        decision=None,
    )
    # Initial evidence is observed before form so the first request sees source.
    incremental = 0
    if unread:
        vis = _visible_after_read(
            store, case, unread[0], generation, instance_id, man.source_revision
        )
        observed[vis.evidence_id] = vis
        state.observed_evidence.append(vis.evidence_id)
        unread = unread[1:]
    steps: list[dict[str, Any]] = []
    fairness: dict[str, str] = {}
    sent_bodies: dict[str, dict[str, Any]] = {}
    execution_status = "ok"
    model_decision = None
    tokenizer = getattr(model, "counter", None) or CharChatTokenCounter()
    schedule = list(config.frozen_schedule) or ["form", "read_0", "read_1_or_none", "final"]
    for step_name in schedule:
        no_more = False
        if step_name in {"read_0", "read_1_or_none"}:
            if unread:
                vis = _visible_after_read(
                    store, case, unread[0], generation, instance_id, man.source_revision
                )
                if vis.evidence_id in observed:
                    no_more = True
                else:
                    observed[vis.evidence_id] = vis
                    state.observed_evidence.append(vis.evidence_id)
                    unread = unread[1:]
                    incremental += 1
                    state.remaining_budget = max(0, state.remaining_budget - 1)
            else:
                no_more = True
        items = list(observed.values())
        hist_notes = memory.prompt_notes() if representation == "history" else PRE_SUCCESS
        sbs_notes = memory.prompt_notes() if representation == "sbs" else PRE_SUCCESS
        if representation == "history":
            sbs_notes = PRE_SUCCESS
        else:
            hist_notes = PRE_SUCCESS
        # Fair pair: both notes stay within reserve; evidence is shared.
        overflow = False
        if representation == "sbs" and memory.sbs_card is not None:
            serialized = memory.sbs_card.serialize()
            if tokenizer.count(serialized) > config.note_reserve_tokens:
                overflow = True
        h_notes, _, _ = tokenizer.truncate(hist_notes, config.note_reserve_tokens) if representation == "history" else (hist_notes, 0, 0)
        if representation == "history":
            # Keep newest complete notes only: truncate from the start of the joined oldest.
            joined = memory.prompt_notes()
            kept: list[str] = []
            acc = ""
            for note in reversed(memory.history_notes):
                trial = note if not acc else f"{note}\n{acc}"
                if tokenizer.count(trial) <= config.note_reserve_tokens:
                    kept.insert(0, note)
                    acc = trial
                else:
                    break
            h_notes = acc if memory.history_notes else PRE_SUCCESS
        s_notes = sbs_notes
        rendered_h, rendered_s = render_fair_prompts(
            visible_context=case.visible_context,
            history_notes=h_notes if representation == "history" else PRE_SUCCESS,
            sbs_notes=s_notes if representation == "sbs" else PRE_SUCCESS,
            evidences=items,
            tokenizer=tokenizer,
            max_input_tokens=config.max_input_tokens_including_chat,
            note_reserve=config.note_reserve_tokens,
        )
        compare_final_prompts(rendered_h, rendered_s)
        chosen = rendered_h if representation == "history" else rendered_s
        visible_body = chosen.evidence_block_bytes
        visible_sha = sha256_bytes(visible_body)
        sent_meta = {
            "visible_body_sha256": visible_sha,
            "clip_bounds": list(chosen.clip_bounds),
            "context_insufficient": chosen.context_insufficient or overflow,
            "prompt_sha256": chosen.prompt_sha256,
        }
        sent_bodies[representation] = sent_meta
        # Cross-check against the sibling rendering's evidence bytes (same function).
        sibling = rendered_s if representation == "history" else rendered_h
        assert_sent_visible_bodies_match(
            {"visible_body_sha256": sha256_bytes(rendered_h.evidence_block_bytes)},
            {"visible_body_sha256": sha256_bytes(rendered_s.evidence_block_bytes)},
        )
        fairness[f"{step_name}/evidence"] = visible_sha
        contract, instruction = contract_instruction(representation, step_name)
        user = chosen.prompt_bytes.decode("utf-8") + "\n" + instruction
        if no_more:
            user += "\nno_more_material\n"
        if not items:
            raise PilotConfigError("form/read request has no initial source evidence")
        messages = [
            {"role": "system", "content": SYSTEM_TEXT},
            {"role": "user", "content": user},
        ]
        if overflow or chosen.context_insufficient:
            steps.append(
                {
                    "step": step_name,
                    "status": "memory_overflow" if overflow else "context_insufficient",
                    "fairness_sha256": visible_sha,
                    "clip_bounds": list(chosen.clip_bounds),
                    "visible_body_sha256": visible_sha,
                }
            )
            state.termination_reason = "memory_overflow" if overflow else "context_insufficient"
            execution_status = state.termination_reason
            break
        tok = tokenizer_of(model)
        _n, id_list, _how = count_chat_tokens(tok, messages, add_generation_prompt=True)
        if _n > config.max_input_tokens_including_chat:
            steps.append(
                {
                    "step": step_name,
                    "status": "context_insufficient",
                    "input_tokens": _n,
                    "visible_body_sha256": visible_sha,
                    "intercepted_before_generate": True,
                }
            )
            execution_status = "context_insufficient"
            break
        key = _cache_key(
            model_id=str(config.model.get("repo_id")),
            revision=str(config.model.get("resolved_revision")),
            generation_id=generation,
            instance_id=instance_id,
            representation=representation,
            step=step_name,
            token_ids_sha=sha256_bytes(canonical_json_bytes(id_list)),
        )
        pre_hash = memory.pre_hash()
        row = _logical_generate(
            model=model,
            messages=messages,
            contract=contract,
            contract_text=instruction,
            observed_ids=set(observed),
            ledger=ledger,
            legacy=legacy,
            out_dir=out_dir,
            stem=f"{instance_id}_{representation}_{step_name}",
            seed=config.seed,
            max_new_tokens=config.max_new_tokens,
            max_input_tokens=config.max_input_tokens_including_chat,
            phase="E1",
            meta={
                "instance_id": instance_id,
                "representation": representation,
                "step": step_name,
            },
            cache=cache,
            cache_key=key,
            wall_deadline=wall_deadline,
        )
        applied = False
        ref_status = "not_applied"
        payload = row.get("payload")
        try:
            if row.get("accepted") and payload is not None:
                if step_name == "final":
                    state = apply_r02c_final(
                        state,
                        payload,
                        instance_id=instance_id,
                        generation_id=generation,
                        observed=observed,
                        allowed_evidence_ids=list(case.allowed_evidence_ids),
                    )
                    applied = True
                    ref_status = "applied"
                    model_decision = payload.get("verdict")
                elif representation == "history":
                    apply_history_note(memory, payload)
                    applied = True
                    ref_status = "applied"
                else:
                    apply_sbs_card(memory, payload, observed_ids=set(observed))
                    applied = True
                    ref_status = "applied"
                    if memory.sbs_card is not None:
                        hypothesis.entities = list(memory.sbs_card.entities)
                        hypothesis.security_relation = memory.sbs_card.hypothesis
            elif row.get("accepted") is False and not row.get("cached"):
                ref_status = "output_contract_failed"
        except BindingError:
            ref_status = "rejected"
            applied = False
        post_hash = memory.pre_hash()
        step_row = {
            "step": step_name,
            "representation": representation,
            "instance_id": instance_id,
            "accepted": row.get("accepted"),
            "used_attempt": row.get("used_attempt"),
            "schema_valid": row.get("schema_valid"),
            "reference_valid": row.get("reference_valid"),
            "state_applied": applied,
            "ref_status": ref_status,
            "pre_state_hash": pre_hash,
            "post_state_hash": post_hash,
            "visible_body_sha256": visible_sha,
            "prompt_sha256": sha256_text(user),
            "clip_bounds": list(chosen.clip_bounds),
            "no_more_material": no_more,
            "seq": row.get("seq"),
            "raw_sha256": row.get("raw_sha256") or (row.get("first_attempt") or {}).get("raw_sha256"),
            "error_codes": row.get("error_codes"),
            "cached": row.get("cached"),
        }
        steps.append(step_row)
        _write_json(out_dir / f"{step_name}.json", {"generate": row, "step": step_row})
        if ref_status == "output_contract_failed":
            execution_status = "output_contract_failed"
            model_decision = None
            state.terminal = state.terminal or "UNRESOLVED"
            state.termination_reason = "output_contract_failed"
            break
    if execution_status == "ok" and state.decision is None:
        execution_status = "no_valid_final"
        model_decision = None
        state.terminal = "UNRESOLVED"
        state.termination_reason = "no_valid_final"
    return {
        "instance_id": instance_id,
        "representation": representation,
        "generation_id": generation,
        "steps": steps,
        "fairness": fairness,
        "terminal": state.terminal,
        "termination_reason": state.termination_reason,
        "decision": None if state.decision is None else state.decision.model_dump(mode="json"),
        "model_decision": model_decision,
        "execution_status": execution_status,
        "sbs_card": None if memory.sbs_card is None else memory.sbs_card.as_payload(),
        "sbs_revision": None if memory.sbs_card is None else memory.sbs_card.revision,
        "sbs_initialized": memory.sbs_card is not None,
        "history_note_count": len(memory.history_notes),
        "remaining_budget": state.remaining_budget,
        "single_evidence_interface_pilot": len(evidence_ids) <= 1,
        "incremental_evidence_steps": incremental,
        "raw_cards_saved": len(memory.sbs_card_history) + (1 if memory.sbs_card else 0),
    }


def run_r02c_pilot(
    workspace: Path,
    config_path: Path,
    *,
    code_sha: str | None,
    phase: str = "auto",
    model_loader: Callable[[dict[str, Any]], Any] | None = None,
    model: Any | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace)
    config = load_r02c_config(config_path)
    status_path = round_status_path(workspace, config)
    if status_path.is_file():
        prior = json.loads(status_path.read_text(encoding="utf-8"))
        if prior.get("status") == "complete":
            return {
                "ok": False,
                "blocked": "round_already_complete",
                "model_loaded": False,
                "model_called": False,
                "e1": {"generate_count": 0, "skipped": "round_already_complete"},
                "ledger_consumed": open_r02c_ledger(workspace, config).consumed(),
            }
    actor_manifest_path = workspace / config.actor_manifest_relative_path
    if not actor_manifest_path.is_file():
        raise PilotConfigError("actor manifest missing")
    validation = validate_r02c_manifest(workspace, actor_manifest_path)
    if not validation.get("ok"):
        return {
            "ok": False,
            "blocked": "manifest_validation_failed",
            "validation": validation,
            "model_loaded": False,
            "model_called": False,
            "e1": {"generate_count": 0},
        }
    legacy = load_legacy_consumed(workspace, config)
    started = _now()
    wall_deadline = time.time() + int(config.max_inference_wall_seconds or WALL_SECONDS)
    run_root = workspace / config.run_output_root / started.replace(":", "")
    run_root.mkdir(parents=True, exist_ok=True)
    ledger = open_r02c_ledger(workspace, config)
    ledger_before = ledger.consumed()
    actor_manifest = json.loads(actor_manifest_path.read_text(encoding="utf-8"))
    forbidden = [workspace / rel for rel in (actor_manifest.get("forbidden_paths") or FORBIDDEN_RELATIVE)]
    model_spec = config.model
    revision = model_spec.get("resolved_revision")
    if not revision:
        _write_json(run_root / "env_block.json", {"blocker": "model_revision_unresolved"})
        return {
            "ok": False,
            "blocked": "model_revision_unresolved",
            "run_dir": str(run_root),
            "validation": validation,
            "model_loaded": False,
            "model_called": False,
        }
    loader = model_loader or load_frozen_model
    try:
        runtime_model = model if model is not None else loader(model_spec)
    except Exception as exc:
        _write_json(run_root / "env_block.json", {"blocker": "model_load_failed", "error": type(exc).__name__})
        return {
            "ok": False,
            "blocked": "model_load_failed",
            "error": type(exc).__name__,
            "run_dir": str(run_root),
            "validation": validation,
            "model_loaded": False,
            "model_called": False,
        }
    cache: dict[str, dict[str, Any]] = {}
    e0 = run_e0(
        workspace=workspace,
        config=config,
        model=runtime_model,
        ledger=ledger,
        legacy=legacy,
        out_dir=run_root / "e0",
        cache=cache,
        wall_deadline=wall_deadline,
    )
    output_index = {"e0": (run_root / "e0").as_posix()}
    e1: dict[str, Any]
    generate_e1 = 0
    if not e0.get("open_e1") or phase == "e0":
        e1 = {
            "generate_count": 0,
            "skipped": e0.get("gate") if not e0.get("open_e1") else "e0_only",
            "episodes": [],
        }
    else:
        wanted = list(config.frozen_e1_instance_ids)
        instances = [
            inst
            for inst in (actor_manifest.get("instances") or [])
            if inst["instance_id"] in wanted
        ]
        if [i["instance_id"] for i in instances] != wanted and set(i["instance_id"] for i in instances) != set(wanted):
            # Keep management order from the frozen list in the lock.
            order = {iid: n for n, iid in enumerate(wanted)}
            instances.sort(key=lambda row: order.get(row["instance_id"], 99))
        episodes = []
        consecutive_contract_fail = 0
        circuit = False
        for inst in instances:
            for representation in config.representations:
                ep_dir = run_root / "e1" / inst["instance_id"] / representation
                ep_dir.mkdir(parents=True, exist_ok=True)
                before = ledger.consumed()
                episode = run_instance_episode_r02c(
                    workspace=workspace,
                    instance_rel=inst["relative_root"],
                    representation=representation,
                    model=runtime_model,
                    ledger=ledger,
                    legacy=legacy,
                    out_dir=ep_dir,
                    config=config,
                    cache=cache,
                    wall_deadline=wall_deadline,
                    forbidden=forbidden,
                )
                generate_e1 += ledger.consumed() - before
                episodes.append(episode)
                if episode.get("execution_status") == "output_contract_failed":
                    consecutive_contract_fail += 1
                else:
                    consecutive_contract_fail = 0
                if consecutive_contract_fail >= 2:
                    circuit = True
                    break
            if circuit:
                break
        e1 = {
            "episodes": episodes,
            "episode_count": len(episodes),
            "generate_count": generate_e1,
            "circuit_breaker": circuit,
        }
        output_index["e1"] = (run_root / "e1").as_posix()
    ledger_after = ledger.consumed()
    per_run = ledger_after - ledger_before
    fairness: dict[str, str] = {}
    for ep in e1.get("episodes") or []:
        fairness.update(
            {
                f"{ep['instance_id']}/{ep['representation']}/{key}": value
                for key, value in ep.get("fairness", {}).items()
            }
        )
    manifest = FrozenPilotManifest(
        mode="frozen_model_pilot",
        task_id="R02C",
        seed=config.seed,
        split=config.split,
        representations=list(config.representations),
        model_repo_id=str(model_spec.get("repo_id")),
        model_revision=str(revision),
        dtype=str(model_spec.get("dtype") or "float32"),
        device=str(model_spec.get("device") or "cpu"),
        trust_remote_code=False,
        model_calls=per_run,
        model_calls_allowed=int(config.task_request_cap),
        requests_attempted=per_run,
        hard_total=HARD_TOTAL,
        paid_budget_usd=0,
        code_sha=code_sha,
        config_sha256=sha256_bytes(canonical_json_bytes(config.model_dump(mode="json"))),
        material_sha256=sha256_bytes(Path(actor_manifest_path).read_bytes()),
        output_index=output_index,
        exit_status="ok" if e0.get("open_e1") or e1.get("skipped") else "gated",
        started_at=started,
        finished_at=_now(),
        fairness_hashes=fairness,
    )
    (run_root / "run_manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    summary = {
        "ok": True,
        "run_dir": str(run_root),
        "e0": e0,
        "e1": e1,
        "requests_attempted": per_run,
        "ledger_before": ledger_before,
        "ledger_after": ledger_after,
        "ledger_consumed": ledger_after,
        "per_run_attempts": per_run,
        "project_consumed_conservative": legacy + ledger_after,
        "legacy_consumed": legacy,
        "task_reservations": ledger_after,
        "validation": validation,
        "request_ledger": ledger.path.as_posix(),
        "model_loaded": True,
        "model_called": per_run > 0,
        "manifest_mode": manifest.mode,
        "code_sha": code_sha,
        "semantic_metrics": None,
    }
    _write_json(run_root / "summary.json", summary)
    snapshot = run_root / "request_ledger.jsonl"
    snapshot.write_bytes(ledger.path.read_bytes())
    _write_json(
        status_path,
        {"status": "complete", "run_dir": str(run_root), "finished_at": _now()},
    )
    return summary
