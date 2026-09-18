"""Frozen-model pilot: distinct from fixture_replay. Persist request accounting first."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbs.binding import apply_atomic_update
from sbs.errors import BindingError, PilotBudgetError, PilotConfigError
from sbs.isolation import IsolatedStore, assert_real_model_actor_root, load_case_view
from sbs.prompts import RenderedPrompt, compare_final_prompts, render_fair_prompts
from sbs.schema import (
    AuditState,
    EvidenceRef,
    FrozenPilotConfig,
    FrozenPilotManifest,
    Hypothesis,
    LineSpan,
    ModelUpdate,
    VisibleEvidence,
    canonical_json_bytes,
    load_instance_manifest_payload,
    parse_frozen_pilot_config,
    sha256_bytes,
    sha256_text,
)
from sbs.tokens import CharTokenCounter, HuggingFaceTokenCounter, TokenCounter
from sbs.views import visible_from_observation


FINAL_KEYS = (
    "hypothesis",
    "verdict",
    "support_refs",
    "counter_refs",
    "unknowns",
    "limitations",
)
HARD_TOTAL = 192


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_pilot_config(path: Path) -> FrozenPilotConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("task_id") == "R02C":
        raise PilotConfigError("use load_r02c_config / run_r02c_pilot for R02C")
    config = parse_frozen_pilot_config(payload)
    if config.mode != "frozen_model_pilot":
        raise PilotConfigError("mode must be frozen_model_pilot")
    if config.paid_budget_usd != 0:
        raise PilotConfigError("paid_budget_usd must be 0")
    if config.enable_training or config.enable_branch_rollouts:
        raise PilotConfigError("training and branch rollouts are disabled")
    if config.model.get("trust_remote_code") is not False:
        raise PilotConfigError("trust_remote_code must be false")
    caps = config.request_caps
    if caps.get("hard_total") != HARD_TOTAL:
        raise PilotConfigError("hard_total must be 192")
    return config


class RequestLedger:
    def __init__(self, path: Path, hard_total: int = HARD_TOTAL) -> None:
        self.path = Path(path)
        self.hard_total = hard_total
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def entries(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def consumed(self) -> int:
        return len(self.entries())

    def reserve(self, record: dict[str, Any]) -> int:
        current = self.consumed()
        if current >= self.hard_total:
            raise PilotBudgetError("hard request cap reached; budget is not reset on restart")
        payload = dict(record)
        payload["seq"] = current + 1
        payload["reserved_at"] = _now()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return current + 1


def request_ledger_path(workspace: Path, config: FrozenPilotConfig) -> Path:
    """Stable path for the 192-cap ledger. Not a timestamped run directory."""

    relative = Path(config.run_output_root)
    if relative.is_absolute() or ".." in relative.parts:
        raise PilotConfigError("run_output_root must be a relative path without '..'")
    return Path(workspace) / relative.parent / "request_ledger.jsonl"


def open_request_ledger(workspace: Path, config: FrozenPilotConfig) -> RequestLedger:
    """Open the workspace-stable request ledger used by run-pilot restarts."""

    hard_total = int(config.request_caps.get("hard_total", HARD_TOTAL))
    if hard_total != HARD_TOTAL:
        raise PilotConfigError("hard_total must be 192")
    return RequestLedger(request_ledger_path(workspace, config), hard_total=hard_total)


def parse_model_output(raw: str) -> tuple[dict[str, Any] | None, str]:
    """Store illegal JSON as failed. Do not repair semantics."""

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None, "parse_error"
    if not isinstance(obj, dict):
        return None, "parse_error"
    missing = [key for key in FINAL_KEYS if key not in obj]
    if missing:
        return None, "parse_error"
    if obj.get("verdict") not in {"supported", "refuted", "unresolved"}:
        return None, "parse_error"
    return obj, "parsed"


def validate_pilot_manifest(workspace: Path, manifest_path: Path) -> dict[str, Any]:
    """Validate actor packs without calling a model."""

    workspace = Path(workspace)
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if payload.get("task_id") != "R02B":
        raise PilotConfigError("actor manifest task_id must be R02B")
    instances = payload.get("instances") or []
    evaluator_root = workspace / payload.get(
        "evaluator_relative_root", "local_data/r02b/evaluator"
    )
    problems: list[str] = []
    ready = 0
    for row in instances:
        rel = row["relative_root"]
        root = workspace / rel
        try:
            assert_real_model_actor_root(root)
            store = IsolatedStore(root, evaluator_root=evaluator_root)
            case = load_case_view(store)
            man = load_instance_manifest_payload(
                json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            )
            if man.source_revision is None:
                raise PilotConfigError("source_revision=None")
            if case.split != "dev_pilot":
                raise PilotConfigError("split must be dev_pilot")
            from sbs.schema import reject_answer_fields

            reject_answer_fields(case.model_dump(mode="json"))
            for evidence_id in case.allowed_evidence_ids:
                store.read_evidence(
                    case,
                    evidence_id,
                    expected_generation=man.generation_id,
                    expected_instance=man.instance_id,
                    expected_revision=man.source_revision,
                )
            if store.evaluator_was_read():
                raise PilotConfigError("actor path read evaluator root")
            ready += 1
        except Exception as exc:
            problems.append(f"{row.get('instance_id')}: {type(exc).__name__}")
    return {
        "ok": not problems,
        "instances": len(instances),
        "validated": ready,
        "problems": problems,
        "model_called": False,
    }


def _probe_env() -> dict[str, Any]:
    import platform
    import shutil

    info: dict[str, Any] = {
        "python": platform.python_version(),
        "torch": None,
        "transformers": None,
        "cuda": False,
        "gpu_name": None,
    }
    try:
        import torch

        info["torch"] = getattr(torch, "__version__", "present")
        info["cuda"] = bool(torch.cuda.is_available())
        if info["cuda"]:
            info["gpu_name"] = torch.cuda.get_device_name(0)
    except Exception as exc:
        info["torch_error"] = type(exc).__name__
    try:
        import transformers

        info["transformers"] = getattr(transformers, "__version__", "present")
    except Exception as exc:
        info["transformers_error"] = type(exc).__name__
    nvidia = shutil.which("nvidia-smi")
    info["nvidia_smi"] = bool(nvidia)
    return info


def resolve_local_revision(repo_id: str) -> str | None:
    from huggingface_hub import scan_cache_dir

    try:
        cache = scan_cache_dir()
    except Exception:
        return None
    target = repo_id.replace("/", "--")
    for info in cache.repos:
        name = getattr(info, "repo_id", None) or str(getattr(info, "repo_path", ""))
        if repo_id not in str(name) and target not in str(name):
            continue
        revisions = list(getattr(info, "revisions", []) or [])
        for rev in revisions:
            sha = getattr(rev, "commit_hash", None)
            if isinstance(sha, str) and len(sha) >= 7:
                return sha
    hub = Path.home() / ".cache" / "huggingface" / "hub" / f"models--{target}" / "snapshots"
    if hub.is_dir():
        snaps = sorted(p.name for p in hub.iterdir() if p.is_dir())
        if snaps:
            return snaps[-1]
    return None


def lock_model_identity(template: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    repo_id = template.get("model", {}).get("repo_id") or "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    revision = resolve_local_revision(repo_id)
    device = "cpu"
    dtype = "float32"
    if env.get("cuda"):
        device = "cuda"
        dtype = "bfloat16"
        try:
            import torch

            if not torch.cuda.is_bf16_supported():
                dtype = "float16"
        except Exception:
            dtype = "float16"
    locked = dict(template)
    locked["document_kind"] = "locked_runnable_config"
    locked["mode"] = "frozen_model_pilot"
    model = dict(locked.get("model") or {})
    model.update(
        {
            "repo_id": repo_id,
            "resolved_revision": revision,
            "dtype": dtype,
            "device": device,
            "trust_remote_code": False,
            "use_safetensors": True,
        }
    )
    locked["model"] = model
    locked["env_probe"] = {
        "python": env.get("python"),
        "torch": env.get("torch"),
        "transformers": env.get("transformers"),
        "device": device,
        "dtype": dtype,
    }
    return locked


class FrozenModel:
    def __init__(self, repo_id: str, revision: str, device: str, dtype: str) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        torch_dtype = {
            "bfloat16": torch.bfloat16,
            "float16": torch.float16,
            "float32": torch.float32,
        }[dtype]
        self.tokenizer = AutoTokenizer.from_pretrained(
            repo_id,
            revision=revision,
            trust_remote_code=False,
            use_fast=True,
        )
        load_kwargs = dict(
            revision=revision,
            trust_remote_code=False,
            use_safetensors=True,
        )
        try:
            self.model = AutoModelForCausalLM.from_pretrained(
                repo_id, dtype=torch_dtype, **load_kwargs
            )
        except TypeError:
            self.model = AutoModelForCausalLM.from_pretrained(
                repo_id, torch_dtype=torch_dtype, **load_kwargs
            )
        self.device = device
        self.model.to(device)
        self.model.eval()
        self.counter = HuggingFaceTokenCounter(self.tokenizer)

    def generate(self, prompt: str, max_new_tokens: int, seed: int) -> dict[str, Any]:
        import torch

        torch.manual_seed(seed)
        messages = [{"role": "user", "content": prompt}]
        text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(text, return_tensors="pt")
        inputs = {key: value.to(self.device) for key, value in inputs.items()}
        input_len = int(inputs["input_ids"].shape[-1])
        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
            )
        generated = out[0][input_len:]
        raw = self.tokenizer.decode(generated, skip_special_tokens=True)
        return {
            "text": raw,
            "input_tokens": input_len,
            "output_tokens": int(generated.shape[-1]),
            "request_sha256": sha256_text(prompt),
        }

    def generate_chat(
        self,
        messages: list[dict[str, str]],
        max_new_tokens: int,
        seed: int,
        max_input_tokens: int = 3072,
    ) -> dict[str, Any]:
        import torch

        from sbs.tokens import count_chat_tokens

        torch.manual_seed(seed)
        n_ids, ids, method = count_chat_tokens(
            self.tokenizer, messages, add_generation_prompt=True
        )
        attention_mask = None
        try:
            tensor = self.tokenizer.apply_chat_template(
                messages,
                tokenize=True,
                add_generation_prompt=True,
                return_tensors="pt",
            )
            if hasattr(tensor, "keys") and "input_ids" in tensor:
                input_ids = tensor["input_ids"]
                attention_mask = tensor.get("attention_mask") if hasattr(tensor, "get") else tensor["attention_mask"] if "attention_mask" in tensor else None
            elif hasattr(tensor, "to") and hasattr(tensor, "dim"):
                input_ids = tensor
            else:
                input_ids = torch.tensor(ids, dtype=torch.long).unsqueeze(0)
            if hasattr(input_ids, "to"):
                input_ids = input_ids.to(self.device)
            if attention_mask is not None and hasattr(attention_mask, "to"):
                attention_mask = attention_mask.to(self.device)
        except TypeError:
            text = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
            encoded = self.tokenizer(text, return_tensors="pt", add_special_tokens=False)
            input_ids = encoded["input_ids"].to(self.device)
            attention_mask = encoded.get("attention_mask")
            if attention_mask is not None:
                attention_mask = attention_mask.to(self.device)
            method = "template_text_then_encode_no_special"
        if input_ids.dim() == 1:
            input_ids = input_ids.unsqueeze(0)
        input_len = int(input_ids.shape[-1])
        if input_len > max_input_tokens:
            return {
                "text": "",
                "input_tokens": input_len,
                "output_tokens": 0,
                "request_sha256": sha256_text(json.dumps(messages, sort_keys=True)),
                "blocked": "context_insufficient",
                "count_method": method,
            }
        gen_kwargs = {"input_ids": input_ids, "max_new_tokens": max_new_tokens, "do_sample": False}
        if attention_mask is not None:
            gen_kwargs["attention_mask"] = attention_mask
        with torch.no_grad():
            out = self.model.generate(**gen_kwargs)
        generated = out[0][input_len:]
        raw = self.tokenizer.decode(generated, skip_special_tokens=True)
        return {
            "text": raw,
            "input_tokens": input_len,
            "output_tokens": int(generated.shape[-1]),
            "request_sha256": sha256_text(json.dumps(messages, sort_keys=True)),
            "count_method": method,
            "input_token_ids_sha256": sha256_bytes(
                canonical_json_bytes([int(x) for x in input_ids[0].tolist()])
            ),
        }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _visible_after_read(
    store: IsolatedStore,
    case,
    evidence_id: str,
    generation: str,
    instance_id: str,
    revision: str,
) -> VisibleEvidence:
    record, observation = store.read_evidence(
        case,
        evidence_id,
        expected_generation=generation,
        expected_instance=instance_id,
        expected_revision=revision,
    )
    return visible_from_observation(
        instance_id=instance_id,
        observation=observation,
        display_path=record.display_path,
        displayed_span=record.span,
    )


def _refs_from_payload(
    values: Any,
    *,
    instance_id: str,
    generation_id: str,
    default_span: LineSpan | None,
) -> list[EvidenceRef]:
    refs: list[EvidenceRef] = []
    if not isinstance(values, list):
        return refs
    for item in values:
        if isinstance(item, str):
            refs.append(
                EvidenceRef(
                    evidence_id=item,
                    instance_id=instance_id,
                    generation_id=generation_id,
                    span=default_span,
                )
            )
        elif isinstance(item, dict) and "evidence_id" in item:
            span = item.get("span")
            refs.append(
                EvidenceRef(
                    evidence_id=item["evidence_id"],
                    instance_id=item.get("instance_id", instance_id),
                    generation_id=item.get("generation_id", generation_id),
                    span=LineSpan.model_validate(span) if span else default_span,
                )
            )
    return refs


def run_e0_smoke(
    *,
    model: FrozenModel,
    ledger: RequestLedger,
    out_dir: Path,
    seed: int,
    max_new_tokens: int,
    max_requests: int = 8,
) -> dict[str, Any]:
    """Tiny authored citation task. Model output is stored raw; not scripted."""

    out_dir.mkdir(parents=True, exist_ok=True)
    snippet = (
        "class Account {\n"
        "  private final String owner;\n"
        "  Account(String owner) { this.owner = owner; }\n"
        "  String owner() { return owner; }\n"
        "}\n"
    )
    prompt = (
        "Return JSON with keys hypothesis, verdict, support_refs, counter_refs, "
        "unknowns, limitations. verdict must be supported, refuted, or unresolved. "
        "Cite evidence_id ev-e0 if the owner() method returns the constructor argument.\n"
        f"evidence_id=ev-e0\n{snippet}\n"
    )
    results = []
    n = min(2, max_requests)
    for index in range(n):
        seq = ledger.reserve(
            {
                "phase": "E0",
                "index": index,
                "prompt_sha256": sha256_text(prompt),
            }
        )
        started = _now()
        try:
            gen = model.generate(prompt, max_new_tokens=max_new_tokens, seed=seed)
            parsed, status = parse_model_output(gen["text"])
            row = {
                "seq": seq,
                "started_at": started,
                "finished_at": _now(),
                "parse_status": status,
                "input_tokens": gen["input_tokens"],
                "output_tokens": gen["output_tokens"],
                "request_sha256": gen["request_sha256"],
                "raw_sha256": sha256_text(gen["text"]),
                "parsed": parsed,
            }
            raw_path = out_dir / f"e0_{index}.txt"
            raw_path.write_text(gen["text"], encoding="utf-8")
            row["raw_relative"] = raw_path.name
        except Exception as exc:
            row = {
                "seq": seq,
                "started_at": started,
                "finished_at": _now(),
                "parse_status": "failed",
                "error": type(exc).__name__,
            }
        results.append(row)
        _write_json(out_dir / f"e0_{index}.json", row)
    return {"phase": "E0", "requests": len(results), "results": results}


def run_instance_episode(
    *,
    workspace: Path,
    instance_rel: str,
    evaluator_rel: str,
    representation: str,
    model: FrozenModel,
    ledger: RequestLedger,
    out_dir: Path,
    seed: int,
    max_input_tokens: int,
    max_new_tokens: int,
    tokenizer: TokenCounter,
) -> dict[str, Any]:
    actor = workspace / instance_rel
    evaluator = workspace / evaluator_rel
    assert_real_model_actor_root(actor)
    store = IsolatedStore(actor, evaluator_root=evaluator)
    case = load_case_view(store)
    man = load_instance_manifest_payload(
        json.loads((actor / "manifest.json").read_text(encoding="utf-8"))
    )
    instance_id = man.instance_id
    generation = man.generation_id
    observed: dict[str, VisibleEvidence] = {}
    notes = ""
    hypothesis = Hypothesis(
        hypothesis_id="h-primary",
        entities=["unit", "constraint"],
        security_relation="the pinned unit satisfies the implied functional constraint",
        relation_source="model_draft",
        unknowns=["constraint_source"],
        status="open",
    )
    state = AuditState(
        observed_evidence=[],
        hypotheses=[hypothesis],
        unresolved_items=["constraint_source"],
        remaining_budget=4,
        inspection_history=["INIT"],
        terminal=None,
        termination_reason=None,
        decision=None,
    )
    steps = []
    evidence_ids = list(case.allowed_evidence_ids)
    plan = ["form", "read_0", "read_1_or_none", "final"]
    fairness: dict[str, str] = {}
    for step_name in plan:
        if step_name == "read_0" and evidence_ids:
            visible = _visible_after_read(
                store, case, evidence_ids[0], generation, instance_id, man.source_revision
            )
            observed[visible.evidence_id] = visible
            state.observed_evidence.append(visible.evidence_id)
            state.remaining_budget = max(0, state.remaining_budget - 1)
        elif step_name == "read_1_or_none":
            if len(evidence_ids) > 1:
                visible = _visible_after_read(
                    store, case, evidence_ids[1], generation, instance_id, man.source_revision
                )
                observed[visible.evidence_id] = visible
                state.observed_evidence.append(visible.evidence_id)
                state.remaining_budget = max(0, state.remaining_budget - 1)
            else:
                notes = (notes + "\nno_more_material").strip()
        items = list(observed.values())
        history_notes = notes if representation == "history" else notes
        sbs_notes = (
            notes
            if representation == "sbs"
            else notes
        )
        if representation == "sbs":
            sbs_notes = (
                f"{notes}\nstructured: entities={hypothesis.entities} "
                f"relation={hypothesis.security_relation}"
            ).strip()
        else:
            history_notes = (notes + "\nfreeform notes").strip()
        rendered_h, rendered_s = render_fair_prompts(
            visible_context=case.visible_context,
            history_notes=history_notes,
            sbs_notes=sbs_notes,
            evidences=items,
            tokenizer=tokenizer,
            max_input_tokens=max_input_tokens,
        )
        compare_final_prompts(rendered_h, rendered_s)
        chosen = rendered_h if representation == "history" else rendered_s
        fairness[f"{step_name}/evidence"] = chosen.evidence_block_sha256
        if chosen.context_insufficient:
            steps.append(
                {
                    "step": step_name,
                    "status": "context_insufficient",
                    "fairness_sha256": chosen.evidence_block_sha256,
                    "clip_bounds": list(chosen.clip_bounds),
                }
            )
            state.termination_reason = "context_insufficient"
            break
        instruction = (
            "Return JSON with keys hypothesis, verdict, support_refs, "
            "counter_refs, unknowns, limitations. Do not invent evidence IDs."
        )
        prompt = chosen.prompt_bytes.decode("utf-8") + "\n" + instruction
        seq = ledger.reserve(
            {
                "phase": "E1",
                "instance_id": instance_id,
                "representation": representation,
                "step": step_name,
                "prompt_sha256": sha256_text(prompt),
                "evidence_sha256": chosen.evidence_block_sha256,
            }
        )
        started = _now()
        gen = model.generate(prompt, max_new_tokens=max_new_tokens, seed=seed)
        parsed, parse_status = parse_model_output(gen["text"])
        raw_path = out_dir / f"{instance_id}_{representation}_{step_name}.txt"
        raw_path.write_text(gen["text"], encoding="utf-8")
        ref_status = "not_applied"
        if parse_status == "parsed" and parsed is not None and step_name == "final":
            try:
                default_span = items[0].displayed_span if items else None
                update = ModelUpdate(
                    hypothesis_id="h-primary",
                    support_refs=_refs_from_payload(
                        parsed.get("support_refs"),
                        instance_id=instance_id,
                        generation_id=generation,
                        default_span=default_span,
                    ),
                    counter_refs=_refs_from_payload(
                        parsed.get("counter_refs"),
                        instance_id=instance_id,
                        generation_id=generation,
                        default_span=default_span,
                    ),
                    unknowns=list(parsed.get("unknowns") or []),
                    limitations=list(parsed.get("limitations") or []),
                    verdict=parsed.get("verdict"),
                    status=parsed.get("verdict"),
                    hypothesis_text=str(parsed.get("hypothesis")),
                )
                state = apply_atomic_update(
                    state,
                    update,
                    instance_id=instance_id,
                    generation_id=generation,
                    allowed_evidence_ids=list(case.allowed_evidence_ids),
                    observed=observed,
                    remaining_budget=state.remaining_budget,
                    context_insufficient=chosen.context_insufficient,
                )
                ref_status = "applied"
            except BindingError:
                ref_status = "rejected"
        elif parse_status != "parsed":
            ref_status = "parse_error"
        if store.evaluator_was_read():
            raise PilotConfigError("actor path read evaluator root")
        row = {
            "seq": seq,
            "step": step_name,
            "representation": representation,
            "instance_id": instance_id,
            "started_at": started,
            "finished_at": _now(),
            "parse_status": parse_status,
            "ref_status": ref_status,
            "input_tokens": gen["input_tokens"],
            "output_tokens": gen["output_tokens"],
            "request_sha256": gen["request_sha256"],
            "evidence_sha256": chosen.evidence_block_sha256,
            "clip_bounds": list(chosen.clip_bounds),
            "raw_relative": raw_path.name,
            "raw_sha256": sha256_text(gen["text"]),
        }
        steps.append(row)
        if parse_status == "parsed" and parsed is not None and step_name != "final":
            notes = str(parsed.get("hypothesis") or notes)
    return {
        "instance_id": instance_id,
        "representation": representation,
        "steps": steps,
        "fairness": fairness,
        "terminal": state.terminal,
        "decision": None if state.decision is None else state.decision.model_dump(mode="json"),
        "remaining_budget": state.remaining_budget,
    }


def write_run_manifest(
    *,
    out_dir: Path,
    config: FrozenPilotConfig,
    code_sha: str | None,
    requests_attempted: int,
    fairness_hashes: dict[str, str],
    output_index: dict[str, str],
    exit_status: str,
    started: str,
    material_sha: str,
) -> FrozenPilotManifest:
    model = config.model
    manifest = FrozenPilotManifest(
        mode="frozen_model_pilot",
        task_id="R02B",
        seed=config.seed,
        split=config.split,
        representations=list(config.representations),
        model_repo_id=str(model.get("repo_id")),
        model_revision=str(model.get("resolved_revision") or "unresolved"),
        dtype=str(model.get("dtype") or "unresolved"),
        device=str(model.get("device") or "unresolved"),
        trust_remote_code=False,
        model_calls=requests_attempted,
        model_calls_allowed=int(config.request_caps.get("hard_total", HARD_TOTAL)),
        requests_attempted=requests_attempted,
        hard_total=HARD_TOTAL,
        paid_budget_usd=0,
        code_sha=code_sha,
        config_sha256=sha256_bytes(canonical_json_bytes(config.model_dump(mode="json"))),
        material_sha256=material_sha,
        output_index=output_index,
        exit_status=exit_status,
        started_at=started,
        finished_at=_now(),
        fairness_hashes=fairness_hashes,
    )
    (out_dir / "run_manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def run_pilot(
    workspace: Path,
    config_path: Path,
    *,
    code_sha: str | None,
    phase: str = "auto",
) -> dict[str, Any]:
    workspace = Path(workspace)
    peek = json.loads(Path(config_path).read_text(encoding="utf-8"))
    if peek.get("task_id") == "R02C":
        from sbs.r02c_pilot import run_r02c_pilot

        return run_r02c_pilot(workspace, config_path, code_sha=code_sha, phase=phase)
    config = load_pilot_config(config_path)
    actor_manifest_path = workspace / config.actor_manifest_relative_path
    if not actor_manifest_path.is_file():
        raise PilotConfigError("actor manifest missing")
    validation = validate_pilot_manifest(workspace, actor_manifest_path)
    started = _now()
    run_root = workspace / config.run_output_root / started.replace(":", "")
    run_root.mkdir(parents=True, exist_ok=True)
    ledger = open_request_ledger(workspace, config)
    actor_manifest = json.loads(actor_manifest_path.read_text(encoding="utf-8"))
    from sbs.static_check import count_complete_version_pairs

    counts = count_complete_version_pairs(
        workspace / "local_data" / "r02b" / "actor",
        workspace / "local_data" / "r02b" / "evaluator" / "pairs.jsonl",
    )
    complete = int(counts.get("complete_version_pairs") or 0)
    model_spec = config.model
    revision = model_spec.get("resolved_revision")
    if not revision:
        _write_json(
            run_root / "env_block.json",
            {"blocker": "model_revision_unresolved", "model": model_spec},
        )
        return {
            "ok": False,
            "blocked": "model_revision_unresolved",
            "run_dir": str(run_root),
            "complete_version_pairs": complete,
            "validation": validation,
        }
    try:
        model = FrozenModel(
            str(model_spec["repo_id"]),
            str(revision),
            str(model_spec.get("device") or "cpu"),
            str(model_spec.get("dtype") or "float32"),
        )
    except Exception as exc:
        payload = {"blocker": "model_load_failed", "error": type(exc).__name__}
        _write_json(run_root / "env_block.json", payload)
        return {
            "ok": False,
            "blocked": "model_load_failed",
            "error": type(exc).__name__,
            "run_dir": str(run_root),
            "complete_version_pairs": complete,
            "validation": validation,
        }
    tokenizer: TokenCounter = model.counter
    output_index: dict[str, str] = {}
    fairness: dict[str, str] = {}
    e0 = run_e0_smoke(
        model=model,
        ledger=ledger,
        out_dir=run_root / "e0",
        seed=config.seed,
        max_new_tokens=config.max_new_tokens,
        max_requests=int(config.request_caps.get("smoke", 8)),
    )
    output_index["e0"] = (run_root / "e0").as_posix()
    e1: dict[str, Any] | None = None
    if complete < 1:
        e1 = {"blocked": "no_complete_version_pair"}
    elif phase == "e0":
        e1 = {"skipped": "e0_only"}
    else:
        instances = list(actor_manifest.get("instances") or [])[:2]
        episodes = []
        for inst in instances:
            for representation in config.representations:
                ep_dir = run_root / "e1" / inst["instance_id"] / representation
                ep_dir.mkdir(parents=True, exist_ok=True)
                episode = run_instance_episode(
                    workspace=workspace,
                    instance_rel=inst["relative_root"],
                    evaluator_rel=actor_manifest.get(
                        "evaluator_relative_root", "local_data/r02b/evaluator"
                    ),
                    representation=representation,
                    model=model,
                    ledger=ledger,
                    out_dir=ep_dir,
                    seed=config.seed,
                    max_input_tokens=config.max_input_tokens,
                    max_new_tokens=config.max_new_tokens,
                    tokenizer=tokenizer,
                )
                episodes.append(episode)
                fairness.update(
                    {
                        f"{inst['instance_id']}/{representation}/{key}": value
                        for key, value in episode.get("fairness", {}).items()
                    }
                )
        e1 = {"episodes": episodes, "episode_count": len(episodes)}
        output_index["e1"] = (run_root / "e1").as_posix()
    manifest = write_run_manifest(
        out_dir=run_root,
        config=config,
        code_sha=code_sha,
        requests_attempted=ledger.consumed(),
        fairness_hashes=fairness,
        output_index=output_index,
        exit_status="ok" if e1 and "blocked" not in e1 else "partial",
        started=started,
        material_sha=sha256_bytes(
            Path(actor_manifest_path).read_bytes()
        ),
    )
    summary = {
        "ok": True,
        "run_dir": str(run_root),
        "e0": {"requests": e0.get("requests")},
        "e1": e1,
        "requests_attempted": ledger.consumed(),
        "complete_version_pairs": complete,
        "manifest_mode": manifest.mode,
        "validation": validation,
        "request_ledger": ledger.path.as_posix(),
        "ledger_consumed": ledger.consumed(),
    }
    _write_json(run_root / "summary.json", summary)
    snapshot = run_root / "request_ledger.jsonl"
    snapshot.write_bytes(ledger.path.read_bytes())
    return summary
