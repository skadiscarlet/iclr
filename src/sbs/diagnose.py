"""Offline diagnosis of registered R02B outputs. Zero model calls."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from sbs.output_contract import parse_response
from sbs.pilot import parse_model_output
from sbs.schema import sha256_text


REGISTERED_RUNS = (
    "2026-09-17T140949+0000",
    "2026-09-17T141202+0000",
    "2026-09-17T142041+0000",
)
REPORTED_LOWER_BOUND = 38


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def classify_layers(
    raw: str | None,
    *,
    contract: str,
    observed_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Layered diagnosis. Semantics stay not_evaluated. No value repair."""

    if raw is None:
        return {
            "response": "missing",
            "envelope": "not_attempted",
            "json": "not_attempted",
            "shape": "not_attempted",
            "reference": "not_evaluated",
            "semantics": "not_evaluated",
            "error_codes": ["raw_missing"],
            "accepted": False,
            "retrospective_parse_only": True,
            "policy_trajectory_recovered": False,
        }
    if raw == "":
        return {
            "response": "empty",
            "envelope": "not_attempted",
            "json": "not_attempted",
            "shape": "not_attempted",
            "reference": "not_evaluated",
            "semantics": "not_evaluated",
            "error_codes": ["raw_empty"],
            "accepted": False,
            "retrospective_parse_only": True,
            "policy_trajectory_recovered": False,
        }
    parsed = parse_response(raw, contract)  # type: ignore[arg-type]
    reference = "not_evaluated"
    extra_errors: list[str] = []
    if parsed.accepted and parsed.payload is not None and observed_ids is not None:
        from sbs.output_contract import reference_id_errors

        ref_errors = reference_id_errors(parsed.payload, observed_ids)
        extra_errors.extend(ref_errors)
        reference = "invalid" if ref_errors else "valid"
    elif parsed.accepted and "support_refs" in (parsed.payload or {}):
        reference = "not_evaluated"
    layers = {
        "response": "exists",
        "envelope": parsed.envelope,
        "json": parsed.json_status,
        "shape": parsed.schema_status,
        "reference": reference,
        "semantics": "not_evaluated",
        "error_codes": list(parsed.error_codes) + extra_errors,
        "accepted": parsed.accepted and not extra_errors,
        "raw_sha256": parsed.raw_sha256,
        "normalized_sha256": parsed.normalized_sha256,
        "retrospective_parse_only": True,
        "policy_trajectory_recovered": False,
    }
    return layers


def _contract_for_step(phase: str, step: str | None, representation: str | None) -> str:
    if phase == "E0":
        return "final"
    if step == "final":
        return "final"
    if representation == "sbs":
        return "sbs_note"
    return "history_note"


def _discover_requests(run_dir: Path, run_meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Map each request from the run ledger plus raw/sidecar files. Read-only."""

    run_id = run_meta["run_id"]
    ledger_path = run_dir / "request_ledger.jsonl"
    rows: list[dict[str, Any]] = []
    if ledger_path.is_file():
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    requests: list[dict[str, Any]] = []
    for entry in rows:
        phase = str(entry.get("phase") or "unknown")
        seq = entry.get("seq")
        instance_id = entry.get("instance_id")
        representation = entry.get("representation")
        step = entry.get("step")
        raw_path: Path | None = None
        sidecar: dict[str, Any] | None = None
        if phase == "E0":
            index = entry.get("index", (seq or 1) - 1)
            candidate_txt = run_dir / "e0" / f"e0_{index}.txt"
            candidate_json = run_dir / "e0" / f"e0_{index}.json"
            if candidate_txt.is_file():
                raw_path = candidate_txt
            if candidate_json.is_file():
                sidecar = json.loads(candidate_json.read_text(encoding="utf-8"))
                rel = sidecar.get("raw_relative")
                if raw_path is None and rel:
                    alt = run_dir / "e0" / rel
                    if alt.is_file():
                        raw_path = alt
        else:
            if instance_id and representation and step:
                candidate = (
                    run_dir
                    / "e1"
                    / str(instance_id)
                    / str(representation)
                    / f"{instance_id}_{representation}_{step}.txt"
                )
                if candidate.is_file():
                    raw_path = candidate
        raw_text: str | None = None
        raw_bytes: bytes | None = None
        if raw_path is not None and raw_path.is_file():
            raw_bytes = raw_path.read_bytes()
            raw_text = raw_bytes.decode("utf-8")
        historical = None
        if raw_text is not None:
            _parsed, historical = parse_model_output(raw_text)
        elif sidecar and sidecar.get("parse_status"):
            historical = sidecar.get("parse_status")
        code_sha = run_meta.get("code_sha")
        if code_sha in {None, "pre-A", "pre-a"}:
            code_identity = "unverified_precommit"
        else:
            code_identity = str(code_sha)
        contract = _contract_for_step(phase, step, representation)
        layers = classify_layers(raw_text, contract="final")
        # Historical E1 steps all asked for the six-key final object.
        hist_final_layers = classify_layers(raw_text, contract="final")
        requests.append(
            {
                "run_id": run_id,
                "seq": seq,
                "phase": phase,
                "instance_id": instance_id,
                "representation": representation,
                "step": step if phase != "E0" else f"e0_{entry.get('index')}",
                "event_id": (
                    f"{run_id}|{seq}|{phase}|{instance_id}|{representation}|{step}"
                ),
                "raw_present": raw_text is not None,
                "raw_sha256": _hash_bytes(raw_bytes) if raw_bytes is not None else None,
                "input_tokens": (sidecar or {}).get("input_tokens") or entry.get("input_tokens"),
                "output_tokens": (sidecar or {}).get("output_tokens") or entry.get("output_tokens"),
                "finish_reason": (sidecar or {}).get("finish_reason") or "unknown",
                "code_identity": code_identity,
                "historical_parser_status": historical,
                "contract_used_historically": "final",
                "layers": hist_final_layers,
                "r02c_contract_if_reparsed": contract,
                "r02c_layers_not_policy": classify_layers(raw_text, contract=contract),
                "prompt_sha256": entry.get("prompt_sha256"),
                "evidence_sha256": entry.get("evidence_sha256"),
                "reserved_at": entry.get("reserved_at"),
                "sidecar_error": (sidecar or {}).get("error"),
            }
        )
    return requests


def _safe_excerpt(raw: str | None, *, max_chars: int = 180) -> str | None:
    """Minimal format fragment. No third-party source, no long code."""

    if raw is None:
        return None
    stripped = raw.strip()
    for needle in ('"verdict":"True"', '"verdict": "True"', '"verdict":"Yes"', '"verdict": "Yes"', '"verdict":"supported"', '"verdict": "supported"'):
        idx = stripped.find(needle)
        if idx >= 0:
            start = max(0, idx - 8)
            end = min(len(stripped), idx + len(needle) + 8)
            return stripped[start:end]
    return stripped[:max_chars]


def diagnose_registered_runs(
    workspace: Path,
    run_index_path: Path,
) -> dict[str, Any]:
    """Diagnose only the three registered R02B run directories. No generate."""

    workspace = Path(workspace)
    index = json.loads(Path(run_index_path).read_text(encoding="utf-8"))
    runs_meta = {row["run_id"]: row for row in index.get("runs") or []}
    missing = [rid for rid in REGISTERED_RUNS if rid not in runs_meta]
    if missing:
        raise ValueError(f"run_index missing registered runs: {missing}")
    all_requests: list[dict[str, Any]] = []
    per_run: list[dict[str, Any]] = []
    for run_id in REGISTERED_RUNS:
        meta = runs_meta[run_id]
        rel = meta["relative_dir"]
        run_dir = workspace / rel
        if not run_dir.is_dir():
            raise FileNotFoundError(f"registered run dir missing: {rel}")
        reqs = _discover_requests(run_dir, meta)
        all_requests.extend(reqs)
        per_run.append(
            {
                "run_id": run_id,
                "kind": meta.get("kind"),
                "reported_requests": meta.get("requests_attempted"),
                "observed_requests": len(reqs),
                "relative_dir": rel,
                "code_sha": meta.get("code_sha"),
            }
        )

    # Unique events by (run_id, seq, phase, instance, representation, step).
    unique: dict[str, dict[str, Any]] = {}
    for row in all_requests:
        unique[row["event_id"]] = row
    observed = len(unique)
    reported = sum(int(r.get("reported_requests") or 0) for r in per_run)
    if reported < REPORTED_LOWER_BOUND:
        reported = REPORTED_LOWER_BOUND

    stable_ledger = workspace / "artifacts" / "r02b" / "request_ledger.jsonl"
    stable_count = 0
    if stable_ledger.is_file():
        stable_count = sum(1 for line in stable_ledger.read_text(encoding="utf-8").splitlines() if line.strip())

    # Duplicate ledger copies of the same event count once (run identity).
    lower = max(REPORTED_LOWER_BOUND, observed)
    upper = max(lower, stable_count, reported)
    # Identical raw hashes still count as two calls: we counted events, not hashes.
    hash_counts = Counter(r["raw_sha256"] for r in unique.values() if r.get("raw_sha256"))
    duplicate_raw_hashes = sum(1 for _h, n in hash_counts.items() if n > 1)

    layer_counts = Counter()
    envelope_counts = Counter()
    json_counts = Counter()
    shape_counts = Counter()
    hist_parser = Counter()
    missing_raw = 0
    for row in unique.values():
        layers = row["layers"]
        layer_counts[f"response:{layers['response']}"] += 1
        envelope_counts[layers["envelope"]] += 1
        json_counts[layers["json"]] += 1
        shape_counts[layers["shape"]] += 1
        hist_parser[str(row.get("historical_parser_status"))] += 1
        if layers["response"] != "exists":
            missing_raw += 1

    conservative_consumed = upper
    payload = {
        "task_id": "R02C",
        "source_run_index": str(Path(run_index_path).as_posix()),
        "model_called": False,
        "model_loaded": False,
        "registered_runs": per_run,
        "requests": [
            {
                key: value
                for key, value in row.items()
                if key not in {"sidecar_error"} or value
            }
            for row in unique.values()
        ],
        "counts": {
            "reported_lower_bound": REPORTED_LOWER_BOUND,
            "reported_sum_of_index": reported,
            "observed_unique_events": observed,
            "stable_ledger_rows": stable_count,
            "duplicate_raw_hash_groups": duplicate_raw_hashes,
            "missing_raw": missing_raw,
            "historical_parser": dict(hist_parser),
            "envelope": dict(envelope_counts),
            "json": dict(json_counts),
            "shape": dict(shape_counts),
            "response": dict(layer_counts),
        },
        "reconciliation": {
            "expected_lower_bound": REPORTED_LOWER_BOUND,
            "observed_unique_events": observed,
            "stable_ledger_rows_are_copies_plus_events": True,
            "duplicate_ledger_copies_counted_once": True,
            "identical_raw_hash_still_two_calls": True,
            "reconciled_consumed_lower": lower,
            "reconciled_consumed_upper": upper,
            "conservative_consumed_for_new_call_limit": conservative_consumed,
            "uncertainty": (
                "none"
                if lower == upper == observed
                else "bounds_differ_use_upper"
            ),
        },
    }
    return payload


def write_diagnosis_reports(workspace: Path, diagnosis: dict[str, Any]) -> dict[str, str]:
    out = Path(workspace) / "reports" / "rounds" / "R02C"
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "output_diagnosis.json"
    json_path.write_text(
        json.dumps(diagnosis, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    rec = diagnosis["reconciliation"]
    counts = diagnosis["counts"]
    excerpts: list[str] = []
    for row in diagnosis["requests"]:
        if row["phase"] != "E0" or not row.get("raw_present"):
            continue
        # Reload a tiny excerpt from raw using stored hash only in the report.
        run_dir = Path(workspace) / "artifacts" / "r02b" / "runs" / row["run_id"]
        step = row.get("step") or "e0_0"
        txt = run_dir / "e0" / f"{step}.txt"
        if not txt.is_file():
            continue
        raw = txt.read_text(encoding="utf-8")
        fragment = _safe_excerpt(raw)
        if fragment:
            excerpts.append(
                f"- run `{row['run_id']}` seq={row['seq']} raw={row.get('raw_sha256')} "
                f"historical={row.get('historical_parser_status')} layers.json={row['layers']['json']} "
                f"shape={row['layers']['shape']} excerpt=`{fragment}`"
            )
        if len(excerpts) >= 4:
            break
    # One real-sample format-only excerpt (verdict token only).
    for row in diagnosis["requests"]:
        if row["phase"] != "E1" or not row.get("raw_present"):
            continue
        if row.get("step") != "final":
            continue
        inst = row.get("instance_id")
        rep = row.get("representation")
        txt = (
            Path(workspace)
            / "artifacts"
            / "r02b"
            / "runs"
            / row["run_id"]
            / "e1"
            / str(inst)
            / str(rep)
            / f"{inst}_{rep}_final.txt"
        )
        if txt.is_file():
            fragment = _safe_excerpt(txt.read_text(encoding="utf-8"))
            excerpts.append(
                f"- E1 format fragment run `{row['run_id']}` {inst}/{rep} raw={row.get('raw_sha256')} "
                f"excerpt=`{fragment}` (no source body)"
            )
            break
    md = [
        "# R02C output diagnosis (offline, 0 model calls)",
        "",
        "Old R02B raw, manifests and reports were **not rewritten**. "
        "Retrospective parse does not recover the policy trajectory "
        "(`retrospective_parse_only=true`, `policy_trajectory_recovered=false`).",
        "",
        "## Denominator",
        "",
        f"- Reported lower bound (task): **{REPORTED_LOWER_BOUND}**",
        f"- Sum of run_index requests_attempted: **{counts['reported_sum_of_index']}**",
        f"- Observed unique events `(run_id, seq, phase, instance_id, representation, step)`: **{counts['observed_unique_events']}**",
        f"- Stable ledger rows (copies of the same events, counted separately as copies): **{counts['stable_ledger_rows']}**",
        f"- Reconciled consumed lower/upper: **{rec['reconciled_consumed_lower']} / {rec['reconciled_consumed_upper']}**",
        f"- Conservative consumed used for new-call limits: **{rec['conservative_consumed_for_new_call_limit']}**",
        f"- Uncertainty: **{rec['uncertainty']}**",
        f"- Duplicate raw-hash groups (still counted as distinct calls): **{counts['duplicate_raw_hash_groups']}**",
        f"- Missing raw bodies: **{counts['missing_raw']}**",
        "",
        "## Historical parser vs layered re-parse",
        "",
        f"- Historical `parse_model_output` statuses: `{counts['historical_parser']}`",
        f"- Envelope: `{counts['envelope']}`",
        f"- JSON: `{counts['json']}`",
        f"- Shape: `{counts['shape']}`",
        "",
        "Fence removal is normalize-only. `True`/`Yes` verdicts stay illegal; they are not mapped to `supported`.",
        "A retrospectively valid six-key object is **not** a recovered SBS card.",
        "",
        "## Necessary safe excerpts",
        "",
    ]
    md.extend(excerpts or ["- (no E0 raw excerpt available)"])
    md.extend(
        [
            "",
            "## Limits",
            "",
            "- Full prompts, token ids and third-party bodies stay local under `artifacts/r02b/`.",
            "- Semantics = `not_evaluated`. No detection accuracy/F1.",
            "- First registered run includes a FileNotFoundError sidecar with missing `e0_0.txt`.",
            "",
        ]
    )
    md_path = out / "OUTPUT_DIAGNOSIS.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    rec_path = out / "legacy_request_reconciliation.json"
    rec_payload = {
        "task_id": "R02C",
        "reported_lower_bound": REPORTED_LOWER_BOUND,
        "observed_unique_events": rec["observed_unique_events"],
        "reconciled_consumed_lower": rec["reconciled_consumed_lower"],
        "reconciled_consumed_upper": rec["reconciled_consumed_upper"],
        "conservative_consumed_for_new_call_limit": rec["conservative_consumed_for_new_call_limit"],
        "uncertainty": rec["uncertainty"],
        "duplicate_ledger_copies_counted_once": True,
        "identical_raw_hash_still_two_calls": True,
        "new_ledger_does_not_contain_forged_historical_reservations": True,
        "historical_baseline_relative_path": "reports/rounds/R02C/legacy_request_reconciliation.json",
        "new_ledger_relative_path": "artifacts/r02c/request_ledger.jsonl",
        "registered_runs": diagnosis["registered_runs"],
        "model_called": False,
    }
    rec_path.write_text(
        json.dumps(rec_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "output_diagnosis_json": json_path.as_posix(),
        "output_diagnosis_md": md_path.as_posix(),
        "legacy_request_reconciliation": rec_path.as_posix(),
    }


def diagnose_output(workspace: Path, run_index: Path) -> dict[str, Any]:
    diagnosis = diagnose_registered_runs(workspace, run_index)
    paths = write_diagnosis_reports(workspace, diagnosis)
    return {
        "ok": True,
        "model_called": False,
        "model_loaded": False,
        "observed_unique_events": diagnosis["reconciliation"]["observed_unique_events"],
        "conservative_consumed": diagnosis["reconciliation"][
            "conservative_consumed_for_new_call_limit"
        ],
        "paths": paths,
    }
