"""Emit one canonical collection/execution commitment from trusted pytest."""

from __future__ import annotations

import hashlib
import json
from typing import Any


PREFIX = "EGSI_PYTEST_CONTRACT="


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def pytest_collection_finish(session: Any) -> None:
    session.config._egsi_collection_nodeids = [
        item.nodeid for item in session.items
    ]
    session.config._egsi_terminal_outcomes = {}


def pytest_runtest_logreport(report: Any) -> None:
    config = getattr(report, "config", None)
    del config
    # Reports do not expose Config. The active outcome map is installed on the
    # plugin module by pytest_sessionstart and cleared at session finish.
    if report.when == "call":
        _TERMINAL_OUTCOMES[report.nodeid] = report.outcome
    elif report.when == "setup" and report.outcome in {"failed", "skipped"}:
        _TERMINAL_OUTCOMES[report.nodeid] = report.outcome


_TERMINAL_OUTCOMES: dict[str, str] = {}


def pytest_sessionstart(session: Any) -> None:
    del session
    _TERMINAL_OUTCOMES.clear()


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    collection = list(
        getattr(session.config, "_egsi_collection_nodeids", [])
    )
    executed = [nodeid for nodeid in collection if nodeid in _TERMINAL_OUTCOMES]
    outcomes = [_TERMINAL_OUTCOMES[nodeid] for nodeid in executed]
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "exit_status": int(exitstatus),
        "collection_count": len(collection),
        "collection_nodeids_sha256": _sha256(collection),
        "executed_count": len(executed),
        "executed_nodeids_sha256": _sha256(executed),
        "passed_count": outcomes.count("passed"),
        "failed_count": outcomes.count("failed"),
        "skipped_count": outcomes.count("skipped"),
        "contract_sha256": "sha256:" + "0" * 64,
    }
    value["contract_sha256"] = _sha256(
        {key: item for key, item in value.items() if key != "contract_sha256"}
    )
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(PREFIX + _canonical(value).decode("utf-8"))
    _TERMINAL_OUTCOMES.clear()
