"""Non-secret repository and resource inventory."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _redact_origin(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if "@" in path and "/" in path.split("@", 1)[-1]:
        path = path.split("@", 1)[-1]
    normalized = path
    if host in {"github.com", "ssh.github.com"} or host.endswith("github.com"):
        normalized = path
    netloc = parsed.hostname or parsed.netloc.split("@")[-1]
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    redacted = urlunparse(
        (parsed.scheme, netloc, parsed.path, "", "", "")
    )
    return normalized, redacted


def _java_version() -> str | None:
    result = subprocess.run(
        ["java", "-version"], text=True, capture_output=True, check=False
    )
    text = (result.stderr or result.stdout or "").splitlines()
    return text[0] if text else None


def _gpu_info() -> dict[str, Any]:
    result = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total",
            "--format=csv,noheader",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return {"gpu_present": False, "gpu_count": 0, "gpu_models": []}
    models = []
    for line in result.stdout.splitlines():
        name = line.split(",", 1)[0].strip()
        if name:
            models.append(name)
    return {
        "gpu_present": bool(models),
        "gpu_count": len(models),
        "gpu_models": models,
    }


def _credentials_present() -> bool:
    names = (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "OPENAI_API_KEY_SECRET",
    )
    return any(bool(os.environ.get(name)) for name in names)


def collect_inventory(repo: Path) -> dict[str, Any]:
    repo = Path(repo).resolve()
    origin = _run(["git", "remote", "get-url", "origin"], repo)
    origin_url = origin.stdout.strip()
    normalized, redacted = _redact_origin(origin_url) if origin_url else ("", "")
    head = _run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
    branch = _run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], repo
    ).stdout.strip()
    porcelain = _run(["git", "status", "--porcelain"], repo)
    dirty = bool(porcelain.stdout.strip())
    untracked = [
        line[3:]
        for line in porcelain.stdout.splitlines()
        if line.startswith("?? ")
        and not line[3:].endswith(".env")
        and "id_rsa" not in line
        and ".pem" not in line
    ]
    fetch = _run(["git", "fetch", "origin"], repo)
    remote_head = _run(["git", "ls-remote", "--symref", "origin", "HEAD"], repo)
    default_branch = "unknown"
    remote_head_sha = None
    for line in remote_head.stdout.splitlines():
        if line.startswith("ref:"):
            ref = line.split()[1]
            default_branch = ref.rsplit("/", 1)[-1]
        elif line.strip():
            remote_head_sha = line.split()[0]
    unpushed = _run(
        ["git", "rev-list", "--count", f"origin/{branch}..HEAD"], repo
    )
    unpushed_count = 0
    if unpushed.returncode == 0 and unpushed.stdout.strip().isdigit():
        unpushed_count = int(unpushed.stdout.strip())
    ram_pages = os.sysconf("SC_PHYS_PAGES")
    page = os.sysconf("SC_PAGE_SIZE")
    disk = shutil.disk_usage(repo)
    gpu = _gpu_info()
    java = _java_version()
    providers_local = (repo / "configs" / "providers.local.toml").exists()
    data_link = (repo / "data").is_symlink() or (repo / "data").is_dir()
    catalog = (repo / "data" / "catalog" / "cases.jsonl").is_file()
    return {
        "schema_version": "1.0",
        "round_id": "R01",
        "collected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository": {
            "normalized_origin": normalized,
            "origin_url_redacted": redacted,
            "head": head,
            "current_branch": branch,
            "default_branch": default_branch,
            "worktree_dirty": dirty,
            "untracked_non_secret": untracked,
            "unpushed_commits": unpushed_count,
            "fetch_ok": fetch.returncode == 0,
            "fetch_exit_code": fetch.returncode,
            "remote_head": remote_head_sha,
            "assistant_repo_access": "unverified_404",
        },
        "resources": {
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            "java": java,
            "git": _run(["git", "--version"], repo).stdout.strip(),
            "cpu_count": os.cpu_count(),
            "ram_gib_approx": round(ram_pages * page / 1024**3, 1),
            "disk_free_gib_approx": round(disk.free / 1024**3),
            "gpu_present": gpu["gpu_present"],
            "gpu_count": gpu["gpu_count"],
            "gpu_models": gpu["gpu_models"],
            "model_api_credentials_present": _credentials_present(),
            "providers_local_toml_present": providers_local,
            "new_model_api_budget": 0,
            "local_data_catalog_present": catalog,
            "data_tree_present": data_link,
        },
    }


def write_inventory(repo: Path, output: Path) -> dict[str, Any]:
    payload = collect_inventory(repo)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    import json

    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
