#!/usr/bin/env python3
"""Re-exec the stdlib-only bootstrap for explicit runner-lock maintenance."""

from __future__ import annotations

import os
import sys


_MINIMAL_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "HOME": "/nonexistent",
    "TMPDIR": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
}


def _root_argument(argv: list[str]) -> str:
    if len(argv) == 2 and argv[0] == "--root" and argv[1]:
        return os.path.realpath(argv[1])
    if len(argv) == 1 and argv[0].startswith("--root="):
        value = argv[0].partition("=")[2]
        if value:
            return os.path.realpath(value)
    raise ValueError("exactly one --root argument is required")


def main() -> int:
    try:
        root = _root_argument(sys.argv[1:])
    except ValueError:
        return 2
    executable = os.path.join(
        root, ".work", "offline-test-runner-venv", "bin", "python"
    )
    bootstrap = os.path.join(root, "scripts", "locked_runtime_bootstrap.py")
    os.execve(
        executable,
        [
            executable,
            "-X",
            "pycache_prefix=/nonexistent/egsi-locked-pycache",
            "-I",
            "-B",
            "-S",
            bootstrap,
            "build-lock",
            "--root",
            root,
        ],
        dict(_MINIMAL_ENVIRONMENT),
    )
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
