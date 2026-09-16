"""Standalone Linux PID-namespace supervisor for the first-case gate.

The verifier launches this file with ``python -I -B -S``. This outer process
creates a same-ID user namespace and a fresh PID namespace, then forks the
namespace init process. Only namespace PID 1 supervises the untrusted target;
when PID 1 exits the kernel destroys every remaining process in that namespace.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from typing import Any


RESULT_SCHEMA_VERSION = "1.0"
RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "returncode",
        "stdout_base64",
        "stderr_base64",
        "error_code",
    }
)
_MAX_CAPTURE_LIMIT_BYTES = 16 * 1024 * 1024
_MAX_TERMINATION_GRACE_SECONDS = 30.0
_RESULT_OVERHEAD_BYTES = 16 * 1024
_POST_EXIT_DRAIN_SECONDS = 0.1
_MAX_ADOPTED_REAPS_PER_TICK = 64
_PR_SET_PDEATHSIG = 1
_PR_GET_CHILD_SUBREAPER = 37
_OUTER_TERMINATION_REQUESTED = False
_ERROR_CODES = frozenset(
    {
        "capture_failed",
        "capture_limit",
        "cleanup_failed",
        "internal_error",
        "launch_failed",
        "namespace_unavailable",
        "terminated",
        "timeout",
    }
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _linux_prctl() -> Any:
    if sys.platform != "linux" or not Path("/proc/self").is_dir():
        raise ValueError("Linux process controls are unavailable")
    library = ctypes.CDLL(None, use_errno=True)
    operation = library.prctl
    operation.restype = ctypes.c_int
    return operation


def _get_child_subreaper_state() -> int:
    """Read, but never alter, the caller's child-subreaper state."""

    state = ctypes.c_int(-1)
    result = _linux_prctl()(
        ctypes.c_int(_PR_GET_CHILD_SUBREAPER),
        ctypes.byref(state),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0 or state.value not in {0, 1}:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return state.value


def _validate_inputs(
    command: list[str],
    cwd: Path,
    timeout_seconds: float,
    termination_grace_seconds: float,
    capture_limit: int,
) -> None:
    _require(
        type(command) is list
        and bool(command)
        and all(type(item) is str and bool(item) for item in command),
        "process command is invalid",
    )
    _require(cwd.is_absolute() and cwd.is_dir(), "process cwd is invalid")
    _require(
        type(timeout_seconds) in {int, float}
        and not isinstance(timeout_seconds, bool)
        and math.isfinite(timeout_seconds)
        and timeout_seconds > 0,
        "process timeout is invalid",
    )
    _require(
        type(termination_grace_seconds) in {int, float}
        and not isinstance(termination_grace_seconds, bool)
        and math.isfinite(termination_grace_seconds)
        and 0 < termination_grace_seconds
        <= _MAX_TERMINATION_GRACE_SECONDS,
        "process termination grace is invalid",
    )
    _require(
        type(capture_limit) is int
        and 0 < capture_limit <= _MAX_CAPTURE_LIMIT_BYTES,
        "process capture limit is invalid",
    )


def _error_result(error_code: str) -> dict[str, object]:
    _require(error_code in _ERROR_CODES, "supervisor error code is invalid")
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "error",
        "returncode": None,
        "stdout_base64": "",
        "stderr_base64": "",
        "error_code": error_code,
    }


def _completed_result(
    command: list[str], returncode: int, stdout: bytes, stderr: bytes
) -> dict[str, object]:
    del command
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "completed",
        "returncode": returncode,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "error_code": None,
    }


def _result_limit(capture_limit: int) -> int:
    encoded_stream_limit = 4 * ((capture_limit + 2) // 3)
    return 2 * encoded_stream_limit + _RESULT_OVERHEAD_BYTES


def _encode_result(result: dict[str, object]) -> bytes:
    return json.dumps(
        result,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def _strict_json_object(raw: bytes) -> object:
    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON field")
            value[key] = item
        return value

    return json.loads(
        raw.decode("ascii", "strict"),
        object_pairs_hook=pairs_hook,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {value}")
        ),
    )


def _validate_result(
    raw: bytes, *, capture_limit: int
) -> dict[str, object]:
    if (
        not raw.endswith(b"\n")
        or b"\n" in raw[:-1]
        or len(raw) > _result_limit(capture_limit)
    ):
        raise ValueError("namespace result is invalid")
    value = _strict_json_object(raw[:-1])
    if not (
        type(value) is dict
        and set(value) == RESULT_FIELDS
        and value.get("schema_version") == RESULT_SCHEMA_VERSION
        and value.get("status") in {"completed", "error"}
        and type(value.get("stdout_base64")) is str
        and type(value.get("stderr_base64")) is str
    ):
        raise ValueError("namespace result is invalid")
    try:
        stdout = base64.b64decode(
            value["stdout_base64"].encode("ascii"), validate=True
        )
        stderr = base64.b64decode(
            value["stderr_base64"].encode("ascii"), validate=True
        )
    except (UnicodeError, binascii.Error, ValueError):
        raise ValueError("namespace result is invalid") from None
    if len(stdout) > capture_limit or len(stderr) > capture_limit:
        raise ValueError("namespace result is invalid")
    if value["status"] == "completed":
        if not (
            type(value.get("returncode")) is int
            and -255 <= value["returncode"] <= 255
            and value.get("error_code") is None
        ):
            raise ValueError("namespace result is invalid")
    elif not (
        value.get("returncode") is None
        and stdout == b""
        and stderr == b""
        and type(value.get("error_code")) is str
        and value["error_code"] in _ERROR_CODES
    ):
        raise ValueError("namespace result is invalid")
    return value


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("short result-pipe write")
        offset += written


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _reap_adopted_children_nohang(target_pid: int) -> None:
    """Reap exited PID-namespace orphans without consuming the target."""

    for _ in range(_MAX_ADOPTED_REAPS_PER_TICK):
        try:
            candidate = os.waitid(
                os.P_ALL,
                0,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        except OSError as error:
            raise RuntimeError("adopted-child inspection failed") from error
        if candidate is None or candidate.si_pid == 0:
            return
        candidate_pid = candidate.si_pid
        if candidate_pid == target_pid:
            return
        try:
            observed, _ = os.waitpid(candidate_pid, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        except OSError as error:
            raise RuntimeError("adopted-child reap failed") from error
        if observed != candidate_pid:
            return


def _run_target(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    termination_grace_seconds: float,
    capture_limit: int,
    liveness_read_fd: int,
) -> dict[str, object]:
    """Run one target as namespace PID 2 and capture both streams."""

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            text=False,
            bufsize=0,
            close_fds=True,
        )
    except OSError:
        return _error_result("launch_failed")
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    post_exit_deadline: float | None = None
    failure: str | None = None
    try:
        _require(
            process.stdout is not None and process.stderr is not None,
            "target pipes are unavailable",
        )
        for name, stream in (
            ("stdout", process.stdout),
            ("stderr", process.stderr),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        os.set_blocking(liveness_read_fd, False)
        selector.register(
            liveness_read_fd, selectors.EVENT_READ, "outer_liveness"
        )
        while True:
            now = time.monotonic()
            returncode = process.poll()
            if returncode is None:
                _reap_adopted_children_nohang(process.pid)
            if returncode is not None and post_exit_deadline is None:
                post_exit_deadline = now + min(
                    _POST_EXIT_DRAIN_SECONDS,
                    termination_grace_seconds / 2,
                )
            active_deadline = (
                post_exit_deadline
                if post_exit_deadline is not None
                else deadline
            )
            target_streams_open = any(
                key.data in {"stdout", "stderr"}
                for key in selector.get_map().values()
            )
            if (
                returncode is not None
                and not target_streams_open
                and post_exit_deadline is not None
                and now >= post_exit_deadline
            ):
                break
            if now >= active_deadline:
                if returncode is None:
                    failure = "timeout"
                break
            events = selector.select(
                timeout=min(0.01, max(0.0, active_deadline - now))
            )
            for key, _ in events:
                name = key.data
                if name == "outer_liveness":
                    try:
                        alive = os.read(liveness_read_fd, 1)
                    except BlockingIOError:
                        continue
                    except InterruptedError:
                        continue
                    if not alive:
                        os._exit(125)
                    continue
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 65_536)
                except BlockingIOError:
                    continue
                except OSError:
                    failure = "capture_failed"
                    break
                if not chunk:
                    selector.unregister(stream)
                    continue
                buffers[name].extend(chunk)
                if len(buffers[name]) > capture_limit:
                    failure = "capture_limit"
                    break
            if failure is not None:
                break
        if failure is not None:
            return _error_result(failure)
        returncode = process.poll()
        if returncode is None:
            return _error_result("timeout")
        return _completed_result(
            command,
            returncode,
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
        )
    except (OSError, ValueError):
        return _error_result("capture_failed")
    except Exception:
        return _error_result("internal_error")
    finally:
        selector.close()
        _close_process_pipes(process)


def _write_proc_control(path: str, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        _write_all(descriptor, raw)
    finally:
        os.close(descriptor)


def _enter_same_id_user_namespace() -> None:
    uid = os.getuid()
    gid = os.getgid()
    clone_newuser = getattr(os, "CLONE_NEWUSER", None)
    unshare = getattr(os, "unshare", None)
    if type(clone_newuser) is not int or not callable(unshare):
        raise OSError("user namespaces are unavailable")
    unshare(clone_newuser)
    _write_proc_control("/proc/self/setgroups", b"deny\n")
    _write_proc_control(
        "/proc/self/uid_map", f"{uid} {uid} 1\n".encode("ascii")
    )
    _write_proc_control(
        "/proc/self/gid_map", f"{gid} {gid} 1\n".encode("ascii")
    )
    current = os.stat("/proc/self")
    if os.getuid() != uid or os.getgid() != gid or current.st_uid != uid:
        raise OSError("same-ID namespace mapping failed")


def _arm_outer_death_signal(liveness_read_fd: int) -> None:
    result = _linux_prctl()(
        ctypes.c_int(_PR_SET_PDEATHSIG),
        ctypes.c_ulong(signal.SIGKILL),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    os.set_blocking(liveness_read_fd, False)
    try:
        raw = os.read(liveness_read_fd, 1)
    except BlockingIOError:
        return
    if not raw:
        os._exit(125)


def _pid1_main(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    termination_grace_seconds: float,
    capture_limit: int,
    result_write_fd: int,
    liveness_read_fd: int,
) -> None:
    """Act as namespace init without member-triggerable signal handlers."""

    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        _arm_outer_death_signal(liveness_read_fd)
        result = _run_target(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            termination_grace_seconds=termination_grace_seconds,
            capture_limit=capture_limit,
            liveness_read_fd=liveness_read_fd,
        )
    except BaseException:
        result = _error_result("internal_error")
    try:
        _write_all(result_write_fd, _encode_result(result))
    except BaseException:
        pass
    finally:
        try:
            os.close(result_write_fd)
        except OSError:
            pass
        os._exit(0)


def _waitpid_nohang(pid: int) -> int | None:
    while True:
        try:
            observed, status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            continue
        return status if observed == pid else None


def _kill_and_reap_pid1(pid: int, *, deadline: float) -> bool:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return False
    while True:
        try:
            observed, _ = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return True
        if observed == pid:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _request_outer_termination(
    signum: int, frame: object | None
) -> None:
    del signum, frame
    global _OUTER_TERMINATION_REQUESTED
    _OUTER_TERMINATION_REQUESTED = True


def _outer_collect_result(
    pid: int,
    result_read_fd: int,
    *,
    timeout_seconds: float,
    termination_grace_seconds: float,
    capture_limit: int,
) -> dict[str, object]:
    limit = _result_limit(capture_limit)
    buffer = bytearray()
    selector = selectors.DefaultSelector()
    os.set_blocking(result_read_fd, False)
    selector.register(result_read_fd, selectors.EVENT_READ)
    deadline = (
        time.monotonic()
        + timeout_seconds
        + max(1.0, 2 * termination_grace_seconds)
    )
    child_status: int | None = None
    eof = False
    try:
        while True:
            if _OUTER_TERMINATION_REQUESTED:
                cleaned = child_status is not None or _kill_and_reap_pid1(
                    pid,
                    deadline=(
                        time.monotonic()
                        + max(1.0, termination_grace_seconds)
                    ),
                )
                return _error_result(
                    "terminated" if cleaned else "cleanup_failed"
                )
            if child_status is None:
                child_status = _waitpid_nohang(pid)
            if child_status is not None and eof:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                cleaned = child_status is not None or _kill_and_reap_pid1(
                    pid,
                    deadline=(
                        time.monotonic()
                        + max(1.0, termination_grace_seconds)
                    ),
                )
                return _error_result(
                    "internal_error" if cleaned else "cleanup_failed"
                )
            for _, _ in selector.select(timeout=min(0.01, remaining)):
                while True:
                    try:
                        chunk = os.read(result_read_fd, 65_536)
                    except BlockingIOError:
                        break
                    except InterruptedError:
                        continue
                    except OSError:
                        return _error_result("internal_error")
                    if not chunk:
                        eof = True
                        try:
                            selector.unregister(result_read_fd)
                        except KeyError:
                            pass
                        break
                    buffer.extend(chunk)
                    if len(buffer) > limit:
                        cleaned = (
                            child_status is not None
                            or _kill_and_reap_pid1(
                                pid,
                                deadline=(
                                    time.monotonic()
                                    + max(
                                        1.0, termination_grace_seconds
                                    )
                                ),
                            )
                        )
                        return _error_result(
                            "internal_error" if cleaned else "cleanup_failed"
                        )
        if not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
            return _error_result("internal_error")
        try:
            return _validate_result(bytes(buffer), capture_limit=capture_limit)
        except (TypeError, ValueError):
            return _error_result("internal_error")
    finally:
        selector.close()


def _namespace_supervise(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    termination_grace_seconds: float,
    capture_limit: int,
) -> dict[str, object]:
    """Create the namespaces and relay one strictly bounded PID-1 result."""

    _validate_inputs(
        command,
        cwd,
        timeout_seconds,
        termination_grace_seconds,
        capture_limit,
    )
    clone_newpid = getattr(os, "CLONE_NEWPID", None)
    if type(clone_newpid) is not int:
        return _error_result("namespace_unavailable")
    try:
        _enter_same_id_user_namespace()
    except (OSError, ValueError):
        return _error_result("namespace_unavailable")

    result_read_fd: int | None = None
    result_write_fd: int | None = None
    liveness_read_fd: int | None = None
    liveness_write_fd: int | None = None
    try:
        result_read_fd, result_write_fd = os.pipe2(os.O_CLOEXEC)
        liveness_read_fd, liveness_write_fd = os.pipe2(os.O_CLOEXEC)
        os.unshare(clone_newpid)
        pid = os.fork()
    except OSError:
        for descriptor in (
            result_read_fd,
            result_write_fd,
            liveness_read_fd,
            liveness_write_fd,
        ):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        return _error_result("namespace_unavailable")

    assert result_read_fd is not None
    assert result_write_fd is not None
    assert liveness_read_fd is not None
    assert liveness_write_fd is not None
    if pid == 0:
        os.close(result_read_fd)
        os.close(liveness_write_fd)
        _pid1_main(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            termination_grace_seconds=termination_grace_seconds,
            capture_limit=capture_limit,
            result_write_fd=result_write_fd,
            liveness_read_fd=liveness_read_fd,
        )
        os._exit(126)

    os.close(result_write_fd)
    os.close(liveness_read_fd)
    signal.signal(signal.SIGTERM, _request_outer_termination)
    try:
        return _outer_collect_result(
            pid,
            result_read_fd,
            timeout_seconds=timeout_seconds,
            termination_grace_seconds=termination_grace_seconds,
            capture_limit=capture_limit,
        )
    finally:
        for descriptor in (result_read_fd, liveness_write_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _await_launch_gate(descriptor: int | None) -> None:
    """Do not create a PID namespace or target until the parent pins control."""

    if descriptor is None:
        return
    _require(
        type(descriptor) is int and descriptor >= 3,
        "process launch gate is invalid",
    )
    try:
        while True:
            try:
                raw = os.read(descriptor, 2)
                break
            except InterruptedError:
                continue
    finally:
        os.close(descriptor)
    _require(raw == b"G", "process launch gate was not released")


def _signal_launch_ready(descriptor: int | None) -> None:
    """Acknowledge that SIGTERM control is armed before gate release."""

    if descriptor is None:
        return
    _require(
        type(descriptor) is int and descriptor >= 3,
        "process launch ready descriptor is invalid",
    )
    try:
        _write_all(descriptor, b"R")
    finally:
        os.close(descriptor)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--launch-gate-fd", type=int)
    parser.add_argument("--launch-ready-fd", type=int)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--timeout-seconds", required=True, type=float)
    parser.add_argument(
        "--termination-grace-seconds", required=True, type=float
    )
    parser.add_argument("--capture-limit", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global _OUTER_TERMINATION_REQUESTED
    try:
        arguments = _parse_args(sys.argv[1:] if argv is None else argv)
        _OUTER_TERMINATION_REQUESTED = False
        signal.signal(signal.SIGTERM, _request_outer_termination)
        _signal_launch_ready(arguments.launch_ready_fd)
        _await_launch_gate(arguments.launch_gate_fd)
        command = arguments.command
        if command[:1] == ["--"]:
            command = command[1:]
        result = _namespace_supervise(
            command,
            cwd=Path(arguments.cwd),
            timeout_seconds=arguments.timeout_seconds,
            termination_grace_seconds=arguments.termination_grace_seconds,
            capture_limit=arguments.capture_limit,
        )
    except (OSError, ValueError, OverflowError):
        result = _error_result("internal_error")
    raw = _encode_result(result)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
