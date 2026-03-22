"""Global rate limiter for Visma RoE compliance.

Enforces the 20 req/sec AGGREGATE limit across all active pipeline workers
using a Redis-based distributed mutex. Only one active-scanning subprocess
runs at a time, guaranteeing the total rate never exceeds the per-tool cap.

Usage:
    from .ratelimit import active_scan_slot

    with active_scan_slot("naabu"):
        subprocess.run(["naabu", ...])
"""

import os
import signal
import subprocess
import time
import uuid
import logging
import threading
import contextlib
from pathlib import Path

log = logging.getLogger(__name__)

_redis = None

# Set this event to abort all active_scan_slot wait loops immediately on shutdown.
_shutdown_event = threading.Event()

# ── Child process tracking ──────────────────────────────────────────────────
# All long-running subprocesses are registered here so they can be killed on
# shutdown and discovered/cleaned up on the next pipeline start.

_PIDS_FILE = Path("/tmp/bbtrs_children.pids")
_child_procs: list[subprocess.Popen] = []
_child_procs_lock = threading.Lock()


def _register_child(proc: subprocess.Popen) -> None:
    with _child_procs_lock:
        _child_procs.append(proc)
    try:
        with open(_PIDS_FILE, "a") as f:
            f.write(f"{proc.pid}\n")
    except Exception:
        pass


def _unregister_child(proc: subprocess.Popen) -> None:
    with _child_procs_lock:
        try:
            _child_procs.remove(proc)
        except ValueError:
            pass


def kill_child_procs() -> int:
    """Kill all currently tracked child processes. Returns number killed.

    Called by the shutdown handler in cli.py to ensure no orphan tool
    processes (nmap, naabu, nuclei, httpx, etc.) survive the pipeline exit.
    """
    with _child_procs_lock:
        procs = list(_child_procs)
    killed = 0
    for proc in procs:
        try:
            proc.kill()
            killed += 1
        except (ProcessLookupError, OSError):
            pass
    try:
        _PIDS_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return killed


def kill_orphans_from_previous_run() -> int:
    """Kill any subprocesses left over from a previous crashed pipeline run.

    Reads /tmp/bbtrs_children.pids written by the last run and SIGTERMs each
    PID that is still alive. Should be called once at pipeline startup.
    Returns the number of orphans killed.
    """
    if not _PIDS_FILE.exists():
        return 0
    killed = 0
    try:
        pids_text = _PIDS_FILE.read_text().strip()
        for line in pids_text.splitlines():
            try:
                pid = int(line.strip())
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except (ValueError, ProcessLookupError, PermissionError):
                pass
    except Exception:
        pass
    try:
        _PIDS_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return killed


def tracked_run(cmd, input=None, timeout=None, **kwargs) -> subprocess.CompletedProcess:
    """Drop-in replacement for subprocess.run() with two extra behaviours:

    1. Kills the child process immediately when ``_shutdown_event`` is set,
       then raises ``PipelineShuttingDown``.
    2. Writes the child PID to ``/tmp/bbtrs_children.pids`` so that a
       subsequent pipeline start can clean up any survivors (see
       ``kill_orphans_from_previous_run``).

    All other semantics match subprocess.run(): same args, same exceptions
    (TimeoutExpired, CalledProcessError, FileNotFoundError …).
    """
    # Expand capture_output shorthand that Popen doesn't support
    if kwargs.pop("capture_output", False):
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    stdin_pipe = subprocess.PIPE if input is not None else None
    proc = subprocess.Popen(cmd, stdin=stdin_pipe, **kwargs)
    _register_child(proc)

    result_stdout = None
    result_stderr = None
    comm_exc: list[Exception | None] = [None]
    done_event = threading.Event()

    def _communicate():
        nonlocal result_stdout, result_stderr
        try:
            out, err = proc.communicate(input=input, timeout=timeout)
            result_stdout = out
            result_stderr = err
        except subprocess.TimeoutExpired:
            # Replicate subprocess.run() behaviour: kill then wait for cleanup
            proc.kill()
            out, err = proc.communicate()
            comm_exc[0] = subprocess.TimeoutExpired(
                cmd, timeout, output=out, stderr=err
            )
        except Exception as exc:
            comm_exc[0] = exc
        finally:
            done_event.set()

    t = threading.Thread(target=_communicate, daemon=True)
    t.start()

    try:
        while not done_event.wait(timeout=0.2):
            if _shutdown_event.is_set():
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                done_event.wait(timeout=2)
                raise PipelineShuttingDown(
                    f"subprocess {cmd[0] if isinstance(cmd, list) else cmd}"
                    " killed — pipeline shutting down"
                )
    finally:
        _unregister_child(proc)

    if comm_exc[0] is not None:
        raise comm_exc[0]

    return subprocess.CompletedProcess(cmd, proc.returncode, result_stdout, result_stderr)


class PipelineShuttingDown(Exception):
    """Raised inside active_scan_slot or tracked_run when the pipeline is shutting down."""

# Lua: release the lock only if this process still owns it
_RELEASE_LUA = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
"""


def _get_redis():
    global _redis
    if _redis is None:
        import redis as redis_lib
        from .config import get_config
        cfg = get_config().get("redis", {})
        _redis = redis_lib.Redis(
            host=cfg.get("host", "127.0.0.1"),
            port=cfg.get("port", 6379),
            db=cfg.get("db", 0),
            decode_responses=True,
        )
    return _redis


@contextlib.contextmanager
def active_scan_slot(worker_name: str, lease_seconds: int = 3600, wait_timeout: int = 7200):
    """Distributed mutex: only one active scanner runs at a time.

    Blocks until the global scan slot is free, then holds it for the
    duration of the ``with`` block. Auto-releases on exit (or crash via TTL).

    Args:
        worker_name:    Identifier shown in debug logs (e.g. "naabu", "katana").
        lease_seconds:  How long the lock lives if the process crashes (TTL).
        wait_timeout:   Give up waiting after this many seconds (default 2 h).
    """
    from .config import get_config
    cfg = get_config()

    # Allow opt-out for non-RoE targets
    if not cfg.get("intigriti", {}).get("enforce_global_rate_limit", True):
        yield True
        return

    r = _get_redis()
    key = "roe:active_scan_mutex"
    token = f"{worker_name}:{uuid.uuid4().hex}"
    lease_ms = lease_seconds * 1000

    acquired = False
    deadline = time.monotonic() + wait_timeout

    while time.monotonic() < deadline:
        if _shutdown_event.is_set():
            raise PipelineShuttingDown(f"{worker_name} aborted — pipeline shutting down")

        result = r.set(key, token, nx=True, px=lease_ms)
        if result:
            acquired = True
            log.debug(f"[ratelimit] {worker_name} acquired global scan slot")
            break

        holder = r.get(key) or "unknown"
        log.debug(f"[ratelimit] {worker_name} waiting for scan slot (held by: {holder})")
        # Sleep in short increments so shutdown events are noticed quickly
        for _ in range(20):
            if _shutdown_event.is_set():
                raise PipelineShuttingDown(f"{worker_name} aborted — pipeline shutting down")
            time.sleep(0.1)

    if not acquired:
        log.error(f"[ratelimit] {worker_name} timed out after {wait_timeout}s — proceeding anyway")

    try:
        yield acquired
    finally:
        if acquired:
            r.eval(_RELEASE_LUA, 1, key, token)
            log.debug(f"[ratelimit] {worker_name} released global scan slot")
