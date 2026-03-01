"""Forensic context capture for canAIry.

Captures a rich snapshot of the runtime environment at the moment a trap
fires — who triggered it, what process called the trap, and the full
ancestor chain back to PID 1 (or the system root on Windows).

All psutil calls are defensively wrapped: process state can change at any
instant, so AccessDenied / NoSuchProcess / ZombieProcess are caught and
replaced with sensible fallback values.
"""

from __future__ import annotations

import datetime
import getpass
import os
import platform
import socket
from typing import Any

import psutil


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def capture_context(extra: dict | None = None) -> dict[str, Any]:
    """Return a forensic snapshot dict for the current process.

    Parameters
    ----------
    extra:
        Optional mapping merged into the returned dict (values from *extra*
        take precedence over computed values so callers can override fields).

    Returns
    -------
    dict with keys:
        timestamp, hostname, platform, user, uid (Linux/macOS only),
        pid, parent_pid, parent_name, parent_cmdline, process_tree,
        working_directory, plus any keys from *extra*.
    """
    ctx: dict[str, Any] = {}

    # --- basic identity ---------------------------------------------------
    ctx["timestamp"] = _utc_now()
    ctx["hostname"] = _safe(socket.gethostname, "unknown")
    ctx["platform"] = platform.system().lower()  # 'linux', 'windows', 'darwin'
    ctx["user"] = _safe(getpass.getuser, "unknown")

    # uid is not meaningful on Windows (and os.getuid doesn't exist there).
    if hasattr(os, "getuid"):
        ctx["uid"] = _safe(os.getuid, None)

    # --- current process --------------------------------------------------
    current_pid = os.getpid()
    ctx["pid"] = current_pid

    try:
        current_proc = psutil.Process(current_pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        current_proc = None

    # --- parent process ---------------------------------------------------
    parent_pid: int | None = None
    parent_name: str | None = None
    parent_cmdline: list[str] | None = None

    if current_proc is not None:
        try:
            parent = current_proc.parent()
            if parent is not None:
                parent_pid = parent.pid
                parent_name = _proc_name(parent)
                parent_cmdline = _proc_cmdline(parent)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    ctx["parent_pid"] = parent_pid
    ctx["parent_name"] = parent_name
    ctx["parent_cmdline"] = parent_cmdline

    # --- process tree (ancestors) ----------------------------------------
    ctx["process_tree"] = _build_process_tree(current_proc)

    # --- working directory ------------------------------------------------
    cwd: str | None = None
    if current_proc is not None:
        try:
            cwd = current_proc.cwd()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if cwd is None:
        cwd = _safe(os.getcwd, None)
    ctx["working_directory"] = cwd

    # --- merge caller-supplied extras ------------------------------------
    if extra:
        ctx.update(extra)

    return ctx


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    """ISO 8601 timestamp in UTC."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _safe(fn, fallback):
    """Call *fn()* and return *fallback* on any exception."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return fallback


def _proc_name(proc: psutil.Process) -> str | None:
    """Return process name, None on access error."""
    try:
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _proc_cmdline(proc: psutil.Process) -> list[str] | None:
    """Return command-line argv list, None on access error."""
    try:
        return proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _proc_info(proc: psutil.Process) -> dict[str, Any]:
    """Return a compact dict describing a single process."""
    return {
        "pid": proc.pid,
        "name": _proc_name(proc),
        "cmdline": _proc_cmdline(proc),
    }


def _build_process_tree(start_proc: psutil.Process | None) -> list[dict[str, Any]]:
    """Walk up the parent chain from *start_proc* to PID 1 / system root.

    Returns a list ordered from *start_proc*'s parent to the oldest ancestor.
    The start process itself is excluded (it is already captured as pid /
    parent_pid / parent_name / parent_cmdline at the top level).

    Terminates when:
    - we reach PID 0 or PID 1 on POSIX (init / launchd / systemd)
    - we reach PID 4 or lower on Windows (System / Idle processes)
    - the process no longer exists
    - we detect a cycle (pid seen twice — shouldn't happen on a healthy OS)
    - we have walked more than 64 levels (safety guard)
    """
    tree: list[dict[str, Any]] = []

    if start_proc is None:
        return tree

    seen_pids: set[int] = {start_proc.pid}
    max_depth = 64
    depth = 0

    try:
        current = start_proc.parent()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return tree

    while current is not None and depth < max_depth:
        depth += 1
        pid = current.pid

        # Stop at OS roots.
        if pid in (0, 1):
            tree.append({"pid": pid, "name": _proc_name(current), "cmdline": None})
            break

        # Windows: PID 4 is the System process, PID 0 is Idle.
        if platform.system() == "Windows" and pid <= 4:
            tree.append({"pid": pid, "name": _proc_name(current), "cmdline": None})
            break

        # Cycle guard (should never happen, but be paranoid).
        if pid in seen_pids:
            break
        seen_pids.add(pid)

        tree.append(_proc_info(current))

        try:
            current = current.parent()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            break

    return tree
