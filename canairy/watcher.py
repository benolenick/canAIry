"""Cross-platform filesystem access watcher for canAIry traps.

Uses the ``watchdog`` library to monitor directories containing planted canary
files.  When any file is accessed or modified, an alert is fired through the
async alerter.  The watchdog observers run in daemon threads but dispatch alerts
back onto the asyncio event loop via ``asyncio.run_coroutine_threadsafe``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

try:
    from canairy.forensics import capture_context  # type: ignore[import]
except ImportError:
    capture_context = None  # forensics module is optional

logger = logging.getLogger(__name__)

# Cooldown: don't re-alert the same path more than once per N seconds.
_COOLDOWN_SECONDS = 10.0

# Directories that belong to canAIry itself — never alert on these.
_OWN_DIRS = frozenset([
    str(Path.home() / ".canairy"),
])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _friendly_path(path: str) -> str:
    """Replace home directory prefix with ~ for readability in alert names."""
    try:
        rel = Path(path).relative_to(Path.home())
        return "~/" + str(rel).replace("\\", "/")
    except ValueError:
        return path


def _is_own_path(path: str) -> bool:
    """Return True if *path* is inside one of canAIry's own directories."""
    abs_path = str(Path(path).resolve())
    for own in _OWN_DIRS:
        try:
            own_resolved = str(Path(own).resolve())
            if abs_path == own_resolved or abs_path.startswith(own_resolved + os.sep):
                return True
        except Exception:
            pass
    return False


def _basic_forensics(src_path: str) -> dict[str, Any]:
    """Gather available forensic context without importing the forensics module."""
    ctx: dict[str, Any] = {
        "timestamp": _now_iso(),
        "hostname": socket.getfqdn(),
        "platform": platform.platform(),
        "file_path": src_path,
        "cwd": None,
        "uid": None,
        "username": None,
        "ppid": os.getppid(),
    }

    try:
        ctx["cwd"] = os.getcwd()
    except Exception:
        pass

    try:
        ctx["uid"] = os.getuid()  # type: ignore[attr-defined]
    except AttributeError:
        pass

    try:
        import pwd  # type: ignore[import]
        ctx["username"] = pwd.getpwuid(os.getuid()).pw_name  # type: ignore[attr-defined]
    except Exception:
        ctx["username"] = (
            os.environ.get("USER")
            or os.environ.get("USERNAME")
            or "unknown"
        )

    # File stat info
    try:
        st = os.stat(src_path)
        ctx["file_size"] = st.st_size
        ctx["file_mtime"] = st.st_mtime
    except Exception:
        pass

    return ctx


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------


class CanairyEventHandler(FileSystemEventHandler):
    """Watchdog event handler that fires canAIry alerts on file system events.

    Parameters
    ----------
    alerter:
        Object with ``async alerter.send(alert_dict)`` method.
    trap_type:
        The ``trap_type`` field sent in every alert (e.g. ``"canary_key"``).
    loop:
        The running asyncio event loop.  Alerts are dispatched onto this loop
        via ``asyncio.run_coroutine_threadsafe`` so we never block watchdog's
        observer thread.
    """

    def __init__(
        self,
        alerter: Any,
        trap_type: str,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        super().__init__()
        self.alerter = alerter
        self.trap_type = trap_type
        self.loop = loop
        self._cooldown: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_on_cooldown(self, path: str) -> bool:
        last = self._cooldown.get(path, 0.0)
        return (time.monotonic() - last) < _COOLDOWN_SECONDS

    def _touch_cooldown(self, path: str) -> None:
        self._cooldown[path] = time.monotonic()

    def _build_alert(self, event: FileSystemEvent) -> dict[str, Any]:
        src = event.src_path
        friendly = _friendly_path(src)

        # Determine a human-readable trap name based on path prefix
        if ".ollama" in src:
            trap_name = f"Config accessed: {friendly}"
        elif ".config/claude" in src or "AppData/Roaming/claude" in src:
            trap_name = f"Config accessed: {friendly}"
        elif ".config/github-copilot" in src or "AppData/Local/github-copilot" in src:
            trap_name = f"Config accessed: {friendly}"
        else:
            trap_name = f"File accessed: {friendly}"

        # Prefer the full forensics module if available
        if capture_context is not None:
            try:
                forensics = capture_context()
            except Exception:
                forensics = _basic_forensics(src)
        else:
            forensics = _basic_forensics(src)

        return {
            "trap_type": self.trap_type,
            "trap_name": trap_name,
            "timestamp": _now_iso(),
            "details": {
                "event_type": event.event_type,
                "src_path": src,
                "is_directory": event.is_directory,
                "friendly_path": friendly,
                "forensics": forensics,
            },
        }

    async def _send_alert(self, alert: dict[str, Any]) -> None:
        try:
            await self.alerter.send(alert)
        except Exception as exc:
            logger.warning("Failed to send watcher alert: %s", exc)

    # ------------------------------------------------------------------
    # Watchdog interface
    # ------------------------------------------------------------------

    def on_any_event(self, event: FileSystemEvent) -> None:
        # Skip directory events — only care about file-level access
        if event.is_directory:
            return

        src_path: str = event.src_path

        # Never alert on our own config dir
        if _is_own_path(src_path):
            return

        # Skip hidden OS metadata files
        basename = os.path.basename(src_path)
        if basename.startswith(".") and basename in (
            ".DS_Store", ".localized", "Thumbs.db", "desktop.ini",
        ):
            return

        # Cooldown check
        if self._is_on_cooldown(src_path):
            return
        self._touch_cooldown(src_path)

        try:
            alert = self._build_alert(event)
        except Exception as exc:
            logger.warning("Failed to build watcher alert for %s: %s", src_path, exc)
            return

        # Dispatch the coroutine onto the asyncio loop from this watchdog thread
        if self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self._send_alert(alert), self.loop)
        else:
            logger.warning(
                "Asyncio loop is not running — dropping alert for %s", src_path
            )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def start_watcher(
    paths: list[Path],
    alerter: Any,
    trap_type: str = "canary_key",
) -> list[Observer]:
    """Start watchdog observers for the given paths.

    Each path gets its own ``Observer`` so that paths on different filesystems
    (or with different inotify requirements) are handled independently.

    Parameters
    ----------
    paths:
        List of files or directories to monitor.  Directories are watched
        recursively.
    alerter:
        Object with ``async alerter.send(alert_dict)`` method.
    trap_type:
        Value for the ``trap_type`` field in every alert.

    Returns
    -------
    list[Observer]
        Running Observer instances.  Call ``observer.stop(); observer.join()``
        on each to shut down cleanly.
    """
    loop = asyncio.get_running_loop()
    handler = CanairyEventHandler(alerter=alerter, trap_type=trap_type, loop=loop)

    observers: list[Observer] = []
    watched: set[str] = set()

    for path in paths:
        path = Path(path).expanduser().resolve()

        # For a file, watch its parent directory and rely on the handler to
        # filter events by filename.  For directories, watch the directory itself.
        if path.is_file():
            watch_root = str(path.parent)
            recursive = False
        elif path.is_dir():
            watch_root = str(path)
            recursive = True
        else:
            # Path doesn't exist yet — watch the closest existing ancestor
            ancestor = path
            while not ancestor.exists() and ancestor != ancestor.parent:
                ancestor = ancestor.parent
            watch_root = str(ancestor)
            recursive = True
            logger.info(
                "Watched path %s does not exist; watching ancestor %s instead.",
                path,
                watch_root,
            )

        if watch_root in watched:
            logger.debug("Already watching %s — skipping duplicate.", watch_root)
            continue
        watched.add(watch_root)

        observer = Observer()
        observer.schedule(handler, watch_root, recursive=recursive)
        observer.daemon = True
        observer.start()
        observers.append(observer)
        logger.info(
            "Watcher started: %s (recursive=%s, trap_type=%r)",
            watch_root,
            recursive,
            trap_type,
        )

    return observers


async def stop_watchers(observers: list[Observer]) -> None:
    """Stop and join all observers gracefully.

    Runs the blocking ``observer.join()`` calls in a thread pool to avoid
    blocking the event loop.
    """
    for obs in observers:
        obs.stop()

    loop = asyncio.get_running_loop()
    for obs in observers:
        await loop.run_in_executor(None, obs.join)
        logger.debug("Observer stopped: %s", obs)
