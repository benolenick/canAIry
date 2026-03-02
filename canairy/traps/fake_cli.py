"""Fake CLI tool trap generator.

Generates standalone Python scripts that impersonate AI CLI tools (ollama, claude,
codex, gemini, aider). When invoked by an attacker, each script fires an alert to
the configured webhook, then simulates the real interactive TUI of the tool —
capturing every line of attacker input and firing additional alerts.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Standalone script template
# ---------------------------------------------------------------------------
# Placeholders filled at install time:
#   {WEBHOOK_URL_REPR}  – repr() of the webhook URL string
#   {TOOL_NAME_REPR}    – repr() of the tool name string
#   {TOOL_LOGIC}        – indented block that defines _run_tool()

_SCRIPT_TEMPLATE = r'''#!/usr/bin/env python3
"""Fake {TOOL_NAME} CLI — canAIry honeypot trap."""

import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration (embedded at install time)
# ---------------------------------------------------------------------------

_WEBHOOK_URL = {WEBHOOK_URL_REPR}
_TOOL_NAME = {TOOL_NAME_REPR}

# ---------------------------------------------------------------------------
# Forensics capture
# ---------------------------------------------------------------------------

def _capture_context(extra=None):
    ctx = {{
        "tool": _TOOL_NAME,
        "argv": sys.argv[1:],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.getfqdn(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "uid": None,
        "username": None,
        "ppid": os.getppid(),
        "env_vars": {{
            k: os.environ.get(k, "")
            for k in (
                "PATH", "HOME", "USER", "LOGNAME", "SHELL",
                "TERM", "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY",
                "SUDO_USER", "DISPLAY",
            )
        }},
    }}
    if extra:
        ctx.update(extra)
    try:
        ctx["uid"] = os.getuid()  # type: ignore[attr-defined]
    except AttributeError:
        pass
    try:
        import pwd
        ctx["username"] = pwd.getpwuid(os.getuid()).pw_name  # type: ignore[attr-defined]
    except Exception:
        ctx["username"] = os.environ.get("USER") or os.environ.get("USERNAME", "unknown")

    try:
        with open(f"/proc/{{os.getppid()}}/comm") as fh:
            ctx["parent_comm"] = fh.read().strip()
    except Exception:
        try:
            result = subprocess.run(
                ["ps", "-p", str(os.getppid()), "-o", "comm="],
                capture_output=True, text=True, timeout=2,
            )
            ctx["parent_comm"] = result.stdout.strip()
        except Exception:
            ctx["parent_comm"] = "unknown"

    for hist_file in ("~/.bash_history", "~/.zsh_history", "~/.sh_history"):
        expanded = os.path.expanduser(hist_file)
        if os.path.exists(expanded):
            try:
                with open(expanded, "rb") as fh:
                    fh.seek(0, 2)
                    size = fh.tell()
                    fh.seek(max(0, size - 512))
                    ctx["shell_history_tail"] = fh.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            break

    return ctx


# ---------------------------------------------------------------------------
# Alert sender
# ---------------------------------------------------------------------------

def _send_alert(trap_name, context):
    if not _WEBHOOK_URL:
        return
    alert = {{
        "trap_type": "fake_cli",
        "trap_name": trap_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": context,
    }}
    try:
        payload = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            _WEBHOOK_URL,
            data=payload,
            headers={{"Content-Type": "application/json", "User-Agent": "canairy/0.1"}},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Never crash — stay invisible


# ---------------------------------------------------------------------------
# Shared interactive helpers
# ---------------------------------------------------------------------------

def _thinking(label="Thinking"):
    """Print an animated ellipsis then clear the line."""
    sys.stdout.write(f"  {{label}}")
    sys.stdout.flush()
    for _ in range(3):
        time.sleep(0.4)
        sys.stdout.write(".")
        sys.stdout.flush()
    time.sleep(0.3)
    sys.stdout.write("\r" + " " * (len(label) + 6) + "\r")
    sys.stdout.flush()


def _classify_input(text):
    tl = text.lower()
    if any(w in tl for w in ("file", "open", "read", "cat", "ls", "dir", "path", "/")):
        return "file"
    if any(w in tl for w in ("bug", "error", "fix", "crash", "exception", "fail", "broken")):
        return "error"
    return "default"


def _generic_response(text):
    kind = _classify_input(text)
    if kind == "file":
        print("  I'll look at that file for you...")
        time.sleep(0.6)
        print("  I can see the file. What would you like me to do with it?")
    elif kind == "error":
        print("  Let me analyze that...")
        time.sleep(0.6)
        print("  I found a potential issue. Would you like me to fix it?")
    else:
        print("  I understand. Let me think about that...")
        time.sleep(0.5)
        print("  Here's what I'd suggest: review the relevant code section and ensure")
        print("  the logic aligns with the intended behaviour. Let me know if you'd")
        print("  like me to make specific changes.")


# ---------------------------------------------------------------------------
# Tool-specific logic
# ---------------------------------------------------------------------------

{TOOL_LOGIC}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        ctx = _capture_context()
        _send_alert(f"Fake CLI invoked: {{_TOOL_NAME}}", ctx)
    except Exception:
        pass
    try:
        _run_tool()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
'''

# ---------------------------------------------------------------------------
# Per-tool logic blocks
# Each defines _run_tool() and any helper functions needed.
# Written as raw strings; NO outer indentation expected here — the template
# drops them in verbatim after the shared helpers.
# ---------------------------------------------------------------------------

_TOOL_LOGIC: dict[str, str] = {

# ── claude ──────────────────────────────────────────────────────────────────
"claude": r'''
_CLAUDE_HELP = """
/help        Show this help
/clear       Clear conversation
/model       Show current model
/exit        Exit Claude Code
"""

def _claude_banner():
    cwd = os.getcwd()
    print("\u256d\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e")
    print("\u2502        Claude Code v2.1.63             \u2502")
    print("\u2502        Model: claude-opus-4-20250514   \u2502")
    print("\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f")
    print()
    print("  Tips for getting started:")
    print("  - Ask me to help with coding tasks")
    print("  - I can edit files, run commands, and search code")
    print("  - Type /help for available commands")
    print()
    print(f"cwd: {cwd}")
    print()


def _run_tool():
    args = sys.argv[1:]
    cmd = args[0] if args else ""

    if cmd in ("--version", "-v"):
        print("2.1.63")
        return

    if cmd in ("--help", "-h"):
        print("Claude Code v2.1.63")
        print()
        print("Usage: claude [options]")
        print()
        print("Options:")
        print("  -p, --print              Print response without interactive mode")
        print("  --model <model>          Model to use")
        print("  --api-key <key>          Anthropic API key")
        print("  -v, --version            Show version")
        print("  -h, --help               Show help")
        return

    if cmd in ("-p", "--print") and len(args) > 1:
        prompt = " ".join(args[1:])
        _thinking("Thinking")
        _generic_response(prompt)
        return

    # Interactive mode
    _claude_banner()
    session_history = []

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            print()
            break

        if not line:
            continue

        session_history.append(line)

        if line in ("/exit", "/quit", "exit", "quit"):
            break

        if line == "/help":
            print(_CLAUDE_HELP)
            continue

        if line == "/clear":
            session_history.clear()
            print("  Conversation cleared.")
            continue

        if line == "/model":
            print("  Current model: claude-opus-4-20250514")
            continue

        # Fire alert for this input
        try:
            ctx = _capture_context({{
                "input_text": line,
                "session_history": session_history,
            }})
            _send_alert(f"Fake CLI input: claude - {line}", ctx)
        except Exception:
            pass

        _thinking()
        _generic_response(line)
        print()
''',

# ── codex ────────────────────────────────────────────────────────────────────
"codex": r'''
_CODEX_HELP = """
Commands:
  /help        Show this help
  /model       Show current model
  /clear       Clear session
  /exit        Exit
"""

def _codex_banner():
    print("codex v0.7.2")
    print("Model: o4-mini")
    print("Approval mode: suggest")
    print()


def _run_tool():
    args = sys.argv[1:]
    cmd = args[0] if args else ""

    if cmd in ("--version", "-v", "version"):
        print("codex/0.7.2 linux-x64 node-v22.14.0")
        return

    if cmd in ("--help", "-h", "help"):
        print("""codex - OpenAI Codex CLI

Usage: codex [options] [prompt]

Options:
  -m, --model <model>       Model ID to use (default: o4-mini)
  --approval-mode <mode>    Approval mode: suggest, auto-edit, full-auto
  --no-project-doc          Do not include project documentation
  -q, --quiet               Non-interactive mode
  -v, --version             Show version
  -h, --help                Show help
""")
        return

    # If a prompt is supplied non-interactively
    if cmd and not cmd.startswith("/") and not cmd.startswith("-"):
        prompt = " ".join(args)
        _codex_banner()
        _thinking("Thinking")
        _generic_response(prompt)
        return

    # Interactive mode
    _codex_banner()
    session_history = []

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            print()
            break

        if not line:
            continue

        session_history.append(line)

        if line in ("/exit", "/quit", "exit", "quit"):
            break

        if line == "/help":
            print(_CODEX_HELP)
            continue

        if line == "/clear":
            session_history.clear()
            print("  Session cleared.")
            continue

        if line == "/model":
            print("  Current model: o4-mini")
            continue

        try:
            ctx = _capture_context({{
                "input_text": line,
                "session_history": session_history,
            }})
            _send_alert(f"Fake CLI input: codex - {line}", ctx)
        except Exception:
            pass

        _thinking()
        _generic_response(line)
        print()
''',

# ── gemini ───────────────────────────────────────────────────────────────────
"gemini": r'''
_GEMINI_HELP = """
Commands:
  /help        Show this help
  /model       Show current model
  /clear       Clear conversation
  /exit        Exit
"""

def _gemini_banner():
    print("\u2726 Welcome to Gemini CLI (v1.0.5)")
    print()
    print("You're connected to: gemini-2.5-flash")
    print()


def _run_tool():
    args = sys.argv[1:]
    cmd = args[0] if args else ""

    if cmd in ("--version", "-v", "version"):
        print("gemini-cli/1.0.5")
        return

    if cmd in ("--help", "-h", "help"):
        print("""gemini - Google Gemini CLI

Usage: gemini [options] [prompt]

Options:
  -m, --model <model>       Model to use (default: gemini-2.5-flash)
  -p, --prompt <text>       Run a single prompt non-interactively
  --sandbox                 Run in sandbox mode
  -v, --version             Show version
  -h, --help                Show help
""")
        return

    # Interactive mode (default)
    _gemini_banner()
    session_history = []

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            print()
            break

        if not line:
            continue

        session_history.append(line)

        if line in ("/exit", "/quit", "exit", "quit"):
            break

        if line == "/help":
            print(_GEMINI_HELP)
            continue

        if line == "/clear":
            session_history.clear()
            print("  Conversation cleared.")
            continue

        if line == "/model":
            print("  Current model: gemini-2.5-flash")
            continue

        try:
            ctx = _capture_context({{
                "input_text": line,
                "session_history": session_history,
            }})
            _send_alert(f"Fake CLI input: gemini - {line}", ctx)
        except Exception:
            pass

        _thinking()
        _generic_response(line)
        print()
''',

# ── ollama ───────────────────────────────────────────────────────────────────
"ollama": r'''
def _ollama_chat_loop(model):
    """Simulate an interactive ollama chat session."""
    print(f">>> Send a message (/? for help)")
    session_history = []

    while True:
        try:
            line = input(">>> ").strip()
        except EOFError:
            print()
            break

        if not line:
            continue

        session_history.append(line)

        if line in ("/bye", "/exit", "/quit"):
            print("Goodbye!")
            break

        if line == "/?":
            print("""Available Commands:
  /set            Set session variables
  /show           Show model information
  /load <model>   Load a session or model
  /save <name>    Save your current session
  /clear          Clear session context
  /bye            Exit
  /?              Help for a command
""")
            continue

        if line == "/clear":
            session_history.clear()
            print("Cleared session context")
            continue

        try:
            ctx = _capture_context({{
                "input_text": line,
                "session_history": session_history,
                "ollama_model": model,
            }})
            _send_alert(f"Fake CLI input: ollama - {line}", ctx)
        except Exception:
            pass

        _thinking()
        _generic_response(line)
        print()


def _run_tool():
    args = sys.argv[1:]
    cmd = args[0] if args else ""

    if not args:
        print("""Large language model runner

Usage:
  ollama [flags]
  ollama [command]

Available Commands:
  serve       Start ollama
  create      Create a model from a Modelfile
  show        Show information for a model
  run         Run a model
  pull        Pull a model from a registry
  push        Push a model to a registry
  list        List models
  ps          List running models
  cp          Copy a model
  rm          Remove a model
  help        Help about any command

Flags:
  -h, --help      help for ollama
  -v, --version   Show version information

Use "ollama [command] --help" for more information about a command.""")
        return

    if cmd in ("list", "ls"):
        print(f"{'NAME':<30} {'ID':<15} {'SIZE':<10} {'MODIFIED':<20}")
        models = [
            ("llama3:latest",        "365c0bd3c000", "4.7 GB",  "2 weeks ago"),
            ("mistral:7b-instruct",  "7f859a2a652c", "4.1 GB",  "3 weeks ago"),
            ("codellama:13b",        "9f438cb9cd58", "7.4 GB",  "1 month ago"),
            ("deepseek-coder:6.7b",  "a1e4937c0073", "3.8 GB",  "1 month ago"),
        ]
        for name, mid, size, modified in models:
            print(f"{name:<30} {mid:<15} {size:<10} {modified:<20}")
        return

    if cmd == "run":
        model = args[1] if len(args) > 1 else "llama3"
        _ollama_chat_loop(model)
        return

    if cmd == "pull":
        model = args[1] if len(args) > 1 else "llama3"
        print(f"pulling manifest ")
        for pct in (25, 50, 75, 100):
            filled = pct // 5
            bar = "\u2588" * filled + "\u2591" * (20 - filled)
            mb_done = int(4661 * pct / 100)
            print(f"\rpulling {bar} {pct}% ({mb_done} MB/4661 MB)", end="", flush=True)
            time.sleep(0.3)
        print("\nverifying sha256 digest ")
        print("writing manifest ")
        print("success ")
        return

    if cmd == "serve":
        print("Error: listen tcp 127.0.0.1:11434: bind: address already in use")
        sys.exit(1)

    if cmd == "ps":
        print(f"{'NAME':<30} {'ID':<15} {'SIZE':<10} {'PROCESSOR':<15} {'UNTIL'}")
        print(f"{'llama3:latest':<30} {'365c0bd3c000':<15} {'5.8 GB':<10} {'100% GPU':<15} {'4 minutes from now'}")
        return

    if cmd in ("--version", "-v", "version"):
        print("ollama version is 0.3.12")
        return

    if cmd == "show":
        print("  Model")
        print("    architecture\tllama")
        print("    parameters\t8B")
        print("    context length\t8192")
        print("    embedding length\t4096")
        print("    quantization\tQ4_0")
        print()
        print("  Parameters")
        print('    stop\t"<|start_header_id|>"')
        print('    stop\t"<|end_header_id|>"')
        print('    stop\t"<|eot_id|>"')
        print()
        print("  License")
        print("    LLAMA 3 COMMUNITY LICENSE AGREEMENT")
        return

    print(f'Error: unknown command "{cmd}" for "ollama"')
    print("Run 'ollama --help' for usage.")
    sys.exit(1)
''',

# ── aider ────────────────────────────────────────────────────────────────────
"aider": r'''
_AIDER_HELP = """
aider commands:
  /add <file>      Add files to the chat
  /drop <file>     Remove files from the chat
  /ls              List files in chat
  /diff            Show last diff
  /git <cmd>       Run a git command
  /run <cmd>       Run a shell command
  /undo            Undo last git commit
  /clear           Clear chat history
  /help            Show this help
  /exit            Exit
"""

def _aider_banner():
    import subprocess as _sp
    try:
        result = _sp.run(["git", "rev-list", "--count", "HEAD"],
                         capture_output=True, text=True, timeout=2)
        count = result.stdout.strip() or "42"
    except Exception:
        count = "42"
    print("Aider v0.82.0")
    print("Model: claude-sonnet-4-5 with diff edit format")
    print(f"Git repo: .git with {count} files")
    print("Repo-map: using 1024 tokens, auto refresh")
    print()


def _run_tool():
    args = sys.argv[1:]
    cmd = args[0] if args else ""

    if cmd in ("--version", "-v", "version"):
        print("aider v0.82.0")
        return

    if cmd in ("--help", "-h", "help"):
        print("""aider v0.82.0

Aider is AI pair programming in your terminal.

Usage:
  aider [options] [FILE...]

Options:
  --model MODEL               Specify the model to use
  --opus                      Use claude-opus-4-20250514
  --sonnet                    Use claude-sonnet-4-5
  --no-git                    Do not look for a git repo
  --auto-commits              Enable auto commit of LLM changes
  --api-key PROVIDER=KEY      Set an API key for a provider
  -v, --version               Show version and exit
  -h, --help                  Show help
""")
        return

    # Interactive mode
    _aider_banner()
    session_history = []
    chat_files = []

    # Pre-add any file args
    for a in args:
        if not a.startswith("-") and os.path.exists(a):
            chat_files.append(a)
            print(f"Added {a} to the chat.")

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            print()
            break

        if not line:
            continue

        session_history.append(line)

        lc = line.lower()

        if lc in ("/exit", "/quit", "exit", "quit"):
            break

        if lc == "/help":
            print(_AIDER_HELP)
            continue

        if lc == "/clear":
            session_history.clear()
            print("  Chat history cleared.")
            continue

        if lc == "/ls":
            if chat_files:
                for f in chat_files:
                    print(f"  {f}")
            else:
                print("  (no files in chat)")
            continue

        if lc.startswith("/add "):
            fname = line[5:].strip()
            chat_files.append(fname)
            print(f"  Added {fname} to the chat.")
            continue

        if lc.startswith("/drop "):
            fname = line[6:].strip()
            if fname in chat_files:
                chat_files.remove(fname)
                print(f"  Removed {fname} from the chat.")
            else:
                print(f"  {fname} not in chat.")
            continue

        try:
            ctx = _capture_context({{
                "input_text": line,
                "session_history": session_history,
                "chat_files": chat_files,
            }})
            _send_alert(f"Fake CLI input: aider - {line}", ctx)
        except Exception:
            pass

        _thinking()
        _generic_response(line)
        print()
''',

}  # end _TOOL_LOGIC


# ---------------------------------------------------------------------------
# Canary marker used to detect our own fakes
# ---------------------------------------------------------------------------

_CANARY_MARKER = "canAIry honeypot trap"

# Real tool names and their renamed variants
_REAL_TOOL_MAP: dict[str, str] = {
    "claude": "claudereal",
    "codex":  "codexreal",
    "gemini": "geminireal",
    "ollama": "ollamareal",
    "aider":  "aiderreal",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_install_dir(config: dict) -> Path:
    """Return the directory where fake CLI scripts will be installed.

    On Linux/macOS: ``config["install_path"]`` → ``~/.local/bin`` → ``/usr/local/bin``
    On Windows: ``~/.canairy/bin`` (user must add this to PATH manually).
    """
    if platform.system() == "Windows":
        target = Path.home() / ".canairy" / "bin"
        target.mkdir(parents=True, exist_ok=True)
        return target

    # Unix
    configured = config.get("install_path", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    local_bin = Path.home() / ".local" / "bin"
    if local_bin.exists() and os.access(str(local_bin), os.W_OK):
        return local_bin

    usr_local = Path("/usr/local/bin")
    if usr_local.exists() and os.access(str(usr_local), os.W_OK):
        return usr_local

    # Fallback: create ~/.local/bin
    local_bin.mkdir(parents=True, exist_ok=True)
    return local_bin


def _build_script(tool_name: str, webhook_url: str) -> str:
    """Render the full script source for a given tool."""
    logic = _TOOL_LOGIC.get(tool_name)
    if logic is None:
        raise ValueError(f"No tool logic defined for: {tool_name!r}")

    return _SCRIPT_TEMPLATE.format(
        TOOL_NAME=tool_name,
        WEBHOOK_URL_REPR=repr(webhook_url),
        TOOL_NAME_REPR=repr(tool_name),
        TOOL_LOGIC=logic,
    )


def _script_path(install_dir: Path, tool_name: str) -> Path:
    if platform.system() == "Windows":
        return install_dir / f"{tool_name}.py"
    return install_dir / tool_name


def _is_our_fake(path: Path) -> bool:
    """Return True if *path* is a canAIry-generated fake script."""
    try:
        with path.open("rb") as fh:
            head = fh.read(1024).decode("utf-8", errors="replace")
        return _CANARY_MARKER in head
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def install_fake_clis(config: dict, alerter_config: dict) -> list[Path]:
    """Write fake CLI scripts to the install directory.

    Parameters
    ----------
    config:
        The ``traps.fake_cli`` section of the canAIry config.
    alerter_config:
        The ``alerts`` section — used to extract the webhook URL.

    Returns
    -------
    list[Path]
        Paths of all successfully installed scripts.
    """
    tools: list[str] = config.get("tools", list(_TOOL_LOGIC.keys()))
    install_dir = get_install_dir(config)

    # Extract webhook URL
    webhook_url: str = alerter_config.get("webhook", {}).get("url", "") or ""

    installed: list[Path] = []
    for tool in tools:
        if tool not in _TOOL_LOGIC:
            logger.warning("No fake CLI template for tool %r — skipping.", tool)
            continue
        try:
            script_text = _build_script(tool, webhook_url)
            dest = _script_path(install_dir, tool)
            dest.write_text(script_text, encoding="utf-8")

            if platform.system() != "Windows":
                current_mode = dest.stat().st_mode
                dest.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            installed.append(dest)
            logger.info("Installed fake %s CLI at %s", tool, dest)
        except Exception as exc:
            logger.error("Failed to install fake %s CLI: %s", tool, exc)

    if platform.system() == "Windows" and installed:
        print(
            f"\n[canairy] Fake CLIs installed to: {install_dir}\n"
            f"Add this directory to your PATH:\n"
            f'  $env:PATH = "{install_dir};$env:PATH"\n'
        )

    return installed


def uninstall_fake_clis(config: dict) -> list[Path]:
    """Remove all fake CLI scripts from the install directory.

    Returns
    -------
    list[Path]
        Paths of scripts that were successfully removed.
    """
    tools: list[str] = config.get("tools", list(_TOOL_LOGIC.keys()))
    install_dir = get_install_dir(config)

    removed: list[Path] = []
    for tool in tools:
        dest = _script_path(install_dir, tool)
        if dest.exists():
            try:
                dest.unlink()
                removed.append(dest)
                logger.info("Removed fake %s CLI from %s", tool, dest)
            except OSError as exc:
                logger.error("Failed to remove %s: %s", dest, exc)

    return removed


def rename_real_tools(config: dict) -> dict[str, tuple[Path, Path]]:
    """Find real tool binaries on PATH and rename them to ``*real`` variants.

    For each tool in ``_REAL_TOOL_MAP`` (e.g. ``claude`` → ``claudereal``):

    1. Locate the binary with ``shutil.which``.
    2. Skip if the binary is already a canAIry fake (checked by marker string).
    3. Skip if the ``*real`` variant already exists (idempotent).
    4. Rename ``claude`` → ``claudereal`` in place.

    Parameters
    ----------
    config:
        The ``traps.fake_cli`` section of the canAIry config (currently unused
        but kept for future extension / symmetry with other API functions).

    Returns
    -------
    dict[str, tuple[Path, Path]]
        Mapping of ``tool_name -> (original_path, renamed_path)`` for every
        rename that succeeded.
    """
    renamed: dict[str, tuple[Path, Path]] = {}

    for tool, real_name in _REAL_TOOL_MAP.items():
        found = shutil.which(tool)
        if not found:
            logger.debug("rename_real_tools: %r not found on PATH — skipping.", tool)
            continue

        original = Path(found)

        # Don't rename our own fakes
        if _is_our_fake(original):
            logger.debug("rename_real_tools: %s is already a canAIry fake — skipping.", original)
            continue

        # Preserve original extension (e.g. .CMD, .EXE on Windows)
        dest = original.parent / (real_name + original.suffix)

        # Idempotent: already renamed (check with and without extension)
        if dest.exists() or (original.parent / real_name).exists():
            logger.debug("rename_real_tools: %s already exists — skipping.", dest)
            continue

        try:
            original.rename(dest)
            renamed[tool] = (original, dest)
            logger.info("Renamed %s -> %s", original, dest)
        except OSError as exc:
            logger.error("Failed to rename %s -> %s: %s", original, dest, exc)

    return renamed


def restore_real_tools(config: dict) -> list[str]:
    """Reverse ``rename_real_tools``: rename ``claudereal`` → ``claude``, etc.

    Only restores a ``*real`` binary if the corresponding plain name either
    does not exist, or currently exists as a canAIry fake (so the fake is
    overwritten by the real tool on restore).

    Parameters
    ----------
    config:
        The ``traps.fake_cli`` section of the canAIry config.

    Returns
    -------
    list[str]
        Names of tools that were successfully restored.
    """
    restored: list[str] = []

    for tool, real_name in _REAL_TOOL_MAP.items():
        # Look for the renamed binary anywhere on PATH (with or without ext)
        found = shutil.which(real_name)
        if not found:
            # Also check same directory as our fake, if installed
            try:
                install_dir = get_install_dir(config)
                # Try with common extensions too (.cmd, .exe)
                for ext in ("", ".cmd", ".exe", ".CMD", ".EXE"):
                    candidate = install_dir / (real_name + ext)
                    if candidate.exists():
                        found = str(candidate)
                        break
            except Exception:
                pass

        if not found:
            logger.debug("restore_real_tools: %r not found — skipping.", real_name)
            continue

        real_path = Path(found)
        # Restore to original name with same extension
        original = real_path.parent / (tool + real_path.suffix)

        # If the plain name exists and is NOT our fake, leave it alone
        if original.exists() and not _is_our_fake(original):
            logger.warning(
                "restore_real_tools: %s exists and is not a canAIry fake — skipping restore.",
                original,
            )
            continue

        # Remove the fake if present so the rename can succeed
        if original.exists():
            try:
                original.unlink()
            except OSError as exc:
                logger.error("restore_real_tools: could not remove fake %s: %s", original, exc)
                continue

        try:
            real_path.rename(original)
            restored.append(tool)
            logger.info("Restored %s -> %s", real_path, original)
        except OSError as exc:
            logger.error("Failed to restore %s -> %s: %s", real_path, original, exc)

    return restored
