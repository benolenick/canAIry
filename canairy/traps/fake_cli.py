"""Fake CLI tool trap generator.

Generates standalone Python scripts that impersonate AI CLI tools (ollama, claude,
codex, aider). When invoked by an attacker, each script fires an alert to the
configured webhook and prints realistic-looking output.
"""

from __future__ import annotations

import logging
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Script template
# ---------------------------------------------------------------------------

# The template is a self-contained Python script.  Placeholders:
#   {WEBHOOK_URL}   – the alert webhook URL
#   {TOOL_NAME}     – the name of the CLI tool being mimicked
#   {TOOL_LOGIC}    – the tool-specific output logic (indented block)
_SCRIPT_TEMPLATE = r'''#!/usr/bin/env python3
"""Fake {TOOL_NAME} CLI — canAIry honeypot trap."""

import json
import os
import platform
import socket
import subprocess
import sys
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

def _capture_context():
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
    try:
        ctx["uid"] = os.getuid()  # type: ignore[attr-defined]
    except AttributeError:
        pass
    try:
        import pwd
        ctx["username"] = pwd.getpwuid(os.getuid()).pw_name  # type: ignore[attr-defined]
    except Exception:
        ctx["username"] = os.environ.get("USER") or os.environ.get("USERNAME", "unknown")

    # Try to grab parent process name
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

    # Try to capture current shell history tail
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

def _send_alert(context):
    if not _WEBHOOK_URL:
        return
    alert = {{
        "trap_type": "fake_cli",
        "trap_name": f"Fake CLI invoked: {{_TOOL_NAME}}",
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
# Tool-specific output logic
# ---------------------------------------------------------------------------

def _run_tool():
    args = sys.argv[1:]
    cmd = args[0] if args else ""

{TOOL_LOGIC}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        ctx = _capture_context()
        _send_alert(ctx)
    except Exception:
        pass
    _run_tool()
'''

# ---------------------------------------------------------------------------
# Per-tool output logic blocks
# Indented with 4 spaces to fit inside the _run_tool() function body.
# ---------------------------------------------------------------------------

_TOOL_LOGIC: dict[str, str] = {
    "ollama": '''\
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
    elif cmd == "list" or cmd == "ls":
        print(f"{'NAME':<30} {'ID':<15} {'SIZE':<10} {'MODIFIED':<20}")
        models = [
            ("llama3:latest",        "365c0bd3c000", "4.7 GB",  "2 weeks ago"),
            ("mistral:7b-instruct",  "7f859a2a652c", "4.1 GB",  "3 weeks ago"),
            ("codellama:13b",        "9f438cb9cd58", "7.4 GB",  "1 month ago"),
            ("deepseek-coder:6.7b",  "a1e4937c0073", "3.8 GB",  "1 month ago"),
        ]
        for name, mid, size, modified in models:
            print(f"{name:<30} {mid:<15} {size:<10} {modified:<20}")
    elif cmd == "run":
        model = args[1] if len(args) > 1 else "llama3"
        print(f"Error: model \\'{model}\\' not found, try pulling it first")
        sys.exit(1)
    elif cmd == "pull":
        model = args[1] if len(args) > 1 else "llama3"
        import time
        print(f"pulling manifest ")
        for pct in (25, 50, 75, 100):
            filled = pct // 5
            bar = "█" * filled + "░" * (20 - filled)
            mb_done = int(4661 * pct / 100)
            print(f"\\rpulling {bar} {pct}% ({mb_done} MB/4661 MB)", end="", flush=True)
            time.sleep(0.3)
        print("\\nverifying sha256 digest ")
        print("writing manifest ")
        print("success ")
    elif cmd == "serve":
        print("Error: listen tcp 127.0.0.1:11434: bind: address already in use")
        sys.exit(1)
    elif cmd == "ps":
        print(f"{'NAME':<30} {'ID':<15} {'SIZE':<10} {'PROCESSOR':<15} {'UNTIL'}")
        print(f"{'llama3:latest':<30} {'365c0bd3c000':<15} {'5.8 GB':<10} {'100% GPU':<15} {'4 minutes from now'}")
    elif cmd in ("--version", "-v", "version"):
        print("ollama version is 0.3.12")
    elif cmd == "show":
        model = args[1] if len(args) > 1 else "llama3:latest"
        print(f"  Model")
        print(f"    architecture\\tllama")
        print(f"    parameters\\t8B")
        print(f"    context length\\t8192")
        print(f"    embedding length\\t4096")
        print(f"    quantization\\tQ4_0")
        print()
        print(f"  Parameters")
        print(f"    stop\\t\\"<|start_header_id|>\\"")
        print(f"    stop\\t\\"<|end_header_id|>\\"")
        print(f"    stop\\t\\"<|eot_id|>\\"")
        print()
        print(f"  License")
        print(f"    LLAMA 3 COMMUNITY LICENSE AGREEMENT")
    else:
        print(f"Error: unknown command \\"{cmd}\\" for \\"ollama\\"")
        print("Run 'ollama --help' for usage.")
        sys.exit(1)''',

    "claude": '''\
    if not args or cmd in ("--help", "-h", "help"):
        print("Claude Code v2.1.63")
        print()
        print("Usage: claude [options] [command]")
        print()
        print("Options:")
        print("  -p, --print              Print response without interactive mode")
        print("  --output-format <fmt>    Output format: text, json, stream-json")
        print("  --model <model>          Model to use (default: claude-opus-4-20250514)")
        print("  --max-tokens <n>         Maximum tokens in response")
        print("  --no-stream              Disable streaming")
        print("  --api-key <key>          Anthropic API key (or set ANTHROPIC_API_KEY)")
        print("  -v, --version            Show version")
        print("  -h, --help               Show help")
        print()
        print("Commands:")
        print("  login                    Authenticate with Anthropic")
        print("  logout                   Remove stored credentials")
        print("  config                   Manage configuration")
        print("  update                   Update Claude Code")
        print()
        print("Examples:")
        print("  claude -p \\"Explain this code\\"")
        print("  claude --model claude-3-5-sonnet-20241022 -p \\"Hello\\"")
    elif cmd in ("--version", "-v", "version"):
        print("2.1.63")
    elif cmd == "login":
        print("Error: authentication failed. Please visit https://claude.ai/settings/api-keys")
        sys.exit(1)
    elif cmd == "logout":
        print("Logged out successfully.")
    else:
        print("Error: authentication required. Run `claude login` first.")
        sys.exit(1)''',

    "codex": '''\
    if not args or cmd in ("--help", "-h", "help"):
        print("""codex - OpenAI Codex CLI

Usage: codex [options] [prompt]

Options:
  -m, --model <model>       Model ID to use (default: o4-mini)
  -i, --image <path>        Image file path or URL to include
  --approval-mode <mode>    Approval mode: suggest, auto-edit, full-auto
  --no-project-doc          Do not include project documentation
  --no-git-context          Do not include git context
  --full-stdout             Do not truncate stdout/stderr
  -q, --quiet               Non-interactive mode
  --notify                  Enable desktop notifications
  -v, --version             Show version
  -h, --help                Show help

Examples:
  codex \\"refactor this file to use async/await\\"
  codex -m o3 \\"fix the bug in main.py\\"
  codex --approval-mode full-auto \\"add unit tests\\"
""")
    elif cmd in ("--version", "-v", "version"):
        print("codex/0.7.2 linux-x64 node-v22.14.0")
    else:
        print("Error: OPENAI_API_KEY not set")
        print("Set the OPENAI_API_KEY environment variable and try again.")
        print("  export OPENAI_API_KEY=sk-proj-...")
        sys.exit(1)''',

    "aider": '''\
    if not args or cmd in ("--help", "-h", "help"):
        print("""aider v0.82.0

Aider is AI pair programming in your terminal.

Usage:
  aider [options] [FILE...]

Options:
  --model MODEL               Specify the model to use for the main chat
  --opus                      Use claude-opus-4-20250514 model for the main chat
  --sonnet                    Use claude-sonnet-4-5 model for the main chat
  --4                         Use gpt-4o model for the main chat
  --4o                        Use gpt-4o model for the main chat
  --mini                      Use gpt-4o-mini model for the main chat
  --35turbo                   Use gpt-3.5-turbo model for the main chat
  --deepseek                  Use deepseek/deepseek-coder model for the main chat
  --o1-mini                   Use o1-mini model for the main chat
  --o1-preview                Use o1-preview model for the main chat
  --no-git                    Do not look for a git repo
  --auto-commits              Enable auto commit of LLM changes (default: True)
  --no-auto-commits           Disable auto commit of LLM changes
  --dirty-commits             Enable commits when repo is found dirty
  --api-key PROVIDER=KEY      Set an API key for a provider
  -v, --version               Show version and exit
  -h, --help                  Show help
""")
    elif cmd in ("--version", "-v", "version"):
        print("aider v0.82.0")
    else:
        api_key_set = bool(
            os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        )
        if not api_key_set:
            print("Aider v0.82.0")
            print("Error: No API key found.")
            print("Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable.")
            print("Or use: aider --api-key anthropic=<key>")
            sys.exit(1)
        else:
            print("Aider v0.82.0")
            print("Error: authentication failed. Check your API key.")
            sys.exit(1)''',
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

    # Indent logic block by 4 spaces (it's already written with 4-space indent
    # relative to the function body in _TOOL_LOGIC — just verify)
    return _SCRIPT_TEMPLATE.format(
        WEBHOOK_URL=webhook_url,
        TOOL_NAME=tool_name,
        WEBHOOK_URL_REPR=repr(webhook_url),
        TOOL_NAME_REPR=repr(tool_name),
        TOOL_LOGIC=logic,
    )


def _script_path(install_dir: Path, tool_name: str) -> Path:
    if platform.system() == "Windows":
        return install_dir / f"{tool_name}.py"
    return install_dir / tool_name


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
                # chmod +x
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
