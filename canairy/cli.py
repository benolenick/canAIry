"""canAIry CLI entry point.

Commands
-------
(no command)   Interactive configuration menu
setup          Quick mode selection wizard
run            Load config and start all enabled traps (blocking)
status         Show current config summary
test-alert     Fire a test alert to all configured channels
uninstall      Remove planted artefacts (traps, keys, fake configs)
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Configure root logger early so trap modules can use it.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("canairy")

VERSION = "0.2.0"


# ---------------------------------------------------------------------------
# Lazy imports — keep CLI startup fast
# ---------------------------------------------------------------------------


def _import_config():
    from canairy.config import load_config, save_config, get_config_dir
    return load_config, save_config, get_config_dir


def _import_alerter():
    from canairy.alerter import Alerter
    return Alerter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _yn(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question; return bool."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        raw = input(f"{prompt} {hint}: ").strip().lower()
        if raw == "":
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Please enter y or n.")


def _prompt(prompt: str, default: str = "", secret: bool = False) -> str:
    """Prompt for a string value, showing the default."""
    if default:
        display = f"{prompt} [{default}]: "
    else:
        display = f"{prompt}: "

    if secret:
        value = getpass.getpass(display)
    else:
        value = input(display).strip()

    return value if value else default


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _print_section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _detect_mode(config: dict) -> str:
    """Determine current trap mode from config."""
    traps = config.get("traps", {})
    has_servers = traps.get("ollama_server", {}).get("enabled", False)
    has_cli = traps.get("fake_cli", {}).get("enabled", False)

    if has_servers and has_cli:
        return "Full"
    elif has_servers:
        return "Server Traps"
    elif has_cli:
        return "CLI Traps"
    else:
        # Check if any passive traps are on
        has_keys = traps.get("canary_keys", {}).get("enabled", False)
        has_configs = traps.get("fake_configs", {}).get("enabled", False)
        if has_keys or has_configs:
            return "Passive Only"
        return "Disabled"


def _trap_summary(config: dict) -> str:
    """Return a short string describing active traps."""
    parts = []
    traps = config.get("traps", {})
    if traps.get("ollama_server", {}).get("enabled"):
        port = traps["ollama_server"].get("port", 11434)
        parts.append(f"Ollama :{port}")
    if traps.get("fake_cli", {}).get("enabled"):
        tools = traps["fake_cli"].get("tools", [])
        parts.append(f"CLI ({', '.join(tools)})")
    if traps.get("canary_keys", {}).get("enabled"):
        parts.append("canary keys")
    if traps.get("fake_configs", {}).get("enabled"):
        parts.append("fake configs")
    return ", ".join(parts) if parts else "none"


def _alert_summary(config: dict) -> str:
    """Return short string of active alert channels."""
    parts = []
    alerts = config.get("alerts", {})
    if alerts.get("syslog", {}).get("enabled"):
        addr = alerts["syslog"].get("address", "")
        port = alerts["syslog"].get("port", 514)
        parts.append(f"syslog({addr}:{port})")
    if alerts.get("webhook", {}).get("enabled"):
        parts.append("webhook")
    if alerts.get("email", {}).get("enabled"):
        parts.append("email")
    if alerts.get("logfile", {}).get("enabled"):
        parts.append("logfile")
    return ", ".join(parts) if parts else "none"


# ---------------------------------------------------------------------------
# Interactive menu (default when no subcommand given)
# ---------------------------------------------------------------------------


def cmd_menu() -> None:
    """Interactive configuration menu."""
    load_config, save_config, get_config_dir = _import_config()

    while True:
        config = load_config()
        mode = _detect_mode(config)

        _print_section(f"canAIry v{VERSION}")
        print()
        print(f"  Mode:    {mode}")
        print(f"  Traps:   {_trap_summary(config)}")
        print(f"  Alerts:  {_alert_summary(config)}")
        print()
        print("  [1] Setup      choose trap mode and configure alerts")
        print("  [2] Status     detailed configuration view")
        print("  [3] Run        start the honeypot")
        print("  [4] Test       send a test alert")
        print("  [5] Uninstall  remove all traps")
        print("  [q] Quit")
        print()

        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "1":
            _setup_interactive(config, save_config)
        elif choice == "2":
            cmd_status(argparse.Namespace())
        elif choice == "3":
            cmd_run(argparse.Namespace(daemon=False))
            break  # run blocks until Ctrl-C
        elif choice == "4":
            cmd_test_alert(argparse.Namespace())
        elif choice == "5":
            cmd_uninstall(argparse.Namespace())
        elif choice in ("q", "quit", "exit"):
            break
        else:
            print("  Invalid choice.\n")


# ---------------------------------------------------------------------------
# setup (replaces old install)
# ---------------------------------------------------------------------------


def _setup_interactive(config: dict | None = None, save_fn=None) -> None:
    """Quick mode selection + alert configuration."""
    if config is None or save_fn is None:
        load_config, save_fn, _ = _import_config()
        config = load_config()

    _print_section("Trap Mode")
    print()
    print("  [1] Server traps only")
    print("      Fake Ollama API on port 11434 — no CLI changes")
    print()
    print("  [2] CLI traps only")
    print("      Fake claude, codex, gemini, ollama, aider commands")
    print("      Real tools renamed (claude -> claudereal, etc.)")
    print()
    print("  [3] Full deployment")
    print("      Both server and CLI traps + canary keys + fake configs")
    print()
    print("  [4] Custom")
    print("      Pick individual traps")
    print()

    try:
        choice = input("  Mode [1-4]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        return

    traps = config["traps"]

    if choice == "1":
        traps["ollama_server"]["enabled"] = True
        traps["fake_cli"]["enabled"] = False
        traps["canary_keys"]["enabled"] = False
        traps["fake_configs"]["enabled"] = False
        print("\n  -> Server traps mode.")

    elif choice == "2":
        traps["ollama_server"]["enabled"] = False
        traps["fake_cli"]["enabled"] = True
        traps["fake_cli"]["rename_real_tools"] = True
        traps["canary_keys"]["enabled"] = False
        traps["fake_configs"]["enabled"] = False
        print("\n  -> CLI traps mode.")

    elif choice == "3":
        traps["ollama_server"]["enabled"] = True
        traps["fake_cli"]["enabled"] = True
        traps["fake_cli"]["rename_real_tools"] = True
        traps["canary_keys"]["enabled"] = True
        traps["fake_configs"]["enabled"] = True
        print("\n  -> Full deployment mode.")

    elif choice == "4":
        _setup_custom(traps)

    else:
        print("  Invalid choice, keeping current config.")
        return

    # Alert channel configuration
    print()
    if _yn("  Configure alert channels?", default=True):
        _setup_alerts(config)

    save_fn(config)
    print(f"\n  Config saved. Run 'canairy run' or choose [3] from menu to start.\n")


def _setup_custom(traps: dict) -> None:
    """Let user toggle individual traps."""
    print()

    # Ollama server
    traps["ollama_server"]["enabled"] = _yn(
        "  Fake Ollama server?",
        default=traps["ollama_server"]["enabled"],
    )
    if traps["ollama_server"]["enabled"]:
        port_raw = _prompt(
            "    Port", str(traps["ollama_server"].get("port", 11434))
        )
        try:
            traps["ollama_server"]["port"] = int(port_raw)
        except ValueError:
            pass

    # Fake CLI
    traps["fake_cli"]["enabled"] = _yn(
        "  Fake CLI tools (claude, codex, gemini, ollama, aider)?",
        default=traps["fake_cli"]["enabled"],
    )
    if traps["fake_cli"]["enabled"]:
        traps["fake_cli"]["rename_real_tools"] = _yn(
            "    Rename real tools? (claude -> claudereal, etc.)",
            default=traps["fake_cli"].get("rename_real_tools", True),
        )
        install_path = _prompt(
            "    Install directory (empty = auto-detect)",
            default=traps["fake_cli"].get("install_path", ""),
        )
        traps["fake_cli"]["install_path"] = install_path

    # Canary keys
    traps["canary_keys"]["enabled"] = _yn(
        "  Plant canary API keys?",
        default=traps["canary_keys"]["enabled"],
    )

    # Fake configs
    traps["fake_configs"]["enabled"] = _yn(
        "  Plant fake config directories?",
        default=traps["fake_configs"]["enabled"],
    )


def _setup_alerts(config: dict) -> None:
    """Configure alert channels."""
    alerts = config["alerts"]

    # Syslog
    print("\n  -- Syslog (SIEM: Security Onion, Splunk, etc.) --")
    alerts["syslog"]["enabled"] = _yn(
        "  Enable syslog?", alerts["syslog"]["enabled"]
    )
    if alerts["syslog"]["enabled"]:
        alerts["syslog"]["address"] = _prompt(
            "    Address (IP or socket path)",
            alerts["syslog"].get("address", "/dev/log"),
        )
        port_raw = _prompt(
            "    Port", str(alerts["syslog"].get("port", 514))
        )
        try:
            alerts["syslog"]["port"] = int(port_raw)
        except ValueError:
            pass

    # Webhook
    print("\n  -- Webhook (Discord / Slack / generic) --")
    alerts["webhook"]["enabled"] = _yn(
        "  Enable webhook?", alerts["webhook"]["enabled"]
    )
    if alerts["webhook"]["enabled"]:
        alerts["webhook"]["url"] = _prompt(
            "    Webhook URL", alerts["webhook"].get("url", "")
        )

    # Email
    print("\n  -- Email (SMTP) --")
    alerts["email"]["enabled"] = _yn(
        "  Enable email?", alerts["email"]["enabled"]
    )
    if alerts["email"]["enabled"]:
        alerts["email"]["smtp_host"] = _prompt(
            "    SMTP host", alerts["email"].get("smtp_host", "")
        )
        port_raw = _prompt(
            "    SMTP port", str(alerts["email"].get("smtp_port", 587))
        )
        try:
            alerts["email"]["smtp_port"] = int(port_raw)
        except ValueError:
            pass
        alerts["email"]["from_addr"] = _prompt(
            "    From address", alerts["email"].get("from_addr", "")
        )
        alerts["email"]["to_addr"] = _prompt(
            "    To address", alerts["email"].get("to_addr", "")
        )
        alerts["email"]["password"] = _prompt(
            "    SMTP password", alerts["email"].get("password", ""), secret=True
        )

    # Logfile
    print("\n  -- Log file --")
    alerts["logfile"]["enabled"] = _yn(
        "  Enable JSON logfile?", alerts["logfile"]["enabled"]
    )
    if alerts["logfile"]["enabled"]:
        alerts["logfile"]["path"] = _prompt(
            "    Path", alerts["logfile"].get("path", "~/.canairy/alerts.log")
        )


def cmd_setup(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Quick setup wizard (subcommand entry point)."""
    _setup_interactive()


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> None:
    """Load config and start all enabled traps."""
    if getattr(args, "daemon", False):
        print(
            "Daemonisation is not built in. Use systemd (or launchd / Task Scheduler):\n"
            "\n"
            "  [Unit]\n"
            "  Description=canAIry honeypot\n"
            "\n"
            "  [Service]\n"
            "  ExecStart=canairy run\n"
            "  Restart=on-failure\n"
            "\n"
            "  [Install]\n"
            "  WantedBy=multi-user.target\n"
        )
        return

    load_config, _, _ = _import_config()
    Alerter = _import_alerter()

    config = load_config()
    alerter = Alerter(config)

    asyncio.run(_run_async(config, alerter))


async def _run_async(config: dict, alerter: Any) -> None:
    """Start all enabled traps and run until Ctrl-C."""
    trap_cfg = config.get("traps", {})

    # Paths to watch (populated by synchronous planters below).
    watch_paths: list[str] = []

    # Resources to clean up on shutdown.
    observers = []      # watchdog Observer instances
    runner = None       # aiohttp AppRunner
    started_any = False

    # -- Canary keys (sync plant, then watch) ------------------------------
    if trap_cfg.get("canary_keys", {}).get("enabled"):
        try:
            from canairy.traps.canary_keys import plant_canary_keys

            planted = plant_canary_keys(trap_cfg["canary_keys"])
            watch_paths.extend(str(p) for p in (planted if isinstance(planted, list) else []))
            logger.info("Canary keys planted.")
        except ImportError:
            logger.warning("canairy.traps.canary_keys not found — skipping.")
        except Exception as exc:  # noqa: BLE001
            logger.error("canary_keys planting failed: %s", exc)

    # -- Fake configs (sync plant, then watch) -----------------------------
    if trap_cfg.get("fake_configs", {}).get("enabled"):
        try:
            from canairy.traps.fake_configs import plant_fake_configs

            planted = plant_fake_configs(trap_cfg["fake_configs"])
            watch_paths.extend(str(p) for p in (planted if isinstance(planted, list) else []))
            logger.info("Fake configs planted.")
        except ImportError:
            logger.warning("canairy.traps.fake_configs not found — skipping.")
        except Exception as exc:  # noqa: BLE001
            logger.error("fake_configs planting failed: %s", exc)

    # -- Fake CLI tools (sync install) -------------------------------------
    if trap_cfg.get("fake_cli", {}).get("enabled"):
        try:
            from canairy.traps.fake_cli import install_fake_clis, rename_real_tools

            # Rename real tools first (claude->claudereal, etc.)
            if trap_cfg["fake_cli"].get("rename_real_tools", True):
                renamed = rename_real_tools(trap_cfg["fake_cli"])
                for tool, (orig, dest) in renamed.items():
                    logger.info("Renamed real %s: %s -> %s", tool, orig, dest)

            install_fake_clis(trap_cfg["fake_cli"], config.get("alerts", {}))
            logger.info("Fake CLI tools installed.")
            started_any = True
        except ImportError:
            logger.warning("canairy.traps.fake_cli not found — skipping.")
        except Exception as exc:  # noqa: BLE001
            logger.error("fake_cli install failed: %s", exc)

    # -- File watcher (starts observers in background threads) -------------
    if watch_paths:
        try:
            from canairy.watcher import start_watcher

            observers = await start_watcher(watch_paths, alerter)
            logger.info("File watcher started for %d path(s).", len(watch_paths))
            started_any = True
        except ImportError:
            logger.warning("canairy.watcher not found — skipping file watch.")

    # -- Fake Ollama server (starts aiohttp server) ------------------------
    if trap_cfg.get("ollama_server", {}).get("enabled"):
        try:
            from canairy.traps.ollama_server import start_ollama_server

            runner = await start_ollama_server(trap_cfg["ollama_server"], alerter)
            port = trap_cfg["ollama_server"].get("port", 11434)
            logger.info("Fake Ollama server listening on port %d.", port)
            started_any = True
        except ImportError:
            logger.warning("canairy.traps.ollama_server not found — skipping.")

    if not started_any:
        logger.warning(
            "No traps are running. Run 'canairy setup' to enable traps."
        )
        return

    mode = _detect_mode({"traps": trap_cfg})
    print(f"canAIry is running ({mode}). Press Ctrl-C to stop.")

    # Block forever until interrupted.
    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        # Clean up watchers.
        for obs in observers:
            obs.stop()
        # Clean up aiohttp.
        if runner is not None:
            await runner.cleanup()
        print("\ncanAIry stopped.")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Print a human-readable configuration summary."""
    load_config, _, get_config_dir = _import_config()

    config = load_config()
    cfg_path = get_config_dir() / "config.yaml"

    _print_section("canAIry Status")

    print(f"\n  Config:  {cfg_path}")
    print(f"  Mode:    {_detect_mode(config)}")

    print("\n  Traps:")
    for name, val in config.get("traps", {}).items():
        enabled = val.get("enabled", False)
        marker = "[ON] " if enabled else "[off]"
        extra = ""
        if name == "ollama_server" and enabled:
            extra = f"  port={val.get('port', 11434)}"
        elif name == "fake_cli" and enabled:
            extra = f"  tools={val.get('tools', [])}"
            if val.get("rename_real_tools"):
                extra += "  (renames real tools)"
        elif name == "canary_keys" and enabled:
            extra = f"  locations={val.get('locations', [])}"
        elif name == "fake_configs" and enabled:
            extra = f"  configs={val.get('configs', [])}"
        print(f"    {marker} {name}{extra}")

    print("\n  Alert Channels:")
    for name, val in config.get("alerts", {}).items():
        enabled = val.get("enabled", False)
        marker = "[ON] " if enabled else "[off]"
        extra = ""
        if name == "webhook" and enabled:
            url = val.get("url", "")
            masked = (url[:40] + "...") if len(url) > 40 else url
            extra = f"  url={masked}"
        elif name == "email" and enabled:
            extra = f"  to={val.get('to_addr', '')}"
        elif name == "syslog" and enabled:
            extra = f"  {val.get('address', '')}:{val.get('port', 514)}"
        elif name == "logfile" and enabled:
            extra = f"  {val.get('path', '')}"
        print(f"    {marker} {name}{extra}")

    print()


# ---------------------------------------------------------------------------
# test-alert
# ---------------------------------------------------------------------------


def cmd_test_alert(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Send a test alert to all configured channels and print results."""
    load_config, _, _ = _import_config()
    Alerter = _import_alerter()

    config = load_config()
    alerter = Alerter(config)

    print("  Sending test alert to all enabled channels...")

    async def _run() -> dict:
        return await alerter.test()

    results = asyncio.run(_run())

    print("\n  Results:")
    for channel, outcome in results.items():
        status = "OK" if outcome == "ok" else f"FAILED: {outcome}"
        print(f"    {channel:20s} {status}")
    print()


# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------


def cmd_uninstall(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Remove planted honeypot artefacts (keeps config and alert log)."""
    load_config, _, get_config_dir = _import_config()

    _print_section("canAIry Uninstall")
    print("  This will remove:")
    print("    - Fake CLI wrapper scripts")
    print("    - Canary key files")
    print("    - Fake config directories")
    print()
    print("  This will NOT remove:")
    print("    - ~/.canairy/config.yaml")
    print("    - ~/.canairy/alerts.log")
    print()

    if not _yn("  Continue with uninstall?", default=False):
        print("  Uninstall cancelled.")
        return

    config = load_config()
    trap_cfg = config.get("traps", {})
    errors: list[str] = []

    # -- Fake CLI tools ---------------------------------------------------
    if trap_cfg.get("fake_cli", {}).get("enabled"):
        try:
            from canairy.traps.fake_cli import uninstall_fake_clis, restore_real_tools

            uninstall_fake_clis(trap_cfg["fake_cli"])
            print("    Fake CLI tools removed.")

            # Restore renamed real tools (claudereal->claude, etc.)
            restored = restore_real_tools(trap_cfg["fake_cli"])
            if restored:
                print(f"    Restored real tools: {', '.join(restored)}")
        except ImportError:
            print("    canairy.traps.fake_cli not available — skipping.")
        except Exception as exc:  # noqa: BLE001
            msg = f"    Failed to remove fake CLI tools: {exc}"
            print(msg)
            errors.append(msg)

    # -- Canary keys ------------------------------------------------------
    if trap_cfg.get("canary_keys", {}).get("enabled"):
        try:
            from canairy.traps.canary_keys import uninstall_canary_keys

            uninstall_canary_keys(trap_cfg["canary_keys"])
            print("    Canary key files removed.")
        except ImportError:
            _remove_canary_key_files(trap_cfg.get("canary_keys", {}), errors)
        except Exception as exc:  # noqa: BLE001
            msg = f"    Failed to remove canary keys: {exc}"
            print(msg)
            errors.append(msg)

    # -- Fake configs -----------------------------------------------------
    if trap_cfg.get("fake_configs", {}).get("enabled"):
        try:
            from canairy.traps.fake_configs import uninstall_fake_configs

            uninstall_fake_configs(trap_cfg["fake_configs"])
            print("    Fake config files removed.")
        except ImportError:
            print("    canairy.traps.fake_configs not available — skipping.")
        except Exception as exc:  # noqa: BLE001
            msg = f"    Failed to remove fake configs: {exc}"
            print(msg)
            errors.append(msg)

    if errors:
        print("\n  Uninstall completed with errors (see above).")
        sys.exit(1)
    else:
        print("\n  Uninstall complete.")
        print("  Config and alert log preserved in:", get_config_dir())


def _remove_canary_key_files(canary_cfg: dict, errors: list[str]) -> None:
    """Best-effort removal of canary key files listed in config."""
    for loc in canary_cfg.get("locations", []):
        path = Path(loc).expanduser()
        if path.exists():
            try:
                path.unlink()
                print(f"    Removed: {path}")
            except OSError as exc:
                msg = f"    Could not remove {path}: {exc}"
                print(msg)
                errors.append(msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="canairy",
        description=(
            "canAIry — LLM honeypot for detecting attackers probing AI infrastructure.\n"
            "Run with no arguments for an interactive menu."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    # NOT required — no subcommand means interactive menu.

    # setup (with install as alias)
    p_setup = sub.add_parser(
        "setup",
        help="Quick trap mode selection wizard.",
        aliases=["install"],
    )
    p_setup.set_defaults(func=cmd_setup)

    # run
    p_run = sub.add_parser("run", help="Start all enabled traps.")
    p_run.add_argument(
        "--daemon",
        action="store_true",
        help="Print systemd unit instructions and exit.",
    )
    p_run.set_defaults(func=cmd_run)

    # status
    p_status = sub.add_parser("status", help="Show configuration summary.")
    p_status.set_defaults(func=cmd_status)

    # test-alert
    p_test = sub.add_parser("test-alert", help="Send a test alert to all channels.")
    p_test.set_defaults(func=cmd_test_alert)

    # uninstall
    p_uninstall = sub.add_parser(
        "uninstall",
        help="Remove planted honeypot artefacts (keeps config and log).",
    )
    p_uninstall.set_defaults(func=cmd_uninstall)

    args = parser.parse_args()

    if args.command is None:
        cmd_menu()
    else:
        args.func(args)


if __name__ == "__main__":
    main()
