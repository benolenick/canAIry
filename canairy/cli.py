"""canAIry CLI entry point.

Subcommands
-----------
install      Interactive first-run setup — picks traps and alert channels.
run          Load config and start all enabled traps (blocking).
status       Show current config summary.
test-alert   Fire a test alert to all configured channels.
uninstall    Remove planted artefacts (traps, keys, fake configs).
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


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------


def cmd_install(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Interactive first-run wizard."""
    load_config, save_config, get_config_dir = _import_config()

    _print_section("canAIry — Interactive Setup")
    print("This wizard will configure your honeypot traps and alert channels.")
    print("Press Enter to accept defaults.\n")

    config = load_config()

    # ------------------------------------------------------------------ traps
    _print_section("Trap Configuration")

    trap_cfg = config["traps"]

    print("\n-- Ollama Server --")
    trap_cfg["ollama_server"]["enabled"] = _yn(
        "Enable fake Ollama API server?",
        default=trap_cfg["ollama_server"]["enabled"],
    )
    if trap_cfg["ollama_server"]["enabled"]:
        port_raw = _prompt(
            "  Listen port",
            default=str(trap_cfg["ollama_server"]["port"]),
        )
        try:
            trap_cfg["ollama_server"]["port"] = int(port_raw)
        except ValueError:
            print("  Invalid port, keeping default.")

    print("\n-- Fake CLI Tools --")
    trap_cfg["fake_cli"]["enabled"] = _yn(
        "Install fake CLI wrappers (ollama, claude, codex, aider)?",
        default=trap_cfg["fake_cli"]["enabled"],
    )
    if trap_cfg["fake_cli"]["enabled"]:
        install_path = _prompt(
            "  Install directory (empty = auto-detect PATH)",
            default=trap_cfg["fake_cli"]["install_path"],
        )
        trap_cfg["fake_cli"]["install_path"] = install_path

        print("\n  When enabled, real AI tools on your PATH (claude, codex, gemini,")
        print("  ollama, aider) get renamed to claudereal, codexreal, etc.")
        print("  The original command names become honeypot traps.")
        trap_cfg["fake_cli"]["rename_real_tools"] = _yn(
            "  Rename real tools? (e.g. claude -> claudereal)",
            default=trap_cfg["fake_cli"].get("rename_real_tools", True),
        )

    print("\n-- Canary Keys --")
    trap_cfg["canary_keys"]["enabled"] = _yn(
        "Plant canary API keys in common locations?",
        default=trap_cfg["canary_keys"]["enabled"],
    )
    if trap_cfg["canary_keys"]["enabled"]:
        locs = trap_cfg["canary_keys"]["locations"]
        print(f"  Current locations: {locs}")
        add_more = _yn("  Add another location?", default=False)
        while add_more:
            loc = _prompt("    Path (e.g. ~/.config/myapp/.env)").strip()
            if loc:
                locs.append(loc)
            add_more = _yn("  Add another?", default=False)

    print("\n-- Fake Configs --")
    trap_cfg["fake_configs"]["enabled"] = _yn(
        "Plant fake AI tool config files?",
        default=trap_cfg["fake_configs"]["enabled"],
    )

    # -------------------------------------------------------------- alerts
    _print_section("Alert Channel Configuration")

    alert_cfg = config["alerts"]

    # Webhook
    print("\n-- Webhook (Discord / Slack / generic) --")
    alert_cfg["webhook"]["enabled"] = _yn(
        "Enable webhook alerts?",
        default=alert_cfg["webhook"]["enabled"],
    )
    if alert_cfg["webhook"]["enabled"]:
        alert_cfg["webhook"]["url"] = _prompt(
            "  Webhook URL",
            default=alert_cfg["webhook"]["url"],
        )

    # Email
    print("\n-- Email (SMTP) --")
    alert_cfg["email"]["enabled"] = _yn(
        "Enable email alerts?",
        default=alert_cfg["email"]["enabled"],
    )
    if alert_cfg["email"]["enabled"]:
        alert_cfg["email"]["smtp_host"] = _prompt(
            "  SMTP host",
            default=alert_cfg["email"]["smtp_host"],
        )
        port_raw = _prompt(
            "  SMTP port",
            default=str(alert_cfg["email"]["smtp_port"]),
        )
        try:
            alert_cfg["email"]["smtp_port"] = int(port_raw)
        except ValueError:
            print("  Invalid port, keeping default.")
        alert_cfg["email"]["from_addr"] = _prompt(
            "  From address",
            default=alert_cfg["email"]["from_addr"],
        )
        alert_cfg["email"]["to_addr"] = _prompt(
            "  To address",
            default=alert_cfg["email"]["to_addr"],
        )
        alert_cfg["email"]["password"] = _prompt(
            "  SMTP password",
            default=alert_cfg["email"]["password"],
            secret=True,
        )

    # Syslog
    print("\n-- Syslog --")
    alert_cfg["syslog"]["enabled"] = _yn(
        "Enable syslog alerts?",
        default=alert_cfg["syslog"]["enabled"],
    )
    if alert_cfg["syslog"]["enabled"]:
        alert_cfg["syslog"]["address"] = _prompt(
            "  Syslog address (socket path or hostname)",
            default=alert_cfg["syslog"]["address"],
        )
        port_raw = _prompt(
            "  Syslog port (ignored for socket paths)",
            default=str(alert_cfg["syslog"]["port"]),
        )
        try:
            alert_cfg["syslog"]["port"] = int(port_raw)
        except ValueError:
            pass

    # Logfile (always shown; defaulted to enabled)
    print("\n-- Log File --")
    alert_cfg["logfile"]["enabled"] = _yn(
        "Enable JSON logfile alerts?",
        default=alert_cfg["logfile"]["enabled"],
    )
    if alert_cfg["logfile"]["enabled"]:
        alert_cfg["logfile"]["path"] = _prompt(
            "  Log file path",
            default=alert_cfg["logfile"]["path"],
        )

    # ------------------------------------------------------------------ save
    save_config(config)
    cfg_path = get_config_dir() / "config.yaml"

    _print_section("Setup Complete")
    print(f"\nConfig saved to: {cfg_path}")
    print("\nEnabled traps:")
    for trap_name, trap_val in config["traps"].items():
        status = "on" if trap_val.get("enabled") else "off"
        print(f"  {trap_name:25s} {status}")
    print("\nEnabled alert channels:")
    for ch_name, ch_val in config["alerts"].items():
        status = "on" if ch_val.get("enabled") else "off"
        print(f"  {ch_name:25s} {status}")
    print(
        "\nRun `canairy run` to start the honeypot.\n"
        "Run `canairy test-alert` to verify your alert channels.\n"
    )


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

            # Rename real tools first (claude→claudereal, etc.)
            if trap_cfg["fake_cli"].get("rename_real_tools", True):
                renamed = rename_real_tools(trap_cfg["fake_cli"])
                for tool, (orig, dest) in renamed.items():
                    logger.info("Renamed real %s: %s → %s", tool, orig, dest)

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
            "No traps are running. Enable at least one trap in your config."
        )
        return

    print("canAIry is running. Press Ctrl-C to stop.")

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

    print(f"\nConfig file : {cfg_path}")
    print(f"Config exists: {cfg_path.exists()}")

    print("\nTraps:")
    for name, val in config.get("traps", {}).items():
        enabled = val.get("enabled", False)
        marker = "[ON] " if enabled else "[off]"
        extra = ""
        if name == "ollama_server" and enabled:
            extra = f"  port={val.get('port', 11434)}"
        elif name == "fake_cli" and enabled:
            extra = f"  tools={val.get('tools', [])}"
        elif name == "canary_keys" and enabled:
            extra = f"  locations={val.get('locations', [])}"
        elif name == "fake_configs" and enabled:
            extra = f"  configs={val.get('configs', [])}"
        print(f"  {marker} {name}{extra}")

    print("\nAlert Channels:")
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
            extra = f"  address={val.get('address', '')}"
        elif name == "logfile" and enabled:
            extra = f"  path={val.get('path', '')}"
        print(f"  {marker} {name}{extra}")

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

    print("Sending test alert to all enabled channels...")

    async def _run() -> dict:
        return await alerter.test()

    results = asyncio.run(_run())

    print("\nResults:")
    for channel, outcome in results.items():
        status = "OK" if outcome == "ok" else f"FAILED: {outcome}"
        print(f"  {channel:20s} {status}")
    print()


# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------


def cmd_uninstall(args: argparse.Namespace) -> None:  # noqa: ARG001
    """Remove planted honeypot artefacts (keeps config and alert log)."""
    load_config, _, get_config_dir = _import_config()

    _print_section("canAIry Uninstall")
    print("This will remove:\n"
          "  - Fake CLI wrapper scripts\n"
          "  - Canary key files\n"
          "  - Fake config directories\n")
    print("This will NOT remove:\n"
          "  - ~/.canairy/config.yaml\n"
          "  - ~/.canairy/alerts.log\n")

    if not _yn("Continue with uninstall?", default=False):
        print("Uninstall cancelled.")
        return

    config = load_config()
    trap_cfg = config.get("traps", {})
    errors: list[str] = []

    # -- Fake CLI tools ---------------------------------------------------
    if trap_cfg.get("fake_cli", {}).get("enabled"):
        try:
            from canairy.traps.fake_cli import uninstall_fake_clis, restore_real_tools  # type: ignore[import]

            uninstall_fake_clis(trap_cfg["fake_cli"])
            print("  Fake CLI tools removed.")

            # Restore renamed real tools (claudereal→claude, etc.)
            restored = restore_real_tools(trap_cfg["fake_cli"])
            if restored:
                print(f"  Restored real tools: {', '.join(restored)}")
        except ImportError:
            print("  canairy.traps.fake_cli not available — skipping.")
        except Exception as exc:  # noqa: BLE001
            msg = f"  Failed to remove fake CLI tools: {exc}"
            print(msg)
            errors.append(msg)

    # -- Canary keys ------------------------------------------------------
    if trap_cfg.get("canary_keys", {}).get("enabled"):
        try:
            from canairy.traps.canary_keys import uninstall_canary_keys  # type: ignore[import]

            uninstall_canary_keys(trap_cfg["canary_keys"])
            print("  Canary key files removed.")
        except ImportError:
            # Fallback: delete the files listed in config ourselves.
            _remove_canary_key_files(trap_cfg.get("canary_keys", {}), errors)
        except Exception as exc:  # noqa: BLE001
            msg = f"  Failed to remove canary keys: {exc}"
            print(msg)
            errors.append(msg)

    # -- Fake configs -----------------------------------------------------
    if trap_cfg.get("fake_configs", {}).get("enabled"):
        try:
            from canairy.traps.fake_configs import uninstall_fake_configs  # type: ignore[import]

            uninstall_fake_configs(trap_cfg["fake_configs"])
            print("  Fake config files removed.")
        except ImportError:
            print("  canairy.traps.fake_configs not available — skipping.")
        except Exception as exc:  # noqa: BLE001
            msg = f"  Failed to remove fake configs: {exc}"
            print(msg)
            errors.append(msg)

    if errors:
        print("\nUninstall completed with errors (see above).")
        sys.exit(1)
    else:
        print("\nUninstall complete.")
        print("Config and alert log are preserved in:", get_config_dir())


def _remove_canary_key_files(canary_cfg: dict, errors: list[str]) -> None:
    """Best-effort removal of canary key files listed in config."""
    for loc in canary_cfg.get("locations", []):
        path = Path(loc).expanduser()
        if path.exists():
            try:
                path.unlink()
                print(f"  Removed: {path}")
            except OSError as exc:
                msg = f"  Could not remove {path}: {exc}"
                print(msg)
                errors.append(msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="canairy",
        description="canAIry — LLM honeypot for detecting attackers probing AI infrastructure.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # install
    p_install = sub.add_parser("install", help="Interactive setup wizard.")
    p_install.set_defaults(func=cmd_install)

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
    args.func(args)


if __name__ == "__main__":
    main()
