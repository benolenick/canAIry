"""Multi-channel alert dispatcher for canAIry.

Supported channels:
  - webhook  (Discord / Slack / generic JSON POST)
  - email    (SMTP with STARTTLS)
  - syslog   (via logging.handlers.SysLogHandler)
  - logfile  (newline-delimited JSON)

All async channels are called concurrently via asyncio.gather so a slow
channel does not block the others.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import socket
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


class Alerter:
    """Dispatches alert dicts to all enabled channels."""

    def __init__(self, config: dict) -> None:
        # Extract only the alerts section; tolerate a bare top-level config.
        self._cfg: dict[str, Any] = config.get("alerts", config)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def send(self, alert: dict) -> None:
        """Dispatch *alert* to all enabled channels concurrently.

        Errors in individual channels are logged but never propagate so that
        a broken channel cannot prevent the others from firing.
        """
        tasks: list[asyncio.coroutines] = []

        if self._cfg.get("webhook", {}).get("enabled"):
            tasks.append(self._send_webhook(alert))

        if self._cfg.get("email", {}).get("enabled"):
            tasks.append(self._send_email(alert))

        if self._cfg.get("syslog", {}).get("enabled"):
            tasks.append(self._send_syslog(alert))

        # Logfile is synchronous — run it before the async gather.
        if self._cfg.get("logfile", {}).get("enabled"):
            self._send_logfile(alert)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.error("Alert channel raised an exception: %s", result)

    async def test(self) -> dict[str, str]:
        """Send a test alert to every configured channel.

        Returns a mapping of ``channel_name -> "ok"`` or ``channel_name ->
        "<error message>"``.
        """
        test_alert = {
            "timestamp": _utc_now(),
            "hostname": socket.gethostname(),
            "trap_type": "test",
            "trap_name": "canAIry test alert",
            "details": {"message": "This is a test alert from canAIry."},
        }

        results: dict[str, str] = {}

        async def _run(name: str, coro: asyncio.coroutines) -> None:
            try:
                await coro
                results[name] = "ok"
            except Exception as exc:  # noqa: BLE001
                results[name] = str(exc)

        tasks = []

        if self._cfg.get("webhook", {}).get("enabled"):
            tasks.append(_run("webhook", self._send_webhook(test_alert)))

        if self._cfg.get("email", {}).get("enabled"):
            tasks.append(_run("email", self._send_email(test_alert)))

        if self._cfg.get("syslog", {}).get("enabled"):
            tasks.append(_run("syslog", self._send_syslog(test_alert)))

        if self._cfg.get("logfile", {}).get("enabled"):
            try:
                self._send_logfile(test_alert)
                results["logfile"] = "ok"
            except Exception as exc:  # noqa: BLE001
                results["logfile"] = str(exc)

        if tasks:
            await asyncio.gather(*tasks)

        if not results:
            results["(none)"] = "no channels enabled"

        return results

    # ------------------------------------------------------------------
    # Channel implementations
    # ------------------------------------------------------------------

    async def _send_webhook(self, alert: dict) -> None:
        """POST the alert to a webhook URL.

        Auto-detects Discord and Slack by URL substring and formats
        appropriately; falls back to raw JSON for generic webhooks.
        """
        cfg = self._cfg.get("webhook", {})
        url: str = cfg.get("url", "").strip()
        if not url:
            raise ValueError("Webhook URL is not configured.")

        payload = self._format_webhook_payload(url, alert)

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status not in (200, 204):
                    body = await resp.text()
                    raise RuntimeError(
                        f"Webhook returned HTTP {resp.status}: {body[:200]}"
                    )

    def _format_webhook_payload(self, url: str, alert: dict) -> dict:
        """Return a correctly formatted payload dict for the given webhook URL."""
        if "discord.com" in url or "discordapp.com" in url:
            return self._discord_payload(alert)
        if "hooks.slack.com" in url:
            return self._slack_payload(alert)
        # Generic — send the raw alert dict.
        return alert

    def _discord_payload(self, alert: dict) -> dict:
        """Format alert as a Discord embed."""
        timestamp = alert.get("timestamp", _utc_now())
        hostname = alert.get("hostname", "unknown")
        trap_type = alert.get("trap_type", "unknown")
        trap_name = alert.get("trap_name", "unknown")
        details = alert.get("details", {})

        fields = [
            {"name": "Trap", "value": trap_name, "inline": True},
            {"name": "Time", "value": timestamp, "inline": True},
        ]

        # Add top-level detail fields (skip deeply nested dicts).
        for key, value in details.items():
            if isinstance(value, (str, int, float, bool)):
                fields.append(
                    {"name": key.replace("_", " ").title(), "value": str(value), "inline": True}
                )

        return {
            "embeds": [
                {
                    "title": "canAIry Alert",
                    "description": (
                        f"**{trap_type}** triggered on **{hostname}**"
                    ),
                    "color": 0xFF0000,
                    "fields": fields,
                    "footer": {"text": "canAIry honeypot"},
                    "timestamp": timestamp,
                }
            ]
        }

    def _slack_payload(self, alert: dict) -> dict:
        """Format alert as Slack Block Kit blocks."""
        timestamp = alert.get("timestamp", _utc_now())
        hostname = alert.get("hostname", "unknown")
        trap_type = alert.get("trap_type", "unknown")
        trap_name = alert.get("trap_name", "unknown")
        details = alert.get("details", {})

        detail_lines = "\n".join(
            f"• *{k.replace('_', ' ').title()}*: {v}"
            for k, v in details.items()
            if isinstance(v, (str, int, float, bool))
        )

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":rotating_light: canAIry Alert"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{trap_type}* triggered on *{hostname}*\n"
                        f"*Trap:* {trap_name}\n"
                        f"*Time:* {timestamp}"
                    ),
                },
            },
        ]

        if detail_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": detail_lines},
                }
            )

        return {"blocks": blocks}

    async def _send_email(self, alert: dict) -> None:
        """Send *alert* as a plain-text email via SMTP with STARTTLS."""
        cfg = self._cfg.get("email", {})
        smtp_host: str = cfg.get("smtp_host", "").strip()
        smtp_port: int = int(cfg.get("smtp_port", 587))
        from_addr: str = cfg.get("from_addr", "").strip()
        to_addr: str = cfg.get("to_addr", "").strip()
        password: str = cfg.get("password", "")

        if not all([smtp_host, from_addr, to_addr]):
            raise ValueError("Email alerter: smtp_host, from_addr, and to_addr are required.")

        subject = (
            f"[canAIry] {alert.get('trap_type', 'unknown')} triggered"
            f" on {alert.get('hostname', 'unknown')}"
        )
        body = json.dumps(alert, indent=2)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.set_content(body)

        # smtplib is synchronous — run in a thread so we don't block the loop.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: _smtp_send(smtp_host, smtp_port, from_addr, password, msg),
        )

    async def _send_syslog(self, alert: dict) -> None:
        """Emit *alert* as a structured syslog message.

        Sends the full alert as JSON in the syslog body for SIEM parsing.
        The message is prefixed with ``canAIry:`` so rules can match on it.
        """
        cfg = self._cfg.get("syslog", {})
        address = cfg.get("address", "/dev/log")
        port = int(cfg.get("port", 514))

        # Send full JSON for SIEM ingestion — prefix with program name for
        # easy rule matching in Security Onion / Splunk / etc.
        message = f"canAIry: {json.dumps(alert, ensure_ascii=False)}"

        # Determine address tuple vs socket path.
        # If address looks like a filesystem path, use it directly (Unix socket).
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: _syslog_emit(address, port, message),
        )

    def _send_logfile(self, alert: dict) -> None:
        """Append a JSON line to the configured log file."""
        cfg = self._cfg.get("logfile", {})
        raw_path: str = cfg.get("path", "~/.canairy/alerts.log")
        path = Path(raw_path).expanduser()

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("Logfile alert failed: %s", exc)
            raise


# ---------------------------------------------------------------------------
# Thread-pool helpers (synchronous, called via run_in_executor)
# ---------------------------------------------------------------------------


def _smtp_send(
    host: str,
    port: int,
    from_addr: str,
    password: str,
    msg: EmailMessage,
) -> None:
    """Blocking SMTP send with STARTTLS."""
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        if password:
            smtp.login(from_addr, password)
        smtp.send_message(msg)


def _syslog_emit(address: str, port: int, message: str) -> None:
    """Blocking syslog emit."""
    # Decide whether address is a socket path or a hostname.
    if address.startswith("/") or address.startswith("\\\\.\\"):
        # Unix domain socket (Linux/macOS) or Windows named pipe path.
        handler = SysLogHandler(address=address)
    else:
        handler = SysLogHandler(address=(address, port))

    try:
        record = logging.LogRecord(
            name="canairy",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg=message,
            args=(),
            exc_info=None,
        )
        handler.emit(record)
    finally:
        handler.close()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
