"""Fake config directory trap.

Plants realistic-looking AI tool configuration directories with fake credentials
and configuration files. When a filesystem watcher detects access to these files,
it triggers an alert.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import shutil
import socket
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MARKER_FILENAME = ".canairy-marker"

# ---------------------------------------------------------------------------
# Deterministic fake token generation (same approach as canary_keys.py)
# ---------------------------------------------------------------------------

def _machine_seed() -> str:
    return socket.getfqdn()


def _derive_b62(label: str, length: int) -> str:
    _CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    seed = _machine_seed()
    raw_bytes = hashlib.sha256(f"{seed}:{label}".encode()).digest()
    extended_bytes = raw_bytes
    while len(extended_bytes) < length:
        extended_bytes += hashlib.sha256(extended_bytes).digest()
    return "".join(_CHARSET[b % 62] for b in extended_bytes[:length])


def _derive_hex(label: str, length: int) -> str:
    seed = _machine_seed()
    raw = hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()
    extended = raw
    while len(extended) < length:
        extended += hashlib.sha256(extended.encode()).hexdigest()
    return extended[:length]


def _fake_anthropic_key(label: str = "claude-cfg") -> str:
    part = _derive_b62(label, 88)
    return f"sk-ant-api03-{part[:44]}-{part[44:]}-AA"


def _fake_org_id(label: str = "claude-org") -> str:
    return "org-" + _derive_b62(label, 24)


def _fake_github_token(label: str = "gh-token") -> str:
    return "gho_" + _derive_b62(label, 36)


def _fake_ssh_key_body(label: str = "ssh-key") -> str:
    """Generate a fake base64 blob that looks like an ed25519 private key body."""
    import base64
    raw = hashlib.sha256(f"{_machine_seed()}:{label}".encode()).digest()
    extended = raw
    while len(extended) < 128:
        extended += hashlib.sha256(extended).digest()
    return base64.b64encode(extended[:96]).decode()


# ---------------------------------------------------------------------------
# Platform paths
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return platform.system() == "Windows"


def _home() -> Path:
    return Path.home()


# ---------------------------------------------------------------------------
# Per-config planters
# ---------------------------------------------------------------------------


def _plant_ollama(root: Path) -> list[Path]:
    """Plant a fake ~/.ollama directory structure."""
    created: list[Path] = []

    # Manifest file
    manifest_path = (
        root
        / "models"
        / "manifests"
        / "registry.ollama.ai"
        / "library"
        / "llama3"
        / "latest"
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.ollama.image.model",
            "digest": "sha256:" + _derive_hex("ollama-manifest-config", 64),
            "size": 4661224676,
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": "sha256:" + _derive_hex("ollama-layer-0", 64),
                "size": 4661224676,
            },
            {
                "mediaType": "application/vnd.ollama.image.params",
                "digest": "sha256:" + _derive_hex("ollama-layer-1", 64),
                "size": 285,
            },
            {
                "mediaType": "application/vnd.ollama.image.template",
                "digest": "sha256:" + _derive_hex("ollama-layer-2", 64),
                "size": 312,
            },
            {
                "mediaType": "application/vnd.ollama.image.license",
                "digest": "sha256:" + _derive_hex("ollama-layer-3", 64),
                "size": 7020,
            },
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    created.append(manifest_path)

    # Fake SSH key (looks like an Ollama server identity key)
    ssh_key_path = root / "id_ed25519"
    key_body = _fake_ssh_key_body("ollama-ssh")
    ssh_key_path.write_text(
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{key_body}\n"
        f"-----END OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    # Restrict permissions on Unix
    if not _is_windows():
        ssh_key_path.chmod(0o600)
    created.append(ssh_key_path)

    # Fake command history
    history_path = root / "history"
    history_entries = [
        "ollama pull llama3:latest",
        "ollama pull mistral:7b-instruct",
        "ollama run llama3",
        "ollama list",
        "ollama run codellama:13b",
        "ollama ps",
        "ollama show llama3",
    ]
    history_path.write_text("\n".join(history_entries) + "\n", encoding="utf-8")
    created.append(history_path)

    # Marker
    marker = root / _MARKER_FILENAME
    marker.write_text("canairy-managed\n", encoding="utf-8")

    return created


def _plant_claude(root: Path) -> list[Path]:
    """Plant a fake Claude config directory."""
    created: list[Path] = []

    root.mkdir(parents=True, exist_ok=True)

    api_key = _fake_anthropic_key("claude-settings")
    org_id = _fake_org_id("claude-org")

    # settings.json
    settings = {
        "api_key": api_key,
        "model": "claude-sonnet-4-20250514",
        "theme": "dark",
        "auto_update": True,
        "telemetry": False,
        "max_tokens": 8096,
        "temperature": 1.0,
        "stream": True,
        "editor": "vscode",
        "history_size": 1000,
    }
    settings_path = root / "settings.json"
    settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    created.append(settings_path)

    # credentials.json
    credentials = {
        "default": {
            "api_key": api_key,
            "organization_id": org_id,
            "account_email": f"dev@{socket.getfqdn().split('.')[-1] or 'example'}.com",
            "token_type": "Bearer",
        }
    }
    creds_path = root / "credentials.json"
    creds_path.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
    created.append(creds_path)

    # .gitignore
    gitignore_content = (
        "# Claude Code configuration\n"
        "credentials.json\n"
        "settings.json\n"
        "*.log\n"
        ".env\n"
        "*.key\n"
    )
    gitignore_path = root / ".gitignore"
    gitignore_path.write_text(gitignore_content, encoding="utf-8")
    created.append(gitignore_path)

    # Marker
    marker = root / _MARKER_FILENAME
    marker.write_text("canairy-managed\n", encoding="utf-8")

    return created


def _plant_copilot(root: Path) -> list[Path]:
    """Plant a fake GitHub Copilot config directory."""
    created: list[Path] = []

    root.mkdir(parents=True, exist_ok=True)

    oauth_token = _fake_github_token("copilot-token")
    username = _derive_b62("copilot-user", 8).lower()

    # hosts.json
    hosts = {
        "github.com": {
            "oauth_token": oauth_token,
            "user": username,
            "git_protocol": "https",
            "copilot_plan": "business",
        }
    }
    hosts_path = root / "hosts.json"
    hosts_path.write_text(json.dumps(hosts, indent=2), encoding="utf-8")
    created.append(hosts_path)

    # versions.json
    versions = {
        "version": "1.143.0",
        "build": "1.143.7459",
        "last_check": "2024-09-12T14:32:00Z",
    }
    versions_path = root / "versions.json"
    versions_path.write_text(json.dumps(versions, indent=2), encoding="utf-8")
    created.append(versions_path)

    # apps.json — per-IDE copilot settings
    apps = {
        "github.com": {
            "user": username,
            "oauth_token": oauth_token,
        }
    }
    apps_path = root / "apps.json"
    apps_path.write_text(json.dumps(apps, indent=2), encoding="utf-8")
    created.append(apps_path)

    # Marker
    marker = root / _MARKER_FILENAME
    marker.write_text("canairy-managed\n", encoding="utf-8")

    return created


# ---------------------------------------------------------------------------
# Config → root path mapping
# ---------------------------------------------------------------------------

def _config_root(name: str) -> Path:
    home = _home()
    is_win = _is_windows()

    if name == "ollama":
        return home / ".ollama"

    elif name == "claude":
        if is_win:
            appdata = Path(
                __import__("os").environ.get("APPDATA", str(home / "AppData" / "Roaming"))
            )
            return appdata / "claude"
        else:
            return home / ".config" / "claude"

    elif name == "copilot":
        if is_win:
            localappdata = Path(
                __import__("os").environ.get(
                    "LOCALAPPDATA", str(home / "AppData" / "Local")
                )
            )
            return localappdata / "github-copilot"
        else:
            return home / ".config" / "github-copilot"

    else:
        raise ValueError(f"Unknown fake config type: {name!r}")


_PLANTERS = {
    "ollama": _plant_ollama,
    "claude": _plant_claude,
    "copilot": _plant_copilot,
}


# ---------------------------------------------------------------------------
# Marker helpers
# ---------------------------------------------------------------------------


def _is_managed(root: Path) -> bool:
    return (root / _MARKER_FILENAME).exists()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_config_paths(config: dict) -> list[Path]:
    """Return the list of root directory paths being monitored.

    Parameters
    ----------
    config:
        The ``traps.fake_configs`` section.
    """
    configs: list[str] = config.get("configs", list(_PLANTERS.keys()))
    paths = []
    for name in configs:
        try:
            paths.append(_config_root(name))
        except ValueError as exc:
            logger.warning("%s", exc)
    return paths


def plant_fake_configs(config: dict) -> list[Path]:
    """Create fake config directories for the configured tools.

    Skips any directory that already exists and was NOT created by canAIry.

    Returns
    -------
    list[Path]
        Root directory paths that were successfully planted.
    """
    configs: list[str] = config.get("configs", list(_PLANTERS.keys()))
    planted_roots: list[Path] = []

    for name in configs:
        try:
            root = _config_root(name)
        except ValueError as exc:
            logger.warning("%s", exc)
            continue

        if root.exists() and not _is_managed(root):
            logger.info(
                "Skipping %s — directory exists and was not created by canairy.", root
            )
            continue

        try:
            root.mkdir(parents=True, exist_ok=True)
            planter = _PLANTERS[name]
            planter(root)
            planted_roots.append(root)
            logger.info("Planted fake %s config at %s", name, root)
        except Exception as exc:
            logger.error("Failed to plant fake %s config: %s", name, exc)

    return planted_roots


def uninstall_fake_configs(config: dict) -> list[Path]:
    """Remove fake config directories that were created by canAIry.

    Only removes directories that contain the ``.canairy-marker`` file.

    Returns
    -------
    list[Path]
        Root directory paths that were successfully removed.
    """
    configs: list[str] = config.get("configs", list(_PLANTERS.keys()))
    removed: list[Path] = []

    for name in configs:
        try:
            root = _config_root(name)
        except ValueError as exc:
            logger.warning("%s", exc)
            continue

        if not root.exists():
            continue

        if not _is_managed(root):
            logger.warning(
                "Skipping %s — not a canairy-managed directory (no marker).", root
            )
            continue

        try:
            shutil.rmtree(root)
            removed.append(root)
            logger.info("Removed fake %s config directory %s", name, root)
        except OSError as exc:
            logger.error("Failed to remove %s: %s", root, exc)

    return removed
