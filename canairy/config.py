"""Configuration management for canAIry.

Loads and saves YAML config from ~/.canairy/config.yaml.
Falls back to DEFAULT_CONFIG if the file is missing or malformed.
"""

from __future__ import annotations

import copy
import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "alerts": {
        "webhook": {
            "enabled": False,
            "url": "",
        },
        "email": {
            "enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "from_addr": "",
            "to_addr": "",
            "password": "",
        },
        "syslog": {
            "enabled": False,
            "address": "/dev/log",
            "port": 514,
        },
        "logfile": {
            "enabled": True,
            "path": "~/.canairy/alerts.log",
        },
    },
    "traps": {
        "ollama_server": {
            "enabled": True,
            "port": 11434,
            "models": [
                "llama3:latest",
                "mistral:7b-instruct",
                "codellama:13b",
                "deepseek-coder:6.7b",
            ],
        },
        "fake_cli": {
            "enabled": True,
            "tools": ["ollama", "claude", "codex", "aider"],
            "install_path": "",  # empty = auto-detect
        },
        "canary_keys": {
            "enabled": True,
            "locations": [
                "~/.env",
            ],
        },
        "fake_configs": {
            "enabled": True,
            "configs": ["ollama", "claude", "copilot"],
        },
    },
}


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def get_config_dir() -> Path:
    """Return ~/.canairy, creating it (and parents) if it does not exist."""
    config_dir = Path.home() / ".canairy"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def _config_path() -> Path:
    return get_config_dir() / "config.yaml"


# ---------------------------------------------------------------------------
# Deep-merge helper
# ---------------------------------------------------------------------------


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*.

    Keys present only in *base* are kept (provides defaults for missing keys).
    Keys present only in *override* are added.
    For overlapping keys: dicts are merged recursively, all other types take
    the value from *override*.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config() -> dict:
    """Load config.yaml, merging with DEFAULT_CONFIG to fill missing keys.

    Returns a fully-populated config dict. Writes the defaults to disk if no
    config file exists yet.
    """
    path = _config_path()

    if not path.exists():
        logger.debug("No config file found at %s — writing defaults.", path)
        config = copy.deepcopy(DEFAULT_CONFIG)
        save_config(config)
        return config

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.warning(
            "Config file %s is malformed (%s) — using defaults.", path, exc
        )
        return copy.deepcopy(DEFAULT_CONFIG)
    except OSError as exc:
        logger.warning(
            "Could not read config file %s (%s) — using defaults.", path, exc
        )
        return copy.deepcopy(DEFAULT_CONFIG)

    if not isinstance(raw, dict):
        logger.warning(
            "Config file %s does not contain a YAML mapping — using defaults.", path
        )
        return copy.deepcopy(DEFAULT_CONFIG)

    # Merge so that any keys the user hasn't set fall back to defaults.
    return _deep_merge(DEFAULT_CONFIG, raw)


def save_config(config: dict) -> None:
    """Persist *config* to ~/.canairy/config.yaml.

    The file is written atomically (via a temp file + rename) so a crash
    mid-write cannot corrupt the existing config.
    """
    path = _config_path()
    tmp_path = path.with_suffix(".yaml.tmp")

    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(config, fh, default_flow_style=False, allow_unicode=True)
        # Atomic replace — on Windows this may fail if the target is open;
        # fall back to a direct overwrite in that case.
        try:
            os.replace(tmp_path, path)
        except OSError:
            tmp_path.rename(path)
    except OSError as exc:
        logger.error("Failed to save config to %s: %s", path, exc)
        raise
    finally:
        # Clean up the temp file if it still exists (e.g. after an error).
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
