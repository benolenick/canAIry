"""Canary API key trap.

Plants realistic-looking but fake AI service API keys into .env files.
Keys are deterministically generated from the machine hostname so they look
unique per host but remain reproducible (important for identifying which host
triggered an alert if the keys are used out-of-band).
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
from pathlib import Path

logger = logging.getLogger(__name__)

# Marker appended to every canairy-managed file so we can safely uninstall.
_MANAGED_MARKER = "# canairy-managed"

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _machine_seed() -> str:
    """Return a stable, machine-unique seed string."""
    return socket.getfqdn()


def _derive_hex(label: str, length: int) -> str:
    """Derive a deterministic hex string of *length* chars using the machine seed."""
    seed = _machine_seed()
    raw = hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()
    # Extend by chaining SHA-256 if we need more than 64 chars
    extended = raw
    while len(extended) < length:
        extended += hashlib.sha256(extended.encode()).hexdigest()
    return extended[:length]


def _derive_b62(label: str, length: int) -> str:
    """Derive a deterministic base-62 string (alphanumeric) of *length* chars."""
    _CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    seed = _machine_seed()
    raw_bytes = hashlib.sha256(f"{seed}:{label}".encode()).digest()
    # Stretch with multiple rounds
    extended_bytes = raw_bytes
    while len(extended_bytes) < length:
        extended_bytes += hashlib.sha256(extended_bytes).digest()
    return "".join(_CHARSET[b % 62] for b in extended_bytes[:length])


def _generate_openai_key() -> str:
    # Real format: sk-proj-<48 alphanumeric chars>
    return "sk-proj-" + _derive_b62("openai", 48)


def _generate_anthropic_key() -> str:
    # Real format: sk-ant-api03-<95 alphanumeric + hyphen chars>
    part = _derive_b62("anthropic", 88)
    # Insert two hyphens to mimic real Anthropic key structure
    return f"sk-ant-api03-{part[:44]}-{part[44:]}-AA"


def _generate_huggingface_token() -> str:
    # Real format: hf_<34 alphanumeric chars>
    return "hf_" + _derive_b62("huggingface", 34)


def _generate_replicate_token() -> str:
    # Real format: r8_<40 alphanumeric chars>
    return "r8_" + _derive_b62("replicate", 40)


def _generate_together_key() -> str:
    # 64 hex chars
    return _derive_hex("together", 64)


def _generate_cohere_key() -> str:
    # Real format: <40 alphanumeric chars>
    return _derive_b62("cohere", 40)


def _generate_mistral_key() -> str:
    # Real format: <32 alphanumeric chars>
    return _derive_b62("mistral", 32)


# ---------------------------------------------------------------------------
# .env content builder
# ---------------------------------------------------------------------------

def _build_env_content() -> str:
    lines = [
        "# AI Service Configuration",
        "# Generated configuration — do not commit to version control",
        "",
        f"OPENAI_API_KEY={_generate_openai_key()}",
        f"ANTHROPIC_API_KEY={_generate_anthropic_key()}",
        f"HUGGINGFACE_TOKEN={_generate_huggingface_token()}",
        f"REPLICATE_API_TOKEN={_generate_replicate_token()}",
        f"TOGETHER_API_KEY={_generate_together_key()}",
        f"COHERE_API_KEY={_generate_cohere_key()}",
        f"MISTRAL_API_KEY={_generate_mistral_key()}",
        "",
        "# Model preferences",
        "DEFAULT_MODEL=gpt-4o",
        "FALLBACK_MODEL=claude-sonnet-4-5",
        "EMBEDDING_MODEL=text-embedding-3-small",
        "",
        _MANAGED_MARKER,
    ]
    return "\n".join(lines) + "\n"


def _is_managed(path: Path) -> bool:
    """Return True if *path* contains the canairy marker."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return _MANAGED_MARKER in content
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_canary_paths(config: dict) -> list[Path]:
    """Return the expanded list of canary key file paths from config."""
    locations: list[str] = config.get("locations", ["~/.env"])
    return [Path(loc).expanduser() for loc in locations]


def plant_canary_keys(config: dict) -> list[Path]:
    """Create .env files containing fake API keys at all configured locations.

    If a file already exists at the path, it is left untouched unless it was
    previously managed by canAIry (contains the marker).

    Returns
    -------
    list[Path]
        Paths of files successfully created or updated.
    """
    paths = get_canary_paths(config)
    created: list[Path] = []

    for path in paths:
        try:
            if path.exists() and not _is_managed(path):
                logger.info(
                    "Skipping %s — file exists and was not created by canairy.", path
                )
                continue

            path.parent.mkdir(parents=True, exist_ok=True)
            content = _build_env_content()
            path.write_text(content, encoding="utf-8")
            created.append(path)
            logger.info("Planted canary keys at %s", path)
        except OSError as exc:
            logger.error("Failed to plant canary keys at %s: %s", path, exc)

    return created


def uninstall_canary_keys(config: dict) -> list[Path]:
    """Remove canary key files that were created by canairy.

    Only removes files that contain the ``# canairy-managed`` marker.

    Returns
    -------
    list[Path]
        Paths of files successfully removed.
    """
    paths = get_canary_paths(config)
    removed: list[Path] = []

    for path in paths:
        if not path.exists():
            continue
        if not _is_managed(path):
            logger.warning(
                "Skipping %s — not a canairy-managed file (no marker found).", path
            )
            continue
        try:
            path.unlink()
            removed.append(path)
            logger.info("Removed canary key file %s", path)
        except OSError as exc:
            logger.error("Failed to remove %s: %s", path, exc)

    return removed
