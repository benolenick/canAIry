"""Fake Ollama HTTP API trap.

Mimics the real Ollama REST API on port 11434 (configurable) using aiohttp.
Every request fires an alert via the provided alerter before responding.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp.web

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Realistic model metadata
# ---------------------------------------------------------------------------

_MODEL_META: dict[str, dict[str, Any]] = {
    "llama3:latest": {
        "size": 4661224676,
        "digest_seed": "llama3latest",
        "family": "llama",
        "families": ["llama"],
        "parameter_size": "8B",
        "quantization_level": "Q4_0",
    },
    "llama3:8b": {
        "size": 4661224676,
        "digest_seed": "llama38b",
        "family": "llama",
        "families": ["llama"],
        "parameter_size": "8B",
        "quantization_level": "Q4_0",
    },
    "llama3:70b": {
        "size": 39970766048,
        "digest_seed": "llama370b",
        "family": "llama",
        "families": ["llama"],
        "parameter_size": "70B",
        "quantization_level": "Q4_0",
    },
    "mistral:latest": {
        "size": 4109854720,
        "digest_seed": "mistralatest",
        "family": "mistral",
        "families": ["mistral"],
        "parameter_size": "7B",
        "quantization_level": "Q4_0",
    },
    "mistral:7b-instruct": {
        "size": 4109854720,
        "digest_seed": "mistral7binst",
        "family": "mistral",
        "families": ["mistral"],
        "parameter_size": "7B",
        "quantization_level": "Q4_0",
    },
    "codellama:13b": {
        "size": 7365960704,
        "digest_seed": "codellama13b",
        "family": "llama",
        "families": ["llama"],
        "parameter_size": "13B",
        "quantization_level": "Q4_0",
    },
    "codellama:latest": {
        "size": 3823750912,
        "digest_seed": "codellamatest",
        "family": "llama",
        "families": ["llama"],
        "parameter_size": "7B",
        "quantization_level": "Q4_0",
    },
    "deepseek-coder:6.7b": {
        "size": 3825819648,
        "digest_seed": "deepseek67b",
        "family": "deepseek",
        "families": ["deepseek"],
        "parameter_size": "6.7B",
        "quantization_level": "Q4_0",
    },
    "phi3:latest": {
        "size": 2176178048,
        "digest_seed": "phi3latest",
        "family": "phi3",
        "families": ["phi3"],
        "parameter_size": "3.8B",
        "quantization_level": "Q4_0",
    },
}

_FAKE_RESPONSE_TOKENS = [
    "I", "'d", " be", " happy", " to", " help", " you", " with",
    " that", ".", " Let", " me", " think", " about", " this", " carefully",
    "...", "\n\n", "Based", " on", " what", " you", "'ve", " described",
    ",", " here", "'s", " what", " I", " recommend", ":",
]

_SELECTED_HEADERS = {
    "user-agent", "x-forwarded-for", "x-real-ip", "accept",
    "content-type", "authorization", "origin", "referer",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_digest(seed: str) -> str:
    """Return a realistic-looking sha256 digest from a seed string."""
    raw = hashlib.sha256(seed.encode()).hexdigest()
    # Ollama uses sha256: prefix with full 64-char hex
    return f"sha256:{raw}{raw}"[:71]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _build_model_entry(name: str, meta: dict[str, Any]) -> dict[str, Any]:
    # Deterministic modified_at based on name so it looks stable
    ts_seed = int(hashlib.md5(name.encode()).hexdigest()[:8], 16)
    # Pick a date in 2024
    modified_ts = 1704067200 + (ts_seed % (86400 * 200))  # within ~200 days of 2024-01-01
    modified_at = datetime.fromtimestamp(modified_ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    ) + "Z"
    return {
        "name": name,
        "model": name,
        "modified_at": modified_at,
        "size": meta["size"],
        "digest": _make_digest(meta["digest_seed"]),
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": meta["family"],
            "families": meta["families"],
            "parameter_size": meta["parameter_size"],
            "quantization_level": meta["quantization_level"],
        },
    }


def _source_ip(request: aiohttp.web.Request) -> str:
    """Best-effort extraction of the real client IP."""
    for header in ("X-Forwarded-For", "X-Real-IP"):
        value = request.headers.get(header, "").split(",")[0].strip()
        if value:
            return value
    return request.remote or "unknown"


def _selected_headers(request: aiohttp.web.Request) -> dict[str, str]:
    return {
        k: v
        for k, v in request.headers.items()
        if k.lower() in _SELECTED_HEADERS
    }


async def _read_body(request: aiohttp.web.Request, max_bytes: int = 1024) -> str:
    """Read and truncate request body for alert details."""
    try:
        raw = await request.read()
        text = raw[:max_bytes].decode("utf-8", errors="replace")
        if len(raw) > max_bytes:
            text += f"... [{len(raw) - max_bytes} bytes truncated]"
        return text
    except Exception:
        return "<unreadable>"


async def _fire_alert(
    alerter: Any,
    request: aiohttp.web.Request,
    body_text: str,
) -> None:
    alert = {
        "trap_type": "ollama_server",
        "trap_name": f"Ollama API {request.method} {request.path}",
        "timestamp": _now_iso(),
        "details": {
            "source_ip": _source_ip(request),
            "method": request.method,
            "path": request.path,
            "query_string": str(request.query_string),
            "headers": _selected_headers(request),
            "body": body_text,
        },
    }
    try:
        await alerter.send(alert)
    except Exception as exc:
        logger.warning("Alert send failed: %s", exc)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


async def _handle_root(request: aiohttp.web.Request) -> aiohttp.web.Response:
    body = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body)
    return aiohttp.web.Response(text="Ollama is running\n", content_type="text/plain")


async def _handle_api_tags(request: aiohttp.web.Request) -> aiohttp.web.Response:
    body = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body)

    models = request.app["models"]
    model_list = []
    for name in models:
        meta = _MODEL_META.get(name, {
            "size": 4000000000,
            "digest_seed": name,
            "family": "llama",
            "families": ["llama"],
            "parameter_size": "7B",
            "quantization_level": "Q4_0",
        })
        model_list.append(_build_model_entry(name, meta))

    payload = {"models": model_list}
    return aiohttp.web.Response(
        text=json.dumps(payload),
        content_type="application/json",
    )


async def _handle_api_generate(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
    body_text = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body_text)

    # Parse request to extract model name for realistic echo
    try:
        req_data = json.loads(body_text.split("... [")[0])
        model_name = req_data.get("model", "llama3:latest")
    except Exception:
        model_name = "llama3:latest"

    response = aiohttp.web.StreamResponse(
        status=200,
        headers={"Content-Type": "application/x-ndjson"},
    )
    await response.prepare(request)

    start_ns = time.time_ns()

    for token in _FAKE_RESPONSE_TOKENS:
        line = json.dumps({
            "model": model_name,
            "created_at": _now_iso(),
            "response": token,
            "done": False,
        })
        await response.write((line + "\n").encode())
        await asyncio.sleep(0.05)

    total_ns = time.time_ns() - start_ns
    final = json.dumps({
        "model": model_name,
        "created_at": _now_iso(),
        "response": "",
        "done": True,
        "context": [1, 2, 3, 4, 5],
        "total_duration": total_ns,
        "load_duration": 1523000000,
        "prompt_eval_count": 26,
        "prompt_eval_duration": 130079000,
        "eval_count": len(_FAKE_RESPONSE_TOKENS),
        "eval_duration": total_ns - 130079000,
    })
    await response.write((final + "\n").encode())
    await response.write_eof()
    return response


async def _handle_api_chat(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
    body_text = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body_text)

    try:
        req_data = json.loads(body_text.split("... [")[0])
        model_name = req_data.get("model", "llama3:latest")
    except Exception:
        model_name = "llama3:latest"

    response = aiohttp.web.StreamResponse(
        status=200,
        headers={"Content-Type": "application/x-ndjson"},
    )
    await response.prepare(request)

    start_ns = time.time_ns()

    for token in _FAKE_RESPONSE_TOKENS:
        line = json.dumps({
            "model": model_name,
            "created_at": _now_iso(),
            "message": {
                "role": "assistant",
                "content": token,
            },
            "done": False,
        })
        await response.write((line + "\n").encode())
        await asyncio.sleep(0.05)

    total_ns = time.time_ns() - start_ns
    final = json.dumps({
        "model": model_name,
        "created_at": _now_iso(),
        "message": {"role": "assistant", "content": ""},
        "done": True,
        "total_duration": total_ns,
        "load_duration": 1812000000,
        "prompt_eval_count": 14,
        "prompt_eval_duration": 118522000,
        "eval_count": len(_FAKE_RESPONSE_TOKENS),
        "eval_duration": total_ns - 118522000,
    })
    await response.write((final + "\n").encode())
    await response.write_eof()
    return response


async def _handle_api_pull(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
    body_text = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body_text)

    try:
        req_data = json.loads(body_text.split("... [")[0])
        model_name = req_data.get("name", "llama3:latest")
    except Exception:
        model_name = "llama3:latest"

    response = aiohttp.web.StreamResponse(
        status=200,
        headers={"Content-Type": "application/x-ndjson"},
    )
    await response.prepare(request)

    # Emit realistic pull progress
    steps = [
        {"status": f"pulling manifest"},
        {"status": "pulling 6a0746a1ec1a", "digest": "sha256:6a0746a1ec1a", "total": 4661224676, "completed": 0},
        {"status": "pulling 6a0746a1ec1a", "digest": "sha256:6a0746a1ec1a", "total": 4661224676, "completed": 1165306169},
        {"status": "pulling 6a0746a1ec1a", "digest": "sha256:6a0746a1ec1a", "total": 4661224676, "completed": 2330612338},
        {"status": "pulling 6a0746a1ec1a", "digest": "sha256:6a0746a1ec1a", "total": 4661224676, "completed": 3495918507},
        {"status": "pulling 6a0746a1ec1a", "digest": "sha256:6a0746a1ec1a", "total": 4661224676, "completed": 4661224676},
        {"status": "pulling fa304d675061", "digest": "sha256:fa304d675061", "total": 1152, "completed": 1152},
        {"status": "pulling 8ab4849b038c", "digest": "sha256:8ab4849b038c", "total": 254, "completed": 254},
        {"status": "pulling 577073ffcc6c", "digest": "sha256:577073ffcc6c", "total": 110, "completed": 110},
        {"status": "pulling 3f8eb4da87fa", "digest": "sha256:3f8eb4da87fa", "total": 485, "completed": 485},
        {"status": "verifying sha256 digest"},
        {"status": "writing manifest"},
        {"status": "removing any unused layers"},
        {"status": "success"},
    ]

    for step in steps:
        await response.write((json.dumps(step) + "\n").encode())
        await asyncio.sleep(0.12)

    await response.write_eof()
    return response


async def _handle_api_show(request: aiohttp.web.Request) -> aiohttp.web.Response:
    body_text = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body_text)

    try:
        req_data = json.loads(body_text.split("... [")[0])
        model_name = req_data.get("name", req_data.get("model", "llama3:latest"))
    except Exception:
        model_name = "llama3:latest"

    meta = _MODEL_META.get(model_name, {
        "size": 4000000000,
        "digest_seed": model_name,
        "family": "llama",
        "families": ["llama"],
        "parameter_size": "7B",
        "quantization_level": "Q4_0",
    })

    payload = {
        "license": "LLAMA 3 COMMUNITY LICENSE AGREEMENT\n...",
        "modelfile": (
            f"# Modelfile generated by \"ollama show\"\n"
            f"# To build a new Modelfile based on this, replace FROM with:\n"
            f"# FROM {model_name}\n\n"
            f"FROM /usr/share/ollama/.ollama/models/blobs/sha256-6a0746a1ec1a\n"
            f"TEMPLATE \"\"\"{{{{ if .System }}}}<|start_header_id|>system<|end_header_id|>\n\n"
            f"{{{{ .System }}}}<|eot_id|>{{{{ end }}}}\"\"\"\n"
            f"PARAMETER stop \"<|start_header_id|>\"\n"
            f"PARAMETER stop \"<|end_header_id|>\"\n"
            f"PARAMETER stop \"<|eot_id|>\"\n"
        ),
        "parameters": "stop                           <|start_header_id|>\nstop                           <|end_header_id|>\nstop                           <|eot_id|>",
        "template": "{{ if .System }}<|start_header_id|>system<|end_header_id|>\n\n{{ .System }}<|eot_id|>{{ end }}",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": meta["family"],
            "families": meta["families"],
            "parameter_size": meta["parameter_size"],
            "quantization_level": meta["quantization_level"],
        },
        "model_info": {
            "general.architecture": meta["family"],
            "general.file_type": 2,
            "general.parameter_count": 8030261248,
            "general.quantization_version": 2,
            f"{meta['family']}.attention.head_count": 32,
            f"{meta['family']}.attention.head_count_kv": 8,
            f"{meta['family']}.attention.layer_norm_rms_epsilon": 1e-05,
            f"{meta['family']}.block_count": 32,
            f"{meta['family']}.context_length": 8192,
            f"{meta['family']}.embedding_length": 4096,
            f"{meta['family']}.feed_forward_length": 14336,
            f"{meta['family']}.rope.dimension_count": 128,
            f"{meta['family']}.rope.freq_base": 500000,
            "tokenizer.ggml.model": meta["family"],
        },
        "modified_at": _build_model_entry(model_name, meta)["modified_at"],
    }

    return aiohttp.web.Response(
        text=json.dumps(payload),
        content_type="application/json",
    )


async def _handle_catch_all(request: aiohttp.web.Request) -> aiohttp.web.Response:
    body_text = await _read_body(request)
    await _fire_alert(request.app["alerter"], request, body_text)
    return aiohttp.web.Response(
        status=404,
        text=json.dumps({"error": f"unknown path: {request.path}"}),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app(config: dict, alerter: Any) -> aiohttp.web.Application:
    app = aiohttp.web.Application()
    app["alerter"] = alerter
    app["models"] = config.get("models", list(_MODEL_META.keys()))

    app.router.add_route("GET", "/", _handle_root)
    app.router.add_route("GET", "/api/tags", _handle_api_tags)
    app.router.add_route("POST", "/api/generate", _handle_api_generate)
    app.router.add_route("POST", "/api/chat", _handle_api_chat)
    app.router.add_route("POST", "/api/pull", _handle_api_pull)
    app.router.add_route("POST", "/api/show", _handle_api_show)
    # Catch-all for any other path/method
    app.router.add_route("*", "/{path_info:.*}", _handle_catch_all)

    return app


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def start_ollama_server(
    config: dict,
    alerter: Any,
) -> aiohttp.web.AppRunner:
    """Start the fake Ollama HTTP server.

    Parameters
    ----------
    config:
        The ``traps.ollama_server`` section of the canAIry config dict.
    alerter:
        An object with ``async alerter.send(alert_dict)`` method.

    Returns
    -------
    aiohttp.web.AppRunner
        A running AppRunner. Call ``await runner.cleanup()`` to shut down.
    """
    port: int = config.get("port", 11434)
    host: str = config.get("host", "0.0.0.0")

    app = _build_app(config, alerter)
    runner = aiohttp.web.AppRunner(app, access_log=None)
    await runner.setup()

    site = aiohttp.web.TCPSite(runner, host, port)
    await site.start()

    logger.info(
        "Fake Ollama server listening on %s:%d (%d models)",
        host,
        port,
        len(app["models"]),
    )
    return runner
