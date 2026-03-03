# canAIry

LLM honeypot — detect attackers probing for AI tools on compromised systems.

When attackers compromise a system, they increasingly search for local LLMs, API keys, and AI CLI tools. canAIry plants realistic decoys that silently alert you the moment someone interacts with them.

## Quick Start

```bash
pip install .
canairy            # Interactive menu — setup, run, test, uninstall
```

Or use direct commands:

```bash
canairy setup      # Choose trap mode and alerts
canairy run        # Start the honeypot
canairy test-alert # Verify alerts are working
```

## Trap Modes

Run `canairy` or `canairy setup` to choose a mode:

### 1. Server Traps

Fake Ollama API server on port 11434. Returns realistic model lists, streams fake completions. Every HTTP request fires an alert. **No changes to your CLI tools.**

Catches attackers running:
```bash
curl http://localhost:11434/api/tags
curl -X POST http://localhost:11434/api/generate -d '{"model":"llama3","prompt":"..."}'
```

### 2. CLI Traps

Fake `claude`, `codex`, `gemini`, `ollama`, `aider` commands with interactive TUI simulation — realistic banners, prompts, and thinking animations. Real tools are renamed so you can still use them:

| Real tool | Renamed to | Fake replaces |
|-----------|-----------|--------------|
| `claude` | `claudereal` | `claude` |
| `codex` | `codexreal` | `codex` |
| `gemini` | `geminireal` | `gemini` |
| `ollama` | `ollamareal` | `ollama` |
| `aider` | `aiderreal` | `aider` |

Every attacker keystroke is captured and alerted. **No server processes.**

### 3. Full

Both server and CLI traps, plus canary API keys in `~/.env` and fake config directories (`~/.ollama/`, `~/.config/claude/`, `~/.config/github-copilot/`).

### 4. Custom

Pick individual traps to enable.

## Alert Channels

Alerts fire through multiple channels simultaneously:

- **Syslog** — for SIEM ingestion (Security Onion, Splunk, Wazuh, etc.)
- **Webhook** — Discord, Slack, or any generic HTTP endpoint
- **Email** — SMTP with STARTTLS
- **Log file** — always-on JSON lines at `~/.canairy/alerts.log`

## Commands

```
canairy              Interactive configuration menu
canairy setup        Quick trap mode selection (alias: install)
canairy run          Start all enabled traps (Ctrl-C to stop)
canairy run --daemon Show systemd setup instructions
canairy status       Show current configuration
canairy test-alert   Send test alert to all configured channels
canairy uninstall    Remove all traps + restore original tools
canairy --version    Show version
```

## SIEM Integration

### Security Onion

```bash
canairy setup
# Choose your trap mode
# Enable syslog -> point to your SO manager IP, port 514
canairy test-alert
# Verify in SO: Alerts / Dashboards -> search for "canAIry"
```

canAIry sends syslog messages with facility `user` at `WARNING` level. The message format is:
```
canAIry alert: trap=<type> name=<description> host=<hostname> ts=<ISO8601>
```

### Splunk / Generic SIEM

Point syslog to your SIEM's syslog collector. All alerts also write to `~/.canairy/alerts.log` as newline-delimited JSON for file-based ingestion.

## Alert Format

Every alert includes forensic context:

```json
{
  "timestamp": "2026-03-01T14:30:00+00:00",
  "hostname": "webserver-prod",
  "trap_type": "ollama_server",
  "trap_name": "Ollama API request: POST /api/generate",
  "details": {
    "source_ip": "10.0.0.5",
    "method": "POST",
    "path": "/api/generate",
    "user_agent": "python-requests/2.31.0"
  }
}
```

## Deployment

### Linux (systemd)

```bash
sudo cp systemd/canairy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canairy
```

### Windows (startup)

```cmd
:: Run at login — add shortcut to shell:startup pointing to:
python -m canairy run
```

### Docker

```dockerfile
FROM python:3.12-slim
COPY . /app
WORKDIR /app
RUN pip install .
CMD ["canairy", "run"]
```

## Configuration

Config lives at `~/.canairy/config.yaml`. Run `canairy setup` to configure interactively, or edit the file directly. See [config.example.yaml](config.example.yaml) for all options.

## Dependencies

- Python 3.10+
- aiohttp, watchdog, pyyaml, psutil

## License

MIT
