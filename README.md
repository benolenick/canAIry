# canAIry

LLM honeypot for detecting attackers probing AI infrastructure on compromised systems.

When an attacker gains access to your box, they increasingly look for local LLMs, AI API keys, and AI tools to exploit. canAIry plants realistic decoys — fake Ollama servers, fake CLI tools, canary API keys, and fake config directories — that silently alert you the moment someone interacts with them.

## How It Works

canAIry deploys four types of traps:

| Trap | What it does |
|------|-------------|
| **Fake Ollama Server** | HTTP API on port 11434 mimicking real Ollama. Returns model lists, streams fake completions. Every request fires an alert. |
| **Fake CLI Tools** | Standalone scripts (`ollama`, `claude`, `codex`, `aider`) that print realistic output and phone home when executed. |
| **Canary API Keys** | Fake `.env` files with realistic `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc. File access triggers alerts. |
| **Fake Config Dirs** | Realistic `~/.ollama/`, `~/.config/claude/`, `~/.config/github-copilot/` directories monitored for access. |

Alerts fire through multiple channels simultaneously:
- **Webhook** — Discord, Slack, or any generic endpoint
- **Email** — SMTP with TLS
- **Syslog** — for SIEM ingestion (e.g., Security Onion)
- **Log file** — always-on JSON lines at `~/.canairy/alerts.log`

## Quick Start

```bash
# Install
pip install .

# Interactive setup — pick traps and configure alerts
canairy install

# Start the honeypot
canairy run

# Test your alert channels
canairy test-alert
```

## Alert Format

Every alert includes forensic context about the attacker:

```json
{
  "timestamp": "2026-03-01T14:30:00+00:00",
  "hostname": "webserver-prod",
  "trap_type": "ollama_server",
  "trap_name": "Ollama API GET /api/tags",
  "details": {
    "source_ip": "10.0.0.5",
    "user": "www-data",
    "pid": 12345,
    "parent_process": "/bin/bash",
    "command_line": "curl http://localhost:11434/api/tags",
    "working_directory": "/tmp"
  }
}
```

## Commands

```
canairy install      # Interactive setup wizard
canairy run          # Start all enabled traps (Ctrl-C to stop)
canairy run --daemon # Show systemd setup instructions
canairy status       # Show which traps and alert channels are configured
canairy test-alert   # Send a test alert to all configured channels
canairy uninstall    # Remove all planted traps (keeps config and logs)
```

## Configuration

Config lives at `~/.canairy/config.yaml`. See [config.example.yaml](config.example.yaml) for all options.

## Deployment

### Systemd (recommended for Linux servers)

```bash
sudo cp systemd/canairy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canairy
```

### Docker

```dockerfile
FROM python:3.12-slim
COPY . /app
WORKDIR /app
RUN pip install .
CMD ["canairy", "run"]
```

## Dependencies

- Python 3.10+
- aiohttp
- watchdog
- pyyaml
- psutil

## License

MIT
