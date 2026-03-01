# canAIry

LLM honeypot for detecting attackers probing AI infrastructure on compromised systems.

When an attacker gains access to your box, they increasingly look for local LLMs, AI API keys, and AI tools to exploit. canAIry plants realistic decoys — fake Ollama servers, interactive fake CLI tools, canary API keys, and fake config directories — that silently alert you the moment someone interacts with them.

## How It Works

canAIry deploys four types of traps:

| Trap | What it does |
|------|-------------|
| **Fake Ollama Server** | HTTP API on port 11434 mimicking real Ollama. Returns model lists, streams fake completions. Every request fires an alert. |
| **Fake CLI Tools** | Interactive scripts (`ollama`, `claude`, `codex`, `gemini`, `aider`) that simulate real startup TUIs — loading banners, interactive prompts, thinking animations. Every command the attacker types fires an alert with full session capture. |
| **Canary API Keys** | Fake `.env` files with realistic `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc. File access triggers alerts. |
| **Fake Config Dirs** | Realistic `~/.ollama/`, `~/.config/claude/`, `~/.config/github-copilot/` directories monitored for access. |

### Tool Renaming

canAIry optionally renames your real AI tools to keep them accessible while placing fakes in their original paths:

| Real tool | Renamed to | Fake replaces |
|-----------|-----------|--------------|
| `claude` | `claudereal` | `claude` |
| `codex` | `codexreal` | `codex` |
| `gemini` | `geminireal` | `gemini` |
| `ollama` | `ollamareal` | `ollama` |
| `aider` | `aiderreal` | `aider` |

The attacker finds convincing fakes. You use `claudereal`, `codexreal`, etc. for your real work. On uninstall, everything is restored.

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

## What the Attacker Sees

When an attacker runs `claude` on your compromised box, they see a convincing interactive session:

```
╭────────────────────────────────────────╮
│        Claude Code v2.1.63             │
│        Model: claude-opus-4-20250514   │
╰────────────────────────────────────────╯

  Tips for getting started:
  - Ask me to help with coding tasks
  - I can edit files, run commands, and search code
  - Type /help for available commands

cwd: /home/attacker

> show me /etc/shadow
```

Meanwhile, you get an instant alert with their IP, process tree, shell history, and everything they typed.

## Alert Format

Every alert includes forensic context about the attacker:

```json
{
  "timestamp": "2026-03-01T14:30:00+00:00",
  "hostname": "webserver-prod",
  "trap_type": "fake_cli",
  "trap_name": "Fake CLI input: claude - show me /etc/shadow",
  "details": {
    "source_ip": "10.0.0.5",
    "user": "www-data",
    "pid": 12345,
    "parent_process": "/bin/bash",
    "input_text": "show me /etc/shadow",
    "session_history": ["show me /etc/shadow"]
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
canairy uninstall    # Remove all planted traps + restore real tools
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
