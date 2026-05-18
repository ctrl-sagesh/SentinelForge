# SentinelForge Deployment Guide

## Prerequisites

- Python 3.11+
- Docker & Docker Compose (for containerized deployment)
- Ollama (optional, for local LLM inference)

---

## Quick Start (Development)

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1
```

### Linux / macOS

```bash
bash scripts/setup_linux.sh
```

### Manual Setup

```bash
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate     # Windows

pip install -e ".[all]"
cp .env.example .env
# Edit .env with your configuration

mkdir -p data logs

# Run tests to verify
python -m pytest tests/ -q

# Run a simulation
sentinelforge run --scenario brute_force
```

---

## Docker Deployment

### Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  API Server  │  │    Worker    │  │  Dashboard   │  │    Ollama    │
│  :8000       │  │  (one-shot)  │  │  :8501       │  │  :11434      │
│  FastAPI     │  │  Defense     │  │  Streamlit   │  │  Local LLM   │
│              │  │  Cycles      │  │              │  │              │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │                 │
       └─────────────────┴─────────────────┴─────────────────┘
                         sentinelforge-net (bridge)
```

### Steps

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env — set at minimum:
#   SF_AUTH__JWT_SECRET (generate with: python -c "import secrets; print(secrets.token_hex(32))")
#   SF_AUTH__DASHBOARD_PASSWORD

# 2. Build and start
docker compose build
docker compose up -d

# 3. (Optional) Pull Ollama model for LLM analysis
docker exec sentinelforge-ollama ollama pull llama3.1:8b

# 4. Verify
curl http://localhost:8000/health
# Open http://localhost:8501 for dashboard
```

### Services

| Service | Port | Purpose |
|---------|------|---------|
| sentinelforge-api | 8000 | REST API, event submission, defense cycles |
| sentinelforge-worker | - | Runs defense cycles (one-shot, restarts manually) |
| sentinelforge-dashboard | 8501 | Streamlit web UI |
| sentinelforge-ollama | 11434 (localhost only) | Local LLM inference |

### Volumes

| Volume | Purpose |
|--------|---------|
| sf-data | SQLite database, audit logs, vector DB |
| sf-logs | Application logs, alert logs |
| ollama-models | Downloaded LLM models |

---

## Production Checklist

### Security

- [ ] Set a strong `SF_AUTH__JWT_SECRET` (64+ hex chars)
- [ ] Set `SF_AUTH__ENABLED=true`
- [ ] Change `SF_AUTH__DASHBOARD_PASSWORD` from default
- [ ] Set `SF_SIMULATION_MODE=true` initially, switch to `false` only after testing
- [ ] Review `configs/default.yaml` allowed/blocked action lists
- [ ] Restrict CORS origins to your dashboard domain
- [ ] Place the API behind a reverse proxy (nginx/Caddy) with TLS

### Monitoring

- [ ] Enable file alerts: `SF_ALERTS__FILE_ALERTS=true`
- [ ] Configure Slack webhooks: `SF_SLACK_WEBHOOK_URL=https://hooks.slack.com/...`
- [ ] Configure email alerts: set `SF_SMTP_*` variables
- [ ] Set up syslog forwarding: `SF_SYSLOG_HOST=your-siem.example.com`
- [ ] Verify audit chain periodically: `sentinelforge audit --verify`

### Infrastructure

- [ ] Back up `data/sentinelforge.db` and `data/audit.log` regularly
- [ ] Set up log rotation (Docker json-file driver handles this)
- [ ] Monitor container health: `docker compose ps`
- [ ] Set resource limits appropriate to your hardware

---

## LLM Configuration

SentinelForge works in three modes:

### 1. Rule-Based (No LLM)

Default mode. No API keys needed. Uses pattern matching and heuristics.

```bash
sentinelforge run --scenario brute_force
```

### 2. Local LLM (Ollama)

Private, no data leaves your network.

```bash
# Install Ollama: https://ollama.com
ollama pull llama3.1:8b

# Set in .env:
SF_LLM__PROVIDER=ollama
SF_LLM__BASE_URL=http://localhost:11434
SF_LLM__MODEL=llama3.1:8b

sentinelforge run --scenario brute_force --llm
```

### 3. Cloud LLM (Anthropic / OpenAI)

Higher quality analysis, requires API key.

```bash
# Anthropic
SF_LLM__PROVIDER=anthropic
SF_LLM__API_KEY=sk-ant-...

# OpenAI
SF_LLM__PROVIDER=openai
SF_LLM__API_KEY=sk-...

sentinelforge run --scenario brute_force --llm
```

**Auto-detection:** If `SF_LLM__PROVIDER` is not set, the system checks for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `OLLAMA_HOST` environment variables in order.

---

## Alerting Configuration

### Slack

```bash
SF_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/xxx
SF_SLACK_CHANNEL=#security-alerts
```

### Email (SMTP)

```bash
SF_SMTP_HOST=smtp.gmail.com
SF_SMTP_PORT=587
SF_SMTP_USER=alerts@example.com
SF_SMTP_PASSWORD=app-password
SF_SMTP_FROM=sentinelforge@example.com
SF_SMTP_TO=security-team@example.com
```

### Syslog (RFC 5424)

```bash
SF_SYSLOG_HOST=siem.example.com
SF_SYSLOG_PORT=514
SF_SYSLOG_PROTO=udp    # or tcp
```

---

## API Authentication

### Generate a JWT Secret

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Login and Get Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-dashboard-password"}'
```

### Use the Token

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/audit
```

---

## Troubleshooting

### Tests Failing

```bash
# Reset singletons and run tests
python -m pytest tests/ -v --tb=short
```

### Database Issues

```bash
# The database auto-creates on startup. To reset:
rm data/sentinelforge.db
sentinelforge run --scenario brute_force
```

### Audit Chain Broken

```bash
sentinelforge audit --verify
# If broken, the old log can be archived and a new chain starts
mv data/audit.log data/audit.log.bak
```

### Ollama Not Connecting

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# In Docker, ensure the service name is used
SF_LLM__BASE_URL=http://ollama:11434
```

### Dashboard Not Loading

```bash
# Check if Streamlit is installed
pip install streamlit plotly

# Run directly
python -m streamlit run src/sentinelforge/dashboard/app.py
```
