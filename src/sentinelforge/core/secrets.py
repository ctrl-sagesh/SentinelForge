"""Secrets management — secure loading from .env, environment, and keyring.

Priority order (highest wins):
  1. Environment variables (SF_ prefix)
  2. .env file (project root)
  3. Defaults from config YAML

Secrets are never logged or included in audit trails.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from sentinelforge.core.logging import get_logger

logger = get_logger("secrets")

_SECRETS_LOADED = False
_SECRET_STORE: dict[str, str] = {}

SENSITIVE_KEYS = {
    "SF_JWT_SECRET",
    "SF_LLM__API_KEY",
    "SF_SIEM_API_KEY",
    "SF_OTX_API_KEY",
    "SF_MISP_API_KEY",
    "SF_DASHBOARD_PASSWORD",
}

REDACTED = "***REDACTED***"


def load_dotenv(env_path: Path | None = None) -> dict[str, str]:
    """Load .env file into the secret store without polluting os.environ for non-SF keys."""
    global _SECRETS_LOADED, _SECRET_STORE

    if env_path is None:
        candidates = [Path(".env"), Path("../.env"), Path.home() / ".sentinelforge" / ".env"]
        for c in candidates:
            if c.exists():
                env_path = c
                break

    if env_path is None or not env_path.exists():
        logger.debug("no_dotenv_found")
        _SECRETS_LOADED = True
        return {}

    loaded: dict[str, str] = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^([A-Z_][A-Z0-9_]*)=(.*)$', line, re.IGNORECASE)
            if match:
                key, value = match.group(1), match.group(2)
                value = value.strip().strip("'\"")
                loaded[key] = value
                if key not in os.environ:
                    os.environ[key] = value

    _SECRET_STORE.update(loaded)
    _SECRETS_LOADED = True
    logger.info("dotenv_loaded", keys_loaded=len(loaded), path=str(env_path))
    return loaded


def get_secret(key: str, default: str = "") -> str:
    """Retrieve a secret by key. Checks env vars first, then .env store."""
    if not _SECRETS_LOADED:
        load_dotenv()
    return os.environ.get(key, _SECRET_STORE.get(key, default))


def redact(value: str) -> str:
    """Return a redacted version of a secret for logging."""
    if not value or len(value) < 8:
        return REDACTED
    return value[:4] + "..." + value[-4:]


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive values in a dict for safe logging."""
    out = {}
    for k, v in data.items():
        if any(s in k.upper() for s in ("KEY", "SECRET", "PASSWORD", "TOKEN")):
            out[k] = REDACTED if v else ""
        elif isinstance(v, dict):
            out[k] = redact_dict(v)
        else:
            out[k] = v
    return out


def validate_secrets() -> list[str]:
    """Check that required secrets are present. Returns list of missing keys."""
    missing = []
    jwt_secret = get_secret("SF_JWT_SECRET")
    if not jwt_secret or len(jwt_secret) < 32:
        missing.append("SF_JWT_SECRET (must be at least 32 chars)")
    return missing


def generate_env_template(output_path: Path | None = None) -> str:
    """Generate a .env.example template."""
    template = """# SentinelForge Environment Configuration
# Copy this to .env and fill in your values.
# NEVER commit .env to version control.

# JWT secret for API authentication (minimum 32 characters)
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
SF_JWT_SECRET=

# LLM provider API key (only needed if using cloud LLM)
SF_LLM__API_KEY=

# SIEM connector API key
SF_SIEM_API_KEY=

# Threat intel feed keys
SF_OTX_API_KEY=
SF_MISP_API_KEY=

# Dashboard authentication password
SF_DASHBOARD_PASSWORD=changeme

# Default admin API key (auto-generated on first run if empty)
SF_ADMIN_API_KEY=
"""
    if output_path:
        output_path.write_text(template)
        logger.info("env_template_generated", path=str(output_path))
    return template
