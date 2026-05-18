"""Centralized configuration loaded from YAML + environment variables."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class AggressivenessLevel(str, Enum):
    PASSIVE = "passive"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


class LLMConfig(BaseModel):
    provider: LLMProvider = LLMProvider.OLLAMA
    model: str = "llama3.1:8b"
    base_url: str = "http://localhost:11434"
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 4096


class SafetyConfig(BaseModel):
    human_approval_required: bool = True
    max_actions_per_minute: int = 10
    allowed_containment_actions: list[str] = Field(
        default_factory=lambda: ["block_ip", "isolate_host", "disable_account", "kill_process", "quarantine_file"]
    )
    blocked_actions: list[str] = Field(
        default_factory=lambda: ["wipe_disk", "shutdown_network", "delete_logs"]
    )
    prompt_injection_detection: bool = True
    sandbox_mode: bool = True


class MonitorConfig(BaseModel):
    log_sources: list[str] = Field(default_factory=lambda: ["syslog", "file"])
    poll_interval_seconds: int = 5
    anomaly_threshold: float = 0.7
    log_file_paths: list[str] = Field(default_factory=lambda: ["./data/sample_logs.txt"])
    watch_directories: list[str] = Field(default_factory=list)
    enable_windows_events: bool = False
    enable_sysmon: bool = False
    enable_file_integrity: bool = False
    file_integrity_paths: list[str] = Field(default_factory=list)
    enable_network_monitor: bool = False
    network_alert_threshold_mbps: float = 100.0


class ConnectorConfig(BaseModel):
    siem_type: str = "none"
    siem_url: str = ""
    siem_api_key: str = ""
    threat_intel_feeds: list[str] = Field(
        default_factory=lambda: ["otx", "misp_local"]
    )


class AuthConfig(BaseModel):
    enabled: bool = False
    jwt_secret: str = ""
    token_expiry_seconds: int = 3600
    dashboard_password: str = "changeme"
    require_auth_for_api: bool = False


class APIConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    rate_limit_per_minute: int = 60
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    max_request_size_kb: int = 1024


class LoggingConfig(BaseModel):
    level: str = "INFO"
    log_to_file: bool = True
    log_file_path: str = "./logs/sentinelforge.log"
    log_max_size_mb: int = 50
    log_backup_count: int = 5
    log_format: str = "json"


class ResponderConfig(BaseModel):
    canary_mode: bool = True
    executor_timeout_seconds: int = 30
    allowed_executors: list[str] = Field(
        default_factory=lambda: ["block_ip", "isolate_host", "disable_account", "kill_process", "quarantine_file"]
    )
    approval_timeout_seconds: int = 300
    auto_deny_on_timeout: bool = True


class AlertConfig(BaseModel):
    enabled: bool = True
    console_alerts: bool = True
    file_alerts: bool = True
    alert_file_path: str = "./logs/alerts.log"
    webhook_url: str = ""
    webhook_enabled: bool = False
    min_severity: str = "high"


class HealthConfig(BaseModel):
    enable_self_monitor: bool = True
    cpu_alert_percent: float = 90.0
    memory_alert_percent: float = 85.0
    check_interval_seconds: int = 30


class Settings(BaseSettings):
    project_name: str = "SentinelForge"
    environment: str = "development"
    debug: bool = False
    aggressiveness: AggressivenessLevel = AggressivenessLevel.MODERATE
    llm: LLMConfig = Field(default_factory=LLMConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    connectors: ConnectorConfig = Field(default_factory=ConnectorConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)
    responder: ResponderConfig = Field(default_factory=ResponderConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    vector_db_path: str = "./data/vector_db"
    audit_log_path: str = "./data/audit.log"
    simulation_mode: bool = True

    model_config = {"env_prefix": "SF_", "env_nested_delimiter": "__"}


def load_config(config_path: Path | None = None) -> Settings:
    """Load settings from YAML file, overridden by environment variables."""
    base: dict[str, Any] = {}
    if config_path and config_path.exists():
        with open(config_path) as f:
            base = yaml.safe_load(f) or {}
    elif (default := Path("configs/default.yaml")).exists():
        with open(default) as f:
            base = yaml.safe_load(f) or {}

    return Settings(**base)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_config()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
