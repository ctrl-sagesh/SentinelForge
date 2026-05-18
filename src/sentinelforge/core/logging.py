"""Structured logging with file rotation, console, and syslog support."""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

import structlog


def setup_logging(
    level: str = "INFO",
    log_to_file: bool = False,
    log_file_path: str = "./logs/sentinelforge.log",
    log_max_size_mb: int = 50,
    log_backup_count: int = 5,
    log_format: str = "json",
    debug: bool = False,
) -> None:
    """Configure structured JSON logging with optional file rotation."""
    if log_to_file:
        log_path = Path(log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_path),
            maxBytes=log_max_size_mb * 1024 * 1024,
            backupCount=log_backup_count,
            encoding="utf-8",
        )
        logging.basicConfig(
            format="%(message)s",
            level=getattr(logging, level.upper(), logging.INFO),
            handlers=[logging.StreamHandler(sys.stderr), file_handler],
            force=True,
        )

    renderer = (
        structlog.dev.ConsoleRenderer()
        if debug or log_format == "console"
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0 if debug else 20),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


_initialized = False


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    global _initialized
    if not _initialized:
        debug = os.environ.get("SF_DEBUG", "false").lower() == "true"
        setup_logging(debug=debug)
        _initialized = True
    return structlog.get_logger(name)
