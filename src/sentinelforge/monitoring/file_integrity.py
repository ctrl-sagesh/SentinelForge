"""File Integrity Monitor (FIM) — detects unauthorized file modifications.

Computes SHA-256 hashes of monitored files and alerts on changes.
Useful for detecting tampering with system binaries, config files,
or web application assets.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import Severity, ThreatEvent

logger = get_logger("file_integrity")

BASELINE_FILE = "./data/fim_baseline.json"


class FileIntegrityMonitor:
    """Tracks file hashes and detects modifications."""

    def __init__(self, monitored_paths: list[str] | None = None) -> None:
        self._paths = monitored_paths or []
        self._baseline: dict[str, dict[str, Any]] = {}
        self._baseline_path = Path(BASELINE_FILE)
        self._load_baseline()

    def _load_baseline(self) -> None:
        if self._baseline_path.exists():
            try:
                with open(self._baseline_path) as f:
                    self._baseline = json.load(f)
                logger.info("fim_baseline_loaded", files=len(self._baseline))
            except (json.JSONDecodeError, OSError):
                self._baseline = {}

    def _save_baseline(self) -> None:
        self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._baseline_path, "w") as f:
            json.dump(self._baseline, f, indent=2)

    def build_baseline(self) -> int:
        """Scan all monitored paths and record current hashes."""
        count = 0
        for path_str in self._paths:
            path = Path(path_str)
            if path.is_file():
                self._hash_file(path)
                count += 1
            elif path.is_dir():
                for fp in path.rglob("*"):
                    if fp.is_file() and not self._should_skip(fp):
                        self._hash_file(fp)
                        count += 1

        self._save_baseline()
        logger.info("fim_baseline_built", files=count)
        return count

    def check_integrity(self) -> list[ThreatEvent]:
        """Compare current file state against baseline. Returns change events."""
        events: list[ThreatEvent] = []

        for file_path, record in list(self._baseline.items()):
            fp = Path(file_path)

            if not fp.exists():
                events.append(self._make_event(
                    file_path, "file_deleted",
                    "Monitored file was deleted",
                    Severity.HIGH,
                ))
                continue

            current_hash = self._compute_hash(fp)
            if current_hash != record.get("hash"):
                current_size = fp.stat().st_size
                events.append(self._make_event(
                    file_path, "file_modified",
                    f"File hash changed (size: {record.get('size', '?')} -> {current_size})",
                    Severity.HIGH,
                ))

            current_perms = oct(fp.stat().st_mode)[-3:]
            if current_perms != record.get("permissions", current_perms):
                events.append(self._make_event(
                    file_path, "permission_changed",
                    f"File permissions changed: {record.get('permissions')} -> {current_perms}",
                    Severity.MEDIUM,
                ))

        for path_str in self._paths:
            path = Path(path_str)
            if path.is_dir():
                for fp in path.rglob("*"):
                    if (
                        fp.is_file()
                        and str(fp) not in self._baseline
                        and fp != self._baseline_path
                        and not self._should_skip(fp)
                    ):
                        events.append(self._make_event(
                            str(fp), "new_file",
                            "New file detected in monitored directory",
                            Severity.MEDIUM,
                        ))

        if events:
            logger.warning("fim_changes_detected", count=len(events))

        return events

    def _hash_file(self, fp: Path) -> None:
        file_hash = self._compute_hash(fp)
        stat = fp.stat()
        self._baseline[str(fp)] = {
            "hash": file_hash,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "permissions": oct(stat.st_mode)[-3:],
        }

    @staticmethod
    def _compute_hash(fp: Path, chunk_size: int = 65536) -> str:
        sha = hashlib.sha256()
        try:
            with open(fp, "rb") as f:
                while chunk := f.read(chunk_size):
                    sha.update(chunk)
            return sha.hexdigest()
        except (PermissionError, OSError):
            return "unreadable"

    @staticmethod
    def _should_skip(fp: Path) -> bool:
        skip_exts = {".pyc", ".pyo", ".tmp", ".swp", ".lock"}
        skip_dirs = {"__pycache__", ".git", "node_modules", ".venv", "venv"}
        return (
            fp.suffix in skip_exts
            or any(d in fp.parts for d in skip_dirs)
        )

    @staticmethod
    def _make_event(
        file_path: str, event_type: str, description: str, severity: Severity
    ) -> ThreatEvent:
        return ThreatEvent(
            source="file_integrity_monitor",
            event_type=event_type,
            description=f"{description}: {file_path}",
            severity=severity,
            raw_data={"file_path": file_path},
            mitre_techniques=["T1565"] if "modif" in event_type else ["T1070"],
            confidence=0.9,
            hostname=os.uname().nodename if hasattr(os, "uname") else "",
        )
