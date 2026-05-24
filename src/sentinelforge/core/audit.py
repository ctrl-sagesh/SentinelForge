"""Tamper-evident audit logging with hash chains."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import ActionStatus, AgentRole, AuditEntry

logger = get_logger("audit")


class AuditLogger:
    """Append-only audit log with cryptographic hash chaining."""

    def __init__(self, log_path: str = "./data/audit.log") -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._previous_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self._path.exists():
            return "GENESIS"
        try:
            with open(self._path, "rb") as f:
                last_line = b""
                for current_line in f:
                    last_line = current_line
                last = json.loads(last_line.decode())
                return last.get("entry_hash", "GENESIS")
        except Exception:
            return "GENESIS"

    def log(
        self,
        agent: AgentRole,
        action: str,
        status: ActionStatus,
        target: str = "",
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            agent=agent,
            action=action,
            target=target,
            details=details or {},
            status=status,
            previous_hash=self._previous_hash,
        )
        entry.entry_hash = entry.compute_hash(self._previous_hash)

        with self._lock:
            with open(self._path, "a") as f:
                f.write(entry.model_dump_json() + "\n")
            self._previous_hash = entry.entry_hash

        try:
            from sentinelforge.core.database import get_database
            db = get_database()
            db.save_audit_entry(entry.model_dump(mode="json"))
        except Exception as exc:
            logger.debug("audit_db_write_failed", error=str(exc))

        logger.info(
            "audit_entry",
            agent=agent.value,
            action=action,
            status=status.value,
            entry_hash=entry.entry_hash[:16],
        )
        return entry

    def get_entries(self, limit: int = 100, since_hours: int | None = None) -> list[dict]:
        """Get audit entries from the JSON file with optional time filtering."""
        if not self._path.exists():
            return []
        entries = []
        with open(self._path) as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if since_hours is not None:
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
            cutoff_str = cutoff.isoformat()
            entries = [e for e in entries if e.get("timestamp", "") >= cutoff_str]

        return entries[-limit:]

    def export_csv(self, since_hours: int | None = None) -> str:
        entries = self.get_entries(limit=10000, since_hours=since_hours)
        lines = ["id,timestamp,agent,action,target,status,entry_hash"]
        for e in entries:
            lines.append(
                f"{e.get('id','')},{e.get('timestamp','')},{e.get('agent','')},"
                f"{e.get('action','')},{e.get('target','')},{e.get('status','')},"
                f"{e.get('entry_hash','')}"
            )
        return "\n".join(lines)

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the entire audit chain. Returns (valid, count)."""
        if not self._path.exists():
            return True, 0

        prev_hash = "GENESIS"
        count = 0
        with open(self._path) as f:
            for line in f:
                data = json.loads(line)
                entry = AuditEntry(**data)
                expected = entry.compute_hash(prev_hash)
                if entry.entry_hash != expected:
                    logger.error("audit_chain_broken", line=count, expected=expected)
                    return False, count
                if entry.previous_hash != prev_hash:
                    logger.error("audit_prev_hash_mismatch", line=count)
                    return False, count
                prev_hash = entry.entry_hash
                count += 1

        return True, count


_audit_logger: AuditLogger | None = None


def get_audit_logger(log_path: str = "./data/audit.log") -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_path)
    return _audit_logger
