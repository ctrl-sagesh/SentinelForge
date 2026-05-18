"""SQLite persistence layer for SentinelForge.

Stores events, investigations, actions, reports, audit entries, and pending approvals.
Auto-creates tables on startup. Thread-safe via sqlite3's check_same_thread=False.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelforge.core.logging import get_logger

logger = get_logger("database")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT DEFAULT '',
    event_type TEXT DEFAULT '',
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    raw_data TEXT DEFAULT '{}',
    source_ip TEXT DEFAULT '',
    dest_ip TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT DEFAULT '[]',
    iocs TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_ids TEXT DEFAULT '[]',
    summary TEXT DEFAULT '',
    root_cause TEXT DEFAULT '',
    affected_assets TEXT DEFAULT '[]',
    mitre_techniques TEXT DEFAULT '[]',
    severity TEXT DEFAULT 'info',
    confidence REAL DEFAULT 0.0,
    recommended_actions TEXT DEFAULT '[]',
    reasoning_trace TEXT DEFAULT '[]',
    recurrence_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action_type TEXT DEFAULT '',
    target TEXT DEFAULT '',
    status TEXT DEFAULT 'proposed',
    reversible INTEGER DEFAULT 1,
    risk_score REAL DEFAULT 0.0,
    reasoning TEXT DEFAULT '',
    canary_result TEXT DEFAULT '',
    execution_output TEXT DEFAULT '',
    requires_human INTEGER DEFAULT 0,
    approved_by TEXT DEFAULT '',
    rollback_procedure TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    title TEXT DEFAULT '',
    executive_summary TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    investigation_id TEXT DEFAULT '',
    timeline TEXT DEFAULT '[]',
    recommendations TEXT DEFAULT '[]',
    mitre_mapping TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent TEXT DEFAULT '',
    action TEXT DEFAULT '',
    target TEXT DEFAULT '',
    status TEXT DEFAULT '',
    details TEXT DEFAULT '{}',
    previous_hash TEXT DEFAULT '',
    entry_hash TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    action_data TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    timeout_seconds INTEGER DEFAULT 300,
    reason TEXT DEFAULT '',
    approved INTEGER DEFAULT NULL,
    decided_by TEXT DEFAULT '',
    decided_at TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""


class Database:
    """SQLite database for SentinelForge persistence."""

    def __init__(self, db_path: str = "./data/sentinelforge.db") -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        logger.info("database_initialized", path=self._db_path)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=10,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # --- Events ---

    def save_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._get_conn().execute(
                """INSERT OR REPLACE INTO events
                   (id, timestamp, source, event_type, description, severity,
                    raw_data, source_ip, dest_ip, hostname, confidence,
                    mitre_techniques, iocs)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["id"], event.get("timestamp", ""),
                    event.get("source", ""), event.get("event_type", ""),
                    event.get("description", ""), event.get("severity", "info"),
                    json.dumps(event.get("raw_data", {})),
                    event.get("source_ip", ""), event.get("dest_ip", ""),
                    event.get("hostname", ""), event.get("confidence", 0.0),
                    json.dumps(event.get("mitre_techniques", [])),
                    json.dumps(event.get("iocs", [])),
                ),
            )
            self._get_conn().commit()

    def get_recent_events(self, hours: int = 24, limit: int = 100) -> list[dict]:
        cutoff = datetime.now(timezone.utc).isoformat()
        rows = self._get_conn().execute(
            """SELECT * FROM events
               WHERE timestamp >= datetime(?, '-' || ? || ' hours')
               ORDER BY timestamp DESC LIMIT ?""",
            (cutoff, hours, limit),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def find_events_by_source_ip(self, source_ip: str, hours: int = 24) -> list[dict]:
        cutoff = datetime.now(timezone.utc).isoformat()
        rows = self._get_conn().execute(
            """SELECT * FROM events
               WHERE source_ip = ? AND timestamp >= datetime(?, '-' || ? || ' hours')
               ORDER BY timestamp DESC""",
            (source_ip, cutoff, hours),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # --- Investigations ---

    def save_investigation(self, inv: dict[str, Any]) -> None:
        with self._lock:
            self._get_conn().execute(
                """INSERT OR REPLACE INTO investigations
                   (id, timestamp, event_ids, summary, root_cause,
                    affected_assets, mitre_techniques, severity, confidence,
                    recommended_actions, reasoning_trace, recurrence_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    inv["id"], inv.get("timestamp", ""),
                    json.dumps(inv.get("event_ids", [])),
                    inv.get("summary", ""), inv.get("root_cause", ""),
                    json.dumps(inv.get("affected_assets", [])),
                    json.dumps(inv.get("mitre_techniques", [])),
                    inv.get("severity", "info"), inv.get("confidence", 0.0),
                    json.dumps(inv.get("recommended_actions", [])),
                    json.dumps(inv.get("reasoning_trace", [])),
                    inv.get("recurrence_count", 0),
                ),
            )
            self._get_conn().commit()

    # --- Actions ---

    def save_action(self, action: dict[str, Any]) -> None:
        with self._lock:
            self._get_conn().execute(
                """INSERT OR REPLACE INTO actions
                   (id, timestamp, action_type, target, status, reversible,
                    risk_score, reasoning, canary_result, execution_output,
                    requires_human, approved_by, rollback_procedure)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action["id"], action.get("timestamp", ""),
                    action.get("action_type", ""), action.get("target", ""),
                    action.get("status", "proposed"),
                    1 if action.get("reversible", True) else 0,
                    action.get("risk_score", 0.0), action.get("reasoning", ""),
                    action.get("canary_result", ""), action.get("execution_output", ""),
                    1 if action.get("requires_human", False) else 0,
                    action.get("approved_by", ""),
                    action.get("rollback_procedure", ""),
                ),
            )
            self._get_conn().commit()

    # --- Reports ---

    def save_report(self, report: dict[str, Any]) -> None:
        with self._lock:
            inv_id = ""
            if report.get("investigation"):
                inv_id = report["investigation"].get("id", "") if isinstance(report["investigation"], dict) else ""
            self._get_conn().execute(
                """INSERT OR REPLACE INTO reports
                   (id, timestamp, title, executive_summary, severity,
                    investigation_id, timeline, recommendations, mitre_mapping)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report["id"], report.get("timestamp", ""),
                    report.get("title", ""), report.get("executive_summary", ""),
                    report.get("severity", "info"), inv_id,
                    json.dumps(report.get("timeline", [])),
                    json.dumps(report.get("recommendations", [])),
                    json.dumps(report.get("mitre_mapping", [])),
                ),
            )
            self._get_conn().commit()

    def get_reports(self, limit: int = 50) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT * FROM reports ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # --- Audit Log ---

    def save_audit_entry(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._get_conn().execute(
                """INSERT OR REPLACE INTO audit_log
                   (id, timestamp, agent, action, target, status,
                    details, previous_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry["id"], entry.get("timestamp", ""),
                    entry.get("agent", ""), entry.get("action", ""),
                    entry.get("target", ""), entry.get("status", ""),
                    json.dumps(entry.get("details", {})),
                    entry.get("previous_hash", ""),
                    entry.get("entry_hash", ""),
                ),
            )
            self._get_conn().commit()

    def get_audit_entries(self, limit: int = 100, since_hours: int | None = None) -> list[dict]:
        if since_hours:
            cutoff = datetime.now(timezone.utc).isoformat()
            rows = self._get_conn().execute(
                """SELECT * FROM audit_log
                   WHERE timestamp >= datetime(?, '-' || ? || ' hours')
                   ORDER BY timestamp DESC LIMIT ?""",
                (cutoff, since_hours, limit),
            ).fetchall()
        else:
            rows = self._get_conn().execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def export_audit_csv(self, since_hours: int | None = None) -> str:
        entries = self.get_audit_entries(limit=10000, since_hours=since_hours)
        if not entries:
            return "id,timestamp,agent,action,target,status,entry_hash\n"
        lines = ["id,timestamp,agent,action,target,status,entry_hash"]
        for e in entries:
            lines.append(
                f"{e.get('id','')},{e.get('timestamp','')},{e.get('agent','')},"
                f"{e.get('action','')},{e.get('target','')},{e.get('status','')},"
                f"{e.get('entry_hash','')}"
            )
        return "\n".join(lines)

    # --- Pending Approvals ---

    def save_pending_approval(self, action_id: str, action_data: str,
                              requested_at: str, timeout_seconds: int,
                              reason: str) -> int:
        with self._lock:
            cursor = self._get_conn().execute(
                """INSERT INTO pending_approvals
                   (action_id, action_data, requested_at, timeout_seconds, reason)
                   VALUES (?, ?, ?, ?, ?)""",
                (action_id, action_data, requested_at, timeout_seconds, reason),
            )
            self._get_conn().commit()
            return cursor.lastrowid

    def get_pending_approvals(self) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT * FROM pending_approvals WHERE approved IS NULL ORDER BY requested_at"
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def resolve_approval(self, action_id: str, approved: bool, decided_by: str) -> None:
        with self._lock:
            self._get_conn().execute(
                """UPDATE pending_approvals
                   SET approved = ?, decided_by = ?, decided_at = ?
                   WHERE action_id = ? AND approved IS NULL""",
                (1 if approved else 0, decided_by,
                 datetime.now(timezone.utc).isoformat(), action_id),
            )
            self._get_conn().commit()

    # --- Helpers ---

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for key in ("raw_data", "details", "event_ids", "affected_assets",
                     "mitre_techniques", "iocs", "recommended_actions",
                     "reasoning_trace", "timeline", "recommendations",
                     "mitre_mapping"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d


_database: Database | None = None


def get_database() -> Database:
    global _database
    if _database is None:
        from sentinelforge.core.config import get_settings
        db_path = getattr(get_settings(), "database_path", "./data/sentinelforge.db")
        _database = Database(db_path)
    return _database


def reset_database() -> None:
    global _database
    if _database:
        _database.close()
    _database = None
