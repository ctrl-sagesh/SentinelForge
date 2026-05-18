"""Tests for the tamper-evident audit log."""

from pathlib import Path

import pytest

from sentinelforge.core.audit import AuditLogger
from sentinelforge.core.models import ActionStatus, AgentRole


@pytest.fixture
def audit_logger(tmp_path):
    return AuditLogger(str(tmp_path / "test_audit.log"))


class TestAuditLogger:
    def test_log_creates_entry(self, audit_logger):
        entry = audit_logger.log(
            agent=AgentRole.MONITOR,
            action="test_scan",
            status=ActionStatus.EXECUTED,
        )
        assert entry.entry_hash
        assert entry.agent == AgentRole.MONITOR

    def test_hash_chain_valid(self, audit_logger):
        for i in range(5):
            audit_logger.log(
                agent=AgentRole.GUARDIAN,
                action=f"action_{i}",
                status=ActionStatus.EXECUTED,
            )
        valid, count = audit_logger.verify_chain()
        assert valid
        assert count == 5

    def test_tamper_detection(self, audit_logger):
        for i in range(3):
            audit_logger.log(
                agent=AgentRole.MONITOR,
                action=f"action_{i}",
                status=ActionStatus.EXECUTED,
            )

        path = Path(audit_logger._path)
        lines = path.read_text().splitlines()
        import json

        tampered = json.loads(lines[1])
        tampered["action"] = "TAMPERED"
        lines[1] = json.dumps(tampered)
        path.write_text("\n".join(lines) + "\n")

        valid, broken_at = audit_logger.verify_chain()
        assert not valid
