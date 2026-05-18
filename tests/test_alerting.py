"""Tests for the alerting system."""

import json

import pytest

from sentinelforge.core.alerting import AlertManager
from sentinelforge.core.config import AlertConfig
from sentinelforge.core.models import (
    ActionStatus,
    ContainmentAction,
    Severity,
    ThreatEvent,
)


@pytest.fixture
def alert_mgr(tmp_path):
    config = AlertConfig(
        enabled=True,
        console_alerts=False,
        file_alerts=True,
        alert_file_path=str(tmp_path / "test_alerts.log"),
        webhook_enabled=False,
        min_severity="medium",
    )
    return AlertManager(config)


@pytest.fixture
def alert_file(tmp_path):
    return tmp_path / "test_alerts.log"


def _make_event(severity: str = "high") -> ThreatEvent:
    return ThreatEvent(
        event_type="brute_force",
        source="test",
        severity=Severity(severity),
        description="Test brute force event",
        confidence=0.9,
        mitre_techniques=["T1110"],
        source_ip="10.0.0.1",
    )


def _make_action() -> ContainmentAction:
    return ContainmentAction(
        action_type="block_ip",
        target="10.0.0.1",
        risk_score=0.6,
        reasoning="Block attacker IP",
        status=ActionStatus.EXECUTED,
    )


class TestAlertFiltering:
    def test_high_severity_sent(self, alert_mgr, alert_file):
        alert_mgr.alert_threat(_make_event("high"))
        assert alert_file.exists()
        lines = alert_file.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["type"] == "threat"
        assert entry["severity"] == "high"

    def test_low_severity_filtered(self, alert_mgr, alert_file):
        alert_mgr.alert_threat(_make_event("low"))
        assert not alert_file.exists()

    def test_medium_at_threshold(self, alert_mgr, alert_file):
        alert_mgr.alert_threat(_make_event("medium"))
        assert alert_file.exists()

    def test_disabled_sends_nothing(self, tmp_path):
        config = AlertConfig(enabled=False, alert_file_path=str(tmp_path / "no.log"))
        mgr = AlertManager(config)
        mgr.alert_threat(_make_event("critical"))
        assert not (tmp_path / "no.log").exists()


class TestAlertTypes:
    def test_action_executed_alert(self, alert_mgr, alert_file):
        alert_mgr.alert_action_executed(_make_action())
        assert alert_file.exists()
        entry = json.loads(alert_file.read_text().strip())
        assert entry["type"] == "action"

    def test_safety_violation_alert(self, alert_mgr, alert_file):
        alert_mgr.alert_safety_violation("Prompt injection detected in action reasoning")
        assert alert_file.exists()
        entry = json.loads(alert_file.read_text().strip())
        assert entry["type"] == "violation"
        assert entry["severity"] == "critical"

    def test_approval_needed_alert(self, alert_mgr, alert_file):
        action = _make_action()
        alert_mgr.alert_approval_needed(action, timeout_seconds=300)
        assert alert_file.exists()
        entry = json.loads(alert_file.read_text().strip())
        assert entry["type"] == "approval"
        assert "300s" in entry["message"]

    def test_approval_timeout_alert(self, alert_mgr, alert_file):
        action = _make_action()
        alert_mgr.alert_approval_timeout(action)
        assert alert_file.exists()
        entry = json.loads(alert_file.read_text().strip())
        assert entry["type"] == "timeout"


class TestMultipleAlerts:
    def test_multiple_alerts_appended(self, alert_mgr, alert_file):
        alert_mgr.alert_threat(_make_event("high"))
        alert_mgr.alert_threat(_make_event("critical"))
        alert_mgr.alert_action_executed(_make_action())
        lines = alert_file.read_text().strip().split("\n")
        assert len(lines) == 3
