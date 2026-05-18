"""Tests for health monitoring."""


from sentinelforge.core.health import HealthMonitor


class TestHealthMonitor:
    def test_check_returns_status(self):
        hm = HealthMonitor()
        status = hm.check()
        assert status.uptime_seconds >= 0
        assert isinstance(status.healthy, bool)
        assert status.version == "0.1.0"

    def test_agent_heartbeat(self):
        hm = HealthMonitor()
        hm.record_heartbeat("monitor")
        status = hm.check()
        assert status.agents_status.get("monitor") == "healthy"

    def test_stale_agent_detected(self):
        import time

        hm = HealthMonitor()
        hm._agent_heartbeats["old_agent"] = time.monotonic() - 600
        status = hm.check()
        assert status.agents_status["old_agent"] == "stale"
        assert any("old_agent" in w for w in status.warnings)

    def test_resource_snapshot(self):
        hm = HealthMonitor()
        snap = hm.get_resource_snapshot()
        assert isinstance(snap, dict)
        if snap.get("available"):
            assert "cpu_percent" in snap
            assert "memory_total_gb" in snap
