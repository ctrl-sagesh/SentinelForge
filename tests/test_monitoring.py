"""Tests for monitoring modules."""


import pytest

from sentinelforge.monitoring.file_integrity import FileIntegrityMonitor
from sentinelforge.monitoring.network import NetworkMonitor


class TestFileIntegrityMonitor:
    def test_build_baseline(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        fim = FileIntegrityMonitor([str(tmp_path)])
        fim._baseline_path = tmp_path / "baseline.json"
        count = fim.build_baseline()
        assert count >= 1
        assert fim._baseline_path.exists()

    def test_detect_modification(self, tmp_path):
        test_file = tmp_path / "config.txt"
        test_file.write_text("original content")

        fim = FileIntegrityMonitor([str(tmp_path)])
        fim._baseline_path = tmp_path / "baseline.json"
        fim.build_baseline()

        test_file.write_text("TAMPERED content")

        events = fim.check_integrity()
        modified = [e for e in events if e.event_type == "file_modified"]
        assert len(modified) >= 1

    def test_detect_deletion(self, tmp_path):
        test_file = tmp_path / "important.dat"
        test_file.write_text("critical data")

        fim = FileIntegrityMonitor([str(tmp_path)])
        fim._baseline_path = tmp_path / "baseline.json"
        fim.build_baseline()

        test_file.unlink()

        events = fim.check_integrity()
        deleted = [e for e in events if e.event_type == "file_deleted"]
        assert len(deleted) == 1

    def test_detect_new_file(self, tmp_path):
        existing = tmp_path / "existing.txt"
        existing.write_text("ok")

        fim = FileIntegrityMonitor([str(tmp_path)])
        fim._baseline_path = tmp_path / "baseline.json"
        fim.build_baseline()

        new_file = tmp_path / "dropper.exe"
        new_file.write_text("malicious")

        events = fim.check_integrity()
        new = [e for e in events if e.event_type == "new_file"]
        assert len(new) >= 1

    def test_skip_pyc_files(self, tmp_path):
        pyc = tmp_path / "cache.pyc"
        pyc.write_text("bytecode")

        fim = FileIntegrityMonitor([str(tmp_path)])
        fim._baseline_path = tmp_path / "baseline.json"
        count = fim.build_baseline()
        assert count == 0

    def test_no_changes_clean(self, tmp_path):
        test_file = tmp_path / "stable.txt"
        test_file.write_text("unchanged")

        fim = FileIntegrityMonitor([str(tmp_path)])
        fim._baseline_path = tmp_path / "baseline.json"
        fim.build_baseline()

        events = fim.check_integrity()
        assert len(events) == 0


class TestNetworkMonitor:
    def test_init(self):
        nm = NetworkMonitor(alert_threshold_mbps=50.0)
        assert isinstance(nm.available, bool)

    @pytest.mark.skipif(
        not NetworkMonitor().available,
        reason="psutil not available",
    )
    def test_check_returns_events(self):
        nm = NetworkMonitor()
        events = nm.check()
        assert isinstance(events, list)

    @pytest.mark.skipif(
        not NetworkMonitor().available,
        reason="psutil not available",
    )
    def test_get_stats(self):
        nm = NetworkMonitor()
        stats = nm.get_stats()
        assert "bytes_sent" in stats
        assert "established_connections" in stats

    def test_unavailable_returns_empty(self):
        nm = NetworkMonitor()
        nm._available = False
        assert nm.check() == []
        assert nm.get_stats() == {}
