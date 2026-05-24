"""Health checks and self-monitoring — monitors resource usage and system state."""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinelforge.core.logging import get_logger

logger = get_logger("health")


@dataclass
class HealthStatus:
    healthy: bool = True
    uptime_seconds: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    audit_chain_valid: bool = True
    agents_status: dict[str, str] = field(default_factory=dict)
    last_check: str = ""
    warnings: list[str] = field(default_factory=list)
    version: str = "0.1.0"
    platform: str = ""


class HealthMonitor:
    """Monitors system resources and agent health."""

    def __init__(
        self,
        cpu_alert: float = 90.0,
        memory_alert: float = 85.0,
    ) -> None:
        self._start_time = time.monotonic()
        self._cpu_alert = cpu_alert
        self._memory_alert = memory_alert
        self._psutil_available = False
        self._agent_heartbeats: dict[str, float] = {}

        try:
            import psutil  # noqa: F401
            self._psutil_available = True
        except ImportError:
            pass

    def check(self) -> HealthStatus:
        status = HealthStatus(
            uptime_seconds=time.monotonic() - self._start_time,
            last_check=datetime.now(timezone.utc).isoformat(),
            platform=f"{platform.system()} {platform.release()}",
        )

        if self._psutil_available:
            self._check_resources(status)

        self._check_agents(status)
        self._check_disk(status)

        status.healthy = len(status.warnings) == 0
        return status

    def _check_resources(self, status: HealthStatus) -> None:
        import psutil

        status.cpu_percent = psutil.cpu_percent(interval=0.1)
        status.memory_percent = psutil.virtual_memory().percent

        if status.cpu_percent > self._cpu_alert:
            status.warnings.append(f"CPU usage high: {status.cpu_percent:.1f}%")
            logger.warning("cpu_high", percent=status.cpu_percent)

        if status.memory_percent > self._memory_alert:
            status.warnings.append(f"Memory usage high: {status.memory_percent:.1f}%")
            logger.warning("memory_high", percent=status.memory_percent)

    def _check_agents(self, status: HealthStatus) -> None:
        now = time.monotonic()
        stale_threshold = 300

        for agent, last_beat in self._agent_heartbeats.items():
            elapsed = now - last_beat
            if elapsed > stale_threshold:
                status.agents_status[agent] = "stale"
                status.warnings.append(f"Agent '{agent}' has not responded in {elapsed:.0f}s")
            else:
                status.agents_status[agent] = "healthy"

    def _check_disk(self, status: HealthStatus) -> None:
        if not self._psutil_available:
            return

        import psutil
        try:
            disk = psutil.disk_usage(".")
            status.disk_percent = disk.percent
            if disk.percent > 90:
                status.warnings.append(f"Disk usage high: {disk.percent:.1f}%")
        except Exception:  # noqa: S110
            pass  # Disk check is optional, failure is non-critical

    def record_heartbeat(self, agent_name: str) -> None:
        self._agent_heartbeats[agent_name] = time.monotonic()

    def get_resource_snapshot(self) -> dict[str, Any]:
        """Get detailed resource stats for dashboard display."""
        if not self._psutil_available:
            return {"available": False}

        import psutil

        mem = psutil.virtual_memory()
        return {
            "available": True,
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(mem.total / (1024**3), 1),
            "memory_used_gb": round(mem.used / (1024**3), 1),
            "memory_percent": mem.percent,
            "uptime_seconds": time.monotonic() - self._start_time,
        }


_health_monitor: HealthMonitor | None = None


def get_health_monitor() -> HealthMonitor:
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor()
    return _health_monitor
