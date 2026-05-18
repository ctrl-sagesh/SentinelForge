"""Network monitor — safe, read-only network telemetry via psutil.

No packet capture, no raw sockets. Only reads OS-level connection
tables and network counters. Safe for unprivileged processes.
"""

from __future__ import annotations

import platform
import time
from collections import Counter
from typing import Any

from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import Severity, ThreatEvent

logger = get_logger("network_monitor")


class NetworkMonitor:
    """Read-only network monitoring using psutil."""

    def __init__(self, alert_threshold_mbps: float = 100.0) -> None:
        self._available = False
        self._threshold_bytes = alert_threshold_mbps * 1024 * 1024 / 8
        self._last_counters: dict[str, Any] | None = None
        self._last_check_time: float = 0
        self._known_connections: set[tuple[str, int, str, int]] = set()

        try:
            import psutil  # noqa: F401
            self._available = True
        except ImportError:
            logger.warning("psutil_not_available")

    @property
    def available(self) -> bool:
        return self._available

    def check(self) -> list[ThreatEvent]:
        """Run all network checks. Returns threat events."""
        if not self._available:
            return []

        events: list[ThreatEvent] = []
        events.extend(self._check_suspicious_connections())
        events.extend(self._check_bandwidth_anomaly())
        events.extend(self._check_listening_ports())
        return events

    def _check_suspicious_connections(self) -> list[ThreatEvent]:
        import psutil

        events: list[ThreatEvent] = []
        connections = psutil.net_connections(kind="inet")

        outbound_by_ip: Counter[str] = Counter()
        current: set[tuple[str, int, str, int]] = set()

        for conn in connections:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue

            raddr_ip = conn.raddr.ip
            raddr_port = conn.raddr.port
            laddr_ip = conn.laddr.ip if conn.laddr else ""
            laddr_port = conn.laddr.port if conn.laddr else 0

            key = (laddr_ip, laddr_port, raddr_ip, raddr_port)
            current.add(key)
            outbound_by_ip[raddr_ip] += 1

        new_connections = current - self._known_connections
        for lip, lport, rip, rport in new_connections:
            if rport in (4444, 5555, 6666, 8888, 9999, 1337, 31337):
                events.append(ThreatEvent(
                    source="network_monitor",
                    event_type="suspicious_port",
                    description=f"Connection to suspicious port {rip}:{rport}",
                    severity=Severity.HIGH,
                    raw_data={"local": f"{lip}:{lport}", "remote": f"{rip}:{rport}"},
                    mitre_techniques=["T1571"],
                    confidence=0.7,
                    source_ip=lip,
                    dest_ip=rip,
                ))

        for ip, count in outbound_by_ip.items():
            if count > 20 and not ip.startswith(("10.", "172.", "192.168.", "127.")):
                events.append(ThreatEvent(
                    source="network_monitor",
                    event_type="high_connection_count",
                    description=f"{count} connections to external IP {ip}",
                    severity=Severity.MEDIUM,
                    raw_data={"remote_ip": ip, "connection_count": count},
                    mitre_techniques=["T1071"],
                    confidence=0.6,
                    dest_ip=ip,
                ))

        self._known_connections = current
        return events

    def _check_bandwidth_anomaly(self) -> list[ThreatEvent]:
        import psutil

        events: list[ThreatEvent] = []
        counters = psutil.net_io_counters()
        now = time.time()

        if self._last_counters and self._last_check_time:
            elapsed = now - self._last_check_time
            if elapsed > 0:
                bytes_sent_rate = (counters.bytes_sent - self._last_counters["bytes_sent"]) / elapsed
                bytes_recv_rate = (counters.bytes_recv - self._last_counters["bytes_recv"]) / elapsed

                if bytes_sent_rate > self._threshold_bytes:
                    mbps = bytes_sent_rate * 8 / (1024 * 1024)
                    events.append(ThreatEvent(
                        source="network_monitor",
                        event_type="bandwidth_anomaly_upload",
                        description=f"High upload rate: {mbps:.1f} Mbps",
                        severity=Severity.HIGH,
                        raw_data={"bytes_per_sec": bytes_sent_rate, "mbps": mbps},
                        mitre_techniques=["T1048"],
                        confidence=0.65,
                    ))

                if bytes_recv_rate > self._threshold_bytes * 2:
                    mbps = bytes_recv_rate * 8 / (1024 * 1024)
                    events.append(ThreatEvent(
                        source="network_monitor",
                        event_type="bandwidth_anomaly_download",
                        description=f"High download rate: {mbps:.1f} Mbps",
                        severity=Severity.MEDIUM,
                        raw_data={"bytes_per_sec": bytes_recv_rate, "mbps": mbps},
                        mitre_techniques=["T1105"],
                        confidence=0.5,
                    ))

        self._last_counters = {
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
        }
        self._last_check_time = now
        return events

    def _check_listening_ports(self) -> list[ThreatEvent]:
        import psutil

        events: list[ThreatEvent] = []
        connections = psutil.net_connections(kind="inet")

        suspicious_listen_ports = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345}

        for conn in connections:
            if conn.status != "LISTEN" or not conn.laddr:
                continue

            port = conn.laddr.port
            if port in suspicious_listen_ports:
                events.append(ThreatEvent(
                    source="network_monitor",
                    event_type="suspicious_listener",
                    description=f"Process listening on suspicious port {port}",
                    severity=Severity.HIGH,
                    raw_data={
                        "port": port,
                        "address": conn.laddr.ip,
                        "pid": conn.pid,
                    },
                    mitre_techniques=["T1059"],
                    confidence=0.75,
                    hostname=platform.node(),
                ))

        return events

    def get_stats(self) -> dict[str, Any]:
        """Return current network statistics for dashboard display."""
        if not self._available:
            return {}

        import psutil

        counters = psutil.net_io_counters()
        connections = psutil.net_connections(kind="inet")

        established = sum(1 for c in connections if c.status == "ESTABLISHED")
        listening = sum(1 for c in connections if c.status == "LISTEN")

        return {
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
            "packets_sent": counters.packets_sent,
            "packets_recv": counters.packets_recv,
            "established_connections": established,
            "listening_ports": listening,
            "total_connections": len(connections),
        }
