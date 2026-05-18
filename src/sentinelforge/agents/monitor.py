"""Monitor Agent — real-time log/traffic anomaly detection."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sentinelforge.agents.base import BaseAgent
from sentinelforge.core.models import (
    ActionStatus,
    AgentRole,
    OrchestratorState,
    Severity,
    ThreatEvent,
)

ANOMALY_SIGNATURES = {
    "brute_force": {
        "pattern": r"(?:failed\s+(?:login|password|auth)|authentication\s+fail)",
        "severity": Severity.HIGH,
        "mitre": ["T1110"],
        "description": "Multiple authentication failures detected",
    },
    "port_scan": {
        "pattern": r"(?:port\s+scan|SYN\s+scan|connection\s+refused.*(?:\d+\s+times))",
        "severity": Severity.MEDIUM,
        "mitre": ["T1046"],
        "description": "Port scanning activity detected",
    },
    "privilege_escalation": {
        "pattern": r"(?:sudo|su\s+root|privilege.*escalat|setuid|chmod\s+[47])",
        "severity": Severity.CRITICAL,
        "mitre": ["T1548"],
        "description": "Potential privilege escalation attempt",
    },
    "data_exfiltration": {
        "pattern": r"(?:large\s+(?:upload|transfer)|dns\s+tunnel|base64.*(?:POST|curl))",
        "severity": Severity.CRITICAL,
        "mitre": ["T1048"],
        "description": "Possible data exfiltration activity",
    },
    "malware_indicator": {
        "pattern": r"(?:reverse\s+shell|nc\s+-[el]|/dev/tcp|powershell.*-enc|mshta)",
        "severity": Severity.CRITICAL,
        "mitre": ["T1059"],
        "description": "Malware/reverse shell indicator detected",
    },
    "lateral_movement": {
        "pattern": r"(?:psexec|wmic.*process|smbclient|net\s+use|pass.the.hash)",
        "severity": Severity.HIGH,
        "mitre": ["T1021"],
        "description": "Lateral movement indicators detected",
    },
    "suspicious_process": {
        "pattern": r"(?:mimikatz|lazagne|bloodhound|rubeus|certutil.*decode)",
        "severity": Severity.CRITICAL,
        "mitre": ["T1003"],
        "description": "Known offensive tool detected",
    },
    "ransomware": {
        "pattern": r"(?:encrypt|ransom|\.locked|\.crypt|vssadmin.*delete|bcdedit.*recoveryenabled)",
        "severity": Severity.CRITICAL,
        "mitre": ["T1486"],
        "description": "Ransomware indicators detected",
    },
}


class MonitorAgent(BaseAgent):
    """Ingests logs and network data, detects anomalies using signatures and heuristics."""

    role = AgentRole.MONITOR

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._compiled = {
            name: re.compile(sig["pattern"], re.IGNORECASE)
            for name, sig in ANOMALY_SIGNATURES.items()
        }
        self._processed_lines: set[str] = set()
        self._windows_reader: Any = None
        self._file_integrity: Any = None
        self._network_monitor: Any = None
        self._init_monitors()

    def _init_monitors(self) -> None:
        cfg = self.settings.monitor

        if cfg.enable_windows_events or cfg.enable_sysmon:
            try:
                from sentinelforge.monitoring.windows_events import WindowsEventReader
                self._windows_reader = WindowsEventReader()
            except Exception:
                pass

        if cfg.enable_file_integrity and cfg.file_integrity_paths:
            try:
                from sentinelforge.monitoring.file_integrity import FileIntegrityMonitor
                self._file_integrity = FileIntegrityMonitor(cfg.file_integrity_paths)
            except Exception:
                pass

        if cfg.enable_network_monitor:
            try:
                from sentinelforge.monitoring.network import NetworkMonitor
                self._network_monitor = NetworkMonitor(cfg.network_alert_threshold_mbps)
            except Exception:
                pass

    async def run(self, state: OrchestratorState) -> OrchestratorState:
        self.logger.info("monitor_cycle_start", iteration=state.iteration)
        self._audit("monitor_scan", ActionStatus.EXECUTED, iteration=state.iteration)

        new_events: list[ThreatEvent] = []

        for source in self.settings.monitor.log_sources:
            if source == "file":
                for log_path in self.settings.monitor.log_file_paths:
                    events = self._scan_log_file(log_path)
                    new_events.extend(events)
            elif source == "syslog":
                events = self._scan_syslog()
                new_events.extend(events)
            elif source == "simulation":
                pass

        if self._windows_reader and self._windows_reader.available:
            if self.settings.monitor.enable_windows_events:
                new_events.extend(self._windows_reader.read_security_events())
                new_events.extend(self._windows_reader.read_system_events())
            if self.settings.monitor.enable_sysmon:
                new_events.extend(self._windows_reader.read_sysmon_events())

        if self._file_integrity and self.settings.monitor.enable_file_integrity:
            new_events.extend(self._file_integrity.check_integrity())

        if self._network_monitor and self._network_monitor.available:
            new_events.extend(self._network_monitor.check())

        state.events.extend(new_events)
        state.new_events_this_iteration = len(new_events)

        if new_events:
            self.logger.info("threats_detected", count=len(new_events))

        return state

    def _scan_log_file(self, path: str = "./data/sample_logs.txt") -> list[ThreatEvent]:
        log_path = Path(path)
        if not log_path.exists():
            return []

        events: list[ThreatEvent] = []
        with open(log_path) as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped in self._processed_lines:
                    continue
                self._processed_lines.add(stripped)
                for name, compiled in self._compiled.items():
                    if compiled.search(line):
                        sig = ANOMALY_SIGNATURES[name]
                        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                        events.append(
                            ThreatEvent(
                                source="log_file",
                                event_type=name,
                                description=sig["description"],
                                severity=sig["severity"],
                                raw_data={"log_line": stripped},
                                mitre_techniques=sig["mitre"],
                                confidence=0.75,
                                source_ip=ip_match.group(1) if ip_match else "",
                            )
                        )
                        break
        return events

    def _scan_syslog(self) -> list[ThreatEvent]:
        return []

    def analyze_raw_event(self, raw: dict[str, Any]) -> ThreatEvent | None:
        """Analyze a single raw event dict for anomalies."""
        text = json.dumps(raw).lower()
        for name, compiled in self._compiled.items():
            if compiled.search(text):
                sig = ANOMALY_SIGNATURES[name]
                return ThreatEvent(
                    source="api",
                    event_type=name,
                    description=sig["description"],
                    severity=sig["severity"],
                    raw_data=raw,
                    mitre_techniques=sig["mitre"],
                    confidence=0.7,
                )
        return None
