"""Windows Event Log and Sysmon log reader.

Reads Security, System, and Application event logs on Windows.
Falls back gracefully on non-Windows systems.
"""

from __future__ import annotations

import platform
from datetime import datetime, timezone

from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import Severity, ThreatEvent

logger = get_logger("windows_events")

SECURITY_EVENT_IDS = {
    4625: ("brute_force", Severity.HIGH, ["T1110"], "Failed logon attempt"),
    4624: ("successful_logon", Severity.INFO, ["T1078"], "Successful logon"),
    4648: ("explicit_credential", Severity.MEDIUM, ["T1078"], "Logon with explicit credentials"),
    4672: ("special_privileges", Severity.MEDIUM, ["T1548"], "Special privileges assigned to new logon"),
    4688: ("process_creation", Severity.LOW, ["T1059"], "New process created"),
    4720: ("account_created", Severity.MEDIUM, ["T1136"], "User account created"),
    4726: ("account_deleted", Severity.MEDIUM, ["T1531"], "User account deleted"),
    4732: ("group_member_added", Severity.HIGH, ["T1098"], "Member added to security-enabled group"),
    4738: ("account_changed", Severity.MEDIUM, ["T1098"], "User account changed"),
    4776: ("credential_validation", Severity.LOW, ["T1110"], "Credential validation attempt"),
    1102: ("audit_log_cleared", Severity.CRITICAL, ["T1070"], "Audit log was cleared"),
    7045: ("service_installed", Severity.HIGH, ["T1543"], "New service installed"),
}

SYSMON_EVENT_IDS = {
    1: ("process_create", Severity.LOW, ["T1059"], "Process creation"),
    3: ("network_connection", Severity.LOW, ["T1071"], "Network connection detected"),
    7: ("image_loaded", Severity.LOW, ["T1055"], "Image loaded"),
    8: ("create_remote_thread", Severity.HIGH, ["T1055"], "CreateRemoteThread detected"),
    10: ("process_access", Severity.MEDIUM, ["T1003"], "Process accessed"),
    11: ("file_created", Severity.LOW, ["T1105"], "File created"),
    12: ("registry_event", Severity.MEDIUM, ["T1112"], "Registry object added or deleted"),
    13: ("registry_value_set", Severity.MEDIUM, ["T1112"], "Registry value set"),
    22: ("dns_query", Severity.LOW, ["T1071"], "DNS query"),
    23: ("file_delete", Severity.LOW, ["T1070"], "File deleted"),
    25: ("process_tampering", Severity.CRITICAL, ["T1055"], "Process tampering detected"),
}


class WindowsEventReader:
    """Reads Windows Event Logs using win32evtlog (if available)."""

    def __init__(self) -> None:
        self._available = False
        self._last_read_times: dict[str, datetime] = {}

        if platform.system() != "Windows":
            logger.info("windows_events_unavailable", reason="not_windows")
            return

        try:
            import win32evtlog  # noqa: F401
            import win32evtlogutil  # noqa: F401
            self._available = True
            logger.info("windows_events_available")
        except ImportError:
            logger.warning("windows_events_unavailable", reason="pywin32_not_installed")

    @property
    def available(self) -> bool:
        return self._available

    def read_security_events(self, max_events: int = 100) -> list[ThreatEvent]:
        if not self._available:
            return []
        return self._read_log("Security", SECURITY_EVENT_IDS, max_events)

    def read_system_events(self, max_events: int = 50) -> list[ThreatEvent]:
        if not self._available:
            return []
        return self._read_log("System", SECURITY_EVENT_IDS, max_events)

    def read_sysmon_events(self, max_events: int = 100) -> list[ThreatEvent]:
        if not self._available:
            return []
        return self._read_log(
            "Microsoft-Windows-Sysmon/Operational",
            SYSMON_EVENT_IDS,
            max_events,
        )

    def _read_log(
        self,
        log_name: str,
        event_map: dict[int, tuple[str, Severity, list[str], str]],
        max_events: int,
    ) -> list[ThreatEvent]:
        try:
            import win32evtlog
            import win32evtlogutil

            server = None
            handle = win32evtlog.OpenEventLog(server, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events: list[ThreatEvent] = []
            last_read = self._last_read_times.get(log_name)
            read_count = 0

            while read_count < max_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break

                for record in records:
                    if read_count >= max_events:
                        break

                    event_time = datetime(
                        record.TimeGenerated.year,
                        record.TimeGenerated.month,
                        record.TimeGenerated.day,
                        record.TimeGenerated.hour,
                        record.TimeGenerated.minute,
                        record.TimeGenerated.second,
                        tzinfo=timezone.utc,
                    )

                    if last_read and event_time <= last_read:
                        continue

                    event_id = record.EventID & 0xFFFF
                    if event_id not in event_map:
                        continue

                    etype, severity, mitre, description = event_map[event_id]

                    try:
                        message = win32evtlogutil.SafeFormatMessage(record, log_name)
                    except Exception:
                        message = f"EventID={event_id}"

                    source_ip = ""
                    if record.StringInserts:
                        for s in record.StringInserts:
                            if s and _looks_like_ip(s):
                                source_ip = s
                                break

                    events.append(
                        ThreatEvent(
                            source=f"windows_{log_name.lower()}",
                            event_type=etype,
                            description=description,
                            severity=severity,
                            raw_data={
                                "event_id": event_id,
                                "source_name": record.SourceName or "",
                                "message": message[:500],
                                "log_name": log_name,
                            },
                            mitre_techniques=mitre,
                            confidence=0.8,
                            source_ip=source_ip,
                            hostname=platform.node(),
                        )
                    )
                    read_count += 1

            if events:
                self._last_read_times[log_name] = max(e.timestamp for e in events)

            win32evtlog.CloseEventLog(handle)
            logger.info("windows_events_read", log=log_name, count=len(events))
            return events

        except Exception as exc:
            logger.error("windows_events_error", log=log_name, error=str(exc))
            return []


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
