"""Alerting system — console, file, webhook, Slack, email, and syslog.

Sends alerts when critical events are detected, actions are executed,
or safety violations occur.
"""

from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from sentinelforge.core.config import AlertConfig, get_settings
from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import ContainmentAction, ThreatEvent

logger = get_logger("alerting")


class AlertManager:
    """Manages alert delivery across multiple channels."""

    def __init__(self, config: AlertConfig | None = None) -> None:
        self.config = config or get_settings().alerts
        self._severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        self._min_severity_level = self._severity_order.get(self.config.min_severity, 3)

    def alert_threat(self, event: ThreatEvent) -> None:
        """Send alert for a detected threat event."""
        if not self.config.enabled:
            return
        if self._severity_order.get(event.severity.value, 0) < self._min_severity_level:
            return

        message = (
            f"[THREAT] {event.severity.value.upper()} — {event.event_type}: "
            f"{event.description} | Source: {event.source_ip or 'N/A'} | "
            f"MITRE: {', '.join(event.mitre_techniques)}"
        )
        self._dispatch(message, "threat", event.severity.value)

    def alert_action_executed(self, action: ContainmentAction) -> None:
        """Send alert when a containment action is executed."""
        if not self.config.enabled:
            return

        message = (
            f"[ACTION] {action.action_type} executed on {action.target} | "
            f"Risk: {action.risk_score:.2f} | Status: {action.status.value} | "
            f"Approved by: {action.approved_by or 'auto'}"
        )
        self._dispatch(message, "action", "high")

    def alert_safety_violation(self, violation: str) -> None:
        """Send alert for a safety violation."""
        if not self.config.enabled:
            return

        message = f"[SAFETY VIOLATION] {violation}"
        self._dispatch(message, "violation", "critical")

    def alert_approval_needed(self, action: ContainmentAction, timeout_seconds: int) -> None:
        """Send alert that human approval is needed."""
        if not self.config.enabled:
            return

        message = (
            f"[APPROVAL NEEDED] {action.action_type} on {action.target} | "
            f"Risk: {action.risk_score:.2f} | Timeout: {timeout_seconds}s | "
            f"Reason: {action.reasoning[:100]}"
        )
        self._dispatch(message, "approval", "high")

    def alert_approval_timeout(self, action: ContainmentAction) -> None:
        """Send alert that an approval request timed out (auto-denied)."""
        if not self.config.enabled:
            return

        message = (
            f"[APPROVAL TIMEOUT] {action.action_type} on {action.target} auto-denied | "
            f"No human response within timeout period"
        )
        self._dispatch(message, "timeout", "medium")

    def _dispatch(self, message: str, alert_type: str, severity: str) -> None:
        """Send alert to all configured channels."""
        timestamp = datetime.now(timezone.utc).isoformat()

        if self.config.console_alerts:
            self._console_alert(message, severity)

        if self.config.file_alerts:
            self._file_alert(message, alert_type, severity, timestamp)

        if self.config.webhook_enabled and self.config.webhook_url:
            self._webhook_alert(message, alert_type, severity, timestamp)

        slack_url = os.environ.get("SF_SLACK_WEBHOOK_URL", "")
        if slack_url:
            self._slack_alert(message, alert_type, severity, timestamp, slack_url)

        smtp_host = os.environ.get("SF_SMTP_HOST", "")
        if smtp_host:
            self._email_alert(message, alert_type, severity, timestamp)

        syslog_host = os.environ.get("SF_SYSLOG_HOST", "")
        if syslog_host:
            self._syslog_alert(message, alert_type, severity, timestamp, syslog_host)

    def _console_alert(self, message: str, severity: str) -> None:
        color_codes = {
            "critical": "\033[1;31m",  # Bold red
            "high": "\033[0;31m",      # Red
            "medium": "\033[0;33m",    # Yellow
            "low": "\033[0;32m",       # Green
            "info": "\033[0;36m",      # Cyan
        }
        reset = "\033[0m"
        color = color_codes.get(severity, "")
        print(f"{color}{'='*60}\n{message}\n{'='*60}{reset}")

    def _file_alert(self, message: str, alert_type: str, severity: str, timestamp: str) -> None:
        try:
            path = Path(self.config.alert_file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            entry = json.dumps({
                "timestamp": timestamp,
                "type": alert_type,
                "severity": severity,
                "message": message,
            })
            with open(path, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except Exception as e:
            logger.error("file_alert_failed", error=str(e))

    def _webhook_alert(self, message: str, alert_type: str, severity: str, timestamp: str) -> None:
        try:
            import httpx
            payload = {
                "text": message,
                "severity": severity,
                "type": alert_type,
                "timestamp": timestamp,
                "source": "SentinelForge",
            }
            httpx.post(self.config.webhook_url, json=payload, timeout=10)
            logger.info("webhook_alert_sent", type=alert_type)
        except Exception as e:
            logger.error("webhook_alert_failed", error=str(e))

    def _slack_alert(
        self, message: str, alert_type: str, severity: str, timestamp: str, webhook_url: str
    ) -> None:
        """Send alert to Slack via incoming webhook."""
        severity_emoji = {
            "critical": ":rotating_light:", "high": ":red_circle:",
            "medium": ":large_yellow_circle:", "low": ":large_green_circle:",
            "info": ":large_blue_circle:",
        }
        emoji = severity_emoji.get(severity, ":white_circle:")
        channel = os.environ.get("SF_SLACK_CHANNEL", "#security-alerts")

        payload = {
            "channel": channel,
            "username": "SentinelForge",
            "icon_emoji": ":shield:",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} SentinelForge Alert"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Type:* {alert_type}"},
                        {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"_Timestamp: {timestamp}_"},
                    ],
                },
            ],
        }
        try:
            import httpx
            resp = httpx.post(webhook_url, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.info("slack_alert_sent", type=alert_type)
            else:
                logger.warning("slack_alert_error", status=resp.status_code)
        except Exception as e:
            logger.error("slack_alert_failed", error=str(e))

    def _email_alert(
        self, message: str, alert_type: str, severity: str, timestamp: str
    ) -> None:
        """Send alert via SMTP email."""
        import smtplib
        from email.mime.text import MIMEText

        smtp_host = os.environ.get("SF_SMTP_HOST", "")
        smtp_port = int(os.environ.get("SF_SMTP_PORT", "587"))
        smtp_user = os.environ.get("SF_SMTP_USER", "")
        smtp_password = os.environ.get("SF_SMTP_PASSWORD", "")
        from_addr = os.environ.get("SF_SMTP_FROM", "sentinelforge@example.com")
        to_addr = os.environ.get("SF_SMTP_TO", "")

        if not to_addr:
            return

        subject = f"[SentinelForge] {severity.upper()} {alert_type} alert"
        body = f"SentinelForge Security Alert\n\nType: {alert_type}\nSeverity: {severity}\nTime: {timestamp}\n\n{message}"

        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                if smtp_port == 587:
                    server.starttls()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_addr, [to_addr], msg.as_string())
            logger.info("email_alert_sent", type=alert_type, to=to_addr)
        except Exception as e:
            logger.error("email_alert_failed", error=str(e))

    def _syslog_alert(
        self, message: str, alert_type: str, severity: str, timestamp: str, syslog_host: str
    ) -> None:
        """Send alert via Syslog (RFC 5424)."""
        syslog_port = int(os.environ.get("SF_SYSLOG_PORT", "514"))
        syslog_proto = os.environ.get("SF_SYSLOG_PROTO", "udp").lower()

        severity_map = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
        syslog_severity = severity_map.get(severity, 6)
        facility = 10  # security/authorization (authpriv)
        priority = facility * 8 + syslog_severity

        hostname = socket.gethostname()
        app_name = "SentinelForge"
        msg_id = alert_type.upper()
        structured_data = f'[alert@0 severity="{severity}" type="{alert_type}"]'

        rfc5424_msg = (
            f"<{priority}>1 {timestamp} {hostname} {app_name} "
            f"- {msg_id} {structured_data} {message}"
        )

        try:
            if syslog_proto == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    sock.connect((syslog_host, syslog_port))
                    sock.sendall((rfc5424_msg + "\n").encode("utf-8"))
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(rfc5424_msg.encode("utf-8"), (syslog_host, syslog_port))
            logger.info("syslog_alert_sent", type=alert_type, host=syslog_host)
        except Exception as e:
            logger.error("syslog_alert_failed", error=str(e))


_alert_manager: AlertManager | None = None


def get_alert_manager() -> AlertManager:
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


def reset_alert_manager() -> None:
    global _alert_manager
    _alert_manager = None
