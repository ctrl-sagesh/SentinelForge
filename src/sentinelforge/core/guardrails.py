"""Guardrails — output validation and canary (dry-run) execution.

Validates that agent outputs conform to expected schemas and safety
constraints before any action reaches the executor layer.
"""

from __future__ import annotations

import re

from sentinelforge.core.executors import (
    ExecutionResult,
    block_ip,
    disable_account,
    isolate_host,
    kill_process,
    quarantine_file,
)
from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import ContainmentAction, Investigation, Severity

logger = get_logger("guardrails")


class OutputValidator:
    """Validates agent outputs against expected schemas and constraints."""

    @staticmethod
    def validate_investigation(inv: Investigation) -> list[str]:
        """Check that an investigation output is well-formed."""
        issues: list[str] = []
        if not inv.summary or len(inv.summary) < 5:
            issues.append("Investigation summary is too short or empty")
        if not inv.root_cause:
            issues.append("Investigation has no root cause")
        if inv.confidence < 0 or inv.confidence > 1:
            issues.append(f"Confidence {inv.confidence} is out of [0,1] range")
        if inv.severity == Severity.CRITICAL and inv.confidence < 0.3:
            issues.append("Critical severity with very low confidence is suspicious")
        for action in inv.recommended_actions:
            if _contains_shell_meta(action):
                issues.append(f"Recommended action contains shell metacharacters: {action[:50]}")
        return issues

    @staticmethod
    def validate_action(action: ContainmentAction) -> list[str]:
        """Check that a containment action is well-formed before execution."""
        issues: list[str] = []
        if not action.action_type:
            issues.append("Action has no type")
        if not action.target:
            issues.append("Action has no target")
        if action.risk_score < 0 or action.risk_score > 1:
            issues.append(f"Risk score {action.risk_score} is out of [0,1] range")
        if action.action_type == "block_ip" and not _is_valid_ip(action.target):
            issues.append(f"block_ip target is not a valid IP: {action.target}")
        if action.action_type == "kill_process" and _contains_shell_meta(action.target):
            issues.append("kill_process target contains shell metacharacters")
        if action.action_type == "disable_account" and _contains_shell_meta(action.target):
            issues.append("disable_account target contains shell metacharacters")
        if _contains_shell_meta(action.reasoning):
            issues.append("Action reasoning contains suspicious shell metacharacters")
        return issues

    @staticmethod
    def validate_llm_output(text: str) -> list[str]:
        """Check LLM output for safety issues."""
        issues: list[str] = []
        if len(text) > 50000:
            issues.append("LLM output exceeds 50KB — possible resource exhaustion")
        dangerous_patterns = [
            (r"rm\s+-rf\s+/", "Destructive rm -rf / command detected"),
            (r"format\s+[a-z]:", "Disk format command detected"),
            (r"del\s+/[sf]\s+/q", "Destructive del command detected"),
            (r"DROP\s+TABLE|DROP\s+DATABASE", "SQL DROP command detected"),
            (r"exec\s*\(|eval\s*\(|__import__", "Code execution detected in output"),
        ]
        for pattern, message in dangerous_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                issues.append(message)
        return issues


class CanaryExecutor:
    """Runs actions in canary (dry-run) mode to preview what would happen."""

    @staticmethod
    def run_canary(action: ContainmentAction) -> ExecutionResult:
        """Execute an action in canary mode — validates and previews without side effects."""
        executors = {
            "block_ip": lambda a: block_ip(a.target, canary=True),
            "isolate_host": lambda a: isolate_host(a.target, canary=True),
            "disable_account": lambda a: disable_account(a.target, canary=True),
            "kill_process": lambda a: kill_process(a.target, canary=True),
            "quarantine_file": lambda a: quarantine_file(a.target, canary=True),
        }

        executor = executors.get(action.action_type)
        if executor is None:
            return ExecutionResult(
                success=False,
                output=f"No canary executor for action type: {action.action_type}",
                command_preview="",
                canary=True,
            )

        return executor(action)


def _is_valid_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _contains_shell_meta(text: str) -> bool:
    return bool(re.search(r"[;&|`$\\]", text))
