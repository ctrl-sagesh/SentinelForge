"""Explainer Agent — generates human-readable incident reports with reasoning traces.

v0.4: Two report modes (executive and technical), LLM-generated summaries with
structured output, confidence scores, and guardrail validation.
"""

from __future__ import annotations

from typing import Any

from sentinelforge.agents.base import BaseAgent
from sentinelforge.core.llm import build_llm, invoke_llm_with_retry
from sentinelforge.core.models import (
    ActionStatus,
    AgentRole,
    IncidentReport,
    OrchestratorState,
    Severity,
)
from sentinelforge.core.safety import get_safety_engine

EXECUTIVE_SCHEMA = """{
  "title": "string — incident title",
  "executive_summary": "string — 2-3 sentence summary",
  "business_impact": "string — what this means for the organization",
  "recommendations": ["string — actionable next steps in plain language"]
}"""

TECHNICAL_SCHEMA = """{
  "title": "string — incident title with MITRE IDs",
  "executive_summary": "string — detailed technical narrative",
  "root_cause_detail": "string — in-depth technical root cause",
  "ioc_summary": "string — indicators of compromise found",
  "recommendations": ["string — specific technical remediation steps"]
}"""

REPORT_PROMPT = """{system_prompt}

Generate an incident report from the following data.

Investigation Summary: {summary}
Root Cause: {root_cause}
Severity: {severity}
Confidence: {confidence}
Affected Assets: {assets}
MITRE Techniques: {mitre}
Actions Taken: {actions}

Report Mode: {mode}

Respond ONLY with valid JSON matching the schema. No markdown, no explanation outside the JSON.
"""


class ExplainerAgent(BaseAgent):
    """Generates human-readable reports for every incident."""

    role = AgentRole.EXPLAINER

    def __init__(self, use_llm: bool = True, report_mode: str = "executive", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._use_llm = use_llm
        self._report_mode = report_mode
        self._llm = None

    async def run(self, state: OrchestratorState) -> OrchestratorState:
        unreported = [
            inv for inv in state.investigations
            if not any(
                r.investigation and r.investigation.id == inv.id
                for r in state.reports
            )
        ]

        if not unreported:
            self.logger.info("no_new_investigations_to_report")
            return state

        for inv in unreported:
            related_actions = [
                a for a in state.executed_actions
                if inv.id in (a.reasoning or "")
            ]

            report = await self._generate_report(inv, related_actions, state)
            state.reports.append(report)

            self._audit(
                "report_generated",
                ActionStatus.EXECUTED,
                report_id=report.id,
                investigation_id=inv.id,
            )

        return state

    async def _generate_report(
        self, inv: Any, actions: list[Any], state: OrchestratorState
    ) -> IncidentReport:
        related_events = [
            e for e in state.events if e.id in inv.event_ids
        ]

        timeline = []
        for e in sorted(related_events, key=lambda x: x.timestamp):
            timeline.append({
                "time": e.timestamp.isoformat(),
                "type": e.event_type,
                "description": e.description,
                "severity": e.severity.value,
            })
        for a in sorted(actions, key=lambda x: x.timestamp):
            timeline.append({
                "time": a.timestamp.isoformat(),
                "type": f"action:{a.action_type}",
                "description": f"{a.action_type} on {a.target}",
                "status": a.status.value,
            })

        if self._use_llm:
            try:
                exec_summary = await self._llm_summary(inv, actions)
            except Exception as exc:
                self.logger.warning("llm_report_failed", error=str(exc))
                exec_summary = self._rule_summary(inv, actions)
        else:
            exec_summary = self._rule_summary(inv, actions)

        recommendations = list(inv.recommended_actions)
        if inv.severity in (Severity.HIGH, Severity.CRITICAL):
            recommendations.append("Review and harden affected systems")
            recommendations.append("Conduct post-incident review within 48 hours")

        return IncidentReport(
            title=f"Incident: {inv.summary}",
            executive_summary=exec_summary,
            timeline=timeline,
            events=related_events,
            investigation=inv,
            actions_taken=actions,
            reasoning_trace=inv.reasoning_trace,
            recommendations=recommendations,
            mitre_mapping=inv.mitre_techniques,
            severity=inv.severity,
        )

    def _rule_summary(self, inv: Any, actions: list[Any]) -> str:
        action_summary = (
            f" {len(actions)} containment actions were executed."
            if actions else " No automated actions were taken."
        )
        return (
            f"A {inv.severity.value}-severity incident was detected: {inv.summary}. "
            f"Root cause: {inv.root_cause}. "
            f"{len(inv.affected_assets)} assets were affected."
            f"{action_summary}"
            f" Confidence: {inv.confidence:.0%}."
        )

    async def _llm_summary(self, inv: Any, actions: list[Any]) -> str:
        if self._llm is None:
            self._llm = build_llm()
        if self._llm is None:
            raise RuntimeError("No LLM available")

        safety = get_safety_engine()
        schema = EXECUTIVE_SCHEMA if self._report_mode == "executive" else TECHNICAL_SCHEMA
        system_prompt = safety.build_system_prompt(schema)

        prompt = REPORT_PROMPT.format(
            system_prompt=system_prompt,
            summary=inv.summary,
            root_cause=inv.root_cause,
            severity=inv.severity.value,
            confidence=f"{inv.confidence:.0%}",
            assets=", ".join(inv.affected_assets[:20]),
            mitre=", ".join(inv.mitre_techniques),
            actions="; ".join(
                f"{a.action_type} on {a.target} ({a.status.value})" for a in actions
            ) or "None",
            mode=self._report_mode,
        )

        valid, reason = safety.validate_llm_prompt(prompt)
        if not valid:
            raise ValueError(f"Prompt validation failed: {reason}")

        content = await invoke_llm_with_retry(self._llm, prompt, sanitize=True)

        valid, reason = safety.validate_llm_output(content)
        if not valid:
            raise ValueError(f"Output validation failed: {reason}")

        try:
            import json
            data = json.loads(content.strip())
            return str(data.get("executive_summary", content))
        except (json.JSONDecodeError, AttributeError):
            return content
