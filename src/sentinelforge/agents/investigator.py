"""Investigator Agent — correlates events, queries threat intel, root cause analysis.

v0.4: Real LLM integration with structured prompts, JSON output parsing,
Guardian sanitization, guardrail validation, and knowledge base enrichment.
Falls back to rule-based analysis when LLM is unavailable or returns invalid output.
"""

from __future__ import annotations

import json
from typing import Any

from sentinelforge.agents.base import BaseAgent
from sentinelforge.core.guardrails import OutputValidator
from sentinelforge.core.llm import build_llm, invoke_llm_with_retry
from sentinelforge.core.models import (
    ActionStatus,
    AgentRole,
    Investigation,
    OrchestratorState,
    Severity,
    ThreatEvent,
)
from sentinelforge.core.safety import get_safety_engine

INVESTIGATION_SCHEMA = """{
  "summary": "string — concise description of the incident",
  "root_cause": "string — root cause analysis",
  "affected_assets": ["string — IPs, hostnames, or accounts"],
  "mitre_techniques": ["string — MITRE ATT&CK IDs like T1110"],
  "severity": "string — one of: info, low, medium, high, critical",
  "confidence": "float — 0.0 to 1.0",
  "recommended_actions": ["string — e.g. 'block_ip 10.0.0.1'"],
  "reasoning_trace": ["string — step-by-step analysis"]
}"""

INVESTIGATION_PROMPT = """{system_prompt}

Analyze the following security events and produce a structured investigation.

Events:
{events}

{knowledge_context}

Respond ONLY with valid JSON matching the schema. No markdown, no explanation outside the JSON.
"""


class InvestigatorAgent(BaseAgent):
    """Correlates events, enriches with threat intel, performs root cause analysis."""

    role = AgentRole.INVESTIGATOR

    def __init__(self, use_llm: bool = True, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._use_llm = use_llm
        self._llm = None

    async def run(self, state: OrchestratorState) -> OrchestratorState:
        uninvestigated = [
            e for e in state.events
            if not any(e.id in inv.event_ids for inv in state.investigations)
        ]

        if not uninvestigated:
            self.logger.info("no_new_events_to_investigate")
            return state

        self.logger.info("investigating_events", count=len(uninvestigated))

        correlated_groups = self._correlate_events(uninvestigated)

        for group in correlated_groups:
            investigation = await self._investigate_group(group)
            state.investigations.append(investigation)
            self._audit(
                "investigation_complete",
                ActionStatus.EXECUTED,
                investigation_id=investigation.id,
                severity=investigation.severity.value,
            )

        return state

    def _correlate_events(self, events: list[ThreatEvent]) -> list[list[ThreatEvent]]:
        groups: dict[str, list[ThreatEvent]] = {}
        for event in events:
            key = event.source_ip or event.hostname or event.event_type
            groups.setdefault(key, []).append(event)
        return list(groups.values())

    async def _investigate_group(self, events: list[ThreatEvent]) -> Investigation:
        event_ids = [e.id for e in events]
        max_severity = max(events, key=lambda e: self._severity_rank(e.severity))

        all_iocs: list[str] = []
        all_mitre: list[str] = []
        all_assets: list[str] = []

        for e in events:
            all_iocs.extend(e.iocs)
            all_mitre.extend(e.mitre_techniques)
            if e.source_ip:
                all_assets.append(e.source_ip)
            if e.dest_ip:
                all_assets.append(e.dest_ip)
            if e.hostname:
                all_assets.append(e.hostname)

        if self._use_llm:
            try:
                inv = await self._llm_investigate(events, event_ids)
            except Exception as exc:
                self.logger.warning("llm_investigation_failed", error=str(exc))
                inv = self._rule_investigate(events, event_ids, all_assets, all_mitre)
        else:
            inv = self._rule_investigate(events, event_ids, all_assets, all_mitre)

        recurrence = self._check_recurrence(events)
        if recurrence > 0:
            inv.reasoning_trace.append(f"Cross-run correlation: {recurrence} prior events from same source in last 24h")
            if recurrence >= 5 and self._severity_rank(inv.severity) < 3:
                inv.severity = Severity.HIGH
                inv.reasoning_trace.append("Severity escalated to HIGH due to repeated activity")

        return inv

    def _rule_investigate(
        self,
        events: list[ThreatEvent],
        event_ids: list[str],
        all_assets: list[str],
        all_mitre: list[str],
    ) -> Investigation:
        max_severity = max(events, key=lambda e: self._severity_rank(e.severity))

        reasoning = [
            f"Analyzed {len(events)} correlated events",
            f"Event types: {', '.join(set(e.event_type for e in events))}",
            f"Source IPs involved: {', '.join(set(e.source_ip for e in events if e.source_ip))}",
            f"MITRE techniques: {', '.join(set(all_mitre))}",
        ]

        recommended = []
        for e in events:
            if e.source_ip and e.severity in (Severity.HIGH, Severity.CRITICAL):
                recommended.append(f"block_ip {e.source_ip}")
            if e.hostname and e.severity == Severity.CRITICAL:
                recommended.append(f"isolate_host {e.hostname}")

        return Investigation(
            event_ids=event_ids,
            summary=f"Correlated incident: {', '.join(set(e.event_type for e in events))}",
            root_cause=f"Detected {events[0].event_type} activity from {events[0].source_ip or 'unknown source'}",
            affected_assets=list(set(all_assets)),
            mitre_techniques=list(set(all_mitre)),
            severity=max_severity.severity,
            confidence=max(e.confidence for e in events),
            recommended_actions=recommended,
            reasoning_trace=reasoning,
        )

    async def _llm_investigate(
        self, events: list[ThreatEvent], event_ids: list[str]
    ) -> Investigation:
        if self._llm is None:
            self._llm = build_llm()
        if self._llm is None:
            raise RuntimeError("No LLM available")

        safety = get_safety_engine()
        system_prompt = safety.build_system_prompt(INVESTIGATION_SCHEMA)

        events_text = "\n".join(
            f"- [{e.severity.value}] {e.event_type}: {e.description} "
            f"(src={e.source_ip}, dst={e.dest_ip}, host={e.hostname}, "
            f"mitre={','.join(e.mitre_techniques)})"
            for e in events
        )

        knowledge_context = self._get_knowledge_context(events)

        prompt = INVESTIGATION_PROMPT.format(
            system_prompt=system_prompt,
            events=events_text,
            knowledge_context=knowledge_context,
        )

        valid, reason = safety.validate_llm_prompt(prompt)
        if not valid:
            raise ValueError(f"Prompt validation failed: {reason}")

        content = await invoke_llm_with_retry(self._llm, prompt, sanitize=True)

        valid, reason = safety.validate_llm_output(content)
        if not valid:
            raise ValueError(f"Output validation failed: {reason}")

        data = _parse_llm_json(content)

        inv = Investigation(
            event_ids=event_ids,
            summary=str(data.get("summary", ""))[:500],
            root_cause=str(data.get("root_cause", ""))[:500],
            affected_assets=_safe_list(data.get("affected_assets", [])),
            mitre_techniques=_safe_list(data.get("mitre_techniques", [])),
            severity=_safe_severity(data.get("severity", "medium")),
            confidence=_safe_float(data.get("confidence", 0.5), 0.0, 1.0),
            recommended_actions=_safe_list(data.get("recommended_actions", [])),
            reasoning_trace=_safe_list(data.get("reasoning_trace", [])),
        )

        issues = OutputValidator.validate_investigation(inv)
        if issues:
            self.logger.warning("llm_investigation_validation_issues", issues=issues)

        return inv

    def _get_knowledge_context(self, events: list[ThreatEvent]) -> str:
        try:
            from sentinelforge.core.knowledge import get_knowledge_base
            kb = get_knowledge_base()
            if kb.count() == 0:
                return ""
            query = " ".join(set(e.event_type for e in events))
            results = kb.query(query, n_results=3)
            if results:
                context = "Relevant threat intelligence:\n" + "\n".join(
                    f"- {r['document']}" for r in results
                )
                return context
        except Exception:
            pass
        return ""

    def _check_recurrence(self, events: list[ThreatEvent]) -> int:
        """Check database for prior events from the same source IPs."""
        try:
            from sentinelforge.core.database import get_database
            db = get_database()
            total = 0
            seen_ips = set()
            for e in events:
                if e.source_ip and e.source_ip not in seen_ips:
                    seen_ips.add(e.source_ip)
                    prior = db.find_events_by_source_ip(e.source_ip, hours=24)
                    total += len(prior)
            return total
        except Exception:
            return 0

    @staticmethod
    def _severity_rank(sev: Severity) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[sev.value]


def _parse_llm_json(content: str) -> dict[str, Any]:
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        content = "\n".join(lines)

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(content[start:end])
            except json.JSONDecodeError:
                pass
        raise ValueError(f"LLM returned non-JSON response: {content[:200]}")


def _safe_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value[:50]]
    return []


def _safe_float(value: Any, min_val: float, max_val: float) -> float:
    try:
        f = float(value)
        return max(min_val, min(max_val, f))
    except (TypeError, ValueError):
        return (min_val + max_val) / 2


def _safe_severity(value: Any) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.MEDIUM
