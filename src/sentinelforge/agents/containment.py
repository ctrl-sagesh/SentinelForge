"""Containment Agent — proposes safe, reversible isolation actions.

v0.3: Expanded action registry (5 types), auto-actions for known event
patterns, human-approval flag based on risk score and reversibility.
"""

from __future__ import annotations

import re
from typing import Any

from sentinelforge.agents.base import BaseAgent
from sentinelforge.core.models import (
    AgentRole,
    ContainmentAction,
    Investigation,
    OrchestratorState,
    Severity,
)

ACTION_REGISTRY: dict[str, dict[str, Any]] = {
    "block_ip": {
        "params": {"direction": "inbound", "duration": 3600},
        "rollback": "unblock_ip",
        "reversible": True,
        "base_risk": 0.3,
    },
    "isolate_host": {
        "params": {"method": "network_isolation"},
        "rollback": "reconnect_host",
        "reversible": True,
        "base_risk": 0.6,
    },
    "disable_account": {
        "params": {"method": "disable_login"},
        "rollback": "enable_account",
        "reversible": True,
        "base_risk": 0.5,
    },
    "kill_process": {
        "params": {"signal": "SIGKILL"},
        "rollback": "",
        "reversible": False,
        "base_risk": 0.4,
    },
    "quarantine_file": {
        "params": {"method": "move_to_quarantine"},
        "rollback": "restore_file",
        "reversible": True,
        "base_risk": 0.35,
    },
}

SEVERITY_WEIGHT = {
    "info": 0.1, "low": 0.2, "medium": 0.4, "high": 0.6, "critical": 0.8,
}


class ContainmentAgent(BaseAgent):
    """Generates containment actions based on investigation results."""

    role = AgentRole.CONTAINMENT

    async def run(self, state: OrchestratorState) -> OrchestratorState:
        new_investigations = [
            inv for inv in state.investigations
            if not any(
                a.reasoning and inv.id in a.reasoning
                for a in state.proposed_actions
            )
        ]

        if not new_investigations:
            self.logger.info("no_new_investigations")
            return state

        for inv in new_investigations:
            actions = self._generate_actions(inv)
            auto = self._auto_actions_for_event(inv)
            all_actions = actions + auto
            state.proposed_actions.extend(all_actions)
            self.logger.info(
                "actions_proposed",
                investigation_id=inv.id,
                count=len(all_actions),
            )

        return state

    def _generate_actions(self, investigation: Investigation) -> list[ContainmentAction]:
        actions: list[ContainmentAction] = []

        for rec in investigation.recommended_actions:
            action = self._parse_recommendation(rec, investigation)
            if action:
                actions.append(action)

        if not actions and investigation.severity in (Severity.HIGH, Severity.CRITICAL):
            for asset in investigation.affected_assets:
                if self._is_ip(asset):
                    actions.append(
                        _build_action(
                            "block_ip",
                            asset,
                            investigation,
                        )
                    )

        return actions

    def _parse_recommendation(
        self, rec: str, investigation: Investigation
    ) -> ContainmentAction | None:
        parts = rec.strip().split(maxsplit=1)
        if len(parts) < 2:
            return None

        action_type, target = parts[0], parts[1]

        if action_type not in ACTION_REGISTRY:
            self.logger.warning("unknown_action_type", action_type=action_type)
            return None

        return _build_action(action_type, target, investigation)

    def _auto_actions_for_event(self, investigation: Investigation) -> list[ContainmentAction]:
        """Generate automatic actions for well-known event patterns."""
        actions: list[ContainmentAction] = []
        event_types = _get_event_types(investigation)

        if "suspicious_process" in event_types:
            for asset in investigation.affected_assets:
                if not self._is_ip(asset):
                    actions.append(
                        _build_action("kill_process", asset, investigation)
                    )

        if "malware_detected" in event_types:
            for asset in investigation.affected_assets:
                if not self._is_ip(asset) and "." in asset:
                    actions.append(
                        _build_action("quarantine_file", asset, investigation)
                    )

        return actions

    @staticmethod
    def _is_ip(value: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


def _build_action(
    action_type: str,
    target: str,
    investigation: Investigation,
) -> ContainmentAction:
    cfg = ACTION_REGISTRY[action_type]
    risk = _compute_risk(investigation.severity, cfg["base_risk"])
    requires_human = risk > 0.6 or not cfg["reversible"]

    return ContainmentAction(
        action_type=action_type,
        target=target,
        parameters=cfg["params"],
        reversible=cfg["reversible"],
        rollback_procedure=f"{cfg['rollback']} {target}" if cfg["rollback"] else "",
        reasoning=f"From investigation {investigation.id}: {investigation.summary}",
        risk_score=risk,
        requires_human=requires_human,
    )


def _compute_risk(severity: Severity, base_risk: float) -> float:
    s = SEVERITY_WEIGHT.get(severity.value, 0.5)
    return min(1.0, (s + base_risk) / 2)


def _get_event_types(investigation: Investigation) -> set[str]:
    """Extract event type keywords from investigation text."""
    keywords = {"suspicious_process", "malware_detected", "brute_force",
                "data_exfiltration", "lateral_movement"}
    text = f"{investigation.summary} {investigation.root_cause}".lower()
    return {k for k in keywords if k.replace("_", " ") in text or k in text}
