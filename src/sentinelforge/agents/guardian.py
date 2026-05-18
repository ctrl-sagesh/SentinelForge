"""Guardian Agent — oversees all other agents for safety and integrity.

This is the most critical agent. It validates every proposed action,
detects prompt injection, monitors for goal hijacking, and enforces
constitutional rules. It has veto power over all other agents.
"""

from __future__ import annotations

from sentinelforge.agents.base import BaseAgent
from sentinelforge.core.models import (
    ActionStatus,
    AgentRole,
    ContainmentAction,
    OrchestratorState,
    PendingApproval,
)


class GuardianAgent(BaseAgent):
    """Validates actions, detects anomalous agent behavior, enforces safety policy."""

    role = AgentRole.GUARDIAN

    async def run(self, state: OrchestratorState) -> OrchestratorState:
        self.logger.info("guardian_review_start", proposed=len(state.proposed_actions))

        pending = [
            a for a in state.proposed_actions
            if a.status == ActionStatus.PROPOSED
        ]

        for action in pending:
            approved, reason = self._review_action(action)

            if approved:
                if self.safety.requires_human_approval(action):
                    pa = PendingApproval(
                        action=action,
                        timeout_seconds=self.settings.responder.approval_timeout_seconds,
                        reason=f"Risk={action.risk_score:.2f}, requires human review",
                    )
                    state.pending_approvals.append(pa)
                    state.human_escalations.append(
                        f"Action {action.action_type} on {action.target} requires human approval "
                        f"(risk={action.risk_score:.2f}): {action.reasoning}"
                    )
                    self._persist_approval(pa)
                    self.logger.info(
                        "escalated_to_human",
                        action=action.action_type,
                        risk=action.risk_score,
                    )
                    action.status = ActionStatus.PROPOSED
                else:
                    action.status = ActionStatus.APPROVED
                    state.approved_actions.append(action)
                    self._audit(
                        "approve_action",
                        ActionStatus.APPROVED,
                        action_id=action.id,
                        action_type=action.action_type,
                        target=action.target,
                    )
            else:
                action.status = ActionStatus.REJECTED
                is_policy = (
                    "rate limit" in reason.lower()
                    or "sandbox" in reason.lower()
                    or "not in the allowed" in reason.lower()
                    or "human approval" in reason.lower()
                )
                if not is_policy:
                    state.safety_violations.append(reason)
                self._audit(
                    "reject_action",
                    ActionStatus.REJECTED,
                    action_id=action.id,
                    reason=reason,
                )
                self.logger.warning(
                    "action_rejected",
                    action=action.action_type,
                    reason=reason,
                )

        self._check_agent_behavior(state)

        return state

    def _review_action(self, action: ContainmentAction) -> tuple[bool, str]:
        """Multi-layer validation of a proposed action."""
        allowed, reason = self.safety.validate_action(action)
        if not allowed:
            return False, reason

        violations = self.safety.check_constitutional_compliance(
            f"{action.action_type} {action.target} {action.reasoning}"
        )
        if violations:
            return False, f"Constitutional violation: {violations[0]}"

        if self.safety.detect_prompt_injection(action.reasoning):
            return False, "Prompt injection detected in action reasoning"

        if action.risk_score > 0.9:
            return False, f"Risk score {action.risk_score:.2f} exceeds maximum threshold"

        return True, "Approved by Guardian"

    def _check_agent_behavior(self, state: OrchestratorState) -> None:
        """Detect anomalous patterns in agent behavior."""
        actions_per_iteration = (
            len(state.proposed_actions) / max(1, state.iteration + 1)
        )
        if state.iteration > 1 and actions_per_iteration > 20:
            self.logger.warning(
                "high_action_volume",
                per_iteration=actions_per_iteration,
                msg="Unusually high number of actions — possible runaway agent",
            )
            state.safety_violations.append(
                "Guardian alert: high action volume detected, possible agent loop"
            )

        action_types = [a.action_type for a in state.proposed_actions[-10:]]
        if len(action_types) >= 8 and len(set(action_types)) == 1:
            self.logger.warning(
                "repetitive_actions",
                action_type=action_types[0],
                msg="Agent appears stuck in a loop",
            )
            state.safety_violations.append(
                f"Guardian alert: repetitive {action_types[0]} actions detected"
            )

        for inv in state.investigations:
            if self.safety.detect_prompt_injection(inv.summary):
                state.safety_violations.append(
                    f"Prompt injection detected in investigation {inv.id}"
                )
            if self.safety.detect_prompt_injection(inv.root_cause):
                state.safety_violations.append(
                    f"Prompt injection detected in root cause of investigation {inv.id}"
                )

    def _persist_approval(self, pa: PendingApproval) -> None:
        """Store a PendingApproval in the database."""
        try:
            from sentinelforge.core.database import get_database
            db = get_database()
            db.save_pending_approval(
                action_id=pa.action.id,
                action_data=pa.action.model_dump_json(),
                requested_at=pa.requested_at.isoformat(),
                timeout_seconds=pa.timeout_seconds,
                reason=pa.reason,
            )
        except Exception as exc:
            self.logger.warning("persist_approval_failed", error=str(exc))
