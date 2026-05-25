"""Responder Agent — executes approved containment actions.

v0.4: Persistent approval queue backed by SQLite. On startup, loads
pending approvals that haven't timed out. Approval decisions are
written back to the database for dashboard visibility.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelforge.agents.base import BaseAgent
from sentinelforge.core.alerting import get_alert_manager
from sentinelforge.core.config import get_settings
from sentinelforge.core.executors import (
    ExecutionResult,
    block_ip,
    disable_account,
    isolate_host,
    kill_process,
    quarantine_file,
)
from sentinelforge.core.guardrails import CanaryExecutor, OutputValidator
from sentinelforge.core.models import (
    ActionStatus,
    AgentRole,
    ContainmentAction,
    OrchestratorState,
    PendingApproval,
)

EXECUTOR_MAP = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "disable_account": disable_account,
    "kill_process": kill_process,
    "quarantine_file": quarantine_file,
}


class ResponderAgent(BaseAgent):
    """Executes approved actions via real system executors with canary pre-checks."""

    role = AgentRole.RESPONDER

    async def run(self, state: OrchestratorState) -> OrchestratorState:
        self._load_db_approvals(state)
        self._process_pending_approvals(state)

        pending = [
            a for a in state.approved_actions
            if a.status == ActionStatus.APPROVED
        ]

        if not pending:
            self.logger.info("no_approved_actions")
            return state

        alert_mgr = get_alert_manager()
        responder_cfg = get_settings().responder

        for action in pending:
            issues = OutputValidator.validate_action(action)
            if issues:
                self.logger.warning("action_validation_failed", issues=issues)
                action.status = ActionStatus.FAILED
                action.execution_output = f"Validation failed: {'; '.join(issues)}"
                continue

            if responder_cfg.canary_mode:
                canary_result = CanaryExecutor.run_canary(action)
                action.canary_result = canary_result.output
                if not canary_result.success:
                    self.logger.warning("canary_failed", output=canary_result.output)
                    action.status = ActionStatus.FAILED
                    action.execution_output = f"Canary failed: {canary_result.output}"
                    continue
                self.logger.info("canary_passed", preview=canary_result.command_preview)

            import os
            if os.environ.get("SENTINELFORGE_DEMO_MODE") == "true":
                self.logger.info(
                    "demo_mode_skip",
                    action=action.action_type,
                    target=action.target,
                )
                action.status = ActionStatus.EXECUTED
                action.execution_output = "Demo mode: skipping real execution"
                state.executed_actions.append(action)
                continue

            if self.settings.simulation_mode:
                self.logger.info(
                    "simulated_execution",
                    action=action.action_type,
                    target=action.target,
                )
                action.status = ActionStatus.EXECUTED
                action.execution_output = "Simulated — no real execution"
                state.executed_actions.append(action)
                self._audit(
                    f"simulate_{action.action_type}",
                    ActionStatus.EXECUTED,
                    target=action.target,
                    action_id=action.id,
                )
                continue

            result = self._execute_real(action, responder_cfg.executor_timeout_seconds)
            action.execution_output = result.output

            if result.success:
                action.status = ActionStatus.EXECUTED
                state.executed_actions.append(action)
                alert_mgr.alert_action_executed(action)
                self._audit(
                    f"execute_{action.action_type}",
                    ActionStatus.EXECUTED,
                    target=action.target,
                    action_id=action.id,
                )
            else:
                action.status = ActionStatus.FAILED
                self._audit(
                    f"execute_{action.action_type}",
                    ActionStatus.FAILED,
                    target=action.target,
                    action_id=action.id,
                    error=result.output,
                )

        return state

    def _execute_real(self, action: ContainmentAction, timeout: int) -> ExecutionResult:
        executor_fn = EXECUTOR_MAP.get(action.action_type)
        if executor_fn is None:
            self.logger.error("no_executor", action_type=action.action_type)
            return ExecutionResult(False, f"No executor for: {action.action_type}", "")

        responder_cfg = get_settings().responder
        if action.action_type not in responder_cfg.allowed_executors:
            return ExecutionResult(
                False,
                f"Executor '{action.action_type}' not in allowed list",
                "",
            )

        try:
            if action.action_type == "quarantine_file":
                return executor_fn(action.target, canary=False)
            return executor_fn(action.target, canary=False, timeout=timeout)
        except Exception as exc:
            self.logger.error(
                "execution_exception",
                action=action.action_type,
                error=str(exc),
            )
            return ExecutionResult(False, f"Exception: {exc}", "")

    def _load_db_approvals(self, state: OrchestratorState) -> None:
        """Load pending approvals from the database that aren't already in state."""
        try:
            from sentinelforge.core.database import get_database
            db = get_database()
            db_rows = db.get_pending_approvals()
        except Exception as exc:
            self.logger.warning("load_db_approvals_failed", error=str(exc))
            return

        existing_ids = {pa.action.id for pa in state.pending_approvals}

        for row in db_rows:
            action_id = row.get("action_id", "")
            if action_id in existing_ids:
                continue
            try:
                action = ContainmentAction.model_validate_json(row["action_data"])
                requested_at = datetime.fromisoformat(row["requested_at"])
                pa = PendingApproval(
                    action=action,
                    requested_at=requested_at,
                    timeout_seconds=row.get("timeout_seconds", 300),
                    reason=row.get("reason", ""),
                )
                if not pa.is_expired:
                    state.pending_approvals.append(pa)
                    self.logger.info("loaded_db_approval", action_id=action_id)
            except Exception as exc:
                self.logger.warning("parse_db_approval_failed", error=str(exc))

    def _persist_approval_decision(self, pa: PendingApproval) -> None:
        """Write an approval/denial decision back to the database."""
        try:
            from sentinelforge.core.database import get_database
            db = get_database()
            db.resolve_approval(
                action_id=pa.action.id,
                approved=bool(pa.approved),
                decided_by=pa.decided_by,
            )
        except Exception as exc:
            self.logger.warning("persist_decision_failed", error=str(exc))

    def _process_pending_approvals(self, state: OrchestratorState) -> None:
        """Check pending approvals for timeouts and auto-deny expired ones."""
        responder_cfg = get_settings().responder
        alert_mgr = get_alert_manager()

        still_pending: list[PendingApproval] = []
        for pa in state.pending_approvals:
            if pa.approved is not None:
                if pa.approved:
                    pa.action.status = ActionStatus.APPROVED
                    state.approved_actions.append(pa.action)
                else:
                    pa.action.status = ActionStatus.DENIED
                self._persist_approval_decision(pa)
                continue

            if pa.is_expired:
                if responder_cfg.auto_deny_on_timeout:
                    pa.approved = False
                    pa.decided_by = "auto_timeout"
                    pa.decided_at = datetime.now(timezone.utc)
                    pa.action.status = ActionStatus.DENIED
                    self._persist_approval_decision(pa)
                    alert_mgr.alert_approval_timeout(pa.action)
                    self.logger.info(
                        "approval_auto_denied",
                        action=pa.action.action_type,
                        target=pa.action.target,
                    )
                else:
                    still_pending.append(pa)
            else:
                still_pending.append(pa)

        state.pending_approvals = still_pending
