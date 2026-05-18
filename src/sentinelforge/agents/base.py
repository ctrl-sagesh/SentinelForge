"""Base agent class with shared safety and audit hooks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sentinelforge.core.audit import AuditLogger, get_audit_logger
from sentinelforge.core.config import Settings, get_settings
from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import ActionStatus, AgentRole, OrchestratorState
from sentinelforge.core.safety import SafetyEngine, get_safety_engine


class BaseAgent(ABC):
    """Every agent inherits safety checks, audit logging, and config access."""

    role: AgentRole

    def __init__(
        self,
        settings: Settings | None = None,
        safety: SafetyEngine | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.safety = safety or get_safety_engine()
        self.audit = audit or get_audit_logger()
        self.logger = get_logger(f"agent.{self.role.value}")

    @abstractmethod
    async def run(self, state: OrchestratorState) -> OrchestratorState:
        """Execute this agent's task and return updated state."""
        ...

    def _audit(self, action: str, status: ActionStatus, **details: Any) -> None:
        self.audit.log(
            agent=self.role,
            action=action,
            status=status,
            details=details,
        )
