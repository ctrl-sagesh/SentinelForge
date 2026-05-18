"""Shared data models used across all agents."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentRole(str, Enum):
    MONITOR = "monitor"
    INVESTIGATOR = "investigator"
    CONTAINMENT = "containment"
    RESPONDER = "responder"
    GUARDIAN = "guardian"
    EXPLAINER = "explainer"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ThreatEvent(BaseModel):
    """A detected security event or anomaly."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    event_type: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    raw_data: dict[str, Any] = Field(default_factory=dict)
    iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    source_ip: str = ""
    dest_ip: str = ""
    hostname: str = ""


class Investigation(BaseModel):
    """Result of an investigator agent's analysis."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_ids: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: str = ""
    root_cause: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    threat_intel_matches: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    recommended_actions: list[str] = Field(default_factory=list)
    reasoning_trace: list[str] = Field(default_factory=list)


class ContainmentAction(BaseModel):
    """A proposed or executed containment/response action."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent: AgentRole = AgentRole.CONTAINMENT
    action_type: str = ""
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: ActionStatus = ActionStatus.PROPOSED
    reversible: bool = True
    rollback_procedure: str = ""
    reasoning: str = ""
    risk_score: float = 0.0
    approved_by: str = ""
    canary_result: str = ""
    execution_output: str = ""
    requires_human: bool = False


class IncidentReport(BaseModel):
    """Human-readable incident report."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    title: str = ""
    executive_summary: str = ""
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    events: list[ThreatEvent] = Field(default_factory=list)
    investigation: Investigation | None = None
    actions_taken: list[ContainmentAction] = Field(default_factory=list)
    reasoning_trace: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    mitre_mapping: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO


class AuditEntry(BaseModel):
    """Immutable audit log entry with cryptographic integrity."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent: AgentRole
    action: str
    target: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    status: ActionStatus
    previous_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self, previous_hash: str = "") -> str:
        payload = f"{self.id}|{self.timestamp.isoformat()}|{self.agent}|{self.action}|{previous_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()


class PendingApproval(BaseModel):
    """An action waiting for human approval with a timeout."""

    action: ContainmentAction
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    timeout_seconds: int = 300
    reason: str = ""
    approved: bool | None = None
    decided_by: str = ""
    decided_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        elapsed = (datetime.now(timezone.utc) - self.requested_at).total_seconds()
        return elapsed > self.timeout_seconds


class OrchestratorState(BaseModel):
    """Shared state passed through the LangGraph workflow."""

    events: list[ThreatEvent] = Field(default_factory=list)
    investigations: list[Investigation] = Field(default_factory=list)
    proposed_actions: list[ContainmentAction] = Field(default_factory=list)
    approved_actions: list[ContainmentAction] = Field(default_factory=list)
    executed_actions: list[ContainmentAction] = Field(default_factory=list)
    reports: list[IncidentReport] = Field(default_factory=list)
    safety_violations: list[str] = Field(default_factory=list)
    human_escalations: list[str] = Field(default_factory=list)
    pending_approvals: list[PendingApproval] = Field(default_factory=list)
    iteration: int = 0
    new_events_this_iteration: int = 0
    should_continue: bool = True
    error: str = ""
