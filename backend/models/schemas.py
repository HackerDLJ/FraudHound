from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_EVIDENCE = "AWAITING_EVIDENCE"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTION_RECOMMENDED = "ACTION_RECOMMENDED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class Evidence(BaseModel):
    id: str
    kind: str
    statement: str
    source: str
    polarity: Literal["supporting", "contradicting", "unknown"] = "supporting"
    strength: float = Field(ge=0, le=1)
    timestamp: str = Field(default_factory=now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConflictResolution(str, Enum):
    RECONCILE = "RECONCILE"
    ESCALATE = "ESCALATE"
    DEFER = "DEFER"


class ConflictStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class EvidenceConflict(BaseModel):
    conflict_id: str
    case_id: str
    evidence_a: str
    evidence_b: str
    status: ConflictStatus = ConflictStatus.OPEN
    resolution: ConflictResolution | None = None
    analyst: str | None = None
    reason: str | None = None
    created_at: str = Field(default_factory=now_iso)
    resolved_at: str | None = None


class PatternFinding(BaseModel):
    pattern: str
    confidence: float = Field(ge=0, le=1)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    graph_signals: list[str] = Field(default_factory=list)
    explanation: str


class RiskAssessment(BaseModel):
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    uncertainty: list[str] = Field(default_factory=list)
    rationale: str


class EvidenceRequest(BaseModel):
    request_id: str
    type: str
    reason: str
    question: str
    expected_information: str
    how_it_reduces_uncertainty: str
    status: Literal["REQUESTED", "RECEIVED", "CANCELLED"] = "REQUESTED"


class ActionRecommendation(BaseModel):
    action: str
    reason: str
    supporting_evidence: list[str]
    risk: str
    confidence: float = Field(ge=0, le=1)
    required_approval: bool
    approval_route: str | None = None
    policy_reference: str | None = None
    reversible: bool = True


class AuditEvent(BaseModel):
    timestamp: str = Field(default_factory=now_iso)
    event: str
    actor: str = "fraudhound-agent"
    tool: str | None = None
    input: Any = None
    output: Any = None
    risk_before: int | None = None
    risk_after: int | None = None
    confidence_before: float | None = None
    confidence_after: float | None = None


class Case(BaseModel):
    case_id: str
    trigger: dict[str, Any]
    status: CaseStatus = CaseStatus.OPEN
    created_at: str = Field(default_factory=now_iso)

    entities: list[dict[str, Any]] = Field(default_factory=list)
    transactions: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    conflicts: list[EvidenceConflict] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    patterns: list[PatternFinding] = Field(default_factory=list)

    # Phase 4B: graph fraud-ring findings.
    fraud_rings: list[dict[str, Any]] = Field(default_factory=list)

    risk_assessment: RiskAssessment | None = None
    uncertainties: list[str] = Field(default_factory=list)
    evidence_requests: list[EvidenceRequest] = Field(default_factory=list)
    decisions: list[ActionRecommendation] = Field(default_factory=list)
    recommended_actions: list[ActionRecommendation] = Field(default_factory=list)
    executed_actions: list[dict[str, Any]] = Field(default_factory=list)
    approval_history: list[dict[str, Any]] = Field(default_factory=list)
    policy_references: list[str] = Field(default_factory=list)
    similar_cases: list[dict[str, Any]] = Field(default_factory=list)
    outcome: str | None = None
    explanation: str = ""
    timeline: list[AuditEvent] = Field(default_factory=list)
    iterations: int = 0


class InvestigationRequest(BaseModel):
    transaction_id: str | None = None
    scenario: str | None = None
    trigger: dict[str, Any] = Field(default_factory=dict)


class EvidenceInput(BaseModel):
    request_id: str
    result: dict[str, Any]


class ApprovalInput(BaseModel):
    approved: bool
    approver: str = "demo-analyst"
    note: str = ""


class ActionInput(BaseModel):
    action: str


class ConflictResolutionInput(BaseModel):
    resolution: ConflictResolution
    analyst: str = "demo-analyst"
    reason: str