
from pathlib import Path

import pytest

from backend.agent.controller import FraudHoundController
from backend.graph.mock_adapter import MockGraphAdapter
from backend.memory.case_memory import CaseMemory
from backend.models.schemas import (
    ConflictResolution,
    EvidenceInput,
    InvestigationRequest,
)


def make():
    db = Path("/tmp/fraudhound-test.db")
    db.unlink(missing_ok=True)

    graph = MockGraphAdapter()
    memory = CaseMemory(db)

    return FraudHoundController(graph, memory), graph


def test_high_confidence_requires_approval():
    controller, graph = make()

    graph.select_scenario("high_confidence")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="high_confidence"
            )
        )
    )

    assert case.risk_assessment.risk_level in (
        "HIGH",
        "CRITICAL",
    )

    assert (
        case.recommended_actions[-1].action
        == "BLOCK_TRANSACTION"
    )

    assert (
        case.recommended_actions[-1].required_approval
        is True
    )


def test_ambiguous_requests_evidence_then_changes():
    controller, graph = make()

    graph.select_scenario("ambiguous")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="ambiguous"
            )
        )
    )

    assert case.status == "AWAITING_EVIDENCE"

    request_id = case.evidence_requests[-1].request_id

    case = controller.receive_evidence(
        case,
        EvidenceInput(
            request_id=request_id,
            result={
                "customer_authenticated": True
            },
        ),
    )

    assert case.recommended_actions[-1].action in (
        "ALLOW_TRANSACTION",
        "MONITOR_TRANSACTION",
    )

    assert case.risk_assessment.confidence >= 0.78


def test_legitimate_case_has_contradicting_evidence():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    assert any(
        evidence.polarity == "contradicting"
        for evidence in case.evidence
    )

    assert case.recommended_actions[-1].action in (
        "ALLOW_TRANSACTION",
        "MONITOR_TRANSACTION",
    )


def test_conflicting_evidence_creates_conflict():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    conflicts = controller.detect_conflicts(case)

    assert len(conflicts) >= 1

    conflict = conflicts[0]

    assert conflict.status == "OPEN"

    evidence_ids = {
        evidence.id
        for evidence in case.evidence
    }

    assert conflict.evidence_a in evidence_ids
    assert conflict.evidence_b in evidence_ids

    assert conflict.case_id == case.case_id


def test_reconcile_conflict_updates_confidence():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    conflicts = controller.detect_conflicts(case)

    assert conflicts

    conflict = conflicts[0]

    before = case.risk_assessment.confidence

    case = controller.resolve_conflict(
        case,
        conflict.conflict_id,
        ConflictResolution.RECONCILE,
        "analyst-001",
        (
            "Customer validation explains the apparently "
            "contradictory device evidence."
        ),
    )

    resolved = case.conflicts[0]

    assert resolved.status == "RESOLVED"
    assert (
        resolved.resolution
        == ConflictResolution.RECONCILE
    )
    assert resolved.analyst == "analyst-001"
    assert resolved.reason

    assert (
        case.risk_assessment.confidence
        >= before
    )

    assert any(
        event.event
        == "Evidence conflict resolved"
        for event in case.timeline
    )


def test_escalate_conflict_changes_case_status():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    conflict = controller.detect_conflicts(case)[0]

    case = controller.resolve_conflict(
        case,
        conflict.conflict_id,
        ConflictResolution.ESCALATE,
        "analyst-002",
        (
            "Evidence cannot be reconciled with the "
            "available information."
        ),
    )

    assert case.status == "ESCALATED"

    assert (
        case.conflicts[0].resolution
        == ConflictResolution.ESCALATE
    )


def test_defer_conflict_requests_further_review():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    conflict = controller.detect_conflicts(case)[0]

    case = controller.resolve_conflict(
        case,
        conflict.conflict_id,
        ConflictResolution.DEFER,
        "analyst-003",
        (
            "Additional customer evidence is required "
            "before resolution."
        ),
    )

    assert case.status == "AWAITING_EVIDENCE"

    assert (
        case.conflicts[0].resolution
        == ConflictResolution.DEFER
    )


def test_resolved_conflict_cannot_be_resolved_twice():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    conflict = controller.detect_conflicts(case)[0]

    controller.resolve_conflict(
        case,
        conflict.conflict_id,
        ConflictResolution.RECONCILE,
        "analyst-001",
        "Conflict reconciled using customer validation.",
    )

    with pytest.raises(ValueError, match="already resolved"):
        controller.resolve_conflict(
            case,
            conflict.conflict_id,
            ConflictResolution.ESCALATE,
            "analyst-002",
            "Attempted second resolution.",
        )


def test_conflict_resolution_requires_reason():
    controller, graph = make()

    graph.select_scenario("legitimate")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(
                scenario="legitimate"
            )
        )
    )

    conflict = controller.detect_conflicts(case)[0]

    with pytest.raises(
        ValueError,
        match="Resolution reason is required",
    ):
        controller.resolve_conflict(
            case,
            conflict.conflict_id,
            ConflictResolution.RECONCILE,
            "analyst-001",
            "   ",
        )

