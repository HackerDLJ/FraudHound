from backend.agent.controller import FraudHoundController
from backend.graph.mock_adapter import MockGraphAdapter
from backend.memory.case_memory import CaseMemory
from backend.models.schemas import InvestigationRequest, EvidenceInput
from pathlib import Path

def make():
    db=Path('/tmp/fraudhound-test.db')
    db.unlink(missing_ok=True)
    g=MockGraphAdapter(); m=CaseMemory(db); return FraudHoundController(g,m),g

def test_high_confidence_requires_approval():
    c,g=make(); g.select_scenario('high_confidence'); case=c.investigate(c.create_case(InvestigationRequest(scenario='high_confidence')))
    assert case.risk_assessment.risk_level in ('HIGH','CRITICAL')
    assert case.recommended_actions[-1].action=='BLOCK_TRANSACTION'
    assert case.recommended_actions[-1].required_approval is True

def test_ambiguous_requests_evidence_then_changes():
    c,g=make(); g.select_scenario('ambiguous'); case=c.investigate(c.create_case(InvestigationRequest(scenario='ambiguous')))
    assert case.status=='AWAITING_EVIDENCE'
    req=case.evidence_requests[-1].request_id
    case=c.receive_evidence(case,EvidenceInput(request_id=req,result={'customer_authenticated':True}))
    assert case.recommended_actions[-1].action in ('ALLOW_TRANSACTION','MONITOR_TRANSACTION')
    assert case.risk_assessment.confidence>=.78

def test_legitimate_case_has_contradicting_evidence():
    c,g=make(); g.select_scenario('legitimate'); case=c.investigate(c.create_case(InvestigationRequest(scenario='legitimate')))
    assert any(e.polarity=='contradicting' for e in case.evidence)
    assert case.recommended_actions[-1].action in ('ALLOW_TRANSACTION','MONITOR_TRANSACTION')
