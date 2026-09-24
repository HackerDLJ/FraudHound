from pathlib import Path

from backend.agent.controller import FraudHoundController
from backend.agent.reasoning import ReasoningResult
from backend.graph.mock_adapter import MockGraphAdapter
from backend.memory.case_memory import CaseMemory
from backend.models.schemas import InvestigationRequest


class SpyReasoningProvider:
    def __init__(self):
        self.calls = []

    def reason(self, context, available_tools):
        self.calls.append(
            {
                "context": context,
                "available_tools": available_tools,
            }
        )
        return ReasoningResult(
            selected_tool="get_graph_neighborhood",
            tool_arguments={
                "entity_id": context["transactions"][0]["account_id"],
                "depth": 2,
            },
            evidence_summary="Graph evidence was selected for review.",
            uncertainty=context["uncertainties"],
            explanation="The registered graph tool was selected for additional context.",
        )


def make(provider=None):
    db = Path("/tmp/fraudhound-reasoning-integration.db")
    db.unlink(missing_ok=True)
    graph = MockGraphAdapter()
    memory = CaseMemory(db)
    controller = FraudHoundController(
        graph,
        memory,
        reasoning_provider=provider,
    )
    return controller, graph


def test_reasoning_is_called_and_audited():
    provider = SpyReasoningProvider()
    controller, graph = make(provider)
    graph.select_scenario("high_confidence")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(scenario="high_confidence")
        )
    )

    assert len(provider.calls) == 1
    assert "get_graph_neighborhood" in provider.calls[0]["available_tools"]

    event = next(
        event
        for event in case.timeline
        if event.event == "Reasoning completed"
    )

    assert event.actor == "fraudhound-reasoner"
    assert event.tool == "get_graph_neighborhood"
    assert event.output["selected_tool"] == "get_graph_neighborhood"
    assert event.output["tool_result"]["result_type"] == "structured"
    assert event.output["tool_result"]["node_count"] >= 1


def test_reasoning_does_not_override_deterministic_next_action():
    provider = SpyReasoningProvider()
    controller, graph = make(provider)
    graph.select_scenario("high_confidence")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(scenario="high_confidence")
        )
    )

    assert case.recommended_actions[-1].action == "BLOCK_TRANSACTION"
    assert case.recommended_actions[-1].required_approval is True


def test_reasoning_runs_after_evidence_update():
    provider = SpyReasoningProvider()
    controller, graph = make(provider)
    graph.select_scenario("ambiguous")

    case = controller.investigate(
        controller.create_case(
            InvestigationRequest(scenario="ambiguous")
        )
    )

    request_id = case.evidence_requests[-1].request_id
    controller.receive_evidence(
        case,
        __import__("backend.models.schemas", fromlist=["EvidenceInput"]).EvidenceInput(
            request_id=request_id,
            result={"customer_authenticated": True},
        ),
    )

    assert len(provider.calls) == 2
    events = [
        event.event
        for event in case.timeline
    ]
    assert events.count("Reasoning completed") == 2


def test_reasoning_tool_registry_exposes_only_registered_tools():
    controller, _ = make()

    assert set(controller.tool_registry.tools) == {
        "get_transaction",
        "get_customer",
        "get_account",
        "get_transaction_history",
        "get_graph_neighborhood",
        "detect_fraud_patterns",
        "find_similar_entities",
    }
    assert "execute_sql" not in controller.tool_registry.tools
    assert "execute_gsql" not in controller.tool_registry.tools
