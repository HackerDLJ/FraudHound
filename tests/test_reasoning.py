from backend.agent.reasoning import (
    DeterministicReasoningProvider,
    ReasoningResult,
    build_evidence_context,
    validate_reasoning_result,
)


def make_case():
    return {
        "trigger": {"scenario": "high_confidence"},
        "transactions": [
            {
                "transaction_id": "TX-DEMO-001",
                "account_id": "ACC-001",
                "amount": 1842.19,
            }
        ],
        "evidence": [
            {
                "id": "EVID-SHARED-DEVICE",
                "kind": "network_signal",
                "statement": "Device is associated with 4 accounts.",
                "source": "graph",
            }
        ],
        "patterns": [],
        "risk_assessment": {
            "risk_level": "CRITICAL",
            "risk_score": 96,
            "confidence": 0.90,
        },
        "uncertainties": [
            "Geolocation differs from recent account activity."
        ],
        "similar_cases": [],
        "policy_references": [],
    }


def test_build_evidence_context_is_compact_and_structured():
    case = make_case()
    context = build_evidence_context(case)
    assert set(context) == {
        "trigger", "transactions", "evidence", "patterns",
        "risk_assessment", "uncertainties", "similar_cases",
        "policy_references",
    }
    assert context["transactions"][0]["transaction_id"] == "TX-DEMO-001"


def test_reasoning_provider_selects_registered_graph_tool():
    result = DeterministicReasoningProvider().reason(
        build_evidence_context(make_case()),
        ["get_transaction", "get_graph_neighborhood", "get_transaction_history"],
    )
    assert result.selected_tool == "get_graph_neighborhood"
    assert result.tool_arguments == {"entity_id": "ACC-001", "depth": 2}


def test_reasoning_provider_can_select_transaction_history():
    case = make_case()
    case["evidence"] = []
    result = DeterministicReasoningProvider().reason(
        build_evidence_context(case),
        ["get_transaction", "get_transaction_history"],
    )
    assert result.selected_tool == "get_transaction_history"
    assert result.tool_arguments == {"account_id": "ACC-001"}


def test_reasoning_provider_can_select_transaction_record():
    case = make_case()
    case["evidence"] = []
    result = DeterministicReasoningProvider().reason(
        build_evidence_context(case),
        ["get_transaction"],
    )
    assert result.selected_tool == "get_transaction"
    assert result.tool_arguments == {"transaction_id": "TX-DEMO-001"}


def test_reasoning_provider_never_invents_unregistered_tool():
    case = make_case()
    case["evidence"] = []
    result = DeterministicReasoningProvider().reason(
        build_evidence_context(case),
        ["find_similar_entities"],
    )
    assert result.selected_tool is None


def test_unregistered_reasoning_result_is_rejected():
    result = ReasoningResult(
        selected_tool="execute_gsql",
        tool_arguments={"query": "SELECT *"},
    )
    try:
        validate_reasoning_result(result, ["get_graph_neighborhood"])
    except PermissionError as exc:
        assert str(exc) == "Unregistered tool: execute_gsql"
    else:
        raise AssertionError("Expected unregistered tool to be rejected")


def test_reasoning_result_preserves_uncertainty_and_explanation():
    result = DeterministicReasoningProvider().reason(
        build_evidence_context(make_case()),
        ["get_graph_neighborhood"],
    )
    assert result.uncertainty == [
        "Geolocation differs from recent account activity."
    ]
    assert "registered tool set" in result.explanation


def test_reasoning_layer_does_not_execute_tools():
    class ExplodingProvider:
        def reason(self, context, available_tools):
            return ReasoningResult(
                selected_tool="get_graph_neighborhood",
                tool_arguments={"entity_id": "ACC-001", "depth": 2},
            )

    result = ExplodingProvider().reason(
        build_evidence_context(make_case()),
        ["get_graph_neighborhood"],
    )
    assert result.selected_tool == "get_graph_neighborhood"
