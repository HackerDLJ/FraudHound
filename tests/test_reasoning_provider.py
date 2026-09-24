from __future__ import annotations

import pytest

from backend.agent.reasoning import CallableReasoningProvider, DeterministicReasoningProvider, ReasoningResult, validate_reasoning_result

AVAILABLE_TOOLS = [
    "get_transaction", "get_customer", "get_account", "get_transaction_history",
    "get_graph_neighborhood", "detect_fraud_patterns", "find_similar_entities",
]


def test_deterministic_provider_selects_registered_graph_tool():
    result = DeterministicReasoningProvider().reason(
        {"transactions": [{"transaction_id": "TX-001", "account_id": "ACC-001"}], "uncertainties": ["location requires verification"]},
        AVAILABLE_TOOLS,
    )
    assert result.selected_tool == "get_graph_neighborhood"
    assert result.tool_arguments == {"entity_id": "ACC-001", "depth": 2}
    assert result.uncertainty == ["location requires verification"]


def test_provider_rejects_unregistered_tool():
    with pytest.raises(PermissionError):
        validate_reasoning_result({"selected_tool": "execute_sql", "tool_arguments": {"query": "SELECT * FROM accounts"}, "evidence_summary": "invalid", "uncertainty": [], "explanation": "invalid tool"}, AVAILABLE_TOOLS)


def test_provider_rejects_unknown_output_fields():
    with pytest.raises(ValueError):
        validate_reasoning_result({"selected_tool": None, "tool_arguments": {}, "evidence_summary": "ok", "uncertainty": [], "explanation": "ok", "next_best_action": "BLOCK"}, AVAILABLE_TOOLS)


def test_provider_rejects_tool_arguments_without_tool():
    with pytest.raises(ValueError):
        validate_reasoning_result({"selected_tool": None, "tool_arguments": {"entity_id": "ACC-001"}, "evidence_summary": "ok", "uncertainty": [], "explanation": "ok"}, AVAILABLE_TOOLS)


def test_callable_provider_accepts_structured_dict():
    provider = CallableReasoningProvider(lambda context, tools: {"selected_tool": "get_customer", "tool_arguments": {"customer_id": "CUST-001"}, "evidence_summary": "Customer context requested.", "uncertainty": ["identity confirmation pending"], "explanation": "Additional customer context is required."})
    result = provider.reason({}, AVAILABLE_TOOLS)
    assert result == ReasoningResult(selected_tool="get_customer", tool_arguments={"customer_id": "CUST-001"}, evidence_summary="Customer context requested.", uncertainty=["identity confirmation pending"], explanation="Additional customer context is required.")


def test_callable_provider_rejects_non_structured_output():
    provider = CallableReasoningProvider(lambda context, tools: "BLOCK the account")
    with pytest.raises(TypeError):
        provider.reason({}, AVAILABLE_TOOLS)


def test_callable_provider_cannot_bypass_tool_validation():
    provider = CallableReasoningProvider(lambda context, tools: {"selected_tool": "execute_gsql", "tool_arguments": {"query": "RUN QUERY"}, "evidence_summary": "invalid", "uncertainty": [], "explanation": "invalid"})
    with pytest.raises(PermissionError):
        provider.reason({}, AVAILABLE_TOOLS)


def test_validation_preserves_uncertainty_and_explanation():
    result = validate_reasoning_result({"selected_tool": "get_account", "tool_arguments": {"account_id": "ACC-001"}, "evidence_summary": "Account evidence retrieved.", "uncertainty": ["customer confirmation is missing"], "explanation": "Account-level evidence may reduce uncertainty."}, AVAILABLE_TOOLS)
    assert result.uncertainty == ["customer confirmation is missing"]
    assert result.explanation == "Account-level evidence may reduce uncertainty."
