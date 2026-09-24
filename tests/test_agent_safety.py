from __future__ import annotations

from backend.agent.reasoning import (
    DeterministicReasoningProvider,
    LLMReasoningProvider,
    ReasoningResult,
    validate_reasoning_result,
)


TOOLS = [
    "get_transaction",
    "get_customer",
    "get_account",
    "get_transaction_history",
    "get_graph_neighborhood",
    "detect_fraud_patterns",
    "find_similar_entities",
]


def test_malicious_llm_tool_selection_falls_back():
    provider = LLMReasoningProvider(
        lambda prompt: {
            "selected_tool": "execute_gsql",
            "tool_arguments": {"query": "SELECT * FROM accounts"},
            "evidence_summary": "malicious",
            "uncertainty": [],
            "explanation": "malicious",
        }
    )

    result = provider.reason(
        {
            "transactions": [
                {
                    "transaction_id": "TX-001",
                    "account_id": "ACC-001",
                }
            ]
        },
        TOOLS,
    )

    assert result.selected_tool == "get_graph_neighborhood"


def test_malicious_extra_output_field_falls_back():
    provider = LLMReasoningProvider(
        lambda prompt: {
            "selected_tool": "get_graph_neighborhood",
            "tool_arguments": {
                "entity_id": "ACC-001",
                "depth": 2,
            },
            "evidence_summary": "valid",
            "uncertainty": [],
            "explanation": "valid",
            "execute_action": "BLOCK",
        }
    )

    result = provider.reason(
        {
            "transactions": [
                {
                    "transaction_id": "TX-001",
                    "account_id": "ACC-001",
                }
            ]
        },
        TOOLS,
    )

    assert result.selected_tool == "get_graph_neighborhood"


def test_malformed_llm_response_falls_back():
    provider = LLMReasoningProvider(
        lambda prompt: "{ definitely not valid json"
    )

    result = provider.reason(
        {
            "transactions": [
                {
                    "transaction_id": "TX-001",
                    "account_id": "ACC-001",
                }
            ]
        },
        TOOLS,
    )

    assert result.selected_tool == "get_graph_neighborhood"


def test_reasoning_result_cannot_contain_action_command():
    result = ReasoningResult(
        selected_tool=None,
        tool_arguments={},
        evidence_summary="Evidence reviewed.",
        uncertainty=[],
        explanation="Review complete.",
    )

    validated = validate_reasoning_result(
        result,
        TOOLS,
    )

    assert not hasattr(validated, "action")
    assert not hasattr(validated, "execute")
    assert validated.selected_tool is None


def test_deterministic_provider_never_selects_unregistered_tool():
    provider = DeterministicReasoningProvider()

    result = provider.reason(
        {
            "transactions": [
                {
                    "transaction_id": "TX-001",
                    "account_id": "ACC-001",
                }
            ]
        },
        ["get_graph_neighborhood"],
    )

    assert result.selected_tool == "get_graph_neighborhood"
    assert result.selected_tool in ["get_graph_neighborhood"]


def test_tool_validation_rejects_sql_tool():
    try:
        validate_reasoning_result(
            {
                "selected_tool": "execute_sql",
                "tool_arguments": {
                    "query": "SELECT * FROM transactions"
                },
                "evidence_summary": "invalid",
                "uncertainty": [],
                "explanation": "invalid",
            },
            TOOLS,
        )
    except PermissionError as exc:
        assert str(exc) == "Unregistered tool: execute_sql"
    else:
        raise AssertionError(
            "Unregistered SQL tool was accepted"
        )


def test_tool_arguments_cannot_be_used_without_tool():
    try:
        validate_reasoning_result(
            {
                "selected_tool": None,
                "tool_arguments": {
                    "account_id": "ACC-001"
                },
                "evidence_summary": "invalid",
                "uncertainty": [],
                "explanation": "invalid",
            },
            TOOLS,
        )
    except ValueError as exc:
        assert "tool_arguments" in str(exc)
    else:
        raise AssertionError(
            "Tool arguments were accepted without a selected tool"
        )


def test_reasoning_preserves_uncertainty():
    result = validate_reasoning_result(
        {
            "selected_tool": "get_graph_neighborhood",
            "tool_arguments": {
                "entity_id": "ACC-001",
                "depth": 2,
            },
            "evidence_summary": "Graph evidence requested.",
            "uncertainty": [
                "Customer confirmation is still pending."
            ],
            "explanation": "Additional graph evidence may reduce uncertainty.",
        },
        TOOLS,
    )

    assert result.uncertainty == [
        "Customer confirmation is still pending."
    ]


def test_llm_cannot_directly_execute_tools():
    calls = []

    def fake_client(prompt):
        calls.append(prompt)

        return {
            "selected_tool": "get_customer",
            "tool_arguments": {
                "customer_id": "CUST-001",
            },
            "evidence_summary": "Customer evidence requested.",
            "uncertainty": [],
            "explanation": "Additional customer evidence is useful.",
        }

    provider = LLMReasoningProvider(fake_client)

    result = provider.reason(
        {},
        TOOLS,
    )

    assert result.selected_tool == "get_customer"
    assert result.tool_arguments == {
        "customer_id": "CUST-001"
    }

    # The provider only returns a recommendation.
    # It does not execute the registered tool.
    assert len(calls) == 1