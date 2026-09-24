from __future__ import annotations

import json

from backend.agent.reasoning import (
    DeterministicReasoningProvider,
    LLMReasoningProvider,
    ReasoningResult,
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


def test_llm_provider_accepts_structured_json():
    def fake_client(prompt):
        return json.dumps(
            {
                "selected_tool": "get_graph_neighborhood",
                "tool_arguments": {
                    "entity_id": "ACC-001",
                    "depth": 2,
                },
                "evidence_summary": "Graph evidence should be reviewed.",
                "uncertainty": ["location requires verification"],
                "explanation": "The graph neighborhood may clarify the relationship.",
            }
        )

    provider = LLMReasoningProvider(fake_client)

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
    assert result.tool_arguments["entity_id"] == "ACC-001"


def test_llm_provider_accepts_dictionary_response():
    def fake_client(prompt):
        return {
            "selected_tool": "get_customer",
            "tool_arguments": {
                "customer_id": "CUST-001",
            },
            "evidence_summary": "Customer evidence requested.",
            "uncertainty": [],
            "explanation": "Customer context may reduce uncertainty.",
        }

    result = LLMReasoningProvider(fake_client).reason(
        {},
        TOOLS,
    )

    assert result.selected_tool == "get_customer"


def test_llm_provider_parses_markdown_json():
    def fake_client(prompt):
        return """```json
{
  "selected_tool": "get_account",
  "tool_arguments": {"account_id": "ACC-001"},
  "evidence_summary": "Account context requested.",
  "uncertainty": [],
  "explanation": "Additional account evidence is useful."
}
```"""

    result = LLMReasoningProvider(fake_client).reason(
        {},
        TOOLS,
    )

    assert result.selected_tool == "get_account"


def test_llm_provider_falls_back_on_invalid_json():
    fallback = DeterministicReasoningProvider()

    provider = LLMReasoningProvider(
        lambda prompt: "not valid json",
        fallback=fallback,
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


def test_llm_provider_falls_back_on_unregistered_tool():
    provider = LLMReasoningProvider(
        lambda prompt: {
            "selected_tool": "execute_gsql",
            "tool_arguments": {
                "query": "SELECT *",
            },
            "evidence_summary": "invalid",
            "uncertainty": [],
            "explanation": "invalid",
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


def test_llm_provider_does_not_execute_tools():
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

    result = provider.reason({}, TOOLS)

    assert result.selected_tool == "get_customer"
    assert len(calls) == 1
    assert "get_customer" in calls[0]


def test_llm_prompt_contains_only_registered_tools():
    captured = {}

    def fake_client(prompt):
        captured["prompt"] = prompt
        return {
            "selected_tool": None,
            "tool_arguments": {},
            "evidence_summary": "No additional tool required.",
            "uncertainty": [],
            "explanation": "Available evidence is sufficient.",
        }

    provider = LLMReasoningProvider(fake_client)

    provider.reason(
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

    assert "execute_gsql" not in captured["prompt"]
    assert "SELECT *" not in captured["prompt"]
    assert '"available_tools"' in captured["prompt"]


def test_llm_provider_preserves_reasoning_result_contract():
    result = LLMReasoningProvider(
        lambda prompt: {
            "selected_tool": None,
            "tool_arguments": {},
            "evidence_summary": "Evidence reviewed.",
            "uncertainty": ["customer confirmation pending"],
            "explanation": "The evidence remains incomplete.",
        }
    ).reason({}, TOOLS)

    assert isinstance(result, ReasoningResult)
    assert result.uncertainty == ["customer confirmation pending"]
    assert result.explanation == "The evidence remains incomplete."