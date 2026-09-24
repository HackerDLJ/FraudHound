from __future__ import annotations

import pytest

from backend.graph.mock_adapter import MockGraphAdapter
from backend.tools.registry import ToolRegistry


@pytest.fixture
def registry():
    return ToolRegistry(MockGraphAdapter())


def test_registry_exposes_only_registered_tools(registry):
    assert registry.available_tools() == [
        "get_transaction",
        "get_customer",
        "get_account",
        "get_transaction_history",
        "get_graph_neighborhood",
        "detect_fraud_patterns",
        "find_similar_entities",
    ]


def test_registered_tool_executes_with_valid_arguments(registry):
    result = registry.call(
        "get_transaction",
        transaction_id="TX-DEMO-001",
    )

    assert result["transaction_id"] == "TX-DEMO-001"


def test_graph_neighborhood_accepts_optional_depth(registry):
    result = registry.call(
        "get_graph_neighborhood",
        entity_id="ACC-001",
        depth=2,
    )

    assert "nodes" in result
    assert "edges" in result


def test_unregistered_tool_is_rejected(registry):
    with pytest.raises(PermissionError, match="Unregistered tool"):
        registry.call("execute_gsql", query="SELECT *")


def test_missing_required_argument_is_rejected(registry):
    with pytest.raises(ValueError, match="Missing required arguments"):
        registry.call("get_customer")


def test_unexpected_argument_is_rejected(registry):
    with pytest.raises(ValueError, match="Unexpected arguments"):
        registry.call(
            "get_customer",
            customer_id="CUST-001",
            query="SELECT *",
        )


def test_invalid_argument_type_is_rejected(registry):
    with pytest.raises(ValueError, match="Invalid argument"):
        registry.call(
            "get_transaction",
            transaction_id=123,
        )


def test_invalid_graph_depth_is_rejected(registry):
    with pytest.raises(ValueError, match="Invalid argument"):
        registry.call(
            "get_graph_neighborhood",
            entity_id="ACC-001",
            depth=0,
        )


def test_boolean_graph_depth_is_rejected(registry):
    with pytest.raises(ValueError, match="Invalid argument"):
        registry.call(
            "get_graph_neighborhood",
            entity_id="ACC-001",
            depth=True,
        )