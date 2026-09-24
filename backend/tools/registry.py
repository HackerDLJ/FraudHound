from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: Callable[..., Any]
    required_args: frozenset[str]
    optional_args: frozenset[str] = frozenset()
    validators: dict[str, Callable[[Any], bool]] | None = None


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_depth(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 5


class ToolRegistry:
    """Permission and argument-validation boundary for application tools."""

    def __init__(self, graph):
        self.graph = graph
        self.tools = {
            "get_transaction": ToolSpec(
                "get_transaction",
                graph.get_transaction,
                frozenset({"transaction_id"}),
                validators={"transaction_id": _non_empty_string},
            ),
            "get_customer": ToolSpec(
                "get_customer",
                graph.get_customer,
                frozenset({"customer_id"}),
                validators={"customer_id": _non_empty_string},
            ),
            "get_account": ToolSpec(
                "get_account",
                graph.get_account,
                frozenset({"account_id"}),
                validators={"account_id": _non_empty_string},
            ),
            "get_transaction_history": ToolSpec(
                "get_transaction_history",
                graph.get_transaction_history,
                frozenset({"account_id"}),
                validators={"account_id": _non_empty_string},
            ),
            "get_graph_neighborhood": ToolSpec(
                "get_graph_neighborhood",
                graph.get_graph_neighborhood,
                frozenset({"entity_id"}),
                frozenset({"depth"}),
                {
                    "entity_id": _non_empty_string,
                    "depth": _valid_depth,
                },
            ),
            "detect_fraud_patterns": ToolSpec(
                "detect_fraud_patterns",
                graph.detect_patterns,
                frozenset({"transaction_id"}),
                validators={"transaction_id": _non_empty_string},
            ),
            "find_similar_entities": ToolSpec(
                "find_similar_entities",
                graph.similar_entities,
                frozenset({"entity_id"}),
                validators={"entity_id": _non_empty_string},
            ),
        }

    def available_tools(self) -> list[str]:
        return list(self.tools.keys())

    def call(self, name: str, **kwargs):
        if name not in self.tools:
            raise PermissionError(f"Unregistered tool: {name}")

        spec = self.tools[name]

        supplied = set(kwargs)
        allowed = set(spec.required_args) | set(spec.optional_args)

        missing = spec.required_args - supplied
        if missing:
            raise ValueError(
                f"Missing required arguments for {name}: {sorted(missing)}"
            )

        unexpected = supplied - allowed
        if unexpected:
            raise ValueError(
                f"Unexpected arguments for {name}: {sorted(unexpected)}"
            )

        for argument, validator in (spec.validators or {}).items():
            if argument in kwargs and not validator(kwargs[argument]):
                raise ValueError(
                    f"Invalid argument '{argument}' for {name}"
                )

        return spec.handler(**kwargs)