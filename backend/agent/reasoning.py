from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


REGISTERED_REASONING_FIELDS = {
    "selected_tool",
    "tool_arguments",
    "evidence_summary",
    "uncertainty",
    "explanation",
}


def build_evidence_context(case: dict[str, Any]) -> dict[str, Any]:
    """Build a compact case context suitable for a reasoning provider."""
    return {
        "trigger": case.get("trigger"),
        "transactions": case.get("transactions", [])[:10],
        "evidence": case.get("evidence", [])[-30:],
        "patterns": case.get("patterns", []),
        "risk_assessment": case.get("risk_assessment"),
        "uncertainties": case.get("uncertainties", []),
        "similar_cases": case.get("similar_cases", [])[:5],
        "policy_references": case.get("policy_references", []),
    }


@dataclass(frozen=True)
class ReasoningResult:
    """Structured output from the reasoning boundary.

    The reasoning layer may recommend a registered tool, but it never
    executes tools itself. Tool execution remains the responsibility of
    ToolRegistry.
    """

    selected_tool: str | None = None
    tool_arguments: dict[str, Any] = field(default_factory=dict)
    evidence_summary: str = ""
    uncertainty: list[str] = field(default_factory=list)
    explanation: str = ""


class ReasoningProvider(Protocol):
    """Provider boundary for deterministic or external reasoning systems."""

    def reason(
        self,
        context: dict[str, Any],
        available_tools: list[str],
    ) -> ReasoningResult:
        ...


class DeterministicReasoningProvider:
    """Safe deterministic baseline for the reasoning boundary.

    Tool selection is based only on the compact evidence context and the
    registered tool set supplied by the caller. The provider never executes
    a tool itself.

    The selection order preserves the Phase 5A reasoning contract:
    graph neighborhood first, then transaction history, then transaction
    record.
    """

    def reason(
        self,
        context: dict[str, Any],
        available_tools: list[str],
    ) -> ReasoningResult:
        transactions = context.get("transactions") or []
        evidence = context.get("evidence") or []
        uncertainties = list(context.get("uncertainties") or [])

        selected_tool: str | None = None
        arguments: dict[str, Any] = {}

        transaction = transactions[0] if transactions else {}

        account_id = transaction.get("account_id")
        transaction_id = transaction.get("transaction_id")

        # Preserve the Phase 5A default: graph neighborhood is preferred
        # whenever it is available and we have an entity to investigate.
        if "get_graph_neighborhood" in available_tools:
            if account_id:
                selected_tool = "get_graph_neighborhood"
                arguments = {
                    "entity_id": account_id,
                    "depth": 2,
                }
            elif transaction_id:
                selected_tool = "get_graph_neighborhood"
                arguments = {
                    "entity_id": transaction_id,
                    "depth": 2,
                }

        # If graph retrieval is unavailable, fall back to transaction history.
        if selected_tool is None and "get_transaction_history" in available_tools:
            if account_id:
                selected_tool = "get_transaction_history"
                arguments = {
                    "account_id": account_id,
                }

        # If neither graph nor history is available, retrieve the transaction
        # record directly.
        if selected_tool is None and "get_transaction" in available_tools:
            if transaction_id:
                selected_tool = "get_transaction"
                arguments = {
                    "transaction_id": transaction_id,
                }

        # Evidence-source fallback for contexts without transaction identity.
        if selected_tool is None and evidence:
            first_evidence = evidence[-1]

            if isinstance(first_evidence, dict):
                evidence_source = first_evidence.get("source")

                if (
                    evidence_source
                    and "get_graph_neighborhood" in available_tools
                ):
                    selected_tool = "get_graph_neighborhood"
                    arguments = {
                        "entity_id": evidence_source,
                        "depth": 2,
                    }

        return ReasoningResult(
            selected_tool=selected_tool,
            tool_arguments=arguments,
            evidence_summary=(
                "Reasoning reviewed the compact case context and selected "
                "additional evidence from the registered tool set when available."
            ),
            uncertainty=uncertainties,
            explanation=(
                "The reasoning boundary is advisory and uses the registered "
                "tool set only. Deterministic evidence, risk assessment, "
                "policy, and next-best-action logic remain authoritative."
            ),
        )


class CallableReasoningProvider:
    """Adapter for an external reasoning callable.

    The callable is responsible only for producing structured reasoning data.
    It cannot execute application tools through this adapter.
    """

    def __init__(
        self,
        resolver: Callable[
            [dict[str, Any], list[str]],
            ReasoningResult | dict[str, Any],
        ],
    ):
        self.resolver = resolver

    def reason(
        self,
        context: dict[str, Any],
        available_tools: list[str],
    ) -> ReasoningResult:
        raw = self.resolver(context, list(available_tools))

        if isinstance(raw, ReasoningResult):
            return validate_reasoning_result(raw, available_tools)

        if not isinstance(raw, dict):
            raise TypeError(
                "Reasoning provider must return ReasoningResult or dict"
            )

        return validate_reasoning_result(raw, available_tools)


def validate_reasoning_result(
    result: ReasoningResult | dict[str, Any],
    available_tools: list[str] | None = None,
) -> ReasoningResult:
    """Strictly validate provider output before it can reach ToolRegistry.

    Validation is intentionally strict. Unknown fields and unregistered tools
    are rejected before anything can reach the application tool boundary.
    """
    if isinstance(result, ReasoningResult):
        normalized = result

    elif isinstance(result, dict):
        unknown = set(result) - REGISTERED_REASONING_FIELDS

        if unknown:
            raise ValueError(
                f"Unsupported reasoning fields: {sorted(unknown)}"
            )

        normalized = ReasoningResult(
            selected_tool=result.get("selected_tool"),
            tool_arguments=result.get("tool_arguments") or {},
            evidence_summary=result.get("evidence_summary", ""),
            uncertainty=result.get("uncertainty") or [],
            explanation=result.get("explanation", ""),
        )

    else:
        raise TypeError(
            "Reasoning result must be ReasoningResult or dict"
        )

    if normalized.selected_tool is not None:
        if not isinstance(normalized.selected_tool, str):
            raise TypeError(
                "selected_tool must be a string or None"
            )

        if (
            available_tools is not None
            and normalized.selected_tool not in available_tools
        ):
            raise PermissionError(
                f"Unregistered tool: {normalized.selected_tool}"
            )

    if not isinstance(normalized.tool_arguments, dict):
        raise TypeError(
            "tool_arguments must be a dictionary"
        )

    if not isinstance(normalized.evidence_summary, str):
        raise TypeError(
            "evidence_summary must be a string"
        )

    if (
        not isinstance(normalized.uncertainty, list)
        or not all(
            isinstance(item, str)
            for item in normalized.uncertainty
        )
    ):
        raise TypeError(
            "uncertainty must be a list of strings"
        )

    if not isinstance(normalized.explanation, str):
        raise TypeError(
            "explanation must be a string"
        )

    if (
        normalized.selected_tool is None
        and normalized.tool_arguments
    ):
        raise ValueError(
            "tool_arguments cannot be supplied when selected_tool is None"
        )

    return normalized