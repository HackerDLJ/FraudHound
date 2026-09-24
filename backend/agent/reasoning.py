from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


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
    """Provider boundary for deterministic or external LLM reasoning."""

    def reason(
        self,
        context: dict[str, Any],
        available_tools: list[str],
    ) -> ReasoningResult:
        ...


class DeterministicReasoningProvider:
    """Small deterministic provider used to validate the reasoning boundary.

    This provider deliberately does not call tools. It only chooses from
    names supplied by the caller, so an eventual LLM can be substituted
    without changing the permission boundary.
    """

    def reason(
        self,
        context: dict[str, Any],
        available_tools: list[str],
    ) -> ReasoningResult:
        allowed = set(available_tools)

        evidence = context.get("evidence", [])
        transactions = context.get("transactions", [])
        uncertainties = list(context.get("uncertainties", []))
        patterns = context.get("patterns", [])

        if not isinstance(evidence, list):
            evidence = []
        if not isinstance(transactions, list):
            transactions = []
        if not isinstance(patterns, list):
            patterns = []

        transaction = transactions[0] if transactions else {}
        if not isinstance(transaction, dict):
            transaction = {}

        evidence_kinds = {
            item.get("kind")
            for item in evidence
            if isinstance(item, dict)
        }

        selected_tool: str | None = None
        tool_arguments: dict[str, Any] = {}
        reason = ""

        if (
            "get_graph_neighborhood" in allowed
            and (
                "network_signal" in evidence_kinds
                or "fraud_ring" in evidence_kinds
                or any(
                    isinstance(pattern, dict)
                    and pattern.get("graph_signals")
                    for pattern in patterns
                )
            )
        ):
            account_id = transaction.get("account_id")
            if account_id:
                selected_tool = "get_graph_neighborhood"
                tool_arguments = {"entity_id": account_id, "depth": 2}
                reason = "Graph relationships are relevant to the observed evidence."

        if selected_tool is None and "get_transaction_history" in allowed:
            account_id = transaction.get("account_id")
            if account_id:
                selected_tool = "get_transaction_history"
                tool_arguments = {"account_id": account_id}
                reason = "Transaction history can clarify behavioral context."

        if selected_tool is None and "get_transaction" in allowed:
            transaction_id = transaction.get("transaction_id")
            if transaction_id:
                selected_tool = "get_transaction"
                tool_arguments = {"transaction_id": transaction_id}
                reason = "The transaction record provides the primary case context."

        if selected_tool is None:
            reason = "No suitable registered tool was identified from the available context."

        evidence_summary = self._summarize_evidence(evidence)

        if not uncertainties:
            uncertainties = [
                "No unresolved uncertainty was supplied in the reasoning context."
            ]

        explanation = (
            reason
            if selected_tool is None
            else f"{reason} Selected only from the registered tool set."
        )

        return ReasoningResult(
            selected_tool=selected_tool,
            tool_arguments=tool_arguments,
            evidence_summary=evidence_summary,
            uncertainty=uncertainties,
            explanation=explanation,
        )

    @staticmethod
    def _summarize_evidence(evidence: list[Any]) -> str:
        statements: list[str] = []

        for item in evidence[:10]:
            if not isinstance(item, dict):
                continue

            statement = item.get("statement")
            source = item.get("source")

            if statement and source:
                statements.append(f"{statement} [{source}]")
            elif statement:
                statements.append(str(statement))

        if not statements:
            return "No retrieved evidence was supplied."

        return " ".join(statements)


def validate_reasoning_result(
    result: ReasoningResult,
    available_tools: list[str],
) -> ReasoningResult:
    """Validate that a reasoning result stays inside the tool boundary."""
    if result.selected_tool is None:
        return result

    if result.selected_tool not in set(available_tools):
        raise PermissionError(f"Unregistered tool: {result.selected_tool}")

    return result
