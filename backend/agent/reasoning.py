from __future__ import annotations

import json
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
    """Structured output from the reasoning boundary."""

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
    """Safe deterministic baseline for the reasoning boundary."""

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

        if (
            selected_tool is None
            and "get_transaction_history" in available_tools
            and account_id
        ):
            selected_tool = "get_transaction_history"
            arguments = {"account_id": account_id}

        if (
            selected_tool is None
            and "get_transaction" in available_tools
            and transaction_id
        ):
            selected_tool = "get_transaction"
            arguments = {"transaction_id": transaction_id}

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
    """Adapter for an external reasoning callable."""

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


class LLMClient(Protocol):
    """Minimal boundary expected from an external LLM client."""

    def generate(
        self,
        prompt: str,
    ) -> str | dict[str, Any]:
        ...


class LLMReasoningProvider:
    """LLM-backed reasoning provider with a strict structured-output boundary.

    The LLM receives only the compact investigation context and the registered
    tool names. It cannot execute tools itself.

    The client is injected so tests remain offline and no vendor SDK is
    required by the core FraudHound package.
    """

    def __init__(
        self,
        client: LLMClient | Callable[[str], str | dict[str, Any]],
        fallback: ReasoningProvider | None = None,
    ):
        self.client = client
        self.fallback = fallback or DeterministicReasoningProvider()

    def reason(
        self,
        context: dict[str, Any],
        available_tools: list[str],
    ) -> ReasoningResult:
        prompt = self._build_prompt(context, available_tools)

        try:
            if callable(self.client):
                raw = self.client(prompt)
            else:
                raw = self.client.generate(prompt)

            result = self._parse_response(raw)

            return validate_reasoning_result(
                result,
                available_tools,
            )

        except (TypeError, ValueError, PermissionError, json.JSONDecodeError):
            return self.fallback.reason(
                context,
                available_tools,
            )

    @staticmethod
    def _build_prompt(
        context: dict[str, Any],
        available_tools: list[str],
    ) -> str:
        """Build a bounded prompt containing only retrieved case context."""
        payload = {
            "case_context": context,
            "available_tools": available_tools,
            "output_schema": {
                "selected_tool": "string or null",
                "tool_arguments": "object",
                "evidence_summary": "string",
                "uncertainty": "array of strings",
                "explanation": "string",
            },
            "constraints": [
                "Use only the supplied registered tools.",
                "Never invent a tool name.",
                "Never execute a tool.",
                "Do not make the final fraud decision.",
                "Do not recommend an action outside the supplied evidence.",
                "Return only the requested structured fields.",
            ],
        }

        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

    @staticmethod
    def _parse_response(
        raw: str | dict[str, Any],
    ) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw

        if not isinstance(raw, str):
            raise TypeError("LLM response must be a string or dictionary")

        text = raw.strip()

        if text.startswith("```"):
            lines = text.splitlines()

            if len(lines) >= 3:
                lines = lines[1:-1]

            text = "\n".join(lines).strip()

        parsed = json.loads(text)

        if not isinstance(parsed, dict):
            raise TypeError("LLM response JSON must be an object")

        return parsed


def validate_reasoning_result(
    result: ReasoningResult | dict[str, Any],
    available_tools: list[str] | None = None,
) -> ReasoningResult:
    """Strictly validate provider output before it can reach ToolRegistry."""

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