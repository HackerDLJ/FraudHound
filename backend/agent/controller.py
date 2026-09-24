from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.agent.pattern_precedence import apply_precedence
from backend.agent.reasoning import (
    DeterministicReasoningProvider,
    ReasoningProvider,
    build_evidence_context,
    validate_reasoning_result,
)
from backend.graph.fraud_ring import detect_fraud_rings
from backend.memory.case_memory import CaseMemory
from backend.memory.graphrag import build_graphrag_context
from backend.models.schemas import (
    ActionInput,
    ActionRecommendation,
    ApprovalInput,
    AuditEvent,
    Case,
    CaseStatus,
    ConflictResolution,
    ConflictStatus,
    Evidence,
    EvidenceConflict,
    EvidenceInput,
    EvidenceRequest,
    InvestigationRequest,
    PatternFinding,
    RiskAssessment,
)
from backend.tools.registry import ToolRegistry


class FraudHoundController:
    def __init__(
        self,
        graph,
        memory: CaseMemory,
        policy_engine=None,
        reasoning_provider: ReasoningProvider | None = None,
    ):
        self.graph = graph
        self.memory = memory
        self.policy_engine = policy_engine
        self.tool_registry = ToolRegistry(graph)
        self.reasoning_provider = (
            reasoning_provider or DeterministicReasoningProvider()
        )

    def _event(
        self,
        case: Case,
        event: str,
        *,
        actor: str = "fraudhound-agent",
        tool: str | None = None,
        input: Any = None,
        output: Any = None,
        risk_before: int | None = None,
        risk_after: int | None = None,
        confidence_before: float | None = None,
        confidence_after: float | None = None,
    ) -> AuditEvent:
        audit_event = AuditEvent(
            event=event,
            actor=actor,
            tool=tool,
            input=input,
            output=output,
            risk_before=risk_before,
            risk_after=risk_after,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )
        case.timeline.append(audit_event)
        self.memory.audit(
            case.case_id,
            event,
            audit_event.model_dump(mode="json"),
        )
        return audit_event

    def create_case(self, request: InvestigationRequest) -> Case:
        scenario = request.scenario or "high_confidence"
        trigger = dict(request.trigger)
        trigger["scenario"] = scenario
        if request.transaction_id:
            trigger["transaction_id"] = request.transaction_id
        case = Case(
            case_id=f"CASE-{scenario.upper()}",
            trigger=trigger,
            status=CaseStatus.OPEN,
        )
        self._event(case, "Case created", input=trigger)
        self.memory.save(case)
        return case

    def _detect_fraud_rings(
        self,
        case: Case,
        neighborhood: dict[str, Any],
    ) -> list[dict[str, Any]]:
        nodes = neighborhood.get("nodes", [])
        edges = neighborhood.get("edges", [])
        rings = detect_fraud_rings(nodes, edges, min_accounts=3)
        case.fraud_rings = rings
        if rings:
            self._event(
                case,
                "Fraud ring detected",
                tool="fraud_ring_detector",
                input={
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                    "min_accounts": 3,
                },
                output={"ring_count": len(rings), "rings": rings},
            )
        return rings

    def _add_fraud_ring_evidence(
        self,
        case: Case,
        rings: list[dict[str, Any]],
    ) -> None:
        if not rings or any(
            evidence.id == "EVID-FRAUD-RING"
            for evidence in case.evidence
        ):
            return
        strongest_ring = rings[0]
        case.evidence.append(
            Evidence(
                id="EVID-FRAUD-RING",
                kind="fraud_ring",
                statement=(
                    f"Graph analysis identified a connected cluster "
                    f"of {strongest_ring['account_count']} accounts with "
                    "shared infrastructure or account relationships."
                ),
                source="fraud_ring_detector",
                polarity="supporting",
                strength=strongest_ring["confidence"],
                metadata={
                    "ring_id": strongest_ring["ring_id"],
                    "account_ids": strongest_ring["account_ids"],
                    "shared_devices": strongest_ring["shared_devices"],
                    "shared_ips": strongest_ring["shared_ips"],
                    "historical_fraud_accounts": (
                        strongest_ring["historical_fraud_accounts"]
                    ),
                },
            )
        )

    def _run_reasoning(
        self,
        case: Case,
        neighborhood: dict[str, Any],
    ) -> None:
        """Run the controlled reasoning boundary without changing NBA logic."""
        case_dict = case.model_dump(mode="json")
        context = build_evidence_context(case_dict)
        graph_context = build_graphrag_context(
            neighborhood,
            [],
            case.similar_cases,
        )
        context["graph_context"] = graph_context

        available_tools = sorted(self.tool_registry.tools)
        result = self.reasoning_provider.reason(
            context,
            available_tools,
        )
        validate_reasoning_result(result, available_tools)

        tool_output: Any = None
        if result.selected_tool:
            tool_output = self.tool_registry.call(
                result.selected_tool,
                **result.tool_arguments,
            )

        structured_evidence = {
            "selected_tool": result.selected_tool,
            "tool_arguments": result.tool_arguments,
            "evidence_summary": result.evidence_summary,
            "uncertainty": result.uncertainty,
            "explanation": result.explanation,
            "tool_result": self._reasoning_tool_summary(tool_output),
        }

        self._event(
            case,
            "Reasoning completed",
            actor="fraudhound-reasoner",
            tool=result.selected_tool,
            input={
                "available_tools": available_tools,
                "graph_context_chars": len(graph_context),
            },
            output=structured_evidence,
        )

    @staticmethod
    def _reasoning_tool_summary(tool_output: Any) -> dict[str, Any]:
        if isinstance(tool_output, dict):
            summary: dict[str, Any] = {
                "result_type": "structured",
                "keys": sorted(tool_output.keys()),
            }
            if isinstance(tool_output.get("nodes"), list):
                summary["node_count"] = len(tool_output["nodes"])
            if isinstance(tool_output.get("edges"), list):
                summary["edge_count"] = len(tool_output["edges"])
            if isinstance(tool_output.get("signals"), dict):
                summary["signals"] = tool_output["signals"]
            if "patterns" in tool_output and isinstance(
                tool_output["patterns"], list
            ):
                summary["pattern_count"] = len(tool_output["patterns"])
            return summary
        return {"result_type": type(tool_output).__name__}

    def investigate(self, case: Case) -> Case:
        scenario = case.trigger.get("scenario", "high_confidence")
        transaction_id = (
            case.trigger.get("transaction_id")
            or self.graph.current.get("transaction_id", "TX-DEMO-001")
        )
        transaction = self.graph.get_transaction(transaction_id)
        customer_id = transaction["customer_id"]
        account_id = transaction["account_id"]

        self.graph.get_customer(customer_id)
        self.graph.get_account(account_id)
        self.graph.get_transaction_history(account_id)
        neighborhood = self.graph.get_graph_neighborhood(account_id, depth=2)
        graph_signals = neighborhood.get("signals", {})

        case.entities = [
            {"id": customer_id, "type": "Customer"},
            {"id": account_id, "type": "Account"},
            {"id": transaction["transaction_id"], "type": "Transaction"},
            {"id": transaction["device_id"], "type": "Device"},
            {"id": transaction["ip_id"], "type": "IPAddress"},
            {"id": transaction["merchant_id"], "type": "Merchant"},
        ]
        case.transactions = [transaction]

        fraud_rings = self._detect_fraud_rings(case, neighborhood)

        case.evidence = [
            Evidence(
                id="EVID-TRANSACTION",
                kind="transaction",
                statement=(
                    f"Transaction {transaction['transaction_id']} "
                    f"for amount {transaction['amount']}"
                ),
                source="transaction_record",
                polarity="supporting",
                strength=min(1.0, transaction.get("risk_score", 0) / 100),
            )
        ]

        if transaction.get("new_device"):
            case.evidence.append(
                Evidence(
                    id="EVID-DEVICE",
                    kind="device_behavior",
                    statement="Transaction originated from a newly observed device.",
                    source="graph",
                    polarity="supporting",
                    strength=0.78,
                )
            )
        if transaction.get("shared_device_accounts", 0) >= 2:
            case.evidence.append(
                Evidence(
                    id="EVID-SHARED-DEVICE",
                    kind="network_signal",
                    statement=(
                        f"Device is associated with "
                        f"{transaction['shared_device_accounts']} accounts."
                    ),
                    source="graph",
                    polarity="supporting",
                    strength=0.86,
                )
            )
        if transaction.get("shared_ip_accounts", 0) >= 2:
            case.evidence.append(
                Evidence(
                    id="EVID-SHARED-IP",
                    kind="network_signal",
                    statement=(
                        f"IP address is associated with "
                        f"{transaction['shared_ip_accounts']} accounts."
                    ),
                    source="graph",
                    polarity="supporting",
                    strength=0.72,
                )
            )
        if transaction.get("prior_fraud_connected"):
            case.evidence.append(
                Evidence(
                    id="EVID-HISTORICAL-FRAUD",
                    kind="historical_fraud",
                    statement=(
                        "Connected account has a confirmed historical "
                        "fraud association."
                    ),
                    source="graph",
                    polarity="supporting",
                    strength=0.94,
                )
            )
        if transaction.get("velocity_24h", 0) >= 5:
            case.evidence.append(
                Evidence(
                    id="EVID-VELOCITY",
                    kind="velocity",
                    statement=(
                        f"Account recorded {transaction['velocity_24h']} "
                        "transactions in the last 24 hours."
                    ),
                    source="transaction_history",
                    polarity="supporting",
                    strength=0.82,
                )
            )
        if transaction.get("location_mismatch"):
            case.evidence.append(
                Evidence(
                    id="EVID-LOCATION",
                    kind="geolocation",
                    statement=(
                        "Transaction location differs from recent "
                        "account geography."
                    ),
                    source="behavioral_analysis",
                    polarity="supporting",
                    strength=0.73,
                )
            )
        if transaction.get("customer_confirmed"):
            case.evidence.append(
                Evidence(
                    id="EVID-CUSTOMER-CONFIRMATION",
                    kind="customer_confirmation",
                    statement="Customer confirmed the transaction.",
                    source="customer_verification",
                    polarity="contradicting",
                    strength=0.95,
                )
            )

        self._add_fraud_ring_evidence(case, fraud_rings)

        raw_patterns = self.graph.detect_patterns(transaction_id).get(
            "patterns", []
        )
        raw_patterns = apply_precedence(raw_patterns, graph_signals)
        case.patterns = [PatternFinding(**pattern) for pattern in raw_patterns]

        if fraud_rings:
            strongest_ring = fraud_rings[0]
            case.patterns.append(
                PatternFinding(
                    pattern="Coordinated Fraud Ring",
                    confidence=strongest_ring["confidence"],
                    supporting_evidence=["EVID-FRAUD-RING"],
                    contradicting_evidence=[],
                    graph_signals=strongest_ring["signals"],
                    explanation=strongest_ring["explanation"],
                )
            )

        # Phase 5B: controlled reasoning is advisory and audited.
        self._run_reasoning(case, neighborhood)

        risk_score = int(transaction.get("risk_score", 0))
        supporting_count = sum(
            1 for evidence in case.evidence
            if evidence.polarity == "supporting"
        )
        contradicting_count = sum(
            1 for evidence in case.evidence
            if evidence.polarity == "contradicting"
        )

        if scenario == "high_confidence":
            confidence = 0.90
        elif scenario == "ambiguous":
            confidence = 0.65
        elif scenario == "legitimate":
            confidence = 0.82
        else:
            confidence = 0.60

        if supporting_count >= 4:
            confidence = max(confidence, 0.85)
        if contradicting_count:
            confidence = max(confidence, 0.78)
        if fraud_rings:
            confidence = max(confidence, fraud_rings[0]["confidence"])
        confidence = min(confidence, 0.99)

        uncertainty: list[str] = []
        if (
            scenario == "ambiguous"
            and not any(
                e.kind == "customer_authentication"
                for e in case.evidence
            )
        ):
            uncertainty.append(
                "Customer authorization has not yet been independently confirmed."
            )
        if transaction.get("location_mismatch"):
            uncertainty.append(
                "Geolocation differs from recent account activity."
            )
        if not uncertainty:
            uncertainty.append(
                "No material unresolved uncertainty identified."
            )

        case.risk_assessment = RiskAssessment(
            risk_level=self._risk_level(risk_score),
            risk_score=risk_score,
            confidence=confidence,
            uncertainty=uncertainty,
            rationale=self._risk_rationale(
                risk_score,
                confidence,
                case,
            ),
        )
        case.uncertainties = uncertainty
        case.conflicts = self.detect_conflicts(case)

        customer_authenticated = any(
            e.kind == "customer_authentication"
            and e.polarity == "supporting"
            for e in case.evidence
        )

        if scenario == "ambiguous" and not customer_authenticated:
            request = EvidenceRequest(
                request_id=f"REQ-{case.case_id}-CUSTOMER-AUTH",
                type="CUSTOMER_AUTHENTICATION",
                reason=(
                    "High transaction risk is offset by insufficient "
                    "confirmation of customer authorization."
                ),
                question=(
                    "Can the customer independently authenticate "
                    "and confirm this transaction?"
                ),
                expected_information=(
                    "Verified confirmation from the account holder."
                ),
                how_it_reduces_uncertainty=(
                    "It distinguishes unauthorized activity from "
                    "legitimate customer activity."
                ),
            )
            case.evidence_requests = [request]
            case.status = CaseStatus.AWAITING_EVIDENCE
            case.recommended_actions = [
                ActionRecommendation(
                    action="REQUEST_MORE_EVIDENCE",
                    reason=(
                        "Risk is high but confidence is insufficient "
                        "to make a final action."
                    ),
                    supporting_evidence=[
                        e.id
                        for e in case.evidence
                        if e.polarity == "supporting"
                    ],
                    risk=self._risk_level(risk_score),
                    confidence=confidence,
                    required_approval=False,
                    reversible=True,
                )
            ]
            self._event(
                case,
                "Evidence requested",
                output=request.model_dump(mode="json"),
                risk_after=risk_score,
                confidence_after=confidence,
            )
            case.iterations += 1
            self.memory.save(case)
            return case

        customer_confirmed = any(
            e.kind in {"customer_confirmation", "customer_authentication"}
            for e in case.evidence
        )
        action = self._next_action(
            case,
            risk_score,
            confidence,
            customer_confirmed=customer_confirmed,
        )
        case.recommended_actions = [action]
        case.status = (
            CaseStatus.AWAITING_EVIDENCE
            if action.action == "REQUEST_MORE_EVIDENCE"
            else CaseStatus.ACTION_RECOMMENDED
        )
        case.explanation = self._explain(case, action)

        self._event(
            case,
            "Investigation completed",
            output={
                "action": action.action,
                "risk_score": risk_score,
                "confidence": confidence,
                "fraud_ring_count": len(fraud_rings),
            },
            risk_after=risk_score,
            confidence_after=confidence,
        )
        case.iterations += 1
        self.memory.save(case)
        return case

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 90:
            return "CRITICAL"
        if score >= 75:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        return "LOW"

    def _risk_rationale(
        self,
        risk_score: int,
        confidence: float,
        case: Case,
    ) -> str:
        pattern_names = [pattern.pattern for pattern in case.patterns]
        if pattern_names:
            return (
                f"Risk score is {risk_score}/100 with confidence "
                f"{confidence:.2f}. Detected patterns: "
                f"{', '.join(pattern_names)}."
            )
        return (
            f"Risk score is {risk_score}/100 with confidence "
            f"{confidence:.2f}."
        )

    def _next_action(
        self,
        case: Case,
        risk_score: int,
        confidence: float,
        *,
        customer_confirmed: bool = False,
    ) -> ActionRecommendation:
        supporting = [
            e.id for e in case.evidence if e.polarity == "supporting"
        ]
        contradicting = [
            e.id for e in case.evidence if e.polarity == "contradicting"
        ]

        if customer_confirmed:
            return ActionRecommendation(
                action="MONITOR_TRANSACTION",
                reason=(
                    "Customer authentication or confirmation provides "
                    "contradicting evidence against unauthorized activity. "
                    "Elevated network risk remains, so monitoring is "
                    "recommended rather than automatic blocking."
                ),
                supporting_evidence=supporting + contradicting,
                risk=self._risk_level(risk_score),
                confidence=confidence,
                required_approval=False,
                reversible=True,
            )
        if risk_score >= 80 and confidence >= 0.80:
            return ActionRecommendation(
                action="BLOCK_TRANSACTION",
                reason="High risk with high confidence.",
                supporting_evidence=supporting,
                risk=self._risk_level(risk_score),
                confidence=confidence,
                required_approval=True,
                approval_route="fraud-analyst",
                reversible=False,
            )
        if risk_score >= 70 and confidence < 0.80:
            return ActionRecommendation(
                action="MONITOR_TRANSACTION",
                reason=(
                    "Risk is elevated but confidence is insufficient "
                    "for an automatic blocking action."
                ),
                supporting_evidence=supporting,
                risk=self._risk_level(risk_score),
                confidence=confidence,
                required_approval=False,
                reversible=True,
            )
        if risk_score < 50:
            return ActionRecommendation(
                action="ALLOW_TRANSACTION",
                reason="Risk is low.",
                supporting_evidence=supporting + contradicting,
                risk=self._risk_level(risk_score),
                confidence=confidence,
                required_approval=False,
                reversible=True,
            )
        return ActionRecommendation(
            action="MONITOR_TRANSACTION",
            reason="Risk is moderate and should be monitored.",
            supporting_evidence=supporting + contradicting,
            risk=self._risk_level(risk_score),
            confidence=confidence,
            required_approval=False,
            reversible=True,
        )

    def _explain(
        self,
        case: Case,
        action: ActionRecommendation,
    ) -> str:
        risk = case.risk_assessment
        if risk is None:
            return action.reason
        return (
            f"Risk level: {risk.risk_level}. "
            f"Risk score: {risk.risk_score}/100. "
            f"Confidence: {risk.confidence:.2f}. "
            f"Recommended action: {action.action}. "
            f"{action.reason}"
        )

    def detect_conflicts(
        self,
        case: Case,
    ) -> list[EvidenceConflict]:
        conflicts = list(case.conflicts)
        existing_pairs = {
            tuple(sorted((conflict.evidence_a, conflict.evidence_b)))
            for conflict in case.conflicts
        }
        supporting = [
            e for e in case.evidence if e.polarity == "supporting"
        ]
        contradicting = [
            e for e in case.evidence if e.polarity == "contradicting"
        ]
        for evidence_a in supporting:
            for evidence_b in contradicting:
                pair = tuple(sorted((evidence_a.id, evidence_b.id)))
                if pair in existing_pairs:
                    continue
                conflicts.append(
                    EvidenceConflict(
                        conflict_id=(
                            f"CONFLICT-{case.case_id}-"
                            f"{evidence_a.id}-{evidence_b.id}"
                        ),
                        case_id=case.case_id,
                        evidence_a=evidence_a.id,
                        evidence_b=evidence_b.id,
                    )
                )
                existing_pairs.add(pair)
        case.conflicts = conflicts
        return conflicts

    def resolve_conflict(
        self,
        case: Case,
        conflict_id: str,
        resolution: ConflictResolution,
        analyst: str,
        reason: str,
    ) -> Case:
        if not reason.strip():
            raise ValueError("Resolution reason is required")
        conflict = next(
            (
                conflict
                for conflict in case.conflicts
                if conflict.conflict_id == conflict_id
            ),
            None,
        )
        if conflict is None:
            self.detect_conflicts(case)
            conflict = next(
                (
                    conflict
                    for conflict in case.conflicts
                    if conflict.conflict_id == conflict_id
                ),
                None,
            )
        if conflict is None:
            raise ValueError(f"Conflict '{conflict_id}' not found.")
        if conflict.status == ConflictStatus.RESOLVED:
            raise ValueError(
                f"Conflict '{conflict_id}' already resolved."
            )

        confidence_before = (
            case.risk_assessment.confidence
            if case.risk_assessment
            else None
        )
        conflict.status = ConflictStatus.RESOLVED
        conflict.resolution = resolution
        conflict.analyst = analyst
        conflict.reason = reason
        conflict.resolved_at = datetime.now(timezone.utc).isoformat()

        if case.risk_assessment:
            if resolution == ConflictResolution.RECONCILE:
                case.risk_assessment.confidence = min(
                    0.99,
                    case.risk_assessment.confidence + 0.05,
                )
            elif resolution == ConflictResolution.DEFER:
                case.risk_assessment.confidence = min(
                    case.risk_assessment.confidence,
                    0.75,
                )

        if resolution == ConflictResolution.ESCALATE:
            case.status = CaseStatus.ESCALATED
        elif resolution == ConflictResolution.DEFER:
            case.status = CaseStatus.AWAITING_EVIDENCE
        else:
            case.status = CaseStatus.ACTION_RECOMMENDED

        self._event(
            case,
            "Evidence conflict resolved",
            actor=analyst,
            input={
                "conflict_id": conflict_id,
                "resolution": resolution.value,
                "reason": reason,
            },
            output={
                "status": conflict.status.value,
                "resolution": conflict.resolution.value,
            },
            confidence_before=confidence_before,
            confidence_after=(
                case.risk_assessment.confidence
                if case.risk_assessment
                else None
            ),
        )
        self.memory.save(case)
        return case

    def receive_evidence(
        self,
        case: Case,
        evidence_input: EvidenceInput,
    ) -> Case:
        request = next(
            (
                item
                for item in case.evidence_requests
                if item.request_id == evidence_input.request_id
            ),
            None,
        )
        if request is None:
            raise ValueError(
                f"Evidence request '{evidence_input.request_id}' not found."
            )

        result = dict(evidence_input.result)
        if result.get("customer_authenticated") is True:
            case.evidence.append(
                Evidence(
                    id="EVID-CUSTOMER-AUTH",
                    kind="customer_authentication",
                    statement=(
                        "Customer successfully authenticated and "
                        "confirmed the transaction."
                    ),
                    source="customer_verification",
                    polarity="supporting",
                    strength=0.95,
                )
            )

        request.status = "RECEIVED"
        self._event(
            case,
            "Evidence received",
            input={
                "request_id": evidence_input.request_id,
                "result": result,
            },
            output={"request_status": request.status},
        )
        case.status = CaseStatus.INVESTIGATING

        authenticated_evidence = [
            e for e in case.evidence
            if e.kind == "customer_authentication"
        ]
        scenario = case.trigger.get("scenario", "high_confidence")
        transaction_id = (
            case.trigger.get("transaction_id")
            or self.graph.current.get("transaction_id", "TX-DEMO-001")
        )
        transaction = self.graph.get_transaction(transaction_id)
        neighborhood = self.graph.get_graph_neighborhood(
            transaction["account_id"],
            depth=2,
        )
        graph_signals = neighborhood.get("signals", {})
        fraud_rings = self._detect_fraud_rings(case, neighborhood)

        case.evidence = [
            Evidence(
                id="EVID-TRANSACTION",
                kind="transaction",
                statement=(
                    f"Transaction {transaction['transaction_id']} "
                    f"for amount {transaction['amount']}"
                ),
                source="transaction_record",
                polarity="supporting",
                strength=min(1.0, transaction.get("risk_score", 0) / 100),
            )
        ]
        if transaction.get("new_device"):
            case.evidence.append(
                Evidence(
                    id="EVID-DEVICE",
                    kind="device_behavior",
                    statement="Transaction originated from a newly observed device.",
                    source="graph",
                    polarity="supporting",
                    strength=0.78,
                )
            )
        if transaction.get("shared_device_accounts", 0) >= 2:
            case.evidence.append(
                Evidence(
                    id="EVID-SHARED-DEVICE",
                    kind="network_signal",
                    statement=(
                        f"Device is associated with "
                        f"{transaction['shared_device_accounts']} accounts."
                    ),
                    source="graph",
                    polarity="supporting",
                    strength=0.86,
                )
            )
        if transaction.get("shared_ip_accounts", 0) >= 2:
            case.evidence.append(
                Evidence(
                    id="EVID-SHARED-IP",
                    kind="network_signal",
                    statement=(
                        f"IP address is associated with "
                        f"{transaction['shared_ip_accounts']} accounts."
                    ),
                    source="graph",
                    polarity="supporting",
                    strength=0.72,
                )
            )
        if transaction.get("prior_fraud_connected"):
            case.evidence.append(
                Evidence(
                    id="EVID-HISTORICAL-FRAUD",
                    kind="historical_fraud",
                    statement=(
                        "Connected account has a confirmed historical "
                        "fraud association."
                    ),
                    source="graph",
                    polarity="supporting",
                    strength=0.94,
                )
            )
        if transaction.get("velocity_24h", 0) >= 5:
            case.evidence.append(
                Evidence(
                    id="EVID-VELOCITY",
                    kind="velocity",
                    statement=(
                        f"Account recorded {transaction['velocity_24h']} "
                        "transactions in the last 24 hours."
                    ),
                    source="transaction_history",
                    polarity="supporting",
                    strength=0.82,
                )
            )
        if transaction.get("location_mismatch"):
            case.evidence.append(
                Evidence(
                    id="EVID-LOCATION",
                    kind="geolocation",
                    statement=(
                        "Transaction location differs from recent "
                        "account geography."
                    ),
                    source="behavioral_analysis",
                    polarity="supporting",
                    strength=0.73,
                )
            )
        if transaction.get("customer_confirmed"):
            case.evidence.append(
                Evidence(
                    id="EVID-CUSTOMER-CONFIRMATION",
                    kind="customer_confirmation",
                    statement="Customer confirmed the transaction.",
                    source="customer_verification",
                    polarity="contradicting",
                    strength=0.95,
                )
            )

        self._add_fraud_ring_evidence(case, fraud_rings)
        case.evidence.extend(authenticated_evidence)

        raw_patterns = self.graph.detect_patterns(transaction_id).get(
            "patterns", []
        )
        raw_patterns = apply_precedence(raw_patterns, graph_signals)
        case.patterns = [PatternFinding(**pattern) for pattern in raw_patterns]

        if fraud_rings:
            strongest_ring = fraud_rings[0]
            case.patterns.append(
                PatternFinding(
                    pattern="Coordinated Fraud Ring",
                    confidence=strongest_ring["confidence"],
                    supporting_evidence=["EVID-FRAUD-RING"],
                    contradicting_evidence=[],
                    graph_signals=strongest_ring["signals"],
                    explanation=strongest_ring["explanation"],
                )
            )

        # Phase 5B: controlled reasoning is advisory and audited.
        self._run_reasoning(case, neighborhood)

        risk_score = int(transaction.get("risk_score", 0))
        supporting_count = sum(
            1 for e in case.evidence if e.polarity == "supporting"
        )
        contradicting_count = sum(
            1 for e in case.evidence if e.polarity == "contradicting"
        )

        if scenario == "ambiguous":
            confidence = 0.82
        elif scenario == "legitimate":
            confidence = 0.82
        else:
            confidence = 0.90

        if supporting_count >= 4:
            confidence = max(confidence, 0.85)
        if contradicting_count:
            confidence = max(confidence, 0.78)
        if fraud_rings:
            confidence = max(confidence, fraud_rings[0]["confidence"])
        confidence = min(confidence, 0.99)

        case.risk_assessment = RiskAssessment(
            risk_level=self._risk_level(risk_score),
            risk_score=risk_score,
            confidence=confidence,
            uncertainty=(
                [
                    "Network risk remains elevated despite customer authentication."
                ]
                if authenticated_evidence
                else ["No material unresolved uncertainty identified."]
            ),
            rationale=self._risk_rationale(
                risk_score,
                confidence,
                case,
            ),
        )
        case.uncertainties = case.risk_assessment.uncertainty
        case.conflicts = self.detect_conflicts(case)

        action = self._next_action(
            case,
            risk_score,
            confidence,
            customer_confirmed=bool(
                authenticated_evidence
                or transaction.get("customer_confirmed")
            ),
        )
        case.recommended_actions = [action]
        case.status = CaseStatus.ACTION_RECOMMENDED
        case.evidence_requests = [
            request
            for request in case.evidence_requests
            if request.status != "RECEIVED"
        ]
        case.explanation = self._explain(case, action)

        self._event(
            case,
            "Investigation updated after evidence",
            output={
                "action": action.action,
                "risk_score": risk_score,
                "confidence": confidence,
                "fraud_ring_count": len(fraud_rings),
            },
            risk_after=risk_score,
            confidence_after=confidence,
        )
        case.iterations += 1
        self.memory.save(case)
        return case

    def approve(
        self,
        case: Case,
        approval: ApprovalInput,
    ) -> Case:
        if not case.recommended_actions:
            raise ValueError(
                "No recommended action is available for approval."
            )
        recommendation = case.recommended_actions[-1]
        if not recommendation.required_approval:
            raise ValueError(
                "The recommended action does not require approval."
            )
        case.approval_history.append(
            {
                "approved": approval.approved,
                "approver": approval.approver,
                "note": approval.note,
            }
        )
        if approval.approved:
            case.status = CaseStatus.PENDING_APPROVAL
        else:
            case.status = CaseStatus.ESCALATED
        self._event(
            case,
            "Action approval recorded",
            actor=approval.approver,
            input={
                "approved": approval.approved,
                "note": approval.note,
            },
        )
        self.memory.save(case)
        return case

    def execute_action(
        self,
        case: Case,
        action_input: ActionInput,
    ) -> Case:
        if not case.recommended_actions:
            raise ValueError("No recommended action is available.")
        recommendation = case.recommended_actions[-1]
        if action_input.action != recommendation.action:
            raise ValueError(
                "Requested action does not match the recommended action."
            )
        if recommendation.required_approval:
            approved = any(
                item.get("approved") is True
                for item in case.approval_history
            )
            if not approved:
                raise ValueError("Required approval has not been granted.")
        executed = {
            "action": action_input.action,
            "status": "EXECUTED",
        }
        case.executed_actions.append(executed)
        case.status = CaseStatus.ACTION_EXECUTED
        self._event(
            case,
            "Action executed",
            input=action_input.model_dump(mode="json"),
            output=executed,
        )
        self.memory.save(case)
        return case
