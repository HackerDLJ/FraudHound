from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.agent.pattern_precedence import apply_precedence
from backend.memory.case_memory import CaseMemory
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


class FraudHoundController:
    def __init__(
        self,
        graph,
        memory: CaseMemory,
        policy_engine=None,
    ):
        self.graph = graph
        self.memory = memory
        self.policy_engine = policy_engine

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Case creation
    # ------------------------------------------------------------------

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

        self._event(
            case,
            "Case created",
            input=trigger,
        )

        self.memory.save(case)
        return case

    # ------------------------------------------------------------------
    # Investigation
    # ------------------------------------------------------------------

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

        neighborhood = self.graph.get_graph_neighborhood(
            account_id,
            depth=2,
        )

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

        # --------------------------------------------------------------
        # Evidence
        # --------------------------------------------------------------

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
                strength=min(
                    1.0,
                    transaction.get("risk_score", 0) / 100,
                ),
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

        # --------------------------------------------------------------
        # Pattern detection
        # --------------------------------------------------------------

        raw_patterns = self.graph.detect_patterns(transaction_id).get(
            "patterns",
            [],
        )

        raw_patterns = apply_precedence(
            raw_patterns,
            graph_signals,
        )

        case.patterns = [
            PatternFinding(**pattern)
            for pattern in raw_patterns
        ]

        # --------------------------------------------------------------
        # Risk and confidence
        # --------------------------------------------------------------

        risk_score = int(transaction.get("risk_score", 0))

        supporting_count = sum(
            1
            for evidence in case.evidence
            if evidence.polarity == "supporting"
        )

        contradicting_count = sum(
            1
            for evidence in case.evidence
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

        # --------------------------------------------------------------
        # Conflict detection
        # --------------------------------------------------------------

        case.conflicts = self.detect_conflicts(case)

        # --------------------------------------------------------------
        # Ambiguous workflow
        # --------------------------------------------------------------

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

        # --------------------------------------------------------------
        # Recommendation
        # --------------------------------------------------------------

        customer_confirmed = any(
            e.kind in {
                "customer_confirmation",
                "customer_authentication",
            }
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
            },
            risk_after=risk_score,
            confidence_after=confidence,
        )

        case.iterations += 1
        self.memory.save(case)

        return case

    # ------------------------------------------------------------------
    # Risk helpers
    # ------------------------------------------------------------------

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
        pattern_names = [
            pattern.pattern
            for pattern in case.patterns
        ]

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

    # ------------------------------------------------------------------
    # Next-best action
    # ------------------------------------------------------------------

    def _next_action(
        self,
        case: Case,
        risk_score: int,
        confidence: float,
        *,
        customer_confirmed: bool = False,
    ) -> ActionRecommendation:

        supporting = [
            e.id
            for e in case.evidence
            if e.polarity == "supporting"
        ]

        contradicting = [
            e.id
            for e in case.evidence
            if e.polarity == "contradicting"
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

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Conflict detection
    # ------------------------------------------------------------------

    def detect_conflicts(
        self,
        case: Case,
    ) -> list[EvidenceConflict]:
        conflicts = list(case.conflicts)

        existing_pairs = {
            tuple(
                sorted(
                    (
                        conflict.evidence_a,
                        conflict.evidence_b,
                    )
                )
            )
            for conflict in case.conflicts
        }

        supporting = [
            e
            for e in case.evidence
            if e.polarity == "supporting"
        ]

        contradicting = [
            e
            for e in case.evidence
            if e.polarity == "contradicting"
        ]

        for evidence_a in supporting:
            for evidence_b in contradicting:
                pair = tuple(
                    sorted(
                        (
                            evidence_a.id,
                            evidence_b.id,
                        )
                    )
                )

                if pair in existing_pairs:
                    continue

                conflict = EvidenceConflict(
                    conflict_id=(
                        f"CONFLICT-{case.case_id}-"
                        f"{evidence_a.id}-{evidence_b.id}"
                    ),
                    case_id=case.case_id,
                    evidence_a=evidence_a.id,
                    evidence_b=evidence_b.id,
                )

                conflicts.append(conflict)
                existing_pairs.add(pair)

        case.conflicts = conflicts

        return conflicts

    # ------------------------------------------------------------------
    # Conflict resolution
    # ------------------------------------------------------------------

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
            raise ValueError(
                f"Conflict '{conflict_id}' not found."
            )

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
        conflict.resolved_at = datetime.now(
            timezone.utc
        ).isoformat()

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

    # ------------------------------------------------------------------
    # Evidence intake
    # ------------------------------------------------------------------

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
            output={
                "request_status": request.status,
            },
        )

        case.status = CaseStatus.INVESTIGATING

        authenticated_evidence = [
            e
            for e in case.evidence
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
                strength=min(
                    1.0,
                    transaction.get("risk_score", 0) / 100,
                ),
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

        case.evidence.extend(authenticated_evidence)

        raw_patterns = self.graph.detect_patterns(transaction_id).get(
            "patterns",
            [],
        )

        raw_patterns = apply_precedence(
            raw_patterns,
            graph_signals,
        )

        case.patterns = [
            PatternFinding(**pattern)
            for pattern in raw_patterns
        ]

        risk_score = int(transaction.get("risk_score", 0))

        supporting_count = sum(
            1
            for e in case.evidence
            if e.polarity == "supporting"
        )

        contradicting_count = sum(
            1
            for e in case.evidence
            if e.polarity == "contradicting"
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

        confidence = min(confidence, 0.99)

        case.risk_assessment = RiskAssessment(
            risk_level=self._risk_level(risk_score),
            risk_score=risk_score,
            confidence=confidence,
            uncertainty=[
                "Network risk remains elevated despite customer authentication."
            ]
            if authenticated_evidence
            else ["No material unresolved uncertainty identified."],
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
            },
            risk_after=risk_score,
            confidence_after=confidence,
        )

        case.iterations += 1
        self.memory.save(case)

        return case

    # ------------------------------------------------------------------
    # Approval
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------

    def execute_action(
        self,
        case: Case,
        action_input: ActionInput,
    ) -> Case:

        if not case.recommended_actions:
            raise ValueError(
                "No recommended action is available."
            )

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
                raise ValueError(
                    "Required approval has not been granted."
                )

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