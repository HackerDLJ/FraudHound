from __future__ import annotations
import uuid
from backend.models.schemas import *
from backend.policy.policy_engine import check_action
from backend.agent.pattern_precedence import apply_precedence

class FraudHoundController:
    def __init__(self, graph, memory): self.graph=graph; self.memory=memory
    def _event(self, case,event,**kw):
        ev=AuditEvent(event=event,**kw); case.timeline.append(ev); self.memory.audit(case.case_id,event,ev.model_dump()); return ev
    def create_case(self, req):
        txid=req.transaction_id or req.trigger.get('transaction_id') or 'TX-DEMO-001'
        case=Case(case_id='HHG-'+uuid.uuid4().hex[:8].upper(),trigger={**req.trigger,'transaction_id':txid,'scenario':req.scenario})
        case.status=CaseStatus.INVESTIGATING; self._event(case,'Investigation triggered'); self._event(case,'Case created'); return case
    def investigate(self, case, max_iterations=3):
        for _ in range(max_iterations):
            case.iterations += 1
            txid=case.trigger['transaction_id']; tx=self.graph.get_transaction(txid)
            self._event(case,'Transaction retrieved',tool='get_transaction',output=tx)
            case.transactions=[tx]
            account=self.graph.get_account(tx['account_id']); customer=self.graph.get_customer(tx['customer_id'])
            case.entities=[{'id':customer['customer_id'],'type':'Customer'},{'id':account['account_id'],'type':'Account'},{'id':tx['device_id'],'type':'Device'},{'id':tx['ip_id'],'type':'IPAddress'},{'id':tx['merchant_id'],'type':'Merchant'}]
            hist=self.graph.get_transaction_history(tx['account_id']); neigh=self.graph.get_graph_neighborhood(tx['account_id'],2)
            self._event(case,'Graph neighborhood analyzed',tool='get_graph_neighborhood',output=neigh)
            evidence=[]
            def add(kind,statement,source,pol='supporting',strength=.7,meta=None):
                evidence.append(Evidence(id='E-'+uuid.uuid4().hex[:6],kind=kind,statement=statement,source=source,polarity=pol,strength=strength,metadata=meta or {}))
            add('transaction',f"Transaction amount is ${tx['amount']:,.2f} with source risk score {tx['risk_score']}.",'transaction')
            if tx['new_device']: add('device','Device is newly associated with the account.','graph',strength=.8)
            if tx['shared_device_accounts']>1: add('graph',f"Device connects {tx['shared_device_accounts']} accounts.",'graph',strength=.9)
            if tx['shared_ip_accounts']>1: add('graph',f"IP address connects {tx['shared_ip_accounts']} accounts.",'graph',strength=.75)
            if tx['prior_fraud_connected']: add('history','A connected account intersects a confirmed historical fraud case.','graph',strength=.95)
            if tx['location_mismatch']: add('behavior','Observed location is inconsistent with recent account activity.','transaction',strength=.65)
            if tx['customer_confirmed']: add('customer','Customer has confirmed control/authorization.','customer_validation','contradicting',.95)
            case.evidence.extend(evidence)
            raw_patterns=self.graph.detect_patterns(txid)['patterns']
            raw_patterns=apply_precedence(raw_patterns, neigh.get('signals', {}))
            case.patterns=[PatternFinding(**p) for p in raw_patterns]
            self._event(case,'Patterns assessed',tool='detect_fraud_patterns',output=raw_patterns)
            score=min(99, round(tx['risk_score']*0.55 + min(tx['shared_device_accounts']*8,24) + (15 if tx['prior_fraud_connected'] else 0) + (6 if tx['location_mismatch'] else 0)))
            contradictions=sum(e.strength for e in case.evidence if e.polarity=='contradicting')
            support=sum(e.strength for e in case.evidence if e.polarity=='supporting')
            confidence=max(.35,min(.97,0.45 + .07*len(case.patterns) + .03*min(support,8) - .10*contradictions))
            if tx['customer_confirmed']: confidence=max(confidence,.84); score=max(25,score-35)
            uncertainty=[]
            if not tx['customer_confirmed']: uncertainty.append('Customer ownership/control of the observed device is not verified.')
            if tx['shared_device_accounts']>=2 and not tx['prior_fraud_connected']: uncertainty.append('Shared-device linkage is suspicious but does not by itself establish account takeover.')
            level='CRITICAL' if score>=90 else 'HIGH' if score>=75 else 'MEDIUM' if score>=45 else 'LOW'
            assessment=RiskAssessment(risk_level=level,risk_score=score,confidence=round(confidence,2),uncertainty=uncertainty,rationale='Risk combines transaction risk, graph connectivity, behavioral signals, historical links, and contradictory evidence.')
            prev=case.risk_assessment; case.risk_assessment=assessment; case.uncertainties=uncertainty
            self._event(case,'Risk reassessed',risk_before=prev.risk_score if prev else None,risk_after=score,confidence_before=prev.confidence if prev else None,confidence_after=confidence)
            case.similar_cases=self.memory.similar(case)
            if uncertainty and confidence < .78 and not any(r.status=='REQUESTED' for r in case.evidence_requests):
                req=EvidenceRequest(request_id='REQ-'+uuid.uuid4().hex[:6],type='request_step_up_auth',reason='High risk remains coupled with material uncertainty about account-owner control.',question='Can the customer successfully complete step-up authentication for this transaction?',expected_information='Proof that the legitimate account owner controls the session/device.',how_it_reduces_uncertainty='A successful challenge materially increases confidence in customer authorization.')
                case.evidence_requests.append(req); case.status=CaseStatus.AWAITING_EVIDENCE
                self._event(case,'Additional evidence requested',output=req.model_dump()); self.memory.save(case); return case
            action=self._next_action(case)
            case.recommended_actions=[action]; case.decisions.append(action); case.status=CaseStatus.PENDING_APPROVAL if action.required_approval else CaseStatus.ACTION_RECOMMENDED
            case.policy_references=[action.policy_reference] if action.policy_reference else []
            case.explanation=self._explain(case,action)
            self._event(case,'Next-best action selected',output=action.model_dump())
            self.memory.save(case); return case
        self.memory.save(case); return case
    def _next_action(self,case):
        a=case.risk_assessment
        if a.risk_level in ('CRITICAL','HIGH') and a.confidence>=.78: name='BLOCK_TRANSACTION'
        elif a.risk_level in ('HIGH','MEDIUM'): name='MONITOR_TRANSACTION'
        else: name='ALLOW_TRANSACTION'
        meta=check_action(name)
        return ActionRecommendation(action=name,reason='Selected from current evidence, risk, confidence, and policy permissions.',supporting_evidence=[e.id for e in case.evidence if e.polarity=='supporting'][-6:],risk=a.risk_level,confidence=a.confidence,required_approval=meta['approval'],approval_route=meta['route'],policy_reference=meta['policy'],reversible=meta['reversible'])
    def _explain(self,case,action):
        sup='; '.join(e.statement for e in case.evidence if e.polarity=='supporting')
        unc='; '.join(case.uncertainties) if case.uncertainties else 'No material uncertainty remains.'
        return f"Evidence used: {sup}. Remaining uncertainty: {unc}. Final decision: {action.action}. Policy: {action.policy_reference}."
    def receive_evidence(self,case,result):
        req=next((r for r in case.evidence_requests if r.request_id==result.request_id),None)
        if not req: raise ValueError('Unknown evidence request')
        req.status='RECEIVED'; data=result.result
        if data.get('customer_authenticated') is True:
            case.transactions[0]['customer_confirmed']=True
            self.graph.current['customer_confirmed']=True if hasattr(self.graph,'current') else True
            case.evidence.append(Evidence(id='E-'+uuid.uuid4().hex[:6],kind='customer_validation',statement='Customer successfully completed step-up authentication.',source='simulated_evidence',polarity='contradicting',strength=.95))
        case.status=CaseStatus.INVESTIGATING; self._event(case,'Evidence received',output=data); return self.investigate(case)
    def approve(self,case,approved,approver,note=''):
        case.approval_history.append({'timestamp':now_iso(),'approver':approver,'approved':approved,'note':note})
        if not approved: case.status=CaseStatus.ESCALATED; case.outcome='Action denied by approver'; self._event(case,'Approval denied'); self.memory.save(case); return case
        case.status=CaseStatus.ACTION_EXECUTED; action=case.recommended_actions[-1].action; case.executed_actions.append({'action':action,'timestamp':now_iso(),'mode':'SIMULATED','approver':approver}); case.outcome=action; self._event(case,'Approved action simulated',output={'action':action,'approver':approver}); self.memory.save(case); return case
    def execute(self,case,action):
        if not case.recommended_actions or case.recommended_actions[-1].action!=action: raise ValueError('Action is not the current recommendation')
        meta=check_action(action)
        if meta['approval']: raise ValueError('Approval required before execution')
        case.status=CaseStatus.ACTION_EXECUTED; case.executed_actions.append({'action':action,'timestamp':now_iso(),'mode':'SIMULATED'}); case.outcome=action; self._event(case,'Action simulated',output={'action':action}); self.memory.save(case); return case
