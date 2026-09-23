from __future__ import annotations
from typing import Any

def build_evidence_context(case: dict[str,Any]) -> dict[str,Any]:
    return {
        'trigger':case.get('trigger'),
        'transactions':case.get('transactions',[])[:10],
        'evidence':case.get('evidence',[])[-30:],
        'patterns':case.get('patterns',[]),
        'risk_assessment':case.get('risk_assessment'),
        'uncertainties':case.get('uncertainties',[]),
        'similar_cases':case.get('similar_cases',[])[:5],
        'policy_references':case.get('policy_references',[]),
    }
