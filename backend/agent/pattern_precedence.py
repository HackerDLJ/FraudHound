from __future__ import annotations

def apply_precedence(patterns: list[dict], graph_signals: dict) -> list[dict]:
    """Prevents an overly broad ATO label from swallowing stronger network evidence.

    This is intentionally evidence-based. It does not create a pattern without graph signals.
    """
    if graph_signals.get('shared_device_accounts',0) >= 2 and graph_signals.get('prior_fraud_connected'):
        patterns=[p for p in patterns if p.get('pattern') != 'Account Takeover']
        patterns.append({
            'pattern':'Coordinated / Undocumented Network Abuse',
            'confidence':0.90,
            'supporting_evidence':['shared device across multiple accounts','connected historical fraud'],
            'contradicting_evidence':[],
            'graph_signals':['multi-account device linkage','historical fraud in connected neighborhood'],
            'explanation':'Network evidence indicates coordinated abuse; a single-account takeover interpretation is not sufficient.'
        })
    return patterns
