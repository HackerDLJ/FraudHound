from __future__ import annotations
from typing import Any

def build_graphrag_context(graph_evidence: dict[str,Any], policy_chunks: list[dict[str,Any]], cases: list[dict[str,Any]], max_chars: int=12000) -> str:
    """Small, provenance-preserving context window for an LLM.

    The caller supplies only retrieved/filtered items. The entire graph or policy corpus is never passed through.
    """
    chunks=['GRAPH EVIDENCE:',str(graph_evidence),'POLICY EVIDENCE:',str(policy_chunks[:8]),'HISTORICAL CASE CONTEXT:',str(cases[:5])]
    text='\n'.join(chunks)
    return text[:max_chars]
