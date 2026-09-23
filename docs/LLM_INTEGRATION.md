# LLM integration boundary

FraudHound is deliberately split into deterministic investigation tools and an LLM reasoning layer.

The deterministic layer owns:
- graph retrieval
- graph algorithms/signals
- pattern detection
- policy permissions
- action execution
- audit logging

An LLM may be connected to `backend/agent/reasoning.py` to:
- select the next registered tool
- synthesize retrieved evidence
- identify uncertainty
- explain the recommendation

The LLM receives a compact GraphRAG context, never raw hidden benchmark labels and never arbitrary API access. The tool registry in `backend/tools/registry.py` is the permission boundary.
