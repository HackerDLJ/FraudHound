# TigerGraph MCP integration

Connect TigerGraph MCP to the same logical investigation tools used by `ToolRegistry`.

Recommended MCP tool names:
- get_transaction
- get_customer
- get_account
- get_transaction_history
- get_graph_neighborhood
- detect_fraud_patterns
- find_similar_entities

The application should treat MCP responses as structured evidence with provenance. Do not expose a generic SQL/GSQL execution tool to the LLM.
