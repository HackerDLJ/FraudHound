from __future__ import annotations
class ToolRegistry:
    """Only registered, typed application tools can be exposed to an LLM/MCP layer."""
    def __init__(self, graph):
        self.graph=graph
        self.tools={
            'get_transaction':graph.get_transaction,
            'get_customer':graph.get_customer,
            'get_account':graph.get_account,
            'get_transaction_history':graph.get_transaction_history,
            'get_graph_neighborhood':graph.get_graph_neighborhood,
            'detect_fraud_patterns':graph.detect_patterns,
            'find_similar_entities':graph.similar_entities,
        }
    def call(self,name,**kwargs):
        if name not in self.tools: raise PermissionError(f'Unregistered tool: {name}')
        return self.tools[name](**kwargs)
