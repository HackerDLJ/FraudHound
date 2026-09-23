from __future__ import annotations
import os, httpx

class TigerGraphAdapter:
    """Thin REST adapter. GSQL lives in schema.gsql/queries.gsql; MCP can expose the same logical tools."""
    def __init__(self):
        self.base=os.getenv('TIGERGRAPH_URL','').rstrip('/')
        self.graph=os.getenv('TIGERGRAPH_GRAPH','HHGOA_IEEE')
        self.token=os.getenv('TIGERGRAPH_TOKEN','')
        if not self.base: raise RuntimeError('TIGERGRAPH_URL is required for TigerGraph backend')
    def _get(self,path):
        headers={'Authorization':f'Bearer {self.token}'} if self.token else {}
        r=httpx.get(f'{self.base}{path}',headers=headers,timeout=20); r.raise_for_status(); return r.json()
    def _query(self,name,params):
        qs='&'.join(f'{k}={v}' for k,v in params.items())
        return self._get(f'/gsqlserver/gsql/query/{name}?{qs}')
    def get_transaction(self, transaction_id): return self._query('getTransaction',{'transaction_id':transaction_id})
    def get_customer(self, customer_id): return self._query('getCustomer',{'customer_id':customer_id})
    def get_account(self, account_id): return self._query('getAccount',{'account_id':account_id})
    def get_transaction_history(self, account_id): return self._query('getTransactionHistory',{'account_id':account_id})
    def get_graph_neighborhood(self, entity_id, depth=2): return self._query('getNeighborhood',{'entity_id':entity_id,'depth':depth})
    def detect_patterns(self, transaction_id): return self._query('detectPatterns',{'transaction_id':transaction_id})
    def similar_entities(self, entity_id): return self._query('similarEntities',{'entity_id':entity_id})
