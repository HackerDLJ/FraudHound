from __future__ import annotations
from typing import Any

SCENARIOS = {
    'high_confidence': {
        'transaction_id':'TX-DEMO-001','customer_id':'CUST-001','account_id':'ACC-001','device_id':'DEV-900','ip_id':'IP-001','merchant_id':'M-001',
        'amount':1842.19,'risk_score':96,'new_device':True,'shared_device_accounts':4,'shared_ip_accounts':3,'prior_fraud_connected':True,'velocity_24h':8,
        'location_mismatch':True,'customer_confirmed':False,
    },
    'ambiguous': {
        'transaction_id':'TX-DEMO-002','customer_id':'CUST-002','account_id':'ACC-002','device_id':'DEV-901','ip_id':'IP-002','merchant_id':'M-002',
        'amount':439.61,'risk_score':91,'new_device':True,'shared_device_accounts':2,'shared_ip_accounts':1,'prior_fraud_connected':False,'velocity_24h':3,
        'location_mismatch':True,'customer_confirmed':False,
    },
    'legitimate': {
        'transaction_id':'TX-DEMO-003','customer_id':'CUST-003','account_id':'ACC-003','device_id':'DEV-902','ip_id':'IP-003','merchant_id':'M-003',
        'amount':79.20,'risk_score':72,'new_device':True,'shared_device_accounts':1,'shared_ip_accounts':1,'prior_fraud_connected':False,'velocity_24h':1,
        'location_mismatch':False,'customer_confirmed':True,
    }
}

class MockGraphAdapter:
    def __init__(self): self.current = SCENARIOS['high_confidence']
    def select_scenario(self, name: str):
        if name not in SCENARIOS: raise ValueError(f'Unknown scenario: {name}')
        self.current = dict(SCENARIOS[name])
        return self.current
    def get_transaction(self, transaction_id: str):
        x=dict(self.current); x['transaction_id']=transaction_id; return x
    def get_customer(self, customer_id: str): return {'customer_id':customer_id,'name':'Demo Customer','tenure_days':742,'status':'ACTIVE'}
    def get_account(self, account_id: str): return {'account_id':account_id,'customer_id':self.current['customer_id'],'status':'ACTIVE'}
    def get_transaction_history(self, account_id: str):
        return [{'transaction_id':f'H-{i}','account_id':account_id,'amount':(i+1)*61.4,'merchant_id':self.current['merchant_id'],'device_id':self.current['device_id'] if i==0 else f'DEV-H{i}'} for i in range(5)]
    def get_graph_neighborhood(self, entity_id: str, depth: int=2):
        x=self.current
        nodes=[
            {'id':x['customer_id'],'type':'Customer','label':'Customer'}, {'id':x['account_id'],'type':'Account','label':'Account'},
            {'id':x['transaction_id'],'type':'Transaction','label':'Transaction'}, {'id':x['device_id'],'type':'Device','label':'Device'},
            {'id':x['ip_id'],'type':'IPAddress','label':'IP'}, {'id':x['merchant_id'],'type':'Merchant','label':'Merchant'}]
        edges=[
            {'source':x['customer_id'],'target':x['account_id'],'type':'OWNS'}, {'source':x['account_id'],'target':x['transaction_id'],'type':'PERFORMED'},
            {'source':x['transaction_id'],'target':x['device_id'],'type':'USED'}, {'source':x['transaction_id'],'target':x['ip_id'],'type':'FROM_IP'},
            {'source':x['transaction_id'],'target':x['merchant_id'],'type':'TO'}]
        for i in range(x['shared_device_accounts']-1):
            aid=f'ACC-SHARED-{i+1}'; nodes.append({'id':aid,'type':'Account','label':f'Shared account {i+1}'})
            edges.append({'source':x['device_id'],'target':aid,'type':'ASSOCIATED_WITH'})
        if x['prior_fraud_connected']:
            nodes.append({'id':'CASE-HIST-01','type':'FraudCase','label':'Confirmed historical fraud'}); edges.append({'source':f'ACC-SHARED-1','target':'CASE-HIST-01','type':'INVOLVED_IN'})
        return {'nodes':nodes,'edges':edges,'signals':{'shared_device_accounts':x['shared_device_accounts'],'shared_ip_accounts':x['shared_ip_accounts'],'prior_fraud_connected':x['prior_fraud_connected']}}
    def detect_patterns(self, transaction_id: str):
        x=self.current; p=[]
        if x['new_device'] and x['shared_device_accounts']>=2:
            p.append({'pattern':'Shared / New Device Abuse','confidence':0.91,'supporting_evidence':['device is newly associated','device links multiple accounts'],'contradicting_evidence':[],'graph_signals':[f"device connects {x['shared_device_accounts']} accounts"],'explanation':'A newly observed device is reused across multiple accounts.'})
        if x['prior_fraud_connected']:
            p.append({'pattern':'Connected Historical Fraud','confidence':0.94,'supporting_evidence':['connected account has confirmed historical fraud'],'contradicting_evidence':[],'graph_signals':['historical fraud case in neighborhood'],'explanation':'The transaction network intersects a previously confirmed fraud case.'})
        if x['velocity_24h']>=5:
            p.append({'pattern':'Transaction Burst','confidence':0.82,'supporting_evidence':['elevated transaction velocity'],'contradicting_evidence':[],'graph_signals':[f"{x['velocity_24h']} transactions in 24h"],'explanation':'Transaction velocity is elevated for the account.'})
        if x['location_mismatch']:
            p.append({'pattern':'Out-of-Region Activity','confidence':0.73,'supporting_evidence':['location mismatch'],'contradicting_evidence':[],'graph_signals':['geographic mismatch'],'explanation':'Observed activity is inconsistent with recent account geography.'})
        return {'patterns':p}
    def similar_entities(self, entity_id: str): return [{'entity_id':'ACC-HIST-01','similarity':0.81,'reason':'shared device and transaction behavior'}]
