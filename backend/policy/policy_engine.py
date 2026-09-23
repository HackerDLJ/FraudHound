from __future__ import annotations
ACTION_PERMISSIONS = {
 'ALLOW_TRANSACTION': {'approval':False,'route':None,'policy':'POLICY-TXN-01','reversible':True},
 'MONITOR_TRANSACTION': {'approval':False,'route':None,'policy':'POLICY-MON-01','reversible':True},
 'MONITOR_ACCOUNT': {'approval':False,'route':None,'policy':'POLICY-MON-02','reversible':True},
 'WARN_CUSTOMER': {'approval':False,'route':None,'policy':'POLICY-CUST-02','reversible':True},
 'BLOCK_TRANSACTION': {'approval':True,'route':'FRAUD_ANALYST','policy':'POLICY-TXN-07','reversible':True},
 'BLOCK_CARD': {'approval':True,'route':'FRAUD_ANALYST','policy':'POLICY-CARD-03','reversible':True},
 'FREEZE_ACCOUNT': {'approval':True,'route':'FRAUD_ANALYST','policy':'POLICY-ATO-04','reversible':True},
 'CREATE_FRAUD_CASE': {'approval':False,'route':None,'policy':'POLICY-CASE-01','reversible':True},
 'REQUEST_MORE_EVIDENCE': {'approval':False,'route':None,'policy':'POLICY-EVID-01','reversible':True},
 'REQUEST_STEP_UP_AUTH': {'approval':False,'route':None,'policy':'POLICY-EVID-02','reversible':True},
 'ESCALATE_TO_ANALYST': {'approval':False,'route':None,'policy':'POLICY-ESC-01','reversible':True},
 'FILE_SAR': {'approval':True,'route':'COMPLIANCE_OFFICER','policy':'POLICY-SAR-01','reversible':False},
 'CLOSE_CASE': {'approval':False,'route':None,'policy':'POLICY-CASE-09','reversible':True},
}

def check_action(action: str) -> dict:
    if action not in ACTION_PERMISSIONS: return {'allowed':False,'reason':'Action not registered'}
    return {'allowed':True, **ACTION_PERMISSIONS[action]}
