from __future__ import annotations
import json, sqlite3
from pathlib import Path
from typing import Any

class CaseMemory:
    def __init__(self,path='data/fraudhound.db'):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self._init()
    def _conn(self): return sqlite3.connect(self.path)
    def _init(self):
        with self._conn() as c:
            c.execute('CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, data TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS audit (case_id TEXT, ts TEXT, event TEXT, data TEXT)')
    def save(self, case):
        with self._conn() as c: c.execute('INSERT OR REPLACE INTO cases(case_id,data) VALUES(?,?)',(case.case_id,case.model_dump_json()))
    def get(self, case_id):
        with self._conn() as c:
            r=c.execute('SELECT data FROM cases WHERE case_id=?',(case_id,)).fetchone()
        return json.loads(r[0]) if r else None
    def list(self):
        with self._conn() as c: rows=c.execute('SELECT data FROM cases ORDER BY rowid DESC').fetchall()
        return [json.loads(x[0]) for x in rows]
    def audit(self, case_id, event, data):
        with self._conn() as c: c.execute('INSERT INTO audit VALUES(?,?,?,?)',(case_id,data.get('timestamp',''),event,json.dumps(data,default=str)))
    def similar(self, case, limit=5):
        out=[]
        for x in self.list():
            if x['case_id']==case.case_id: continue
            score=0; reasons=[]
            if x.get('risk_assessment',{}).get('risk_level')==getattr(case.risk_assessment,'risk_level',None): score+=0.1
            xp={p['pattern'] for p in x.get('patterns',[])}; cp={p.pattern for p in case.patterns}; shared=xp&cp
            if shared: score+=0.35*min(1,len(shared)/2); reasons.append('shared fraud pattern')
            xe={e.get('id') for e in x.get('entities',[])}; ce={e.get('id') for e in case.entities}
            if xe&ce: score+=0.3; reasons.append('shared entity')
            if x.get('trigger',{}).get('scenario')==case.trigger.get('scenario'): score+=0.15; reasons.append('same demo scenario')
            if score>0: out.append({'case_id':x['case_id'],'similarity':round(min(score,1),2),'reason':', '.join(reasons) or 'similar risk profile','outcome':x.get('outcome')})
        return sorted(out,key=lambda z:z['similarity'],reverse=True)[:limit]
