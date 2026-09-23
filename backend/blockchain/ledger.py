from __future__ import annotations
import hashlib, json, sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class AuditLedger:
    """Append-only hash-chained audit ledger.

    This is the local/POC adapter. It intentionally stores hashes and event metadata,
    not raw customer/transaction payloads. A production adapter can implement the
    same interface over a permissioned network such as Hyperledger Fabric.
    """
    def __init__(self, path: str = 'data/fraudhound.db'):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self._conn() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS blockchain_events (
                block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata TEXT NOT NULL
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_bc_case ON blockchain_events(case_id)')

    @staticmethod
    def hash_payload(payload: Any) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode()
        return hashlib.sha256(raw).hexdigest()

    def append(self, case_id: str, event_type: str, payload: Any, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        payload_hash = self.hash_payload(payload)
        with self._conn() as c:
            prev = c.execute(
                '''
                SELECT block_hash
                FROM blockchain_events
                WHERE case_id = ?
                ORDER BY block_index DESC
                LIMIT 1
                ''',
                (case_id,),
            ).fetchone()
            previous_hash = prev[0] if prev else 'GENESIS'
            timestamp = now_iso()
            material = f'{case_id}|{event_type}|{payload_hash}|{previous_hash}|{timestamp}'.encode()
            block_hash = hashlib.sha256(material).hexdigest()
            cur = c.execute('''INSERT INTO blockchain_events
                (case_id,event_type,payload_hash,previous_hash,block_hash,timestamp,metadata)
                VALUES(?,?,?,?,?,?,?)''', (case_id,event_type,payload_hash,previous_hash,block_hash,timestamp,json.dumps(metadata or {}, sort_keys=True)))
            idx = cur.lastrowid
        return {'block_index': idx, 'case_id': case_id, 'event_type': event_type,
                'payload_hash': payload_hash, 'previous_hash': previous_hash,
                'block_hash': block_hash, 'timestamp': timestamp, 'metadata': metadata or {}}

    def list(self, case_id: str | None = None, limit: int = 100):
        with self._conn() as c:
            if case_id:
                rows = c.execute(
                    'SELECT * FROM blockchain_events WHERE case_id=? ORDER BY block_index',
                    (case_id,)
                ).fetchall()
            else:
                rows = c.execute('SELECT * FROM blockchain_events ORDER BY block_index DESC LIMIT ?', (limit,)).fetchall()
        cols = ['block_index','case_id','event_type','payload_hash','previous_hash','block_hash','timestamp','metadata']
        out=[]
        for row in rows:
            x=dict(zip(cols,row)); x['metadata']=json.loads(x['metadata']); out.append(x)
        return out

    def verify(self, case_id: str) -> dict[str, Any]:
        events=self.list(case_id)
        expected_prev='GENESIS'; errors=[]
        for e in events:
            material=f"{e['case_id']}|{e['event_type']}|{e['payload_hash']}|{e['previous_hash']}|{e['timestamp']}".encode()
            expected=hashlib.sha256(material).hexdigest()
            if e['previous_hash'] != expected_prev: errors.append({'block_index':e['block_index'],'error':'previous_hash_mismatch'})
            if e['block_hash'] != expected: errors.append({'block_index':e['block_index'],'error':'block_hash_mismatch'})
            expected_prev=e['block_hash']
        return {'case_id':case_id,'verified':not errors,'events':len(events),'errors':errors,'tip':events[-1]['block_hash'] if events else None}
