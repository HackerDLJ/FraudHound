from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any


class CaseMemory:
    def __init__(self, path: str | Path | None = None):
        if path is None:
            if os.getenv("VERCEL") == "1" or os.getenv("VERCEL_ENV"):
                path = "/tmp/fraudhound.db"
            else:
                path = "data/fraudhound.db"

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    case_id TEXT,
                    ts TEXT,
                    event TEXT,
                    data TEXT
                )
                """
            )

    def save(self, case):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO cases(case_id, data) VALUES(?, ?)",
                (
                    case.case_id,
                    case.model_dump_json(),
                ),
            )

    def get(self, case_id):
        with self._conn() as c:
            row = c.execute(
                "SELECT data FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()

        return json.loads(row[0]) if row else None

    def list(self):
        with self._conn() as c:
            rows = c.execute(
                "SELECT data FROM cases ORDER BY rowid DESC"
            ).fetchall()

        return [json.loads(row[0]) for row in rows]

    def audit(self, case_id, event, data):
        with self._conn() as c:
            c.execute(
                "INSERT INTO audit VALUES(?, ?, ?, ?)",
                (
                    case_id,
                    data.get("timestamp", ""),
                    event,
                    json.dumps(data, default=str),
                ),
            )

    def similar(self, case, limit=5):
        out = []

        for existing_case in self.list():
            if existing_case["case_id"] == case.case_id:
                continue

            score = 0
            reasons = []

            if (
                existing_case.get("risk_assessment", {}).get("risk_level")
                == getattr(case.risk_assessment, "risk_level", None)
            ):
                score += 0.1

            existing_patterns = {
                pattern["pattern"]
                for pattern in existing_case.get("patterns", [])
            }

            current_patterns = {
                pattern.pattern
                for pattern in case.patterns
            }

            shared_patterns = existing_patterns & current_patterns

            if shared_patterns:
                score += 0.35 * min(
                    1,
                    len(shared_patterns) / 2,
                )
                reasons.append("shared fraud pattern")

            existing_entities = {
                entity.get("id")
                for entity in existing_case.get("entities", [])
            }

            current_entities = {
                entity.get("id")
                for entity in case.entities
            }

            if existing_entities & current_entities:
                score += 0.3
                reasons.append("shared entity")

            if (
                existing_case.get("trigger", {}).get("scenario")
                == case.trigger.get("scenario")
            ):
                score += 0.15
                reasons.append("same demo scenario")

            if score > 0:
                out.append(
                    {
                        "case_id": existing_case["case_id"],
                        "similarity": round(min(score, 1), 2),
                        "reason": ", ".join(reasons)
                        or "similar risk profile",
                        "outcome": existing_case.get("outcome"),
                    }
                )

        return sorted(
            out,
            key=lambda item: item["similarity"],
            reverse=True,
        )[:limit]        return sorted(out,key=lambda z:z['similarity'],reverse=True)[:limit]
