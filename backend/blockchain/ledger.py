from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENESIS_HASH = "GENESIS"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLedger:
    """Append-only hash-chained audit ledger.

    This is the local/POC adapter. It intentionally stores hashes and event
    metadata, not raw customer/transaction payloads.

    A production adapter can implement the same interface over a permissioned
    network such as Hyperledger Fabric.
    """

    def __init__(self, path: str = "data/fraudhound.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blockchain_events (
                    block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_bc_case
                ON blockchain_events(case_id)
                """
            )

    @staticmethod
    def hash_payload(payload: Any) -> str:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()

        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _block_material(
        case_id: str,
        event_type: str,
        payload_hash: str,
        previous_hash: str,
        timestamp: str,
    ) -> bytes:
        return (
            f"{case_id}|"
            f"{event_type}|"
            f"{payload_hash}|"
            f"{previous_hash}|"
            f"{timestamp}"
        ).encode()

    @classmethod
    def _calculate_block_hash(
        cls,
        case_id: str,
        event_type: str,
        payload_hash: str,
        previous_hash: str,
        timestamp: str,
    ) -> str:
        material = cls._block_material(
            case_id,
            event_type,
            payload_hash,
            previous_hash,
            timestamp,
        )

        return hashlib.sha256(material).hexdigest()

    def append(
        self,
        case_id: str,
        event_type: str,
        payload: Any,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload_hash = self.hash_payload(payload)

        with self._conn() as conn:
            previous = conn.execute(
                """
                SELECT block_hash
                FROM blockchain_events
                WHERE case_id = ?
                ORDER BY block_index DESC
                LIMIT 1
                """,
                (case_id,),
            ).fetchone()

            previous_hash = (
                previous[0]
                if previous
                else GENESIS_HASH
            )

            timestamp = now_iso()

            block_hash = self._calculate_block_hash(
                case_id=case_id,
                event_type=event_type,
                payload_hash=payload_hash,
                previous_hash=previous_hash,
                timestamp=timestamp,
            )

            cursor = conn.execute(
                """
                INSERT INTO blockchain_events
                (
                    case_id,
                    event_type,
                    payload_hash,
                    previous_hash,
                    block_hash,
                    timestamp,
                    metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    event_type,
                    payload_hash,
                    previous_hash,
                    block_hash,
                    timestamp,
                    json.dumps(
                        metadata or {},
                        sort_keys=True,
                    ),
                ),
            )

            block_index = cursor.lastrowid

        return {
            "block_index": block_index,
            "case_id": case_id,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
            "block_hash": block_hash,
            "timestamp": timestamp,
            "metadata": metadata or {},
        }

    def list(
        self,
        case_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._conn() as conn:
            if case_id:
                rows = conn.execute(
                    """
                    SELECT *
                    FROM blockchain_events
                    WHERE case_id = ?
                    ORDER BY block_index
                    """,
                    (case_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT *
                    FROM blockchain_events
                    ORDER BY block_index DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()

        columns = [
            "block_index",
            "case_id",
            "event_type",
            "payload_hash",
            "previous_hash",
            "block_hash",
            "timestamp",
            "metadata",
        ]

        events = []

        for row in rows:
            event = dict(zip(columns, row))

            try:
                event["metadata"] = json.loads(
                    event["metadata"]
                )
            except (TypeError, json.JSONDecodeError):
                event["metadata"] = {}

            events.append(event)

        return events

    def verify(self, case_id: str) -> dict[str, Any]:
        """Verify the complete hash chain for one case.

        The original verification contract is preserved:
            verified
            events
            errors
            tip

        Additional fields provide structured integrity information for
        the analyst UI.
        """

        events = self.list(case_id)

        errors: list[dict[str, Any]] = []

        expected_previous_hash = GENESIS_HASH

        genesis_valid = True
        hash_links_valid = True
        block_hashes_valid = True

        for position, event in enumerate(events):
            block_index = event["block_index"]

            if position == 0:
                if event["previous_hash"] != GENESIS_HASH:
                    genesis_valid = False
                    hash_links_valid = False

                    errors.append(
                        {
                            "block_index": block_index,
                            "error": "genesis_mismatch",
                            "expected": GENESIS_HASH,
                            "actual": event["previous_hash"],
                        }
                    )

            elif event["previous_hash"] != expected_previous_hash:
                hash_links_valid = False

                errors.append(
                    {
                        "block_index": block_index,
                        "error": "previous_hash_mismatch",
                        "expected": expected_previous_hash,
                        "actual": event["previous_hash"],
                    }
                )

            expected_block_hash = self._calculate_block_hash(
                case_id=event["case_id"],
                event_type=event["event_type"],
                payload_hash=event["payload_hash"],
                previous_hash=event["previous_hash"],
                timestamp=event["timestamp"],
            )

            if event["block_hash"] != expected_block_hash:
                block_hashes_valid = False

                errors.append(
                    {
                        "block_index": block_index,
                        "error": "block_hash_mismatch",
                        "expected": expected_block_hash,
                        "actual": event["block_hash"],
                    }
                )

            expected_previous_hash = event["block_hash"]

        verified = not errors

        return {
            "case_id": case_id,
            "verified": verified,
            "events": len(events),
            "errors": errors,
            "tip": (
                events[-1]["block_hash"]
                if events
                else None
            ),
            "genesis_valid": genesis_valid,
            "hash_links_valid": hash_links_valid,
            "block_hashes_valid": block_hashes_valid,
        }

    def chain_status(self, case_id: str) -> dict[str, Any]:
        """Return UI-friendly chain status and block information."""

        events = self.list(case_id)
        verification = self.verify(case_id)

        blocks = []

        for event in events:
            block_errors = [
                error
                for error in verification["errors"]
                if error.get("block_index")
                == event["block_index"]
            ]

            blocks.append(
                {
                    "block_index": event["block_index"],
                    "event_type": event["event_type"],
                    "timestamp": event["timestamp"],
                    "payload_hash": event["payload_hash"],
                    "previous_hash": event["previous_hash"],
                    "block_hash": event["block_hash"],
                    "metadata": event["metadata"],
                    "integrity": (
                        "VALID"
                        if not block_errors
                        else "INVALID"
                    ),
                    "errors": block_errors,
                }
            )

        return {
            "case_id": case_id,
            "status": (
                "VALID"
                if verification["verified"]
                else "COMPROMISED"
            ),
            "verified": verification["verified"],
            "events": verification["events"],
            "genesis_valid": verification["genesis_valid"],
            "hash_links_valid": verification["hash_links_valid"],
            "block_hashes_valid": verification["block_hashes_valid"],
            "tip": verification["tip"],
            "errors": verification["errors"],
            "blocks": blocks,
        }