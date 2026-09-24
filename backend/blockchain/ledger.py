from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENESIS_HASH = "GENESIS"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLedger:
    """Append-only hash-chained audit ledger with Merkle batching.

    This is the local/POC adapter. It intentionally stores hashes and event
    metadata, not raw customer/transaction payloads.

    The hash chain provides per-case sequential integrity.

    The Merkle layer provides a compact cryptographic commitment over a batch
    of existing blockchain events. A production adapter can implement the
    same interface over a permissioned network such as Hyperledger Fabric.
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

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS merkle_batches (
                    batch_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    start_block INTEGER NOT NULL,
                    end_block INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    merkle_root TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_merkle_case
                ON merkle_batches(case_id)
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS merkle_batch_events (
                    batch_id TEXT NOT NULL,
                    block_index INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    leaf_hash TEXT NOT NULL,
                    PRIMARY KEY (batch_id, block_index),
                    FOREIGN KEY (batch_id)
                        REFERENCES merkle_batches(batch_id)
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_merkle_batch_events
                ON merkle_batch_events(batch_id)
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

    @staticmethod
    def _merkle_leaf_hash(block_hash: str) -> str:
        """Hash a blockchain block hash into a Merkle leaf."""

        return hashlib.sha256(
            f"leaf:{block_hash}".encode()
        ).hexdigest()

    @staticmethod
    def _merkle_parent_hash(
        left: str,
        right: str,
    ) -> str:
        """Calculate one internal Merkle tree node."""

        return hashlib.sha256(
            f"node:{left}:{right}".encode()
        ).hexdigest()

    @classmethod
    def _calculate_merkle_root(
        cls,
        block_hashes: list[str],
    ) -> str | None:
        """Calculate a deterministic Merkle root.

        For an odd number of nodes, the final node is duplicated before
        calculating the next level.
        """

        if not block_hashes:
            return None

        level = [
            cls._merkle_leaf_hash(block_hash)
            for block_hash in block_hashes
        ]

        while len(level) > 1:
            next_level: list[str] = []

            for index in range(0, len(level), 2):
                left = level[index]

                if index + 1 < len(level):
                    right = level[index + 1]
                else:
                    right = left

                next_level.append(
                    cls._merkle_parent_hash(
                        left,
                        right,
                    )
                )

            level = next_level

        return level[0]

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

    def _batched_block_indexes(
        self,
        case_id: str,
    ) -> set[int]:
        """Return block indexes already included in a Merkle batch."""

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT mbe.block_index
                FROM merkle_batch_events AS mbe
                JOIN merkle_batches AS mb
                    ON mb.batch_id = mbe.batch_id
                WHERE mb.case_id = ?
                """,
                (case_id,),
            ).fetchall()

        return {row[0] for row in rows}

    def create_merkle_batch(
        self,
        case_id: str,
    ) -> dict[str, Any]:
        """Create a Merkle batch from all currently unbatched events.

        Existing blockchain events are never modified.

        If every event for the case is already included in a Merkle batch,
        the method returns an explicit no-op response instead of creating
        an empty batch.
        """

        events = self.list(case_id)

        if not events:
            raise ValueError(
                f"No blockchain events found for case {case_id}"
            )

        already_batched = self._batched_block_indexes(case_id)

        batch_events = [
            event
            for event in events
            if event["block_index"] not in already_batched
        ]

        if not batch_events:
            return {
                "created": False,
                "case_id": case_id,
                "reason": "all_events_already_batched",
                "batch": None,
            }

        block_hashes = [
            event["block_hash"]
            for event in batch_events
        ]

        merkle_root = self._calculate_merkle_root(
            block_hashes
        )

        if merkle_root is None:
            raise ValueError(
                "Cannot create a Merkle batch without events"
            )

        batch_id = (
            f"MB-{uuid.uuid4().hex[:16].upper()}"
        )

        created_at = now_iso()

        start_block = batch_events[0]["block_index"]
        end_block = batch_events[-1]["block_index"]

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO merkle_batches
                (
                    batch_id,
                    case_id,
                    start_block,
                    end_block,
                    event_count,
                    merkle_root,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch_id,
                    case_id,
                    start_block,
                    end_block,
                    len(batch_events),
                    merkle_root,
                    created_at,
                ),
            )

            for event in batch_events:
                leaf_hash = self._merkle_leaf_hash(
                    event["block_hash"]
                )

                conn.execute(
                    """
                    INSERT INTO merkle_batch_events
                    (
                        batch_id,
                        block_index,
                        block_hash,
                        leaf_hash
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        batch_id,
                        event["block_index"],
                        event["block_hash"],
                        leaf_hash,
                    ),
                )

        return {
            "created": True,
            "case_id": case_id,
            "reason": None,
            "batch": {
                "batch_id": batch_id,
                "case_id": case_id,
                "start_block": start_block,
                "end_block": end_block,
                "event_count": len(batch_events),
                "merkle_root": merkle_root,
                "created_at": created_at,
            },
        }

    def list_merkle_batches(
        self,
        case_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List persisted Merkle batches."""

        with self._conn() as conn:
            if case_id:
                rows = conn.execute(
                    """
                    SELECT
                        batch_id,
                        case_id,
                        start_block,
                        end_block,
                        event_count,
                        merkle_root,
                        created_at
                    FROM merkle_batches
                    WHERE case_id = ?
                    ORDER BY created_at
                    """,
                    (case_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT
                        batch_id,
                        case_id,
                        start_block,
                        end_block,
                        event_count,
                        merkle_root,
                        created_at
                    FROM merkle_batches
                    ORDER BY created_at DESC
                    """,
                ).fetchall()

        columns = [
            "batch_id",
            "case_id",
            "start_block",
            "end_block",
            "event_count",
            "merkle_root",
            "created_at",
        ]

        return [
            dict(zip(columns, row))
            for row in rows
        ]

    def verify_merkle_batch(
        self,
        batch_id: str,
    ) -> dict[str, Any]:
        """Verify one persisted Merkle batch.

        Verification checks:

        1. The batch exists.
        2. Every referenced blockchain block still exists.
        3. The stored block hash matches the current block hash.
        4. The stored leaf hash matches the current block hash.
        5. The recomputed Merkle root matches the stored root.
        """

        with self._conn() as conn:
            batch = conn.execute(
                """
                SELECT
                    batch_id,
                    case_id,
                    start_block,
                    end_block,
                    event_count,
                    merkle_root,
                    created_at
                FROM merkle_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()

            if not batch:
                raise ValueError(
                    f"Merkle batch not found: {batch_id}"
                )

            event_rows = conn.execute(
                """
                SELECT
                    block_index,
                    block_hash,
                    leaf_hash
                FROM merkle_batch_events
                WHERE batch_id = ?
                ORDER BY block_index
                """,
                (batch_id,),
            ).fetchall()

            current_block_rows = []

            for block_index, stored_block_hash, stored_leaf_hash in event_rows:
                row = conn.execute(
                    """
                    SELECT block_hash
                    FROM blockchain_events
                    WHERE block_index = ?
                    AND case_id = ?
                    """,
                    (
                        block_index,
                        batch[1],
                    ),
                ).fetchone()

                current_block_rows.append(
                    (
                        block_index,
                        stored_block_hash,
                        stored_leaf_hash,
                        row[0] if row else None,
                    )
                )

        errors: list[dict[str, Any]] = []

        current_block_hashes: list[str] = []

        for (
            block_index,
            stored_block_hash,
            stored_leaf_hash,
            current_block_hash,
        ) in current_block_rows:
            if current_block_hash is None:
                errors.append(
                    {
                        "block_index": block_index,
                        "error": "block_missing",
                    }
                )
                continue

            current_block_hashes.append(
                current_block_hash
            )

            if current_block_hash != stored_block_hash:
                errors.append(
                    {
                        "block_index": block_index,
                        "error": "block_hash_changed",
                        "expected": stored_block_hash,
                        "actual": current_block_hash,
                    }
                )

            expected_leaf_hash = self._merkle_leaf_hash(
                current_block_hash
            )

            if stored_leaf_hash != expected_leaf_hash:
                errors.append(
                    {
                        "block_index": block_index,
                        "error": "leaf_hash_mismatch",
                        "expected": expected_leaf_hash,
                        "actual": stored_leaf_hash,
                    }
                )

        recomputed_root = self._calculate_merkle_root(
            current_block_hashes
        )

        stored_root = batch[5]

        if recomputed_root != stored_root:
            errors.append(
                {
                    "error": "merkle_root_mismatch",
                    "expected": stored_root,
                    "actual": recomputed_root,
                }
            )

        verified = not errors

        return {
            "batch_id": batch[0],
            "case_id": batch[1],
            "start_block": batch[2],
            "end_block": batch[3],
            "event_count": batch[4],
            "merkle_root": stored_root,
            "recomputed_root": recomputed_root,
            "created_at": batch[6],
            "verified": verified,
            "status": (
                "VALID"
                if verified
                else "COMPROMISED"
            ),
            "errors": errors,
            "blocks": [
                {
                    "block_index": block_index,
                    "stored_block_hash": stored_block_hash,
                    "current_block_hash": current_block_hash,
                    "leaf_hash": stored_leaf_hash,
                    "integrity": (
                        "VALID"
                        if current_block_hash == stored_block_hash
                        and stored_leaf_hash
                        == self._merkle_leaf_hash(
                            current_block_hash
                        )
                        else "INVALID"
                    ),
                }
                for (
                    block_index,
                    stored_block_hash,
                    stored_leaf_hash,
                    current_block_hash,
                ) in current_block_rows
            ],
        }