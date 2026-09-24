from backend.blockchain.ledger import AuditLedger


def test_hash_chain_verifies(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"x": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 87})

    result = ledger.verify("C1")

    assert result["verified"] is True
    assert result["events"] == 2


def test_tampering_is_detected(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"x": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 87})

    with ledger._conn() as conn:
        conn.execute(
            """
            UPDATE blockchain_events
            SET payload_hash = ?
            WHERE block_index = 2
            """,
            ("tampered_hash",),
        )

    result = ledger.verify("C1")

    assert result["verified"] is False
    assert len(result["errors"]) > 0


def test_cases_have_independent_chains(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"case": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 80})

    ledger.append("C2", "CASE_CREATED", {"case": 2})
    ledger.append("C2", "RISK_ASSESSED", {"risk": 20})

    ledger.append(
        "C1",
        "ACTION_RECOMMENDED",
        {"action": "MONITOR_ACCOUNT"},
    )

    result_c1 = ledger.verify("C1")
    result_c2 = ledger.verify("C2")

    assert result_c1["verified"] is True
    assert result_c1["events"] == 3

    assert result_c2["verified"] is True
    assert result_c2["events"] == 2


def test_merkle_batch_creation_and_verification(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"case": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 87})
    ledger.append(
        "C1",
        "ACTION_RECOMMENDED",
        {"action": "BLOCK_TRANSACTION"},
    )

    result = ledger.create_merkle_batch("C1")

    assert result["created"] is True
    assert result["case_id"] == "C1"
    assert result["batch"]["event_count"] == 3
    assert result["batch"]["start_block"] == 1
    assert result["batch"]["end_block"] == 3
    assert result["batch"]["merkle_root"]

    batch_id = result["batch"]["batch_id"]

    verification = ledger.verify_merkle_batch(batch_id)

    assert verification["verified"] is True
    assert verification["status"] == "VALID"
    assert verification["errors"] == []
    assert (
        verification["merkle_root"]
        == verification["recomputed_root"]
    )


def test_merkle_batch_prevents_duplicate_events(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"case": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 87})

    first = ledger.create_merkle_batch("C1")

    assert first["created"] is True

    second = ledger.create_merkle_batch("C1")

    assert second["created"] is False
    assert second["reason"] == "all_events_already_batched"
    assert second["batch"] is None

    batches = ledger.list_merkle_batches("C1")

    assert len(batches) == 1


def test_merkle_batch_includes_only_new_events(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"case": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 87})

    first = ledger.create_merkle_batch("C1")

    assert first["created"] is True
    assert first["batch"]["event_count"] == 2

    ledger.append(
        "C1",
        "ACTION_RECOMMENDED",
        {"action": "BLOCK_TRANSACTION"},
    )

    second = ledger.create_merkle_batch("C1")

    assert second["created"] is True
    assert second["batch"]["event_count"] == 1
    assert second["batch"]["start_block"] == 3
    assert second["batch"]["end_block"] == 3

    batches = ledger.list_merkle_batches("C1")

    assert len(batches) == 2


def test_merkle_tampering_is_detected(tmp_path):
    ledger = AuditLedger(str(tmp_path / "db.sqlite"))

    ledger.append("C1", "CASE_CREATED", {"case": 1})
    ledger.append("C1", "RISK_ASSESSED", {"risk": 87})
    ledger.append(
        "C1",
        "ACTION_RECOMMENDED",
        {"action": "BLOCK_TRANSACTION"},
    )

    result = ledger.create_merkle_batch("C1")

    batch_id = result["batch"]["batch_id"]

    with ledger._conn() as conn:
        conn.execute(
            """
            UPDATE blockchain_events
            SET block_hash = ?
            WHERE block_index = 2
            """,
            ("tampered_block_hash",),
        )

    verification = ledger.verify_merkle_batch(batch_id)

    assert verification["verified"] is False
    assert verification["status"] == "COMPROMISED"
    assert len(verification["errors"]) > 0

    error_types = {
        error["error"]
        for error in verification["errors"]
    }

    assert "block_hash_changed" in error_types
    assert "merkle_root_mismatch" in error_types