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

    ledger.append("C1", "ACTION_RECOMMENDED", {"action": "MONITOR_ACCOUNT"})

    result_c1 = ledger.verify("C1")
    result_c2 = ledger.verify("C2")

    assert result_c1["verified"] is True
    assert result_c1["events"] == 3

    assert result_c2["verified"] is True
    assert result_c2["events"] == 2