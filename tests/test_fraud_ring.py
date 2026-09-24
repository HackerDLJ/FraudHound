from backend.graph.fraud_ring import detect_fraud_rings


def test_detects_accounts_sharing_device_and_ip():
    nodes = [
        {"id": "A1", "type": "Account"},
        {"id": "A2", "type": "Account"},
        {"id": "A3", "type": "Account"},
        {"id": "D1", "type": "Device"},
        {"id": "IP1", "type": "IPAddress"},
    ]

    edges = [
        {"source": "A1", "target": "D1", "type": "USES_DEVICE"},
        {"source": "A2", "target": "D1", "type": "USES_DEVICE"},
        {"source": "A3", "target": "D1", "type": "USES_DEVICE"},
        {"source": "A1", "target": "IP1", "type": "USES_IP"},
        {"source": "A2", "target": "IP1", "type": "USES_IP"},
    ]

    rings = detect_fraud_rings(nodes, edges)

    assert len(rings) == 1

    ring = rings[0]

    assert ring["account_ids"] == ["A1", "A2", "A3"]
    assert ring["account_count"] == 3
    assert len(ring["shared_devices"]) == 1
    assert len(ring["shared_ips"]) == 1
    assert ring["confidence"] > 0


def test_detects_historical_fraud_connection():
    nodes = [
        {"id": "A1", "type": "Account"},
        {"id": "A2", "type": "Account"},
        {"id": "A3", "type": "Account"},
        {"id": "D1", "type": "Device"},
        {"id": "FRAUD-1", "type": "FraudCase"},
    ]

    edges = [
        {"source": "A1", "target": "D1", "type": "USES_DEVICE"},
        {"source": "A2", "target": "D1", "type": "USES_DEVICE"},
        {"source": "A3", "target": "D1", "type": "USES_DEVICE"},
        {
            "source": "A2",
            "target": "FRAUD-1",
            "type": "LINKED_TO_FRAUD",
        },
    ]

    rings = detect_fraud_rings(nodes, edges)

    assert len(rings) == 1

    ring = rings[0]

    assert ring["historical_fraud_accounts"] == ["A2"]

    assert any(
        "historical fraud" in signal
        for signal in ring["signals"]
    )


def test_separate_account_clusters_produce_separate_rings():
    nodes = [
        {"id": "A1", "type": "Account"},
        {"id": "A2", "type": "Account"},
        {"id": "A3", "type": "Account"},
        {"id": "A4", "type": "Account"},
        {"id": "A5", "type": "Account"},
        {"id": "A6", "type": "Account"},
        {"id": "D1", "type": "Device"},
        {"id": "D2", "type": "Device"},
    ]

    edges = [
        {"source": "A1", "target": "D1"},
        {"source": "A2", "target": "D1"},
        {"source": "A3", "target": "D1"},
        {"source": "A4", "target": "D2"},
        {"source": "A5", "target": "D2"},
        {"source": "A6", "target": "D2"},
    ]

    rings = detect_fraud_rings(nodes, edges)

    assert len(rings) == 2

    account_clusters = {
        tuple(ring["account_ids"])
        for ring in rings
    }

    assert (
        ("A1", "A2", "A3") in account_clusters
    )

    assert (
        ("A4", "A5", "A6") in account_clusters
    )


def test_ignores_small_connected_group():
    nodes = [
        {"id": "A1", "type": "Account"},
        {"id": "A2", "type": "Account"},
        {"id": "D1", "type": "Device"},
    ]

    edges = [
        {"source": "A1", "target": "D1"},
        {"source": "A2", "target": "D1"},
    ]

    rings = detect_fraud_rings(nodes, edges)

    assert rings == []


def test_does_not_invent_relationships():
    nodes = [
        {"id": "A1", "type": "Account"},
        {"id": "A2", "type": "Account"},
        {"id": "A3", "type": "Account"},
    ]

    edges = []

    rings = detect_fraud_rings(nodes, edges)

    assert rings == []


def test_min_accounts_can_be_configured():
    nodes = [
        {"id": "A1", "type": "Account"},
        {"id": "A2", "type": "Account"},
        {"id": "D1", "type": "Device"},
    ]

    edges = [
        {"source": "A1", "target": "D1"},
        {"source": "A2", "target": "D1"},
    ]

    rings = detect_fraud_rings(
        nodes,
        edges,
        min_accounts=2,
    )

    assert len(rings) == 1
    assert rings[0]["account_ids"] == ["A1", "A2"]


def test_rejects_invalid_min_accounts():
    nodes = []
    edges = []

    try:
        detect_fraud_rings(
            nodes,
            edges,
            min_accounts=1,
        )
    except ValueError as exc:
        assert "min_accounts" in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError for min_accounts < 2"
        )
        