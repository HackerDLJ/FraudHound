from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


ACCOUNT_TYPES = {
    "Account",
    "ACCOUNT",
    "account",
}

DEVICE_TYPES = {
    "Device",
    "DEVICE",
    "device",
}

IP_TYPES = {
    "IPAddress",
    "IP",
    "IP_ADDRESS",
    "ip",
    "ip_address",
}

TRANSACTION_TYPES = {
    "Transaction",
    "TRANSACTION",
    "transaction",
}

FRAUD_TYPES = {
    "FraudCase",
    "FRAUD_CASE",
    "Fraud",
    "fraud",
    "fraud_case",
}


def _node_id(node: dict[str, Any]) -> str | None:
    value = node.get("id")

    if value is None:
        value = node.get("node_id")

    if value is None:
        return None

    return str(value)


def _node_type(node: dict[str, Any]) -> str:
    value = node.get("type")

    if value is None:
        value = node.get("label")

    return str(value or "")


def _edge_endpoint(
    edge: dict[str, Any],
    *keys: str,
) -> str | None:
    for key in keys:
        value = edge.get(key)

        if value is not None:
            return str(value)

    return None


def _edge_source(edge: dict[str, Any]) -> str | None:
    return _edge_endpoint(
        edge,
        "source",
        "from",
        "src",
        "source_id",
        "from_id",
    )


def _edge_target(edge: dict[str, Any]) -> str | None:
    return _edge_endpoint(
        edge,
        "target",
        "to",
        "dst",
        "target_id",
        "to_id",
    )


def _edge_type(edge: dict[str, Any]) -> str:
    value = edge.get("type")

    if value is None:
        value = edge.get("label")

    return str(value or "")


def _normalise_graph(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> tuple[
    dict[str, dict[str, Any]],
    list[tuple[str, str, str]],
]:
    node_map: dict[str, dict[str, Any]] = {}

    for node in nodes:
        node_id = _node_id(node)

        if node_id is None:
            continue

        node_map[node_id] = {
            **node,
            "id": node_id,
        }

    normalised_edges: list[tuple[str, str, str]] = []

    for edge in edges:
        source = _edge_source(edge)
        target = _edge_target(edge)

        if source is None or target is None:
            continue

        if source not in node_map:
            continue

        if target not in node_map:
            continue

        normalised_edges.append(
            (
                source,
                target,
                _edge_type(edge),
            )
        )

    return node_map, normalised_edges


def _shared_entity_maps(
    edges: list[tuple[str, str, str]],
    node_map: dict[str, dict[str, Any]],
) -> tuple[
    dict[str, set[str]],
    dict[str, set[str]],
]:
    """
    Build:

        device_id -> account IDs
        ip_id     -> account IDs

    This is the important bridge between the heterogeneous graph and
    account-level fraud-ring detection.
    """

    device_accounts: dict[str, set[str]] = defaultdict(set)
    ip_accounts: dict[str, set[str]] = defaultdict(set)

    for source, target, _ in edges:
        source_type = _node_type(node_map[source])
        target_type = _node_type(node_map[target])

        if (
            source_type in ACCOUNT_TYPES
            and target_type in DEVICE_TYPES
        ):
            device_accounts[target].add(source)

        elif (
            target_type in ACCOUNT_TYPES
            and source_type in DEVICE_TYPES
        ):
            device_accounts[source].add(target)

        elif (
            source_type in ACCOUNT_TYPES
            and target_type in IP_TYPES
        ):
            ip_accounts[target].add(source)

        elif (
            target_type in ACCOUNT_TYPES
            and source_type in IP_TYPES
        ):
            ip_accounts[source].add(target)

    return dict(device_accounts), dict(ip_accounts)


def _build_account_adjacency(
    account_ids: list[str],
    edges: list[tuple[str, str, str]],
    node_map: dict[str, dict[str, Any]],
    device_accounts: dict[str, set[str]],
    ip_accounts: dict[str, set[str]],
) -> dict[str, set[str]]:
    """
    Convert heterogeneous graph relationships into account-to-account
    connectivity.

    Accounts become connected when:

    1. There is a direct Account -> Account edge.
    2. They share a device.
    3. They share an IP address.

    This allows a structure such as:

        A1 -> D1 <- A2 <- D1 -> A3

    to become the account cluster:

        A1 <-> A2 <-> A3
    """

    adjacency: dict[str, set[str]] = {
        account_id: set()
        for account_id in account_ids
    }

    account_set = set(account_ids)

    # Direct account-to-account relationships.
    for source, target, _ in edges:
        source_is_account = (
            _node_type(node_map[source]) in ACCOUNT_TYPES
        )
        target_is_account = (
            _node_type(node_map[target]) in ACCOUNT_TYPES
        )

        if not source_is_account or not target_is_account:
            continue

        if source not in account_set:
            continue

        if target not in account_set:
            continue

        adjacency[source].add(target)
        adjacency[target].add(source)

    # Shared devices connect accounts.
    for accounts in device_accounts.values():
        members = sorted(accounts & account_set)

        for index, account_a in enumerate(members):
            for account_b in members[index + 1 :]:
                adjacency[account_a].add(account_b)
                adjacency[account_b].add(account_a)

    # Shared IP addresses connect accounts.
    for accounts in ip_accounts.values():
        members = sorted(accounts & account_set)

        for index, account_a in enumerate(members):
            for account_b in members[index + 1 :]:
                adjacency[account_a].add(account_b)
                adjacency[account_b].add(account_a)

    return adjacency


def _connected_components(
    account_ids: list[str],
    adjacency: dict[str, set[str]],
) -> list[list[str]]:
    components: list[list[str]] = []
    visited: set[str] = set()

    for start in account_ids:
        if start in visited:
            continue

        queue: deque[str] = deque([start])
        visited.add(start)

        component: list[str] = []

        while queue:
            current = queue.popleft()
            component.append(current)

            for neighbour in sorted(
                adjacency.get(current, set())
            ):
                if neighbour in visited:
                    continue

                visited.add(neighbour)
                queue.append(neighbour)

        components.append(sorted(component))

    return components


def _entity_groups_for_accounts(
    account_ids: set[str],
    entity_map: dict[str, set[str]],
) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []

    for entity_id, connected_accounts in entity_map.items():
        members = sorted(
            account_ids & connected_accounts
        )

        if len(members) < 2:
            continue

        groups.append(
            {
                "entity_id": entity_id,
                "account_ids": members,
                "account_count": len(members),
            }
        )

    return sorted(
        groups,
        key=lambda item: (
            -item["account_count"],
            item["entity_id"],
        ),
    )


def _transaction_ids_for_component(
    account_ids: set[str],
    edges: list[tuple[str, str, str]],
    node_map: dict[str, dict[str, Any]],
) -> list[str]:
    transactions: set[str] = set()

    for source, target, _ in edges:
        source_type = _node_type(node_map[source])
        target_type = _node_type(node_map[target])

        if (
            source_type in TRANSACTION_TYPES
            and target in account_ids
        ):
            transactions.add(source)

        if (
            target_type in TRANSACTION_TYPES
            and source in account_ids
        ):
            transactions.add(target)

    return sorted(transactions)


def _historical_fraud_connections(
    account_ids: set[str],
    edges: list[tuple[str, str, str]],
    node_map: dict[str, dict[str, Any]],
) -> list[str]:
    fraud_accounts: set[str] = set()

    for source, target, _ in edges:
        source_type = _node_type(node_map[source])
        target_type = _node_type(node_map[target])

        if (
            source in account_ids
            and target_type in FRAUD_TYPES
        ):
            fraud_accounts.add(source)

        if (
            target in account_ids
            and source_type in FRAUD_TYPES
        ):
            fraud_accounts.add(target)

    return sorted(fraud_accounts)


def _calculate_confidence(
    account_count: int,
    device_groups: list[dict[str, Any]],
    ip_groups: list[dict[str, Any]],
    historical_fraud_accounts: list[str],
    transaction_count: int,
) -> float:
    """
    Transparent deterministic heuristic.

    This is an evidence score, not a machine-learning probability.
    """

    score = 0.0

    if account_count >= 3:
        score += 0.20

    if account_count >= 5:
        score += 0.10

    if device_groups:
        score += min(
            0.25,
            0.12 * len(device_groups),
        )

    if any(
        group["account_count"] >= 3
        for group in device_groups
    ):
        score += 0.10

    if ip_groups:
        score += min(
            0.20,
            0.10 * len(ip_groups),
        )

    if any(
        group["account_count"] >= 3
        for group in ip_groups
    ):
        score += 0.08

    if historical_fraud_accounts:
        score += min(
            0.17,
            0.08 * len(historical_fraud_accounts),
        )

    if transaction_count >= 2:
        score += 0.05

    return round(
        min(score, 0.99),
        2,
    )


def detect_fraud_rings(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    min_accounts: int = 3,
) -> list[dict[str, Any]]:
    """
    Detect coordinated account clusters from graph evidence.

    A candidate ring must contain at least ``min_accounts`` connected
    accounts.

    Account connectivity can come from:

    - direct account relationships
    - shared devices
    - shared IP addresses

    Additional evidence includes:

    - transactions
    - historical fraud connections

    No relationship is invented. Every returned signal is derived from
    the supplied graph.
    """

    if min_accounts < 2:
        raise ValueError(
            "min_accounts must be at least 2"
        )

    node_map, normalised_edges = _normalise_graph(
        nodes,
        edges,
    )

    account_ids = sorted(
        node_id
        for node_id, node in node_map.items()
        if _node_type(node) in ACCOUNT_TYPES
    )

    if len(account_ids) < min_accounts:
        return []

    device_map, ip_map = _shared_entity_maps(
        normalised_edges,
        node_map,
    )

    adjacency = _build_account_adjacency(
        account_ids,
        normalised_edges,
        node_map,
        device_map,
        ip_map,
    )

    components = _connected_components(
        account_ids,
        adjacency,
    )

    findings: list[dict[str, Any]] = []

    for index, component in enumerate(
        components,
        start=1,
    ):
        if len(component) < min_accounts:
            continue

        component_set = set(component)

        device_groups = _entity_groups_for_accounts(
            component_set,
            device_map,
        )

        ip_groups = _entity_groups_for_accounts(
            component_set,
            ip_map,
        )

        transaction_ids = _transaction_ids_for_component(
            component_set,
            normalised_edges,
            node_map,
        )

        historical_fraud_accounts = (
            _historical_fraud_connections(
                component_set,
                normalised_edges,
                node_map,
            )
        )

        signals: list[str] = []

        for group in device_groups:
            signals.append(
                "shared device "
                f"{group['entity_id']} connects "
                f"{group['account_count']} accounts"
            )

        for group in ip_groups:
            signals.append(
                "shared IP "
                f"{group['entity_id']} connects "
                f"{group['account_count']} accounts"
            )

        if transaction_ids:
            signals.append(
                f"{len(transaction_ids)} transaction(s) "
                "connect the cluster"
            )

        if historical_fraud_accounts:
            signals.append(
                f"{len(historical_fraud_accounts)} account(s) "
                "connect to historical fraud evidence"
            )

        confidence = _calculate_confidence(
            account_count=len(component),
            device_groups=device_groups,
            ip_groups=ip_groups,
            historical_fraud_accounts=(
                historical_fraud_accounts
            ),
            transaction_count=len(transaction_ids),
        )

        explanation_parts = [
            (
                "Connected account cluster contains "
                f"{len(component)} accounts."
            )
        ]

        if device_groups:
            explanation_parts.append(
                f"{len(device_groups)} shared device "
                "relationship(s) were found."
            )

        if ip_groups:
            explanation_parts.append(
                f"{len(ip_groups)} shared IP "
                "relationship(s) were found."
            )

        if historical_fraud_accounts:
            explanation_parts.append(
                f"{len(historical_fraud_accounts)} account(s) "
                "connect to historical fraud evidence."
            )

        if transaction_ids:
            explanation_parts.append(
                f"{len(transaction_ids)} transaction(s) "
                "are connected to the cluster."
            )

        findings.append(
            {
                "ring_id": f"RING-{index:03d}",
                "account_ids": component,
                "account_count": len(component),
                "shared_devices": device_groups,
                "shared_ips": ip_groups,
                "transaction_ids": transaction_ids,
                "historical_fraud_accounts": (
                    historical_fraud_accounts
                ),
                "confidence": confidence,
                "signals": signals,
                "explanation": " ".join(
                    explanation_parts
                ),
            }
        )

    findings.sort(
        key=lambda item: (
            -item["confidence"],
            -item["account_count"],
            item["ring_id"],
        )
    )

    return findings