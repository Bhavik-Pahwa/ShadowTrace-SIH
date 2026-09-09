from collections import defaultdict, deque
from datetime import datetime
import hashlib
from statistics import median

import networkx as nx

from .config import FAN_PATTERN_DELTA_SECONDS, PEEL_DELTA_SECONDS
from .synthetic import satoshis_to_btc

WALLET_TYPE_PRIORITY = {
    "output": 1,
    "input": 2,
    "change": 3,
    "exchange": 4,
}


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class EntityUnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, items: list[str]) -> None:
        if not items:
            return
        root = self.find(items[0])
        for item in items[1:]:
            self.parent[self.find(item)] = root

    def entity_id(self, item: str) -> str:
        root = self.find(item)
        digest = hashlib.sha256(root.encode("utf-8")).hexdigest()
        return "entity_" + str(int(digest[:10], 16) % 100000).zfill(5)


def detect_change_output(row: dict) -> str | None:
    inputs = row["input_addresses"]
    outputs = row["output_addresses"]
    amounts = row["output_amounts"]
    if len(outputs) < 2:
        return None
    input_script = "bech32" if inputs and inputs[0].startswith("bc1") else "base58"
    candidates = []
    for address, amount in zip(outputs, amounts):
        script = "bech32" if address.startswith("bc1") else "base58"
        continuity = 1 if script == input_script else 0
        btc = satoshis_to_btc(int(amount))
        decimal_pattern = 1 if abs(btc - round(btc, 2)) > 0.00000001 else 0
        reuse_penalty = -1 if address in inputs else 0
        candidates.append((continuity + decimal_pattern + reuse_penalty, int(amount), address))
    candidates.sort(reverse=True)
    return candidates[0][2]


def _add_wallet_node(graph: nx.MultiDiGraph, address: str, entity_id: str, wallet_type: str) -> None:
    current_type = graph.nodes[address].get("type") if address in graph else None
    if current_type is not None and WALLET_TYPE_PRIORITY.get(current_type, 0) > WALLET_TYPE_PRIORITY.get(wallet_type, 0):
        wallet_type = current_type
    graph.add_node(address, id=address, label="WalletAddress", type=wallet_type, entity_id=entity_id, node_type="WalletAddress")


def build_graph(rows: list[dict]) -> tuple[nx.MultiDiGraph, dict[str, dict]]:
    graph = nx.MultiDiGraph()
    uf = EntityUnionFind()
    for row in rows:
        uf.union(row["input_addresses"])

    tx_by_id = {row["tx_id"]: row for row in rows}
    address_received_from: dict[str, tuple[str, int, str]] = {}
    address_spent_in: dict[str, list[str]] = defaultdict(list)

    for row in rows:
        tx_id = row["tx_id"]
        graph.add_node(
            tx_id,
            id=tx_id,
            label="Transaction",
            type="hub",
            risk="low",
            timestamp=row["timestamp"],
            src_port=row["src_port"],
            dst_ip=row["dst_ip"],
            dst_port=row["dst_port"],
            data_provenance=row.get("heuristics", {}).get("data_provenance"),
            node_type="Transaction",
        )
        graph.add_node(row["src_ip"], id=row["src_ip"], label="IPAddress", type="network", country=row.get("country"), node_type="IPAddress")
        graph.add_node(
            row["asn"],
            id=row["asn"],
            label="ASN",
            type="infrastructure",
            description=row["asn_description"],
            node_type="ASN",
        )
        graph.add_edge(
            tx_id,
            row["src_ip"],
            relationship="BROADCAST_FROM",
            timestamp=row["timestamp"],
            src_port=row["src_port"],
            dst_ip=row["dst_ip"],
            dst_port=row["dst_port"],
        )
        graph.add_edge(row["src_ip"], row["asn"], relationship="BELONGS_TO")

        for address, amount in zip(row["input_addresses"], row["input_amounts"]):
            entity_id = uf.entity_id(address)
            _add_wallet_node(graph, address, entity_id, "input")
            graph.add_edge(address, tx_id, relationship="SPENT", amount_btc=satoshis_to_btc(int(amount)), timestamp=row["timestamp"])
            address_spent_in[address].append(tx_id)

        change_output = detect_change_output(row)
        row["heuristics"]["change_address"] = change_output
        exchange_addresses = set(row.get("heuristics", {}).get("exchange_addresses", []))
        for address, amount in zip(row["output_addresses"], row["output_amounts"]):
            entity_id = uf.entity_id(address)
            node_type = "exchange" if address in exchange_addresses else ("change" if address == change_output else "output")
            _add_wallet_node(graph, address, entity_id, node_type)
            graph.add_edge(tx_id, address, relationship="RECEIVED", amount_btc=satoshis_to_btc(int(amount)), timestamp=row["timestamp"])
            address_received_from[address] = (tx_id, int(amount), row["timestamp"])

    tx_children: dict[str, list[str]] = defaultdict(list)
    for address, spenders in address_spent_in.items():
        if address in address_received_from:
            parent_tx = address_received_from[address][0]
            for child_tx in spenders:
                if child_tx != parent_tx:
                    tx_children[parent_tx].append(child_tx)

    peel_members = detect_peel_chains(rows, tx_children)
    fan_out, fan_in = detect_fan_patterns(rows, address_received_from, address_spent_in)

    for row in rows:
        tx_id = row["tx_id"]
        input_count = len(row["input_addresses"])
        output_count = len(row["output_addresses"])
        total_in = sum(row["input_amounts"])
        total_out = sum(row["output_amounts"])
        fee_ratio = max(total_in - total_out, 0) / max(total_in, 1)
        heuristics = row["heuristics"]
        reused_outputs = sorted(set(row["input_addresses"]) & set(row["output_addresses"]))
        heuristics["cioh_entity_ids"] = sorted({uf.entity_id(addr) for addr in row["input_addresses"]})
        heuristics["address_reuse"] = reused_outputs
        heuristics["peel_chain"] = tx_id in peel_members
        heuristics["fan_out"] = tx_id in fan_out
        heuristics["fan_in"] = tx_id in fan_in
        heuristics["terminal_exchange"] = bool(set(row.get("output_addresses", [])) & set(heuristics.get("exchange_addresses", [])))
        original_features = {k: v for k, v in row.get("features", {}).items() if k.startswith("elliptic_feature_")}
        features = {
            **original_features,
            "tx_volume": satoshis_to_btc(total_in),
            "fee_ratio": fee_ratio,
            "input_count": input_count,
            "output_count": output_count,
            "neighbor_illicit_ratio": neighbor_illicit_ratio(tx_id, graph, tx_by_id),
            "parent_time_delta": parent_time_delta(tx_id, row, address_received_from),
            "degree_centrality": nx.degree_centrality(graph.to_undirected()).get(tx_id, 0.0),
            "tor_or_bulletproof_asn": 1.0 if row["asn_description"] in {"Tor Transit", "NForce Entertainment B.V.", "M247 Europe SRL"} else 0.0,
            "peel_chain": 1.0 if heuristics["peel_chain"] else 0.0,
            "fan_out": 1.0 if heuristics["fan_out"] else 0.0,
            "fan_in": 1.0 if heuristics["fan_in"] else 0.0,
            "change_reuse": 1.0 if reused_outputs else 0.0,
            "terminal_exchange": 1.0 if heuristics["terminal_exchange"] else 0.0,
        }
        row["features"] = features
        graph.nodes[tx_id]["risk"] = "high" if heuristics["peel_chain"] or features["tor_or_bulletproof_asn"] else "medium"

    return graph, tx_by_id


def detect_peel_chains(rows: list[dict], tx_children: dict[str, list[str]]) -> set[str]:
    by_id = {row["tx_id"]: row for row in rows}
    candidates = {
        row["tx_id"]
        for row in rows
        if len(row["input_addresses"]) == 1 and len(row["output_addresses"]) == 2
    }
    peel_members: set[str] = set()
    for start in candidates:
        chain = [start]
        current = start
        amounts = []
        while True:
            children = [child for child in tx_children.get(current, []) if child in candidates]
            if len(children) != 1:
                break
            child = children[0]
            delta = (_parse_ts(by_id[child]["timestamp"]) - _parse_ts(by_id[current]["timestamp"])).total_seconds()
            if not (0 <= delta <= PEEL_DELTA_SECONDS):
                break
            parent_amounts = sorted(by_id[current]["output_amounts"])
            child_amounts = sorted(by_id[child]["output_amounts"])
            amounts.append(parent_amounts[0])
            amounts.append(child_amounts[0])
            chain.append(child)
            current = child
            if current in chain[:-1]:
                break
        if len(chain) >= 3 and repeated_small_amount(amounts):
            peel_members.update(chain)
    return peel_members


def repeated_small_amount(amounts: list[int]) -> bool:
    if len(amounts) < 2:
        return False
    med = median(amounts)
    return all(abs(amount - med) / max(med, 1) <= 0.08 for amount in amounts)


def detect_fan_patterns(
    rows: list[dict],
    address_received_from: dict[str, tuple[str, int, str]] | None = None,
    address_spent_in: dict[str, list[str]] | None = None,
) -> tuple[set[str], set[str]]:
    fan_out = set()
    fan_in = set()
    by_id = {row["tx_id"]: row for row in rows}
    address_received_from = address_received_from or {}
    address_spent_in = address_spent_in or {}
    for row in rows:
        if len(row["input_addresses"]) == 1 and len(row["output_addresses"]) >= 5 and has_rapid_fan_context(row, by_id, address_received_from, address_spent_in):
            fan_out.add(row["tx_id"])
        if len(row["input_addresses"]) >= 5 and len(row["output_addresses"]) <= 2 and has_rapid_fan_context(row, by_id, address_received_from, address_spent_in):
            fan_in.add(row["tx_id"])
    return fan_out, fan_in


def has_rapid_fan_context(
    row: dict,
    tx_by_id: dict[str, dict],
    address_received_from: dict[str, tuple[str, int, str]],
    address_spent_in: dict[str, list[str]],
) -> bool:
    related_times = []
    current = _parse_ts(row["timestamp"])
    for address in row["input_addresses"]:
        if address in address_received_from and address_received_from[address][0] != row["tx_id"]:
            related_times.append(_parse_ts(address_received_from[address][2]))
    for address in row["output_addresses"]:
        for child_tx in address_spent_in.get(address, []):
            if child_tx != row["tx_id"] and child_tx in tx_by_id:
                related_times.append(_parse_ts(tx_by_id[child_tx]["timestamp"]))
    if not related_times:
        return True
    return any(abs((current - timestamp).total_seconds()) <= FAN_PATTERN_DELTA_SECONDS for timestamp in related_times)


def neighbor_illicit_ratio(tx_id: str, graph: nx.MultiDiGraph, tx_by_id: dict[str, dict]) -> float:
    immediate = set(graph.predecessors(tx_id)) | set(graph.successors(tx_id))
    tx_neighbors = set()
    for node in immediate:
        if graph.nodes[node].get("node_type") != "WalletAddress":
            continue
        for tx_neighbor in set(graph.predecessors(node)) | set(graph.successors(node)):
            if tx_neighbor in tx_by_id and tx_neighbor != tx_id:
                tx_neighbors.add(tx_neighbor)
    if not tx_neighbors:
        return 0.0
    illicit = sum(1 for node in tx_neighbors if tx_by_id[node]["label"] == "illicit")
    return illicit / len(tx_neighbors)


def parent_time_delta(tx_id: str, row: dict, address_received_from: dict[str, tuple[str, int, str]]) -> float:
    deltas = []
    current = _parse_ts(row["timestamp"])
    for address in row["input_addresses"]:
        if address in address_received_from and address_received_from[address][0] != tx_id:
            deltas.append(abs((current - _parse_ts(address_received_from[address][2])).total_seconds()))
    return min(deltas) if deltas else 0.0


def n_hop_elements(graph: nx.MultiDiGraph, tx_id: str, hops: int) -> dict:
    seen = {tx_id}
    queue = deque([(tx_id, 0)])
    while queue:
        node, depth = queue.popleft()
        if depth >= hops:
            continue
        for neighbor in sorted(set(graph.predecessors(node)) | set(graph.successors(node))):
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, depth + 1))
    for node in list(seen):
        if graph.nodes[node].get("node_type") != "Transaction":
            continue
        for neighbor in sorted(graph.successors(node)):
            if graph.nodes[neighbor].get("node_type") == "WalletAddress" and graph.nodes[neighbor].get("type") == "exchange":
                seen.add(neighbor)
    sub = graph.subgraph(seen)
    nodes = [
        {"data": {k: v for k, v in sorted(data.items()) if k != "node_type" and v is not None}}
        for _, data in sorted(sub.nodes(data=True), key=lambda item: str(item[0]))
    ]
    edges = []
    sorted_edges = sorted(
        sub.edges(data=True),
        key=lambda item: (
            str(item[0]),
            str(item[1]),
            str(item[2].get("relationship", "")),
            str(item[2].get("amount_btc", "")),
            str(item[2].get("timestamp", "")),
        ),
    )
    for source, target, data in sorted_edges:
        payload = {"source": source, "target": target, **{k: v for k, v in sorted(data.items())}}
        edges.append({"data": payload})
    return {"nodes": nodes, "edges": edges}
