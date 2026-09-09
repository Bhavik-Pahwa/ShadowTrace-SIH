import hashlib
import json

from .ml import FEATURE_ORDER

FEATURE_LABELS = {
    "tx_volume": "Ledger Volume",
    "fee_ratio": "Fee Ratio",
    "input_count": "Input Count",
    "output_count": "Output Count",
    "neighbor_illicit_ratio": "Neighborhood Risk",
    "parent_time_delta": "Parent Time Delta",
    "degree_centrality": "Graph Centrality",
    "tor_or_bulletproof_asn": "Physical IP Anomaly",
    "peel_chain": "Topological Anomaly",
    "fan_out": "Fan-Out Anomaly",
    "fan_in": "Fan-In Anomaly",
    "change_reuse": "Heuristic Anomaly",
    "terminal_exchange": "Exchange Cashout Signal",
    "elliptic_feature_count": "Elliptic Feature Coverage",
    "elliptic_feature_mean": "Elliptic Feature Mean",
    "elliptic_feature_std": "Elliptic Feature Dispersion",
}


def chain_of_custody_hash(tx_id: str, subgraph: dict, timestamp: str | None = None) -> str:
    payload = {"tx_id": tx_id, "timestamp": timestamp, "subgraph": subgraph}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evidence_for(
    row: dict,
    threat_score: int,
    localized_subgraph: dict,
    shap_values: dict[str, float] | None = None,
    explanation_subgraph: dict | None = None,
) -> dict:
    contributions = _feature_contributions(row, threat_score, shap_values)
    total = sum(item["contribution_percentage"] for item in contributions)
    if total != threat_score:
        raise AssertionError(f"Contribution total {total} does not equal score {threat_score} for {row['tx_id']}")
    custody_source = localized_subgraph
    return {
        "tx_id": row["tx_id"],
        "overall_threat_score": threat_score,
        "xai_breakdown": contributions,
        "chain_of_custody_hash": chain_of_custody_hash(row["tx_id"], custody_source, row.get("timestamp")),
        "xai_subgraph": explanation_subgraph or {},
    }


def _feature_contributions(row: dict, threat_score: int, shap_values: dict[str, float] | None = None) -> list[dict]:
    raw = shap_values or {}
    if not raw:
        raw = _local_attribution(row)
    positive = [(name, max(0.0, float(value))) for name, value in raw.items()]
    positive = [(name, value) for name, value in positive if value > 0]
    if not positive:
        positive = [("tx_volume", 1.0)]
    total_raw = sum(value for _, value in positive)
    exact = [(name, (value / total_raw) * threat_score) for name, value in positive]
    scaled = [(name, int(value)) for name, value in exact]
    remainder = threat_score - sum(value for _, value in scaled)
    fractional_rank = sorted(
        enumerate(exact),
        key=lambda item: (item[1][1] - int(item[1][1]), item[1][0]),
        reverse=True,
    )
    for index, _item in fractional_rank[:remainder]:
        name, value = scaled[index]
        scaled[index] = (name, value + 1)
    scaled.sort(key=lambda item: item[1], reverse=True)
    return [
        {
            "feature": FEATURE_LABELS.get(name, name),
            "value": feature_value(name, row),
            "contribution_percentage": float(value),
        }
        for name, value in scaled
        if value > 0
    ]


def build_tree_shap_attributions(rows: list[dict], score_by_tx: dict[str, int]) -> dict[str, dict[str, float]]:
    try:
        import numpy as np
        import shap
        from sklearn.ensemble import RandomForestClassifier
    except Exception:
        return {}

    if len(rows) < 4:
        return {}
    x = np.array([[float(row["features"].get(name, 0.0)) for name in FEATURE_ORDER] for row in rows])
    y = np.array([1 if score_by_tx.get(row["tx_id"], 0) >= 50 else 0 for row in rows])
    if len(set(y.tolist())) < 2:
        return {}
    model = RandomForestClassifier(n_estimators=80, max_depth=6, random_state=26146, class_weight="balanced")
    model.fit(x, y)
    explainer = shap.TreeExplainer(model)
    values = explainer.shap_values(x)
    if isinstance(values, list):
        class_values = values[1]
    elif len(values.shape) == 3:
        class_values = values[:, :, 1]
    else:
        class_values = values
    return {
        row["tx_id"]: {name: abs(float(value)) for name, value in zip(FEATURE_ORDER, class_values[idx])}
        for idx, row in enumerate(rows)
    }


def _local_attribution(row: dict) -> dict[str, float]:
    f = row["features"]
    return {
        "tx_volume": min(float(f.get("tx_volume", 0.0)) / 5.0, 1.0) * 12,
        "fee_ratio": min(float(f.get("fee_ratio", 0.0)) * 80, 1.0) * 8,
        "input_count": min(float(f.get("input_count", 0)) / 8, 1.0) * 7,
        "output_count": min(float(f.get("output_count", 0)) / 8, 1.0) * 7,
        "neighbor_illicit_ratio": float(f.get("neighbor_illicit_ratio", 0.0)) * 10,
        "parent_time_delta": 10 if 0 < float(f.get("parent_time_delta", 0.0)) <= 25 else 0,
        "degree_centrality": min(float(f.get("degree_centrality", 0.0)) * 50, 1.0) * 6,
        "tor_or_bulletproof_asn": 22 if f.get("tor_or_bulletproof_asn") else 0,
        "peel_chain": 18 if f.get("peel_chain") else 0,
        "fan_out": 16 if f.get("fan_out") else 0,
        "fan_in": 16 if f.get("fan_in") else 0,
        "change_reuse": 8 if f.get("change_reuse") else 0,
    }


def feature_value(name: str, row: dict) -> str:
    f = row["features"]
    h = row["heuristics"]
    if name == "tor_or_bulletproof_asn":
        return f"{row['asn_description']} ({row['asn']})"
    if name == "peel_chain":
        return "Peel Chain Structure"
    if name == "fan_out":
        return "Rapid Split to Many Addresses"
    if name == "fan_in":
        return "Many Inputs Consolidated"
    if name == "change_reuse":
        return "Address Reuse (Input = Output)" if h.get("address_reuse") or h.get("change_address") in row.get("input_addresses", []) else "Change Address Signal"
    if name == "terminal_exchange":
        return "Terminal Exchange Wallet" if f.get("terminal_exchange") else "No Terminal Exchange"
    if name.startswith("elliptic_feature_"):
        return str(round(float(f.get(name, 0.0)), 6))
    return str(round(float(f.get(name, 0.0)), 6))


def explain_subgraph_with_gnnexplainer(tx_id: str, graph_elements: dict, artifacts=None) -> dict:
    if artifacts is None or tx_id not in artifacts.tx_index:
        return _with_explanation_metadata(
            _heuristic_minimal_subgraph(tx_id, graph_elements),
            "heuristic_fallback",
            "No GCN artifacts available for this transaction.",
        )
    try:
        from torch_geometric.explain import Explainer, GNNExplainer
    except Exception:
        return _with_explanation_metadata(
            _heuristic_minimal_subgraph(tx_id, graph_elements),
            "heuristic_fallback",
            "PyTorch Geometric GNNExplainer is unavailable.",
        )

    try:
        explainer = Explainer(
            model=artifacts.model,
            algorithm=GNNExplainer(epochs=20),
            explanation_type="model",
            node_mask_type="attributes",
            edge_mask_type="object",
            model_config={
                "mode": "multiclass_classification",
                "task_level": "node",
                "return_type": "raw",
            },
        )
        index = artifacts.tx_index[tx_id]
        explanation = explainer(artifacts.x, artifacts.edge_index, index=index)
        edge_mask = explanation.edge_mask.detach().cpu().tolist()
        important_tx_edges = _important_transaction_edges(artifacts, edge_mask)
        explained = _subgraph_from_important_edges(tx_id, graph_elements, important_tx_edges)
        if explained:
            return _with_explanation_metadata(explained, "gnnexplainer", "GNNExplainer edge mask selected the retained transaction subgraph.")
        return _with_explanation_metadata(
            _heuristic_minimal_subgraph(tx_id, graph_elements),
            "heuristic_fallback",
            "GNNExplainer returned no transaction edges above the retained cutoff.",
        )
    except Exception as exc:
        return _with_explanation_metadata(
            _heuristic_minimal_subgraph(tx_id, graph_elements),
            "heuristic_fallback",
            f"GNNExplainer failed: {exc}",
        )


def _with_explanation_metadata(graph_elements: dict, method: str, details: str) -> dict:
    enriched = {
        "nodes": graph_elements.get("nodes", []),
        "edges": graph_elements.get("edges", []),
        "metadata": {
            "method": method,
            "details": details,
        },
    }
    return enriched


def _important_transaction_edges(artifacts, edge_mask: list[float]) -> set[tuple[str, str]]:
    reverse_index = {idx: tx_id for tx_id, idx in artifacts.tx_index.items()}
    pairs = artifacts.edge_index.t().detach().cpu().tolist()
    if not pairs:
        return set()
    ranked = sorted(zip(pairs, edge_mask), key=lambda item: item[1], reverse=True)
    cutoff_count = max(1, min(8, len(ranked) // 4 or 1))
    important = set()
    for (source_idx, target_idx), _weight in ranked[:cutoff_count]:
        if source_idx == target_idx:
            continue
        important.add((reverse_index[source_idx], reverse_index[target_idx]))
        important.add((reverse_index[target_idx], reverse_index[source_idx]))
    return important


def _subgraph_from_important_edges(tx_id: str, graph_elements: dict, important_tx_edges: set[tuple[str, str]]) -> dict | None:
    if not important_tx_edges:
        return None
    tx_to_outputs: dict[str, set[str]] = {}
    wallet_to_spenders: dict[str, set[str]] = {}
    broadcast_edges = []
    belongs_to_edges_by_ip = {}
    for edge in graph_elements["edges"]:
        data = edge["data"]
        if data.get("relationship") == "RECEIVED":
            tx_to_outputs.setdefault(data["source"], set()).add(data["target"])
        elif data.get("relationship") == "SPENT":
            wallet_to_spenders.setdefault(data["source"], set()).add(data["target"])
        elif data.get("relationship") == "BROADCAST_FROM" and data["source"] == tx_id:
            broadcast_edges.append(edge)
        elif data.get("relationship") == "BELONGS_TO":
            belongs_to_edges_by_ip.setdefault(data["source"], []).append(edge)

    keep_nodes = {tx_id}
    keep_edges = []
    for edge in graph_elements["edges"]:
        data = edge["data"]
        source = data["source"]
        target = data["target"]
        should_keep = False
        for parent_tx, child_tx in important_tx_edges:
            shared_wallets = tx_to_outputs.get(parent_tx, set()) & {
                wallet for wallet, spenders in wallet_to_spenders.items() if child_tx in spenders
            }
            if data.get("relationship") == "RECEIVED" and source == parent_tx and target in shared_wallets:
                should_keep = True
            if data.get("relationship") == "SPENT" and source in shared_wallets and target == child_tx:
                should_keep = True
        if should_keep:
            keep_nodes.update([source, target])
            keep_edges.append(edge)
    for edge in broadcast_edges:
        data = edge["data"]
        keep_nodes.update([data["source"], data["target"]])
        keep_edges.append(edge)
        for asn_edge in belongs_to_edges_by_ip.get(data["target"], []):
            asn_data = asn_edge["data"]
            keep_nodes.update([asn_data["source"], asn_data["target"]])
            keep_edges.append(asn_edge)
    nodes = [node for node in graph_elements["nodes"] if node["data"]["id"] in keep_nodes]
    if not nodes or not keep_edges:
        return None
    return {"nodes": nodes, "edges": keep_edges}


def _heuristic_minimal_subgraph(tx_id: str, graph_elements: dict) -> dict:
    tx_nodes = [node["data"]["id"] for node in graph_elements["nodes"] if node["data"].get("label") == "Transaction"]
    if not tx_nodes:
        return graph_elements
    root = tx_id if tx_id in tx_nodes else tx_nodes[0]
    keep_nodes = {root}
    keep_edges = []
    root_network_nodes = set()
    for edge in graph_elements["edges"]:
        data = edge["data"]
        if data.get("relationship") == "BROADCAST_FROM" and data["source"] == root:
            root_network_nodes.add(data["target"])
        if data["source"] == root or data["target"] == root:
            keep_nodes.add(data["source"])
            keep_nodes.add(data["target"])
            keep_edges.append(edge)
    for edge in graph_elements["edges"]:
        data = edge["data"]
        if data.get("relationship") == "BELONGS_TO" and data["source"] in root_network_nodes:
            keep_nodes.add(data["source"])
            keep_nodes.add(data["target"])
            keep_edges.append(edge)
    nodes = [node for node in graph_elements["nodes"] if node["data"]["id"] in keep_nodes]
    return {"nodes": nodes or graph_elements["nodes"], "edges": keep_edges or graph_elements["edges"]}
