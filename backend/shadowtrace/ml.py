from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import REQUIRE_PYG_EXTENSIONS

FEATURE_ORDER = [
    "tx_volume",
    "fee_ratio",
    "input_count",
    "output_count",
    "neighbor_illicit_ratio",
    "parent_time_delta",
    "degree_centrality",
    "tor_or_bulletproof_asn",
    "peel_chain",
    "fan_out",
    "fan_in",
    "change_reuse",
    "terminal_exchange",
    "elliptic_feature_count",
    "elliptic_feature_mean",
    "elliptic_feature_std",
]


@dataclass
class ModelResult:
    tx_id: str
    threat_score: int
    risk_level: str
    primary_anomaly: str
    probabilities: dict[str, float]


@dataclass
class GCNArtifacts:
    model: Any
    x: Any
    edge_index: Any
    tx_index: dict[str, int]
    validation_metrics: dict[str, float]


class ShadowTraceGCN:
    def __init__(self, in_channels: int, hidden_channels: int = 32, out_channels: int = 3):
        import torch
        from torch import nn
        from torch_geometric.nn import GCNConv

        class GCN(nn.Module):
            def __init__(self):
                super().__init__()
                self.conv1 = GCNConv(in_channels, hidden_channels)
                self.conv2 = GCNConv(hidden_channels, out_channels)

            def forward(self, x, edge_index):
                x = self.conv1(x, edge_index).relu()
                x = self.conv2(x, edge_index)
                return x

        self.torch = torch
        self.model = GCN()


def pyg_available() -> tuple[bool, str]:
    try:
        import torch  # noqa: F401
        import torch_geometric  # noqa: F401
        from torch_geometric.nn import GCNConv  # noqa: F401
    except Exception as exc:
        return False, str(exc)
    return True, "PyTorch Geometric GCN imports successfully."


def pyg_extensions_available() -> tuple[bool, str]:
    try:
        import torch_scatter  # noqa: F401
        import torch_sparse  # noqa: F401
    except Exception as exc:
        return False, str(exc)
    return True, "PyG extension modules imported successfully."


def score_transactions(rows: list[dict], graph=None, return_artifacts: bool = False):
    available, _ = pyg_available()
    extensions_available, extensions_details = pyg_extensions_available()
    if REQUIRE_PYG_EXTENSIONS and not extensions_available:
        raise RuntimeError(f"PyG extension modules are required for target scoring: {extensions_details}")
    if available and _can_make_validation_split(rows):
        results, artifacts = _score_with_gcn(rows, graph)
        return (results, artifacts) if return_artifacts else results
    results = _score_with_local_model(rows)
    return (results, None) if return_artifacts else results


def _can_make_validation_split(rows: list[dict]) -> bool:
    if len(rows) < 10:
        return False
    labels = [{"licit": 0, "illicit": 1, "unknown": 2}.get(row["label"], 2) for row in rows]
    counts = {label: labels.count(label) for label in set(labels)}
    return len(counts) > 1 and min(counts.values()) >= 2


def _score_with_gcn(rows: list[dict], graph=None) -> tuple[list[ModelResult], GCNArtifacts]:
    import torch
    from sklearn.model_selection import train_test_split

    torch.manual_seed(26146)
    _ = ShadowTraceGCN(len(FEATURE_ORDER))
    x = torch.tensor([[float(row["features"].get(name, 0.0)) for name in FEATURE_ORDER] for row in rows], dtype=torch.float)
    labels = torch.tensor([{"licit": 0, "illicit": 1, "unknown": 2}.get(row["label"], 2) for row in rows], dtype=torch.long)
    indices = list(range(len(rows)))
    train_idx, val_idx = train_test_split(indices, test_size=0.2, random_state=26146, stratify=labels.tolist())
    model = ShadowTraceGCN(len(FEATURE_ORDER)).model
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    edge_index = _transaction_edge_index(rows, graph, torch)
    for _epoch in range(20):
        optimizer.zero_grad()
        logits = model(x, edge_index)
        loss = torch.nn.functional.cross_entropy(logits[train_idx], labels[train_idx])
        loss.backward()
        optimizer.step()
    model.eval()
    with torch.no_grad():
        logits = model(x, edge_index)
        probs = torch.softmax(logits, dim=1)
        predictions = logits[val_idx].argmax(dim=1)
        validation_accuracy = float((predictions == labels[val_idx]).float().mean().item())
    return [
        _result_from_probabilities(
            row,
            {
                "licit": float(probs[idx, 0].item()),
                "illicit": float(probs[idx, 1].item()),
                "anomalous": float(probs[idx, 2].item()),
            },
        )
        for idx, row in enumerate(rows)
    ], GCNArtifacts(
        model=model,
        x=x,
        edge_index=edge_index,
        tx_index={row["tx_id"]: idx for idx, row in enumerate(rows)},
        validation_metrics={
            "validation_size": float(len(val_idx)),
            "validation_accuracy": validation_accuracy,
        },
    )


def _transaction_edge_index(rows: list[dict], graph, torch):
    tx_index = {row["tx_id"]: idx for idx, row in enumerate(rows)}
    edges: set[tuple[int, int]] = set()
    if graph is not None:
        for tx_id, idx in tx_index.items():
            neighbors = set(graph.predecessors(tx_id)) | set(graph.successors(tx_id))
            for wallet in neighbors:
                if graph.nodes[wallet].get("node_type") != "WalletAddress":
                    continue
                for tx_neighbor in set(graph.predecessors(wallet)) | set(graph.successors(wallet)):
                    if tx_neighbor in tx_index and tx_neighbor != tx_id:
                        edges.add((idx, tx_index[tx_neighbor]))
                        edges.add((tx_index[tx_neighbor], idx))
    for idx in range(len(rows)):
        edges.add((idx, idx))
    return torch.tensor(sorted(edges), dtype=torch.long).t().contiguous()


def _score_with_local_model(rows: list[dict]) -> list[ModelResult]:
    results = []
    for row in rows:
        f = row["features"]
        score = 0.0
        score += min(float(f.get("tx_volume", 0.0)) / 5.0, 1.0) * 12
        score += min(float(f.get("fee_ratio", 0.0)) * 80, 1.0) * 8
        score += min(float(f.get("input_count", 0)) / 8, 1.0) * 7
        score += min(float(f.get("output_count", 0)) / 8, 1.0) * 7
        score += float(f.get("neighbor_illicit_ratio", 0.0)) * 10
        score += 10 if 0 < float(f.get("parent_time_delta", 0.0)) <= 25 else 0
        score += min(float(f.get("degree_centrality", 0.0)) * 50, 1.0) * 6
        score += 22 if f.get("tor_or_bulletproof_asn") else 0
        score += 18 if f.get("peel_chain") else 0
        score += 16 if f.get("fan_out") else 0
        score += 16 if f.get("fan_in") else 0
        score += 8 if f.get("change_reuse") else 0
        if row["label"] == "illicit":
            score += 10
        probability = max(0.0, min(score / 100.0, 1.0))
        results.append(_result_from_probability(row, probability))
    return results


def _result_from_probability(row: dict, probability: float) -> ModelResult:
    score = int(round(probability * 100))
    return ModelResult(
        tx_id=row["tx_id"],
        threat_score=score,
        risk_level=risk_level(score),
        primary_anomaly=primary_anomaly(row),
        probabilities={
            "licit": round(max(0.0, 1.0 - probability), 6),
            "illicit": round(probability * 0.72, 6),
            "anomalous": round(probability * 0.28, 6),
        },
    )


def _result_from_probabilities(row: dict, probabilities: dict[str, float]) -> ModelResult:
    normalized = {label: max(0.0, float(probabilities.get(label, 0.0))) for label in ("licit", "illicit", "anomalous")}
    total = sum(normalized.values()) or 1.0
    normalized = {label: value / total for label, value in normalized.items()}
    threat_probability = normalized["illicit"] + normalized["anomalous"]
    score = int(round(threat_probability * 100))
    rounded = {
        "licit": round(normalized["licit"], 6),
        "illicit": round(normalized["illicit"], 6),
    }
    rounded["anomalous"] = round(max(0.0, 1.0 - rounded["licit"] - rounded["illicit"]), 6)
    return ModelResult(
        tx_id=row["tx_id"],
        threat_score=score,
        risk_level=risk_level(score),
        primary_anomaly=primary_anomaly(row),
        probabilities=rounded,
    )


def risk_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def primary_anomaly(row: dict) -> str:
    h = row.get("heuristics", {})
    f = row.get("features", {})
    if h.get("peel_chain"):
        return "Peel Chain to Exchange"
    if h.get("fan_out"):
        return "Rapid Fan-Out Smurfing"
    if h.get("fan_in"):
        return "Fan-In Pre-Cashout Aggregation"
    if f.get("tor_or_bulletproof_asn"):
        return "Physical IP Anomaly"
    if h.get("address_reuse") or h.get("change_address") in row.get("input_addresses", []):
        return "Address Reuse (Input = Output)"
    return "GNN Transaction Anomaly"
