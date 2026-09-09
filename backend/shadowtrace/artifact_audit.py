from __future__ import annotations

import argparse
import json

from .config import DEFAULT_HOPS
from .pipeline import ShadowTracePipeline
from .xai import chain_of_custody_hash


REQUIRED_NODE_LABELS = {"Transaction", "WalletAddress", "IPAddress", "ASN"}
REQUIRED_EDGE_TYPES = {"SPENT", "RECEIVED", "BROADCAST_FROM", "BELONGS_TO"}


def failures_for_graph(tx_id: str, graph: dict) -> list[str]:
    failures = []
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        failures.append(f"{tx_id}: graph has no nodes")
    if not edges:
        failures.append(f"{tx_id}: graph has no edges")
    labels = {node.get("data", {}).get("label") for node in nodes}
    missing_labels = REQUIRED_NODE_LABELS - labels
    if missing_labels:
        failures.append(f"{tx_id}: graph missing node labels {sorted(missing_labels)}")
    edge_types = {edge.get("data", {}).get("relationship") for edge in edges}
    missing_edges = REQUIRED_EDGE_TYPES - edge_types
    if missing_edges:
        failures.append(f"{tx_id}: graph missing edge types {sorted(missing_edges)}")
    root_nodes = [node["data"] for node in nodes if node.get("data", {}).get("id") == tx_id]
    if len(root_nodes) != 1:
        failures.append(f"{tx_id}: graph must contain exactly one root transaction node")
    else:
        required_root_fields = {"id", "label", "type", "risk", "timestamp", "threat_score", "risk_level", "primary_anomaly"}
        missing_root_fields = required_root_fields - set(root_nodes[0])
        if missing_root_fields:
            failures.append(f"{tx_id}: root node missing {sorted(missing_root_fields)}")
    for edge in edges:
        data = edge.get("data", {})
        relationship = data.get("relationship")
        if relationship in {"SPENT", "RECEIVED"}:
            missing = {"source", "target", "relationship", "amount_btc", "timestamp"} - set(data)
            if missing:
                failures.append(f"{tx_id}: {relationship} edge missing {sorted(missing)}")
        if relationship == "BROADCAST_FROM":
            missing = {"source", "target", "relationship", "timestamp", "src_port", "dst_ip", "dst_port"} - set(data)
            if missing:
                failures.append(f"{tx_id}: BROADCAST_FROM edge missing {sorted(missing)}")
    return failures


def failures_for_evidence(tx_id: str, alert: dict, evidence: dict | None, graph: dict) -> list[str]:
    if evidence is None:
        return [f"{tx_id}: missing evidence row"]
    failures = []
    public_evidence = {
        key: evidence[key]
        for key in ("tx_id", "overall_threat_score", "xai_breakdown", "chain_of_custody_hash")
        if key in evidence
    }
    if set(public_evidence) != {"tx_id", "overall_threat_score", "xai_breakdown", "chain_of_custody_hash"}:
        failures.append(f"{tx_id}: evidence public shape is {sorted(public_evidence)}")
    if evidence.get("tx_id") != tx_id:
        failures.append(f"{tx_id}: evidence tx_id mismatch")
    if evidence.get("overall_threat_score") != alert.get("threat_score"):
        failures.append(f"{tx_id}: evidence score does not match alert score")
    total = sum(item.get("contribution_percentage", 0) for item in evidence.get("xai_breakdown", []))
    if total != evidence.get("overall_threat_score"):
        failures.append(f"{tx_id}: XAI contributions sum {total}, expected {evidence.get('overall_threat_score')}")
    custody_hash = evidence.get("chain_of_custody_hash", "")
    if len(custody_hash) != 64:
        failures.append(f"{tx_id}: custody hash is not 64 hex chars")
    else:
        try:
            int(custody_hash, 16)
        except ValueError:
            failures.append(f"{tx_id}: custody hash is not valid hex")
    expected_hash = chain_of_custody_hash(tx_id, graph, alert.get("timestamp"))
    if custody_hash != expected_hash:
        failures.append(f"{tx_id}: custody hash does not match default {DEFAULT_HOPS}-hop graph payload")
    return failures


def audit_artifacts(limit: int = 0) -> dict:
    pipeline = ShadowTracePipeline()
    failures = []
    try:
        transactions = pipeline.store.fetch_transactions()
        alerts = pipeline.store.fetch_all_alerts()
        if not transactions:
            failures.append("dataset is empty")
        if not alerts:
            failures.append("no alerts are available")
        selected_alerts = alerts[:limit] if limit > 0 else alerts
        for alert in selected_alerts:
            tx_id = alert["tx_id"]
            graph = pipeline.graph_elements(tx_id)
            failures.extend(failures_for_graph(tx_id, graph))
            evidence = pipeline.store.fetch_evidence(tx_id)
            failures.extend(failures_for_evidence(tx_id, alert, evidence, graph))
    finally:
        pipeline.store.close()

    return {
        "status": "error" if failures else "success",
        "transactions": len(transactions),
        "alerts_audited": len(selected_alerts),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit stored ShadowTrace-XAI artifacts against PRD invariants.")
    parser.add_argument("--limit", type=int, default=0, help="Audit at most this many alerts; 0 means every alert.")
    parser.add_argument("--json", action="store_true", help="Emit a JSON summary.")
    args = parser.parse_args()

    summary = audit_artifacts(limit=args.limit)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"status={summary['status']}")
        print(f"transactions={summary['transactions']}")
        print(f"alerts_audited={summary['alerts_audited']}")
        for failure in summary["failures"]:
            print(f"FAIL {failure}")
    return 1 if summary["failures"] else 0
