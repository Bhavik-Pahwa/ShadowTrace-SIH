import argparse
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def request_json(base_url: str, path: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(base_url.rstrip("/") + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def request_head(base_url: str, path: str) -> tuple[int, str]:
    request = Request(base_url.rstrip("/") + path, method="HEAD")
    with urlopen(request, timeout=15) as response:
        return response.status, response.headers.get("Content-Type", "")


def custody_hash(tx_id: str, graph_elements: dict, timestamp: str) -> str:
    payload = {"tx_id": tx_id, "timestamp": timestamp, "subgraph": graph_elements}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test a running ShadowTrace-XAI API.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    base_url = args.base_url

    status, alerts = request_json(base_url, "/api/alerts?limit=1&offset=0")
    assert status == 200, alerts
    assert set(alerts) == {"status", "total_count", "alerts"}
    assert alerts["status"] == "success"
    assert alerts["alerts"], "No alerts returned; run sample pipeline or ingest data first."
    alert = alerts["alerts"][0]

    status, graph = request_json(base_url, f"/api/graph/{alert['tx_id']}")
    assert status == 200, graph
    assert set(graph) == {"tx_id", "elements"}
    assert graph["elements"]["nodes"]
    assert graph["elements"]["edges"]
    node_labels = {node["data"].get("label") for node in graph["elements"]["nodes"]}
    assert {"Transaction", "WalletAddress", "IPAddress", "ASN"} <= node_labels
    edge_relationships = {edge["data"].get("relationship") for edge in graph["elements"]["edges"]}
    assert {"SPENT", "RECEIVED", "BROADCAST_FROM", "BELONGS_TO"} <= edge_relationships
    root_nodes = [node["data"] for node in graph["elements"]["nodes"] if node["data"].get("id") == alert["tx_id"]]
    assert len(root_nodes) == 1
    assert {"type", "risk", "threat_score", "risk_level", "primary_anomaly", "timestamp"} <= set(root_nodes[0])
    assert root_nodes[0]["type"] == "hub"
    assert root_nodes[0]["risk"] in {"low", "medium", "high", "critical"}
    for edge in graph["elements"]["edges"]:
        data = edge["data"]
        if data["relationship"] in {"SPENT", "RECEIVED"}:
            assert "amount_btc" in data
            assert "timestamp" in data
        if data["relationship"] == "BROADCAST_FROM":
            assert {"timestamp", "src_port", "dst_ip", "dst_port"} <= set(data)

    status, evidence = request_json(base_url, f"/api/evidence/{alert['tx_id']}")
    assert status == 200, evidence
    assert set(evidence) == {"tx_id", "overall_threat_score", "xai_breakdown", "chain_of_custody_hash"}
    total = sum(item["contribution_percentage"] for item in evidence["xai_breakdown"])
    assert total == evidence["overall_threat_score"]
    assert evidence["chain_of_custody_hash"] == custody_hash(alert["tx_id"], graph["elements"], alert["timestamp"])

    status, dossier = request_json(
        base_url,
        "/api/generate-dossier",
        method="POST",
        payload={
            "tx_id": alert["tx_id"],
            "investigator_id": "NTRO_ANALYST_01",
            "include_xai_visuals": True,
            "include_network_metadata": True,
        },
    )
    assert status == 200, dossier
    assert set(dossier) == {"status", "message", "file_path", "download_url"}
    assert Path(dossier["file_path"]).is_absolute()
    head_status, content_type = request_head(base_url, dossier["download_url"])
    assert head_status == 200
    assert content_type.startswith("application/pdf")

    status, error = request_json(base_url, "/api/graph/not-a-real-tx")
    assert status == 404
    assert set(error) == {"status", "code", "message", "details"}
    assert error["status"] == "error"

    status, investigation = request_json(base_url, f"/api/investigate/{alert['tx_id']}")
    assert status == 200, investigation
    assert set(investigation) == {"tx_id", "risk_level", "risk_score", "prediction", "xai_explanation"}
    assert set(investigation["xai_explanation"]) == {"target_node", "feature_weights"}

    status, feedback = request_json(
        base_url,
        "/api/feedback",
        method="POST",
        payload={
            "tx_id": alert["tx_id"],
            "ai_score": alert["threat_score"] / 100,
            "human_label": 1,
            "reviewed_by": "NTRO_ANALYST_01",
        },
    )
    assert status == 200, feedback
    assert set(feedback) == {"status", "message", "recorded_timestamp"}
    assert feedback["status"] == "success"
    print("api_smoke=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
