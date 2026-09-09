import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os
import tempfile

os.environ["SHADOWTRACE_DB_PATH"] = str(Path(tempfile.gettempdir()) / "shadowtrace_test.duckdb")
os.environ["SHADOWTRACE_ALLOW_PDF_FALLBACK"] = "1"

from shadowtrace.main import app, pipeline
from shadowtrace.xai import chain_of_custody_hash

@pytest.fixture(scope="module", autouse=True)
def load_sample():
    pipeline.load_sample()


def test_alerts_contract_and_pagination():
    client = TestClient(app)
    response = client.get("/api/alerts?limit=5&offset=0")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"status", "total_count", "alerts"}
    assert payload["status"] == "success"
    assert len(payload["alerts"]) <= 5
    assert payload["total_count"] >= len(payload["alerts"])
    assert set(payload["alerts"][0]) == {"tx_id", "threat_score", "timestamp", "primary_anomaly", "risk_level"}


def test_ingest_contract_with_csv_upload():
    client = TestClient(app)
    csv = (
        "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts\n"
        "tx_upload_1,1,1,bc1qin,1pay;bc1qchange,100000000,8000000;91990000\n"
    )
    response = client.post("/api/ingest", files={"file": ("sample.csv", csv, "text/csv")})
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"status", "message", "job_id", "rows_processed"}
    assert payload["status"] == "success"
    assert payload["message"] == "Dataset ingested successfully."
    assert payload["job_id"].startswith("job_")
    assert payload["rows_processed"] == 1
    pipeline.load_sample()


def test_ingest_malformed_file_standard_error():
    client = TestClient(app)
    response = client.post("/api/ingest", files={"file": ("bad.txt", "not,csv", "text/plain")})
    assert response.status_code == 400
    assert response.json() == {
        "status": "error",
        "code": 400,
        "message": "Malformed ingest file.",
        "details": "Only CSV files are supported by /api/ingest.",
    }


def test_ingest_bad_row_standard_error():
    client = TestClient(app)
    csv = (
        "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts\n"
        "tx_bad,1,1,bc1qin,1pay;bc1qchange,not-a-number,8000000;91990000\n"
    )
    response = client.post("/api/ingest", files={"file": ("bad.csv", csv, "text/csv")})
    assert response.status_code == 400
    payload = response.json()
    assert payload["status"] == "error"
    assert payload["code"] == 400
    assert payload["message"] == "Malformed ingest file."
    assert "Row 1" in payload["details"]


def test_ingest_unrecognized_columns_standard_error():
    client = TestClient(app)
    response = client.post("/api/ingest", files={"file": ("bad.csv", "foo,bar\nalpha,beta\n", "text/csv")})
    assert response.status_code == 400
    assert response.json() == {
        "status": "error",
        "code": 400,
        "message": "Malformed ingest file.",
        "details": "No recognized transaction columns were found.",
    }


def test_ingest_duplicate_transaction_id_standard_error():
    client = TestClient(app)
    csv = "tx_id,class,time_step\ntx_dup,1,1\ntx_dup,2,2\n"
    response = client.post("/api/ingest", files={"file": ("duplicate.csv", csv, "text/csv")})
    assert response.status_code == 400
    assert response.json() == {
        "status": "error",
        "code": 400,
        "message": "Malformed ingest file.",
        "details": "Row 2: duplicate transaction id tx_dup.",
    }


def test_ingest_empty_csv_standard_error():
    client = TestClient(app)
    response = client.post("/api/ingest", files={"file": ("empty.csv", "tx_id,class,time_step\n", "text/csv")})
    assert response.status_code == 400
    assert response.json() == {
        "status": "error",
        "code": 400,
        "message": "Empty dataset.",
        "details": "The uploaded ingest file contains no transaction rows.",
    }


def test_graph_contract_embeds_metadata():
    client = TestClient(app)
    tx_id = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]["tx_id"]
    payload = client.get(f"/api/graph/{tx_id}").json()
    assert set(payload) == {"tx_id", "elements"}
    assert set(payload["elements"]) == {"nodes", "edges"}
    assert payload["elements"]["nodes"]
    assert payload["elements"]["edges"]
    for edge in payload["elements"]["edges"]:
        data = edge["data"]
        if data["relationship"] in {"SPENT", "RECEIVED"}:
            assert "amount_btc" in data
            assert "timestamp" in data
        if data["relationship"] == "BROADCAST_FROM":
            assert "timestamp" in data
            assert "src_port" in data
            assert "dst_ip" in data
            assert "dst_port" in data
    transaction_nodes = [node["data"] for node in payload["elements"]["nodes"] if node["data"]["label"] == "Transaction"]
    assert any({"timestamp", "src_port", "dst_ip", "dst_port"} <= set(node) for node in transaction_nodes)
    root_node = next(node for node in transaction_nodes if node["id"] == tx_id)
    assert root_node["type"] == "hub"
    assert root_node["risk"] in {"low", "medium", "high", "critical"}
    assert root_node["threat_score"] >= 50
    assert root_node["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert root_node["primary_anomaly"]
    assert root_node["data_provenance"]["dataset"] == "elliptic_augmented"
    assert root_node["data_provenance"]["semi_synthetic"] is False or root_node["data_provenance"]["semi_synthetic"] is True
    assert any(node["data"]["label"] == "IPAddress" for node in payload["elements"]["nodes"])
    assert any(node["data"]["label"] == "ASN" for node in payload["elements"]["nodes"])
    assert any(node["data"]["label"] == "WalletAddress" and node["data"]["type"] == "exchange" for node in payload["elements"]["nodes"])
    assert any(edge["data"]["relationship"] == "BROADCAST_FROM" for edge in payload["elements"]["edges"])
    assert any(edge["data"]["relationship"] == "BELONGS_TO" for edge in payload["elements"]["edges"])


def test_graph_default_hops_include_three_transaction_peel_chain():
    client = TestClient(app)
    csv = (
        "tx_id,class,time_step,timestamp,input_addresses,output_addresses,input_amounts,output_amounts,src_ip,dst_ip,src_port,dst_port,exchange_address\n"
        "peel_1,1,1,2024-08-29T13:45:00Z,bc1qseed,1pay1;bc1qchange1,200000000,8000000;191990000,185.220.101.10,8.8.8.8,8333,8333,\n"
        "peel_2,1,1,2024-08-29T13:45:08Z,bc1qchange1,1pay2;bc1qchange2,191990000,8010000;183970000,185.220.101.11,8.8.8.8,8334,8333,\n"
        "peel_3,1,1,2024-08-29T13:45:16Z,bc1qchange2,1exchange;bc1qchange3,183970000,7990000;175970000,185.220.101.12,8.8.8.8,8335,8333,1exchange\n"
    )
    try:
        ingest_response = client.post("/api/ingest", files={"file": ("peel.csv", csv, "text/csv")})
        assert ingest_response.status_code == 200

        payload = client.get("/api/graph/peel_1").json()
        node_ids = {node["data"]["id"] for node in payload["elements"]["nodes"]}

        assert {"peel_1", "peel_2", "peel_3", "1exchange"} <= node_ids
        assert any(node["data"].get("type") == "exchange" for node in payload["elements"]["nodes"])
    finally:
        pipeline.load_sample()


def test_graph_endpoint_has_no_extra_public_query_contract():
    operation = app.openapi()["paths"]["/api/graph/{tx_id}"]["get"]
    parameters = {(param["name"], param["in"]) for param in operation["parameters"]}
    assert parameters == {("tx_id", "path")}


def test_evidence_sums_to_score_and_hash_is_real():
    client = TestClient(app)
    alert = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]
    tx_id = alert["tx_id"]
    evidence = client.get(f"/api/evidence/{tx_id}").json()
    graph = client.get(f"/api/graph/{tx_id}").json()["elements"]
    assert set(evidence) == {"tx_id", "overall_threat_score", "xai_breakdown", "chain_of_custody_hash"}
    total = sum(item["contribution_percentage"] for item in evidence["xai_breakdown"])
    assert total == evidence["overall_threat_score"]
    assert len(evidence["chain_of_custody_hash"]) == 64
    assert evidence["chain_of_custody_hash"] != "..."
    int(evidence["chain_of_custody_hash"], 16)
    assert evidence["chain_of_custody_hash"] == chain_of_custody_hash(tx_id, graph, alert["timestamp"])


def test_gnnexplainer_subgraph_artifact_is_retained_for_alerts():
    client = TestClient(app)
    alert = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]
    full_graph = client.get(f"/api/graph/{alert['tx_id']}").json()["elements"]
    xai_graph = pipeline.explainer_subgraphs[alert["tx_id"]]
    assert xai_graph["nodes"]
    assert xai_graph["edges"]
    assert pipeline.model_artifacts is not None
    assert xai_graph["metadata"]["method"] == "gnnexplainer"
    assert len(xai_graph["nodes"]) <= len(full_graph["nodes"])
    assert len(xai_graph["edges"]) <= len(full_graph["edges"])


def test_all_alert_evidence_contributions_sum_to_scores():
    client = TestClient(app)
    alerts_payload = client.get("/api/alerts?limit=500&offset=0").json()
    assert alerts_payload["alerts"]
    for alert in alerts_payload["alerts"]:
        evidence = client.get(f"/api/evidence/{alert['tx_id']}").json()
        total = sum(item["contribution_percentage"] for item in evidence["xai_breakdown"])
        assert total == evidence["overall_threat_score"]


def test_unknown_tx_standard_error():
    client = TestClient(app)
    response = client.get("/api/graph/nope")
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Entity not found in the graph.",
        "details": "No hops available for the given tx_id.",
    }


def test_unknown_api_route_standard_error():
    client = TestClient(app)
    response = client.get("/api/not-a-real-route")
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Not Found",
        "details": "Not Found",
    }


def test_unknown_evidence_standard_error():
    client = TestClient(app)
    response = client.get("/api/evidence/nope")
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Entity not found in the graph.",
        "details": "No evidence is available for the given tx_id.",
    }


def test_unknown_dossier_standard_error():
    client = TestClient(app)
    response = client.post(
        "/api/generate-dossier",
        json={
            "tx_id": "nope",
            "investigator_id": "NTRO_ANALYST_01",
            "include_xai_visuals": True,
            "include_network_metadata": True,
        },
    )
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Entity not found in the graph.",
        "details": "No dossier can be generated for an unknown tx_id.",
    }


def test_existing_unflagged_transaction_has_standard_evidence_and_dossier_errors():
    client = TestClient(app)
    csv = (
        "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts,src_ip,dst_ip,src_port,dst_port\n"
        "tx_benign,2,1,bc1qin,bc1qout,100000,99900,8.8.8.8,1.1.1.1,8333,18333\n"
    )
    ingest_response = client.post("/api/ingest", files={"file": ("benign.csv", csv, "text/csv")})
    assert ingest_response.status_code == 200
    alerts_payload = client.get("/api/alerts?limit=50&offset=0").json()
    assert alerts_payload == {"status": "success", "total_count": 0, "alerts": []}

    evidence_response = client.get("/api/evidence/tx_benign")
    assert evidence_response.status_code == 404
    assert evidence_response.json() == {
        "status": "error",
        "code": 404,
        "message": "Evidence not found.",
        "details": "The transaction exists but has not been flagged as an alert.",
    }

    dossier_response = client.post(
        "/api/generate-dossier",
        json={
            "tx_id": "tx_benign",
            "investigator_id": "NTRO_ANALYST_01",
            "include_xai_visuals": True,
            "include_network_metadata": True,
        },
    )
    assert dossier_response.status_code == 404
    assert dossier_response.json() == {
        "status": "error",
        "code": 404,
        "message": "Evidence not found.",
        "details": "The transaction exists but has not been flagged as an alert.",
    }
    pipeline.load_sample()


def test_empty_dataset_alerts_standard_error():
    client = TestClient(app)
    pipeline.store.reset()
    pipeline.graph = None
    pipeline.tx_by_id = {}
    response = client.get("/api/alerts?limit=50&offset=0")
    assert response.status_code == 400
    assert response.json() == {
        "status": "error",
        "code": 400,
        "message": "Empty dataset.",
        "details": "No ingested transactions are available for alert generation.",
    }
    pipeline.load_sample()


def test_validation_error_standard_shape():
    client = TestClient(app)
    response = client.get("/api/alerts?limit=0&offset=0")
    assert response.status_code == 422
    payload = response.json()
    assert set(payload) == {"status", "code", "message", "details"}
    assert payload["status"] == "error"


def test_dossier_rejects_unexpected_request_fields():
    client = TestClient(app)
    tx_id = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]["tx_id"]
    response = client.post(
        "/api/generate-dossier",
        json={
            "tx_id": tx_id,
            "investigator_id": "NTRO_ANALYST_01",
            "include_xai_visuals": True,
            "include_network_metadata": True,
            "extra_demo_flag": True,
        },
    )
    assert response.status_code == 422
    assert response.json()["status"] == "error"


def test_dossier_rejects_stringified_boolean_request_fields():
    client = TestClient(app)
    tx_id = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]["tx_id"]
    response = client.post(
        "/api/generate-dossier",
        json={
            "tx_id": tx_id,
            "investigator_id": "NTRO_ANALYST_01",
            "include_xai_visuals": "true",
            "include_network_metadata": "false",
        },
    )
    assert response.status_code == 422
    payload = response.json()
    assert set(payload) == {"status", "code", "message", "details"}
    assert payload["status"] == "error"


def test_dossier_contract_and_download_path():
    client = TestClient(app)
    tx_id = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]["tx_id"]
    response = client.post(
        "/api/generate-dossier",
        json={
            "tx_id": tx_id,
            "investigator_id": "NTRO_ANALYST_01",
            "include_xai_visuals": True,
            "include_network_metadata": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"status", "message", "file_path", "download_url"}
    assert payload["status"] == "success"
    assert payload["message"] == "Dossier generated successfully."
    assert payload["download_url"].startswith("/api/downloads/")
    dossier_path = Path(payload["file_path"])
    assert dossier_path.is_absolute()
    assert dossier_path.exists()
    assert dossier_path.read_bytes().startswith(b"%PDF")


def test_team_model_investigate_falls_back_to_prd_evidence_for_backend_alert():
    client = TestClient(app)
    alert = client.get("/api/alerts?limit=1&offset=0").json()["alerts"][0]
    response = client.get(f"/api/investigate/{alert['tx_id']}")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"tx_id", "risk_level", "risk_score", "prediction", "xai_explanation"}
    assert payload["tx_id"] == alert["tx_id"]
    assert payload["risk_level"] == alert["risk_level"]
    assert payload["risk_score"] == round(alert["threat_score"] / 100, 6)
    assert payload["prediction"] == "suspicious"
    assert set(payload["xai_explanation"]) == {"target_node", "feature_weights"}
    assert payload["xai_explanation"]["feature_weights"]


def test_feedback_endpoint_records_investigator_label(tmp_path, monkeypatch):
    import shadowtrace.team_model as team_model

    monkeypatch.setattr(team_model, "FEEDBACK_DB", tmp_path / "feedback.db")
    client = TestClient(app)
    response = client.post(
        "/api/feedback",
        json={
            "tx_id": "tx_feedback",
            "ai_score": 0.91,
            "human_label": 1,
            "reviewed_by": "NTRO_ANALYST_01",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"status", "message", "recorded_timestamp"}
    assert payload["status"] == "success"
    assert "tx_feedback" in payload["message"]


def test_feedback_endpoint_rejects_invalid_human_label():
    client = TestClient(app)
    response = client.post(
        "/api/feedback",
        json={
            "tx_id": "tx_feedback",
            "ai_score": 0.91,
            "human_label": 2,
            "reviewed_by": "NTRO_ANALYST_01",
        },
    )
    assert response.status_code == 400
    assert response.json()["message"] == "Malformed feedback payload."


def test_missing_download_uses_standard_error_shape():
    client = TestClient(app)
    response = client.get("/api/downloads/missing.pdf")
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Report not found.",
        "details": "No generated dossier is available at the requested path.",
    }


def test_download_rejects_non_pdf_with_standard_error_shape():
    client = TestClient(app)
    response = client.get("/api/downloads/not_pdf.txt")
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Report not found.",
        "details": "No generated dossier is available at the requested path.",
    }


def test_download_rejects_path_traversal_with_standard_error_shape():
    client = TestClient(app)
    response = client.get("/api/downloads/..%2Fshadowtrace.duckdb")
    assert response.status_code == 404
    assert response.json() == {
        "status": "error",
        "code": 404,
        "message": "Report not found.",
        "details": "No generated dossier is available at the requested path.",
    }
