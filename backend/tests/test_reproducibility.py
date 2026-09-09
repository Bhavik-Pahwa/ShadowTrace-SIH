import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.pipeline import ShadowTracePipeline
from shadowtrace.store import DuckDBStore
from shadowtrace.xai import chain_of_custody_hash


def test_graph_payload_and_hash_are_stable_across_rebuilds(tmp_path):
    db_path = tmp_path / "stable.duckdb"
    first = ShadowTracePipeline(DuckDBStore(db_path))
    first.load_sample()
    alert = first.store.fetch_alerts(1, 0)[0]
    graph_one = first.graph_elements(alert["tx_id"])
    hash_one = chain_of_custody_hash(alert["tx_id"], graph_one, alert["timestamp"])

    second = ShadowTracePipeline(DuckDBStore(db_path))
    graph_two = second.graph_elements(alert["tx_id"])
    hash_two = chain_of_custody_hash(alert["tx_id"], graph_two, alert["timestamp"])

    assert graph_one == graph_two
    assert hash_one == hash_two


def test_stored_evidence_hash_uses_current_default_graph_payload(tmp_path):
    pipeline = ShadowTracePipeline(DuckDBStore(tmp_path / "custody_default.duckdb"))
    pipeline.load_sample()
    alert = pipeline.store.fetch_alerts(1, 0)[0]
    evidence = pipeline.store.fetch_evidence(alert["tx_id"])
    graph = pipeline.graph_elements(alert["tx_id"])

    assert evidence is not None
    assert evidence["chain_of_custody_hash"] == chain_of_custody_hash(alert["tx_id"], graph, alert["timestamp"])
    pipeline.store.close()


def test_fetch_transactions_uses_stable_timestamp_txid_order(tmp_path):
    store = DuckDBStore(tmp_path / "ordered.duckdb")
    rows = [
        {
            "tx_id": "tx_b",
            "label": "licit",
            "timestamp": "2024-08-29T13:45:00Z",
            "time_step": 1,
            "src_ip": "8.8.8.8",
            "dst_ip": "1.1.1.1",
            "src_port": 8333,
            "dst_port": 8333,
            "asn": "AS15169",
            "asn_description": "Google LLC",
            "country": "US",
            "input_addresses": ["bc1qinb"],
            "output_addresses": ["bc1qoutb"],
            "input_amounts": [100_000],
            "output_amounts": [99_000],
            "features": {},
            "heuristics": {},
        },
        {
            "tx_id": "tx_a",
            "label": "licit",
            "timestamp": "2024-08-29T13:45:00Z",
            "time_step": 1,
            "src_ip": "8.8.4.4",
            "dst_ip": "1.0.0.1",
            "src_port": 8334,
            "dst_port": 8333,
            "asn": "AS15169",
            "asn_description": "Google LLC",
            "country": "US",
            "input_addresses": ["bc1qina"],
            "output_addresses": ["bc1qouta"],
            "input_amounts": [100_000],
            "output_amounts": [99_000],
            "features": {},
            "heuristics": {},
        },
    ]
    store.insert_transactions(rows)
    try:
        assert [row["tx_id"] for row in store.fetch_transactions()] == ["tx_a", "tx_b"]
    finally:
        store.close()
