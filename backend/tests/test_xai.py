import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.xai import _feature_contributions, explain_subgraph_with_gnnexplainer


def evidence_row():
    return {
        "tx_id": "tx_xai",
        "timestamp": "2024-08-29T13:45:00Z",
        "asn": "AS208323",
        "asn_description": "Tor Transit",
        "input_addresses": ["bc1qin"],
        "output_addresses": ["1exchange", "bc1qchange"],
        "features": {
            "tx_volume": 1.0,
            "fee_ratio": 0.01,
            "input_count": 1,
            "output_count": 2,
            "terminal_exchange": 1.0,
            "elliptic_feature_mean": 0.42,
        },
        "heuristics": {"change_address": "bc1qchange"},
    }


def test_feature_contributions_use_largest_remainder_for_exact_nonnegative_sum():
    contributions = _feature_contributions(
        evidence_row(),
        3,
        {
            "tx_volume": 1.0,
            "fee_ratio": 1.0,
            "input_count": 1.0,
            "output_count": 1.0,
            "terminal_exchange": 1.0,
        },
    )
    values = [item["contribution_percentage"] for item in contributions]
    assert sum(values) == 3
    assert all(value >= 0 for value in values)


def test_terminal_exchange_and_elliptic_features_have_readable_evidence_labels():
    contributions = _feature_contributions(
        evidence_row(),
        10,
        {"terminal_exchange": 3.0, "elliptic_feature_mean": 2.0},
    )
    labels = {item["feature"]: item["value"] for item in contributions}
    assert labels["Exchange Cashout Signal"] == "Terminal Exchange Wallet"
    assert labels["Elliptic Feature Mean"] == "0.42"


def test_gnnexplainer_fallback_anchors_on_requested_root_transaction():
    graph = {
        "nodes": [
            {"data": {"id": "aaa_other_tx", "label": "Transaction"}},
            {"data": {"id": "wallet", "label": "WalletAddress"}},
            {"data": {"id": "zzz_requested_tx", "label": "Transaction"}},
        ],
        "edges": [
            {"data": {"source": "aaa_other_tx", "target": "wallet", "relationship": "RECEIVED"}},
            {"data": {"source": "wallet", "target": "zzz_requested_tx", "relationship": "SPENT"}},
        ],
    }

    explanation = explain_subgraph_with_gnnexplainer("zzz_requested_tx", graph, artifacts=None)

    assert explanation["metadata"]["method"] == "heuristic_fallback"
    kept_ids = {node["data"]["id"] for node in explanation["nodes"]}
    assert "zzz_requested_tx" in kept_ids
    assert "aaa_other_tx" not in kept_ids


def test_gnnexplainer_fallback_keeps_only_requested_root_network_layer():
    graph = {
        "nodes": [
            {"data": {"id": "root_tx", "label": "Transaction"}},
            {"data": {"id": "other_tx", "label": "Transaction"}},
            {"data": {"id": "185.220.101.5", "label": "IPAddress"}},
            {"data": {"id": "AS208323", "label": "ASN"}},
            {"data": {"id": "8.8.8.8", "label": "IPAddress"}},
            {"data": {"id": "AS15169", "label": "ASN"}},
        ],
        "edges": [
            {"data": {"source": "root_tx", "target": "185.220.101.5", "relationship": "BROADCAST_FROM"}},
            {"data": {"source": "185.220.101.5", "target": "AS208323", "relationship": "BELONGS_TO"}},
            {"data": {"source": "other_tx", "target": "8.8.8.8", "relationship": "BROADCAST_FROM"}},
            {"data": {"source": "8.8.8.8", "target": "AS15169", "relationship": "BELONGS_TO"}},
        ],
    }

    explanation = explain_subgraph_with_gnnexplainer("root_tx", graph, artifacts=None)

    kept_ids = {node["data"]["id"] for node in explanation["nodes"]}
    kept_edges = {(edge["data"]["source"], edge["data"]["target"]) for edge in explanation["edges"]}
    assert {"root_tx", "185.220.101.5", "AS208323"} <= kept_ids
    assert {"other_tx", "8.8.8.8", "AS15169"}.isdisjoint(kept_ids)
    assert ("root_tx", "185.220.101.5") in kept_edges
    assert ("185.220.101.5", "AS208323") in kept_edges
