import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.graph_builder import build_graph
from shadowtrace.ingestion import sample_dataset
from shadowtrace.ml import _result_from_probabilities, _transaction_edge_index, score_transactions
from shadowtrace.pipeline import ShadowTracePipeline
from shadowtrace.store import DuckDBStore


def test_transaction_edge_index_uses_shared_wallet_topology():
    import torch

    rows = sample_dataset()[:3]
    graph, _ = build_graph(rows)
    edge_index = _transaction_edge_index(rows, graph, torch)
    edges = {tuple(pair) for pair in edge_index.t().tolist()}
    assert (0, 1) in edges
    assert (1, 0) in edges
    assert (1, 2) in edges
    assert (2, 1) in edges


def test_gcn_path_records_validation_metrics_when_available():
    rows = sample_dataset()
    graph, _ = build_graph(rows)
    results, artifacts = score_transactions(rows, graph, return_artifacts=True)
    assert results
    first = results[0]
    assert set(first.probabilities) == {"licit", "illicit", "anomalous"}
    illicit_or_anomalous = first.probabilities["illicit"] + first.probabilities["anomalous"]
    assert first.threat_score == round(illicit_or_anomalous * 100)
    assert round(sum(first.probabilities.values()), 6) == 1.0
    if artifacts is not None:
        assert artifacts.validation_metrics["validation_size"] > 0
        assert 0.0 <= artifacts.validation_metrics["validation_accuracy"] <= 1.0


def test_gcn_result_scores_combined_illicit_and_anomalous_probability():
    result = _result_from_probabilities(
        {"tx_id": "tx_prob", "features": {}, "heuristics": {}},
        {"licit": 0.25, "illicit": 0.35, "anomalous": 0.40},
    )
    assert result.threat_score == 75
    assert result.probabilities == {"licit": 0.25, "illicit": 0.35, "anomalous": 0.4}


def test_target_mode_requires_pyg_extension_modules(monkeypatch):
    import pytest
    import shadowtrace.ml as module

    monkeypatch.setattr(module, "REQUIRE_PYG_EXTENSIONS", True)
    monkeypatch.setattr(module, "pyg_available", lambda: (True, "ok"))
    monkeypatch.setattr(module, "pyg_extensions_available", lambda: (False, "missing torch_sparse"))

    with pytest.raises(RuntimeError, match="PyG extension modules are required"):
        module.score_transactions(sample_dataset())


def test_pipeline_persists_latest_model_validation_metrics(tmp_path):
    db_path = tmp_path / "model_run.duckdb"
    pipeline = ShadowTracePipeline(DuckDBStore(db_path))
    pipeline.load_sample()
    model_run = pipeline.store.fetch_model_run()
    pipeline.store.close()
    assert model_run is not None
    assert model_run["run_id"] == "latest"
    assert model_run["scoring_engine"] == "pyg_gcn"
    assert model_run["validation_metrics"]["validation_size"] > 0
    assert 0.0 <= model_run["validation_metrics"]["validation_accuracy"] <= 1.0

    reopened = DuckDBStore(db_path)
    persisted = reopened.fetch_model_run()
    reopened.close()
    assert persisted == model_run
