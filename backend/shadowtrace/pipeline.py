from pathlib import Path

from .config import DEFAULT_HOPS
from .graph_builder import build_graph, n_hop_elements
from .ingestion import ingest_dataset, sample_dataset
from .ml import score_transactions
from .store import DuckDBStore
from .xai import build_tree_shap_attributions, evidence_for, explain_subgraph_with_gnnexplainer


class ShadowTracePipeline:
    def __init__(self, store: DuckDBStore | None = None):
        self.store = store or DuckDBStore()
        self.graph = None
        self.tx_by_id: dict[str, dict] = {}
        self.model_artifacts = None
        self.explainer_subgraphs: dict[str, dict] = {}

    def ingest_file(self, path: Path) -> int:
        rows = ingest_dataset(path)
        return self._load_rows(rows)

    def load_sample(self) -> int:
        return self._load_rows(sample_dataset())

    def _load_rows(self, rows: list[dict]) -> int:
        self.store.reset()
        count = self.store.insert_transactions(rows)
        self.rebuild()
        return count

    def rebuild(self) -> None:
        rows = self.store.fetch_transactions()
        if not rows:
            self.graph = None
            self.tx_by_id = {}
            self.explainer_subgraphs = {}
            return
        self._build_graph_from_rows(rows)
        for row in rows:
            self.store.update_transaction_annotations(row["tx_id"], row["features"], row["heuristics"])
        results, self.model_artifacts = score_transactions(rows, self.graph, return_artifacts=True)
        alerts = []
        score_by_tx = {}
        for result in results:
            score_by_tx[result.tx_id] = result.threat_score
            if result.threat_score >= 50:
                alerts.append(
                    {
                        "tx_id": result.tx_id,
                        "threat_score": result.threat_score,
                        "timestamp": self.tx_by_id[result.tx_id]["timestamp"],
                        "primary_anomaly": result.primary_anomaly,
                        "risk_level": result.risk_level,
                    }
                )
        self.store.insert_alerts(alerts)
        self._annotate_graph_with_alerts(alerts)
        if self.model_artifacts is not None:
            self.store.save_model_run("pyg_gcn", self.model_artifacts.validation_metrics)
        else:
            self.store.save_model_run("local_fallback", {"validation_size": 0.0, "validation_accuracy": 0.0})
        shap_by_tx = build_tree_shap_attributions(rows, score_by_tx)
        evidence_rows = []
        self.explainer_subgraphs = {}
        for alert in alerts:
            localized_subgraph = self.graph_elements(alert["tx_id"])
            explanation_subgraph = explain_subgraph_with_gnnexplainer(alert["tx_id"], localized_subgraph, self.model_artifacts)
            self.explainer_subgraphs[alert["tx_id"]] = explanation_subgraph
            evidence_rows.append(
                evidence_for(
                    self.tx_by_id[alert["tx_id"]],
                    score_by_tx[alert["tx_id"]],
                    localized_subgraph,
                    shap_by_tx.get(alert["tx_id"]),
                    explanation_subgraph,
                )
            )
        self.store.insert_evidence(evidence_rows)

    def ensure_graph(self) -> None:
        if self.graph is None:
            rows = self.store.fetch_transactions()
            if rows:
                self._build_graph_from_rows(rows)
                self._annotate_graph_with_alerts(self.store.fetch_all_alerts())
            else:
                self.graph = None
                self.tx_by_id = {}

    def _build_graph_from_rows(self, rows: list[dict]) -> None:
        self.graph, self.tx_by_id = build_graph(rows)

    def _annotate_graph_with_alerts(self, alerts: list[dict]) -> None:
        if self.graph is None:
            return
        for alert in alerts:
            tx_id = alert["tx_id"]
            if tx_id not in self.graph:
                continue
            self.graph.nodes[tx_id]["threat_score"] = alert["threat_score"]
            self.graph.nodes[tx_id]["risk_level"] = alert["risk_level"]
            self.graph.nodes[tx_id]["primary_anomaly"] = alert["primary_anomaly"]
            self.graph.nodes[tx_id]["risk"] = alert["risk_level"].lower()

    def graph_elements(self, tx_id: str, hops: int | None = None) -> dict:
        self.ensure_graph()
        if self.graph is None or tx_id not in self.graph:
            return {"nodes": [], "edges": []}
        return n_hop_elements(self.graph, tx_id, hops or DEFAULT_HOPS)
