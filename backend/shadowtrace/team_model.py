from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

import polars as pl

from .config import BASE_DIR


TEAM_MODEL_ROOT = Path(os.environ.get("SHADOWTRACE_TEAM_MODEL_ROOT", BASE_DIR.parent / "ML MODEL FOR SIH" / "src"))
TEAM_MODEL_WEIGHTS = Path(os.environ.get("SHADOWTRACE_TEAM_MODEL_WEIGHTS", TEAM_MODEL_ROOT / "shadowtrace.pt"))
TEAM_MODEL_NODES = Path(os.environ.get("SHADOWTRACE_TEAM_MODEL_NODES", TEAM_MODEL_ROOT / "outputs" / "nodes.csv"))
TEAM_MODEL_EDGES = Path(os.environ.get("SHADOWTRACE_TEAM_MODEL_EDGES", TEAM_MODEL_ROOT / "outputs" / "edges.csv"))
TEAM_MODEL_XAI = Path(os.environ.get("SHADOWTRACE_TEAM_MODEL_XAI", TEAM_MODEL_ROOT / "outputs" / "xai_sample.json"))
FEEDBACK_DB = Path(os.environ.get("SHADOWTRACE_FEEDBACK_DB", BASE_DIR / "data" / "feedback.db"))


class TeamModelUnavailable(RuntimeError):
    pass


@dataclass
class TeamPrediction:
    tx_id: str
    risk_score: float
    risk_level: str
    prediction: str
    xai_explanation: dict[str, Any]


class ShadowTraceGraphSAGEAdapter:
    def __init__(
        self,
        model_root: Path = TEAM_MODEL_ROOT,
        weights_path: Path = TEAM_MODEL_WEIGHTS,
        nodes_path: Path = TEAM_MODEL_NODES,
        edges_path: Path = TEAM_MODEL_EDGES,
        xai_path: Path = TEAM_MODEL_XAI,
    ) -> None:
        self.model_root = model_root
        self.weights_path = weights_path
        self.nodes_path = nodes_path
        self.edges_path = edges_path
        self.xai_path = xai_path
        self._model = None
        self._feature_columns: list[str] | None = None
        self._xai_payload: dict | None = None

    def predict(self, tx_id: str) -> TeamPrediction:
        self._require_assets()
        node_ids = self._local_node_ids(tx_id)
        if tx_id not in node_ids:
            raise KeyError(tx_id)
        node_rows = self._node_rows(node_ids)
        if not node_rows:
            raise KeyError(tx_id)
        logits = self._run_model(node_rows, self._edge_rows(node_ids))
        root_idx = next(index for index, row in enumerate(node_rows) if str(row["txId"]) == tx_id)
        risk_score = logits[root_idx]
        return TeamPrediction(
            tx_id=tx_id,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            prediction="suspicious" if risk_score >= 0.5 else "licit",
            xai_explanation=self._xai_explanation(tx_id),
        )

    def _require_assets(self) -> None:
        missing = [
            str(path)
            for path in (self.weights_path, self.nodes_path, self.edges_path, self.xai_path)
            if not path.exists()
        ]
        if missing:
            raise TeamModelUnavailable("Missing team ML assets: " + ", ".join(missing))

    def _feature_names(self) -> list[str]:
        if self._feature_columns is None:
            columns = pl.scan_csv(self.nodes_path, n_rows=1).collect_schema().names()
            self._feature_columns = [name for name in columns if name not in {"txId", "class", "time_step"}]
        return self._feature_columns

    def _local_node_ids(self, tx_id: str) -> set[str]:
        edges = (
            pl.scan_csv(self.edges_path, schema_overrides={"source": pl.Utf8, "target": pl.Utf8})
            .filter((pl.col("source") == tx_id) | (pl.col("target") == tx_id))
            .select(["source", "target"])
            .collect()
        )
        node_ids = {tx_id}
        for row in edges.iter_rows(named=True):
            node_ids.add(str(row["source"]))
            node_ids.add(str(row["target"]))
        return node_ids

    def _node_rows(self, node_ids: set[str]) -> list[dict]:
        rows = (
            pl.scan_csv(self.nodes_path, schema_overrides={"txId": pl.Utf8})
            .filter(pl.col("txId").is_in(sorted(node_ids)))
            .collect()
            .to_dicts()
        )
        return sorted(rows, key=lambda row: (str(row["txId"]) != min(node_ids), str(row["txId"])))

    def _edge_rows(self, node_ids: set[str]) -> list[dict]:
        return (
            pl.scan_csv(self.edges_path, schema_overrides={"source": pl.Utf8, "target": pl.Utf8})
            .filter(pl.col("source").is_in(sorted(node_ids)) & pl.col("target").is_in(sorted(node_ids)))
            .select(["source", "target"])
            .collect()
            .to_dicts()
        )

    def _load_model(self):
        if self._model is not None:
            return self._model
        try:
            import torch
            import torch.nn.functional as F
            from torch_geometric.nn import SAGEConv
        except Exception as exc:
            raise TeamModelUnavailable(f"PyTorch Geometric GraphSAGE imports failed: {exc}") from exc

        class ShadowTraceGNN(torch.nn.Module):
            def __init__(self, in_channels: int, hidden_channels: int, out_channels: int = 1):
                super().__init__()
                self.conv1 = SAGEConv(in_channels, hidden_channels)
                self.conv2 = SAGEConv(hidden_channels, hidden_channels)
                self.conv3 = SAGEConv(hidden_channels, out_channels)

            def forward(self, x, edge_index):
                x = self.conv1(x, edge_index)
                x = F.relu(x)
                x = F.dropout(x, p=0.4, training=self.training)
                x = self.conv2(x, edge_index)
                x = F.relu(x)
                x = F.dropout(x, p=0.4, training=self.training)
                x = self.conv3(x, edge_index)
                return x.squeeze()

        model = ShadowTraceGNN(in_channels=len(self._feature_names()), hidden_channels=64)
        state = torch.load(self.weights_path, map_location="cpu")
        model.load_state_dict(state)
        model.eval()
        self._model = model
        return model

    def _run_model(self, node_rows: list[dict], edge_rows: list[dict]) -> list[float]:
        import torch

        feature_names = self._feature_names()
        node_index = {str(row["txId"]): index for index, row in enumerate(node_rows)}
        x = torch.tensor(
            [[float(row.get(name) or 0.0) for name in feature_names] for row in node_rows],
            dtype=torch.float,
        )
        edges = [
            (node_index[str(row["source"])], node_index[str(row["target"])])
            for row in edge_rows
            if str(row["source"]) in node_index and str(row["target"]) in node_index
        ]
        edges.extend((index, index) for index in range(len(node_rows)))
        edge_index = torch.tensor(sorted(set(edges)), dtype=torch.long).t().contiguous()
        with torch.no_grad():
            scores = torch.sigmoid(self._load_model()(x, edge_index)).detach().cpu().flatten().tolist()
        return [round(float(score), 6) for score in scores]

    def _xai_explanation(self, tx_id: str) -> dict[str, Any]:
        if self._xai_payload is None:
            self._xai_payload = json.loads(self.xai_path.read_text(encoding="utf-8"))
        weights = list(enumerate(self._xai_payload.get("feature_weights", []), start=1))
        top_weights = sorted(weights, key=lambda item: abs(float(item[1])), reverse=True)[:5]
        return {
            "target_node": self._xai_payload.get("target_node", tx_id),
            "feature_weights": [
                {"feature": f"feat_{index}", "weight": float(weight)}
                for index, weight in top_weights
            ],
        }

    @staticmethod
    def _risk_level(risk_score: float) -> str:
        score = risk_score * 100
        if score >= 90:
            return "CRITICAL"
        if score >= 75:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        return "LOW"


def record_feedback(tx_id: str, ai_score: float, human_label: int, reviewed_by: str) -> dict:
    if human_label not in {0, 1}:
        raise ValueError("human_label must be 0 for false positive or 1 for confirmed illicit")
    FEEDBACK_DB.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(FEEDBACK_DB) as conn:
        conn.execute(
            """
            create table if not exists feedback (
                id integer primary key autoincrement,
                tx_id text not null,
                ai_score real not null,
                human_label integer not null,
                reviewed_by text not null,
                timestamp text not null
            )
            """
        )
        conn.execute(
            """
            insert into feedback (tx_id, ai_score, human_label, reviewed_by, timestamp)
            values (?, ?, ?, ?, ?)
            """,
            [tx_id, ai_score, human_label, reviewed_by, timestamp],
        )
    return {
        "status": "success",
        "message": f"Feedback logged. Node {tx_id} queued for next training batch.",
        "recorded_timestamp": timestamp,
    }


team_model_adapter = ShadowTraceGraphSAGEAdapter()
