import json
from pathlib import Path
from typing import Iterable

from .config import DB_PATH


class DuckDBStore:
    def __init__(self, db_path: Path = DB_PATH):
        import duckdb

        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            create table if not exists transactions (
                tx_id varchar primary key,
                label varchar,
                timestamp varchar,
                time_step integer,
                src_ip varchar,
                dst_ip varchar,
                src_port integer,
                dst_port integer,
                asn varchar,
                asn_description varchar,
                country varchar,
                input_addresses json,
                output_addresses json,
                input_amounts json,
                output_amounts json,
                features json,
                heuristics json
            )
            """
        )
        self.conn.execute(
            """
            create table if not exists alerts (
                tx_id varchar primary key,
                threat_score integer,
                timestamp varchar,
                primary_anomaly varchar,
                risk_level varchar
            )
            """
        )
        self.conn.execute(
            """
            create table if not exists evidence (
                tx_id varchar primary key,
                overall_threat_score integer,
                xai_breakdown json,
                chain_of_custody_hash varchar,
                xai_subgraph json
            )
            """
        )
        self._ensure_column("evidence", "xai_subgraph", "json")
        self.conn.execute(
            """
            create table if not exists model_runs (
                run_id varchar primary key,
                scoring_engine varchar,
                validation_metrics json
            )
            """
        )

    def _ensure_column(self, table: str, column: str, column_type: str) -> None:
        exists = self.conn.execute(
            """
            select count(*)
            from information_schema.columns
            where table_name = ? and column_name = ?
            """,
            [table, column],
        ).fetchone()[0]
        if not exists:
            self.conn.execute(f"alter table {table} add column {column} {column_type}")

    def reset(self) -> None:
        for table in ("transactions", "alerts", "evidence", "model_runs"):
            self.conn.execute(f"delete from {table}")

    def insert_transactions(self, rows: Iterable[dict]) -> int:
        rows = list(rows)
        if not rows:
            return 0
        values = []
        for row in rows:
            values.append(
                (
                    row["tx_id"],
                    row["label"],
                    row["timestamp"],
                    row["time_step"],
                    row["src_ip"],
                    row["dst_ip"],
                    row["src_port"],
                    row["dst_port"],
                    row["asn"],
                    row["asn_description"],
                    row.get("country"),
                    json.dumps(row["input_addresses"], sort_keys=True),
                    json.dumps(row["output_addresses"], sort_keys=True),
                    json.dumps(row["input_amounts"], sort_keys=True),
                    json.dumps(row["output_amounts"], sort_keys=True),
                    json.dumps(row.get("features", {}), sort_keys=True),
                    json.dumps(row.get("heuristics", {}), sort_keys=True),
                )
            )
        self.conn.executemany(
            """
            insert or replace into transactions values (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            values,
        )
        return len(rows)

    def update_transaction_annotations(self, tx_id: str, features: dict, heuristics: dict) -> None:
        self.conn.execute(
            "update transactions set features = ?, heuristics = ? where tx_id = ?",
            [json.dumps(features, sort_keys=True), json.dumps(heuristics, sort_keys=True), tx_id],
        )

    def insert_alerts(self, alerts: Iterable[dict]) -> None:
        alerts = list(alerts)
        self.conn.execute("delete from alerts")
        if not alerts:
            return
        self.conn.executemany(
            "insert or replace into alerts values (?, ?, ?, ?, ?)",
            [(a["tx_id"], a["threat_score"], a["timestamp"], a["primary_anomaly"], a["risk_level"]) for a in alerts],
        )

    def insert_evidence(self, evidence: Iterable[dict]) -> None:
        evidence = list(evidence)
        self.conn.execute("delete from evidence")
        if not evidence:
            return
        self.conn.executemany(
            "insert or replace into evidence values (?, ?, ?, ?, ?)",
            [
                (
                    item["tx_id"],
                    item["overall_threat_score"],
                    json.dumps(item["xai_breakdown"], sort_keys=True),
                    item["chain_of_custody_hash"],
                    json.dumps(item.get("xai_subgraph", {}), sort_keys=True),
                )
                for item in evidence
            ],
        )

    def save_model_run(self, scoring_engine: str, validation_metrics: dict) -> None:
        self.conn.execute("delete from model_runs")
        self.conn.execute(
            "insert into model_runs values (?, ?, ?)",
            ["latest", scoring_engine, json.dumps(validation_metrics, sort_keys=True)],
        )

    def fetch_model_run(self) -> dict | None:
        row = self.conn.execute(
            "select run_id, scoring_engine, validation_metrics from model_runs where run_id = ?",
            ["latest"],
        ).fetchone()
        if row is None:
            return None
        return {
            "run_id": row[0],
            "scoring_engine": row[1],
            "validation_metrics": json.loads(row[2]),
        }

    def fetch_transactions(self) -> list[dict]:
        rows = self.conn.execute("select * from transactions order by timestamp, tx_id").fetchall()
        cols = [d[0] for d in self.conn.description]
        return [self._decode(dict(zip(cols, row))) for row in rows]

    def fetch_transaction(self, tx_id: str) -> dict | None:
        row = self.conn.execute("select * from transactions where tx_id = ?", [tx_id]).fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self.conn.description]
        return self._decode(dict(zip(cols, row)))

    def count_alerts(self) -> int:
        return int(self.conn.execute("select count(*) from alerts").fetchone()[0])

    def close(self) -> None:
        self.conn.close()

    def fetch_alerts(self, limit: int, offset: int) -> list[dict]:
        rows = self.conn.execute(
            """
            select tx_id, threat_score, timestamp, primary_anomaly, risk_level
            from alerts
            order by threat_score desc, timestamp desc
            limit ? offset ?
            """,
            [limit, offset],
        ).fetchall()
        return [
            {
                "tx_id": row[0],
                "threat_score": row[1],
                "timestamp": row[2],
                "primary_anomaly": row[3],
                "risk_level": row[4],
            }
            for row in rows
        ]

    def fetch_all_alerts(self) -> list[dict]:
        rows = self.conn.execute(
            """
            select tx_id, threat_score, timestamp, primary_anomaly, risk_level
            from alerts
            """
        ).fetchall()
        return [
            {
                "tx_id": row[0],
                "threat_score": row[1],
                "timestamp": row[2],
                "primary_anomaly": row[3],
                "risk_level": row[4],
            }
            for row in rows
        ]

    def fetch_alert(self, tx_id: str) -> dict | None:
        row = self.conn.execute(
            """
            select tx_id, threat_score, timestamp, primary_anomaly, risk_level
            from alerts
            where tx_id = ?
            """,
            [tx_id],
        ).fetchone()
        if row is None:
            return None
        return {
            "tx_id": row[0],
            "threat_score": row[1],
            "timestamp": row[2],
            "primary_anomaly": row[3],
            "risk_level": row[4],
        }

    def fetch_evidence(self, tx_id: str) -> dict | None:
        row = self.conn.execute(
            "select tx_id, overall_threat_score, xai_breakdown, chain_of_custody_hash from evidence where tx_id = ?",
            [tx_id],
        ).fetchone()
        if row is None:
            return None
        return {
            "tx_id": row[0],
            "overall_threat_score": row[1],
            "xai_breakdown": json.loads(row[2]),
            "chain_of_custody_hash": row[3],
        }

    def fetch_evidence_with_subgraph(self, tx_id: str) -> dict | None:
        row = self.conn.execute(
            "select tx_id, overall_threat_score, xai_breakdown, chain_of_custody_hash, xai_subgraph from evidence where tx_id = ?",
            [tx_id],
        ).fetchone()
        if row is None:
            return None
        return {
            "tx_id": row[0],
            "overall_threat_score": row[1],
            "xai_breakdown": json.loads(row[2]),
            "chain_of_custody_hash": row[3],
            "xai_subgraph": json.loads(row[4]) if row[4] else {},
        }

    @staticmethod
    def _decode(row: dict) -> dict:
        for key in ("input_addresses", "output_addresses", "input_amounts", "output_amounts", "features", "heuristics"):
            if isinstance(row.get(key), str):
                row[key] = json.loads(row[key])
        return row
