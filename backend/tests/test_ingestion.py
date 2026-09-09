import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.graph_builder import build_graph
from shadowtrace.ingestion import ingest_dataset
from shadowtrace.errors import ShadowTraceError


def test_elliptic_style_txid_numeric_features_and_parent_links(tmp_path):
    csv_path = tmp_path / "elliptic_augmented.csv"
    csv_path.write_text(
        "\n".join(
            [
                "txId,class,time_step,feature_1,feature_2,parent_tx_id",
                "parent_tx,1,1,0.5,1.5,",
                "child_tx,1,1,1.0,2.0,parent_tx",
            ]
        ),
        encoding="utf-8",
    )
    rows = ingest_dataset(csv_path)
    parent, child = rows
    assert parent["tx_id"] == "parent_tx"
    assert child["tx_id"] == "child_tx"
    assert child["heuristics"]["parent_tx_ids"] == ["parent_tx"]
    assert child["heuristics"]["data_provenance"]["semi_synthetic"] is True
    assert child["heuristics"]["data_provenance"]["network_layer"] == "synthetic"
    assert parent["output_addresses"][-1] in child["input_addresses"]
    assert child["features"]["elliptic_feature_count"] == 2.0
    graph, _ = build_graph(rows)
    shared_wallet = parent["output_addresses"][-1]
    assert graph.has_edge("parent_tx", shared_wallet)
    assert graph.has_edge(shared_wallet, "child_tx")


def test_ingest_uses_polars_row_iterator_instead_of_full_dict_copy():
    source = Path(__file__).resolve().parents[1] / "shadowtrace" / "ingestion.py"
    text = source.read_text(encoding="utf-8")
    assert ".iter_rows(named=True)" in text
    assert ".to_dicts()" not in text


def test_ingest_closes_geoip_enricher_after_row_processing(tmp_path, monkeypatch):
    import shadowtrace.ingestion as ingestion

    closed = []

    class FakeGeoIPEnricher:
        def enrich(self, _ip, fallback_asn, fallback_description):
            return SimpleNamespace(country="US", asn=fallback_asn, asn_description=fallback_description)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(ingestion, "GeoIPEnricher", FakeGeoIPEnricher)
    csv_path = tmp_path / "geoip_close.csv"
    csv_path.write_text("tx_id,class,time_step\ntx_close,1,1\n", encoding="utf-8")

    rows = ingest_dataset(csv_path)

    assert rows[0]["tx_id"] == "tx_close"
    assert closed == [True]


def test_geoip_enricher_closes_open_reader_when_second_reader_fails(tmp_path, monkeypatch):
    import sys
    import types

    import shadowtrace.geoip as geoip

    city_db = tmp_path / "GeoLite2-City.mmdb"
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    city_db.write_bytes(b"city")
    asn_db.write_bytes(b"asn")
    closed = []

    class Reader:
        def __init__(self, path):
            self.path = path
            if path == str(asn_db):
                raise ValueError("bad asn db")

        def close(self):
            closed.append(self.path)

    geoip_module = types.ModuleType("geoip2")
    database_module = types.ModuleType("geoip2.database")
    database_module.Reader = Reader
    geoip_module.database = database_module
    monkeypatch.setitem(sys.modules, "geoip2", geoip_module)
    monkeypatch.setitem(sys.modules, "geoip2.database", database_module)
    monkeypatch.setattr(geoip, "CITY_DB", city_db)
    monkeypatch.setattr(geoip, "ASN_DB", asn_db)

    with pytest.raises(ValueError, match="bad asn db"):
        geoip.GeoIPEnricher()

    assert closed == [str(city_db)]


def test_geoip_enricher_strict_mode_requires_both_databases(tmp_path, monkeypatch):
    import shadowtrace.geoip as geoip

    city_db = tmp_path / "GeoLite2-City.mmdb"
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    city_db.write_bytes(b"city")
    monkeypatch.setattr(geoip, "CITY_DB", city_db)
    monkeypatch.setattr(geoip, "ASN_DB", asn_db)
    monkeypatch.setattr(geoip, "REQUIRE_GEOIP", True)

    with pytest.raises(FileNotFoundError, match="Required GeoIP database files are missing"):
        geoip.GeoIPEnricher()


def test_ingest_rejects_address_amount_length_mismatch(tmp_path):
    csv_path = tmp_path / "bad_lengths.csv"
    csv_path.write_text(
        "\n".join(
            [
                "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts",
                "tx_bad,1,1,bc1qin1;bc1qin2,bc1qout,100000000,90000000",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)
    assert exc.value.code == 400
    assert "input addresses but 1 input amounts" in exc.value.details


def test_ingest_rejects_files_without_recognized_transaction_columns(tmp_path):
    csv_path = tmp_path / "not_transactions.csv"
    csv_path.write_text("foo,bar\nalpha,beta\n", encoding="utf-8")

    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)

    assert exc.value.code == 400
    assert exc.value.message == "Malformed ingest file."
    assert exc.value.details == "No recognized transaction columns were found."


def test_ingest_generates_balanced_amounts_for_many_outputs(tmp_path):
    csv_path = tmp_path / "many_outputs.csv"
    csv_path.write_text(
        "\n".join(
            [
                "tx_id,class,time_step,output_addresses",
                "tx_many,1,1,bc1qout1;bc1qout2;bc1qout3;bc1qchange",
            ]
        ),
        encoding="utf-8",
    )
    row = ingest_dataset(csv_path)[0]
    assert len(row["output_amounts"]) == len(row["output_addresses"])
    assert sum(row["input_amounts"]) >= sum(row["output_amounts"])
    assert row["heuristics"]["data_provenance"]["semi_synthetic"] is True


def test_ingest_marks_supplied_ledger_and_network_provenance(tmp_path):
    csv_path = tmp_path / "supplied.csv"
    csv_path.write_text(
        "\n".join(
            [
                "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts,src_ip,dst_ip,src_port,dst_port",
                "tx_supplied,2,1,bc1qin,bc1qout,100000000,99990000,8.8.8.8,1.1.1.1,8333,18333",
            ]
        ),
        encoding="utf-8",
    )
    row = ingest_dataset(csv_path)[0]
    provenance = row["heuristics"]["data_provenance"]
    assert provenance == {
        "dataset": "elliptic_augmented",
        "ledger_layer": "supplied",
        "network_layer": "supplied",
        "semi_synthetic": False,
    }


def test_ingest_normalizes_unix_epoch_timestamp(tmp_path):
    csv_path = tmp_path / "epoch.csv"
    csv_path.write_text(
        "\n".join(
            [
                "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts,src_ip,dst_ip,src_port,dst_port,timestamp",
                "tx_epoch,2,1,bc1qin,bc1qout,100000000,99990000,8.8.8.8,1.1.1.1,8333,18333,1724939100",
            ]
        ),
        encoding="utf-8",
    )
    row = ingest_dataset(csv_path)[0]
    assert row["timestamp"] == "2024-08-29T13:45:00Z"


def test_ingest_maps_class_3_to_unknown(tmp_path):
    csv_path = tmp_path / "unknown.csv"
    csv_path.write_text("tx_id,class,time_step\ntx_unknown,3,1\n", encoding="utf-8")
    row = ingest_dataset(csv_path)[0]
    assert row["label"] == "unknown"


def test_ingest_rejects_invalid_class_labels(tmp_path):
    csv_path = tmp_path / "bad_label.csv"
    csv_path.write_text("tx_id,class,time_step\ntx_bad_label,definitely-not-a-class,1\n", encoding="utf-8")

    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)

    assert exc.value.code == 400
    assert exc.value.message == "Malformed ingest file."
    assert "label/class must be one of" in exc.value.details


def test_ingest_rejects_duplicate_transaction_ids(tmp_path):
    csv_path = tmp_path / "duplicate.csv"
    csv_path.write_text("tx_id,class,time_step\ntx_dup,1,1\ntx_dup,2,2\n", encoding="utf-8")

    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)

    assert exc.value.code == 400
    assert exc.value.message == "Malformed ingest file."
    assert exc.value.details == "Row 2: duplicate transaction id tx_dup."


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", "time_step must be in the Elliptic range 1-49"),
        ("50", "time_step must be in the Elliptic range 1-49"),
        ("2.5", "time_step must be an integer in the Elliptic range 1-49"),
        ("not-a-step", "time_step is not numeric"),
    ],
)
def test_ingest_rejects_invalid_time_steps(tmp_path, value, expected):
    csv_path = tmp_path / "bad_timestep.csv"
    csv_path.write_text(f"tx_id,class,time_step\ntx_bad,1,{value}\n", encoding="utf-8")

    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)

    assert exc.value.code == 400
    assert exc.value.message == "Malformed ingest file."
    assert expected in exc.value.details


@pytest.mark.parametrize(
    ("column", "value", "expected"),
    [
        ("src_ip", "not-an-ip", "src_ip is not a valid IP address"),
        ("dst_ip", "999.1.1.1", "dst_ip is not a valid IP address"),
        ("src_port", "70000", "src_port must be between 0 and 65535"),
        ("dst_port", "8333.5", "dst_port must be an integer port"),
        ("timestamp", "not-a-timestamp", "timestamp is not ISO-8601 or Unix epoch"),
    ],
)
def test_ingest_rejects_invalid_network_and_timestamp_fields(tmp_path, column, value, expected):
    values = {
        "tx_id": "tx_invalid",
        "class": "1",
        "time_step": "1",
        "input_addresses": "bc1qin",
        "output_addresses": "bc1qout",
        "input_amounts": "100000000",
        "output_amounts": "99990000",
        "src_ip": "8.8.8.8",
        "dst_ip": "1.1.1.1",
        "src_port": "8333",
        "dst_port": "18333",
        "timestamp": "2024-08-29T13:45:00Z",
    }
    values[column] = value
    csv_path = tmp_path / f"invalid_{column}.csv"
    headers = list(values)
    csv_path.write_text(
        ",".join(headers) + "\n" + ",".join(values[name] for name in headers) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)

    assert exc.value.code == 400
    assert exc.value.message == "Malformed ingest file."
    assert expected in exc.value.details


@pytest.mark.parametrize(
    ("column", "value", "expected"),
    [
        ("input_amounts", "100.5", "amount must be an integer number of satoshis"),
        ("output_amounts", "-1", "amount must be nonnegative satoshis"),
    ],
)
def test_ingest_rejects_invalid_satoshi_amounts(tmp_path, column, value, expected):
    values = {
        "tx_id": "tx_bad_amount",
        "class": "1",
        "time_step": "1",
        "input_addresses": "bc1qin",
        "output_addresses": "bc1qout",
        "input_amounts": "100000000",
        "output_amounts": "99990000",
    }
    values[column] = value
    csv_path = tmp_path / f"invalid_{column}.csv"
    headers = list(values)
    csv_path.write_text(
        ",".join(headers) + "\n" + ",".join(values[name] for name in headers) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ShadowTraceError) as exc:
        ingest_dataset(csv_path)

    assert exc.value.code == 400
    assert exc.value.message == "Malformed ingest file."
    assert expected in exc.value.details


def test_ingest_preserves_large_integer_satoshi_amounts_exactly(tmp_path):
    csv_path = tmp_path / "large_satoshis.csv"
    csv_path.write_text(
        "\n".join(
            [
                "tx_id,class,time_step,input_addresses,output_addresses,input_amounts,output_amounts",
                "tx_large,2,1,bc1qin,bc1qout,100000000000000001,100000000000000000",
            ]
        ),
        encoding="utf-8",
    )

    row = ingest_dataset(csv_path)[0]

    assert row["input_amounts"] == [100000000000000001]
    assert row["output_amounts"] == [100000000000000000]


def test_ingest_supports_json_array_dataset(tmp_path):
    json_path = tmp_path / "elliptic_augmented.json"
    json_path.write_text(
        """
[
  {
    "txId": "json_tx",
    "class": 1,
    "time_step": 3,
    "input_addresses": ["bc1qin"],
    "output_addresses": ["bc1qout"],
    "input_amounts": [100000000],
    "output_amounts": [99990000],
    "src_ip": "8.8.8.8",
    "dst_ip": "1.1.1.1",
    "src_port": 8333,
    "dst_port": 18333,
    "feature_1": 4.5
  }
]
""".strip(),
        encoding="utf-8",
    )

    row = ingest_dataset(json_path)[0]

    assert row["tx_id"] == "json_tx"
    assert row["label"] == "illicit"
    assert row["input_addresses"] == ["bc1qin"]
    assert row["output_amounts"] == [99990000]
    assert row["features"]["elliptic_feature_mean"] == 4.5
    assert row["heuristics"]["data_provenance"]["semi_synthetic"] is False


def test_ingest_supports_single_json_object_dataset(tmp_path):
    json_path = tmp_path / "single_transaction.json"
    json_path.write_text(
        """
{
  "txId": "json_object_tx",
  "class": 2,
  "time_step": 4,
  "input_addresses": ["bc1qin"],
  "output_addresses": ["bc1qout"],
  "input_amounts": [100000000],
  "output_amounts": [99990000],
  "src_ip": "8.8.8.8",
  "dst_ip": "1.1.1.1",
  "src_port": 8333,
  "dst_port": 18333
}
""".strip(),
        encoding="utf-8",
    )

    row = ingest_dataset(json_path)[0]

    assert row["tx_id"] == "json_object_tx"
    assert row["label"] == "licit"
    assert row["input_addresses"] == ["bc1qin"]
    assert row["heuristics"]["data_provenance"]["semi_synthetic"] is False
