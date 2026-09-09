import json
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from .errors import ShadowTraceError
from .geoip import GeoIPEnricher
from .synthetic import make_address, make_asn, make_ip, timestamp_from_time_step, tx_id_from_index

CORE_COLUMNS = {
    "tx_id",
    "txid",
    "txId",
    "transaction_id",
    "id",
    "class",
    "label",
    "target",
    "time_step",
    "timestep",
    "step",
    "input_addresses",
    "inputs",
    "output_addresses",
    "outputs",
    "input_amounts",
    "input_satoshis",
    "output_amounts",
    "output_satoshis",
    "src_ip",
    "source_ip",
    "dst_ip",
    "destination_ip",
    "src_port",
    "source_port",
    "dst_port",
    "destination_port",
    "timestamp",
    "time",
    "parent_tx_id",
    "parent_tx_ids",
    "source_tx_id",
    "source_tx_ids",
    "prev_tx_id",
    "prev_tx_ids",
    "exchange_address",
    "exchange_addresses",
}


def _label(value: Any) -> str:
    text = str(value).strip().lower()
    if text in {"1", "illicit", "class-1"}:
        return "illicit"
    if text in {"2", "licit", "class-2"}:
        return "licit"
    if text in {"3", "unknown", "class-3"}:
        return "unknown"
    raise ValueError(f"label/class must be one of 1, 2, 3, illicit, licit, or unknown: {value}")


def _first_present(row: dict, names: list[str], default: Any = None) -> Any:
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return default


def _parse_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None or value == "":
        return []
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("["):
        return [str(item) for item in json.loads(text)]
    return [part.strip() for part in text.replace("|", ";").split(";") if part.strip()]


def _parse_amounts(value: Any) -> list[int]:
    def parse_one(item: Any) -> int:
        try:
            numeric = Decimal(str(item).strip())
        except (InvalidOperation, AttributeError) as exc:
            raise ValueError(f"amount is not numeric: {item}") from exc
        if numeric != numeric.to_integral_value():
            raise ValueError(f"amount must be an integer number of satoshis: {item}")
        amount = int(numeric)
        if amount < 0:
            raise ValueError(f"amount must be nonnegative satoshis: {item}")
        return amount

    if isinstance(value, list):
        return [parse_one(item) for item in value]
    if value is None or value == "":
        return []
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("["):
        return [parse_one(item) for item in json.loads(text)]
    return [parse_one(part.strip()) for part in text.replace("|", ";").split(";") if part.strip()]


def _numeric_feature_summary(row: dict) -> dict[str, float]:
    values = []
    for key, value in row.items():
        if key in CORE_COLUMNS or value in (None, ""):
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    if not values:
        return {}
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return {
        "elliptic_feature_count": float(len(values)),
        "elliptic_feature_mean": mean,
        "elliptic_feature_std": variance ** 0.5,
    }


def _normalize_ip(value: Any, field_name: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid IP address: {value}") from exc


def _normalize_port(value: Any, field_name: str) -> int:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} is not a valid port: {value}") from exc
    if not numeric.is_integer():
        raise ValueError(f"{field_name} must be an integer port: {value}")
    port = int(numeric)
    if not 0 <= port <= 65535:
        raise ValueError(f"{field_name} must be between 0 and 65535: {value}")
    return port


def _normalize_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    if not text:
        raise ValueError("timestamp is empty")
    try:
        numeric = float(text)
    except ValueError:
        numeric = None
    if numeric is not None:
        return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"timestamp is not ISO-8601 or Unix epoch: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_time_step(value: Any) -> int:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"time_step is not numeric: {value}") from exc
    if not numeric.is_integer():
        raise ValueError(f"time_step must be an integer in the Elliptic range 1-49: {value}")
    time_step = int(numeric)
    if not 1 <= time_step <= 49:
        raise ValueError(f"time_step must be in the Elliptic range 1-49: {value}")
    return time_step


def _read_file(path: Path):
    import polars as pl

    if path.suffix.lower() == ".csv":
        return pl.read_csv(path, infer_schema_length=10000)
    if path.suffix.lower() == ".json":
        return pl.read_json(path)
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return pl.read_ndjson(path)
    raise ShadowTraceError(400, "Malformed ingest file.", "Only CSV, JSON, and newline-delimited JSON files are supported.")


def ingest_dataset(path: Path) -> list[dict]:
    try:
        frame = _read_file(path)
    except ShadowTraceError:
        raise
    except Exception as exc:
        raise ShadowTraceError(400, "Malformed ingest file.", str(exc)) from exc

    if frame.height == 0:
        raise ShadowTraceError(400, "Empty dataset.", "The uploaded ingest file contains no transaction rows.")
    if not (set(frame.columns) & CORE_COLUMNS):
        raise ShadowTraceError(400, "Malformed ingest file.", "No recognized transaction columns were found.")

    rows = []
    seen_tx_ids = set()
    enricher = GeoIPEnricher()
    previous_illicit_change: str | None = None
    previous_illicit_time_step = 1

    try:
        for idx, row in enumerate(frame.iter_rows(named=True)):
            try:
                normalized = _normalize_row(idx, row, enricher, previous_illicit_change, previous_illicit_time_step)
            except ShadowTraceError:
                raise
            except Exception as exc:
                raise ShadowTraceError(400, "Malformed ingest file.", f"Row {idx + 1}: {exc}") from exc
            if normalized["tx_id"] in seen_tx_ids:
                raise ShadowTraceError(400, "Malformed ingest file.", f"Row {idx + 1}: duplicate transaction id {normalized['tx_id']}.")
            seen_tx_ids.add(normalized["tx_id"])
            rows.append(normalized)
            if normalized["label"] == "illicit" and len(normalized["output_addresses"]) >= 2:
                previous_illicit_change = normalized["output_addresses"][1]
                previous_illicit_time_step = normalized["time_step"]

        apply_parent_links(rows)
    finally:
        enricher.close()
    return rows


def _normalize_row(
    idx: int,
    row: dict,
    enricher: GeoIPEnricher,
    previous_illicit_change: str | None,
    previous_illicit_time_step: int,
) -> dict:
        source_tx_id = _first_present(row, ["tx_id", "txid", "txId", "transaction_id", "id"])
        tx_id = tx_id_from_index(idx, str(source_tx_id) if source_tx_id else None)
        time_step = _normalize_time_step(_first_present(row, ["time_step", "timestep", "step"], (idx % 49) + 1))
        label = _label(_first_present(row, ["class", "label", "target"], "unknown"))
        illicit = label == "illicit"

        input_addresses = _parse_list(_first_present(row, ["input_addresses", "inputs"]))
        output_addresses = _parse_list(_first_present(row, ["output_addresses", "outputs"]))
        synthesized_addresses = not input_addresses or not output_addresses
        if not input_addresses:
            if illicit and previous_illicit_change and time_step - previous_illicit_time_step <= 1:
                input_addresses = [previous_illicit_change]
            else:
                input_addresses = [make_address(f"{tx_id}:input:0", "bech32")]
        if not output_addresses:
            output_addresses = [
                make_address(f"{tx_id}:payment:0", "base58"),
                make_address(f"{tx_id}:change:0", "bech32"),
            ]

        input_amounts = _parse_amounts(_first_present(row, ["input_amounts", "input_satoshis"]))
        output_amounts = _parse_amounts(_first_present(row, ["output_amounts", "output_satoshis"]))
        synthesized_amounts = not input_amounts or not output_amounts
        if not input_amounts:
            total = int(120_000_000 + (idx % 500) * 2_000_000)
            input_amounts = [total // len(input_addresses)] * len(input_addresses)
        if len(input_amounts) != len(input_addresses):
            raise ShadowTraceError(
                400,
                "Malformed ingest file.",
                f"Transaction {tx_id} has {len(input_addresses)} input addresses but {len(input_amounts)} input amounts.",
            )
        if not output_amounts:
            total_in = sum(input_amounts)
            if len(output_addresses) == 1:
                output_amounts = [max(total_in - 10_000, 1)]
            else:
                payment_count = len(output_addresses) - 1
                payment = min(8_000_000 + (idx % 3) * 50_000, max((total_in - 15_000) // (payment_count + 1), 1))
                payments = [payment] * payment_count
                change = max(total_in - sum(payments) - 15_000, 1)
                output_amounts = payments + [change]
        if len(output_amounts) != len(output_addresses):
            raise ShadowTraceError(
                400,
                "Malformed ingest file.",
                f"Transaction {tx_id} has {len(output_addresses)} output addresses but {len(output_amounts)} output amounts.",
            )
        if sum(input_amounts) < sum(output_amounts):
            raise ShadowTraceError(
                400,
                "Malformed ingest file.",
                f"Transaction {tx_id} violates sum(inputs) >= sum(outputs).",
            )

        raw_src_ip = _first_present(row, ["src_ip", "source_ip"])
        raw_dst_ip = _first_present(row, ["dst_ip", "destination_ip"])
        raw_src_port = _first_present(row, ["src_port", "source_port"])
        raw_dst_port = _first_present(row, ["dst_port", "destination_port"])
        src_ip = _normalize_ip(raw_src_ip if raw_src_ip is not None else make_ip(f"{tx_id}:src", illicit), "src_ip")
        dst_ip = _normalize_ip(raw_dst_ip if raw_dst_ip is not None else make_ip(f"{tx_id}:dst", False), "dst_ip")
        src_port = _normalize_port(raw_src_port if raw_src_port is not None else 8333 + (idx % 200), "src_port")
        dst_port = _normalize_port(raw_dst_port if raw_dst_port is not None else 8333, "dst_port")
        synthesized_network = raw_src_ip is None or raw_dst_ip is None or raw_src_port is None or raw_dst_port is None
        fallback_asn, fallback_description = make_asn(f"{tx_id}:asn", illicit)
        geo = enricher.enrich(src_ip, fallback_asn, fallback_description)
        timestamp = _normalize_timestamp(_first_present(row, ["timestamp", "time"], timestamp_from_time_step(time_step, idx % 20)))

        parent_tx_ids = _parse_list(
            _first_present(row, ["parent_tx_ids", "parent_tx_id", "source_tx_ids", "source_tx_id", "prev_tx_ids", "prev_tx_id"])
        )
        exchange_addresses = _parse_list(_first_present(row, ["exchange_addresses", "exchange_address"]))
        return {
            "tx_id": tx_id,
            "label": label,
            "timestamp": timestamp,
            "time_step": time_step,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "asn": geo.asn,
            "asn_description": geo.asn_description,
            "country": geo.country,
            "input_addresses": input_addresses,
            "output_addresses": output_addresses,
            "input_amounts": input_amounts,
            "output_amounts": output_amounts,
            "features": _numeric_feature_summary(row),
            "heuristics": {
                "parent_tx_ids": parent_tx_ids,
                "exchange_addresses": exchange_addresses,
                "data_provenance": {
                    "dataset": "elliptic_augmented",
                    "ledger_layer": "supplied" if not synthesized_addresses and not synthesized_amounts else "synthetic",
                    "network_layer": "supplied" if not synthesized_network else "synthetic",
                    "semi_synthetic": synthesized_addresses or synthesized_amounts or synthesized_network,
                },
            },
        }


def apply_parent_links(rows: list[dict]) -> None:
    by_id = {row["tx_id"]: row for row in rows}
    for row in rows:
        parent_tx_ids = row.get("heuristics", {}).get("parent_tx_ids", [])
        for parent_tx_id in parent_tx_ids:
            parent = by_id.get(parent_tx_id)
            if parent is None:
                continue
            link_address = parent["output_addresses"][-1]
            if link_address not in row["input_addresses"]:
                row["input_addresses"].append(link_address)
                available = parent["output_amounts"][-1]
                row["input_amounts"].append(available)
            total_in = sum(row["input_amounts"])
            total_out = sum(row["output_amounts"])
            if total_in < total_out:
                row["input_amounts"][-1] += total_out - total_in + 1_000


def sample_dataset() -> list[dict]:
    rows = []
    for idx in range(90):
        label = "illicit" if idx % 7 in {0, 1, 2} else ("licit" if idx % 5 else "unknown")
        tx_id = tx_id_from_index(idx)
        input_addr = make_address(f"sample:{idx}:input")
        if rows and label == "illicit" and rows[-1]["label"] == "illicit":
            input_addr = rows[-1]["output_addresses"][1]
            timestamp = timestamp_from_time_step(rows[-1]["time_step"], (idx % 3) * 8)
            time_step = rows[-1]["time_step"]
        else:
            time_step = (idx % 49) + 1
            timestamp = timestamp_from_time_step(time_step, idx % 18)
        input_amount = 200_000_000 - idx * 500_000
        output_addresses = [make_address(f"sample:{idx}:payment", "base58"), make_address(f"sample:{idx}:change")]
        output_amounts = [8_000_000 + (idx % 2) * 10_000, input_amount - 8_020_000]
        asn, desc = make_asn(tx_id, label == "illicit")
        rows.append(
            {
                "tx_id": tx_id,
                "label": label,
                "timestamp": timestamp,
                "time_step": time_step,
                "src_ip": make_ip(tx_id, label == "illicit"),
                "dst_ip": make_ip(f"{tx_id}:dst", False),
                "src_port": 8333 + (idx % 120),
                "dst_port": 8333,
                "asn": asn,
                "asn_description": desc,
                "country": "DE" if label == "illicit" else "US",
                "input_addresses": [input_addr],
                "output_addresses": output_addresses,
                "input_amounts": [input_amount],
                "output_amounts": output_amounts,
                "features": {},
                "heuristics": {
                    "parent_tx_ids": [],
                    "exchange_addresses": [output_addresses[0]] if label == "illicit" and idx % 7 == 2 else [],
                    "data_provenance": {
                        "dataset": "elliptic_augmented",
                        "ledger_layer": "synthetic",
                        "network_layer": "synthetic",
                        "semi_synthetic": True,
                    },
                },
            }
        )
    return rows
