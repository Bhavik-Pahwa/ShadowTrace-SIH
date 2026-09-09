import hashlib
import ipaddress
import random
from datetime import datetime, timezone, timedelta

from .config import SATOSHIS_PER_BTC

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "023456789acdefghjklmnpqrstuvwxyz"
TOR_SUBNETS = ["185.220.101.0/24", "45.95.147.0/24", "51.15.0.0/16"]
BULLETPROOF_ASNS = [
    ("AS208323", "Tor Transit"),
    ("AS43350", "NForce Entertainment B.V."),
    ("AS9009", "M247 Europe SRL"),
]
NORMAL_ASNS = [
    ("AS15169", "Google LLC"),
    ("AS13335", "Cloudflare"),
    ("AS8075", "Microsoft Corporation"),
    ("AS16509", "Amazon.com"),
]


def seed_for(value: str) -> random.Random:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def tx_id_from_index(index: int, source_id: str | None = None) -> str:
    if source_id:
        return source_id
    return "txid_" + hashlib.sha256(f"shadowtrace:{index}".encode()).hexdigest()[:24]


def timestamp_from_time_step(time_step: int, offset_seconds: int = 0) -> str:
    base = datetime(2024, 8, 29, 0, 0, tzinfo=timezone.utc)
    ts = base + timedelta(minutes=(int(time_step) - 1) * 10, seconds=offset_seconds)
    return ts.isoformat().replace("+00:00", "Z")


def make_address(seed: str, kind: str = "bech32") -> str:
    rng = seed_for(seed)
    if kind == "base58":
        return "1" + "".join(rng.choice(BASE58) for _ in range(33))
    return "bc1q" + "".join(rng.choice(BECH32) for _ in range(38))


def make_ip(seed: str, illicit: bool) -> str:
    rng = seed_for(seed)
    subnet = ipaddress.ip_network(rng.choice(TOR_SUBNETS if illicit else ["8.8.8.0/24", "1.1.1.0/24", "13.32.0.0/15"]))
    host = rng.randint(1, min(subnet.num_addresses - 2, 250))
    return str(subnet.network_address + host)


def make_asn(seed: str, illicit: bool) -> tuple[str, str]:
    rng = seed_for(seed)
    return rng.choice(BULLETPROOF_ASNS if illicit else NORMAL_ASNS)


def satoshis_to_btc(value: int) -> float:
    return round(value / SATOSHIS_PER_BTC, 8)
