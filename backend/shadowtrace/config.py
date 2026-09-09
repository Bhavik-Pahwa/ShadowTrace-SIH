import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
SOURCE_TEMPLATES_DIR = BASE_DIR / "templates"
PACKAGE_TEMPLATES_DIR = PACKAGE_DIR / "templates"
TEMPLATES_DIR = SOURCE_TEMPLATES_DIR if SOURCE_TEMPLATES_DIR.exists() else PACKAGE_TEMPLATES_DIR
DB_PATH = Path(os.environ.get("SHADOWTRACE_DB_PATH", DATA_DIR / "shadowtrace.duckdb"))
REQUIRE_GEOIP = os.environ.get("SHADOWTRACE_REQUIRE_GEOIP") == "1"
REQUIRE_PYG_EXTENSIONS = os.environ.get("SHADOWTRACE_REQUIRE_PYG_EXTENSIONS") == "1"
GEOIP_DIR = DATA_DIR / "geoip"
CITY_DB = GEOIP_DIR / "GeoLite2-City.mmdb"
ASN_DB = GEOIP_DIR / "GeoLite2-ASN.mmdb"

DEFAULT_HOPS = 4
PEEL_DELTA_SECONDS = 25
FAN_PATTERN_DELTA_SECONDS = 25
DOSSIER_RENDER_TARGET_SECONDS = 2.0
SATOSHIS_PER_BTC = 100_000_000

for path in (DATA_DIR, REPORTS_DIR, SOURCE_TEMPLATES_DIR, GEOIP_DIR):
    path.mkdir(parents=True, exist_ok=True)
