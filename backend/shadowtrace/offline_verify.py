import argparse
from contextlib import contextmanager
import importlib.util
import os
import socket
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

from .config import ASN_DB, CITY_DB, DOSSIER_RENDER_TARGET_SECONDS

REQUIRED = [
    "fastapi",
    "uvicorn",
    "polars",
    "duckdb",
    "networkx",
    "geoip2",
    "torch",
    "torch_geometric",
    "jinja2",
    "weasyprint",
    "shap",
]

PYG_EXTENSIONS = ["torch_scatter", "torch_sparse"]
SUPPORTED_PYTHON_MIN = (3, 10)
SUPPORTED_PYTHON_MAX_EXCLUSIVE = (3, 13)
REQUIRED_WHEELS = {
    "fastapi": "0.116.1",
    "uvicorn": "0.35.0",
    "python_multipart": "0.0.20",
    "polars": "1.32.3",
    "duckdb": "1.3.2",
    "networkx": "3.4.2",
    "geoip2": "5.1.0",
    "jinja2": "3.1.6",
    "weasyprint": "66.0",
    "numpy": "2.1.3",
    "scikit_learn": "1.6.1",
    "shap": "0.46.0",
    "torch": "2.5.1",
    "torch_geometric": "2.6.1",
    "torch_scatter": "2.1.2",
    "torch_sparse": "0.6.18",
    "pytest": "8.3.5",
    "httpx": "0.28.1",
}

REQUIREMENT_FILES = ["requirements.txt", "requirements-pyg-extensions.txt"]


def module_exists(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def wheelhouse_status(
    wheelhouse: Path,
    python_tag: str | None = None,
    abi_tag: str | None = None,
    platform_tag: str | None = None,
) -> tuple[bool, list[str]]:
    wheels = [path.name for path in wheelhouse.glob("*.whl")] if wheelhouse.exists() else []
    python_tag = python_tag or _runtime_python_tag()
    abi_tag = abi_tag or python_tag
    platform_tag = platform_tag or _runtime_platform_tag()
    missing = [
        f"{name}=={version}"
        for name, version in REQUIRED_WHEELS.items()
        if not any(_wheel_satisfies(wheel, name, version, python_tag, abi_tag, platform_tag) for wheel in wheels)
    ]
    return not missing, missing


def offline_pip_resolver_status(wheelhouse: Path, backend_root: Path | None = None) -> tuple[bool, list[str]]:
    backend_root = backend_root or Path(__file__).resolve().parents[1]
    if not wheelhouse.exists():
        return False, [f"wheelhouse missing: {wheelhouse}"]
    issues = []
    for requirements_name in REQUIREMENT_FILES:
        requirements_path = backend_root / requirements_name
        if not requirements_path.exists():
            issues.append(f"requirements file missing: {requirements_path}")
            continue
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--no-index",
                "--find-links",
                str(wheelhouse),
                "-r",
                str(requirements_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            details = (result.stderr or result.stdout).strip().splitlines()
            issues.append(f"{requirements_name} offline resolver failed: {details[-1] if details else 'pip exited nonzero'}")
    return not issues, issues


def _runtime_python_tag() -> str:
    major, minor = sys.version_info[:2]
    if sys.implementation.name == "cpython":
        return f"cp{major}{minor}"
    return f"py{major}"


def _runtime_platform_tag() -> str:
    return _normalize_tag(sysconfig.get_platform())


def _normalize_tag(value: str) -> str:
    return value.lower().replace("-", "_").replace(".", "_")


def _wheel_satisfies(
    wheel_name: str,
    package_name: str,
    version: str,
    python_tag: str,
    abi_tag: str,
    platform_tag: str,
) -> bool:
    parsed = _parse_wheel_filename(wheel_name)
    if parsed is None:
        return False
    dist, wheel_version, wheel_python, wheel_abi, wheel_platform = parsed
    if dist != package_name.lower().replace("-", "_"):
        return False
    if wheel_version.split("+", 1)[0] != version.lower():
        return False
    return _wheel_tags_compatible(wheel_python, wheel_abi, wheel_platform, python_tag, abi_tag, platform_tag)


def _parse_wheel_filename(wheel_name: str) -> tuple[str, str, str, str, str] | None:
    normalized = wheel_name.lower()
    if not normalized.endswith(".whl"):
        return None
    stem = normalized[:-4]
    parts = stem.split("-")
    if len(parts) < 5:
        return None
    python_tag, abi_tag, platform_tag = parts[-3:]
    name_and_version = parts[:-3]
    if len(name_and_version) < 2:
        return None
    distribution = name_and_version[0].replace("-", "_")
    version = name_and_version[1]
    return distribution, version, python_tag, abi_tag, platform_tag


def _wheel_tags_compatible(
    wheel_python: str,
    wheel_abi: str,
    wheel_platform: str,
    python_tag: str,
    abi_tag: str,
    platform_tag: str,
) -> bool:
    py_tags = set(wheel_python.split("."))
    abi_tags = set(wheel_abi.split("."))
    platform_tags = set(wheel_platform.split("."))
    python_tag = _normalize_tag(python_tag)
    abi_tag = _normalize_tag(abi_tag)
    platform_tag = _normalize_tag(platform_tag)
    if python_tag not in py_tags and "py3" not in py_tags:
        return False
    if abi_tag not in abi_tags and not ({"none", "abi3"} & abi_tags):
        return False
    if "any" in platform_tags:
        return True
    return any(_platform_tag_compatible(candidate, platform_tag) for candidate in platform_tags)


def _platform_tag_compatible(wheel_platform: str, platform_tag: str) -> bool:
    wheel_platform = _normalize_tag(wheel_platform)
    platform_tag = _normalize_tag(platform_tag)
    if wheel_platform == platform_tag:
        return True
    if platform_tag.startswith("linux_"):
        arch = platform_tag.removeprefix("linux_")
        return (
            wheel_platform == f"linux_{arch}"
            or (wheel_platform.startswith("manylinux") and wheel_platform.endswith(f"_{arch}"))
            or (wheel_platform.startswith("musllinux") and wheel_platform.endswith(f"_{arch}"))
        )
    return False


def maxmind_db_status(city_db: Path = CITY_DB, asn_db: Path = ASN_DB) -> tuple[bool, list[str]]:
    issues = []
    try:
        import geoip2.database
    except Exception as exc:
        return False, [f"geoip2 reader unavailable: {exc}"]
    for label, path in (("city", city_db), ("asn", asn_db)):
        if not path.exists():
            issues.append(f"{label} db missing: {path}")
            continue
        try:
            reader = geoip2.database.Reader(str(path))
            reader.metadata()
            reader.close()
        except Exception as exc:
            issues.append(f"{label} db unreadable: {exc}")
    return not issues, issues


def linux_default_route_present(route_file: Path = Path("/proc/net/route")) -> bool:
    if not route_file.exists():
        return False
    for line in route_file.read_text(encoding="utf-8").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        interface, destination, _gateway, flags = parts[:4]
        if interface == "lo" or destination != "00000000":
            continue
        try:
            route_is_up = int(flags, 16) & 0x1
        except ValueError:
            route_is_up = 0
        if route_is_up:
            return True
    return False


@contextmanager
def blocked_network(reason: str):
    original_socket = socket.socket
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname

    def fail(*_, **__):
        raise RuntimeError(reason)

    socket.socket = fail
    socket.create_connection = fail
    socket.getaddrinfo = fail
    socket.gethostbyname = fail
    try:
        yield
    finally:
        socket.gethostbyname = original_gethostbyname
        socket.getaddrinfo = original_getaddrinfo
        socket.create_connection = original_create_connection
        socket.socket = original_socket


def assert_no_network_calls() -> None:
    with blocked_network("network access is disabled for offline verification"):
        pass


def verify_weasyprint_render() -> tuple[bool, float | None]:
    try:
        from tempfile import NamedTemporaryFile
        from time import perf_counter

        from weasyprint import HTML

        tmp_path = None
        try:
            with NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            started = perf_counter()
            HTML(string="<html><body><h1>ShadowTrace-XAI</h1></body></html>").write_pdf(str(tmp_path))
            elapsed = perf_counter() - started
            return tmp_path.stat().st_size > 0 and elapsed <= DOSSIER_RENDER_TARGET_SECONDS, elapsed
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
    except Exception as exc:
        print(f"RISK weasyprint render failed: {exc}")
        return False, None


def verify_pipeline_without_network(include_dossier: bool = False) -> bool:
    pipeline = None
    try:
        with blocked_network("network access is disabled for offline pipeline verification"):
            from .pipeline import ShadowTracePipeline
            from .store import DuckDBStore

            db_path = Path(tempfile.gettempdir()) / "shadowtrace_offline_verify.duckdb"
            pipeline = ShadowTracePipeline(DuckDBStore(db_path))
            rows = pipeline.load_sample()
            alerts = pipeline.store.count_alerts()
            if rows <= 0 or alerts <= 0:
                print(f"FAIL offline pipeline produced rows={rows}, alerts={alerts}")
                return False
            print(f"OK offline pipeline rows={rows} alerts={alerts}")
            if include_dossier:
                from .dossier import generate_dossier

                alert = pipeline.store.fetch_alerts(limit=1, offset=0)[0]
                evidence = pipeline.store.fetch_evidence_with_subgraph(alert["tx_id"])
                if evidence is None:
                    print(f"FAIL offline dossier check missing evidence for {alert['tx_id']}")
                    return False
                graph = pipeline.graph_elements(alert["tx_id"])
                output, elapsed = generate_dossier(
                    tx_id=alert["tx_id"],
                    investigator_id="NTRO_OFFLINE_VERIFY",
                    alert=alert,
                    evidence=evidence,
                    graph=graph,
                    include_xai_visuals=True,
                    include_network_metadata=True,
                    xai_graph=evidence.get("xai_subgraph"),
                )
                if not output.exists() or output.stat().st_size == 0:
                    print(f"FAIL offline dossier check produced no PDF at {output}")
                    return False
                print(f"OK offline dossier pdf {output.name} render_seconds={elapsed:.3f}")
            return True
    except Exception as exc:
        print(f"FAIL offline pipeline runtime check failed: {exc}")
        return False
    finally:
        if pipeline is not None:
            pipeline.store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify ShadowTrace-XAI offline runtime dependencies.")
    parser.add_argument("--strict", action="store_true", help="Fail on target risks, not just missing required imports.")
    parser.add_argument("--runtime", action="store_true", help="Run the sample pipeline with runtime network entry points blocked.")
    parser.add_argument("--runtime-dossier", action="store_true", help="Also generate a dossier PDF while runtime network entry points are blocked.")
    args = parser.parse_args()

    print(f"python={sys.version.split()[0]}")
    if sys.version_info < SUPPORTED_PYTHON_MIN:
        print("FAIL python: Python 3.10+ is required")
        return 1
    if sys.version_info >= SUPPORTED_PYTHON_MAX_EXCLUSIVE:
        print("RISK python: use Python 3.10-3.12 for the pinned PyTorch/PyG wheel stack")
        risk_python = True
    else:
        print("OK python target range 3.10-3.12")
        risk_python = False
    missing = [name for name in REQUIRED if not module_exists(name)]
    for name in REQUIRED:
        print(f"{'OK' if name not in missing else 'MISSING'} import {name}")
    for name in PYG_EXTENSIONS:
        print(f"{'OK' if module_exists(name) else 'RISK'} import {name}")
    geoip_ok, geoip_issues = maxmind_db_status()
    print(f"{'OK' if CITY_DB.exists() else 'RISK'} geoip city db {CITY_DB}")
    print(f"{'OK' if ASN_DB.exists() else 'RISK'} geoip asn db {ASN_DB}")
    for issue in geoip_issues:
        print(f"RISK geoip {issue}")
    wheelhouse = Path(__file__).resolve().parents[1] / "wheelhouse"
    wheelhouse_ok, missing_wheels = wheelhouse_status(wheelhouse)
    print(f"{'OK' if wheelhouse_ok else 'RISK'} offline wheelhouse {wheelhouse}")
    if missing_wheels:
        print(f"RISK wheelhouse missing wheels: {', '.join(missing_wheels)}")
    resolver_ok = False
    if wheelhouse.exists():
        resolver_ok, resolver_issues = offline_pip_resolver_status(wheelhouse)
        print(f"{'OK' if resolver_ok else 'RISK'} offline pip resolver")
        for issue in resolver_issues:
            print(f"RISK wheelhouse {issue}")
    assert_no_network_calls()
    if missing:
        print("FAIL required backend modules are missing in this interpreter")
        return 1
    risk = risk_python
    risk = risk or not wheelhouse_ok
    risk = risk or (wheelhouse.exists() and not resolver_ok)
    if not all(module_exists(name) for name in PYG_EXTENSIONS):
        print("RISK PyG extension wheels are not verified in this environment")
        risk = True
    if not geoip_ok:
        print("RISK local MaxMind databases are missing or unreadable; synthetic fallback metadata will be used")
        risk = True
    if module_exists("weasyprint"):
        weasy_ok, weasy_elapsed = verify_weasyprint_render()
        if weasy_elapsed is not None:
            print(f"weasyprint_render_seconds={weasy_elapsed:.3f}")
            if weasy_elapsed > DOSSIER_RENDER_TARGET_SECONDS:
                print(f"RISK weasyprint render exceeded {DOSSIER_RENDER_TARGET_SECONDS:.1f}s target")
        print(f"{'OK' if weasy_ok else 'RISK'} weasyprint pdf render")
        risk = risk or not weasy_ok
    runtime_ok = True
    if args.runtime or args.runtime_dossier:
        runtime_ok = verify_pipeline_without_network(include_dossier=args.runtime_dossier)
    if os.name == "nt":
        print("RISK current verification host is Windows; PRD target is offline Linux")
        risk = True
    elif linux_default_route_present():
        print("RISK linux default network route is present; disable networking before strict target verification")
        risk = True
    else:
        print("OK linux default network route absent")
    print("OK offline verifier completed without runtime network access")
    if not runtime_ok:
        return 1
    if args.strict and risk:
        print("FAIL strict offline target verification has unresolved risks")
        return 1
    return 0
