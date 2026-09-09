from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

from .offline_verify import maxmind_db_status, offline_pip_resolver_status, wheelhouse_status


INCLUDE_FILES = [
    ".dockerignore",
    ".gitignore",
    "Dockerfile",
    "IMPLEMENTATION_STATUS.md",
    "Makefile",
    "PRD_COMPLIANCE_AUDIT.md",
    "PRD_IMPLEMENTATION_CHECKLIST.md",
    "README.md",
    "pyproject.toml",
    "requirements.txt",
    "requirements-pyg-extensions.txt",
]

INCLUDE_DIRS = [
    "shadowtrace",
    "scripts",
    "templates",
    "tests",
    "data/geoip",
    "wheelhouse",
]

EXCLUDE_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "shadowtrace_xai_backend.egg-info",
}


def default_backend_root() -> Path:
    cwd = Path.cwd()
    if (cwd / "pyproject.toml").exists() and (cwd / "requirements.txt").exists():
        return cwd
    source_root = Path(__file__).resolve().parents[1]
    if (source_root / "pyproject.toml").exists() and (source_root / "requirements.txt").exists():
        return source_root
    return cwd


def city_db_for(root: Path) -> Path:
    return root / "data" / "geoip" / "GeoLite2-City.mmdb"


def asn_db_for(root: Path) -> Path:
    return root / "data" / "geoip" / "GeoLite2-ASN.mmdb"


def iter_bundle_files(root: Path) -> list[Path]:
    files = [root / name for name in INCLUDE_FILES]
    for directory in INCLUDE_DIRS:
        path = root / directory
        if not path.exists():
            continue
        for child in path.rglob("*"):
            if child.is_file() and not (set(child.relative_to(root).parts) & EXCLUDE_PARTS):
                files.append(child)
    return sorted({path for path in files if path.exists()})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path, files: list[Path]) -> dict:
    return {
        "bundle": "shadowtrace-xai-offline",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "required_artifacts": [
            city_db_for(root).relative_to(root).as_posix(),
            asn_db_for(root).relative_to(root).as_posix(),
            "wheelhouse/",
        ],
        "files": [
            {
                "path": path.relative_to(root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in files
        ],
    }


def validate_bundle_inputs(root: Path) -> list[str]:
    issues = []
    city_db = city_db_for(root)
    asn_db = asn_db_for(root)
    if not city_db.exists():
        issues.append(f"missing GeoIP city database: {city_db}")
    if not asn_db.exists():
        issues.append(f"missing GeoIP ASN database: {asn_db}")
    if city_db.exists() and asn_db.exists():
        geoip_ok, geoip_issues = maxmind_db_status(city_db, asn_db)
        if not geoip_ok:
            issues.extend(f"invalid GeoIP database: {issue}" for issue in geoip_issues)

    wheelhouse = root / "wheelhouse"
    wheelhouse_ok, missing_wheels = wheelhouse_status(wheelhouse)
    if not wheelhouse_ok:
        issues.append(f"incomplete wheelhouse: {', '.join(missing_wheels)}")
    if wheelhouse.exists():
        resolver_ok, resolver_issues = offline_pip_resolver_status(wheelhouse, root)
        if not resolver_ok:
            issues.extend(f"wheelhouse resolver issue: {issue}" for issue in resolver_issues)
    else:
        issues.append(f"missing wheelhouse directory: {wheelhouse}")
    return issues


def build_bundle(root: Path, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    files = iter_bundle_files(root)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(root).as_posix())
        manifest = json.dumps(build_manifest(root, files), indent=2, sort_keys=True).encode("utf-8")
        archive.writestr("BUNDLE_MANIFEST.json", manifest)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an offline ShadowTrace-XAI Linux demo bundle.")
    parser.add_argument("--output", type=Path, default=Path("shadowtrace-xai-offline-bundle.zip"))
    parser.add_argument("--root", type=Path, default=default_backend_root(), help="Backend project root to package.")
    parser.add_argument("--skip-validation", action="store_true", help="Package source without checking target artifacts.")
    args = parser.parse_args()

    root = args.root.resolve()
    if not args.skip_validation:
        issues = validate_bundle_inputs(root)
        if issues:
            for issue in issues:
                print(f"FAIL {issue}", file=sys.stderr)
            return 1
    output = args.output if args.output.is_absolute() else root / args.output
    bundle = build_bundle(root, output)
    print(f"bundle={bundle}")
    return 0
