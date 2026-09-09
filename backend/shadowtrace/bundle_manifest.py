from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_bundle_manifest(bundle: Path) -> list[str]:
    issues = []
    if not bundle.exists():
        return [f"bundle does not exist: {bundle}"]
    try:
        with zipfile.ZipFile(bundle) as archive:
            names = set(archive.namelist())
            if "BUNDLE_MANIFEST.json" not in names:
                return ["BUNDLE_MANIFEST.json is missing"]
            manifest = json.loads(archive.read("BUNDLE_MANIFEST.json"))
            for required in manifest.get("required_artifacts", []):
                if required.endswith("/"):
                    if not any(name.startswith(required) and name != required for name in names):
                        issues.append(f"required artifact directory is empty or missing: {required}")
                elif required not in names:
                    issues.append(f"required artifact is missing: {required}")
            for item in manifest.get("files", []):
                path = item.get("path")
                if not path or path not in names:
                    issues.append(f"manifest file missing from archive: {path}")
                    continue
                data = archive.read(path)
                if item.get("size_bytes") != len(data):
                    issues.append(f"{path}: size mismatch")
                if item.get("sha256") != _sha256(data):
                    issues.append(f"{path}: sha256 mismatch")
    except zipfile.BadZipFile as exc:
        return [f"bundle is not a readable zip file: {exc}"]
    except json.JSONDecodeError as exc:
        return [f"BUNDLE_MANIFEST.json is not valid JSON: {exc}"]
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a ShadowTrace-XAI offline bundle manifest.")
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()

    issues = verify_bundle_manifest(args.bundle)
    if issues:
        for issue in issues:
            print(f"FAIL {issue}")
        return 1
    print("bundle_manifest=ok")
    return 0
