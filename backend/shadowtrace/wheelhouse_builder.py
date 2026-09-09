from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path


def default_backend_root() -> Path:
    cwd = Path.cwd()
    if (cwd / "pyproject.toml").exists() and (cwd / "requirements.txt").exists():
        return cwd
    source_root = Path(__file__).resolve().parents[1]
    if (source_root / "pyproject.toml").exists() and (source_root / "requirements.txt").exists():
        return source_root
    return cwd


def build_wheelhouse(root: Path) -> int:
    version = sys.version_info
    if not (version.major == 3 and 10 <= version.minor <= 12):
        print("Build the wheelhouse with Python 3.10-3.12 to match pyproject.toml and PyG wheel availability.", file=sys.stderr)
        return 1
    if platform.system() != "Linux":
        print("Build the wheelhouse on the same Linux architecture as the offline target machine.", file=sys.stderr)
        return 1

    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    base_command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--only-binary=:all:",
        "-d",
        str(wheelhouse),
    ]
    subprocess.check_call([*base_command, "-r", str(root / "requirements.txt")])
    subprocess.check_call(
        [
            *base_command,
            "-r",
            str(root / "requirements-pyg-extensions.txt"),
            "-f",
            "https://data.pyg.org/whl/torch-2.5.1+cpu.html",
        ]
    )
    from .offline_verify import offline_pip_resolver_status, wheelhouse_status

    ok, missing = wheelhouse_status(wheelhouse)
    if not ok:
        print(f"Wheelhouse is incomplete or incompatible: {', '.join(missing)}", file=sys.stderr)
        return 1
    resolver_ok, resolver_issues = offline_pip_resolver_status(wheelhouse, root)
    if not resolver_ok:
        print(f"Wheelhouse cannot satisfy offline pip install: {', '.join(resolver_issues)}", file=sys.stderr)
        return 1
    print(f"Wheelhouse written to {wheelhouse}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the ShadowTrace-XAI offline Python wheelhouse.")
    parser.add_argument("--root", type=Path, default=default_backend_root())
    args = parser.parse_args()
    return build_wheelhouse(args.root.resolve())
