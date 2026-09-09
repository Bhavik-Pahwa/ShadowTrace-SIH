import socket
import sys
import ast
from pathlib import Path
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadowtrace.offline_verify import blocked_network
from shadowtrace.pipeline import ShadowTracePipeline
from shadowtrace.store import DuckDBStore
from shadowtrace.dossier import generate_dossier


class FakeVersionInfo(tuple):
    @property
    def major(self):
        return self[0]

    @property
    def minor(self):
        return self[1]


def test_sample_pipeline_runs_with_sockets_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOWTRACE_ALLOW_PDF_FALLBACK", "1")

    with blocked_network("network access blocked during offline runtime test"):
        pipeline = ShadowTracePipeline(DuckDBStore(tmp_path / "offline.duckdb"))
        rows = pipeline.load_sample()
        assert rows == 90
        assert pipeline.store.count_alerts() > 0
        alert = pipeline.store.fetch_alerts(limit=1, offset=0)[0]
        evidence = pipeline.store.fetch_evidence(alert["tx_id"])
        assert evidence is not None
        assert "xai_subgraph" not in evidence
        internal_evidence = pipeline.store.fetch_evidence_with_subgraph(alert["tx_id"])
        assert internal_evidence is not None
        assert internal_evidence["xai_subgraph"]["nodes"]
        assert internal_evidence["xai_subgraph"]["edges"]
        assert internal_evidence["xai_subgraph"]["metadata"]["method"] in {"gnnexplainer", "heuristic_fallback"}
        assert sum(item["contribution_percentage"] for item in evidence["xai_breakdown"]) == evidence["overall_threat_score"]
        output, elapsed = generate_dossier(
            tx_id=alert["tx_id"],
            investigator_id="NTRO_OFFLINE_TEST",
            alert=alert,
            evidence=internal_evidence,
            graph=pipeline.graph_elements(alert["tx_id"]),
            include_xai_visuals=True,
            include_network_metadata=True,
            xai_graph=internal_evidence["xai_subgraph"],
        )
    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF")
    assert elapsed >= 0


def test_blocked_network_blocks_common_socket_entrypoints():
    original_socket = socket.socket
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname

    with blocked_network("offline"):
        for call in (
            lambda: socket.socket(),
            lambda: socket.create_connection(("127.0.0.1", 1), timeout=0.01),
            lambda: socket.getaddrinfo("localhost", 80),
            lambda: socket.gethostbyname("localhost"),
        ):
            try:
                call()
            except RuntimeError as exc:
                assert str(exc) == "offline"
            else:
                raise AssertionError("network entrypoint was not blocked")

    assert socket.socket is original_socket
    assert socket.create_connection is original_create_connection
    assert socket.getaddrinfo is original_getaddrinfo
    assert socket.gethostbyname is original_gethostbyname


def test_runtime_package_has_no_outbound_network_dependencies():
    package_root = Path(__file__).resolve().parents[1] / "shadowtrace"
    disallowed_modules = {"socket", "requests", "urllib", "httpx", "aiohttp"}
    disallowed_calls = {"urlopen", "create_connection", "getaddrinfo", "gethostbyname"}
    allowed_files = {package_root / "offline_verify.py"}
    violations = []

    for source_path in sorted(package_root.rglob("*.py")):
        if source_path in allowed_files:
            continue
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in disallowed_modules:
                        violations.append(f"{source_path.name}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".", 1)[0]
                if module in disallowed_modules:
                    violations.append(f"{source_path.name}:{node.lineno} imports from {node.module}")
            elif isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Name) and function.id in disallowed_calls:
                    violations.append(f"{source_path.name}:{node.lineno} calls {function.id}")
                elif isinstance(function, ast.Attribute) and function.attr in disallowed_calls:
                    violations.append(f"{source_path.name}:{node.lineno} calls {function.attr}")

    assert violations == []


def test_linux_target_script_requires_socket_blocked_dossier_generation():
    script = Path(__file__).resolve().parents[1] / "scripts" / "verify_linux_target.sh"
    text = script.read_text(encoding="utf-8")
    assert "export SHADOWTRACE_REQUIRE_GEOIP=1" in text
    assert "export SHADOWTRACE_REQUIRE_PYG_EXTENSIONS=1" in text
    assert "command -v nmcli" in text
    assert 'NETWORK_STATE="$(nmcli networking 2>/dev/null || true)"' in text
    assert '[[ "${NETWORK_STATE}" != "disabled" ]]' in text
    assert "nmcli networking off" in text
    assert 'PORT="${SHADOWTRACE_VERIFY_PORT:-8000}"' in text
    assert 'export SHADOWTRACE_VERIFY_PORT="${PORT}"' in text
    assert "python scripts/verify_offline.py --strict --runtime --runtime-dossier" in text
    assert "python scripts/audit_prd_artifacts.py" in text
    assert 'kill -0 "${SERVER_PID}"' in text
    assert "SERVER_READY=1" in text
    assert "FastAPI server did not become ready" in text


def test_wheelhouse_builder_refuses_mismatched_python_before_download(monkeypatch):
    import shadowtrace.wheelhouse_builder as module

    monkeypatch.setattr(module.sys, "version_info", FakeVersionInfo((3, 14, 0)))

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("pip download should not run on a mismatched interpreter")

    monkeypatch.setattr(module.subprocess, "check_call", fail_if_called)
    assert module.build_wheelhouse(Path("unused")) == 1


def test_wheelhouse_builder_downloads_shared_pyg_extension_requirements():
    script = Path(__file__).resolve().parents[1] / "shadowtrace" / "wheelhouse_builder.py"
    text = script.read_text(encoding="utf-8")
    assert "requirements-pyg-extensions.txt" in text
    assert "https://data.pyg.org/whl/torch-2.5.1+cpu.html" in text
    assert '"torch-scatter==2.1.2"' not in text
    assert '"torch-sparse==0.6.18"' not in text
    assert "wheelhouse_status(wheelhouse)" in text


def test_packaged_builders_default_to_cwd_when_it_is_backend_root(tmp_path, monkeypatch):
    import shadowtrace.release_bundle as release_bundle
    import shadowtrace.wheelhouse_builder as wheelhouse_builder

    backend_root = tmp_path / "backend"
    backend_root.mkdir()
    (backend_root / "pyproject.toml").write_text("[project]\nname='shadowtrace-xai-backend'\n", encoding="utf-8")
    (backend_root / "requirements.txt").write_text("", encoding="utf-8")
    monkeypatch.chdir(backend_root)

    assert release_bundle.default_backend_root() == backend_root
    assert wheelhouse_builder.default_backend_root() == backend_root


def test_source_builder_wrappers_pass_checked_out_backend_root():
    root = Path(__file__).resolve().parents[1]
    for script_name in ("build_release_bundle.py", "build_offline_wheelhouse.py"):
        text = (root / "scripts" / script_name).read_text(encoding="utf-8")
        assert 'arg == "--root" or arg.startswith("--root=")' in text
        assert 'sys.argv.extend(["--root", str(Path(__file__).resolve().parents[1])])' in text


def test_release_bundle_builder_requires_target_artifacts():
    script = Path(__file__).resolve().parents[1] / "shadowtrace" / "release_bundle.py"
    text = script.read_text(encoding="utf-8")

    assert '".dockerignore"' in text
    assert '"PRD_IMPLEMENTATION_CHECKLIST.md"' in text
    assert "validate_bundle_inputs" in text
    assert "BUNDLE_MANIFEST.json" in text
    assert "build_manifest" in text
    assert "hashlib.sha256()" in text
    assert "maxmind_db_status(city_db, asn_db)" in text
    assert "wheelhouse_status(wheelhouse)" in text
    assert "offline_pip_resolver_status(wheelhouse, root)" in text
    assert "missing GeoIP city database" in text
    assert "missing GeoIP ASN database" in text
    assert "incomplete wheelhouse" in text


def test_release_bundle_validation_uses_supplied_root_geoip_paths(tmp_path, monkeypatch):
    import shadowtrace.release_bundle as module

    root = tmp_path / "backend"
    (root / "data" / "geoip").mkdir(parents=True)
    city_db = root / "data" / "geoip" / "GeoLite2-City.mmdb"
    asn_db = root / "data" / "geoip" / "GeoLite2-ASN.mmdb"
    city_db.write_text("city", encoding="utf-8")
    asn_db.write_text("asn", encoding="utf-8")
    seen = []

    def fake_maxmind(check_city, check_asn):
        seen.append((check_city, check_asn))
        return True, []

    monkeypatch.setattr(module, "maxmind_db_status", fake_maxmind)
    monkeypatch.setattr(module, "wheelhouse_status", lambda _wheelhouse: (True, []))
    monkeypatch.setattr(module, "offline_pip_resolver_status", lambda _wheelhouse, _root: (True, []))

    assert module.validate_bundle_inputs(root) == [f"missing wheelhouse directory: {root / 'wheelhouse'}"]
    assert seen == [(city_db, asn_db)]


def test_release_bundle_validation_reports_missing_geoip_once(tmp_path, monkeypatch):
    import shadowtrace.release_bundle as module

    root = tmp_path / "backend"
    root.mkdir()
    called = []

    def fail_if_called(*_args, **_kwargs):
        called.append(True)
        return False, ["should not run"]

    monkeypatch.setattr(module, "maxmind_db_status", fail_if_called)
    monkeypatch.setattr(module, "wheelhouse_status", lambda _wheelhouse: (True, []))

    issues = module.validate_bundle_inputs(root)

    assert called == []
    assert issues == [
        f"missing GeoIP city database: {root / 'data' / 'geoip' / 'GeoLite2-City.mmdb'}",
        f"missing GeoIP ASN database: {root / 'data' / 'geoip' / 'GeoLite2-ASN.mmdb'}",
        f"missing wheelhouse directory: {root / 'wheelhouse'}",
    ]


def test_release_bundle_builder_excludes_generated_artifacts():
    script = Path(__file__).resolve().parents[1] / "shadowtrace" / "release_bundle.py"
    text = script.read_text(encoding="utf-8")

    assert '"data/geoip"' in text
    assert '"wheelhouse"' in text
    assert '"shadowtrace"' in text
    assert '"__pycache__"' in text
    assert '".pytest_cache"' in text
    assert '"shadowtrace_xai_backend.egg-info"' in text
    assert '"data/shadowtrace.duckdb"' not in text
    assert '"reports"' not in text


def test_release_bundle_manifest_records_hashes(tmp_path):
    import json
    import zipfile
    import shadowtrace.release_bundle as module

    root = tmp_path / "backend"
    (root / "shadowtrace").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "data" / "geoip").mkdir(parents=True)
    (root / "wheelhouse").mkdir()
    (root / "README.md").write_text("readme", encoding="utf-8")
    (root / ".dockerignore").write_text("data/*.duckdb\nreports/*\n", encoding="utf-8")
    (root / "PRD_IMPLEMENTATION_CHECKLIST.md").write_text("checklist", encoding="utf-8")
    (root / "shadowtrace" / "__init__.py").write_text("", encoding="utf-8")
    (root / "data" / "geoip" / "GeoLite2-City.mmdb").write_text("city", encoding="utf-8")
    (root / "data" / "geoip" / "GeoLite2-ASN.mmdb").write_text("asn", encoding="utf-8")
    (root / "data" / "shadowtrace.duckdb").write_text("generated", encoding="utf-8")
    output = root / "bundle.zip"

    module.build_bundle(root, output)

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("BUNDLE_MANIFEST.json"))

    assert "BUNDLE_MANIFEST.json" in names
    assert "README.md" in names
    assert ".dockerignore" in names
    assert "PRD_IMPLEMENTATION_CHECKLIST.md" in names
    assert "data/shadowtrace.duckdb" not in names
    by_path = {item["path"]: item for item in manifest["files"]}
    assert by_path["README.md"]["size_bytes"] == len("readme")
    assert by_path[".dockerignore"]["size_bytes"] == (root / ".dockerignore").stat().st_size
    assert len(by_path["README.md"]["sha256"]) == 64
    assert "data/geoip/GeoLite2-City.mmdb" in manifest["required_artifacts"]
    assert "data/geoip/GeoLite2-ASN.mmdb" in manifest["required_artifacts"]


def test_bundle_manifest_verifier_accepts_generated_bundle(tmp_path):
    import shadowtrace.bundle_manifest as verifier
    import shadowtrace.release_bundle as builder

    root = tmp_path / "backend"
    (root / "shadowtrace").mkdir(parents=True)
    (root / "data" / "geoip").mkdir(parents=True)
    (root / "wheelhouse").mkdir()
    (root / "README.md").write_text("readme", encoding="utf-8")
    (root / "data" / "geoip" / "GeoLite2-City.mmdb").write_text("city", encoding="utf-8")
    (root / "data" / "geoip" / "GeoLite2-ASN.mmdb").write_text("asn", encoding="utf-8")
    (root / "wheelhouse" / "example.whl").write_text("wheel", encoding="utf-8")
    output = builder.build_bundle(root, root / "bundle.zip")

    assert verifier.verify_bundle_manifest(output) == []


def test_bundle_manifest_verifier_rejects_hash_mismatch(tmp_path):
    import json
    import zipfile

    from shadowtrace.bundle_manifest import verify_bundle_manifest

    bundle = tmp_path / "bad_bundle.zip"
    manifest = {
        "bundle": "shadowtrace-xai-offline",
        "generated_at": "2026-09-08T00:00:00Z",
        "required_artifacts": [],
        "files": [{"path": "README.md", "size_bytes": 7, "sha256": "0" * 64}],
    }
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("README.md", b"readme")
        archive.writestr("BUNDLE_MANIFEST.json", json.dumps(manifest))

    issues = verify_bundle_manifest(bundle)

    assert "README.md: size mismatch" in issues
    assert "README.md: sha256 mismatch" in issues


def test_wheelhouse_builder_fails_when_downloaded_wheelhouse_is_incomplete(monkeypatch, tmp_path, capsys):
    import shadowtrace.wheelhouse_builder as module

    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.sys, "version_info", FakeVersionInfo((3, 10, 0)))

    def skip_download(*_args, **_kwargs):
        return None

    monkeypatch.setattr(module.subprocess, "check_call", skip_download)
    assert module.build_wheelhouse(tmp_path / "backend") == 1
    assert "Wheelhouse is incomplete or incompatible" in capsys.readouterr().err


def test_wheelhouse_builder_succeeds_only_after_validated_download(monkeypatch, tmp_path):
    import shadowtrace.wheelhouse_builder as module
    from shadowtrace.offline_verify import REQUIRED_WHEELS

    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.sys, "version_info", FakeVersionInfo((3, 10, 0)))
    monkeypatch.setattr("shadowtrace.offline_verify._runtime_python_tag", lambda: "cp310")
    monkeypatch.setattr("shadowtrace.offline_verify._runtime_platform_tag", lambda: "linux_x86_64")
    monkeypatch.setattr("shadowtrace.offline_verify.offline_pip_resolver_status", lambda _wheelhouse, _root: (True, []))

    def write_fake_wheels(*_args, **_kwargs):
        wheelhouse = tmp_path / "backend" / "wheelhouse"
        wheelhouse.mkdir(parents=True, exist_ok=True)
        for name, version in REQUIRED_WHEELS.items():
            if name in {"torch_scatter", "torch_sparse"}:
                file_name = f"{name}-{version}+pt25cpu-cp310-cp310-linux_x86_64.whl"
            else:
                file_name = f"{name}-{version}-py3-none-any.whl"
            (wheelhouse / file_name).write_text("", encoding="utf-8")

    monkeypatch.setattr(module.subprocess, "check_call", write_fake_wheels)
    assert module.build_wheelhouse(tmp_path / "backend") == 0


def test_offline_pip_resolver_uses_local_wheelhouse_only(tmp_path, monkeypatch):
    from shadowtrace import offline_verify

    backend_root = tmp_path / "backend"
    wheelhouse = backend_root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    for name in offline_verify.REQUIREMENT_FILES:
        (backend_root / name).write_text("example==1.0.0\n", encoding="utf-8")
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        return types.SimpleNamespace(returncode=0, stdout="Would install", stderr="")

    monkeypatch.setattr(offline_verify.subprocess, "run", fake_run)

    ok, issues = offline_verify.offline_pip_resolver_status(wheelhouse, backend_root)

    assert ok is True
    assert issues == []
    assert len(commands) == len(offline_verify.REQUIREMENT_FILES)
    for command, kwargs in commands:
        assert "--dry-run" in command
        assert "--ignore-installed" in command
        assert "--no-index" in command
        assert "--find-links" in command
        assert str(wheelhouse) in command
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False


def test_offline_pip_resolver_reports_missing_transitive_wheel(tmp_path, monkeypatch):
    from shadowtrace import offline_verify

    backend_root = tmp_path / "backend"
    wheelhouse = backend_root / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    for name in offline_verify.REQUIREMENT_FILES:
        (backend_root / name).write_text("example==1.0.0\n", encoding="utf-8")

    def fake_run(_command, **_kwargs):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="ERROR: No matching distribution found for transitive==1.2.3\n")

    monkeypatch.setattr(offline_verify.subprocess, "run", fake_run)

    ok, issues = offline_verify.offline_pip_resolver_status(wheelhouse, backend_root)

    assert ok is False
    assert any("transitive==1.2.3" in issue for issue in issues)


def test_runtime_dossier_flag_implies_runtime_execution():
    source = Path(__file__).resolve().parents[1] / "shadowtrace" / "offline_verify.py"
    text = source.read_text(encoding="utf-8")
    assert "if args.runtime or args.runtime_dossier:" in text
    assert "verify_pipeline_without_network(include_dossier=args.runtime_dossier)" in text


def test_strict_offline_verifier_flags_current_unsupported_python():
    import subprocess

    result = subprocess.run(
        [sys.executable, "scripts/verify_offline.py", "--strict"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "RISK python: use Python 3.10-3.12" in result.stdout


def test_wheelhouse_status_requires_pyg_extension_wheels(tmp_path):
    from shadowtrace.offline_verify import wheelhouse_status

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    required = {
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
        "pytest": "8.3.5",
        "httpx": "0.28.1",
    }
    for name, version in required.items():
        (wheelhouse / f"{name}-{version}-py3-none-any.whl").write_text("", encoding="utf-8")

    ok, missing = wheelhouse_status(wheelhouse, python_tag="cp310", abi_tag="cp310", platform_tag="linux_x86_64")
    assert ok is False
    assert "torch_scatter==2.1.2" in missing
    assert "torch_sparse==0.6.18" in missing

    (wheelhouse / "torch_scatter-2.1.2-cp310-cp310-linux_x86_64.whl").write_text("", encoding="utf-8")
    (wheelhouse / "torch_sparse-0.6.17-cp310-cp310-linux_x86_64.whl").write_text("", encoding="utf-8")
    ok, missing = wheelhouse_status(wheelhouse, python_tag="cp310", abi_tag="cp310", platform_tag="linux_x86_64")
    assert ok is False
    assert "torch_sparse==0.6.18" in missing

    (wheelhouse / "torch_sparse-0.6.18-cp310-cp310-linux_x86_64.whl").write_text("", encoding="utf-8")
    ok, missing = wheelhouse_status(wheelhouse, python_tag="cp310", abi_tag="cp310", platform_tag="linux_x86_64")
    assert ok is True
    assert missing == []


def test_wheelhouse_status_accepts_pyg_local_version_wheel_tags(tmp_path):
    from shadowtrace.offline_verify import REQUIRED_WHEELS, wheelhouse_status

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    for name, version in REQUIRED_WHEELS.items():
        if name == "torch_scatter":
            file_name = "torch_scatter-2.1.2+pt25cpu-cp310-cp310-linux_x86_64.whl"
        elif name == "torch_sparse":
            file_name = "torch_sparse-0.6.18+pt25cpu-cp310-cp310-linux_x86_64.whl"
        else:
            file_name = f"{name}-{version}-py3-none-any.whl"
        (wheelhouse / file_name).write_text("", encoding="utf-8")

    assert wheelhouse_status(wheelhouse, python_tag="cp310", abi_tag="cp310", platform_tag="linux_x86_64") == (True, [])


def test_wheelhouse_status_rejects_incompatible_platform_wheels(tmp_path):
    from shadowtrace.offline_verify import REQUIRED_WHEELS, wheelhouse_status

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    for name, version in REQUIRED_WHEELS.items():
        if name == "torch_scatter":
            file_name = "torch_scatter-2.1.2+pt25cpu-cp310-cp310-win_amd64.whl"
        elif name == "torch_sparse":
            file_name = "torch_sparse-0.6.18+pt25cpu-cp310-cp310-linux_x86_64.whl"
        else:
            file_name = f"{name}-{version}-py3-none-any.whl"
        (wheelhouse / file_name).write_text("", encoding="utf-8")

    ok, missing = wheelhouse_status(wheelhouse, python_tag="cp310", abi_tag="cp310", platform_tag="linux_x86_64")
    assert ok is False
    assert "torch_scatter==2.1.2" in missing
    assert "torch_sparse==0.6.18" not in missing



def test_linux_default_route_detection(tmp_path):
    from shadowtrace.offline_verify import linux_default_route_present

    route_file = tmp_path / "route"
    route_file.write_text(
        "\n".join(
            [
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
                "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
            ]
        ),
        encoding="utf-8",
    )
    assert linux_default_route_present(route_file) is True

    route_file.write_text(
        "\n".join(
            [
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
                "lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0",
                "eth0\t00FEA9FE\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0",
            ]
        ),
        encoding="utf-8",
    )
    assert linux_default_route_present(route_file) is False


def test_maxmind_status_requires_present_readable_databases(tmp_path, monkeypatch):
    from shadowtrace.offline_verify import maxmind_db_status

    city_db = tmp_path / "GeoLite2-City.mmdb"
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    ok, issues = maxmind_db_status(city_db, asn_db)
    assert ok is False
    assert any("city db missing" in issue for issue in issues)
    assert any("asn db missing" in issue for issue in issues)

    city_db.write_bytes(b"not-a-real-mmdb")
    asn_db.write_bytes(b"not-a-real-mmdb")

    class FailingReader:
        def __init__(self, *_args, **_kwargs):
            raise ValueError("bad maxmind file")

    geoip_module = types.ModuleType("geoip2")
    database_module = types.ModuleType("geoip2.database")
    database_module.Reader = FailingReader
    geoip_module.database = database_module
    monkeypatch.setitem(sys.modules, "geoip2", geoip_module)
    monkeypatch.setitem(sys.modules, "geoip2.database", database_module)

    ok, issues = maxmind_db_status(city_db, asn_db)
    assert ok is False
    assert any("city db unreadable" in issue for issue in issues)
    assert any("asn db unreadable" in issue for issue in issues)


def test_maxmind_status_accepts_readable_databases(tmp_path, monkeypatch):
    from shadowtrace.offline_verify import maxmind_db_status

    city_db = tmp_path / "GeoLite2-City.mmdb"
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    city_db.write_bytes(b"fake-city")
    asn_db.write_bytes(b"fake-asn")

    class Reader:
        def __init__(self, path):
            self.path = path

        def metadata(self):
            return {"database_type": "test"}

        def close(self):
            pass

    geoip_module = types.ModuleType("geoip2")
    database_module = types.ModuleType("geoip2.database")
    database_module.Reader = Reader
    geoip_module.database = database_module
    monkeypatch.setitem(sys.modules, "geoip2", geoip_module)
    monkeypatch.setitem(sys.modules, "geoip2.database", database_module)

    assert maxmind_db_status(city_db, asn_db) == (True, [])


def test_dockerfile_installs_python_wheels_from_local_wheelhouse_only():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")
    assert "COPY wheelhouse /app/wheelhouse" in text
    assert "COPY requirements-pyg-extensions.txt /app/requirements-pyg-extensions.txt" in text
    assert "--no-index --find-links /app/wheelhouse" in text
    assert "-r /app/requirements-pyg-extensions.txt" in text
    assert "https://data.pyg.org" not in text
    assert "pip install --upgrade pip" not in text
    assert "pip install --no-cache-dir -r /app/requirements.txt" not in text
    assert "pip install --no-cache-dir --no-build-isolation --no-deps ." in text


def test_dockerignore_excludes_generated_artifacts_without_excluding_target_assets():
    dockerignore = Path(__file__).resolve().parents[1] / ".dockerignore"
    lines = {
        line.strip()
        for line in dockerignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    assert "data/*.duckdb" in lines
    assert "data/*.duckdb.*" in lines
    assert "data/*.db" in lines
    assert "data/*.db.*" in lines
    assert "reports/*" in lines
    assert ".pytest_cache/" in lines
    assert "*.egg-info/" in lines
    assert "*.zip" in lines
    assert "wheelhouse/" not in lines
    assert "data/geoip/" not in lines
    assert "data/geoip/*.mmdb" not in lines


def test_makefile_offline_install_installs_pyg_extensions_from_wheelhouse():
    makefile = Path(__file__).resolve().parents[1] / "Makefile"
    text = makefile.read_text(encoding="utf-8")
    assert "install-offline:" in text
    assert "pip install --no-index --find-links ./wheelhouse -r requirements.txt" in text
    assert "pip install --no-index --find-links ./wheelhouse -r requirements-pyg-extensions.txt" in text
    assert "pip install --no-build-isolation --no-deps -e ." in text
    assert "audit-artifacts:" in text
    assert "python scripts/audit_prd_artifacts.py" in text
    assert "bundle-offline:" in text
    assert "python scripts/build_release_bundle.py" in text
    assert "verify-bundle:" in text
    assert "python scripts/verify_bundle_manifest.py shadowtrace-xai-offline-bundle.zip" in text


def test_pyg_extension_requirements_pin_target_wheels():
    requirements = Path(__file__).resolve().parents[1] / "requirements-pyg-extensions.txt"
    assert requirements.read_text(encoding="utf-8").splitlines() == [
        "torch-scatter==2.1.2",
        "torch-sparse==0.6.18",
    ]


def test_wheelhouse_verifier_covers_direct_pinned_requirements():
    from shadowtrace.offline_verify import REQUIRED_WHEELS

    backend_root = Path(__file__).resolve().parents[1]
    direct_requirements = {}
    for requirements_name in ("requirements.txt", "requirements-pyg-extensions.txt"):
        for line in (backend_root / requirements_name).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "==" not in line:
                continue
            package, version = line.split("==", 1)
            package = package.split("[", 1)[0].replace("-", "_")
            direct_requirements[package] = version

    assert direct_requirements.items() <= REQUIRED_WHEELS.items()


def test_weasyprint_verifier_rejects_slow_successful_render(monkeypatch, tmp_path):
    import shadowtrace.offline_verify as verifier

    class FakeHTML:
        def __init__(self, *_args, **_kwargs):
            pass

        def write_pdf(self, path):
            Path(path).write_bytes(b"%PDF-1.4")

    times = iter([10.0, 13.5])
    monkeypatch.setattr(verifier, "DOSSIER_RENDER_TARGET_SECONDS", 2.0)
    monkeypatch.setattr(verifier, "NamedTemporaryFile", None, raising=False)
    monkeypatch.setattr("time.perf_counter", lambda: next(times))

    import types

    module = types.ModuleType("weasyprint")
    module.HTML = FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", module)

    ok, elapsed = verifier.verify_weasyprint_render()
    assert ok is False
    assert elapsed == 3.5


def test_cold_graph_hydration_from_duckdb_does_not_rescore(tmp_path, monkeypatch):
    import shadowtrace.pipeline as pipeline_module

    db_path = tmp_path / "hydration.duckdb"
    first = ShadowTracePipeline(DuckDBStore(db_path))
    first.load_sample()
    tx_id = first.store.fetch_alerts(limit=1, offset=0)[0]["tx_id"]
    first.store.close()

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("graph hydration should not rerun model scoring")

    monkeypatch.setattr(pipeline_module, "score_transactions", fail_if_called)
    second = ShadowTracePipeline(DuckDBStore(db_path))
    second.graph = None
    elements = second.graph_elements(tx_id)
    internal_evidence = second.store.fetch_evidence_with_subgraph(tx_id)
    second.store.close()
    assert elements["nodes"]
    assert elements["edges"]
    assert internal_evidence is not None
    assert internal_evidence["xai_subgraph"]["nodes"]
    assert internal_evidence["xai_subgraph"]["edges"]
    assert internal_evidence["xai_subgraph"]["metadata"]["method"] in {"gnnexplainer", "heuristic_fallback"}
    root = next(node["data"] for node in elements["nodes"] if node["data"]["id"] == tx_id)
    assert root["threat_score"] >= 50
    assert root["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert root["primary_anomaly"]
