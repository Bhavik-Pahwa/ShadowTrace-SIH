import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_pipeline_entrypoints_close_duckdb_connections():
    root = Path(__file__).resolve().parents[1]
    cli_source = (root / "shadowtrace" / "cli.py").read_text(encoding="utf-8")
    script_source = (root / "scripts" / "run_pipeline.py").read_text(encoding="utf-8")
    audit_source = (root / "shadowtrace" / "artifact_audit.py").read_text(encoding="utf-8")

    for source in (cli_source, script_source, audit_source):
        assert "try:" in source
        assert "finally:" in source
        assert "pipeline.store.close()" in source


def test_artifact_audit_checks_prd_invariants():
    root = Path(__file__).resolve().parents[1]
    audit_source = (root / "shadowtrace" / "artifact_audit.py").read_text(encoding="utf-8")

    assert "REQUIRED_NODE_LABELS" in audit_source
    assert "REQUIRED_EDGE_TYPES" in audit_source
    assert "contribution_percentage" in audit_source
    assert "chain_of_custody_hash" in audit_source
    assert "chain_of_custody_hash(tx_id, graph, alert.get(\"timestamp\"))" in audit_source


def test_pyproject_exposes_all_console_scripts():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert 'shadowtrace-pipeline = "shadowtrace.cli:run_pipeline_main"' in pyproject
    assert 'shadowtrace-verify-offline = "shadowtrace.cli:verify_offline_main"' in pyproject
    assert 'shadowtrace-artifact-audit = "shadowtrace.cli:audit_artifacts_main"' in pyproject
    assert 'shadowtrace-verify-bundle = "shadowtrace.cli:verify_bundle_main"' in pyproject
    assert 'shadowtrace-build-bundle = "shadowtrace.cli:build_bundle_main"' in pyproject
    assert 'shadowtrace-build-wheelhouse = "shadowtrace.cli:build_wheelhouse_main"' in pyproject


def test_offline_verifier_closes_duckdb_connection_after_runtime_check():
    root = Path(__file__).resolve().parents[1]
    verifier_source = (root / "shadowtrace" / "offline_verify.py").read_text(encoding="utf-8")

    assert "pipeline = None" in verifier_source
    assert "if pipeline is not None:" in verifier_source
    assert "pipeline.store.close()" in verifier_source
