import sys
from pathlib import Path
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from jinja2 import Environment, FileSystemLoader, select_autoescape

from shadowtrace.dossier import build_subgraph_svg, build_xai_pie_svg, dossier_file_name, generate_dossier
from shadowtrace.xai import chain_of_custody_hash


def test_build_subgraph_svg_contains_visual_nodes_and_edges():
    graph = {
        "nodes": [
            {"data": {"id": "tx1", "label": "Transaction", "type": "hub"}},
            {"data": {"id": "wallet1", "label": "WalletAddress", "type": "input"}},
            {"data": {"id": "1.1.1.1", "label": "IPAddress", "type": "network"}},
            {"data": {"id": "AS13335", "label": "ASN", "type": "infrastructure"}},
        ],
        "edges": [
            {"data": {"source": "wallet1", "target": "tx1", "relationship": "SPENT"}},
            {"data": {"source": "tx1", "target": "1.1.1.1", "relationship": "BROADCAST_FROM"}},
            {"data": {"source": "1.1.1.1", "target": "AS13335", "relationship": "BELONGS_TO"}},
        ],
    }
    svg = build_subgraph_svg(graph)
    assert svg.startswith("<svg")
    assert "<line" in svg
    assert "Transaction" in svg
    assert "WalletAddress" in svg
    assert "IPAddress" in svg
    assert "ASN" in svg


def test_build_subgraph_svg_centers_requested_root_transaction():
    graph = {
        "nodes": [
            {"data": {"id": "aaa_other_tx", "label": "Transaction", "type": "hub"}},
            {"data": {"id": "zzz_requested_tx", "label": "Transaction", "type": "hub"}},
            {"data": {"id": "wallet1", "label": "WalletAddress", "type": "input"}},
        ],
        "edges": [
            {"data": {"source": "aaa_other_tx", "target": "wallet1", "relationship": "RECEIVED"}},
            {"data": {"source": "wallet1", "target": "zzz_requested_tx", "relationship": "SPENT"}},
        ],
    }

    svg = build_subgraph_svg(graph, root_id="zzz_requested_tx")

    assert "<circle data-node-id='zzz_requested_tx' cx='360' cy='180'" in svg


def test_source_and_package_dossier_templates_match():
    root = Path(__file__).resolve().parents[1]
    source_template = root / "templates" / "dossier.html"
    package_template = root / "shadowtrace" / "templates" / "dossier.html"
    assert source_template.read_text(encoding="utf-8") == package_template.read_text(encoding="utf-8")


def test_dossier_template_includes_edge_metadata_table():
    template = (Path(__file__).resolve().parents[1] / "shadowtrace" / "templates" / "dossier.html").read_text(encoding="utf-8")
    assert "Explainability Visuals" in template
    assert "{{ xai_chart_svg }}" in template
    assert "<h3>Edges</h3>" in template
    assert "{{ edge.data.source }}" in template
    assert "{{ edge.data.target }}" in template
    assert "{{ edge.data.relationship }}" in template
    assert "{{ edge.data.amount_btc|default(\"\", true) }}" in template
    assert "{{ edge.data.timestamp|default(\"\", true) }}" in template


def test_dossier_template_always_includes_feature_attribution():
    templates_dir = Path(__file__).resolve().parents[1] / "shadowtrace" / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=select_autoescape())
    graph = {"nodes": [], "edges": []}
    html = env.get_template("dossier.html").render(
        tx_id="tx1",
        investigator_id="investigator",
        generated_at="2026-09-07T00:00:00Z",
        alert={
            "threat_score": 42.0,
            "risk_level": "medium",
            "primary_anomaly": "cioh_cluster",
            "timestamp": "2026-09-07T00:00:00Z",
        },
        evidence={
            "chain_of_custody_hash": chain_of_custody_hash("tx1", graph, "2026-09-07T00:00:00Z"),
            "xai_breakdown": [{"feature": "cioh_cluster", "value": 1, "contribution_percentage": 42.0}],
        },
        graph=graph,
        graph_svg="<svg></svg>",
        xai_chart_svg="<svg><text>XAI Contribution Chart</text></svg>",
        include_xai_visuals=False,
        include_network_metadata=False,
    )

    assert "Feature Attribution" in html
    assert "XAI Contribution Chart" in html
    assert "cioh_cluster" in html
    assert "42.0" in html


def test_dossier_file_name_sanitizes_transaction_ids():
    file_name = dossier_file_name("../tx/id with spaces")
    assert file_name == "dossier_tx_id_with_spaces.pdf"
    assert "/" not in file_name
    assert "\\" not in file_name
    assert file_name.endswith(".pdf")


def test_build_xai_pie_svg_contains_chart_segments_and_legend():
    svg = build_xai_pie_svg(
        {
            "overall_threat_score": 88,
            "xai_breakdown": [
                {"feature": "peel_chain", "value": True, "contribution_percentage": 50},
                {"feature": "bulletproof_asn", "value": "AS43350", "contribution_percentage": 38},
            ],
        }
    )

    assert svg.startswith("<svg")
    assert "XAI Contribution Chart" in svg
    assert "<path" in svg
    assert "peel_chain" in svg
    assert "bulletproof_asn" in svg


def test_fallback_pdf_is_readable_dossier_not_raw_html(tmp_path, monkeypatch):
    class BrokenHTML:
        def __init__(self, *args, **kwargs):
            pass

        def write_pdf(self, *args, **kwargs):
            raise RuntimeError("native renderer unavailable")

    monkeypatch.setenv("SHADOWTRACE_ALLOW_PDF_FALLBACK", "1")
    monkeypatch.setitem(sys.modules, "weasyprint", types.SimpleNamespace(HTML=BrokenHTML))
    monkeypatch.setattr("shadowtrace.dossier.REPORTS_DIR", tmp_path)
    graph = {
        "nodes": [{"data": {"id": "tx1", "label": "Transaction", "type": "hub"}}],
        "edges": [],
    }
    output, _elapsed = generate_dossier(
        tx_id="tx1",
        investigator_id="NTRO_TEST",
        alert={
            "threat_score": 42,
            "risk_level": "medium",
            "primary_anomaly": "Peel Chain",
            "timestamp": "2026-09-07T00:00:00Z",
        },
        evidence={
            "overall_threat_score": 42,
            "chain_of_custody_hash": chain_of_custody_hash("tx1", graph, "2026-09-07T00:00:00Z"),
            "xai_breakdown": [{"feature": "peel_chain", "value": True, "contribution_percentage": 42}],
        },
        graph=graph,
        include_xai_visuals=True,
        include_network_metadata=True,
    )

    pdf = output.read_bytes()
    assert pdf.startswith(b"%PDF")
    assert b"NTRO ShadowTrace-XAI Evidence Dossier" in pdf
    assert b"XAI Contribution Chart" in pdf
    assert b"Subgraph Visualization" in pdf
    assert b"Feature Attribution" in pdf
    assert b"<!doctype html>" not in pdf
