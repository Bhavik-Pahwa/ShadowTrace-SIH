from pathlib import Path
import os
import re
from html import escape
from math import cos, pi, sin
from time import perf_counter

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from .config import REPORTS_DIR, TEMPLATES_DIR


def dossier_file_name(tx_id: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", tx_id).strip("._")
    if not stem:
        stem = "transaction"
    return f"dossier_{stem[:120]}.pdf"


def generate_dossier(
    tx_id: str,
    investigator_id: str,
    alert: dict,
    evidence: dict,
    graph: dict,
    include_xai_visuals: bool,
    include_network_metadata: bool,
    xai_graph: dict | None = None,
) -> tuple[Path, float]:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=select_autoescape())
    template = env.get_template("dossier.html")
    visual_graph = xai_graph if include_xai_visuals and xai_graph else graph
    html = template.render(
        tx_id=tx_id,
        investigator_id=investigator_id,
        alert=alert,
        evidence=evidence,
        graph=graph,
        graph_svg=Markup(build_subgraph_svg(visual_graph, root_id=tx_id)),
        xai_chart_svg=Markup(build_xai_pie_svg(evidence)),
        include_xai_visuals=include_xai_visuals,
        include_network_metadata=include_network_metadata,
    )
    output = REPORTS_DIR / dossier_file_name(tx_id)
    started = perf_counter()
    try:
        from weasyprint import HTML

        HTML(string=html, base_url=str(TEMPLATES_DIR)).write_pdf(str(output))
    except Exception:
        if os.environ.get("SHADOWTRACE_ALLOW_PDF_FALLBACK") != "1":
            raise
        write_text_fallback_pdf(
            output=output,
            tx_id=tx_id,
            investigator_id=investigator_id,
            alert=alert,
            evidence=evidence,
            graph=graph,
            visual_graph=visual_graph,
            include_network_metadata=include_network_metadata,
        )
    return output, perf_counter() - started


def write_text_fallback_pdf(
    output: Path,
    tx_id: str,
    investigator_id: str,
    alert: dict,
    evidence: dict,
    graph: dict,
    visual_graph: dict,
    include_network_metadata: bool,
) -> None:
    """Write a readable local PDF when WeasyPrint native libraries are unavailable."""
    lines = dossier_text_lines(
        tx_id=tx_id,
        investigator_id=investigator_id,
        alert=alert,
        evidence=evidence,
        graph=graph,
        include_network_metadata=include_network_metadata,
    )
    visual_page_lines = [
        "NTRO ShadowTrace-XAI Evidence Dossier",
        f"Transaction: {tx_id}",
        f"Investigator: {investigator_id}",
        f"Threat Score: {evidence.get('overall_threat_score', '')}",
        f"Risk Level: {alert.get('risk_level', '')}",
        f"Primary Anomaly: {alert.get('primary_anomaly', '')}",
    ]
    pages = paginate_lines(lines, max_lines=46)
    objects: list[bytes] = []
    page_object_numbers: list[int] = []
    content_object_numbers: list[int] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    next_object_number = 4
    visual_content = pdf_visual_stream(
        title_lines=visual_page_lines,
        evidence=evidence,
        graph=visual_graph,
        root_id=tx_id,
    )
    page_object_numbers.append(next_object_number)
    content_object_numbers.append(next_object_number + 1)
    next_object_number += 2
    objects.append(
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_numbers[-1]} 0 R >>".encode("ascii")
    )
    objects.append(b"<< /Length " + str(len(visual_content)).encode("ascii") + b" >> stream\n" + visual_content + b"\nendstream")

    for page_lines in pages:
        page_object_numbers.append(next_object_number)
        content_object_numbers.append(next_object_number + 1)
        next_object_number += 2

        content = pdf_text_stream(page_lines)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_numbers[-1]} 0 R >>".encode("ascii")
        )
        objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >> stream\n" + content + b"\nendstream")

    kids = " ".join(f"{number} 0 R" for number in page_object_numbers)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_numbers)} >>".encode("ascii")
    output.write_bytes(serialize_pdf(objects))


def dossier_text_lines(
    tx_id: str,
    investigator_id: str,
    alert: dict,
    evidence: dict,
    graph: dict,
    include_network_metadata: bool,
) -> list[str]:
    lines = [
        "NTRO ShadowTrace-XAI Evidence Dossier",
        f"Investigator: {investigator_id}",
        f"Transaction: {tx_id}",
        "",
        "Evidence Summary",
        f"Threat Score: {evidence.get('overall_threat_score', '')}",
        f"Risk Level: {alert.get('risk_level', '')}",
        f"Primary Anomaly: {alert.get('primary_anomaly', '')}",
        f"Timestamp: {alert.get('timestamp', '')}",
        "",
        "Feature Attribution",
    ]
    for item in evidence.get("xai_breakdown", []):
        lines.append(
            f"- {item.get('feature', '')}: value={item.get('value', '')}; "
            f"contribution={item.get('contribution_percentage', '')}"
        )

    lines.extend(
        [
            "",
            "Subgraph Summary",
            f"Nodes: {len(graph.get('nodes', []))}",
            f"Edges: {len(graph.get('edges', []))}",
        ]
    )

    if include_network_metadata:
        lines.extend(["", "Selected Nodes"])
        for node in graph.get("nodes", [])[:24]:
            data = node.get("data", {})
            lines.append(
                f"- {data.get('id', '')} | {data.get('label', '')} | "
                f"{data.get('type', '')} | {data.get('country') or data.get('description') or data.get('entity_id') or ''}"
            )
        lines.extend(["", "Selected Edges"])
        for edge in graph.get("edges", [])[:32]:
            data = edge.get("data", {})
            amount = data.get("amount_btc", "")
            lines.append(
                f"- {data.get('source', '')} -> {data.get('target', '')} | "
                f"{data.get('relationship', '')} | amount={amount} | timestamp={data.get('timestamp', '')}"
            )

    lines.extend(["", "Chain Of Custody", str(evidence.get("chain_of_custody_hash", ""))])
    return [line for source_line in lines for line in wrap_pdf_line(source_line)]


def wrap_pdf_line(line: str, width: int = 92) -> list[str]:
    if len(line) <= width:
        return [line]
    wrapped = []
    remaining = line
    while len(remaining) > width:
        split_at = remaining.rfind(" ", 0, width)
        if split_at <= 0:
            split_at = width
        wrapped.append(remaining[:split_at])
        remaining = "  " + remaining[split_at:].strip()
    wrapped.append(remaining)
    return wrapped


def paginate_lines(lines: list[str], max_lines: int) -> list[list[str]]:
    return [lines[index : index + max_lines] for index in range(0, len(lines), max_lines)] or [["No dossier content available."]]


def pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf_text_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "50 750 Td", "14 TL"]
    for line in lines:
        safe = pdf_escape(line.encode("latin-1", errors="replace").decode("latin-1"))
        commands.append(f"({safe}) Tj")
        commands.append("T*")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1")


def pdf_visual_stream(title_lines: list[str], evidence: dict, graph: dict, root_id: str) -> bytes:
    commands: list[str] = [
        "0.98 0.97 0.94 rg",
        "0 0 612 792 re f",
        "0.07 0.08 0.09 rg",
        "42 704 528 46 re f",
        "1 1 1 rg",
        "BT /F1 18 Tf 58 730 Td (Forensic Investigation Dossier) Tj ET",
        "0.95 0.93 0.87 rg",
        "42 642 528 46 re f",
    ]
    commands.extend(pdf_text_commands(title_lines[1:], x=58, y=688, font_size=9, line_height=12, color=(0.16, 0.18, 0.18)))
    commands.extend(pdf_text_commands(["XAI Contribution Chart"], x=58, y=614, font_size=14, line_height=16, color=(0.07, 0.08, 0.09)))
    commands.extend(pdf_pie_commands(evidence.get("xai_breakdown", []), center_x=160, center_y=506, radius=72))
    commands.extend(pdf_legend_commands(evidence.get("xai_breakdown", []), x=260, y=560))
    commands.extend(pdf_text_commands(["Subgraph Visualization"], x=58, y=378, font_size=14, line_height=16, color=(0.07, 0.08, 0.09)))
    commands.extend(pdf_graph_commands(graph=graph, root_id=root_id, x=58, y=84, width=496, height=270))
    return "\n".join(commands).encode("latin-1", errors="replace")


def pdf_text_commands(
    lines: list[str],
    x: int,
    y: int,
    font_size: int,
    line_height: int,
    color: tuple[float, float, float],
) -> list[str]:
    r, g, b = color
    commands = [f"{r:.3f} {g:.3f} {b:.3f} rg", "BT", f"/F1 {font_size} Tf", f"{x} {y} Td", f"{line_height} TL"]
    for line in lines:
        commands.append(f"({pdf_escape(line.encode('latin-1', errors='replace').decode('latin-1'))}) Tj")
        commands.append("T*")
    commands.append("ET")
    return commands


def pdf_pie_commands(features: list[dict], center_x: int, center_y: int, radius: int) -> list[str]:
    colors = [(0.75, 0.56, 0.14), (0.09, 0.45, 0.37), (0.16, 0.38, 0.56), (0.71, 0.14, 0.09), (0.47, 0.33, 0.28)]
    total = sum(float(item.get("contribution_percentage") or 0) for item in features) or 1.0
    start_angle = -pi / 2
    commands: list[str] = []
    for index, item in enumerate(features[:6]):
        value = max(float(item.get("contribution_percentage") or 0), 0)
        end_angle = start_angle + (2 * pi * value / total)
        steps = max(3, int((end_angle - start_angle) / (pi / 10)))
        points = [(center_x, center_y)]
        for step in range(steps + 1):
            angle = start_angle + (end_angle - start_angle) * step / steps
            points.append((center_x + cos(angle) * radius, center_y + sin(angle) * radius))
        r, g, b = colors[index % len(colors)]
        commands.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        commands.append(f"{points[0][0]:.2f} {points[0][1]:.2f} m")
        for x, y in points[1:]:
            commands.append(f"{x:.2f} {y:.2f} l")
        commands.append("h f")
        start_angle = end_angle
    commands.extend(["1 1 1 rg", f"{center_x - 36} {center_y - 36} 72 72 re f"])
    commands.extend(pdf_text_commands(["XAI", "score"], x=center_x - 17, y=center_y + 8, font_size=11, line_height=13, color=(0.07, 0.08, 0.09)))
    return commands


def pdf_legend_commands(features: list[dict], x: int, y: int) -> list[str]:
    colors = [(0.75, 0.56, 0.14), (0.09, 0.45, 0.37), (0.16, 0.38, 0.56), (0.71, 0.14, 0.09), (0.47, 0.33, 0.28)]
    commands: list[str] = []
    for index, item in enumerate(features[:5]):
        r, g, b = colors[index % len(colors)]
        label = f"{item.get('feature', '')}: {item.get('contribution_percentage', '')}"
        commands.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        commands.append(f"{x} {y - index * 28} 12 12 re f")
        commands.extend(pdf_text_commands([wrap_pdf_line(label, width=42)[0]], x=x + 20, y=y + 2 - index * 28, font_size=9, line_height=10, color=(0.16, 0.18, 0.18)))
    return commands


def pdf_graph_commands(graph: dict, root_id: str, x: int, y: int, width: int, height: int) -> list[str]:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        return pdf_text_commands(["No subgraph nodes available"], x=x + 12, y=y + height // 2, font_size=10, line_height=12, color=(0.16, 0.18, 0.18))

    node_ids = {node["data"]["id"] for node in nodes}
    root = root_id if root_id in node_ids else nodes[0]["data"]["id"]
    tx_nodes = [node for node in nodes if node["data"].get("label") == "Transaction" and node["data"]["id"] != root][:5]
    wallet_nodes = [node for node in nodes if node["data"].get("label") == "WalletAddress"][:5]
    network_nodes = [node for node in nodes if node["data"].get("label") == "IPAddress"][:5]
    asn_nodes = [node for node in nodes if node["data"].get("label") == "ASN"][:2]
    positions: dict[str, tuple[float, float, str]] = {root: (x + width * 0.48, y + height * 0.48, "Root")}

    def place(group: list[dict], px: float, start_y: float, step: float, label: str) -> None:
        for index, node in enumerate(group):
            positions[node["data"]["id"]] = (px, start_y - index * step, label)

    place(tx_nodes, x + width * 0.25, y + height * 0.82, 36, "TX")
    place(wallet_nodes, x + width * 0.76, y + height * 0.82, 34, "Wallet")
    place(network_nodes, x + width * 0.76, y + height * 0.34, 28, "IP")
    place(asn_nodes, x + width * 0.94, y + height * 0.30, 42, "ASN")

    commands = ["1 1 1 rg", f"{x} {y} {width} {height} re f", "0.84 0.82 0.76 RG", f"{x} {y} {width} {height} re S"]
    for edge in edges:
        data = edge.get("data", {})
        source = positions.get(data.get("source"))
        target = positions.get(data.get("target"))
        if not source or not target:
            continue
        commands.extend(["0.45 0.48 0.48 RG", "1.1 w", f"{source[0]:.2f} {source[1]:.2f} m {target[0]:.2f} {target[1]:.2f} l S"])
    colors = {
        "Root": (0.71, 0.14, 0.09),
        "TX": (0.75, 0.56, 0.14),
        "Wallet": (0.09, 0.45, 0.37),
        "IP": (0.16, 0.38, 0.56),
        "ASN": (0.47, 0.33, 0.28),
    }
    for node_id, (node_x, node_y, label) in positions.items():
        r, g, b = colors[label]
        commands.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        commands.append(f"{node_x - 25:.2f} {node_y - 10:.2f} 50 20 re f")
        commands.extend(pdf_text_commands([label, str(node_id)[:9]], x=int(node_x - 20), y=int(node_y + 2), font_size=6, line_height=7, color=(1, 1, 1)))
    return commands


def serialize_pdf(objects: list[bytes]) -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    startxref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer << /Root 1 0 R /Size {len(objects) + 1} >>\nstartxref\n{startxref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def build_xai_pie_svg(evidence: dict, width: int = 520, height: int = 240) -> str:
    features = evidence.get("xai_breakdown", [])
    total = sum(float(item.get("contribution_percentage") or 0) for item in features) or 1.0
    colors = ["#bf8f24", "#16725f", "#2a628f", "#b42318", "#795548", "#69706f"]
    center_x = 115
    center_y = 118
    radius = 82
    start_angle = -pi / 2
    parts = [
        f"<svg width='{width}' height='{height}' viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>",
        "<rect width='100%' height='100%' rx='8' fill='#fbfaf7' stroke='#d1d5db'/>",
        "<text x='24' y='30' font-size='15' font-weight='700' fill='#111827'>XAI Contribution Chart</text>",
    ]

    for index, item in enumerate(features[:6]):
        value = max(float(item.get("contribution_percentage") or 0), 0)
        end_angle = start_angle + (2 * pi * value / total)
        large_arc = 1 if end_angle - start_angle > pi else 0
        x1 = center_x + cos(start_angle) * radius
        y1 = center_y + sin(start_angle) * radius
        x2 = center_x + cos(end_angle) * radius
        y2 = center_y + sin(end_angle) * radius
        color = colors[index % len(colors)]
        parts.append(
            f"<path d='M {center_x:.2f} {center_y:.2f} L {x1:.2f} {y1:.2f} "
            f"A {radius} {radius} 0 {large_arc} 1 {x2:.2f} {y2:.2f} Z' fill='{color}'/>"
        )
        legend_y = 70 + index * 24
        label = escape(str(item.get("feature", ""))[:34])
        contribution = escape(str(item.get("contribution_percentage", "")))
        parts.append(f"<rect x='240' y='{legend_y - 11}' width='12' height='12' fill='{color}'/>")
        parts.append(f"<text x='262' y='{legend_y}' font-size='11' fill='#111827'>{label}</text>")
        parts.append(f"<text x='470' y='{legend_y}' text-anchor='end' font-size='11' font-weight='700' fill='#111827'>{contribution}</text>")
        start_angle = end_angle

    parts.extend(
        [
            f"<circle cx='{center_x}' cy='{center_y}' r='36' fill='#fbfaf7'/>",
            f"<text x='{center_x}' y='{center_y - 2}' text-anchor='middle' font-size='16' font-weight='700' fill='#111827'>{escape(str(evidence.get('overall_threat_score', '')))}</text>",
            f"<text x='{center_x}' y='{center_y + 14}' text-anchor='middle' font-size='9' fill='#4b5563'>score</text>",
            "</svg>",
        ]
    )
    return "".join(parts)


def build_subgraph_svg(graph: dict, width: int = 720, height: int = 360, root_id: str | None = None) -> str:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        return "<svg width='720' height='120' xmlns='http://www.w3.org/2000/svg'><text x='20' y='60'>No subgraph nodes available</text></svg>"

    center_x = width // 2
    center_y = height // 2
    radius = min(width, height) // 2 - 52
    positions = {}
    node_ids = {node["data"]["id"] for node in nodes}
    root = root_id if root_id in node_ids else next((node["data"]["id"] for node in nodes if node["data"].get("label") == "Transaction"), nodes[0]["data"]["id"])
    positions[root] = (center_x, center_y)
    others = [node for node in nodes if node["data"]["id"] != root]
    for idx, node in enumerate(others):
        angle = (2 * pi * idx) / max(len(others), 1)
        positions[node["data"]["id"]] = (center_x + int(cos(angle) * radius), center_y + int(sin(angle) * radius))

    parts = [
        f"<svg width='{width}' height='{height}' viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>",
        "<defs><marker id='arrow' markerWidth='8' markerHeight='8' refX='7' refY='3' orient='auto'><path d='M0,0 L0,6 L7,3 z' fill='#6b7280'/></marker></defs>",
        "<rect width='100%' height='100%' fill='#f9fafb' stroke='#d1d5db'/>",
    ]
    for edge in edges:
        data = edge["data"]
        if data["source"] not in positions or data["target"] not in positions:
            continue
        x1, y1 = positions[data["source"]]
        x2, y2 = positions[data["target"]]
        parts.append(f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='#6b7280' stroke-width='1.5' marker-end='url(#arrow)'/>")
    colors = {"Transaction": "#d97706", "WalletAddress": "#0f766e", "IPAddress": "#2563eb", "ASN": "#7c3aed"}
    for node in nodes:
        data = node["data"]
        node_id = data["id"]
        x, y = positions[node_id]
        label = data.get("label", "Node")
        fill = colors.get(label, "#64748b")
        short = escape(str(node_id)[:16])
        parts.append(f"<circle data-node-id='{escape(str(node_id), quote=True)}' cx='{x}' cy='{y}' r='15' fill='{fill}' stroke='#111827' stroke-width='1'/>")
        parts.append(f"<text x='{x}' y='{y + 31}' text-anchor='middle' font-size='9' fill='#111827'>{escape(label)}</text>")
        parts.append(f"<text x='{x}' y='{y + 43}' text-anchor='middle' font-size='7' fill='#4b5563'>{short}</text>")
    parts.append("</svg>")
    return "".join(parts)
