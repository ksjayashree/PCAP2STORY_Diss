#!/usr/bin/env python3
"""Generate an HTML validation report for all synthetic EVPN pcaps.

Runs both the PCAP inspector (sensitivity) and evpnpcapcheck verify (protocol
semantics) against every pcap, then produces a collapsible HTML report.

Usage:
    python scripts/generate_report.py
    python scripts/generate_report.py --output report.html
    python scripts/generate_report.py --topology configs/default_topology.yaml
"""

import argparse
import html
import io
import json
import subprocess
import sys
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

# Add repo root to sys.path so package imports resolve
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


SECTIONS = [
    ("section1_normal", "Section 1 — Normal Traffic"),
    ("section2_labelled", "Section 2 — Labelled Faults"),
    ("section3_mixed", "Section 3 — Mixed Scenarios"),
]


INSPECTOR_SCRIPT = None  # unused; inspector is imported directly


def run_inspector(pcap_path: Path) -> str:
    """Run the PCAP sensitivity inspector and return text output."""
    import re
    from checkers.evpn_bgp.inspector import PcapInspector
    buf = io.StringIO()
    with redirect_stdout(buf):
        inspector = PcapInspector(str(pcap_path))
        inspector.scan()
    output = buf.getvalue() or "No output"
    # Strip ANSI colour codes for clean HTML embedding
    return re.sub(r'\x1b\[[0-9;]*m', '', output)


def parse_inspector_sections(output: str) -> list[tuple[str, str]]:
    """Split inspector output into (title, content) sections.

    Sections are delimited by emoji-prefixed headings (e.g. '📊 CAPTURE SUMMARY').
    """
    import re
    # Match lines that start with an emoji followed by section title
    section_re = re.compile(
        r'^([📊🌐📡🏷🔗🛡📋✅⚠🔴🟢🟡🛑🔢🗂💬🔖⚙️].+)$', re.MULTILINE)

    splits = list(section_re.finditer(output))
    if not splits:
        return [("Full Output", output)]

    sections = []
    # Content before first section (header/banner)
    preamble = output[:splits[0].start()].strip()
    if preamble:
        sections.append(("File Info", preamble))

    for i, match in enumerate(splits):
        title = match.group(1).strip()
        start = match.end()
        end = splits[i + 1].start() if i + 1 < len(splits) else len(output)
        content = output[start:end].strip()
        # Clean up separator lines
        content = re.sub(r'^-{10,}$', '', content, flags=re.MULTILINE).strip()
        sections.append((title, content))

    return sections


def run_evpnpcapcheck(pcap_path: Path, topology: Path = None) -> str:
    """Run evpnpcapcheck verify and return markdown output."""
    cmd = [sys.executable, "-m", "checkers.evpn_bgp", "verify", str(pcap_path)]
    if topology:
        cmd.extend(["--topology", str(topology)])

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    return result.stdout or result.stderr or "No output"


def inspector_badge(output: str) -> str:
    return ''


def checker_badge(output: str) -> str:
    return ''


def generate_topology_svg(topology_path: Path) -> str:
    """Generate an inline SVG network topology diagram from the YAML config."""
    import yaml

    with open(topology_path) as f:
        topo = yaml.safe_load(f)

    rrs = topo.get("route_reflectors", [])
    pes = topo.get("pe_nodes", [])
    vantage = topo.get("capture_vantage", "")
    as_number = topo.get("as_number", "")

    # Build ESI groups for multi-homing links
    esi_groups: dict[str, list[dict]] = {}
    for pe in pes:
        esi = pe.get("esi", "")
        if esi:
            esi_groups.setdefault(esi, []).append(pe)

    # Layout params
    width = 900
    rr_y = 80
    pe_y = 280
    node_r = 30

    # Position RRs
    rr_spacing = width // (len(rrs) + 1)
    rr_positions = {}
    for i, rr in enumerate(rrs):
        rr_positions[rr["id"]] = (rr_spacing * (i + 1), rr_y)

    # Position PEs
    pe_spacing = width // (len(pes) + 1)
    pe_positions = {}
    for i, pe in enumerate(pes):
        pe_positions[pe["id"]] = (pe_spacing * (i + 1), pe_y)

    # Determine height
    height = 400

    lines = []
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
                 f'style="max-width:100%; height:auto; background:#fff; border-radius:8px; '
                 f'border:1px solid #dee2e6;">')

    # Title
    lines.append(f'<text x="{width//2}" y="30" text-anchor="middle" '
                 f'font-size="14" font-weight="bold" fill="#1a1a2e">'
                 f'Network Topology — AS {as_number}</text>')

    # Draw BGP session lines (each PE connects to ALL RRs)
    for rr_id, (rx, ry) in rr_positions.items():
        is_vantage_rr = (rr_id == vantage)
        stroke_color = "#16213e" if is_vantage_rr else "#adb5bd"
        stroke_w = "1.5" if is_vantage_rr else "1"
        for pe_id, (px, py) in pe_positions.items():
            lines.append(f'<line x1="{rx}" y1="{ry + node_r}" x2="{px}" y2="{py - node_r}" '
                         f'stroke="{stroke_color}" stroke-width="{stroke_w}" stroke-dasharray="4,2"/>')

    # Draw ESI multi-homing links between peers
    for esi, peers in esi_groups.items():
        if len(peers) >= 2:
            for i in range(len(peers) - 1):
                p1 = pe_positions[peers[i]["id"]]
                p2 = pe_positions[peers[i + 1]["id"]]
                mid_y = pe_y + node_r + 30
                lines.append(f'<path d="M {p1[0]} {p1[1] + node_r} Q {(p1[0]+p2[0])//2} {mid_y} '
                             f'{p2[0]} {p2[1] + node_r}" '
                             f'fill="none" stroke="#e63946" stroke-width="2" stroke-dasharray="6,3"/>')
                short_esi = esi[-5:]  # last 5 chars for display
                lines.append(f'<text x="{(p1[0]+p2[0])//2}" y="{mid_y + 15}" text-anchor="middle" '
                             f'font-size="10" fill="#e63946">ESI ...{short_esi}</text>')

    # Draw RR nodes
    for rr in rrs:
        x, y = rr_positions[rr["id"]]
        is_vantage = rr["id"] == vantage
        fill = "#16213e" if is_vantage else "#495057"
        stroke = "#ffd700" if is_vantage else "#16213e"
        sw = "3" if is_vantage else "2"
        lines.append(f'<rect x="{x - node_r}" y="{y - node_r}" width="{node_r*2}" height="{node_r*2}" '
                     f'rx="6" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')
        lines.append(f'<text x="{x}" y="{y + 5}" text-anchor="middle" '
                     f'font-size="12" font-weight="bold" fill="#fff">{rr["id"]}</text>')
        # Label below
        label = f'{rr["loopback"]}'
        lines.append(f'<text x="{x}" y="{y - node_r - 8}" text-anchor="middle" '
                     f'font-size="9" fill="#495057">{html.escape(label)}</text>')
        if is_vantage:
            lines.append(f'<text x="{x}" y="{y + node_r + 15}" text-anchor="middle" '
                         f'font-size="9" fill="#ffd700" font-weight="bold">⬤ VANTAGE</text>')

    # Draw PE nodes
    for pe in pes:
        x, y = pe_positions[pe["id"]]
        has_esi = bool(pe.get("esi", ""))
        fill = "#2a9d8f" if has_esi else "#457b9d"
        lines.append(f'<circle cx="{x}" cy="{y}" r="{node_r}" '
                     f'fill="{fill}" stroke="#1a1a2e" stroke-width="2"/>')
        lines.append(f'<text x="{x}" y="{y + 5}" text-anchor="middle" '
                     f'font-size="12" font-weight="bold" fill="#fff">{pe["id"]}</text>')
        # Loopback label above
        lines.append(f'<text x="{x}" y="{y - node_r - 8}" text-anchor="middle" '
                     f'font-size="9" fill="#495057">{html.escape(pe["loopback"])}</text>')

    # Legend
    legend_y = height - 40
    lines.append(f'<rect x="20" y="{legend_y}" width="12" height="12" rx="2" fill="#16213e"/>')
    lines.append(f'<text x="38" y="{legend_y + 10}" font-size="10" fill="#495057">Route Reflector</text>')
    lines.append(f'<circle cx="146" cy="{legend_y + 6}" r="6" fill="#2a9d8f"/>')
    lines.append(f'<text x="158" y="{legend_y + 10}" font-size="10" fill="#495057">Multi-homed PE</text>')
    lines.append(f'<circle cx="276" cy="{legend_y + 6}" r="6" fill="#457b9d"/>')
    lines.append(f'<text x="288" y="{legend_y + 10}" font-size="10" fill="#495057">Single-homed PE</text>')
    lines.append(f'<line x1="390" y1="{legend_y + 6}" x2="410" y2="{legend_y + 6}" '
                 f'stroke="#6c757d" stroke-width="1.5" stroke-dasharray="4,2"/>')
    lines.append(f'<text x="416" y="{legend_y + 10}" font-size="10" fill="#495057">BGP Session</text>')
    lines.append(f'<line x1="500" y1="{legend_y + 6}" x2="520" y2="{legend_y + 6}" '
                 f'stroke="#e63946" stroke-width="2" stroke-dasharray="6,3"/>')
    lines.append(f'<text x="526" y="{legend_y + 10}" font-size="10" fill="#495057">Shared ESI</text>')

    lines.append('</svg>')
    return "\n".join(lines)


def generate_html(sections_data: dict, topology_used: str, topology_svg: str = "") -> str:
    """Generate the full HTML report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count totals
    total_pcaps = sum(len(files) for files in sections_data.values())
    total_clean_inspector = sum(
        1 for files in sections_data.values()
        for f in files if "HIGH" not in f["inspector_output"] and "CRITICAL" not in f["inspector_output"]
    )
    total_clean_checker = sum(
        1 for files in sections_data.values()
        for f in files if "No issues found" in f["checker_output"]
    )

    html_parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EVPN PCAP Analysis Report</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 1200px; margin: 0 auto; padding: 20px;
    background: #f8f9fa; color: #212529;
}}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
.summary {{ background: #fff; border-radius: 8px; padding: 20px; margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
.stat {{ text-align: center; padding: 15px; border-radius: 6px; background: #e9ecef; }}
.stat-value {{ font-size: 2em; font-weight: bold; }}
.stat-label {{ font-size: 0.85em; color: #6c757d; }}
details {{ margin: 10px 0; }}
details > summary {{
    cursor: pointer; padding: 12px 16px; border-radius: 6px;
    font-weight: 600; list-style: none; position: relative;
}}
details > summary::-webkit-details-marker {{ display: none; }}
details > summary::before {{
    content: '▶'; position: absolute; left: 16px;
    transition: transform 0.2s;
}}
details[open] > summary::before {{ transform: rotate(90deg); }}
details > summary {{ padding-left: 40px; }}
.section-details > summary {{
    background: #16213e; color: #fff; font-size: 1.1em;
}}
.pcap-details > summary {{
    background: #fff; border: 1px solid #dee2e6;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}}
.pcap-details > summary:hover {{ background: #f1f3f5; }}
.pcap-content {{ padding: 15px; margin: 5px 0 15px 0; background: #fff;
                 border: 1px solid #dee2e6; border-radius: 0 0 6px 6px; }}
.tool-section {{ margin: 15px 0; }}
.tool-section h4 {{ margin: 0 0 8px 0; color: #495057; border-bottom: 1px solid #dee2e6; padding-bottom: 5px; }}
.inspector-subsection {{ margin: 4px 0; }}
.inspector-subsection > summary {{
    padding: 6px 12px; font-size: 0.9em; cursor: pointer;
    background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px;
}}
.inspector-subsection > summary:hover {{ background: #e9ecef; }}
.inspector-subsection > pre {{ margin: 4px 0 8px 12px; }}
pre {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px;
       padding: 12px; overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; }}
.badge {{ display: none; }}
.checks-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 8px; margin: 10px 0; }}
.check-item {{ padding: 6px 10px; border-radius: 4px; font-size: 0.85em; }}
.check-item.pass {{ background: #d4edda; }}
.check-item.fail {{ background: #f8d7da; }}
.meta {{ color: #6c757d; font-size: 0.85em; margin-top: 20px; }}
</style>
</head>
<body>
<h1>🔍 EVPN PCAP Analysis Report</h1>

<div class="summary">
<div class="summary-grid">
    <div class="stat"><div class="stat-value">{total_pcaps}</div><div class="stat-label">Total PCAPs</div></div>
    <div class="stat"><div class="stat-value">{total_clean_inspector}/{total_pcaps}</div><div class="stat-label">Inspector OK</div></div>
    <div class="stat"><div class="stat-value">{total_clean_checker}/{total_pcaps}</div><div class="stat-label">Protocol Clean (evpnpcapcheck)</div></div>
</div>
<p class="meta">Generated: {now} | Topology: <code>{html.escape(topology_used or 'none')}</code></p>
</div>
"""]

    # Topology diagram section
    if topology_svg:
        html_parts.append(f"""
<details class="section-details" open>
<summary>Network Topology</summary>
<div style="padding: 20px;">
{topology_svg}
</div>
</details>
""")

    for section_dir, section_title in SECTIONS:
        files = sections_data.get(section_dir, [])
        if not files:
            continue

        html_parts.append(f"""
<details class="section-details">
<summary>{html.escape(section_title)} ({len(files)} pcaps)</summary>
<div style="padding: 10px;">
""")

        for entry in files:
            fname = entry["filename"]
            insp_out = entry["inspector_output"]
            checker_out = entry["checker_output"]

            # Build inspector sub-sections
            insp_sections = parse_inspector_sections(insp_out)
            insp_html_parts = []
            for sec_title, sec_content in insp_sections:
                insp_html_parts.append(f"""<details class="inspector-subsection">
<summary>{html.escape(sec_title)}</summary>
<pre>{html.escape(sec_content)}</pre>
</details>""")
            insp_sections_html = "\n".join(insp_html_parts)

            html_parts.append(f"""
<details class="pcap-details">
<summary>{html.escape(fname)} {inspector_badge(insp_out)} {checker_badge(checker_out)}</summary>
<div class="pcap-content">

<div class="tool-section">
<h4>PCAP Inspector — Analysis</h4>
{insp_sections_html}
</div>


<div class="tool-section">
<h4>evpnpcapcheck verify — Protocol Analysis</h4>
<pre>{html.escape(checker_out)}</pre>
</div>
""")

            html_parts.append("</div></details>")  # end pcap-details

        html_parts.append("</div></details>")  # end section-details

    html_parts.append("</body></html>")
    return "".join(html_parts)


def main():
    # Resolve paths relative to the repo root (parent of scripts/)
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(description="Generate HTML validation report")
    parser.add_argument("--output", "-o", default=str(repo_root / "report.html"),
                        help="Output HTML file")
    parser.add_argument("--topology", "-t",
                        default=str(repo_root / "configs" / "default_topology.yaml"),
                        help="Topology YAML for evpnpcapcheck")
    parser.add_argument("--pcap-dir", default=str(repo_root / "output"),
                        help="Directory containing pcaps")
    args = parser.parse_args()

    output_dir = Path(args.pcap_dir)
    topology = Path(args.topology) if args.topology else None

    sections_data = {}

    for section_dir, section_title in SECTIONS:
        section_path = output_dir / section_dir
        if not section_path.exists():
            continue

        pcaps = sorted(section_path.glob("*.pcap"))
        entries = []

        for pcap in pcaps:
            print(f"  Analysing {pcap.name}...", flush=True)
            insp_output = run_inspector(pcap)
            c_output = run_evpnpcapcheck(pcap, topology)
            entries.append({
                "filename": pcap.name,
                "inspector_output": insp_output,
                "checker_output": c_output,
            })

        sections_data[section_dir] = entries
        print(f"✓ {section_title}: {len(entries)} pcaps analysed")

    # Generate topology SVG if topology file provided
    topology_svg = ""
    if topology and topology.exists():
        topology_svg = generate_topology_svg(topology)
        print("✓ Topology diagram generated")

    report_html = generate_html(sections_data, args.topology, topology_svg)
    out_path = Path(args.output)
    out_path.write_text(report_html)
    print(f"\n✓ Report written to {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
