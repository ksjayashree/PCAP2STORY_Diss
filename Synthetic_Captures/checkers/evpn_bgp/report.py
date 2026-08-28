"""Report generation — Markdown and JSON output."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from checkers.evpn_bgp.model import EvpnRoute, Finding, MacEntry, Severity
from checkers.evpn_bgp.evpn.routes import route_type_name


def findings_to_markdown(
    findings: list[Finding],
    summary_only: bool = False,
) -> str:
    """Render findings as a Markdown report.

    When *summary_only* is ``True`` only the summary counts and a per-rule
    breakdown are emitted — individual finding details are suppressed.
    """
    if not findings:
        return "# EVPN-PCAP-Check Report\n\nNo issues found. All checks passed.\n"

    lines = ["# EVPN-PCAP-Check Report\n"]

    counts: dict[str, int] = {Severity.FAIL: 0, Severity.WARN: 0, Severity.INFO: 0}
    code_counts: dict[str, dict[str, int]] = {}  # code -> {severity, count}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.code not in code_counts:
            code_counts[f.code] = {"count": 0, "severity": f.severity}
        code_counts[f.code]["count"] += 1

    lines.append("## Summary\n")
    lines.append(f"- **FAIL**: {counts.get(Severity.FAIL, 0)}")
    lines.append(f"- **WARN**: {counts.get(Severity.WARN, 0)}")
    lines.append(f"- **INFO**: {counts.get(Severity.INFO, 0)}")
    lines.append("")

    if code_counts:
        lines.append("### By Rule\n")
        lines.append("| Rule | Severity | Count |")
        lines.append("|------|----------|-------|")
        for code in sorted(code_counts):
            info = code_counts[code]
            lines.append(f"| {code} | {info['severity']} | {info['count']} |")
        lines.append("")

    if summary_only:
        return "\n".join(lines)

    lines.append("## Findings\n")
    for f in findings:
        lines.append(f"### {f.severity} {f.code} — frame {f.frame}\n")
        lines.append(f.message)
        if f.impact:
            lines.append(f"\n**Impact**: {f.impact}")
        if f.evidence:
            lines.append(f"\n**Evidence**: `{json.dumps(f.evidence)}`")
        lines.append(f"\n**Confidence**: {f.confidence}\n")

    return "\n".join(lines)


def findings_to_json(findings: list[Finding]) -> str:
    """Render findings as JSON."""
    return json.dumps(
        [
            {
                "severity": f.severity,
                "code": f.code,
                "frame": f.frame,
                "message": f.message,
                "impact": f.impact,
                "evidence": f.evidence,
                "confidence": f.confidence,
            }
            for f in findings
        ],
        indent=2,
    )


def timeline_to_markdown(routes: list[EvpnRoute]) -> str:
    """Render an EVPN route timeline as Markdown."""
    if not routes:
        return "# EVPN Route Timeline\n\nNo EVPN routes found.\n"

    lines = ["# EVPN Route Timeline\n"]
    lines.append("| Frame | Time | Type | RD | MAC | IP | Next-Hop | W/D |")
    lines.append("|-------|------|------|-----|-----|-----|----------|-----|")

    for r in sorted(routes, key=lambda x: x.frame_number):
        wd = "W" if r.is_withdrawal else ""
        type_name = route_type_name(r.route_type)
        lines.append(
            f"| {r.frame_number} | {r.timestamp:.6f} | "
            f"{type_name} | {r.rd} | {r.mac} | {r.ip} | "
            f"{r.next_hop} | {wd} |"
        )

    return "\n".join(lines)


def mac_table_to_markdown(
    mac_table: dict[str, MacEntry],
    evi_filter: int | None = None,
) -> str:
    """Render the reconstructed MAC table as Markdown."""
    lines = ["# Reconstructed MAC Table\n"]
    lines.append("| MAC | IP | EVI | ESI | Next-Hop | Active | Moves |")
    lines.append("|-----|-----|-----|-----|----------|--------|-------|")

    for key, entry in sorted(mac_table.items()):
        if evi_filter is not None and entry.evi != evi_filter:
            continue
        active = "Yes" if entry.is_active else "No"
        lines.append(
            f"| {entry.mac} | {entry.ip} | {entry.evi} | "
            f"{entry.esi} | {entry.next_hop} | {active} | {entry.move_count} |"
        )

    if len(lines) == 3:
        lines.append("| *(empty)* | | | | | | |")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Ladder (sequence) diagram
# ---------------------------------------------------------------------------

def _short_rt(route_type: int) -> str:
    """Short label for a route type used in arrows."""
    return {
        1: "T1 EAD",
        2: "T2 MAC",
        3: "T3 IMET",
        4: "T4 ES",
        5: "T5 IP",
    }.get(route_type, f"T{route_type}")


def ladder_to_mermaid(
    routes: list[EvpnRoute],
    *,
    limit: int = 200,
    mac_filter: str | None = None,
    type_filter: list[int] | None = None,
) -> str:
    """Render an EVPN route exchange as a Mermaid sequence diagram.

    Each participating PE (identified by its next-hop / source IP) becomes a
    participant.  Routes are shown as arrows from the advertising PE to the
    receiving PE (destination IP).  Withdrawals are shown as dashed arrows.

    Parameters
    ----------
    routes : list[EvpnRoute]
        The EVPN routes to include.
    limit : int
        Maximum number of arrows to render (default 200).
    mac_filter : str | None
        If set, only include routes involving this MAC address.
    type_filter : list[int] | None
        If set, only include routes of these types (e.g. [2, 3]).
    """
    filtered = routes
    if mac_filter:
        mac_lower = mac_filter.lower()
        filtered = [r for r in filtered if r.mac.lower() == mac_lower]
    if type_filter:
        tf = set(type_filter)
        filtered = [r for r in filtered if r.route_type in tf]

    filtered.sort(key=lambda r: (r.timestamp, r.frame_number))
    filtered = filtered[:limit]

    if not filtered:
        return "```mermaid\nsequenceDiagram\n    Note over Source: No matching routes\n```"

    # Discover participants (PEs) by their IP addresses
    participants: dict[str, str] = {}  # ip -> alias

    def _alias(ip: str) -> str:
        if ip not in participants:
            idx = len(participants) + 1
            participants[ip] = f"PE{idx}"
        return participants[ip]

    # Pre-scan to build participant list in order of appearance
    for r in filtered:
        if r.src_ip:
            _alias(r.src_ip)
        if r.dst_ip:
            _alias(r.dst_ip)

    lines = ["```mermaid", "sequenceDiagram"]

    for ip, alias in participants.items():
        lines.append(f"    participant {alias} as {alias} ({ip})")

    for r in filtered:
        src = _alias(r.src_ip) if r.src_ip else "Unknown"
        dst = _alias(r.dst_ip) if r.dst_ip else "Unknown"
        label = _short_rt(r.route_type)
        extra_parts: list[str] = []
        if r.mac:
            extra_parts.append(r.mac)
        if r.ip:
            extra_parts.append(r.ip)
        if r.esi and r.esi != "00:00:00:00:00:00:00:00:00:00":
            extra_parts.append(f"ESI:{r.esi[-5:]}")
        extra = " " + " ".join(extra_parts) if extra_parts else ""

        if r.is_withdrawal:
            lines.append(f"    {src}-->>-{dst}: F{r.frame_number} {label} W{extra}")
        else:
            lines.append(f"    {src}->>+{dst}: F{r.frame_number} {label}{extra}")

    lines.append("```")
    return "\n".join(lines)
