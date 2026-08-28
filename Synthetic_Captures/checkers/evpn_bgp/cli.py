"""CLI entry point for evpnpcapcheck."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from checkers.evpn_bgp.inspector import PcapInspector

from checkers.evpn_bgp import __version__
from checkers.common.tshark import decode_pcap, load_json, dump_fields
from checkers.evpn_bgp.bgp.extract import extract_bgp_messages
from checkers.evpn_bgp.bgp.session import build_sessions
from checkers.evpn_bgp.bgp.rules import run_bgp_rules
from checkers.evpn_bgp.evpn.extract import extract_evpn_routes
from checkers.evpn_bgp.evpn.macvrf import build_mac_table
from checkers.evpn_bgp.evpn.rules import run_evpn_rules
from checkers.evpn_bgp.topology.loader import load_topology
from checkers.evpn_bgp.topology.rules import run_topology_rules
from checkers.evpn_bgp.scenario.schema import load_scenario
from checkers.evpn_bgp.scenario.compare import run_scenario_checks
from checkers.evpn_bgp.report import (
    findings_to_json,
    findings_to_markdown,
    ladder_to_mermaid,
    mac_table_to_markdown,
    timeline_to_markdown,
)


def _load_packets(args: argparse.Namespace) -> list[dict]:
    """Load packets from a PCAP or pre-decoded JSON file."""
    pcap_path = Path(args.pcap)
    if hasattr(args, "json_input") and args.json_input:
        return load_json(args.json_input)
    if pcap_path.suffix == ".json":
        return load_json(pcap_path)
    return decode_pcap(pcap_path)


def cmd_verify(args: argparse.Namespace) -> int:
    """Run all consistency checks."""
    packets = _load_packets(args)

    bgp_msgs = extract_bgp_messages(packets)
    sessions = build_sessions(bgp_msgs)
    evpn_routes = extract_evpn_routes(packets)

    partial = args.partial_capture

    # Load optional topology
    topology = None
    if args.topology:
        topology = load_topology(args.topology)

    findings = run_bgp_rules(sessions, partial_capture=partial)
    findings.extend(run_evpn_rules(
        sessions, evpn_routes, partial_capture=partial, topology=topology,
    ))

    if topology:
        findings.extend(run_topology_rules(sessions, evpn_routes, topology))

    if args.scenario:
        scenario = load_scenario(args.scenario)
        findings.extend(run_evpn_rules(
            sessions, evpn_routes, scenario=scenario, partial_capture=partial,
            topology=topology,
        ))
        findings.extend(run_scenario_checks(sessions, evpn_routes, scenario))

    # Deduplicate findings by code + frame
    seen: set[tuple[str, int]] = set()
    unique: list = []
    for f in findings:
        key = (f.code, f.frame)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    if args.format == "json":
        output = findings_to_json(findings)
    else:
        output = findings_to_markdown(
            findings, summary_only=getattr(args, "summary_only", False),
        )

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code: 1 if any FAIL, 0 otherwise
    return 1 if any(f.severity == "FAIL" for f in findings) else 0


def cmd_timeline(args: argparse.Namespace) -> int:
    """Print an EVPN route timeline."""
    packets = _load_packets(args)
    evpn_routes = extract_evpn_routes(packets)
    output = timeline_to_markdown(evpn_routes)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Timeline written to {args.output}")
    else:
        print(output)
    return 0


def cmd_mac_table(args: argparse.Namespace) -> int:
    """Print the reconstructed MAC table."""
    packets = _load_packets(args)
    evpn_routes = extract_evpn_routes(packets)
    mac_table = build_mac_table(evpn_routes)

    evi = args.evi if hasattr(args, "evi") and args.evi else None
    output = mac_table_to_markdown(mac_table, evi_filter=evi)

    if args.output:
        Path(args.output).write_text(output)
        print(f"MAC table written to {args.output}")
    else:
        print(output)
    return 0


def cmd_ladder(args: argparse.Namespace) -> int:
    """Generate a Mermaid sequence (ladder) diagram of EVPN messages."""
    packets = _load_packets(args)
    evpn_routes = extract_evpn_routes(packets)

    mac_filter = getattr(args, "mac", None)
    type_filter = None
    if hasattr(args, "types") and args.types:
        type_filter = [int(t) for t in args.types.split(",")]
    limit = getattr(args, "limit", 200) or 200

    output = ladder_to_mermaid(
        evpn_routes,
        limit=limit,
        mac_filter=mac_filter,
        type_filter=type_filter,
    )

    if args.output:
        Path(args.output).write_text(output)
        print(f"Ladder diagram written to {args.output}")
    else:
        print(output)
    return 0


def cmd_dump_fields(args: argparse.Namespace) -> int:
    """Dump tshark JSON field names for debugging."""
    packets = _load_packets(args)
    contains = args.contains if hasattr(args, "contains") else ""
    fields = dump_fields(packets, contains=contains)

    for name, samples in fields.items():
        sample_str = ", ".join(str(s) for s in samples[:3])
        print(f"{name}: [{sample_str}]")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Run the BGP/EVPN sensitivity inspector on a capture."""
    inspector = PcapInspector(args.pcap)
    inspector.scan()
    if hasattr(args, "output") and args.output:
        inspector.save_report(args.output)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evpnpcapcheck",
        description="EVPN-PCAP-Check: BGP/EVPN packet capture consistency checker",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- verify --
    p_verify = subparsers.add_parser("verify", help="Run consistency checks")
    p_verify.add_argument("pcap", help="PCAP/PCAPNG file or tshark JSON file")
    p_verify.add_argument("--json-input", help="Pre-decoded tshark JSON file")
    p_verify.add_argument("--scenario", help="Scenario YAML file")
    p_verify.add_argument(
        "--topology", help="Topology YAML file (enables topology-aware checks)",
    )
    p_verify.add_argument("--output", "-o", help="Output file path")
    p_verify.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)",
    )
    p_verify.add_argument(
        "--partial-capture", action="store_true",
        help="Relax checks for captures that start mid-session",
    )
    p_verify.add_argument(
        "--summary-only", action="store_true",
        help="Print only the summary counts, suppress individual findings",
    )
    p_verify.set_defaults(func=cmd_verify)

    # -- timeline --
    p_timeline = subparsers.add_parser("timeline", help="Show EVPN route timeline")
    p_timeline.add_argument("pcap", help="PCAP/PCAPNG file or tshark JSON file")
    p_timeline.add_argument("--json-input", help="Pre-decoded tshark JSON file")
    p_timeline.add_argument("--output", "-o", help="Output file path")
    p_timeline.set_defaults(func=cmd_timeline)

    # -- mac-table --
    p_mac = subparsers.add_parser("mac-table", help="Show reconstructed MAC table")
    p_mac.add_argument("pcap", help="PCAP/PCAPNG file or tshark JSON file")
    p_mac.add_argument("--json-input", help="Pre-decoded tshark JSON file")
    p_mac.add_argument("--evi", type=int, help="Filter by EVI")
    p_mac.add_argument("--output", "-o", help="Output file path")
    p_mac.set_defaults(func=cmd_mac_table)

    # -- dump-fields --
    p_dump = subparsers.add_parser("dump-fields", help="Dump tshark field names")
    p_dump.add_argument("pcap", help="PCAP/PCAPNG file or tshark JSON file")
    p_dump.add_argument("--json-input", help="Pre-decoded tshark JSON file")
    p_dump.add_argument("--contains", default="", help="Filter fields containing string")
    p_dump.set_defaults(func=cmd_dump_fields)

    # -- inspect --
    p_inspect = subparsers.add_parser(
        "inspect", help="Scan a capture for sensitive data (IPs, ASNs, MACs)",
    )
    p_inspect.add_argument("pcap", help="PCAP/PCAPNG file")
    p_inspect.add_argument("--output", "-o", help="Save report to file")
    p_inspect.set_defaults(func=cmd_inspect)

    # -- ladder --
    p_ladder = subparsers.add_parser(
        "ladder", help="Generate Mermaid sequence (ladder) diagram",
    )
    p_ladder.add_argument("pcap", help="PCAP/PCAPNG file or tshark JSON file")
    p_ladder.add_argument("--json-input", help="Pre-decoded tshark JSON file")
    p_ladder.add_argument("--mac", help="Filter to a specific MAC address")
    p_ladder.add_argument(
        "--types", help="Comma-separated route types to include (e.g. 2,3)",
    )
    p_ladder.add_argument(
        "--limit", type=int, default=200,
        help="Maximum number of messages in diagram (default: 200)",
    )
    p_ladder.add_argument("--output", "-o", help="Output file path")
    p_ladder.set_defaults(func=cmd_ladder)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
