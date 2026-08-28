"""Topology-aware validation rules for evpnpcapcheck.

These rules are only active when a topology file is provided via
``--topology``.  They validate observed BGP sessions and EVPN routes
against the declared topology.
"""

from __future__ import annotations

from checkers.evpn_bgp.model import (
    BgpSession,
    EvpnRoute,
    EvpnRouteType,
    Finding,
    Severity,
)
from .model import Topology


def check_missing_pe_sessions(
    sessions: dict[int, BgpSession],
    topology: Topology,
) -> list[Finding]:
    """TOPO-001: PE declared in topology has no BGP session in capture.

    Compares observed session endpoints against expected PE loopbacks.
    """
    findings: list[Finding] = []

    # Collect all IP addresses observed in sessions (both src and dst)
    observed_ips: set[str] = set()
    for sess in sessions.values():
        if sess.src_ip:
            observed_ips.add(sess.src_ip)
        if sess.dst_ip:
            observed_ips.add(sess.dst_ip)

    for pe in topology.pe_nodes:
        if pe.loopback and pe.loopback not in observed_ips:
            findings.append(Finding(
                severity=Severity.WARN,
                code="TOPO-001",
                frame=0,
                message=(
                    f"PE {pe.id} ({pe.loopback}) declared in topology "
                    f"has no BGP session in the capture."
                ),
                impact=(
                    "This PE may be unreachable or the capture does not "
                    "cover traffic to/from this node."
                ),
                evidence={"pe_id": pe.id, "loopback": pe.loopback},
                confidence="medium",
            ))

    return findings


def check_missing_pe_routes(
    routes: list[EvpnRoute],
    topology: Topology,
) -> list[Finding]:
    """TOPO-002: PE declared in topology advertises no EVPN routes.

    A PE that has a BGP session but never advertises any routes may
    indicate a configuration issue or a fault that prevents route
    advertisement.
    """
    findings: list[Finding] = []

    # Collect next-hops that have advertised at least one route
    advertising_pes: set[str] = set()
    for r in routes:
        if not r.is_withdrawal and r.next_hop:
            advertising_pes.add(r.next_hop)

    for pe in topology.pe_nodes:
        if pe.loopback and pe.loopback not in advertising_pes:
            findings.append(Finding(
                severity=Severity.WARN,
                code="TOPO-002",
                frame=0,
                message=(
                    f"PE {pe.id} ({pe.loopback}) has no EVPN route "
                    f"advertisements in the capture."
                ),
                impact=(
                    "The PE may have no active services, or a fault is "
                    "preventing route advertisement."
                ),
                evidence={"pe_id": pe.id, "loopback": pe.loopback},
                confidence="medium",
            ))

    return findings


def check_unknown_next_hop(
    routes: list[EvpnRoute],
    topology: Topology,
) -> list[Finding]:
    """TOPO-003: Route next-hop does not match any known PE loopback.

    Every EVPN route's next-hop should correspond to a PE in the topology.
    An unknown next-hop may indicate a misconfiguration or a PE that was
    not declared in the topology file.
    """
    findings: list[Finding] = []
    known = topology.all_pe_loopbacks
    flagged: set[str] = set()

    for r in routes:
        if r.is_withdrawal or not r.next_hop:
            continue
        if r.next_hop not in known and r.next_hop not in flagged:
            flagged.add(r.next_hop)
            findings.append(Finding(
                severity=Severity.FAIL,
                code="TOPO-003",
                frame=r.frame_number,
                message=(
                    f"Route next-hop {r.next_hop} does not match any PE "
                    f"loopback in the topology."
                ),
                impact=(
                    "Routes with unknown next-hops cannot be verified against "
                    "the topology. This may indicate a rogue or undeclared PE."
                ),
                evidence={
                    "next_hop": r.next_hop,
                    "known_pe_loopbacks": sorted(known),
                },
                confidence="high",
            ))

    return findings


def check_esi_consistency(
    routes: list[EvpnRoute],
    topology: Topology,
) -> list[Finding]:
    """TOPO-004: ESI-sharing PEs — one PE missing Type 1/4 routes for shared ESI.

    When two PEs share an ESI (multi-homing), both should advertise
    Type 1 (EAD) and Type 4 (ES) routes for that ESI.  If only one PE
    advertises them, the multi-homing setup may be incomplete.
    """
    findings: list[Finding] = []

    # Collect which PEs (by next-hop) advertise Type 1 or 4 for each ESI
    esi_advertisers: dict[str, set[str]] = {}  # ESI → set of next_hops
    for r in routes:
        if r.is_withdrawal:
            continue
        if r.route_type in (EvpnRouteType.ETHERNET_AD, EvpnRouteType.ETHERNET_SEGMENT):
            if r.esi and r.next_hop:
                esi_advertisers.setdefault(r.esi, set()).add(r.next_hop)

    for esi, pe_list in topology.esi_groups.items():
        if len(pe_list) < 2:
            continue
        expected_loopbacks = {pe.loopback for pe in pe_list}
        observed = esi_advertisers.get(esi, set())
        missing = expected_loopbacks - observed

        for loopback in missing:
            node = topology.node_by_loopback(loopback)
            pe_id = node.id if node else loopback
            findings.append(Finding(
                severity=Severity.WARN,
                code="TOPO-004",
                frame=0,
                message=(
                    f"PE {pe_id} ({loopback}) shares ESI {esi} but has no "
                    f"Type 1/4 routes for it in the capture."
                ),
                impact=(
                    "Multi-homing may be incomplete — remote PEs will not "
                    "have backup paths through this PE for the shared segment."
                ),
                evidence={
                    "esi": esi,
                    "missing_pe": pe_id,
                    "expected": sorted(expected_loopbacks),
                    "observed": sorted(observed),
                },
                confidence="high",
            ))

    return findings


def check_single_homed_on_mh_pe(
    routes: list[EvpnRoute],
    topology: Topology,
) -> list[Finding]:
    """TOPO-005: MAC is single-homed but PE has a shared ESI.

    When a PE participates in multi-homing (shares an ESI), we expect
    MACs behind that segment to be advertised by both PEs.  A MAC only
    advertised by one of the ESI-sharing PEs may indicate a fault on
    the peer PE.

    This is informational — some MACs may legitimately be on a
    non-shared port of a multi-homing PE.
    """
    findings: list[Finding] = []

    # Build MAC → set of next_hops (for Type 2 only)
    mac_hops: dict[str, set[str]] = {}
    mac_frame: dict[str, int] = {}
    for r in routes:
        if r.route_type != EvpnRouteType.MAC_IP_ADV or r.is_withdrawal:
            continue
        if r.mac and r.next_hop:
            mac_hops.setdefault(r.mac, set()).add(r.next_hop)
            if r.mac not in mac_frame:
                mac_frame[r.mac] = r.frame_number

    # Only flag MACs that are on exactly one PE AND that PE is multi-homed
    for mac, hops in mac_hops.items():
        if len(hops) != 1:
            continue
        pe_loopback = next(iter(hops))
        if topology.is_multihomed_pe(pe_loopback):
            node = topology.node_by_loopback(pe_loopback)
            pe_id = node.id if node else pe_loopback
            peers = topology.esi_peers(pe_loopback)
            peer_ids = [p.id for p in peers]
            findings.append(Finding(
                severity=Severity.INFO,
                code="TOPO-005",
                frame=mac_frame[mac],
                message=(
                    f"MAC {mac} only advertised by {pe_id} but this PE "
                    f"shares ESI with {', '.join(peer_ids)}."
                ),
                impact=(
                    "If this MAC is on the shared segment, the peer PE "
                    "should also advertise it. May indicate a fault or "
                    "the MAC is on a non-shared port."
                ),
                evidence={
                    "mac": mac,
                    "advertising_pe": pe_id,
                    "esi_peers": peer_ids,
                },
                confidence="low",
            ))

    return findings


def run_topology_rules(
    sessions: dict[int, BgpSession],
    routes: list[EvpnRoute],
    topology: Topology,
) -> list[Finding]:
    """Run all topology-aware rules and return findings."""
    findings: list[Finding] = []
    findings.extend(check_missing_pe_sessions(sessions, topology))
    findings.extend(check_missing_pe_routes(routes, topology))
    findings.extend(check_unknown_next_hop(routes, topology))
    findings.extend(check_esi_consistency(routes, topology))
    findings.extend(check_single_homed_on_mh_pe(routes, topology))
    return findings
