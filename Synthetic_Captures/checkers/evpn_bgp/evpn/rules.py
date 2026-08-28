"""EVPN validation rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from checkers.evpn_bgp.model import (
    BgpSession, EvpnRoute, EvpnRouteType, Finding, MacEntry, Scenario, Severity,
)
from checkers.evpn_bgp.evpn.imet import build_imet_table, has_imet_for
from checkers.evpn_bgp.evpn.macvrf import build_mac_table
from checkers.evpn_bgp.evpn.multihoming import get_type1_esi_set, is_zero_esi

if TYPE_CHECKING:
    from checkers.evpn_bgp.topology.model import Topology


def check_evpn_capability(
    sessions: dict[int, BgpSession],
    routes: list[EvpnRoute],
) -> list[Finding]:
    """EVPN UPDATEs should only appear on sessions with EVPN capability."""
    findings: list[Finding] = []
    streams_with_evpn_cap: set[int] = set()
    for stream, sess in sessions.items():
        if sess.capabilities.evpn or sess.remote_capabilities.evpn:
            streams_with_evpn_cap.add(stream)

    for r in routes:
        if r.tcp_stream not in streams_with_evpn_cap:
            findings.append(Finding(
                severity=Severity.FAIL,
                code="EVPN-001",
                frame=r.frame_number,
                message="EVPN UPDATE on session without EVPN capability.",
                impact=(
                    "Peer has not negotiated L2VPN/EVPN address family; "
                    "route will be rejected."
                ),
                evidence={
                    "tcp_stream": r.tcp_stream,
                    "route_type": r.route_type,
                },
                confidence="high",
            ))
            break  # one per session
    return findings


def check_imet_before_mac(routes: list[EvpnRoute]) -> list[Finding]:
    """Type 3 IMET should appear before Type 2 MAC advertisement per PE/EVI."""
    findings: list[Finding] = []
    imet_table = build_imet_table(routes)

    # Track earliest frame with IMET per (next_hop, etag)
    imet_frames: dict[str, int] = {}
    for r in routes:
        if r.route_type == EvpnRouteType.IMET:
            key = f"{r.next_hop}|{r.ethernet_tag}"
            if key not in imet_frames:
                imet_frames[key] = r.frame_number

    for r in routes:
        if r.route_type != EvpnRouteType.MAC_IP_ADV or r.is_withdrawal:
            continue
        key = f"{r.src_ip}|{r.ethernet_tag}"
        nh_key = f"{r.next_hop}|{r.ethernet_tag}"
        imet_frame = imet_frames.get(nh_key)
        if imet_frame is None:
            findings.append(Finding(
                severity=Severity.WARN,
                code="EVPN-002",
                frame=r.frame_number,
                message=(
                    f"Type 2 MAC advertisement without corresponding "
                    f"Type 3 IMET for next-hop {r.next_hop}, EVI {r.ethernet_tag}."
                ),
                impact="Remote PEs may not have joined the BUM tree for this EVI.",
                evidence={"mac": r.mac, "next_hop": r.next_hop, "evi": r.ethernet_tag},
                confidence="medium",
            ))
        elif imet_frame > r.frame_number:
            findings.append(Finding(
                severity=Severity.WARN,
                code="EVPN-003",
                frame=r.frame_number,
                message=(
                    f"Type 2 MAC advertisement (frame {r.frame_number}) precedes "
                    f"Type 3 IMET (frame {imet_frame})."
                ),
                impact="MAC was advertised before BUM tree was established.",
                evidence={"mac": r.mac, "imet_frame": imet_frame},
                confidence="medium",
            ))
    return findings


def check_mac_withdraw_before_advertise(routes: list[EvpnRoute]) -> list[Finding]:
    """A MAC withdrawal should follow a corresponding advertisement."""
    findings: list[Finding] = []
    mac_table = build_mac_table(routes)
    for key, entry in mac_table.items():
        if entry.frame_withdrawn and not entry.frame_advertised:
            findings.append(Finding(
                severity=Severity.WARN,
                code="EVPN-004",
                frame=entry.frame_withdrawn,
                message=f"MAC withdrawal without prior advertisement: {entry.mac}.",
                impact="Withdrawal of an unknown MAC may indicate a partial capture.",
                evidence={"mac": entry.mac, "evi": entry.evi},
                confidence="medium",
            ))
    return findings


def check_mac_move(routes: list[EvpnRoute]) -> list[Finding]:
    """Warn on MAC moves detected in Type 2 routes.

    A small number of MAC moves is normal in EVPN networks — active-active
    multi-homing, VM migration, and link failovers all produce legitimate
    moves.  We flag any move for visibility but only escalate to FAIL
    when the count is unusually high (>= 10), which is more suggestive of
    a forwarding loop or misconfiguration.
    """
    findings: list[Finding] = []
    mac_table = build_mac_table(routes)
    for key, entry in mac_table.items():
        if entry.move_count > 0:
            if entry.move_count >= 10:
                sev = Severity.FAIL
                impact = (
                    "Excessive MAC moves suggest a possible forwarding loop "
                    "or persistent misconfiguration rather than normal "
                    "EVPN multi-homing convergence."
                )
            else:
                sev = Severity.WARN
                impact = (
                    "MAC moves are expected during EVPN multi-homing failover "
                    "or VM migration. Review if unexpected in the test scenario."
                )
            findings.append(Finding(
                severity=sev,
                code="EVPN-005",
                frame=entry.frame_advertised,
                message=f"MAC move detected for {entry.mac} ({entry.move_count} moves).",
                impact=impact,
                evidence={
                    "mac": entry.mac,
                    "evi": entry.evi,
                    "move_count": entry.move_count,
                },
                confidence="medium",
            ))
    return findings


def check_type2_esi_without_type1(routes: list[EvpnRoute]) -> list[Finding]:
    """Type 2 routes with non-zero ESI should have a matching Type 1 A-D route."""
    findings: list[Finding] = []
    type1_esis = get_type1_esi_set(routes)

    for r in routes:
        if (
            r.route_type == EvpnRouteType.MAC_IP_ADV
            and not r.is_withdrawal
            and not is_zero_esi(r.esi)
            and r.esi not in type1_esis
        ):
            findings.append(Finding(
                severity=Severity.FAIL,
                code="MH-001",
                frame=r.frame_number,
                message=(
                    "Type 2 MAC route has non-zero ESI but no matching "
                    "Type 1 Ethernet A-D route."
                ),
                impact=(
                    "Remote PEs may not have enough information to build "
                    "correct multihoming forwarding state."
                ),
                evidence={
                    "mac": r.mac,
                    "esi": r.esi,
                    "evi": r.ethernet_tag,
                    "src_ip": r.src_ip,
                },
                confidence="high",
            ))
    return findings


def check_rt_against_scenario(
    routes: list[EvpnRoute],
    scenario: Scenario | None,
) -> list[Finding]:
    """Verify Route Targets match the scenario EVI configuration."""
    if scenario is None:
        return []
    findings: list[Finding] = []
    from checkers.evpn_bgp.evpn.evi import build_rt_evi_map, validate_rt_against_scenario

    rt_evi_map = build_rt_evi_map(routes)
    mismatches = validate_rt_against_scenario(rt_evi_map, scenario)
    for rt, expected, observed in mismatches:
        findings.append(Finding(
            severity=Severity.WARN,
            code="EVPN-006",
            frame=0,
            message=(
                f"Route Target {rt} maps to EVIs {observed} "
                f"but scenario expects {expected}."
            ),
            impact="Traffic may be imported into the wrong EVI.",
            evidence={"rt": rt, "expected": list(expected), "observed": list(observed)},
            confidence="medium",
        ))
    return findings


def check_single_rt2_for_mac(
    routes: list[EvpnRoute],
    topology: Topology | None = None,
) -> list[Finding]:
    """Warn when a MAC address has only a single Type 2 advertisement.

    In a resilient EVPN fabric each MAC should be advertised from at least
    two PEs (or from the same PE over two paths) so that remote PEs have a
    backup forwarding entry.  A single advertisement means there is no
    redundancy for that MAC.

    When a topology is provided, findings are suppressed for MACs whose
    sole advertising PE is confirmed single-homed (no shared ESI).  For
    MACs on multi-homed PEs, confidence is upgraded to "high".
    """
    findings: list[Finding] = []
    # Track distinct (next_hop, esi) tuples per MAC (active adverts only)
    mac_origins: dict[str, dict[str, set[str]]] = {}  # mac -> {"hops": set, "frame": first_frame}
    first_frame: dict[str, int] = {}
    for r in routes:
        if r.route_type != EvpnRouteType.MAC_IP_ADV or r.is_withdrawal:
            continue
        if r.mac not in mac_origins:
            mac_origins[r.mac] = set()
            first_frame[r.mac] = r.frame_number
        mac_origins[r.mac].add(r.next_hop)

    for mac, hops in mac_origins.items():
        if len(hops) == 1:
            pe_loopback = next(iter(hops))

            # With topology: suppress if PE is confirmed single-homed
            if topology is not None:
                if not topology.is_multihomed_pe(pe_loopback):
                    continue  # Expected — single-homed PE, no redundancy needed
                # PE is multi-homed but MAC only from one PE → higher confidence
                confidence = "high"
            else:
                confidence = "low"

            findings.append(Finding(
                severity=Severity.WARN,
                code="EVPN-007",
                frame=first_frame[mac],
                message=(
                    f"MAC {mac} has only a single advertising PE "
                    f"({pe_loopback}); no redundancy."
                ),
                impact=(
                    "If the sole advertising PE fails, remote PEs will "
                    "have no backup path for this MAC."
                ),
                evidence={"mac": mac, "next_hops": sorted(hops)},
                confidence=confidence,
            ))
    return findings


def check_valid_mac_type2(routes: list[EvpnRoute]) -> list[Finding]:
    """Type 2 MAC advertisements must carry a valid unicast MAC.

    A broadcast (ff:ff:ff:ff:ff:ff), multicast (I/G bit set in the first
    octet) or all-zero MAC has no business in a Type 2 MAC/IP advertisement.
    Real BGP/EVPN speakers only originate unicast host MACs here, so any of
    these would make a capture look synthetic/malformed.  Locally
    administered unicast MACs (U/L bit set) are perfectly valid and are not
    flagged.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for r in routes:
        if r.route_type != EvpnRouteType.MAC_IP_ADV or r.is_withdrawal:
            continue
        mac = r.mac.strip().lower()
        if not mac or mac in seen:
            continue
        octets = mac.split(":")
        if len(octets) != 6:
            continue
        try:
            first = int(octets[0], 16)
            value = int("".join(octets), 16)
        except ValueError:
            continue

        reason = None
        if value == 0:
            reason = "all-zero"
        elif mac == "ff:ff:ff:ff:ff:ff":
            reason = "broadcast"
        elif first & 0x01:
            reason = "multicast (I/G bit set)"

        if reason is not None:
            seen.add(mac)
            findings.append(Finding(
                severity=Severity.WARN,
                code="EVPN-008",
                frame=r.frame_number,
                message=f"Type 2 advertisement carries invalid {reason} MAC {r.mac}.",
                impact=(
                    "A MAC/IP advertisement should carry a unicast host MAC; "
                    "a broadcast/multicast/zero MAC is never a real host."
                ),
                evidence={"mac": r.mac, "evi": r.ethernet_tag, "reason": reason},
                confidence="high",
            ))
    return findings


def run_evpn_rules(
    sessions: dict[int, BgpSession],
    routes: list[EvpnRoute],
    scenario: Scenario | None = None,
    partial_capture: bool = False,
    topology: Topology | None = None,
) -> list[Finding]:
    """Run all EVPN validation rules and return findings."""
    findings: list[Finding] = []

    if not partial_capture:
        findings.extend(check_evpn_capability(sessions, routes))
        findings.extend(check_imet_before_mac(routes))
    findings.extend(check_mac_withdraw_before_advertise(routes))
    findings.extend(check_mac_move(routes))
    findings.extend(check_type2_esi_without_type1(routes))
    findings.extend(check_valid_mac_type2(routes))
    findings.extend(check_single_rt2_for_mac(routes, topology=topology))
    findings.extend(check_rt_against_scenario(routes, scenario))

    return findings
