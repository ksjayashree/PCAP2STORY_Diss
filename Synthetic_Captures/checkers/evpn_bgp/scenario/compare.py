"""Compare captured data against a scenario definition."""

from __future__ import annotations

from checkers.evpn_bgp.model import (
    BgpSession, EvpnRoute, EvpnRouteType, Finding, Scenario, Severity,
)
from checkers.evpn_bgp.evpn.imet import build_imet_table
from checkers.evpn_bgp.evpn.macvrf import build_mac_table
from checkers.evpn_bgp.scenario.schema import scenario_peer_ips


def check_expected_sessions(
    sessions: dict[int, BgpSession],
    scenario: Scenario,
) -> list[Finding]:
    """Check that all expected peer sessions were established."""
    findings: list[Finding] = []
    expected_ips = scenario_peer_ips(scenario)
    observed_ips: set[str] = set()
    for sess in sessions.values():
        observed_ips.add(sess.src_ip)
        observed_ips.add(sess.dst_ip)

    for peer_name, peer in scenario.peers.items():
        peer_ip = peer.get("ip", "")
        if peer_ip and peer_ip not in observed_ips:
            findings.append(Finding(
                severity=Severity.WARN,
                code="SCEN-001",
                frame=0,
                message=f"Expected peer {peer_name} ({peer_ip}) not seen in capture.",
                impact="Scenario expects a session with this peer.",
                evidence={"peer": peer_name, "ip": peer_ip},
                confidence="medium",
            ))
    return findings


def check_expected_imet(
    routes: list[EvpnRoute],
    scenario: Scenario,
) -> list[Finding]:
    """Check that IMET routes exist for all expected services and PEs."""
    findings: list[Finding] = []
    imet_table = build_imet_table(routes)

    for svc_name, svc in scenario.services.items():
        etags = svc.get("ethernet_tags", [])
        for peer_name, peer in scenario.peers.items():
            peer_ip = peer.get("loopback", peer.get("ip", ""))
            for etag in etags:
                key = f"{peer_ip}|{etag}"
                if key not in imet_table:
                    findings.append(Finding(
                        severity=Severity.WARN,
                        code="SCEN-002",
                        frame=0,
                        message=(
                            f"Missing IMET for peer {peer_name} "
                            f"({peer_ip}), service {svc_name}, tag {etag}."
                        ),
                        impact="BUM traffic may not reach all PEs.",
                        evidence={
                            "peer": peer_name,
                            "service": svc_name,
                            "ethernet_tag": etag,
                        },
                        confidence="medium",
                    ))
    return findings


def check_expected_mac(
    routes: list[EvpnRoute],
    scenario: Scenario,
) -> list[Finding]:
    """Placeholder for expected MAC advertisement checks.

    The scenario YAML would need a ``macs`` section to drive this.
    """
    return []


def run_scenario_checks(
    sessions: dict[int, BgpSession],
    routes: list[EvpnRoute],
    scenario: Scenario,
) -> list[Finding]:
    """Run all scenario comparison checks."""
    findings: list[Finding] = []
    findings.extend(check_expected_sessions(sessions, scenario))
    findings.extend(check_expected_imet(routes, scenario))
    findings.extend(check_expected_mac(routes, scenario))
    return findings
