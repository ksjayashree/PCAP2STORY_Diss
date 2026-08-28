"""EVI-level tracking — Route Target to EVI mapping and Ethernet Tag validation."""

from __future__ import annotations

from checkers.evpn_bgp.model import EvpnRoute, Scenario


def build_rt_evi_map(routes: list[EvpnRoute]) -> dict[str, set[int]]:
    """Map Route Targets to the EVIs (Ethernet Tags) they appear with."""
    rt_map: dict[str, set[int]] = {}
    for r in routes:
        for rt in r.route_targets:
            rt_map.setdefault(rt, set()).add(r.ethernet_tag)
    return rt_map


def validate_rt_against_scenario(
    rt_evi_map: dict[str, set[int]],
    scenario: Scenario,
) -> list[tuple[str, set[int], set[int]]]:
    """Check that observed RT → EVI mappings match the scenario.

    Returns a list of ``(rt, expected_evis, observed_evis)`` tuples for
    each mismatching Route Target.
    """
    mismatches: list[tuple[str, set[int], set[int]]] = []
    for svc_name, svc in scenario.services.items():
        expected_tags = set(svc.get("ethernet_tags", []))
        for rt in svc.get("route_targets", {}).get("import", []):
            observed = rt_evi_map.get(rt, set())
            if observed and observed != expected_tags:
                mismatches.append((rt, expected_tags, observed))
    return mismatches
