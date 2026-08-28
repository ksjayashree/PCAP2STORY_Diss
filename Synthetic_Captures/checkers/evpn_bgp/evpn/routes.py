"""EVPN route type helpers and grouping."""

from __future__ import annotations

from checkers.evpn_bgp.model import EvpnRoute, EvpnRouteType


def routes_by_type(routes: list[EvpnRoute]) -> dict[int, list[EvpnRoute]]:
    """Group EVPN routes by route type."""
    grouped: dict[int, list[EvpnRoute]] = {}
    for r in routes:
        grouped.setdefault(r.route_type, []).append(r)
    return grouped


def routes_by_evi(routes: list[EvpnRoute]) -> dict[int, list[EvpnRoute]]:
    """Group routes by Ethernet Tag (used as EVI proxy)."""
    grouped: dict[int, list[EvpnRoute]] = {}
    for r in routes:
        grouped.setdefault(r.ethernet_tag, []).append(r)
    return grouped


def route_type_name(rt: int) -> str:
    _names = {
        1: "Ethernet A-D",
        2: "MAC/IP Advertisement",
        3: "Inclusive Multicast Ethernet Tag (IMET)",
        4: "Ethernet Segment",
        5: "IP Prefix",
    }
    return _names.get(rt, f"Unknown ({rt})")
