"""Multihoming consistency checks using ESI, Type 1, and Type 4 routes."""

from __future__ import annotations

from checkers.evpn_bgp.model import EvpnRoute, EvpnRouteType

_ZERO_ESI = "00:00:00:00:00:00:00:00:00:00"
_ZERO_ESI_ALT = "0000:0000:0000:0000:0000"


def is_zero_esi(esi: str) -> bool:
    """Return True if *esi* is the all-zeroes ESI."""
    normalised = esi.replace(":", "").replace(".", "").lower()
    return normalised == "0" * 20 or not normalised


def get_type1_esi_set(routes: list[EvpnRoute]) -> set[str]:
    """Return the set of ESIs seen in Type 1 Ethernet A-D routes."""
    return {
        r.esi for r in routes
        if r.route_type == EvpnRouteType.ETHERNET_AD and not is_zero_esi(r.esi)
    }


def get_type4_esi_set(routes: list[EvpnRoute]) -> set[str]:
    """Return the set of ESIs seen in Type 4 Ethernet Segment routes."""
    return {
        r.esi for r in routes
        if r.route_type == EvpnRouteType.ETHERNET_SEGMENT and not is_zero_esi(r.esi)
    }
