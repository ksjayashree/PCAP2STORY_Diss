"""IMET (Type 3) route tracking."""

from __future__ import annotations

from checkers.evpn_bgp.model import EvpnRoute, EvpnRouteType


def build_imet_table(
    routes: list[EvpnRoute],
) -> dict[str, list[EvpnRoute]]:
    """Build an IMET table keyed by (next_hop, ethernet_tag).

    Returns dict mapping ``"next_hop|etag"`` to Type 3 routes.
    """
    table: dict[str, list[EvpnRoute]] = {}
    for r in routes:
        if r.route_type != EvpnRouteType.IMET:
            continue
        key = f"{r.next_hop}|{r.ethernet_tag}"
        table.setdefault(key, []).append(r)
    return table


def has_imet_for(imet_table: dict[str, list[EvpnRoute]],
                 next_hop: str, ethernet_tag: int) -> bool:
    """Check if an IMET route exists for a given PE and EVI."""
    key = f"{next_hop}|{ethernet_tag}"
    return bool(imet_table.get(key))
