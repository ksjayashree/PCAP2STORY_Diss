"""MAC VRF table tracking — advertise, withdraw, and move detection."""

from __future__ import annotations

from checkers.evpn_bgp.model import EvpnRoute, EvpnRouteType, MacEntry


def build_mac_table(routes: list[EvpnRoute]) -> dict[str, MacEntry]:
    """Build a MAC table from Type 2 MAC/IP Advertisement routes.

    Returns a dict keyed by ``(mac, evi)`` as a string key.
    """
    table: dict[str, MacEntry] = {}

    for r in routes:
        if r.route_type != EvpnRouteType.MAC_IP_ADV:
            continue

        key = f"{r.mac}|{r.ethernet_tag}"

        if r.is_withdrawal:
            if key in table:
                entry = table[key]
                entry.frame_withdrawn = r.frame_number
                entry.is_active = False
            else:
                # Withdrawal before advertisement
                table[key] = MacEntry(
                    mac=r.mac,
                    ip=r.ip,
                    evi=r.ethernet_tag,
                    esi=r.esi,
                    next_hop=r.next_hop,
                    frame_withdrawn=r.frame_number,
                    is_active=False,
                )
        else:
            if key in table and table[key].is_active:
                entry = table[key]
                # A different next-hop with the SAME non-zero ESI is
                # all-active multi-homing, not a MAC move.
                same_esi = (entry.esi == r.esi and r.esi
                            and r.esi != "00:00:00:00:00:00:00:00:00:00")
                if not same_esi and (entry.next_hop != r.next_hop or entry.esi != r.esi):
                    entry.move_count += 1
                entry.next_hop = r.next_hop
                entry.esi = r.esi
                entry.ip = r.ip or entry.ip
                entry.frame_advertised = r.frame_number
            else:
                table[key] = MacEntry(
                    mac=r.mac,
                    ip=r.ip,
                    evi=r.ethernet_tag,
                    esi=r.esi,
                    next_hop=r.next_hop,
                    frame_advertised=r.frame_number,
                    is_active=True,
                )

    return table
