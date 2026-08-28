"""Extract EVPN routes from decoded tshark JSON packets.

Uses a field-alias table to cope with different tshark versions.
"""

from __future__ import annotations

from checkers.evpn_bgp.model import EvpnRoute, EvpnRouteType

# ---------------------------------------------------------------------------
# Field alias table — the most important technical component.
# Each logical field maps to a list of tshark JSON field names that may
# carry the value depending on tshark version and NLRI encoding path.
# ---------------------------------------------------------------------------
FIELD_ALIASES: dict[str, list[str]] = {
    "route_type": [
        "bgp.evpn.nlri.rt",
        "bgp.evpn.route_type",
        "bgp.evpn.route.type",
    ],
    "rd": [
        "bgp.evpn.nlri.rd",
        "bgp.evpn.rd",
        "bgp.evpn.route_distinguisher",
    ],
    "esi": [
        "bgp.evpn.nlri.esi",
        "bgp.evpn.esi",
        "bgp.evpn.ethernet_segment_identifier",
    ],
    "ethernet_tag": [
        "bgp.evpn.nlri.etag",
        "bgp.evpn.ethernet_tag",
        "bgp.evpn.ethernet_tag_id",
    ],
    "mac": [
        "bgp.evpn.nlri.mac_addr",
        "bgp.evpn.mac",
        "bgp.evpn.mac_addr",
        "bgp.evpn.nlri.mac",
    ],
    "ip": [
        "bgp.evpn.nlri.ip.addr",
        "bgp.evpn.ip",
        "bgp.evpn.ip_addr",
        "bgp.evpn.nlri.ip",
    ],
    "label": [
        "bgp.evpn.nlri.mpls_ls1",
        "bgp.evpn.label",
        "bgp.evpn.mpls_label",
        "bgp.evpn.nlri.label",
        "bgp.evpn.vni",
    ],
    "next_hop": [
        "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv4",
        "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv6",
        "bgp.update.path_attribute.mp_reach_nlri.next_hop",
        "bgp.next_hop",
        "bgp.update.path_attribute.next_hop",
    ],
    "route_target": [
        "bgp.ext_com.value_rt",
        "bgp.update.path_attribute.community_value",
        "bgp.ext_com.rt",
    ],
}


def _alias_get(d: dict, field_name: str, default: str = "") -> str:
    """Look up a logical field using the alias table."""
    for alias in FIELD_ALIASES.get(field_name, []):
        val = _deep_get(d, alias)
        if val is not None:
            if isinstance(val, list):
                return str(val[0]) if val else default
            return str(val)
    return default


def _alias_get_list(d: dict, field_name: str) -> list[str]:
    """Like _alias_get but returns all values as a list."""
    for alias in FIELD_ALIASES.get(field_name, []):
        val = _deep_get(d, alias)
        if val is not None:
            if isinstance(val, list):
                return [str(v) for v in val]
            return [str(val)]
    return []


def _deep_get(d: dict, dotted_key: str):
    """Look up a dotted key — first as a flat key, then by walking nested dicts."""
    # Flat key lookup (tshark layers use dotted names as flat keys)
    if dotted_key in d:
        return d[dotted_key]

    # Nested walk fallback
    parts = dotted_key.split(".")
    current = d
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            results = []
            for item in current:
                if isinstance(item, dict):
                    v = item.get(part)
                    if v is not None:
                        results.append(v)
            current = results if results else None
        else:
            return None
        if current is None:
            return None
    return current


def extract_evpn_routes(packets: list[dict]) -> list[EvpnRoute]:
    """Extract EVPN routes from tshark-decoded packets."""
    routes: list[EvpnRoute] = []

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        # Quick check: does this packet contain EVPN NLRI?
        rt_raw = _alias_get(layers, "route_type")
        if not rt_raw:
            continue

        try:
            route_type = int(rt_raw)
        except (ValueError, TypeError):
            continue

        frame = int(_first(layers, "frame.number", "0"))
        ts = float(_first(layers, "frame.time_epoch", "0"))
        src = _first(layers, "ip.src", "")
        dst = _first(layers, "ip.dst", "")
        stream = int(_first(layers, "tcp.stream", "0"))

        # Detect withdrawal: if the route appears in withdrawn-routes or
        # MP_UNREACH_NLRI, it's a withdrawal.
        is_withdrawal = bool(
            layers.get("bgp.update.withdrawn_routes")
            or layers.get("bgp.update.path_attribute.mp_unreach_nlri")
            or layers.get("bgp.evpn.nlri.withdrawn")
        )

        etag_raw = _alias_get(layers, "ethernet_tag", "0")
        try:
            etag = int(etag_raw)
        except (ValueError, TypeError):
            etag = 0

        label_raw = _alias_get(layers, "label", "0")
        try:
            label = int(label_raw)
        except (ValueError, TypeError):
            label = 0

        route = EvpnRoute(
            frame_number=frame,
            timestamp=ts,
            route_type=route_type,
            rd=_alias_get(layers, "rd"),
            route_targets=_alias_get_list(layers, "route_target"),
            esi=_alias_get(layers, "esi"),
            ethernet_tag=etag,
            mac=_alias_get(layers, "mac"),
            ip=_alias_get(layers, "ip"),
            next_hop=_alias_get(layers, "next_hop"),
            label=label,
            is_withdrawal=is_withdrawal,
            src_ip=src,
            dst_ip=dst,
            tcp_stream=stream,
            raw=layers,
        )
        routes.append(route)

    return routes


def _first(d: dict, key: str, default: str = "") -> str:
    val = d.get(key)
    if val is None:
        return default
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val)
