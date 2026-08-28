"""Parse BGP capabilities from OPEN messages."""

from __future__ import annotations

from checkers.evpn_bgp.model import BgpCapabilities

# AFI/SAFI for EVPN: AFI 25 (L2VPN), SAFI 70 (EVPN)
_EVPN_AFI = 25
_EVPN_SAFI = 70


def parse_capabilities(open_layers: dict) -> BgpCapabilities:
    """Parse capabilities from the raw layers of a BGP OPEN message.

    This works with the decoded tshark JSON where capabilities appear under
    various field names depending on tshark version.
    """
    caps = BgpCapabilities()

    caps.asn = _int_field(open_layers, "bgp.open.my_as", "bgp.open.as")
    caps.hold_time = _int_field(open_layers, "bgp.open.holdtime")

    # Walk capability entries
    cap_tree = _find_cap_tree(open_layers)
    for entry in cap_tree:
        code = _int_field(entry, "bgp.cap.code", "bgp.cap.type")
        if code == 1:  # Multiprotocol
            afi = _int_field(entry, "bgp.cap.mp.afi")
            safi = _int_field(entry, "bgp.cap.mp.safi")
            caps.multiprotocol.append((afi, safi))
            if afi == _EVPN_AFI and safi == _EVPN_SAFI:
                caps.evpn = True
        elif code == 2:  # Route refresh
            caps.route_refresh = True
        elif code == 64:  # Graceful restart
            caps.graceful_restart = True
        elif code == 65:  # 4-octet AS
            caps.four_octet_as = True

    return caps


def has_evpn_capability(caps: BgpCapabilities) -> bool:
    """Return True if the capabilities include L2VPN/EVPN."""
    return caps.evpn


def _int_field(d: dict, *keys: str) -> int:
    for key in keys:
        val = d.get(key)
        if val is not None:
            if isinstance(val, list):
                val = val[0] if val else None
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
    return 0


def _find_cap_tree(layers: dict) -> list[dict]:
    """Locate the list of capability dicts within the raw layers."""
    # tshark nests capabilities differently across versions.
    # Try known paths.
    if isinstance(layers.get("bgp.cap"), list):
        return layers["bgp.cap"]
    if isinstance(layers.get("bgp.cap"), dict):
        return [layers["bgp.cap"]]

    # Check inside bgp.open.opt → bgp.open.opt.param → bgp.cap
    opt = layers.get("bgp.open.opt")
    if isinstance(opt, dict):
        param = opt.get("bgp.open.opt.param")
        if isinstance(param, dict):
            cap = param.get("bgp.cap")
            if isinstance(cap, list):
                return cap
            if isinstance(cap, dict):
                return [cap]
        elif isinstance(param, list):
            # Multiple opt params — collect all bgp.cap entries
            caps = []
            for p in param:
                if isinstance(p, dict):
                    cap = p.get("bgp.cap")
                    if isinstance(cap, list):
                        caps.extend(cap)
                    elif isinstance(cap, dict):
                        caps.append(cap)
            if caps:
                return caps

    # Walk one level deep looking for capability entries
    for val in layers.values():
        if isinstance(val, dict) and "bgp.cap.code" in val:
            return [val]
        if isinstance(val, list):
            caps = [v for v in val if isinstance(v, dict) and "bgp.cap.code" in v]
            if caps:
                return caps
    return []
