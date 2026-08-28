"""BGP message builders producing raw bytes for each message type."""

import struct
from .constants import *


def build_bgp_header(msg_type: int, payload: bytes) -> bytes:
    """Build complete BGP message with marker + length + type + payload."""
    length = 19 + len(payload)
    return BGP_MARKER + struct.pack('!HB', length, msg_type) + payload


def build_keepalive() -> bytes:
    """Build BGP KEEPALIVE message (19 bytes, no payload)."""
    return BGP_MARKER + struct.pack('!HB', 19, BGP_KEEPALIVE)


def build_open(asn: int, hold_time: int, bgp_id: str, capabilities: list[bytes]) -> bytes:
    """Build BGP OPEN message.

    Args:
        asn: AS number (use AS_TRANS=23456 if >65535, actual AS in 4-byte-AS capability)
        hold_time: Hold timer in seconds
        bgp_id: BGP Router ID as dotted quad string (e.g., "10.0.0.1")
        capabilities: List of encoded capability bytes from capabilities.py
    """
    version = 4
    my_as = asn if asn <= 65535 else 23456  # AS_TRANS
    bgp_id_bytes = bytes(int(x) for x in bgp_id.split('.'))

    # Build optional parameters — all capabilities in a single Opt Param (type=2)
    all_caps = b''.join(capabilities)
    opt_params = struct.pack('!BB', 2, len(all_caps)) + all_caps

    payload = (struct.pack('!BHH', version, my_as, hold_time)
               + bgp_id_bytes
               + struct.pack('!B', len(opt_params))
               + opt_params)
    return build_bgp_header(BGP_OPEN, payload)


def build_notification(error_code: int, error_subcode: int, data: bytes = b'') -> bytes:
    """Build BGP NOTIFICATION message."""
    payload = struct.pack('!BB', error_code, error_subcode) + data
    return build_bgp_header(BGP_NOTIFICATION, payload)


def build_update(withdrawn_routes: bytes = b'', path_attributes: bytes = b'',
                 nlri: bytes = b'') -> bytes:
    """Build BGP UPDATE message.

    For EVPN, routes are carried in MP_REACH_NLRI/MP_UNREACH_NLRI path attributes,
    not in the traditional withdrawn routes or NLRI fields.

    Args:
        withdrawn_routes: Encoded withdrawn routes (usually empty for EVPN)
        path_attributes: Concatenated encoded path attributes
        nlri: Traditional NLRI (usually empty for EVPN)
    """
    payload = struct.pack('!H', len(withdrawn_routes)) + withdrawn_routes
    payload += struct.pack('!H', len(path_attributes)) + path_attributes
    payload += nlri
    return build_bgp_header(BGP_UPDATE, payload)


def build_route_refresh(afi: int = AFI_L2VPN, safi: int = SAFI_EVPN) -> bytes:
    """Build BGP ROUTE-REFRESH message."""
    payload = struct.pack('!HBB', afi, 0, safi)  # AFI (2) + Reserved (1) + SAFI (1)
    return build_bgp_header(BGP_ROUTE_REFRESH, payload)
