"""BGP capability encoding for OPEN message optional parameters."""

import struct
from .constants import *


def encode_capability(code: int, value: bytes) -> bytes:
    """Encode a single BGP capability (code + length + value)."""
    return struct.pack('!BB', code, len(value)) + value


def cap_multiprotocol(afi: int, safi: int) -> bytes:
    """Multiprotocol Extensions capability (RFC 4760)."""
    value = struct.pack('!HBB', afi, 0, safi)  # AFI + Reserved + SAFI
    return encode_capability(CAP_MP_BGP, value)


def cap_4byte_as(asn: int) -> bytes:
    """4-Octet AS Number capability (RFC 6793)."""
    return encode_capability(CAP_4BYTE_AS, struct.pack('!I', asn))


def cap_route_refresh() -> bytes:
    """Route Refresh capability (RFC 2918)."""
    return encode_capability(CAP_ROUTE_REFRESH, b'')


def cap_graceful_restart(restart_time: int = 120, afi_safi_list: list = None,
                         is_restart: bool = False,
                         is_notification_tolerant: bool = False) -> bytes:
    """Graceful Restart capability (RFC 4724, extended by RFC 8538).

    is_restart: sets the Restart State (R) bit. Per RFC 4724 SS3, this bit
    should be 0 on a fresh/first connection and only 1 on the OPEN sent when
    reconnecting after an actual restart, to signal "please preserve my
    forwarding state." Defaults to False so ordinary session establishment
    (the overwhelming majority of callers, via default_evpn_capabilities())
    doesn't claim to be restarting.

    is_notification_tolerant: sets the Notification (N) bit, defined by
    RFC 8538. Signals that graceful restart should still apply even when
    the session is torn down via an explicit NOTIFICATION (e.g. Cease or
    Hold Timer Expired), not only a silent/implicit disconnect (RFC 4724's
    original base case). Both peers negotiate this in their capability
    advertisement; defaults to False, matching existing behavior for every
    prior call site.
    """
    # Flags (4 bits) + Restart Time (12 bits)
    r_bit = 0x8 if is_restart else 0x0
    n_bit = 0x4 if is_notification_tolerant else 0x0
    flags_time = ((r_bit | n_bit) << 12) | (restart_time & 0x0FFF)
    value = struct.pack('!H', flags_time)
    if afi_safi_list:
        for afi, safi, flags in afi_safi_list:
            value += struct.pack('!HBB', afi, safi, flags)
    return encode_capability(CAP_GRACEFUL_RESTART, value)


def cap_add_path(afi: int, safi: int, send_receive: int = 3) -> bytes:
    """Add-Path capability (RFC 7911). send_receive: 1=receive, 2=send, 3=both."""
    value = struct.pack('!HBB', afi, safi, send_receive)
    return encode_capability(CAP_ADD_PATH, value)


def default_evpn_capabilities(asn: int, is_restart: bool = False,
                              is_notification_tolerant: bool = False) -> list[bytes]:
    """Return standard capabilities for an EVPN-capable router.

    is_restart, is_notification_tolerant: passed through to
    cap_graceful_restart() -- see its docstring. Both default to False
    (preserves existing behavior for all prior call sites).
    """
    return [
        cap_multiprotocol(AFI_L2VPN, SAFI_EVPN),
        cap_4byte_as(asn),
        cap_route_refresh(),
        cap_graceful_restart(120, [(AFI_L2VPN, SAFI_EVPN, 0x80)], is_restart=is_restart,
                             is_notification_tolerant=is_notification_tolerant),
    ]
