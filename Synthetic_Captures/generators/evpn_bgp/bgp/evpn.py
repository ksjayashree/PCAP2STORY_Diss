"""EVPN NLRI builders for Route Types 1-5.

Each function returns raw bytes representing the complete NLRI entry
(route_type + length + route-type-specific data) ready to be placed
inside MP_REACH_NLRI or MP_UNREACH_NLRI.
"""

import struct
import ipaddress
from typing import Optional

from .constants import (
    EVPN_RT1_EAD,
    EVPN_RT2_MAC_IP,
    EVPN_RT3_IMET,
    EVPN_RT4_ES,
    EVPN_RT5_IP_PREFIX,
)


def encode_rd(bgp_id: str, assigned_number: int = 100) -> bytes:
    """Encode Route Distinguisher (Type 1: IP:Number).

    Args:
        bgp_id: IPv4 BGP Router ID as dotted-quad (e.g., "10.0.0.11")
        assigned_number: 2-byte assigned number (e.g., VNI)

    Returns:
        8 bytes: Type(2) + IP(4) + Number(2)
    """
    ip_bytes = ipaddress.IPv4Address(bgp_id).packed
    return struct.pack('!H', 1) + ip_bytes + struct.pack('!H', assigned_number)


def encode_esi(esi_str: str) -> bytes:
    """Encode 10-byte Ethernet Segment Identifier from colon-separated hex.

    Args:
        esi_str: ESI string like "00:11:22:33:44:55:66:77:88:01"
                 or "0" / "00:00:00:00:00:00:00:00:00:00" for single-homed

    Returns:
        10 bytes
    """
    if esi_str == "0":
        return b'\x00' * 10
    parts = esi_str.split(':')
    if len(parts) != 10:
        raise ValueError(f"ESI must have 10 colon-separated hex bytes, got {len(parts)}")
    return bytes(int(b, 16) for b in parts)


def encode_mpls_label(label: int) -> bytes:
    """Encode MPLS label as 3 bytes (20-bit label + EXP=0 + S=1).

    Args:
        label: Label value (e.g., VNI=100)

    Returns:
        3 bytes
    """
    return struct.pack('!I', (label << 4) | 1)[1:]


def encode_mac(mac_str: str) -> bytes:
    """Encode MAC address from colon-separated hex string.

    Args:
        mac_str: MAC like "00:aa:bb:cc:dd:ee"

    Returns:
        6 bytes
    """
    parts = mac_str.split(':')
    if len(parts) != 6:
        raise ValueError(f"MAC must have 6 colon-separated hex bytes, got {len(parts)}")
    return bytes(int(b, 16) for b in parts)


def _encode_ip(ip_str: str) -> bytes:
    """Encode an IP address string to packed bytes (4 for IPv4, 16 for IPv6)."""
    addr = ipaddress.ip_address(ip_str)
    return addr.packed


def build_evpn_type1(rd: bytes, esi: bytes, ethernet_tag: int, label: int = 0) -> bytes:
    """Build EVPN Type 1 (Ethernet Auto-Discovery) NLRI.

    Args:
        rd: 8-byte Route Distinguisher
        esi: 10-byte ESI
        ethernet_tag: Ethernet Tag ID (0xFFFFFFFF for per-ES, specific value for per-EVI)
        label: MPLS label/VNI value

    Returns:
        Complete NLRI bytes: route_type(1) + length(1) + RD(8) + ESI(10) + EthTag(4) + Label(3)
    """
    body = rd + esi + struct.pack('!I', ethernet_tag) + encode_mpls_label(label)
    return struct.pack('!BB', EVPN_RT1_EAD, len(body)) + body


def build_evpn_type2(rd: bytes, esi: bytes, ethernet_tag: int, mac: str,
                     ip: Optional[str] = None, label1: int = 0,
                     label2: Optional[int] = None) -> bytes:
    """Build EVPN Type 2 (MAC/IP Advertisement) NLRI.

    Args:
        rd: 8-byte Route Distinguisher
        esi: 10-byte ESI
        ethernet_tag: Ethernet Tag ID
        mac: MAC address string (e.g., "00:aa:bb:cc:dd:ee")
        ip: Optional IP address (IPv4 or IPv6 string)
        label1: Primary MPLS label/VNI
        label2: Optional secondary label (L3 VNI for symmetric IRB)

    Returns:
        Complete NLRI bytes for Type 2 route.
    """
    mac_bytes = encode_mac(mac)
    mac_addr_len = 48  # bits

    if ip is not None:
        ip_bytes = _encode_ip(ip)
        ip_addr_len = len(ip_bytes) * 8  # 32 or 128 bits
    else:
        ip_bytes = b''
        ip_addr_len = 0

    body = (
        rd
        + esi
        + struct.pack('!I', ethernet_tag)
        + struct.pack('!B', mac_addr_len)
        + mac_bytes
        + struct.pack('!B', ip_addr_len)
        + ip_bytes
        + encode_mpls_label(label1)
    )

    if label2 is not None:
        body += encode_mpls_label(label2)

    return struct.pack('!BB', EVPN_RT2_MAC_IP, len(body)) + body


def build_evpn_type3(rd: bytes, ethernet_tag: int, originator_ip: str) -> bytes:
    """Build EVPN Type 3 (Inclusive Multicast Ethernet Tag) NLRI.

    Args:
        rd: 8-byte Route Distinguisher
        ethernet_tag: Ethernet Tag ID (usually 0 for VLAN-based)
        originator_ip: Originating router IP (IPv4 or IPv6)

    Returns:
        Complete NLRI bytes for Type 3 route.
    """
    ip_bytes = _encode_ip(originator_ip)
    ip_addr_len = len(ip_bytes) * 8

    body = rd + struct.pack('!I', ethernet_tag) + struct.pack('!B', ip_addr_len) + ip_bytes
    return struct.pack('!BB', EVPN_RT3_IMET, len(body)) + body


def build_evpn_type4(rd: bytes, esi: bytes, originator_ip: str) -> bytes:
    """Build EVPN Type 4 (Ethernet Segment) NLRI.

    Args:
        rd: 8-byte Route Distinguisher
        esi: 10-byte ESI
        originator_ip: Originating router IP (for DF election)

    Returns:
        Complete NLRI bytes for Type 4 route.
    """
    ip_bytes = _encode_ip(originator_ip)
    ip_addr_len = len(ip_bytes) * 8

    body = rd + esi + struct.pack('!B', ip_addr_len) + ip_bytes
    return struct.pack('!BB', EVPN_RT4_ES, len(body)) + body


def build_evpn_type5(rd: bytes, esi: bytes, ethernet_tag: int,
                     prefix: str, prefix_len: int,
                     gateway_ip: str, label: int = 0) -> bytes:
    """Build EVPN Type 5 (IP Prefix) NLRI.

    Args:
        rd: 8-byte Route Distinguisher
        esi: 10-byte ESI (usually 0 for Type 5)
        ethernet_tag: Ethernet Tag ID
        prefix: IP prefix (IPv4 or IPv6)
        prefix_len: Prefix length in bits
        gateway_ip: Gateway IP address
        label: MPLS label/VNI

    Returns:
        Complete NLRI bytes for Type 5 route.
    """
    prefix_addr = ipaddress.ip_address(prefix)
    prefix_bytes = prefix_addr.packed
    gw_bytes = _encode_ip(gateway_ip)

    body = (
        rd
        + esi
        + struct.pack('!I', ethernet_tag)
        + struct.pack('!B', prefix_len)
        + prefix_bytes
        + gw_bytes
        + encode_mpls_label(label)
    )
    return struct.pack('!BB', EVPN_RT5_IP_PREFIX, len(body)) + body


# --- Convenience functions ---

def build_ead_per_es(bgp_id: str, esi_str: str, vni: int = 100) -> bytes:
    """Convenience: Build per-ES EAD route (Ethernet Tag = 0xFFFFFFFF)."""
    rd = encode_rd(bgp_id, vni)
    esi = encode_esi(esi_str)
    return build_evpn_type1(rd, esi, 0xFFFFFFFF, label=0)


def build_ead_per_evi(bgp_id: str, esi_str: str, ethernet_tag: int = 0,
                      vni: int = 100) -> bytes:
    """Convenience: Build per-EVI EAD route."""
    rd = encode_rd(bgp_id, vni)
    esi = encode_esi(esi_str)
    return build_evpn_type1(rd, esi, ethernet_tag, label=vni)


def build_mac_ip_route(bgp_id: str, esi_str: str, mac: str,
                       ip: Optional[str] = None, vni: int = 100) -> bytes:
    """Convenience: Build MAC/IP advertisement route."""
    rd = encode_rd(bgp_id, vni)
    esi = encode_esi(esi_str)
    return build_evpn_type2(rd, esi, 0, mac, ip=ip, label1=vni)


def build_imet_route(bgp_id: str, originator_ip: str, vni: int = 100) -> bytes:
    """Convenience: Build Inclusive Multicast route."""
    rd = encode_rd(bgp_id, vni)
    return build_evpn_type3(rd, 0, originator_ip)


def build_es_route(bgp_id: str, esi_str: str, originator_ip: str,
                   vni: int = 100) -> bytes:
    """Convenience: Build Ethernet Segment route (for DF election)."""
    rd = encode_rd(bgp_id, vni)
    esi = encode_esi(esi_str)
    return build_evpn_type4(rd, esi, originator_ip)


def build_ip_prefix_route(bgp_id: str, prefix: str, prefix_len: int,
                          gateway_ip: str, vni: int = 100) -> bytes:
    """Convenience: Build IP Prefix route.

    For IPv4 prefixes the gateway must be IPv4 (RFC 7432 Type 5 requires
    prefix and gateway to share the same address family). bgp_id is used
    as the gateway when the prefix is IPv4, regardless of gateway_ip.
    """
    rd = encode_rd(bgp_id, vni)
    esi = encode_esi("0")
    prefix_addr = ipaddress.ip_address(prefix)
    if prefix_addr.version == 4:
        gw = bgp_id        # IPv4 PE router-id as gateway
    else:
        gw = gateway_ip    # IPv6 loopback for IPv6 prefixes
    return build_evpn_type5(rd, esi, 0, prefix, prefix_len, gw, label=vni)
