"""BGP path attribute builders for EVPN UPDATE messages."""

import struct
import ipaddress
from .constants import *


def encode_path_attribute(flags: int, type_code: int, value: bytes) -> bytes:
    """Encode a single path attribute with proper flags and length."""
    if len(value) > 255:
        flags |= ATTR_FLAG_EXTENDED
        return struct.pack('!BBH', flags, type_code, len(value)) + value
    else:
        flags &= ~ATTR_FLAG_EXTENDED
        return struct.pack('!BBB', flags, type_code, len(value)) + value


def attr_origin(origin: int = 0) -> bytes:
    """ORIGIN attribute. 0=IGP, 1=EGP, 2=INCOMPLETE."""
    flags = ATTR_FLAG_TRANSITIVE
    return encode_path_attribute(flags, ATTR_ORIGIN, struct.pack('!B', origin))


def attr_as_path(as_path: list[int] = None) -> bytes:
    """AS_PATH attribute. For iBGP, typically empty."""
    flags = ATTR_FLAG_TRANSITIVE
    if not as_path:
        return encode_path_attribute(flags, ATTR_AS_PATH, b'')
    # AS_SEQUENCE type=2, length=N, then N 4-byte AS numbers
    value = struct.pack('!BB', 2, len(as_path))
    for asn in as_path:
        value += struct.pack('!I', asn)
    return encode_path_attribute(flags, ATTR_AS_PATH, value)


def attr_local_pref(local_pref: int = 100) -> bytes:
    """LOCAL_PREF attribute (iBGP only)."""
    flags = ATTR_FLAG_TRANSITIVE
    return encode_path_attribute(flags, ATTR_LOCAL_PREF, struct.pack('!I', local_pref))


def attr_mp_reach_nlri(afi: int, safi: int, next_hop: str, nlri_bytes: bytes) -> bytes:
    """MP_REACH_NLRI attribute (RFC 4760).

    Args:
        afi: Address Family Identifier (25 for L2VPN)
        safi: Subsequent AFI (70 for EVPN)
        next_hop: Next-hop address string (IPv4 or IPv6)
        nlri_bytes: Encoded NLRI (e.g., EVPN routes)
    """
    flags = ATTR_FLAG_OPTIONAL | ATTR_FLAG_TRANSITIVE
    nh_bytes = ipaddress.ip_address(next_hop).packed
    # AFI (2) + SAFI (1) + NH Length (1) + NH + Reserved (1) + NLRI
    value = struct.pack('!HBB', afi, safi, len(nh_bytes)) + nh_bytes + b'\x00' + nlri_bytes
    return encode_path_attribute(flags, ATTR_MP_REACH_NLRI, value)


def attr_mp_unreach_nlri(afi: int, safi: int, withdrawn_nlri: bytes) -> bytes:
    """MP_UNREACH_NLRI attribute (RFC 4760)."""
    flags = ATTR_FLAG_OPTIONAL | ATTR_FLAG_TRANSITIVE
    # AFI (2) + SAFI (1) + Withdrawn Routes
    value = struct.pack('!HB', afi, safi) + withdrawn_nlri
    return encode_path_attribute(flags, ATTR_MP_UNREACH_NLRI, value)


def attr_extended_communities(communities: list[bytes]) -> bytes:
    """Extended Communities attribute (RFC 4360).
    Each community is 8 bytes.
    """
    flags = ATTR_FLAG_OPTIONAL | ATTR_FLAG_TRANSITIVE
    value = b''.join(communities)
    return encode_path_attribute(flags, ATTR_EXTENDED_COMMUNITY, value)


def encode_rt_community(asn: int, local_value: int) -> bytes:
    """Encode a Route Target extended community (2-byte AS format).
    Type: 0x00 0x02, AS (2 bytes), Assigned Number (4 bytes).
    """
    return struct.pack('!BBHI', 0x00, 0x02, asn & 0xFFFF, local_value)


def encode_rt_community_4byte(asn: int, local_value: int) -> bytes:
    """Encode a Route Target extended community (4-byte AS format).
    Type: 0x02 0x02, AS (4 bytes), Assigned Number (2 bytes).
    """
    return struct.pack('!BBIH', 0x02, 0x02, asn, local_value & 0xFFFF)


def encode_encapsulation_community(tunnel_type: int = TUNNEL_TYPE_VXLAN) -> bytes:
    """Encode Encapsulation extended community.
    Type: 0x03 0x0c, Reserved (4 bytes=0), Tunnel Type (2 bytes).
    """
    return struct.pack('!BBIH', 0x03, 0x0c, 0, tunnel_type)


def encode_df_election_community(df_alg: int, ac_df: bool) -> bytes:
    """Encode DF Election Extended Community (RFC 8584 SS2.2/SS3).

    Attached to a Route Type 4 (ES route) advertisement to carry AC
    (attachment circuit) state as an input to DF election.

    Wire format (8 bytes):
      Octet 0:   Type = 0x06 (EVPN Extended Community)
      Octet 1:   Sub-Type = 0x06 (DF Election Extended Community)
      Octet 2:   3-bit RSV (high bits) + 5-bit DF Alg (low bits, values 0-31)
      Octets 3-4: 2-octet Bitmap; AC-DF capability is bit 1 (LSB-indexed,
                  bit k = 1 << k, so bit 1 = 0x0002).
      Octets 5-7: Reserved (3 bytes, zero-filled padding to the standard
                  8-byte extended community size)

    Args:
        df_alg: DF election algorithm value (0-31, 5 bits)
        ac_df: True if the local AC is up (AC-DF capability bit set),
               False if down
    """
    rsv_df_alg = df_alg & 0x1F  # high 3 bits reserved = 0, low 5 bits = df_alg
    bitmap = 0x0002 if ac_df else 0x0000  # bit 1 = AC-DF capability
    return struct.pack('!BBBHBBB', 0x06, 0x06, rsv_df_alg, bitmap, 0, 0, 0)


def encode_mac_mobility_community(sequence: int, sticky: bool = False) -> bytes:
    """Encode MAC Mobility extended community (RFC 7432 SS7.7).

    Signals a MAC has moved (VM migration, dual-homing failover, MAC
    mobility storm) with an escalating sequence number so receivers can
    determine which advertisement is most recent.

    Wire format (8 bytes): Type=0x06 (1) + Sub-Type=0x00 (1) + Flags (1) +
    Reserved=0x00 (1) + Sequence Number (4).
    """
    flags = 0x01 if sticky else 0x00
    return struct.pack('!BBBBI', 0x06, 0x00, flags, 0x00, sequence)


def attr_next_hop_ipv6(next_hop: str) -> bytes:
    """Traditional NEXT_HOP for IPv6 (not commonly used with MP_REACH, here for completeness)."""
    flags = ATTR_FLAG_TRANSITIVE
    nh_bytes = ipaddress.IPv6Address(next_hop).packed
    return encode_path_attribute(flags, ATTR_NEXT_HOP, nh_bytes)


def attr_originator_id(router_id: str) -> bytes:
    """ORIGINATOR_ID attribute (RFC 4456). Optional, non-transitive.

    Carries the BGP Identifier of the route's originating router.
    """
    flags = ATTR_FLAG_OPTIONAL
    rid_bytes = ipaddress.IPv4Address(router_id).packed
    return encode_path_attribute(flags, ATTR_ORIGINATOR_ID, rid_bytes)


def attr_cluster_list(cluster_ids: list[str]) -> bytes:
    """CLUSTER_LIST attribute (RFC 4456). Optional, non-transitive.

    Sequence of 4-byte CLUSTER_IDs, one per reflection hop.
    """
    flags = ATTR_FLAG_OPTIONAL
    value = b''.join(ipaddress.IPv4Address(cid).packed for cid in cluster_ids)
    return encode_path_attribute(flags, ATTR_CLUSTER_LIST, value)


def build_standard_evpn_path_attrs(next_hop: str, nlri_bytes: bytes, asn: int,
                                   vni: int, local_pref: int = 100,
                                   extra_communities: list[bytes] = None,
                                   originator_id: str = None,
                                   cluster_id: str = None) -> bytes:
    """Build standard set of path attributes for an EVPN UPDATE (advertise).

    originator_id/cluster_id: when both are provided, adds ORIGINATOR_ID and
    CLUSTER_LIST attributes for routes being reflected by an RR (RFC 4456).
    If either is None, both are omitted (direct PE origination).

    Returns concatenated path attribute bytes ready for build_update().
    """
    communities = [
        encode_rt_community(asn, vni),
        encode_encapsulation_community(TUNNEL_TYPE_VXLAN),
    ]
    if extra_communities:
        communities.extend(extra_communities)

    attrs = b''
    attrs += attr_origin(0)  # IGP
    attrs += attr_as_path()  # Empty for iBGP
    attrs += attr_local_pref(local_pref)
    attrs += attr_extended_communities(communities)
    attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, next_hop, nlri_bytes)
    if originator_id is not None and cluster_id is not None:
        attrs += attr_originator_id(originator_id)
        attrs += attr_cluster_list([cluster_id])
    return attrs


def build_evpn_withdraw_attrs(withdrawn_nlri: bytes, originator_id: str = None,
                              cluster_id: str = None) -> bytes:
    """Build path attributes for an EVPN WITHDRAW (MP_UNREACH_NLRI).

    originator_id/cluster_id: when both are provided, adds ORIGINATOR_ID
    and CLUSTER_LIST attributes (RFC 4456) so a reflected withdrawal still
    identifies its true originating PE, not just the relaying RR.
    """
    attrs = attr_mp_unreach_nlri(AFI_L2VPN, SAFI_EVPN, withdrawn_nlri)
    if originator_id is not None and cluster_id is not None:
        attrs += attr_originator_id(originator_id)
        attrs += attr_cluster_list([cluster_id])
    return attrs
