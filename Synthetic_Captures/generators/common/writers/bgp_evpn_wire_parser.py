"""Pure byte-level BGP/EVPN wire parsing -- zero imports from either
synthcap's or pcap2story's other code (stdlib `struct` only).

Extracted (2026-07-22) from csv_writer.py's private _parse_bgp_payload/
_parse_bgp_update/_decode_route_identifiers, which operated identically on
raw bytes even before this extraction -- the only change here is the
import boundary, not the parsing logic itself (byte-for-byte identical
behavior, verified against all 112 files before this module existed
anywhere -- see the accompanying verification report).

WHY THIS MODULE EXISTS: this logic is shared by two consumers with very
different inputs:
  - synthcap's csv_writer.py: called with pkt.payload, a TCPPacket
    object's in-memory attribute (synthcap's own generator already
    guarantees one complete BGP PDU per packet, no reassembly needed).
  - pcap2story's pcap_parser.py: called with reassembled TCP stream
    bytes from a real .pcap file (rule_based/src/pcap_parser.py handles
    the reassembly; this module only ever sees the resulting byte
    stream, never a scapy packet object or anything TCPPacket-shaped).
Both consumers get the exact same, already-debugged parsing (this
session found and fixed real bugs here -- the Type 5 IP-prefix decode
gap and the ORIGINATOR_ID extraction gap -- reusing this module means
neither consumer can silently regress either fix).
"""

import struct

BGP_TYPE_SIGNIFICANCE = {4: 1, 1: 2, 5: 2, 2: 3, 3: 5}

# Readable name for the raw BGP message type byte -- this is what
# bgp_msg_type now holds. BGP_TYPE_SIGNIFICANCE (above) is unrelated to this
# mapping: it stays a numeric rank under its own field, bgp_msg_significance.
BGP_TYPE_NAME = {1: 'OPEN', 2: 'UPDATE', 3: 'NOTIFICATION', 4: 'KEEPALIVE', 5: 'ROUTE-REFRESH'}

ERROR_CODE_SEVERITY = {0: 0, 1: 2, 2: 2, 3: 3, 4: 4, 5: 3, 6: 5}

ERROR_SUBCODE_SEVERITY = {
    (1, 1): 3, (1, 2): 3, (1, 3): 4,
    (2, 1): 3, (2, 2): 4, (2, 3): 4, (2, 4): 2, (2, 5): 5, (2, 6): 3, (2, 7): 2,
    (3, 1): 3, (3, 2): 3, (3, 3): 4, (3, 4): 3, (3, 5): 3, (3, 6): 3,
    (3, 7): 4, (3, 8): 4, (3, 9): 2, (3, 10): 4, (3, 11): 4,
    (5, 1): 4, (5, 2): 4, (5, 3): 5,
    (6, 1): 3, (6, 2): 4, (6, 3): 2, (6, 4): 4, (6, 5): 2,
    (6, 6): 2, (6, 7): 5, (6, 8): 4,
}


def decode_route_identifiers(evpn_route_type: int, nlri_body: bytes) -> dict:
    """Decode the per-route identifying field(s) from an EVPN NLRI body
    (the bytes after the route-type(1) + length(1) header), using the
    deterministic offsets from generators/evpn_bgp/bgp/evpn.py's encoders:

      Type 1 (EAD):     RD(8) + ESI(10) + EthTag(4) + Label(3)
      Type 2 (MAC/IP):  RD(8) + ESI(10) + EthTag(4) + MACLen(1) + MAC(6) + ...
      Type 4 (ES):      RD(8) + ESI(10) + IPLen(1) + IP
      Type 5 (IP Prefix): RD(8) + ESI(10) + EthTag(4) + PrefixLen(1) + PrefixBytes(4/16) + ...

    mac_address only from Type 2, ip_prefix only from Type 5, esi only from
    Type 1/4 -- Type 3 (IMET) has no ESI field in its own encoding
    (build_evpn_type3: RD + EthTag + IPLen + IP, no ESI) and no per-route
    identifier at all (it's per-PE), so it and every other case return all
    three as None, same convention as route_target/next_hop's existing
    defaults for non-applicable rows.
    """
    result = {'mac_address': None, 'ip_prefix': None, 'esi': None}
    try:
        if evpn_route_type == 2 and len(nlri_body) >= 29:
            mac_bytes = nlri_body[23:29]
            result['mac_address'] = ':'.join(f'{b:02x}' for b in mac_bytes)
        elif evpn_route_type == 5 and len(nlri_body) >= 27:
            prefix_len = nlri_body[22]
            prefix_bytes = nlri_body[23:27]
            result['ip_prefix'] = f"{'.'.join(str(b) for b in prefix_bytes)}/{prefix_len}"
        elif evpn_route_type in (1, 4) and len(nlri_body) >= 18:
            esi_bytes = nlri_body[8:18]
            if esi_bytes == b'\x00' * 10:
                result['esi'] = "0"
            else:
                result['esi'] = ':'.join(f'{b:02x}' for b in esi_bytes)
    except Exception as exc:
        # LOUD FALLBACK (2026-07-25): a fixed-offset decode failure here means
        # nlri_body didn't match evpn.py's assumed encoder byte layout for
        # this route type -- previously silent (bare except: pass), so a
        # layout drift would just produce None fields with no signal
        # anywhere. Non-fatal by design: this runs at decode-time inside
        # both synthcap's csv_writer.py and pcap2story's vendored copy, and
        # a hard failure mid-parse would be too disruptive for either
        # consumer. Same non-fatal-warning pattern as metadata.py's _ft().
        print(
            f"WARNING: bgp_evpn_wire_parser.decode_route_identifiers() failed "
            f"for evpn_route_type={evpn_route_type!r}, nlri_body={nlri_body!r} "
            f"-- {exc!r}. Falling back to None fields for this route."
        )
    return result


def parse_bgp_update(body: bytes) -> dict:
    result = {'route_action': 'n/a', 'evpn_route_type': 0,
              'next_hop': 0.0, 'route_target': 0,
              'mac_address': None, 'ip_prefix': None, 'esi': None,
              'originator_id': None}
    try:
        if len(body) < 2:
            return result
        withdrawn_len = struct.unpack('!H', body[0:2])[0]
        if withdrawn_len > 0:
            result['route_action'] = 'withdraw'
        offset = 2 + withdrawn_len
        if offset + 2 > len(body):
            return result
        attr_len = struct.unpack('!H', body[offset:offset + 2])[0]
        attrs_end = offset + 2 + attr_len
        offset += 2
        if withdrawn_len == 0 and attrs_end < len(body):
            result['route_action'] = 'advertise'
        while offset < attrs_end:
            if offset + 3 > len(body):
                break
            attr_flags = body[offset]
            attr_type = body[offset + 1]
            if attr_flags & 0x10:
                if offset + 4 > len(body):
                    break
                attr_val_len = struct.unpack('!H', body[offset + 2:offset + 4])[0]
                attr_val_start = offset + 4
            else:
                attr_val_len = body[offset + 2]
                attr_val_start = offset + 3
            attr_val = body[attr_val_start:attr_val_start + attr_val_len]
            if attr_type in (14, 15) and len(attr_val) >= 3:
                afi = struct.unpack('!H', attr_val[0:2])[0]
                safi = attr_val[2]
                if afi == 25 and safi == 70:
                    if attr_type == 14:
                        result['route_action'] = 'advertise'
                        if len(attr_val) > 3:
                            nh_len = attr_val[3]
                            if nh_len >= 16 and len(attr_val) >= 4 + nh_len:
                                nh_int = int.from_bytes(attr_val[4:4 + nh_len][:16], 'big')
                                result['next_hop'] = round((nh_int % 10000) / 10000.0, 6)
                            nlri_off = 4 + nh_len + 1
                            if nlri_off < len(attr_val):
                                result['evpn_route_type'] = attr_val[nlri_off]
                                if nlri_off + 1 < len(attr_val):
                                    nlri_len = attr_val[nlri_off + 1]
                                    nlri_body = attr_val[nlri_off + 2:nlri_off + 2 + nlri_len]
                                    result.update(decode_route_identifiers(
                                        result['evpn_route_type'], nlri_body))
                    else:
                        if len(attr_val) > 3:
                            result['route_action'] = 'withdraw'
                            result['evpn_route_type'] = attr_val[3]
                            if len(attr_val) > 4:
                                nlri_len = attr_val[4]
                                nlri_body = attr_val[5:5 + nlri_len]
                                result.update(decode_route_identifiers(
                                    result['evpn_route_type'], nlri_body))
                        else:
                            # Empty NLRI -- End-of-RIB marker (RFC 4724), not
                            # a real withdrawal. MP_UNREACH_NLRI with no
                            # withdrawn routes is the wire-format signal that
                            # a session's initial route sync is complete;
                            # conflating it with 'withdraw' made every
                            # Graceful Restart capture's ground truth show a
                            # withdrawal that never actually happened.
                            result['route_action'] = 'end_of_rib'
            elif attr_type == 9 and len(attr_val) >= 4:
                # ORIGINATOR_ID (RFC 4456) -- plain 4-byte IPv4, no AFI/SAFI
                # header unlike MP_REACH/MP_UNREACH. Only present on
                # reflected UPDATEs; absent on withdrawals and non-reflected
                # advertises, which is expected and correct, not a parsing gap.
                result['originator_id'] = '.'.join(str(b) for b in attr_val[0:4])
            elif attr_type == 16 and len(attr_val) >= 8:
                # Extended Communities -- scan for RT community (sub-type 0x02)
                for i in range(len(attr_val) // 8):
                    ec = attr_val[i * 8:(i + 1) * 8]
                    if len(ec) < 8:
                        break
                    ec_high, ec_low = ec[0], ec[1]
                    if ec_low == 0x02 and ec_high in (0x00, 0x01):
                        if ec_high == 0x00:  # type-0: 2-byte ASN + 4-byte local admin
                            rt_asn   = struct.unpack('!H', ec[2:4])[0]
                            rt_admin = struct.unpack('!I', ec[4:8])[0]
                        else:                # type-1: 4-byte IPv4 + 2-byte local admin
                            rt_asn   = struct.unpack('!I', ec[2:6])[0]
                            rt_admin = struct.unpack('!H', ec[6:8])[0]
                        result['route_target'] = rt_asn * 100000 + rt_admin
                        break
            offset = attr_val_start + attr_val_len
    except Exception as exc:
        # LOUD FALLBACK (2026-07-25): see decode_route_identifiers()'s
        # matching comment above -- same non-fatal-warning pattern, same
        # rationale (decode-time, shared by synthcap's csv_writer.py and
        # pcap2story's vendored copy, hard failure mid-parse too disruptive).
        print(
            f"WARNING: bgp_evpn_wire_parser.parse_bgp_update() failed for "
            f"body={body!r} -- {exc!r}. Falling back to partial/default "
            f"result fields."
        )
    return result


def parse_bgp_payload(payload: bytes) -> list:
    """Splits a raw byte stream (a full BGP-over-TCP payload -- one or
    more back-to-back BGP messages, each starting with the standard
    16-byte 0xFF marker) into a list of per-message dicts. Works
    identically whether `payload` came from a single in-memory
    TCPPacket.payload attribute (synthcap's own use) or a reassembled
    real-pcap TCP stream (pcap2story's use) -- this function only ever
    sees bytes, nothing consumer-specific.
    """
    messages = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 19:
            break
        if payload[offset:offset + 16] != b'\xff' * 16:
            break
        length = struct.unpack('!H', payload[offset + 16:offset + 18])[0]
        msg_type = payload[offset + 18]
        if length < 19 or offset + length > len(payload):
            break
        body = payload[offset + 19:offset + length]
        msg = {
            'bgp_msg_type': BGP_TYPE_NAME.get(msg_type, 'UNKNOWN'),
            'bgp_msg_significance': BGP_TYPE_SIGNIFICANCE.get(msg_type, 0),
            'packet_type': 'bgp',
            'route_action': 'n/a', 'error_code': 0, 'error_code_severity': 0,
            'error_subcode': 0, 'error_subcode_severity': 0,
            'evpn_route_type': 0, 'next_hop': 0.0,
            'route_target': 0,
            'mac_address': None, 'ip_prefix': None, 'esi': None,
            'originator_id': None,
        }
        if msg_type == 3 and len(body) >= 2:
            msg['error_code'] = body[0]
            msg['error_subcode'] = body[1]
            msg['error_code_severity'] = ERROR_CODE_SEVERITY.get(body[0], 0)
            msg['error_subcode_severity'] = ERROR_SUBCODE_SEVERITY.get((body[0], body[1]), 0)
        if msg_type == 2:
            msg.update(parse_bgp_update(body))
        messages.append(msg)
        offset += length
    return messages
