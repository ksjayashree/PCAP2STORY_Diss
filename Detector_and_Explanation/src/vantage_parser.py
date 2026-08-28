"""
Layer 2: per-vantage pcap parsing into a normalized event stream.

Takes an explicit {vantage_id: pcap_path} dict (arbitrary N, no rr1/rr2
naming assumption) and topology.json's node list (for IP -> node_involved
resolution), and produces a flat list of:
    {timestamp, source_vantage, event_type, node_involved, protocol_detail}

Reimplemented generically against raw scapy layers -- does not import or
reuse any code from C:\\PCAP2STORY\\rule_based (read-only reference only;
its TCP-session-grouping technique and its EVPN NLRI/extended-community
byte offsets were used as a reference for what correct decoding looks
like, not its code).

Covers: BGP UPDATE/WITHDRAWAL/NOTIFICATION/OPEN, session-established
(first KEEPALIVE after OPEN), TCP RST/FIN, BFD state change, OSPF
neighbor-visible-in-Hello change. BGP UPDATE path attributes are decoded
enough to extract route_target, route_distinguisher, mac_mobility_seq,
evpn_route_type, mac_address, ip_prefix, esi, originator_id, ethernet_tag,
df_election_ac_df (the latter two added for esdf_toggle.py -- ethernet_tag
distinguishes Type-1 per-ES (0xFFFFFFFF sentinel) from per-EVI (real tag)
EAD routes per RFC 8584, df_election_ac_df decodes the DF Election
Extended Community's AC-DF capability bit per RFC 8584 SS2.2/SS3, byte
layout confirmed directly against the synthcap generator's own
encode_df_election_community(), not just RFC text).
"""
import os
import sys
import struct
from datetime import datetime, timezone

from scapy.all import rdpcap, IP, TCP, Raw
from scapy.contrib.bfd import BFD
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

sys.path.insert(0, os.path.dirname(__file__))
from topology import load_topology

BGP_PORT = 179
OSPF_PROTO = 89

BGP_TYPE_NAME = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}

NOTIFICATION_ERROR_CODE = {
    1: "Message Header Error",
    2: "OPEN Message Error",
    3: "UPDATE Message Error",
    4: "Hold Timer Expired",
    5: "Finite State Machine Error",
    6: "Cease",
}
BFD_STATE_NAME = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}


def _ip_to_node(topo):
    return {n["router_id"]: n["id"] for n in topo["nodes"]}


def _node_for_ip(ip_to_node, ip):
    return ip_to_node.get(ip)


def _iso(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------
# Fix 1: TCP stream reassembly, generic over any two session endpoints.
# ---------------------------------------------------------------------

class _DirStream:
    """Byte-stream reassembly for one direction of one TCP session.
    Sorts segments by sequence number (handles out-of-order arrival),
    skips exact-duplicate/overlapping retransmitted bytes, and keeps an
    offset->timestamp map so a BGP message extracted from the assembled
    stream can be attributed back to the packet that completed it."""

    def __init__(self):
        self._segments = []  # (seq, payload_bytes, timestamp)

    def add(self, seq, payload, ts):
        if payload:
            self._segments.append((seq, bytes(payload), ts))

    def assemble(self):
        """Returns (buffer_bytes, offset_ranges) where offset_ranges is a
        sorted list of (start_offset, end_offset, timestamp) covering the
        buffer, for mapping a byte offset back to the packet that carried it."""
        self._segments.sort(key=lambda s: s[0])
        buf = bytearray()
        ranges = []
        next_seq = None
        for seq, payload, ts in self._segments:
            if next_seq is None:
                start = 0
                new_bytes = payload
                next_seq = seq + len(payload)
            elif seq >= next_seq:
                # in-order (or a gap -- gaps aren't expected on this
                # loss-free synthetic lab network; if one occurs we still
                # append what we have rather than stalling the stream)
                start = len(buf)
                new_bytes = payload
                next_seq = seq + len(payload)
            else:
                # overlap with already-buffered bytes (retransmission or
                # partial re-send) -- keep only the genuinely new tail
                overlap = next_seq - seq
                if overlap >= len(payload):
                    continue  # fully-seen retransmission, nothing new
                start = len(buf)
                new_bytes = payload[overlap:]
                next_seq = seq + len(payload)
            if not new_bytes:
                continue
            buf.extend(new_bytes)
            ranges.append((start, start + len(new_bytes), ts))
        return bytes(buf), ranges


def _session_key(a_ip, a_port, b_ip, b_port):
    """Unordered session key -- a BGP session is the same session
    regardless of which side is captured as src vs dst."""
    return tuple(sorted([(a_ip, a_port), (b_ip, b_port)]))


def _timestamp_for_offset(ranges, offset):
    for start, end, ts in ranges:
        if start <= offset < end:
            return ts
    # message starts exactly at the end of the last range (edge case)
    return ranges[-1][2] if ranges else None


def _reassemble_bgp_sessions(packets):
    """Groups all TCP/BGP packets by session+direction, reassembles each
    direction's byte stream, and returns a dict:
        session_key -> {"a": (ip,port), "b": (ip,port),
                         "a_to_b": (buffer, ranges), "b_to_a": (buffer, ranges)}
    """
    streams = {}  # (session_key, direction_tuple) -> _DirStream
    session_endpoints = {}

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        tcp = pkt[TCP]
        if tcp.sport != BGP_PORT and tcp.dport != BGP_PORT:
            continue
        if not pkt.haslayer(Raw):
            continue
        ip = pkt[IP]
        skey = _session_key(ip.src, tcp.sport, ip.dst, tcp.dport)
        direction = (ip.src, tcp.sport, ip.dst, tcp.dport)
        session_endpoints[skey] = skey
        dkey = (skey, direction)
        if dkey not in streams:
            streams[dkey] = _DirStream()
        streams[dkey].add(int(tcp.seq), pkt[Raw].load, float(pkt.time))

    sessions = {}
    for (skey, direction), stream in streams.items():
        buf, ranges = stream.assemble()
        sessions.setdefault(skey, {})[direction] = (buf, ranges)
    return sessions


# ---------------------------------------------------------------------
# Fix 2: full path-attribute decoding -- route_target, route_distinguisher,
# mac_mobility_seq, decoded generically (not special-cased to RT alone).
# ---------------------------------------------------------------------

def _decode_route_distinguisher(rd_bytes):
    """RD is always the first 8 bytes of an EVPN NLRI body. Type field
    (first 2 bytes) determines the shape of the remaining 6:
      type 0: 2-byte ASN + 4-byte number  -> "ASN:number"
      type 1: 4-byte IPv4 + 2-byte number -> "a.b.c.d:number"
      type 2: 4-byte ASN + 2-byte number  -> "ASN:number" """
    if len(rd_bytes) < 8:
        return None
    rd_type = struct.unpack("!H", rd_bytes[0:2])[0]
    if rd_type == 0:
        asn = struct.unpack("!H", rd_bytes[2:4])[0]
        num = struct.unpack("!I", rd_bytes[4:8])[0]
        return f"{asn}:{num}"
    elif rd_type == 1:
        ip = ".".join(str(b) for b in rd_bytes[2:6])
        num = struct.unpack("!H", rd_bytes[6:8])[0]
        return f"{ip}:{num}"
    elif rd_type == 2:
        asn = struct.unpack("!I", rd_bytes[2:6])[0]
        num = struct.unpack("!H", rd_bytes[6:8])[0]
        return f"{asn}:{num}"
    return None


def _decode_extended_communities(attr_val):
    """Generic 8-byte-entry scanner (RFC 4360) -- decodes every entry it
    recognizes, not just Route Target, so new community types (e.g. ES-Import
    RT, used by MAC Mobility work earlier this session) can be added here
    without restructuring the caller."""
    out = {"route_target": None, "mac_mobility_seq": None, "raw_communities": [],
           "df_election_alg": None, "df_election_ac_df": None}
    n = len(attr_val) // 8
    for i in range(n):
        ec = attr_val[i * 8:(i + 1) * 8]
        if len(ec) < 8:
            break
        ec_type, ec_subtype = ec[0], ec[1]
        out["raw_communities"].append(ec.hex())
        if ec_subtype == 0x02 and ec_type in (0x00, 0x01):
            # Route Target
            if ec_type == 0x00:
                asn = struct.unpack("!H", ec[2:4])[0]
                admin = struct.unpack("!I", ec[4:8])[0]
            else:
                asn = struct.unpack("!I", ec[2:6])[0]
                admin = struct.unpack("!H", ec[6:8])[0]
            out["route_target"] = f"{asn}:{admin}"
        elif ec_type == 0x06 and ec_subtype == 0x00:
            # MAC Mobility (RFC 7432 sec 15): flags(1) + reserved(2) + seq(4)
            flags = ec[2]
            seq = struct.unpack("!I", ec[4:8])[0]
            out["mac_mobility_seq"] = seq
            out["mac_mobility_sticky"] = bool(flags & 0x01)
        elif ec_type == 0x06 and ec_subtype == 0x06:
            # DF Election Extended Community (RFC 8584 SS5), esdf_toggle.py
            # investigation: octet 2 = 3-bit RSV + 5-bit DF Alg, octets 3-4
            # = 2-byte bitmap (AC-DF capability = bit 1, i.e. 0x0002), octets
            # 5-7 reserved. Byte layout confirmed against the generator's
            # own encode_df_election_community(), not just RFC text.
            df_alg = ec[2] & 0x1F
            bitmap = struct.unpack("!H", ec[3:5])[0]
            out["df_election_alg"] = df_alg
            out["df_election_ac_df"] = bool(bitmap & 0x0002)
    return out


def _decode_evpn_nlri(evpn_route_type, nlri_body):
    """Route-type-specific identifiers, offsets referenced from the RD
    position (bytes 0-8 of every EVPN NLRI body, before type-specific
    fields) -- same layout documented in pcap2story's wire parser."""
    result = {"route_distinguisher": _decode_route_distinguisher(nlri_body[0:8]),
              "mac_address": None, "ip_prefix": None, "esi": None, "ethernet_tag": None}
    try:
        if evpn_route_type == 2 and len(nlri_body) >= 29:
            mac_bytes = nlri_body[23:29]
            result["mac_address"] = ":".join(f"{b:02x}" for b in mac_bytes)
        elif evpn_route_type == 5 and len(nlri_body) >= 27:
            prefix_len = nlri_body[22]
            prefix_bytes = nlri_body[23:27]
            result["ip_prefix"] = f"{'.'.join(str(b) for b in prefix_bytes)}/{prefix_len}"
        elif evpn_route_type in (1, 4) and len(nlri_body) >= 18:
            esi_bytes = nlri_body[8:18]
            if esi_bytes != b"\x00" * 10:
                result["esi"] = ":".join(f"{b:02x}" for b in esi_bytes)
            # Ethernet Tag ID (RFC 7432 Type-1 NLRI layout: RD(8)+ESI(10)+
            # EthTag(4)+Label(3)) -- esdf_toggle.py investigation: this is
            # what distinguishes per-ES EAD (0xFFFFFFFF sentinel, RFC 8584's
            # ES Full Failure signature) from per-EVI EAD (a real tag,
            # confirmed 0 in the generator's build_ead_per_evi calls).
            if evpn_route_type == 1 and len(nlri_body) >= 22:
                result["ethernet_tag"] = struct.unpack("!I", nlri_body[18:22])[0]
    except Exception:
        pass
    return result


def _decode_update_attributes(body):
    """Full path-attribute walk over one BGP UPDATE body. Returns a dict
    with route_action plus every field Layer 4 rules need: route_target,
    route_distinguisher, mac_mobility_seq, evpn_route_type, mac_address,
    ip_prefix, esi, originator_id."""
    result = {
        "route_action": "update", "evpn_route_type": None,
        "route_target": None, "route_distinguisher": None,
        "mac_mobility_seq": None, "mac_address": None, "ip_prefix": None,
        "esi": None, "originator_id": None, "ethernet_tag": None,
        "df_election_ac_df": None,
    }
    if len(body) < 2:
        return result
    wd_len = struct.unpack("!H", body[:2])[0]
    if wd_len > 0:
        result["route_action"] = "withdraw"
    offset = 2 + wd_len
    if offset + 2 > len(body):
        return result
    pa_len = struct.unpack("!H", body[offset:offset + 2])[0]
    attrs_end = offset + 2 + pa_len
    offset += 2
    if wd_len == 0 and attrs_end < len(body):
        result["route_action"] = "advertise"

    while offset < attrs_end and offset + 3 <= len(body):
        flags = body[offset]
        atype = body[offset + 1]
        if flags & 0x10:
            if offset + 4 > len(body):
                break
            alen = struct.unpack("!H", body[offset + 2:offset + 4])[0]
            val_start = offset + 4
        else:
            alen = body[offset + 2]
            val_start = offset + 3
        val = body[val_start:val_start + alen]

        if atype in (14, 15) and len(val) >= 3:
            afi = struct.unpack("!H", val[0:2])[0]
            safi = val[2]
            if afi == 25 and safi == 70:  # L2VPN EVPN
                if atype == 14:  # MP_REACH_NLRI
                    if len(val) > 3:
                        result["route_action"] = "advertise"
                        nh_len = val[3]
                        nlri_off = 4 + nh_len + 1
                        if nlri_off < len(val):
                            rt = val[nlri_off]
                            result["evpn_route_type"] = rt
                            if nlri_off + 1 < len(val):
                                nlri_len = val[nlri_off + 1]
                                nlri_body = val[nlri_off + 2:nlri_off + 2 + nlri_len]
                                result.update(_decode_evpn_nlri(rt, nlri_body))
                else:  # MP_UNREACH_NLRI
                    if len(val) > 3:
                        result["route_action"] = "withdraw"
                        rt = val[3]
                        result["evpn_route_type"] = rt
                        if len(val) > 4:
                            nlri_len = val[4]
                            nlri_body = val[5:5 + nlri_len]
                            result.update(_decode_evpn_nlri(rt, nlri_body))
                    else:
                        result["route_action"] = "end_of_rib"
        elif atype == 9 and len(val) >= 4:  # ORIGINATOR_ID
            result["originator_id"] = ".".join(str(b) for b in val[0:4])
        elif atype == 16 and len(val) >= 8:  # EXTENDED_COMMUNITIES
            ec = _decode_extended_communities(val)
            result["route_target"] = ec["route_target"]
            result["mac_mobility_seq"] = ec["mac_mobility_seq"]
            result["df_election_ac_df"] = ec["df_election_ac_df"]

        offset = val_start + alen
    return result


# ---------------------------------------------------------------------
# BGP message extraction from a reassembled byte stream
# ---------------------------------------------------------------------

def _split_bgp_messages(buf):
    """(msg_type, body, start_offset) for every complete BGP message in
    the reassembled buffer -- works across arbitrarily many original TCP
    segments now that `buf` is a fully reassembled byte stream, not a
    single packet's payload."""
    out = []
    offset = 0
    while offset < len(buf):
        if len(buf) - offset < 19:
            break
        if buf[offset:offset + 16] != b"\xff" * 16:
            break
        length = struct.unpack("!H", buf[offset + 16:offset + 18])[0]
        msg_type = buf[offset + 18]
        if length < 19 or offset + length > len(buf):
            break
        out.append((msg_type, buf[offset + 19:offset + length], offset))
        offset += length
    return out


def _emit_bgp_events(sessions, vantage, ip_to_node):
    events = []
    # per-direction FSM state, to emit SESSION_ESTABLISHED only once per
    # OPEN->KEEPALIVE transition rather than on every subsequent keepalive
    open_pending = set()  # directions that have sent OPEN, awaiting confirmation

    for skey, directions in sessions.items():
        for direction, (buf, ranges) in directions.items():
            src_ip, src_port, dst_ip, dst_port = direction
            src_node = _node_for_ip(ip_to_node, src_ip)
            dst_node = _node_for_ip(ip_to_node, dst_ip)
            # node_involved default: the node that SENT this message --
            # replaces the old "whichever side listens on port 179"
            # heuristic, which was confirmed (fusion.py checkpoint,
            # rr_down_containerkill_rr1_recovered) to misattribute events to
            # the wrong node whenever the affected node happened to be the
            # TCP-initiating side rather than the listener (e.g. RR1 dying
            # sends FIN/NOTIFICATION *from* its own ephemeral-port session
            # leg, which the old rule silently attributed to the far end
            # instead). The sender is a directly meaningful signal for
            # OPEN/NOTIFICATION (whoever decided to (re)connect or tear
            # down) and for a direct, non-reflected UPDATE (a PE always
            # sends its own routes to its own RR, so src_node IS the
            # originating PE there too).
            default_node_involved = src_node

            for msg_type, body, offset in _split_bgp_messages(buf):
                ts = _timestamp_for_offset(ranges, offset)
                if ts is None:
                    continue
                type_name = BGP_TYPE_NAME.get(msg_type, f"UNKNOWN({msg_type})")

                if type_name == "OPEN":
                    open_pending.add(direction)
                    events.append({
                        "timestamp": ts, "source_vantage": vantage,
                        "event_type": "BGP_OPEN", "node_involved": default_node_involved,
                        "protocol_detail": {"src_ip": src_ip, "dst_ip": dst_ip},
                    })
                elif type_name == "KEEPALIVE" and direction in open_pending:
                    open_pending.discard(direction)
                    events.append({
                        "timestamp": ts, "source_vantage": vantage,
                        "event_type": "SESSION_ESTABLISHED", "node_involved": default_node_involved,
                        "protocol_detail": {"src_ip": src_ip, "dst_ip": dst_ip},
                    })
                elif type_name == "UPDATE":
                    attrs = _decode_update_attributes(body)
                    # For UPDATE/WITHDRAWAL specifically, prefer
                    # originator_id when present -- an RFC 4456 field
                    # wire-carried only on REFLECTED updates, stating
                    # unambiguously which PE the route actually came from,
                    # regardless of how many RR hops relayed it since. This
                    # is strictly more reliable than src_node for a
                    # reflected copy (whose src_ip is the relaying RR, not
                    # the true route owner). Falls back to src_node (the
                    # sender) when absent, which is correct for a direct,
                    # non-reflected hop.
                    route_node = _node_for_ip(ip_to_node, attrs["originator_id"]) if attrs["originator_id"] else None
                    node_involved = route_node or default_node_involved
                    events.append({
                        "timestamp": ts, "source_vantage": vantage,
                        "event_type": "BGP_WITHDRAWAL" if attrs["route_action"] == "withdraw" else "BGP_UPDATE",
                        "node_involved": node_involved,
                        "protocol_detail": {
                            "bgp_type": "UPDATE", "route_action": attrs["route_action"],
                            "evpn_route_type": attrs["evpn_route_type"],
                            "route_target": attrs["route_target"],
                            "route_distinguisher": attrs["route_distinguisher"],
                            "mac_mobility_seq": attrs["mac_mobility_seq"],
                            "mac_address": attrs["mac_address"],
                            "ip_prefix": attrs["ip_prefix"],
                            "esi": attrs["esi"],
                            "originator_id": attrs["originator_id"],
                            "ethernet_tag": attrs["ethernet_tag"],
                            "df_election_ac_df": attrs["df_election_ac_df"],
                            "src_ip": src_ip, "dst_ip": dst_ip,
                        },
                    })
                elif type_name == "NOTIFICATION":
                    error_code = body[0] if len(body) >= 1 else None
                    subcode = body[1] if len(body) >= 2 else None
                    events.append({
                        "timestamp": ts, "source_vantage": vantage,
                        "event_type": "BGP_NOTIFICATION", "node_involved": default_node_involved,
                        "protocol_detail": {
                            "bgp_type": "NOTIFICATION", "error_code": error_code,
                            "error_name": NOTIFICATION_ERROR_CODE.get(error_code, f"Unknown({error_code})"),
                            "subcode": subcode, "src_ip": src_ip, "dst_ip": dst_ip,
                        },
                    })
                # ROUTE-REFRESH: no fault-relevant meaning here, not emitted.
    return events


# ---------------------------------------------------------------------
# TCP lifecycle (RST/FIN), BFD, OSPF -- unchanged from the per-packet pass,
# these don't require stream reassembly (their signal is single-packet).
# ---------------------------------------------------------------------

def _parse_tcp_lifecycle_events(pkt, ts, vantage, ip_to_node):
    events = []
    ip = pkt[IP]
    tcp = pkt[TCP]
    if tcp.sport != BGP_PORT and tcp.dport != BGP_PORT:
        return events
    flags = int(tcp.flags)
    src_node = _node_for_ip(ip_to_node, ip.src)
    dst_node = _node_for_ip(ip_to_node, ip.dst)
    # The sender of a FIN/RST is the node whose session state actually
    # changed (it chose to close, or its kernel reset the connection) --
    # not "whichever side happens to listen on port 179", which is a
    # property of the TCP handshake roles, unrelated to which node is
    # affected. Same fix and same rationale as _emit_bgp_events above.
    node_involved = src_node
    if flags & 0x04:
        events.append({
            "timestamp": ts, "source_vantage": vantage, "event_type": "TCP_RESET",
            "node_involved": node_involved,
            "protocol_detail": {"flags": "RST", "src_ip": ip.src, "dst_ip": ip.dst,
                                "sport": int(tcp.sport), "dport": int(tcp.dport)},
        })
    elif flags & 0x01:
        events.append({
            "timestamp": ts, "source_vantage": vantage, "event_type": "TCP_FIN",
            "node_involved": node_involved,
            "protocol_detail": {"flags": "FIN", "src_ip": ip.src, "dst_ip": ip.dst,
                                "sport": int(tcp.sport), "dport": int(tcp.dport)},
        })
    return events


def _parse_bfd_events(pkt, ts, vantage, ip_to_node, bfd_state):
    events = []
    if not pkt.haslayer(BFD):
        return events
    ip = pkt[IP]
    bfd = pkt[BFD]
    key = tuple(sorted((ip.src, ip.dst)))
    state = int(bfd.sta)
    prev = bfd_state.get(key)
    if prev is None or prev != state:
        bfd_state[key] = state
        src_node = _node_for_ip(ip_to_node, ip.src)
        events.append({
            "timestamp": ts, "source_vantage": vantage, "event_type": "BFD_STATE_CHANGE",
            "node_involved": src_node,
            "protocol_detail": {
                "state": BFD_STATE_NAME.get(state, f"Unknown({state})"),
                "diag": int(bfd.diag), "src_ip": ip.src, "dst_ip": ip.dst,
            },
        })
    return events


def _parse_ospf_events(pkt, ts, vantage, ip_to_node, ospf_neighbors):
    events = []
    if not pkt.haslayer(OSPF_Hdr) or pkt[IP].proto != OSPF_PROTO:
        return events
    ip = pkt[IP]
    src_node = _node_for_ip(ip_to_node, ip.src)
    if pkt.haslayer(OSPF_Hello):
        hello = pkt[OSPF_Hello]
        current = frozenset(hello.neighbors) if hasattr(hello, "neighbors") else frozenset()
        prev = ospf_neighbors.get(ip.src)
        if prev is not None and prev != current:
            lost = prev - current
            gained = current - prev
            events.append({
                "timestamp": ts, "source_vantage": vantage, "event_type": "OSPF_NEIGHBOR_CHANGE",
                "node_involved": src_node,
                "protocol_detail": {"lost_neighbors": sorted(lost), "gained_neighbors": sorted(gained),
                                     "src_ip": ip.src},
            })
        ospf_neighbors[ip.src] = current
    return events


def parse_vantage_pcap(pcap_path, vantage_id, topo):
    ip_to_node = _ip_to_node(topo)
    packets = rdpcap(pcap_path)
    events = []

    sessions = _reassemble_bgp_sessions(packets)
    events.extend(_emit_bgp_events(sessions, vantage_id, ip_to_node))

    bfd_state = {}
    ospf_neighbors = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ts = float(pkt.time)
        if pkt.haslayer(TCP):
            events.extend(_parse_tcp_lifecycle_events(pkt, ts, vantage_id, ip_to_node))
        if pkt.haslayer(BFD):
            events.extend(_parse_bfd_events(pkt, ts, vantage_id, ip_to_node, bfd_state))
        if pkt[IP].proto == OSPF_PROTO:
            events.extend(_parse_ospf_events(pkt, ts, vantage_id, ip_to_node, ospf_neighbors))

    events.sort(key=lambda e: e["timestamp"])
    return events


def parse_vantages(vantage_pcap_map, topology_path=None):
    topo = load_topology(topology_path) if topology_path else load_topology()
    result = {}
    for vantage_id, pcap_path in vantage_pcap_map.items():
        result[vantage_id] = parse_vantage_pcap(pcap_path, vantage_id, topo)
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: vantage_parser.py <scenario_dir>")
        sys.exit(1)
    scenario_dir = sys.argv[1]
    vmap = {
        "RR1": os.path.join(scenario_dir, "rr1.pcap"),
        "RR2": os.path.join(scenario_dir, "rr2.pcap"),
    }
    streams = parse_vantages(vmap)
    for vantage, events in streams.items():
        print(f"=== {vantage}: {len(events)} events ===")
        for e in events:
            print(f"  {_iso(e['timestamp'])} {e['event_type']:20s} node={e['node_involved']} {e['protocol_detail']}")
