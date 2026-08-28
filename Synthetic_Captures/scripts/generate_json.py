"""Generate JSON ground-truth files for every PCAP in the synthcap output directory.

Each .pcap file gets a matching .json file with:
  - scenario metadata (fault type, affected device, recovery)
  - ground truth label for ML training
  - expected BGP event sequence for Ciena verification
  - topology parameters used during generation
  - frame_counts: actual counts read from the pcap (total frames, BGP message
    type breakdown including UPDATE advertisements vs withdrawals)

Run from the synthcap root:
    python scripts/generate_json.py

Output: one .json per .pcap in the same folder, e.g.
    output/section2_labelled/link_down_fast_recovery_pe1.json
"""

import json
import struct
from pathlib import Path

# ---------------------------------------------------------------------------
# Fast binary pcap parser — no scapy required
# ---------------------------------------------------------------------------

_BGP_MARKER = b'\xff' * 16


def _parse_update_type(pkt: bytes, bgp_start: int):
    """Return (is_advertisement, is_withdrawal) for a BGP UPDATE message.

    Checks for:
      - IPv4 unfeasible routes (Withdrawn Routes Length > 0) → withdrawal
      - Path attribute type 14 MP_REACH_NLRI                 → advertisement
      - Path attribute type 15 MP_UNREACH_NLRI               → withdrawal
    """
    pos = bgp_start + 19  # skip 16-byte marker + 2-byte length + 1-byte type

    if pos + 2 > len(pkt):
        return False, False

    # Unfeasible routes length (IPv4 withdrawals)
    unfeasible_len = struct.unpack('!H', pkt[pos:pos + 2])[0]
    has_ipv4_withdraw = unfeasible_len > 0
    pos += 2 + unfeasible_len

    if pos + 2 > len(pkt):
        return False, has_ipv4_withdraw

    # Path attributes block
    path_attr_len = struct.unpack('!H', pkt[pos:pos + 2])[0]
    pos += 2
    end_attrs = min(pos + path_attr_len, len(pkt))

    has_mp_reach = False
    has_mp_unreach = False

    while pos + 3 <= end_attrs:
        flags = pkt[pos]
        type_code = pkt[pos + 1]
        extended = bool(flags & 0x10)  # EXTENDED-LENGTH bit

        if extended:
            if pos + 4 > end_attrs:
                break
            attr_len = struct.unpack('!H', pkt[pos + 2:pos + 4])[0]
            pos += 4
        else:
            attr_len = pkt[pos + 2]
            pos += 3

        if type_code == 14:   # MP_REACH_NLRI
            has_mp_reach = True
        elif type_code == 15:  # MP_UNREACH_NLRI
            has_mp_unreach = True

        if has_mp_reach and has_mp_unreach:
            break

        pos += attr_len

    # IPv4 NLRI present after path attributes = advertisement (rare in EVPN)
    has_ipv4_nlri = end_attrs < len(pkt) and not has_mp_unreach and not has_mp_reach

    is_advertisement = has_mp_reach or has_ipv4_nlri
    is_withdrawal = has_ipv4_withdraw or has_mp_unreach

    return is_advertisement, is_withdrawal


def count_pcap_stats(pcap_path: Path) -> dict:
    """Parse a pcap file and return exact BGP message-type counts.

    Returns a dict with keys:
      total_frames, non_bgp_tcp_frames,
      bgp_open, bgp_keepalive,
      bgp_update, bgp_update_advertisements, bgp_update_withdrawals,
      bgp_notification, bgp_route_refresh
    """
    counts = {
        'total_frames': 0,
        '_frames_with_bgp': 0,
        'bgp_open': 0,
        'bgp_keepalive': 0,
        'bgp_update': 0,
        'bgp_update_advertisements': 0,
        'bgp_update_withdrawals': 0,
        'bgp_notification': 0,
        'bgp_route_refresh': 0,
    }

    try:
        with open(pcap_path, 'rb') as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                return _finalise_counts(counts)
            magic = struct.unpack('<I', hdr[:4])[0]
            big_endian = (magic == 0xd4c3b2a1)

            while True:
                rec = f.read(16)
                if len(rec) < 16:
                    break
                incl_len = struct.unpack('>I' if big_endian else '<I', rec[8:12])[0]
                pkt = f.read(incl_len)
                counts['total_frames'] += 1

                pos = pkt.find(_BGP_MARKER)
                if pos == -1:
                    continue

                frame_has_bgp = False
                while pos != -1 and pos + 19 <= len(pkt):
                    msg_len = struct.unpack('!H', pkt[pos + 16:pos + 18])[0]
                    msg_type = pkt[pos + 18]

                    if 1 <= msg_type <= 5 and msg_len >= 19:
                        frame_has_bgp = True
                        if msg_type == 1:
                            counts['bgp_open'] += 1
                        elif msg_type == 2:
                            counts['bgp_update'] += 1
                            is_adv, is_with = _parse_update_type(pkt, pos)
                            if is_adv:
                                counts['bgp_update_advertisements'] += 1
                            if is_with:
                                counts['bgp_update_withdrawals'] += 1
                        elif msg_type == 3:
                            counts['bgp_notification'] += 1
                        elif msg_type == 4:
                            counts['bgp_keepalive'] += 1
                        elif msg_type == 5:
                            counts['bgp_route_refresh'] += 1

                        pos = pkt.find(_BGP_MARKER, pos + msg_len)
                    else:
                        pos = pkt.find(_BGP_MARKER, pos + 1)

                if frame_has_bgp:
                    counts['_frames_with_bgp'] += 1

    except (IOError, OSError):
        pass

    return _finalise_counts(counts)


def _finalise_counts(counts: dict) -> dict:
    counts['non_bgp_tcp_frames'] = counts['total_frames'] - counts.pop('_frames_with_bgp', 0)
    return counts

# ---------------------------------------------------------------------------
# Topology constants (from default_topology.yaml)
# ---------------------------------------------------------------------------

# Device → link_identity set (derived from IP_TO_NODE + LINK_IDENTITY in extract_features.py)
# Links: 1:PE1-RR1  2:PE2-RR1  3:PE3-RR1  4:PE4-RR2  5:PE5-RR2
#        6:RR1-RR2  7:PE4-RR1  8:PE5-RR1  9:PE1-RR2  10:PE2-RR2  11:PE3-RR2
DEVICE_TO_LINKS = {
    "PE1": [1, 9],
    "PE2": [2, 10],
    "PE3": [3, 11],
    "PE4": [4, 7],
    "PE5": [5, 8],
    "RR1": [1, 2, 3, 6, 7, 8],
    "RR2": [4, 5, 6, 9, 10, 11],
}


def _affected_link_ids(affected_device: str) -> list[int]:
    links: set[int] = set()
    for dev in [d.strip() for d in affected_device.split(",")]:
        links |= set(DEVICE_TO_LINKS.get(dev, []))
    return sorted(links)


# Topology-id keys match Path(config_path).stem for the two real config
# files this project uses (configs/default_topology.yaml,
# configs/3rr_topology.yaml).
TOPOLOGY_ID_2RR = "default_topology"
TOPOLOGY_ID_3RR = "3rr_topology"

TOPOLOGY_2RR = {
    "as_number": 65001,
    "hold_timer_seconds": 30,
    "keepalive_timer_seconds": 10,
    "capture_vantage": "RR1",
    "route_reflectors": ["RR1", "RR2"],
    "pe_nodes": ["PE1", "PE2", "PE3", "PE4", "PE5"],
    "multihomed_esi_pair": ["PE1", "PE2"],
    "esi": "00:11:22:33:44:55:66:77:88:01",
    "evpn_vni": 100,
    "route_target": "65001:100",
    "transport": "IPv6",
    "encapsulation": "SRv6"
}

# TOPOLOGY_3RR: values for configs/3rr_topology.yaml (10 PEs, 3 RRs
# full-mesh, 4-3-3 PE split). No multihomed_esi_pair/esi default -- 3RR
# has TWO ES pairs (PE3/PE4 esi ...02, PE6/PE7 esi ...03), so every
# 3RR-reachable entry that needs these fields sets them explicitly via
# the per-entry override below.
TOPOLOGY_3RR = {
    "as_number": 65001,
    "hold_timer_seconds": 30,
    "keepalive_timer_seconds": 10,
    "capture_vantage": "RR1",
    "route_reflectors": ["RR1", "RR2", "RR3"],
    "pe_nodes": ["PE1", "PE2", "PE3", "PE4", "PE5", "PE6", "PE7", "PE8", "PE9", "PE10"],
    "evpn_vni": 100,
    "route_target": "65001:100",
    "transport": "IPv6",
    "encapsulation": "SRv6"
}

TOPOLOGY = TOPOLOGY_2RR


def _by_topology(value_2rr, value_3rr):
    """A CATALOGUE field whose value differs by which topology built the
    pcap. Used where a shared CATALOGUE key is reachable under both
    topologies with a different answer each time
    (esdf_toggle_full_failure_{no_,}recovery, esdf_toggle_slow)."""
    return {TOPOLOGY_ID_2RR: value_2rr, TOPOLOGY_ID_3RR: value_3rr}


# PE3/PE4 and PE6/PE7 are configs/3rr_topology.yaml's two ES pairs
# (esi ...02 and ...03) and are only reachable under the 3RR topology.
_3RR_ESI_BY_PE = {
    3: (["PE3", "PE4"], "00:11:22:33:44:55:66:77:88:02"),
    4: (["PE3", "PE4"], "00:11:22:33:44:55:66:77:88:02"),
    6: (["PE6", "PE7"], "00:11:22:33:44:55:66:77:88:03"),
    7: (["PE6", "PE7"], "00:11:22:33:44:55:66:77:88:03"),
}


def _make_pe(section, fault_type, ground_truth, pe_i, recovery, recovery_time_seconds,
             description, event_key, **kw):
    """Same as _make(), plus the correct 3RR-only topology override for
    PE3/PE4/PE6/PE7."""
    result = _make(section, fault_type, ground_truth, f"PE{pe_i}",
                    recovery, recovery_time_seconds, description, event_key, **kw)
    override = _3RR_ESI_BY_PE.get(pe_i)
    if override:
        pair, esi = override
        result = {**result, "topology": {**TOPOLOGY_3RR, "multihomed_esi_pair": pair, "esi": esi}}
    return result

# Warmup before fault injection (5 * hold_timer = 150s; actual code uses 5*60=300s)
FAULT_INJECT_TIME = 300

# ---------------------------------------------------------------------------
# Expected BGP event sequences per fault type
# ---------------------------------------------------------------------------

EVENTS = {
    "normal": [
        "TCP SYN / SYN-ACK / ACK handshake for each PE-RR session",
        "BGP OPEN from PE and RR with EVPN capabilities",
        "BGP KEEPALIVE from both sides confirming OPEN",
        "BGP UPDATE Type 3 IMET route per PE per VNI",
        "BGP UPDATE Type 1 EAD and Type 4 ES routes for PE1 and PE2 (shared ESI)",
        "BGP UPDATE Type 2 MAC/IP routes from each PE",
        "BGP UPDATE Type 5 IP Prefix routes from some PEs",
        "Periodic KEEPALIVE every 10 seconds on all sessions throughout capture"
    ],
    "mac_mobility": [
        "Normal session establishment and warmup",
        "New-owner PE advertises a Type 2 MAC/IP UPDATE for a moved MAC with "
        "MAC Mobility extended community (sequence N+1)",
        "Old-owner PE sends a Type 2 WITHDRAW for the same MAC 100-500ms later",
        "Brief pause, then repeats for 3-6 total move events, alternating direction",
        "Classified as Normal traffic — not a fault"
    ],
    "connection_collision": [
        "Two concurrent TCP SYNs, one from each peer, on the affected PE-RR session",
        "BGP OPEN exchanged on both connections",
        "BGP NOTIFICATION CEASE with subcode Connection Collision Resolution on "
        "the connection initiated by the higher-Router-ID peer",
        "Surviving connection proceeds through KEEPALIVE to Established",
        "All other sessions establish normally",
        "Classified as Normal traffic — not a fault"
    ],
    "link_down": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: TCP RST from affected PE session (abrupt link drop)",
        "BGP UPDATE WITHDRAW messages for routes previously advertised by affected PE",
        "Silence on affected session (no KEEPALIVE from that PE) for recovery window",
        "RECOVERY: TCP SYN from affected PE (reconnection attempt)",
        "BGP OPEN exchange on reconnected session",
        "BGP UPDATE re-advertisement of routes by affected PE",
        "KEEPALIVE exchange resumes normally"
    ],
    "link_down_no_recovery": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: TCP RST from affected PE session (abrupt link drop)",
        "BGP UPDATE WITHDRAW for affected PE routes",
        "No further traffic from affected PE for remainder of capture",
        "Other sessions continue normal KEEPALIVE"
    ],
    "link_down_hold_timer": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: KEEPALIVE stops from affected PE (hold timer expiry scenario)",
        "Hold timer expires (~30s after last KEEPALIVE)",
        "BGP NOTIFICATION HOLD TIMER EXPIRED from RR to affected PE",
        "TCP FIN / RST closing the session",
        "BGP UPDATE WITHDRAW for routes from affected PE",
        "No reconnection in capture window"
    ],
    "link_down_rst_slow": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: TCP RST from affected PE session (abrupt link drop)",
        "BGP UPDATE WITHDRAW messages for routes previously advertised by affected PE",
        "Long silence on affected session (2-5 minutes) before reconnection",
        "RECOVERY: TCP SYN from affected PE (reconnection attempt)",
        "BGP OPEN exchange on reconnected session",
        "BGP UPDATE re-advertisement of routes by affected PE",
        "KEEPALIVE exchange resumes normally"
    ],
    "link_down_hold_timer_fast": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: KEEPALIVE stops from affected PE (hold timer expiry scenario)",
        "Hold timer expires (~30s after last KEEPALIVE)",
        "BGP NOTIFICATION HOLD TIMER EXPIRED from RR to affected PE",
        "BGP UPDATE WITHDRAW for routes from affected PE",
        "Silence for 20-30s",
        "RECOVERY: TCP SYN, BGP OPEN, route re-advertisement, KEEPALIVE resumes"
    ],
    "link_down_reflected": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions "
        "visible at the vantage RR, including the RR-RR session",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE (no direct session at this vantage) fails behind its "
        "home RR; the home RR reflects a WITHDRAW for that PE's routes onto the "
        "RR-RR session -- the only observable signature of this fault at the vantage",
        "Silence on the affected PE's reflected presence for the recovery window",
        "RECOVERY: home RR reflects the PE's route set back onto the RR-RR session",
        "KEEPALIVE exchange resumes normally"
    ],
    "link_down_reflected_no_recovery": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions "
        "visible at the vantage RR, including the RR-RR session",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE (no direct session at this vantage) fails behind its "
        "home RR; the home RR reflects a WITHDRAW for that PE's routes onto the "
        "RR-RR session -- the only observable signature of this fault at the vantage",
        "No further reflected activity for this PE for the remainder of capture"
    ],
    "link_down_graceful_restart": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE's session drops abruptly (TCP RST) with NO EVPN "
        "WITHDRAWs -- routes are kept as stale, not withdrawn (the key "
        "distinguishing feature from ordinary Link Down)",
        "2-8 second process-restart gap",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart capability "
        "(Restart State bit set, restart_time=120, EVPN AFI/SAFI Forwarding "
        "State bit set)",
        "KEEPALIVE exchange confirms the new session",
        "Affected PE re-advertises all its routes on the recovered session",
        "End-of-RIB marker sent once re-advertisement completes"
    ],
    "link_down_graceful_restart_reflected": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions "
        "visible at the vantage RR, including the RR-RR session",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE (no direct session at this vantage) restarts behind "
        "its home RR; no WITHDRAW is reflected (routes kept as stale, not "
        "withdrawn) -- the outage itself produces no observable packets at "
        "this vantage",
        "2-8 second process-restart gap",
        "RECOVERY: home RR reflects the PE's full route set back onto the "
        "RR-RR session, the observable signal that resync completed"
    ],
    "link_down_graceful_restart_notified": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE's session torn down via BGP NOTIFICATION "
        "(Administrative Reset), not a bare RST -- still treated as graceful "
        "(NO EVPN WITHDRAWs, routes kept as stale) because both sides "
        "negotiated the RFC 8538 Notification (N) bit",
        "2-8 second process-restart gap",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart capability "
        "(Restart State bit AND Notification bit both set)",
        "KEEPALIVE exchange confirms the new session",
        "Affected PE re-advertises all its routes on the recovered session",
        "End-of-RIB marker sent once re-advertisement completes"
    ],
    "link_down_graceful_restart_timeout": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE's session drops abruptly (TCP RST) with NO EVPN "
        "WITHDRAWs -- routes kept as stale per the Graceful Restart contract",
        "No reconnection attempt is ever observed",
        "Restart Time (120s) elapses with the session still down",
        "RFC 4724 SS4.2 stale-route flush: an explicit BGP UPDATE WITHDRAW "
        "for the affected PE's previously-stale routes fires once the "
        "restart timer expires -- deliberately delayed to the ~120s mark, "
        "not immediate like an ordinary no-recovery Link Down",
        "No further reconnection for the remainder of the capture"
    ],
    "link_down_hard_reset": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions "
        "-- affected PE's session negotiates the RFC 8538 Notification (N) bit "
        "on this original OPEN exchange",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE's session torn down via BGP NOTIFICATION "
        "(Cease / Hard Reset, subcode 9) -- RFC 8538 SS4's explicit "
        "override of the negotiated graceful handling for this teardown",
        "Despite N having been negotiated, a full immediate BGP UPDATE "
        "WITHDRAW appears (Type 2/3, plus Type 1/4 if the PE is "
        "multihomed) -- routes are NOT held stale, unlike every other "
        "Graceful-Restart-family class",
        "20-30 second silence",
        "RECOVERY: ordinary reconnect (TCP + OPEN + KEEPALIVE), not "
        "restart-flagged -- this was never actually a graceful restart",
        "Affected PE re-advertises all its routes on the recovered session"
    ],
    "link_down_graceful_restart_notified_holdtimer": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions "
        "-- affected PE's session negotiates the RFC 8538 Notification (N) bit "
        "on this original OPEN exchange",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "Hold-timer-style silence window (~30-40s) on the affected session "
        "while other sessions keep their normal cadence -- unlike the "
        "abrupt Cease/Administrative-Reset variant",
        "FAULT: Hold Timer Expired NOTIFICATION fires after the silence "
        "window -- still treated as graceful (NO EVPN WITHDRAWs, routes "
        "kept as stale) because both sides negotiated the N bit",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart "
        "capability (Restart State bit AND Notification bit both set)",
        "KEEPALIVE exchange confirms the new session",
        "Affected PE re-advertises all its routes on the recovered session",
        "End-of-RIB marker sent once re-advertisement completes"
    ],
    "link_down_simultaneous": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: TCP RST on PE1 and PE2 sessions within milliseconds of each other",
        "BGP UPDATE WITHDRAW for routes from both PE1 and PE2",
        "Silence on both sessions simultaneously",
        "RECOVERY: Both PEs reconnect, OPEN exchange, routes re-advertised"
    ],
    "rr_down": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all PE-RR sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: All PE sessions to affected RR drop simultaneously (TCP RST burst)",
        "BGP UPDATE WITHDRAW for all routes reflected by affected RR",
        "Silence on all affected PE sessions simultaneously",
        "RECOVERY: All PEs reconnect to surviving RR, OPEN exchange, routes re-advertised"
    ],
    "rr_down_no_recovery": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all PE-RR sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: All PE sessions to affected RR drop simultaneously (TCP RST burst)",
        "BGP UPDATE WITHDRAW for all routes reflected by affected RR",
        "No reconnection on any affected session for remainder of capture"
    ],
    "rr_down_both": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: RR1 sessions drop first, followed by RR2 sessions within seconds",
        "Full session loss across entire topology",
        "BGP UPDATE WITHDRAW flood for all routes",
        "No recovery in capture window"
    ],
    "rr_down_hold_timer": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all PE-RR and RR-RR sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: RR1 stops sending KEEPALIVE to RR2 (silent link degradation)",
        "Hold timer silence (~30s) — only PE-to-RR2 sessions continue KEEPALIVE",
        "Hold timer expires — RR2 sends BGP NOTIFICATION HOLD TIMER EXPIRED and closes session",
        "RECOVERY: RR1 reconnects, full BGP OPEN exchange, full route re-sync for all PEs",
        "KEEPALIVE resumes on all sessions"
    ],
    "rr_down_graceful_restart": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all PE-RR and RR-RR sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: RR-RR session drops abruptly (TCP RST) with NO PE route "
        "WITHDRAWs -- reflected routes are kept as stale, not withdrawn (the "
        "key distinguishing feature from ordinary RR Down)",
        "2-8 second process-restart gap",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart capability "
        "(Restart State bit set) on the restarting RR's OPEN only",
        "KEEPALIVE exchange confirms the new session",
        "Restarting RR's full PE route set is re-reflected onto the RR-RR session",
        "End-of-RIB marker sent on the RR-RR session once resync completes"
    ],
    "rr_down_graceful_restart_notified": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all PE-RR and RR-RR sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: RR-RR session torn down via BGP NOTIFICATION (Administrative "
        "Reset), not a bare RST -- still treated as graceful (NO PE route "
        "WITHDRAWs) because both sides negotiated the RFC 8538 Notification "
        "(N) bit",
        "2-8 second process-restart gap",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart capability "
        "(Restart State bit AND Notification bit both set) on the "
        "restarting RR's OPEN only",
        "KEEPALIVE exchange confirms the new session",
        "Restarting RR's full PE route set is re-reflected onto the RR-RR session",
        "End-of-RIB marker sent on the RR-RR session once resync completes"
    ],
    "rr_down_graceful_restart_timeout": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all PE-RR and RR-RR sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: RR-RR session drops abruptly (TCP RST) with NO PE route "
        "WITHDRAWs -- reflected routes kept as stale per the Graceful "
        "Restart contract",
        "No reconnection attempt is ever observed",
        "Restart Time (120s) elapses with the RR-RR session still down",
        "RFC 4724 SS4.2 stale-route flush: an explicit BGP UPDATE WITHDRAW "
        "for the affected RR's clients' previously-stale routes fires once "
        "the restart timer expires, toward the vantage RR's own clients -- "
        "deliberately delayed to the ~120s mark",
        "No further reconnection for the remainder of the capture"
    ],
    "rr_down_graceful_restart_notified_holdtimer": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all "
        "PE-RR and RR-RR sessions -- RR-RR session negotiates the RFC 8538 "
        "Notification (N) bit on this original OPEN exchange",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "Hold-timer-style silence window (~30-40s) on the RR-RR session "
        "while PE-RR sessions keep their normal cadence -- unlike the "
        "abrupt Cease/Administrative-Reset variant",
        "FAULT: Hold Timer Expired NOTIFICATION fires after the silence "
        "window -- still treated as graceful (NO PE route WITHDRAWs) "
        "because both sides negotiated the N bit",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart "
        "capability (Restart State bit AND Notification bit both set) on "
        "the restarting RR's OPEN only",
        "KEEPALIVE exchange confirms the new session",
        "Restarting RR's full PE route set is re-reflected onto the RR-RR session",
        "End-of-RIB marker sent on the RR-RR session once resync completes"
    ],
    "intermittent_rr": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT CYCLE 1: RR1-RR2 session drops (TCP RST), 15-25s silence, reconnect + full route sync",
        "Brief stable period between cycles",
        "FAULT CYCLE 2: RR1-RR2 session drops again, reconnect + full route sync",
        "FAULT CYCLE 3: RR1-RR2 session drops a third time, reconnect + full route sync",
        "Post-fault normal KEEPALIVE traffic on all sessions"
    ],
    "esdf_toggle": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "Initial BGP UPDATE Type 1 EAD per-ES and per-EVI and Type 4 ES routes from PE1 and PE2",
        "FAULT: BGP UPDATE WITHDRAW for Type 1 A-D per ES route from affected PE "
        "(RFC 7432 SS8.2 mass-withdraw trigger)",
        "Burst of Type 2 MAC/IP WITHDRAW messages (MAC mobility triggered)",
        "DF election re-run on surviving PE (Type 4 ES route follows passively "
        "as a consequence, not as the trigger)",
        "RECOVERY: BGP UPDATE re-advertisement of EAD and ES routes from affected PE",
        "Type 2 MAC/IP routes re-advertised with updated sequence number"
    ],
    "ld_triggers_esdf": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "ROOT CAUSE: affected PE's session drops abruptly (TCP RST); "
        "Type 2/3 routes withdrawn to other sessions",
        "CONSEQUENCE (2-8s later): ESI peer withdraws its Type 1 A-D per ES "
        "route (RFC 7432 SS8.2 mass-withdraw trigger) -- DF re-election "
        "triggered by the co-PE's failure, not an independent fault. Type 4 "
        "ES route follows passively as a consequence, not as the trigger.",
        "RECOVERY: affected PE reconnects and re-advertises Type 2/3 routes first",
        "THEN peer PE re-advertises its Type 1 A-D per ES route -- DF "
        "reversion, same causal ordering as the fault"
    ],
    "ld_esdf_overlap": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT 1: PE1 link down (TCP RST), Type 2/3 routes withdrawn, no recovery",
        "FAULT 2 (3-10s later, overlapping): PE2 ES/DF toggle -- independent "
        "of PE1's fault -- withdraws Type 1/4 routes then re-advertises "
        "after 10-20s",
        "Two independent faults on the two multihomed peers, genuinely "
        "overlapping in time"
    ],
    "ld_rt_overlap": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT 1: PE2 link down via hold-timer expiry (silence, then "
        "NOTIFICATION Hold Timer Expired), recovers with full re-advertisement",
        "FAULT 2 (3-10s later, overlapping): PE3 advertises routes with wrong "
        "Route Target, persists for remainder of capture (no recovery)",
        "Two independent faults with different mechanisms and different "
        "recovery outcomes, overlapping in time"
    ],
    "rr_then_ld": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT 1: RR2's session to RR1 drops (TCP RST), 25-30s silence, "
        "reconnect and full route re-sync -- completes fully",
        "Stable period (60-180s) with normal churn after Fault 1 fully resolves",
        "FAULT 2 (sequential, independent): PE1 link down (TCP RST), Type "
        "2/3 routes withdrawn, no recovery for remainder of capture",
        "Two independent faults occurring one after the other, not overlapping"
    ],
    "esdf_toggle_no_recovery": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "Initial Type 1 EAD and Type 4 ES routes from PE1 and PE2",
        "FAULT: BGP UPDATE WITHDRAW for all EAD and ES routes from affected PE",
        "MAC/IP WITHDRAW burst, DF election on surviving PE",
        "No re-advertisement from affected PE for remainder of capture"
    ],
    "esdf_toggle_repeated": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: 3 to 4 cycles of EAD/ES WITHDRAW followed by re-advertisement, "
        "within a fixed 60-second window",
        "Each cycle's down period lasts 5 to 12 seconds, at ordinary "
        "(not accelerated) per-toggle timing -- cycle count, not speed, is "
        "what distinguishes this variant",
        "Repeated MAC/IP WITHDRAW and re-advertise per cycle",
        "DF election runs multiple times on both PEs"
    ],
    "esdf_toggle_slow": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: EAD/ES WITHDRAW from affected PE",
        "Long silence before any recovery (>60 seconds)",
        "Slow re-advertisement of EAD and ES routes"
    ],
    "esdf_toggle_type1_evi": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: BGP UPDATE WITHDRAW for the affected PE's Type-1 per-EVI EAD route "
        "(RFC 8584's second DF-election trigger type)",
        "DF election re-run in response to the Type-1 per-EVI withdrawal itself, "
        "not a Type-4 ES-route change",
        "RECOVERY: BGP UPDATE re-advertisement of the per-EVI EAD route from the "
        "affected PE after 10-20s"
    ],
    "esdf_toggle_ac_state": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: affected PE re-advertises its Type-4 ES route carrying a DF "
        "Election Extended Community (RFC 8584 SS2.2) with the AC-DF capability "
        "bit cleared -- local AC down. No route is withdrawn at any point.",
        "RECOVERY: affected PE re-advertises the same Type-4 ES route with the "
        "AC-DF capability bit set again after 10-20s -- local AC up"
    ],
    "rt_misconfig": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: Affected PE sends BGP UPDATE with wrong Route Target in extended community",
        "Routes from affected PE are received by RR but silently not reflected (wrong RT)",
        "Sessions remain UP throughout (no NOTIFICATION, no RST)",
        "Normal KEEPALIVE continues on all sessions",
        "No route withdrawals visible at capture vantage",
        "Silent traffic black hole condition"
    ],
    "rt_misconfig_recovery": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: Affected PE sends routes with wrong RT, silently dropped",
        "Sessions remain UP throughout",
        "RECOVERY: Affected PE re-advertises routes with correct RT after ~120s",
        "Routes now accepted and reflected normally"
    ],
    "rt_misconfig_es_import": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: Affected PE sends its Type-4 ES route with wrong RT in extended community",
        "ES-Import RT matching with the multihomed peer breaks -- the peer "
        "cannot discover the shared ESI, breaking multi-homing/DF election "
        "itself (not just a blackholed MAC/IP route)",
        "Type-2 MAC/IP routes from the same PE remain correctly RT'd and are "
        "unaffected",
        "Sessions remain UP throughout (no NOTIFICATION, no RST)",
        "Persistent -- no correction ever appears"
    ],
    "rt_misconfig_es_import_recovery": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: Affected PE's Type-4 ES route sent with wrong RT, breaking "
        "ES-Import matching with the multihomed peer",
        "Type-2 traffic on the same PE remains correctly RT'd",
        "Sessions remain UP throughout",
        "RECOVERY: Affected PE re-advertises the ES route with correct RT after ~120s"
    ],
    "mac_mobility_rapid": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: BGP UPDATE WITHDRAW of the MAC/IP route from the old-owner PE",
        "BGP UPDATE ADVERTISE of the same MAC/IP route from the new-owner PE, "
        "2.0s later, with an incremented RFC 7432 SS15 MAC Mobility sequence number",
        "Single move event -- withdraw always precedes advertise"
    ],
    "mac_mobility_repeated": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: 3-6 WITHDRAW-then-ADVERTISE move cycles for the same MAC within "
        "one capture, each 2.0s apart, 10-20s between successive flap starts",
        "MAC Mobility sequence number increments monotonically across the whole "
        "capture (never reset per flap)",
        "Ownership ping-pongs between the two PEs on every flap"
    ],
    "rd_collision": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: PE3 sends a Type-2 MAC/IP BGP UPDATE using PE1's Route "
        "Distinguisher instead of its own -- identical RD, different MAC/IP",
        "Route-key collision (RD+MAC+IP is the Type-2 route key) -- a real "
        "receiver's best-path selection would treat both PEs' advertisements "
        "as competing paths for the same route and silently mask one",
        "Sessions remain UP throughout (no NOTIFICATION, no RST, no withdrawal)",
        "Silent fault -- may include a recovery variant where PE3's RD is "
        "corrected back to its own after ~120s"
    ],
    "esdf_full_failure": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: PE1 withdraws its Type-1 A-D per ES route for the shared ESI",
        "~150-280ms later: PE2 also withdraws its Type-1 A-D per ES route "
        "for the same ESI -- no surviving DF candidate remains during this "
        "window. Type 4 (ES route) follows passively as a consequence, not "
        "as the trigger.",
        "RECOVERY (if applicable): after 10-20s silence, PE1 re-advertises "
        "its A-D per ES route, then PE2 re-advertises together -- DF "
        "re-elected normally. No-recovery variant: neither PE re-advertises."
    ],
    "cascade_rr_esdf": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT 1: RR session drops (TCP RST) triggering session loss",
        "FAULT 2 CASCADE: Multi-homed PEs detect loss of reflected routes and re-elect DF",
        "Burst of EAD/ES WITHDRAW followed by re-advertisement from PE1 and PE2",
        "Overlapping fault signals: simultaneous session drop AND ES/DF churn"
    ],
    "cascade_link_rt": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT 1: PE link drops (TCP RST), session goes down",
        "FAULT 2 CASCADE: Misconfigured RT on second PE causes silent route drop",
        "Session-level fault + application-level fault in same capture window"
    ],
    "intermittent_link": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: Repeated link flap cycles (down/up/down/up) every 30 to 60 seconds",
        "Each flap: TCP RST, WITHDRAW burst, short silence, TCP SYN, OPEN, re-advertise",
        "Pattern continues multiple times within capture window"
    ],
    "session_flap": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: BGP session tears down and reconnects multiple times",
        "Each flap: NOTIFICATION CEASE or TCP RST, silence, reconnect, OPEN, routes",
        "Session instability pattern distinguishable from single link down"
    ],
    "slow_degradation": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "FAULT: KEEPALIVE intervals gradually increase beyond negotiated 10s",
        "Jitter in KEEPALIVE timing grows progressively",
        "Session eventually drops when hold timer (~30s) expires",
        "BGP NOTIFICATION HOLD TIMER EXPIRED before session close"
    ],
    "mid_session_link_down": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "Longer normal traffic window (~10 minutes of established session activity)",
        "FAULT: Link drops mid-session with established MAC and prefix table",
        "Large WITHDRAW burst due to populated route table at time of fault",
        "Recovery window with full re-synchronisation of route table"
    ],
    "planned_maintenance": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "GRACEFUL SHUTDOWN: BGP NOTIFICATION CEASE with subcode Administrative Shutdown",
        "TCP FIN / FIN-ACK clean close (not RST)",
        "No route WITHDRAW burst (graceful cessation)",
        "Session does not reconnect (planned maintenance window)"
    ],
    "node_removal": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on all sessions",
        "KEEPALIVE and route UPDATE traffic during normal warmup phase (~300s)",
        "GRACEFUL: BGP NOTIFICATION CEASE Administrative Shutdown from removed PE",
        "TCP FIN clean close",
        "Remaining topology continues without the removed node",
        "No session from removed PE for remainder of capture"
    ],
    "unseen_topology": [
        "TCP SYN / SYN-ACK / ACK handshake and BGP OPEN exchange on known sessions",
        "New PE (PE6) initiates TCP SYN and BGP OPEN mid-capture",
        "New session established with EVPN capabilities",
        "PE6 advertises IMET, EAD, MAC/IP routes for first time",
        "Tests model generalisation to topology nodes not seen during training"
    ],
    "as_misconfig": [
        "TCP SYN / SYN-ACK / ACK handshake on all sessions",
        "BGP OPEN exchange where affected PE sends wrong AS number",
        "BGP NOTIFICATION OPEN MESSAGE ERROR with subcode Bad Peer AS",
        "TCP session closes after NOTIFICATION",
        "No BGP routes advertised from affected PE"
    ],
    "hold_timer_mismatch": [
        "TCP SYN / SYN-ACK / ACK handshake on all sessions",
        "BGP OPEN from affected PE with mismatched hold timer value",
        "OPEN exchange completes but hold timer negotiated to unexpected value",
        "KEEPALIVE intervals differ from other sessions",
        "Session eventually drops on hold timer expiry"
    ],
    "max_prefix": [
        "TCP SYN / SYN-ACK / ACK handshake on all sessions",
        "Normal KEEPALIVE and route exchange during warmup",
        "Affected PE floods large volume of BGP UPDATE messages",
        "BGP NOTIFICATION CEASE with subcode Maximum Number of Prefixes Reached",
        "Session closes after max prefix limit triggered"
    ],
    "admin_reset": [
        "Normal session establishment and warmup",
        "BGP NOTIFICATION CEASE with subcode Administrative Reset",
        "TCP RST or FIN after NOTIFICATION",
        "Session does not reconnect immediately"
    ],
    "peer_deconfig": [
        "Normal session establishment and warmup",
        "BGP NOTIFICATION CEASE with subcode Peer Deconfigured",
        "TCP FIN clean close",
        "No reconnection from affected PE"
    ],
    "invalid_nexthop": [
        "Normal session establishment and warmup",
        "BGP UPDATE from affected PE with invalid next-hop address in MP_REACH_NLRI",
        "BGP NOTIFICATION UPDATE MESSAGE ERROR",
        "Session may drop after NOTIFICATION",
        "Routes from affected PE not reachable"
    ],
    "dup_mac": [
        "Normal session establishment and warmup",
        "Two PEs advertise identical MAC address in Type 2 routes",
        "MAC mobility sequence numbers increment as each PE claims the MAC",
        "Rapid alternating Type 2 advertisements for same MAC from different PEs"
    ],
    "vni_mismatch": [
        "Normal session establishment and warmup",
        "Affected PE advertises routes with wrong VNI in extended community",
        "Routes received but traffic black-holed (wrong VNI on encapsulation)",
        "Sessions remain UP, no error notifications visible"
    ],
    "fsm_error": [
        "TCP SYN / SYN-ACK / ACK handshake",
        "BGP OPEN exchange",
        "BGP NOTIFICATION FINITE STATE MACHINE ERROR",
        "Session closes immediately after NOTIFICATION",
        "Reconnect attempt follows"
    ],
    "malformed_aspath": [
        "Normal session establishment and warmup",
        "BGP UPDATE from affected PE with malformed AS_PATH attribute",
        "BGP NOTIFICATION UPDATE MESSAGE ERROR with subcode Malformed AS_PATH",
        "Session closes after NOTIFICATION"
    ],
    "out_of_resources": [
        "Normal session establishment and warmup",
        "BGP NOTIFICATION CEASE with subcode Out of Resources from affected RR",
        "All PE sessions to that RR close",
        "RR-RR session also closes",
        "No recovery in capture window"
    ],
    "af_mismatch": [
        "Normal session establishment and warmup on all sessions",
        "Affected PE's BGP OPEN advertises only 4-Octet AS + Route Refresh "
        "capabilities (no MP-BGP, no Graceful Restart) — the L2VPN/EVPN "
        "AFI/SAFI is never negotiated",
        "Affected session establishes and stays up via KEEPALIVE only",
        "No EVPN UPDATE is ever sent or received on the affected session",
        "All other PE sessions establish normally and exchange EVPN routes",
        "Silent failure — no NOTIFICATION at any point"
    ],
    "graceful_restart": [
        "Normal session establishment, initial routes, and warmup",
        "FAULT: TCP RST on the affected session (abrupt process restart) — "
        "no EVPN WITHDRAWs are sent, distinguishing this from Link Down",
        "2-8 second gap (process restart time)",
        "RECOVERY: new TCP session, BGP OPEN with Graceful Restart capability "
        "(Restart State bit set, restart_time=120, EVPN AFI/SAFI Forwarding "
        "State bit set)",
        "KEEPALIVE exchange confirms the new session",
        "Affected PE re-advertises all its routes on the recovered session",
        "End-of-RIB marker sent once re-advertisement completes"
    ],
    "graceful_restart_timeout": [
        "Normal session establishment, initial routes, and warmup",
        "FAULT: TCP RST on the affected session — no EVPN WITHDRAWs sent",
        "GR restart timer (120s) elapses with no reconnection",
        "Stale routes are purged: WITHDRAWs sent on surviving sessions for "
        "the affected PE's routes",
        "No recovery in capture window"
    ],
    "rr_esdf": [
        "Normal session establishment and warmup",
        "FAULT 1: RR session drops, PE sessions simultaneously affected",
        "FAULT 2: ES/DF re-election on multi-homed PEs triggered by reflected route loss",
        "Overlapping EAD/ES WITHDRAW burst alongside session drop"
    ],
    "rr_rt": [
        "Normal session establishment and warmup",
        "FAULT 1: RR session drops",
        "FAULT 2: Second PE simultaneously advertises routes with wrong RT",
        "Session fault plus silent routing fault in same window"
    ],
    "esdf_rt": [
        "Normal session establishment and warmup",
        "FAULT 1: ES/DF toggle on multi-homed PE (EAD/ES WITHDRAW)",
        "FAULT 2: RT misconfiguration on second PE (silent wrong-RT routes)",
        "ES/DF churn overlapping with silent routing anomaly"
    ],
    "triple_ld_rr_es": [
        "Normal session establishment and warmup",
        "FAULT 1: Link down on a PE session",
        "FAULT 2: RR down triggering simultaneous session loss on other PEs",
        "FAULT 3: ES/DF re-election due to route loss from RR fault",
        "Three overlapping fault signals in capture window"
    ],
    "cross_rr_as_misconfig": [
        "Normal session establishment and warmup",
        "FAULT 1: RR session drops",
        "FAULT 2: PE attempts reconnect with wrong AS number in OPEN",
        "BGP OPEN ERROR overlapping with RR fault"
    ],
    "cross_rt_invalid_nexthop": [
        "Normal session establishment and warmup",
        "FAULT 1: RT misconfiguration (silent route drop)",
        "FAULT 2: Another PE advertises invalid next-hop in UPDATE",
        "Two independent silent routing faults simultaneously"
    ],
}

# ---------------------------------------------------------------------------
# Per-file metadata catalogue
# Keyed by (section_dir, filename_without_extension)
# ---------------------------------------------------------------------------

def _make(
    section, fault_type, ground_truth, affected_device,
    recovery, recovery_time_seconds, description,
    event_key, base_variant=False, notes=None, fault_description=None
):
    return {
        "section": section,
        "fault_type": fault_type,
        "ground_truth_label": ground_truth,
        # fault_description: the more specific/verbose mechanism label
        # (e.g. "RT Misconfiguration (ES-Import)", "ES/DF Full Failure").
        # None for call sites with no more specific variant.
        "fault_description": fault_description,
        "affected_device": affected_device,
        "fault_inject_time_seconds": FAULT_INJECT_TIME if fault_type != "Normal" else None,
        "recovery": recovery,
        "recovery_time_seconds": recovery_time_seconds,
        "description": description,
        "base_variant": base_variant,
        "expected_bgp_events": EVENTS.get(event_key, []),
        "topology": TOPOLOGY,
        "notes": notes,
    }


CATALOGUE = {

    # -------------------------------------------------------------------------
    # SECTION 1 — Normal traffic
    # -------------------------------------------------------------------------

    ("section1_normal", "quiet"): _make(
        1, "Normal", "Normal", "ALL",
        None, None,
        "Quiet normal traffic across all 5 PEs. Low route churn, regular keepalives.",
        "normal"
    ),
    ("section1_normal", "quiet_pe1_pe3"): _make(
        1, "Normal", "Normal", "PE1, PE3",
        None, None,
        "Quiet normal traffic with focus on PE1 and PE3 sessions.",
        "normal"
    ),
    ("section1_normal", "quiet_pe4_pe5"): _make(
        1, "Normal", "Normal", "PE4, PE5",
        None, None,
        "Quiet normal traffic with focus on PE4 and PE5 sessions.",
        "normal"
    ),
    ("section1_normal", "moderate"): _make(
        1, "Normal", "Normal", "ALL",
        None, None,
        "Moderate normal traffic across all 5 PEs. Medium route churn.",
        "normal"
    ),
    ("section1_normal", "moderate_pe1_pe5"): _make(
        1, "Normal", "Normal", "PE1, PE5",
        None, None,
        "Moderate normal traffic with focus on PE1 and PE5 sessions.",
        "normal"
    ),
    ("section1_normal", "moderate_pe2_pe4"): _make(
        1, "Normal", "Normal", "PE2, PE4",
        None, None,
        "Moderate normal traffic with focus on PE2 and PE4 sessions.",
        "normal"
    ),
    ("section1_normal", "busy"): _make(
        1, "Normal", "Normal", "ALL",
        None, None,
        "Busy normal traffic across all 5 PEs. High route churn, frequent updates.",
        "normal"
    ),
    ("section1_normal", "busy_pe1_pe4"): _make(
        1, "Normal", "Normal", "PE1, PE4",
        None, None,
        "Busy normal traffic with focus on PE1 and PE4 sessions.",
        "normal"
    ),
    ("section1_normal", "busy_pe2_pe3"): _make(
        1, "Normal", "Normal", "PE2, PE3",
        None, None,
        "Busy normal traffic with focus on PE2 and PE3 sessions.",
        "normal"
    ),
    ("section1_normal", "mac_mobility_pe1_pe2"): _make(
        1, "Normal", "Normal", "PE1, PE2",
        None, None,
        "A MAC address moves cleanly back and forth between PE1 and PE2 "
        "3-6 times (e.g. VM live migration): new owner advertises with an "
        "incremented MAC Mobility sequence, old owner withdraws shortly after.",
        "mac_mobility"
    ),
    ("section1_normal", "mac_mobility_pe2_pe1"): _make(
        1, "Normal", "Normal", "PE2, PE1",
        None, None,
        "A MAC address moves cleanly back and forth between PE2 and PE1 "
        "3-6 times (e.g. VM live migration): new owner advertises with an "
        "incremented MAC Mobility sequence, old owner withdraws shortly after.",
        "mac_mobility"
    ),
    ("section1_normal", "connection_collision_pe1"): _make(
        1, "Normal", "Normal", "PE1, RR1",
        None, None,
        "PE1 and RR1 initiate a TCP connection to each other simultaneously "
        "during session setup; per RFC 4271 SS6.8 the higher-Router-ID peer's "
        "connection is closed with a Connection Collision Resolution "
        "NOTIFICATION and the other connection proceeds to Established.",
        "connection_collision"
    ),

    # -------------------------------------------------------------------------
    # SECTION 2 — Single fault scenarios
    # -------------------------------------------------------------------------

    ("section2_labelled", "link_down_simultaneous"): _make(
        2, "Link Down", "Link Down", "PE1, PE2",
        True, FAULT_INJECT_TIME + 35,
        "PE1 and PE2 links drop simultaneously. Both recover.",
        "link_down_simultaneous"
    ),

    # Link Down, non-idle injection timing: fault fires mid-churn-burst instead
    # of after an idle warmup gap.
    **{
        ("section2_labelled", f"link_down_fast_recovery_midchurn_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            True, FAULT_INJECT_TIME + 25,
            f"PE{i} link drops abruptly (TCP RST) while an active route-churn "
            f"burst is in flight, not after idle warmup. Reconnects within 20 to 30 seconds.",
            "link_down"
        ) for i in (1, 2, 3)
    },

    # Link Down — PE-specific variants. PE1-3 have a direct session at the
    # capture vantage; PE4/PE5 do not -- their fault is only observable via
    # their home RR reflecting a WITHDRAW/route-set onto the RR-RR session,
    # so they use the "_reflected" events key instead of the direct one.
    **{
        ("section2_labelled", f"link_down_fast_recovery_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            True, FAULT_INJECT_TIME + 25,
            f"PE{i} link drops abruptly (TCP RST). Reconnects within 20 to 30 seconds.",
            "link_down" if i <= 3 else "link_down_reflected"
        ) for i in range(1, 6)
    },
    **{
        ("section2_labelled", f"link_down_slow_recovery_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            True, FAULT_INJECT_TIME + 90,
            f"PE{i} link drops (hold-timer detected). Slow reconnection after "
            f"2 to 5 minutes.",
            "link_down_hold_timer_fast" if i <= 3 else "link_down_reflected"
        ) for i in range(1, 6)
    },
    **{
        ("section2_labelled", f"link_down_no_recovery_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            False, None,
            f"PE{i} link drops (TCP RST). Session never re-establishes in capture window.",
            "link_down_no_recovery" if i <= 3 else "link_down_reflected_no_recovery"
        ) for i in range(1, 6)
    },
    **{
        ("section2_labelled", f"link_down_hold_timer_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            False, None,
            f"PE{i} keepalives stop. Hold timer expires (~30s). NOTIFICATION HOLD TIMER EXPIRED.",
            "link_down_hold_timer" if i <= 3 else "link_down_reflected_no_recovery"
        ) for i in range(1, 6)
    },
    **{
        ("section2_labelled", f"link_down_rst_slow_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            True, FAULT_INJECT_TIME + 90,
            f"PE{i} link drops abruptly (TCP RST). Slow reconnection after "
            f"2 to 5 minutes.",
            "link_down_rst_slow" if i <= 3 else "link_down_reflected"
        ) for i in range(1, 6)
    },
    **{
        ("section2_labelled", f"link_down_hold_timer_fast_pe{i}"): _make(
            2, "Link Down", "Link Down", f"PE{i}",
            True, FAULT_INJECT_TIME + 25,
            f"PE{i} keepalives stop; hold timer expires (~30s). Reconnects "
            f"within 20 to 30 seconds.",
            "link_down_hold_timer_fast" if i <= 3 else "link_down_reflected"
        ) for i in range(1, 6)
    },
    **{
        ("section2_labelled", f"link_down_hard_reset_pe{i}"): _make(
            2, "Hard Reset", "Unknown Fault", f"PE{i}",
            True, FAULT_INJECT_TIME + 25,
            f"PE{i}'s session had negotiated the RFC 8538 Notification bit "
            f"on its original OPEN, but is torn down via an explicit Cease "
            f"/ Hard Reset (subcode 9) NOTIFICATION -- RFC 8538 SS4's "
            f"override of the negotiated graceful handling. A full "
            f"immediate WITHDRAW appears (routes NOT held stale), followed "
            f"by an ordinary (non-restart-flagged) reconnect.",
            "link_down_hard_reset"
        ) for i in range(1, 4)
    },

    ("section2_labelled", "rr_down_both_simultaneous"): _make(
        2, "RR Down", "RR Down", "RR1, RR2",
        False, None,
        "Both RR1 and RR2 go down simultaneously. Full session loss.",
        "rr_down_both"
    ),

    # RR Down — RR-specific variants
    ("section2_labelled", "rr_down_clean_restart_rr1"): _make(
        2, "RR Down", "RR Down", "RR1",
        True, FAULT_INJECT_TIME + 28,
        "RR1 goes down cleanly. All PEs reconnect within 25 to 30 seconds.",
        "rr_down"
    ),
    ("section2_labelled", "rr_down_clean_restart_rr2"): _make(
        2, "RR Down", "RR Down", "RR2",
        True, FAULT_INJECT_TIME + 28,
        "RR2 goes down cleanly. Captured from RR1 vantage. All PEs reconnect.",
        "rr_down"
    ),
    ("section2_labelled", "rr_down_slow_restart_rr1"): _make(
        2, "RR Down", "RR Down", "RR1",
        True, FAULT_INJECT_TIME + 90,
        "RR1 goes down. Slow restart after hold timer expiry.",
        "rr_down"
    ),
    ("section2_labelled", "rr_down_slow_restart_rr2"): _make(
        2, "RR Down", "RR Down", "RR2",
        True, FAULT_INJECT_TIME + 90,
        "RR2 goes down. Slow restart after hold timer expiry.",
        "rr_down"
    ),
    ("section2_labelled", "rr_down_no_recovery_rr1"): _make(
        2, "RR Down", "RR Down", "RR1",
        False, None,
        "RR1 goes down permanently.",
        "rr_down_no_recovery"
    ),
    ("section2_labelled", "rr_down_no_recovery_rr2"): _make(
        2, "RR Down", "RR Down", "RR2",
        False, None,
        "RR2 goes down permanently.",
        "rr_down_no_recovery"
    ),
    ("section2_labelled", "rr_down_hold_timer_rr1"): _make(
        2, "RR Down", "RR Down", "RR1",
        True, FAULT_INJECT_TIME + 70,
        "RR1 stops sending keepalives. Hold timer expires on RR2 side (~30s). NOTIFICATION HOLD TIMER EXPIRED. RR1 recovers and re-syncs full route table.",
        "rr_down_hold_timer"
    ),
    ("section2_labelled", "rr_down_hold_timer_rr2"): _make(
        2, "RR Down", "RR Down", "RR2",
        True, FAULT_INJECT_TIME + 70,
        "RR2 stops sending keepalives. Hold timer expires on RR1 side (~30s). Recovery with full route re-sync.",
        "rr_down_hold_timer"
    ),

    ("section2_labelled", "rr_down_clean_restart_midchurn_rr2"): _make(
        2, "RR Down", "RR Down", "RR2",
        True, FAULT_INJECT_TIME + 25,
        "RR2's session to RR1 drops (TCP RST) while an active route-churn "
        "burst is in flight, not after idle warmup. Reconnects within 25 to 30 seconds.",
        "rr_down"
    ),

    # ESDFSlowToggle has no PE-suffix variant for this stem; it inherits
    # ESDFSingleToggle's auto-discovery (get_multihomed_peers()[0]).
    ("section2_labelled", "esdf_toggle_slow"): {
        **_make(
            2, "ESDF Toggle", "ESDF Toggle",
            _by_topology("PE1", "PE3"),
            True, FAULT_INJECT_TIME + 80,
            "Slow ES/DF toggle on one PE of the shared ES pair. Long gap "
            "before re-advertisement.",
            "esdf_toggle_slow"
        ),
        "topology": _by_topology(
            TOPOLOGY_2RR,
            {**TOPOLOGY_3RR, "multihomed_esi_pair": ["PE3", "PE4"],
             "esi": "00:11:22:33:44:55:66:77:88:02"},
        ),
    },

    # ESDF Toggle — PE-specific variants
    # 5PE/2RR topology: only PE1/PE2 are multihomed (share an ESI) -- see
    # ESDFSingleToggle.__init__'s ValueError for any other PE there.
    # 3RR/10PE topology (configs/3rr_topology.yaml): PE3/PE4 and PE6/PE7
    # are that topology's own ES pairs.
    **{
        ("section2_labelled", f"esdf_toggle_single_pe{i}"): _make_pe(
            2, "ESDF Toggle", "ESDF Toggle", i,
            True, FAULT_INJECT_TIME + 15,
            f"Single ES/DF toggle on PE{i}. Clean recovery in 10 to 20 seconds.",
            "esdf_toggle"
        ) for i in (1, 2, 3, 4, 6, 7)
    },
    **{
        ("section2_labelled", f"esdf_toggle_single_midchurn_pe{i}"): _make_pe(
            2, "ESDF Toggle", "ESDF Toggle", i,
            True, FAULT_INJECT_TIME + 15,
            f"Single ES/DF toggle on PE{i} injected while an active route-churn "
            f"burst is in flight, not after idle warmup. Clean recovery in 10 to 20 seconds.",
            "esdf_toggle"
        ) for i in (1, 2, 3, 4, 6, 7)
    },
    **{
        ("section2_labelled", f"esdf_toggle_repeated_pe{i}"): _make_pe(
            2, "ESDF Toggle", "ESDF Toggle", i,
            True, FAULT_INJECT_TIME + 60,
            f"Repeated ES/DF toggling on PE{i}: 3 to 4 cycles within a "
            f"60-second window, at ordinary (not accelerated) per-toggle "
            f"timing -- toggle count, not speed, is the distinguishing factor.",
            "esdf_toggle_repeated"
        ) for i in (1, 2, 3, 4, 6, 7)
    },
    **{
        ("section2_labelled", f"esdf_toggle_no_recovery_pe{i}"): _make_pe(
            2, "ESDF Toggle", "ESDF Toggle", i,
            False, None,
            f"ES/DF toggle on PE{i}. EAD/ES routes never re-advertised.",
            "esdf_toggle_no_recovery"
        ) for i in (1, 2, 3, 4, 6, 7)
    },
    **{
        ("section2_labelled", f"esdf_toggle_type1_evi_pe{i}"): _make_pe(
            2, "ESDF Toggle", "ESDF Toggle", i,
            True, FAULT_INJECT_TIME + 15,
            f"ES/DF toggle on PE{i} triggered by a Type-1 per-EVI EAD route "
            f"withdrawal (RFC 8584's second DF-election trigger type), distinct "
            f"from the Type-4 ES-route trigger. Clean recovery in 10 to 20 seconds.",
            "esdf_toggle_type1_evi"
        ) for i in (1, 2, 3, 4, 6, 7)
    },
    **{
        ("section2_labelled", f"esdf_toggle_ac_state_pe{i}"): _make_pe(
            2, "ESDF Toggle", "ESDF Toggle", i,
            True, FAULT_INJECT_TIME + 15,
            f"ES/DF toggle on PE{i} triggered by local AC (attachment circuit) "
            f"state (RFC 8584's first DF-election trigger type): the DF Election "
            f"Extended Community's AC-DF bit is cleared on a Type-4 "
            f"re-advertisement, then set again 10 to 20 seconds later. No route "
            f"withdrawal at any point.",
            "esdf_toggle_ac_state"
        ) for i in (1, 2, 3, 4, 6, 7)
    },

    # RT Misconfiguration
    **{
        ("section2_labelled", f"rt_misconfig_pe{i}"): _make(
            2, "RT Misconfiguration", "RT Misconfiguration", f"PE{i}",
            False, None,
            f"PE{i} advertises routes (Type 2 MAC/IP, Type 3 IMET, Type 5 IP "
            f"Prefix, and Type 1 A-D per ES if PE{i} is multihomed) with an "
            f"incorrect Route Target. Because RT-based import filtering "
            f"happens at receiving PEs, the route becomes invisible to any "
            f"PE expecting the correct RT -- while remaining fully visible, "
            f"unfiltered, in the capture at RR1 (RR1 never filters or "
            f"corrects RT; it reflects the wrong-RT route as-is). Sessions "
            f"stay UP throughout.",
            "rt_misconfig"
        ) for i in range(1, 6)
    },
    ("section2_labelled", "rt_misconfig_recovery_pe1"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE1",
        True, FAULT_INJECT_TIME + 120,
        "PE1 advertises routes (Type 2, 3, 5, and Type 1 if multihomed) "
        "with an incorrect Route Target -- visible unfiltered at RR1, "
        "invisible to any PE expecting the correct RT. All perturbed route "
        "types are re-advertised with the correct RT after ~120s.",
        "rt_misconfig_recovery"
    ),
    ("section2_labelled", "rt_misconfig_recovery_pe2"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE2",
        True, FAULT_INJECT_TIME + 120,
        "PE2 advertises routes (Type 2, 3, 5, and Type 1 since PE2 is "
        "multihomed) with an incorrect Route Target -- visible unfiltered "
        "at RR1, invisible to any PE expecting the correct RT. All "
        "perturbed route types are re-advertised with the correct RT after "
        "~120s.",
        "rt_misconfig_recovery"
    ),
    ("section2_labelled", "rt_misconfig_recovery_pe3"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE3",
        True, FAULT_INJECT_TIME + 120,
        "PE3 advertises routes (Type 2, 3, and 5 -- PE3 is not multihomed, "
        "so no Type 1) with an incorrect Route Target -- visible unfiltered "
        "at RR1, invisible to any PE expecting the correct RT. All "
        "perturbed route types are re-advertised with the correct RT after "
        "~120s.",
        "rt_misconfig_recovery"
    ),
    ("section2_labelled", "rt_misconfig_recovery_pe4"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE4",
        True, FAULT_INJECT_TIME + 120,
        "PE4 advertises routes (Type 2, 3, and 5 -- PE4 is not multihomed, "
        "so no Type 1) with an incorrect Route Target -- visible unfiltered "
        "at RR1, invisible to any PE expecting the correct RT. All "
        "perturbed route types are re-advertised with the correct RT after "
        "~120s.",
        "rt_misconfig_recovery"
    ),
    ("section2_labelled", "rt_misconfig_recovery_pe5"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE5",
        True, FAULT_INJECT_TIME + 120,
        "PE5 advertises routes (Type 2, 3, and 5 -- PE5 is not multihomed, "
        "so no Type 1) with an incorrect Route Target -- visible unfiltered "
        "at RR1, invisible to any PE expecting the correct RT. All "
        "perturbed route types are re-advertised with the correct RT after "
        "~120s.",
        "rt_misconfig_recovery"
    ),

    # -------------------------------------------------------------------------
    # SECTION 3 — Mixed evaluation scenarios
    # -------------------------------------------------------------------------

    # Overlapping faults
    ("section3_mixed", "overlapping_ld_ld_pe2_pe3"): _make(
        3, "Link Down", "Link Down", "PE2, PE3",
        True, FAULT_INJECT_TIME + 50,
        "Overlapping link down on PE2 and PE3 simultaneously.",
        "link_down_simultaneous"
    ),
    ("section3_mixed", "overlapping_ld_rr_pe1_rr2"): _make(
        3, "Link Down + RR Down", "Link Down", "PE1, RR2",
        True, FAULT_INJECT_TIME + 50,
        "Overlapping PE1 link down and RR2 session drop.",
        "rr_down"
    ),

    # Overlapping LD + ESDF / LD + RT
    ("section3_mixed", "ld_esdf_pe1_pe2"): _make(
        3, "ESDF Toggle + Link Down", "ESDF Toggle", "PE1, PE2",
        False, None,
        "ES/DF toggle on PE1 (no recovery -- single ES withdrawal, never re-advertised) overlapping with link down on PE2 (also no recovery).",
        "esdf_toggle"
    ),
    ("section3_mixed", "ld_rt_pe2_pe3"): _make(
        3, "RT Misconfiguration + Link Down", "RT Misconfiguration", "PE2, PE3",
        False, None,
        "RT misconfiguration on PE2 overlapping with link down on PE3.",
        "rt_misconfig"
    ),

    # Link Down on a multihomed PE causing the peer's ES/DF re-election (causal,
    # not two independent faults -- ground_truth_label is the root cause only)
    ("section3_mixed", "ld_triggers_esdf_pe1"): _make(
        3, "Link Down + ESDF Toggle", "Link Down", "PE1, PE2",
        True, FAULT_INJECT_TIME + 30,
        "PE1 link down causes its ES/DF peer PE2 to re-elect DF as a direct consequence.",
        "ld_triggers_esdf"
    ),
    ("section3_mixed", "ld_triggers_esdf_pe2"): _make(
        3, "Link Down + ESDF Toggle", "Link Down", "PE2, PE1",
        True, FAULT_INJECT_TIME + 30,
        "PE2 link down causes its ES/DF peer PE1 to re-elect DF as a direct consequence.",
        "ld_triggers_esdf"
    ),

    # Mixed mechanism/recovery pairings -- independent faults, not causal
    ("section3_mixed", "ld_esdf_overlap_pe1_pe2"): _make(
        3, "Link Down + ESDF Toggle", "Link Down", "PE1, PE2",
        False, None,
        "PE1 link down (no recovery) overlapping with an independent ES/DF toggle on PE2 (recovers).",
        "ld_esdf_overlap"
    ),
    ("section3_mixed", "ld_esdf_overlap_pe3_pe2"): _make(
        3, "Link Down + ESDF Toggle", "Link Down", "PE3, PE2",
        False, None,
        "PE3 link down (no recovery) overlapping with an independent ES/DF toggle on PE2 (recovers).",
        "ld_esdf_overlap"
    ),
    ("section3_mixed", "ld_rt_overlap_pe2_pe3"): _make(
        3, "Link Down + RT Misconfiguration", "Link Down", "PE2, PE3",
        True, FAULT_INJECT_TIME + 7.36,
        "PE2 link down via hold-timer expiry (recovers) overlapping with a persistent RT misconfiguration on PE3 (no recovery).",
        "ld_rt_overlap"
    ),
    ("section3_mixed", "ld_rt_overlap_pe3_pe1"): _make(
        3, "Link Down + RT Misconfiguration", "Link Down", "PE3, PE1",
        True, FAULT_INJECT_TIME + 4.94,
        "PE3 link down via hold-timer expiry (recovers) overlapping with a persistent RT misconfiguration on PE1 (no recovery).",
        "ld_rt_overlap"
    ),
    ("section3_mixed", "rr_then_ld_rr2_pe1"): _make(
        3, "RR Down + Link Down", "RR Down", "RR2, PE1",
        True, FAULT_INJECT_TIME + 27.07,
        "RR2 down and full recovery completes, then separately PE1's link fails (no recovery) -- sequential, independent faults.",
        "rr_then_ld"
    ),
    ("section3_mixed", "rr_then_ld_rr2_pe3"): _make(
        3, "RR Down + Link Down", "RR Down", "RR2, PE3",
        True, FAULT_INJECT_TIME + 28.24,
        "RR2 down and full recovery completes, then separately PE3's link fails (no recovery) -- sequential, independent faults.",
        "rr_then_ld"
    ),

    # Planned maintenance (classified as Normal — graceful shutdown)

    # Node removal (classified as Normal)

    # Unseen topology
    ("section3_mixed", "unseen_topology_pe6_joins"): _make(
        3, "Normal", "Normal", "PE6 (new)",
        None, None,
        "New PE6 joins mid-capture. Tests generalisation to unseen topology nodes.",
        "unseen_topology"
    ),

    # Cascade faults
    ("section3_mixed", "cascade_rr_down_esdf_rr1"): _make(
        3, "RR Down + ESDF Toggle", "RR Down", "RR1, PE1, PE2",
        False, None,
        "RR1 goes down triggering ES/DF re-election cascade on multi-homed PE1 and PE2.",
        "cascade_rr_esdf"
    ),
    ("section3_mixed", "cascade_rr_down_esdf_rr2"): _make(
        3, "RR Down + ESDF Toggle", "RR Down", "RR2, PE1, PE2",
        False, None,
        "RR2 goes down triggering ES/DF re-election cascade.",
        "cascade_rr_esdf"
    ),
    ("section3_mixed", "cascade_link_down_rtmisconfig_pe1"): _make(
        3, "Link Down + RT Misconfiguration", "Link Down", "PE1, PE3",
        False, None,
        "PE1 link down cascading into RT misconfiguration on PE3.",
        "cascade_link_rt"
    ),

    # Intermittent faults
    ("section3_mixed", "intermittent_link_flap_pe1"): _make(
        3, "Link Down", "Link Down", "PE1",
        True, None,
        "PE1 link flaps repeatedly (multiple down/up cycles in capture window).",
        "intermittent_link"
    ),
    ("section3_mixed", "intermittent_link_flap_pe2"): _make(
        3, "Link Down", "Link Down", "PE2",
        True, None,
        "PE2 link flaps repeatedly.",
        "intermittent_link"
    ),
    ("section3_mixed", "intermittent_rr_flap_rr1"): _make(
        3, "RR Down", "RR Down", "RR1",
        True, None,
        "RR1-RR2 inter-RR session flaps 3 times with full route sync on each recovery. Tests detection of intermittent RR instability.",
        "intermittent_rr"
    ),
    ("section3_mixed", "intermittent_rr_flap_rr2"): _make(
        3, "RR Down", "RR Down", "RR2",
        True, None,
        "RR2-RR1 inter-RR session flaps 3 times with full route sync on each recovery.",
        "intermittent_rr"
    ),

    # Session flap

    # Slow degradation
    ("section3_mixed", "slow_degradation_pe1"): _make(
        3, "Link Down", "Link Down", "PE1",
        False, None,
        "PE1 keepalive intervals gradually degrade until hold timer expiry.",
        "slow_degradation"
    ),
    ("section3_mixed", "slow_degradation_pe2"): _make(
        3, "Link Down", "Link Down", "PE2",
        False, None,
        "PE2 keepalive intervals gradually degrade until hold timer expiry.",
        "slow_degradation"
    ),

    # Mid-session link down
    ("section3_mixed", "mid_session_link_down_pe1"): _make(
        3, "Link Down", "Link Down", "PE1",
        True, None,
        "PE1 link down mid-session with populated route table. Large WITHDRAW burst on recovery.",
        "mid_session_link_down"
    ),
    ("section3_mixed", "mid_session_link_down_pe2"): _make(
        3, "Link Down", "Link Down", "PE2",
        True, None,
        "PE2 link down mid-session.",
        "mid_session_link_down"
    ),
    ("section3_mixed", "mid_session_link_down_pe3"): _make(
        3, "Link Down", "Link Down", "PE3",
        True, None,
        "PE3 link down mid-session.",
        "mid_session_link_down"
    ),

    # Novel fault types never seen in Section 2

    # Pairwise combinations
    ("section3_mixed", "rr_esdf_rr1_pe1"): _make(
        3, "RR Down + ESDF Toggle", "RR Down", "RR1, PE1",
        False, None,
        "RR1 goes down triggering ES/DF re-election on PE1 (a real "
        "multihomed PE).",
        "rr_esdf"
    ),
    ("section3_mixed", "rr_rt_rr1_pe2"): _make(
        3, "RR Down + RT Misconfiguration", "RR Down", "RR1, PE2",
        False, None,
        "RR1 goes down. PE2 simultaneously has RT misconfiguration.",
        "rr_rt"
    ),
    ("section3_mixed", "esdf_rt_pe1_pe2"): _make(
        3, "ESDF Toggle + RT Misconfiguration", "ESDF Toggle", "PE1, PE2",
        False, None,
        "ES/DF toggle on PE1 overlapping with RT misconfiguration on PE2.",
        "esdf_rt"
    ),

    # Triple combinations
    ("section3_mixed", "triple_ld_rr_esdf"): _make(
        3, "Link Down + RR Down + ESDF Toggle", "Link Down", "PE1, RR1, PE2",
        False, None,
        "Three simultaneous faults: link down, RR down, and ES/DF re-election cascade.",
        "triple_ld_rr_es"
    ),

    # Cross combinations

    # -------------------------------------------------------------------------
    # SECTION 4 — Temporal evaluation scenarios
    # -------------------------------------------------------------------------

    ("section4_additional", "cascade_rr_down_esdf_rr1"): _make(
        4, "RR Down + ESDF Toggle", "RR Down", "RR1, PE1, PE2",
        False, None,
        "RR1 goes down triggering ES/DF re-election cascade on multi-homed PE1 and PE2.",
        "cascade_rr_esdf"
    ),
    ("section4_additional", "cascade_rr_down_esdf_rr2"): _make(
        4, "RR Down + ESDF Toggle", "RR Down", "RR2, PE1, PE2",
        False, None,
        "RR2 goes down triggering ES/DF re-election cascade.",
        "cascade_rr_esdf"
    ),
    ("section4_additional", "cascade_link_down_rtmisconfig_pe1"): _make(
        4, "Link Down + RT Misconfiguration", "Link Down", "PE1, PE3",
        False, None,
        "PE1 link down cascading into RT misconfiguration on PE3.",
        "cascade_link_rt"
    ),
    ("section4_additional", "intermittent_link_flap_pe1"): _make(
        4, "Link Down", "Link Down", "PE1",
        True, None,
        "PE1 link flaps repeatedly. Multiple down/up cycles.",
        "intermittent_link"
    ),
    ("section4_additional", "intermittent_link_flap_pe2"): _make(
        4, "Link Down", "Link Down", "PE2",
        True, None,
        "PE2 link flaps repeatedly.",
        "intermittent_link"
    ),
    ("section4_additional", "intermittent_esdf_toggle_pe1"): _make(
        4, "ESDF Toggle", "ESDF Toggle", "PE1",
        True, None,
        "PE1 ES/DF toggling with irregular intervals between toggles. "
        "Unlike clean periodic toggles, timing is unpredictable, making it "
        "harder to detect from timing alone.",
        "esdf_toggle"
    ),
    ("section4_additional", "intermittent_esdf_toggle_pe2"): _make(
        4, "ESDF Toggle", "ESDF Toggle", "PE2",
        True, None,
        "PE2 ES/DF toggling with irregular intervals between toggles. "
        "Unlike clean periodic toggles, timing is unpredictable, making it "
        "harder to detect from timing alone.",
        "esdf_toggle"
    ),
    ("section4_additional", "slow_degradation_pe1"): _make(
        4, "Link Down", "Link Down", "PE1",
        False, None,
        "PE1 keepalive intervals gradually degrade until hold timer expiry.",
        "slow_degradation"
    ),
    ("section4_additional", "slow_degradation_pe2"): _make(
        4, "Link Down", "Link Down", "PE2",
        False, None,
        "PE2 keepalive intervals gradually degrade.",
        "slow_degradation"
    ),
    ("section4_additional", "mid_session_link_down_pe1"): _make(
        4, "Link Down", "Link Down", "PE1",
        True, None,
        "PE1 link down mid-session with populated route table.",
        "mid_session_link_down"
    ),
    ("section4_additional", "mid_session_link_down_pe2"): _make(
        4, "Link Down", "Link Down", "PE2",
        True, None,
        "PE2 link down mid-session.",
        "mid_session_link_down"
    ),
    ("section4_additional", "mid_session_link_down_pe3"): _make(
        4, "Link Down", "Link Down", "PE3",
        True, None,
        "PE3 link down mid-session.",
        "mid_session_link_down"
    ),
    ("section4_additional", "rt_misconfig_recovery_pe1"): _make(
        4, "RT Misconfiguration", "RT Misconfiguration", "PE1",
        True, FAULT_INJECT_TIME + 120,
        "PE1 RT misconfigured then corrected. Tests detection of silent fault with recovery.",
        "rt_misconfig_recovery"
    ),
    ("section4_additional", "rt_misconfig_recovery_pe2"): _make(
        4, "RT Misconfiguration", "RT Misconfiguration", "PE2",
        True, FAULT_INJECT_TIME + 120,
        "PE2 RT misconfigured then corrected.",
        "rt_misconfig_recovery"
    ),
    ("section4_additional", "rt_misconfig_recovery_pe4"): _make(
        4, "RT Misconfiguration", "RT Misconfiguration", "PE4",
        True, FAULT_INJECT_TIME + 120,
        "PE4 RT misconfigured then corrected.",
        "rt_misconfig_recovery"
    ),

    # -------------------------------------------------------------------------
    # RT Misconfiguration on Type-4 ES route (Section 2 extension)
    # -------------------------------------------------------------------------
    ("section2_labelled", "rt_misconfig_es_import_pe1"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE1",
        False, None,
        "PE1 advertises its Type-4 ES route with wrong RT, breaking "
        "ES-Import RT matching with PE2 (multihoming/DF election broken, "
        "not just a blackholed Type-2 route). Type-2 traffic on PE1 stays "
        "correctly RT'd. Persistent -- no correction ever appears.",
        "rt_misconfig_es_import",
        fault_description="RT Misconfiguration (ES-Import)"
    ),
    ("section2_labelled", "rt_misconfig_es_import_pe2"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE2",
        False, None,
        "PE2 advertises its Type-4 ES route with wrong RT, breaking "
        "ES-Import RT matching with PE1. Type-2 traffic on PE2 stays "
        "correctly RT'd. Persistent -- no correction ever appears.",
        "rt_misconfig_es_import",
        fault_description="RT Misconfiguration (ES-Import)"
    ),
    ("section2_labelled", "rt_misconfig_es_import_recovery_pe1"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE1",
        True, FAULT_INJECT_TIME + 120,
        "PE1 Type-4 ES route RT misconfigured then corrected after ~120s.",
        "rt_misconfig_es_import_recovery",
        fault_description="RT Misconfiguration (ES-Import)"
    ),
    ("section2_labelled", "rt_misconfig_es_import_recovery_pe2"): _make(
        2, "RT Misconfiguration", "RT Misconfiguration", "PE2",
        True, FAULT_INJECT_TIME + 120,
        "PE2 Type-4 ES route RT misconfigured then corrected after ~120s.",
        "rt_misconfig_es_import_recovery",
        fault_description="RT Misconfiguration (ES-Import)"
    ),

    # 3RR/10PE topology entries: PE3/PE4, PE6/PE7 ES pairs.
    **{
        ("section2_labelled", f"rt_misconfig_es_import_pe{i}"): _make(
            2, "RT Misconfiguration", "RT Misconfiguration", f"PE{i}",
            False, None,
            f"PE{i} advertises its Type-4 ES route with wrong RT, breaking "
            f"ES-Import RT matching with its ES partner (multihoming/DF "
            f"election broken, not just a blackholed Type-2 route). Type-2 "
            f"traffic on PE{i} stays correctly RT'd. Persistent -- no "
            f"correction ever appears.",
            "rt_misconfig_es_import",
            fault_description="RT Misconfiguration (ES-Import)"
        ) for i in (3, 4, 6, 7)
    },
    **{
        ("section2_labelled", f"rt_misconfig_es_import_recovery_pe{i}"): _make(
            2, "RT Misconfiguration", "RT Misconfiguration", f"PE{i}",
            True, FAULT_INJECT_TIME + 120,
            f"PE{i} Type-4 ES route RT misconfigured then corrected after ~120s.",
            "rt_misconfig_es_import_recovery",
            fault_description="RT Misconfiguration (ES-Import)"
        ) for i in (3, 4, 6, 7)
    },

    # -------------------------------------------------------------------------
    # MAC Mobility rapid-flap (Section 2)
    # -------------------------------------------------------------------------
    **{
        ("section2_labelled", f"mac_mobility_rapid_{pair}"): _make(
            2, "MAC Mobility", "MAC Mobility", pair.upper().replace("_", ","),
            False, None,
            f"Single MAC Mobility rapid-flap event ({pair}): WITHDRAW from the "
            f"old-owner PE, then ADVERTISE from the new-owner PE with an "
            f"incremented RFC 7432 SS15 sequence number, 2.0s apart -- inside "
            f"the real testbed clean-move delta range of 1.74-6.70s.",
            "mac_mobility_rapid"
        ) for pair in ("pe1_pe2", "pe2_pe1")
    },
    **{
        ("section2_labelled", f"mac_mobility_repeated_{pair}"): _make(
            2, "MAC Mobility", "MAC Mobility", pair.upper().replace("_", ","),
            False, None,
            f"MAC Mobility flap storm ({pair}): the same MAC moves back and "
            f"forth 3-6 times within one capture, each flap using the same "
            f"WITHDRAW-then-ADVERTISE (2.0s gap) ordering as the single-flap "
            f"variant. Sequence number increments monotonically, never "
            f"resetting per flap.",
            "mac_mobility_repeated"
        ) for pair in ("pe1_pe2", "pe2_pe1")
    },
    # PE4/PE5 variants (5PE/2RR topology only): standalone (no ESI) PEs,
    # both homed to RR2, so they avoid the ESI-partner exclusion and the
    # cross-RR reflection gap that apply to the PE1/PE2 pair above.
    **{
        ("section2_labelled", f"mac_mobility_rapid_{pair}"): _make(
            2, "MAC Mobility", "MAC Mobility", pair.upper().replace("_", ","),
            False, None,
            f"Single MAC Mobility rapid-flap event ({pair}): WITHDRAW from the "
            f"old-owner PE, then ADVERTISE from the new-owner PE with an "
            f"incremented RFC 7432 SS15 sequence number, 2.0s apart -- inside "
            f"the real testbed clean-move delta range of 1.74-6.70s.",
            "mac_mobility_rapid"
        ) for pair in ("pe4_pe5", "pe5_pe4")
    },
    **{
        ("section2_labelled", f"mac_mobility_repeated_{pair}"): _make(
            2, "MAC Mobility", "MAC Mobility", pair.upper().replace("_", ","),
            False, None,
            f"MAC Mobility flap storm ({pair}): the same MAC moves back and "
            f"forth 3-6 times within one capture, each flap using the same "
            f"WITHDRAW-then-ADVERTISE (2.0s gap) ordering as the single-flap "
            f"variant. Sequence number increments monotonically, never "
            f"resetting per flap.",
            "mac_mobility_repeated"
        ) for pair in ("pe4_pe5", "pe5_pe4")
    },

    # -------------------------------------------------------------------------
    # RD Collision (Section 3, new fault type)
    # -------------------------------------------------------------------------

    # -------------------------------------------------------------------------
    # ES/DF Full Failure (Section 2, single-fault ESDF Toggle group;
    # class definitions live in mixed.py)
    # -------------------------------------------------------------------------
    # This CATALOGUE key is shared -- looked up under both topologies
    # (ESDFFullFailure* has no PE-suffix variant for the "default" pair,
    # it auto-discovers get_multihomed_peers()[0] for whichever config
    # it's run against):
    #   - configs/default_topology.yaml (2RR/5PE): real ES pair is PE1/PE2,
    #     esi ...01 (the only multihomed pair that topology has).
    #   - configs/3rr_topology.yaml (3RR/10PE): get_multihomed_peers()[0]
    #     resolves to PE3/PE4, esi ...02.
    # affected_device and topology branch on topology_id via
    # _by_topology() rather than a single hardcoded value.
    ("section2_labelled", "esdf_toggle_full_failure_recovery"): {
        **_make(
            2, "ESDF Toggle", "ESDF Toggle",
            _by_topology("PE1, PE2", "PE3, PE4"),
            True, FAULT_INJECT_TIME,
            "Both PEs of the shared ES pair withdraw their Type-1 A-D per ES "
            "route for the shared ESI within ~150-280ms of each other -- the "
            "whole access segment going down, not one PE taking over DF for "
            "the other. No surviving DF candidate during the fault window. "
            "Type 4 (ES route) follows passively as a consequence, not as "
            "the trigger. Both re-advertise together after 10-20s, DF "
            "re-elected normally.",
            "esdf_full_failure",
            fault_description="ES/DF Full Failure"
        ),
        "topology": _by_topology(
            TOPOLOGY_2RR,
            {**TOPOLOGY_3RR, "multihomed_esi_pair": ["PE3", "PE4"],
             "esi": "00:11:22:33:44:55:66:77:88:02"},
        ),
    },
    ("section2_labelled", "esdf_toggle_full_failure_no_recovery"): {
        **_make(
            2, "ESDF Toggle", "ESDF Toggle",
            _by_topology("PE1, PE2", "PE3, PE4"),
            False, None,
            "Same full ES failure as esdf_toggle_full_failure_recovery, but "
            "neither PE ever re-advertises its Type-1 A-D per ES route.",
            "esdf_full_failure",
            fault_description="ES/DF Full Failure"
        ),
        "topology": _by_topology(
            TOPOLOGY_2RR,
            {**TOPOLOGY_3RR, "multihomed_esi_pair": ["PE3", "PE4"],
             "esi": "00:11:22:33:44:55:66:77:88:02"},
        ),
    },

    # 3RR/10PE topology entries: both ES pairs, PE3/PE4 and PE6/PE7, each
    # get their own full-failure recovery/no-recovery pair. 3RR-only, so
    # -- same as _make_pe's PE-suffixed entries -- topology is a direct
    # override via _3RR_ESI_BY_PE, not a _by_topology() branch.
    **{
        ("section2_labelled", f"esdf_toggle_full_failure_recovery_pe{a}pe{b}"): {
            **_make(
                2, "ESDF Toggle", "ESDF Toggle", f"PE{a}, PE{b}",
                True, FAULT_INJECT_TIME,
                f"Both PE{a} and PE{b} withdraw their Type-1 A-D per ES route for "
                f"the shared ESI within ~150-280ms of each other -- the whole "
                f"access segment going down, not one PE taking over DF for the "
                f"other. No surviving DF candidate during the fault window. Type 4 "
                f"(ES route) follows passively as a consequence, not as the "
                f"trigger. Both re-advertise together after 10-20s, DF re-elected "
                f"normally.",
                "esdf_full_failure",
                fault_description="ES/DF Full Failure"
            ),
            "topology": {**TOPOLOGY_3RR, **dict(zip(("multihomed_esi_pair", "esi"), _3RR_ESI_BY_PE[a]))},
        } for a, b in ((3, 4), (6, 7))
    },
    **{
        ("section2_labelled", f"esdf_toggle_full_failure_no_recovery_pe{a}pe{b}"): {
            **_make(
                2, "ESDF Toggle", "ESDF Toggle", f"PE{a}, PE{b}",
                False, None,
                f"Same full ES failure as esdf_toggle_full_failure_recovery_pe{a}pe{b}, "
                f"but neither PE ever re-advertises its Type-1 A-D per ES route.",
                "esdf_full_failure",
                fault_description="ES/DF Full Failure"
            ),
            "topology": {**TOPOLOGY_3RR, **dict(zip(("multihomed_esi_pair", "esi"), _3RR_ESI_BY_PE[a]))},
        } for a, b in ((3, 4), (6, 7))
    },
}


# ---------------------------------------------------------------------------
# Main writer
# ---------------------------------------------------------------------------

def write_json(output_root: Path, dry_run: bool = False):
    written = 0
    skipped = 0
    missing = []

    section_dirs = [
        "section1_normal",
        "section2_labelled",
        "section3_mixed",
        "section4_additional",
    ]

    for section_dir in section_dirs:
        dir_path = output_root / section_dir
        if not dir_path.exists():
            continue

        for pcap_file in sorted(dir_path.glob("*.pcap")):
            stem = pcap_file.stem
            key = (section_dir, stem)
            meta = CATALOGUE.get(key)

            if meta is None:
                missing.append(str(pcap_file.relative_to(output_root)))
                skipped += 1
                continue

            json_path = pcap_file.with_suffix(".json")

            # Read actual packet counts from the pcap
            frame_counts = count_pcap_stats(pcap_file)

            affected_dev = meta.get("affected_device", "")
            fault_t      = meta.get("fault_inject_time_seconds")
            recovery_t   = meta.get("recovery_time_seconds")

            # BaseScenario.write() already wrote <name>.json with a runtime
            # fault_window computed from the actual generation run. Preserve
            # that value if present; otherwise fall back to the static
            # FAULT_INJECT_TIME=300 catalogue constant.
            existing = {}
            if json_path.exists():
                with open(json_path, encoding="utf-8") as _existing:
                    existing = json.load(_existing)
            runtime_fw = existing.get("fault_window")

            # fault_t/recovery_t are a static relative-offset guess (seconds),
            # not a real epoch timestamp, so they cannot be converted to a
            # UTC datetime -- represent "no real timing known" as None under
            # the same keys write() uses.
            fault_window = (
                runtime_fw
                if runtime_fw is not None
                else ({"fault_start_datetime_utc": None, "fault_end_datetime_utc": None}
                      if fault_t is not None else None)
            )

            payload = {
                **existing,
                "pcap_file": pcap_file.name,
                **meta,
                "affected_link_ids": _affected_link_ids(affected_dev) if affected_dev else [],
                "fault_window": fault_window,
                "frame_counts": frame_counts,
            }
            # Remove None values for cleaner JSON
            payload = {k: v for k, v in payload.items() if v is not None}

            if not dry_run:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)

            written += 1
            status = "DRY RUN" if dry_run else "WRITTEN"
            print(f"  [{status}] {section_dir}/{stem}.json  "
                  f"(frames={frame_counts['total_frames']:,}, "
                  f"KA={frame_counts['bgp_keepalive']:,}, "
                  f"UPD={frame_counts['bgp_update']}, "
                  f"adv={frame_counts['bgp_update_advertisements']}, "
                  f"with={frame_counts['bgp_update_withdrawals']}, "
                  f"NOTIF={frame_counts['bgp_notification']})")

    print(f"\nSummary: {written} JSON file(s) written, {skipped} PCAP(s) not in catalogue.")

    if missing:
        print("\nPCAPs with no catalogue entry (need to be added manually):")
        for m in missing:
            print(f"  MISSING: {m}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate JSON ground-truth files for synthcap PCAPs.")
    parser.add_argument(
        "--output-dir", "-o",
        default="output",
        help="Path to the synthcap output directory (default: output)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written without creating any files."
    )
    args = parser.parse_args()

    output_root = Path(args.output_dir)
    if not output_root.exists():
        print(f"ERROR: Output directory not found: {output_root.resolve()}")
        exit(1)

    print(f"Generating JSON files in: {output_root.resolve()}\n")
    write_json(output_root, dry_run=args.dry_run)
