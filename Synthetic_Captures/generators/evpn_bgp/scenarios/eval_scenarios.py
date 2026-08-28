"""Evaluation-only scenarios — new fault types, fault combinations, BGP error code coverage.

None of these appear in Section 2 training.  Every class in this file goes to the
merged evaluation section (Section 3).

Groups
------
A. New fault types (10 types the model has never seen):
   AS misconfiguration, hold-timer mismatch, max-prefix limit, admin reset,
   peer de-configured, invalid NEXT_HOP, duplicate MAC, VNI mismatch,
   FSM error, malformed AS_PATH, out-of-resources.

B. Missing pairwise combinations (RR+ES, RR+RT, ES+RT).

C. Triple combinations (LD+RR+ES, LD+RR+RT, LD+ES+RT, RR+ES+RT).

D. Cross-combinations — new fault type with an existing one.
"""

import random
import struct
from .base import BaseScenario
from .rr_down import RRDownCleanRestart
from ..config import TopologyConfig
from ..tcp.session import TCPSession, TCPPacket
from ..bgp.messages import build_notification, build_keepalive, build_open, build_update
from ..bgp.capabilities import (
    default_evpn_capabilities, cap_4byte_as, cap_route_refresh,
    cap_multiprotocol, cap_graceful_restart,
)
from ..bgp.constants import (
    ERR_OPEN_MSG, ERR_UPDATE_MSG, ERR_FSM, ERR_CEASE,
    CEASE_MAX_PREFIXES, CEASE_ADMIN_SHUTDOWN, CEASE_PEER_DECONFIGURED,
    CEASE_ADMIN_RESET, CEASE_OUT_OF_RESOURCES,
    OPEN_BAD_PEER_AS, OPEN_UNACCEPTABLE_HOLD_TIME,
    UPDATE_INVALID_NEXT_HOP, UPDATE_MALFORMED_ASPATH,
    FSM_UNEXPECTED_MSG_OPEN_SENT,
    AFI_L2VPN, SAFI_EVPN, TUNNEL_TYPE_VXLAN,
)
from ..bgp.attributes import (
    build_standard_evpn_path_attrs, build_evpn_withdraw_attrs,
    attr_origin, attr_as_path, attr_local_pref,
    attr_extended_communities, attr_mp_reach_nlri,
    encode_rt_community, encode_encapsulation_community,
    encode_mac_mobility_community,
)
from ..bgp import evpn
from generators.common.utils.timing import (
    jittered_interval, ack_delay, keepalive_timestamps, route_burst_timestamps,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _session_for_node(scenario: BaseScenario, node_id: str):
    """Return (bgp_session, tcp_session) for a node id, or (None, None)."""
    for bgp_sess in scenario.topology.get_sessions_at_vantage():
        if bgp_sess.local_router.id == node_id:
            tcp = scenario.tcp_sessions.get(bgp_sess.session_id)
            return bgp_sess, tcp
    return None, None


def _reset_session(scenario: BaseScenario, node_id: str, t: float):
    """TCP RST a session for node_id.  Returns packets + new timestamp."""
    pkts = []
    bgp_sess, tcp = _session_for_node(scenario, node_id)
    if tcp and tcp.is_established():
        pkts = tcp.close_reset(timestamp=t, initiator='server')
    return pkts, t + 0.01


def _reconnect_session(scenario: BaseScenario, bgp_sess, t: float):
    """Full BGP session re-establishment.  Returns packets + new timestamp."""
    pkts = []
    pe = bgp_sess.local_router
    rr = bgp_sess.remote_router
    new_tcp = TCPSession(client_ip=pe.bgp_id, server_ip=rr.bgp_id, server_port=179)
    scenario.tcp_sessions[bgp_sess.session_id] = new_tcp

    pkts.extend(new_tcp.connect(timestamp=t)); t += 0.02

    for direction, router, ack_dir in [
        ('client_to_server', pe, 'server_to_client'),
        ('server_to_client', rr, 'client_to_server'),
    ]:
        open_msg = build_open(scenario.config.as_number, scenario.config.timing.hold_timer,
                              router.bgp_id, default_evpn_capabilities(scenario.config.as_number))
        pkts.extend(new_tcp.send_data(open_msg, t, direction))
        t += ack_delay()
        pkts.extend(new_tcp.generate_ack(t, ack_dir))
        t += 0.005

    ka = build_keepalive()
    pkts.extend(new_tcp.send_data(ka, t, 'client_to_server'))
    pkts.extend(new_tcp.send_data(ka, t + 0.001, 'server_to_client'))
    t += 0.01
    return pkts, t


def _fill_to_target(scenario: BaseScenario, packets, t: float):
    """Append keepalives until target_frames is reached."""
    remaining = int(scenario.target_frames * 0.26) - len(packets)
    if remaining > 0:
        dur = max(120, (remaining / max(len(scenario.tcp_sessions) * 4, 1))
                  * scenario.config.timing.keepalive_timer)
        packets.extend(scenario.generate_keepalives_for_duration(t, dur))

    # Pad with pure TCP window-update frames to reach target_frames
    pad_count = scenario.target_frames - len(packets)
    if pad_count > 0:
        pad_pkts = scenario.generate_tcp_window_updates(t, dur, pad_count)
        packets.extend(pad_pkts)

    packets.sort(key=lambda p: p.timestamp)
    return packets[:scenario.target_frames]


def _std_preamble(scenario: BaseScenario, warmup_seconds=None):
    """Setup + initial routes + warmup.  Returns (packets, t_after_warmup).

    warmup_seconds is randomised per-call (120–480s) so the model cannot
    learn fault timing from absolute position in the capture.
    """
    import random
    if warmup_seconds is None:
        warmup_seconds = random.randint(120, 480)
    packets = []
    t = scenario.start_time
    setup_pkts, t = scenario.establish_all_sessions(t)
    packets.extend(setup_pkts)
    init_pkts, t = scenario.generate_initial_routes(t)
    packets.extend(init_pkts)
    packets.extend(scenario.generate_keepalives_for_duration(t, warmup_seconds))
    t += warmup_seconds
    return packets, t


# ===========================================================================
# A. NEW FAULT TYPES
# ===========================================================================

# ---------------------------------------------------------------------------
# A1. AS Misconfiguration — OPEN error code 2, subcode 2
#     PE reconnects with wrong ASN; RR rejects with Bad Peer AS.
# ---------------------------------------------------------------------------

# class ASMisconfigScenario(BaseScenario):
#     """PE session reset then reconnects with wrong ASN.

#     BGP signal: 1 OPEN from PE (wrong AS), 1 NOTIFICATION (code 2 / sub 2).
#     Session stays down — no recovery.
#     """
#     FAULT_TYPE: str = 'AS Misconfig'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None, wrong_asn: int = 64999):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         self.wrong_asn = wrong_asn

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             rst_pkts, t = _reset_session(self, self.affected_pe_id, t)
#             packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#             pe = bgp_sess.local_router
#             rr = bgp_sess.remote_router
#             bad_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)

#             packets.extend(bad_tcp.connect(timestamp=t)); t += 0.02
#             bad_open = build_open(self.wrong_asn, self.config.timing.hold_timer,
#                                   pe.bgp_id, default_evpn_capabilities(self.wrong_asn))
#             packets.extend(self._mark_event(bad_tcp.send_data(bad_open, t, 'client_to_server'), self.FAULT_TYPE, self.affected_pe_id, 'BGP OPEN'))
#             t += ack_delay()
#             packets.extend(bad_tcp.generate_ack(t, 'server_to_client'))
#             t += 0.01

#             notif = build_notification(ERR_OPEN_MSG, OPEN_BAD_PEER_AS)
#             packets.extend(self._mark_event(bad_tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Bad Peer AS'))
#             t += 0.001
#             packets.extend(self._mark_event(bad_tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class ASMisconfigPE1(ASMisconfigScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1', wrong_asn=64999)

# class ASMisconfigPE3(ASMisconfigScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE3', wrong_asn=65111)


# ---------------------------------------------------------------------------
# A2. Hold Timer Mismatch — OPEN error code 2, subcode 6
#     PE proposes hold_time=1 (below BGP minimum of 3); RR rejects.
# ---------------------------------------------------------------------------

# class HoldTimerMismatchScenario(BaseScenario):
#     """PE reconnects proposing hold_time=1; RR sends Unacceptable Hold Time."""
#     FAULT_TYPE: str = 'Hold Timer Mismatch'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[1].id

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             rst_pkts, t = _reset_session(self, self.affected_pe_id, t)
#             packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#             pe = bgp_sess.local_router
#             rr = bgp_sess.remote_router
#             bad_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)

#             packets.extend(bad_tcp.connect(timestamp=t)); t += 0.02
#             bad_open = build_open(self.config.as_number, 1,  # hold_time=1, invalid
#                                   pe.bgp_id, default_evpn_capabilities(self.config.as_number))
#             packets.extend(self._mark_event(bad_tcp.send_data(bad_open, t, 'client_to_server'), self.FAULT_TYPE, self.affected_pe_id, 'BGP OPEN'))
#             t += ack_delay()
#             packets.extend(bad_tcp.generate_ack(t, 'server_to_client'))
#             t += 0.01

#             notif = build_notification(ERR_OPEN_MSG, OPEN_UNACCEPTABLE_HOLD_TIME)
#             packets.extend(self._mark_event(bad_tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Unacceptable Hold Time'))
#             t += 0.001
#             packets.extend(self._mark_event(bad_tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class HoldTimerMismatchPE2(HoldTimerMismatchScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# A3. Max Prefix Limit — CEASE code 6, subcode 1
#     PE floods routes; RR hits prefix limit and sends CEASE.
# ---------------------------------------------------------------------------

# class MaxPrefixLimitScenario(BaseScenario):
#     """RR hits max-prefix limit after PE sends too many EVPN routes."""
#     FAULT_TYPE: str = 'Max Prefix'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None, flood_count: int = 150):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         self.flood_count = flood_count

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             pe = bgp_sess.local_router
#             timestamps = route_burst_timestamps(t, self.flood_count)

#             for i, ts in enumerate(timestamps):
#                 mac = f"00:ff:ee:{(i >> 16) & 0xff:02x}:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}"
#                 nlri = evpn.build_mac_ip_route(
#                     pe.bgp_id, pe.esi or "0", mac,
#                     ip=f"10.{(i >> 8) & 0xff}.{i & 0xff}.1",
#                     vni=self.config.evpn.vni)
#                 path_attrs = build_standard_evpn_path_attrs(
#                     pe.loopback, nlri, self.config.as_number, self.config.evpn.vni,
#                     originator_id=pe.bgp_id, cluster_id=bgp_sess.remote_router.bgp_id)
#                 update = build_update(path_attributes=path_attrs)
#                 packets.extend(self._mark_event(tcp.send_data(update, ts, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))
#                 packets.extend(tcp.generate_ack(ts + ack_delay(), 'client_to_server'))

#             t = timestamps[-1] + 0.1

#             notif = build_notification(ERR_CEASE, CEASE_MAX_PREFIXES)
#             packets.extend(self._mark_event(tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Cease/Max Prefixes Reached'))
#             t += 0.001
#             packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class MaxPrefixLimitPE1(MaxPrefixLimitScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1')


# ---------------------------------------------------------------------------
# A4. Admin Reset — CEASE code 6, subcode 4
#     Operator clears a BGP session; session restarts cleanly.
# ---------------------------------------------------------------------------

# class AdminResetScenario(BaseScenario):
#     """BGP session cleared by operator; session re-establishes after reset."""
#     FAULT_TYPE: str = 'Admin Reset'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 30000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[1].id

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             notif = build_notification(ERR_CEASE, CEASE_ADMIN_RESET)
#             packets.extend(self._mark_event(tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Cease/Administrative Reset'))
#             t += 0.001
#             packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 2.0

#             reconn_pkts, t = _reconnect_session(self, bgp_sess, t)
#             packets.extend(reconn_pkts)

#             route_pkts = self.generate_route_updates(
#                 bgp_sess.session_id,
#                 bgp_sess.local_router,
#                 num_routes=random.randint(5, 10),
#                 start_time=t)
#             packets.extend(route_pkts)
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = t
#         return _fill_to_target(self, packets, t)


# class AdminResetPE2(AdminResetScenario):
#     def __init__(self, config, target_frames=30000):
#         super().__init__(config, target_frames, affected_pe='PE2')

# class AdminResetPE3(AdminResetScenario):
#     def __init__(self, config, target_frames=30000):
#         super().__init__(config, target_frames, affected_pe='PE3')


# ---------------------------------------------------------------------------
# A5. Peer De-configured — CEASE code 6, subcode 3
#     PE removed from RR's neighbor config; session torn down permanently.
# ---------------------------------------------------------------------------

# class PeerDeConfigScenario(BaseScenario):
#     """RR removes PE from neighbor config; CEASE Peer De-configured sent."""
#     FAULT_TYPE: str = 'Peer Deconfig'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             notif = build_notification(ERR_CEASE, CEASE_PEER_DECONFIGURED)
#             packets.extend(self._mark_event(tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Cease/Peer De-configured'))
#             t += 0.001
#             packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class PeerDeConfigPE1(PeerDeConfigScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1')


# ---------------------------------------------------------------------------
# A6. Invalid NEXT_HOP — UPDATE error code 3, subcode 8
#     PE advertises routes with unreachable next-hop; RR sends UPDATE error.
# ---------------------------------------------------------------------------

# class InvalidNextHopScenario(BaseScenario):
#     """PE sends UPDATEs with unreachable next-hop; RR rejects with UPDATE error."""
#     FAULT_TYPE: str = 'Invalid Next Hop'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         self.bad_nexthop = "2001:db8::dead:1"  # Documentation range — unreachable (RFC 3849)

#     def _build_bad_nexthop_attrs(self, nlri_bytes: bytes) -> bytes:
#         rt_val = int(self.config.evpn.route_target.split(':')[1])
#         rt_asn = int(self.config.evpn.route_target.split(':')[0])
#         rt = encode_rt_community(rt_asn, rt_val)
#         encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
#         attrs = b''
#         attrs += attr_origin(0)
#         attrs += attr_as_path()
#         attrs += attr_local_pref(100)
#         attrs += attr_extended_communities([rt, encap])
#         attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, self.bad_nexthop, nlri_bytes)
#         return attrs

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             pe = bgp_sess.local_router
#             macs = self.topology.get_macs_for_pe(
#                 self.affected_pe_id,
#                 count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
#                                       int(self.config.evpn.mac_pool_size * 0.5)))
#             timestamps = route_burst_timestamps(t, len(macs))

#             for mac_entry, ts in zip(macs, timestamps):
#                 nlri = evpn.build_mac_ip_route(
#                     pe.bgp_id, pe.esi or "0", mac_entry.mac,
#                     ip=mac_entry.ip, vni=self.config.evpn.vni)
#                 path_attrs = self._build_bad_nexthop_attrs(nlri)
#                 update = build_update(path_attributes=path_attrs)
#                 packets.extend(self._mark_event(tcp.send_data(update, ts, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))
#                 packets.extend(tcp.generate_ack(ts + ack_delay(), 'client_to_server'))

#             t = timestamps[-1] + 0.1

#             notif = build_notification(ERR_UPDATE_MSG, UPDATE_INVALID_NEXT_HOP)
#             packets.extend(self._mark_event(tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Invalid Next Hop'))
#             t += 0.001
#             packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class InvalidNextHopPE1(InvalidNextHopScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1')

# class InvalidNextHopPE3(InvalidNextHopScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE3')


# ---------------------------------------------------------------------------
# A7. Duplicate MAC — EVPN MAC Mobility conflict
#     Two PEs claim the same MAC with escalating sequence numbers.
# ---------------------------------------------------------------------------

# class DuplicateMACScenario(BaseScenario):
#     """Two PEs advertise the same MAC causing MAC mobility storm.

#     BGP signal: multiple Type-2 UPDATEs with same MAC but different next-hops
#     and incrementing MAC-Mobility extended community sequence numbers.
#     No NOTIFICATION — purely UPDATE anomaly pattern.
#     """
#     FAULT_TYPE: str = 'Duplicate MAC'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  pe_a: str = None, pe_b: str = None):
#         super().__init__(config, target_frames)
#         self.pe_a_id = pe_a or config.pe_nodes[0].id
#         self.pe_b_id = pe_b or config.pe_nodes[2].id
#         self.conflict_mac = "00:de:ad:be:ef:01"
#         self.conflict_ip = "10.100.1.1"

#     def _mac_mobility_attr(self, sequence: int, sticky: bool = False) -> bytes:
#         """Build MAC Mobility extended community (RFC 7432 §7.7)."""
#         return encode_mac_mobility_community(sequence, sticky)

#     def _build_attrs_with_mobility(self, pe_router, nlri_bytes: bytes,
#                                     sequence: int) -> bytes:
#         rt_parts = self.config.evpn.route_target.split(':')
#         rt = encode_rt_community(int(rt_parts[0]), int(rt_parts[1]))
#         encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
#         mobility = self._mac_mobility_attr(sequence)
#         attrs = b''
#         attrs += attr_origin(0)
#         attrs += attr_as_path()
#         attrs += attr_local_pref(100)
#         attrs += attr_extended_communities([rt, encap, mobility])
#         attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.loopback, nlri_bytes)
#         return attrs

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         bgp_a, tcp_a = _session_for_node(self, self.pe_a_id)
#         bgp_b, tcp_b = _session_for_node(self, self.pe_b_id)

#         if not (bgp_a and bgp_b):
#             return _fill_to_target(self, packets, t)

#         pe_a = bgp_a.local_router
#         pe_b = bgp_b.local_router

#         fault_start_t = t
#         # 10 rounds of MAC mobility ping-pong
#         for seq in range(1, 11):
#             # PE-A claims the MAC (odd sequences)
#             if seq % 2 == 1 and tcp_a and tcp_a.is_established():
#                 nlri = evpn.build_mac_ip_route(
#                     pe_a.bgp_id, pe_a.esi or "0",
#                     self.conflict_mac, ip=self.conflict_ip,
#                     vni=self.config.evpn.vni)
#                 path_attrs = self._build_attrs_with_mobility(pe_a, nlri, seq)
#                 update = build_update(path_attributes=path_attrs)
#                 packets.extend(self._mark_event(tcp_a.send_data(update, t, 'server_to_client'), self.FAULT_TYPE, self.pe_a_id, 'Route UPDATE'))
#                 packets.extend(tcp_a.generate_ack(t + ack_delay(), 'client_to_server'))
#             # PE-B counter-claims (even sequences)
#             elif tcp_b and tcp_b.is_established():
#                 nlri = evpn.build_mac_ip_route(
#                     pe_b.bgp_id, pe_b.esi or "0",
#                     self.conflict_mac, ip=self.conflict_ip,
#                     vni=self.config.evpn.vni)
#                 path_attrs = self._build_attrs_with_mobility(pe_b, nlri, seq)
#                 update = build_update(path_attributes=path_attrs)
#                 packets.extend(self._mark_event(tcp_b.send_data(update, t, 'server_to_client'), self.FAULT_TYPE, self.pe_b_id, 'Route UPDATE'))
#                 packets.extend(tcp_b.generate_ack(t + ack_delay(), 'client_to_server'))

#             t += random.uniform(0.5, 2.0)

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = t
#         return _fill_to_target(self, packets, t)


# class DuplicateMACPE1PE3(DuplicateMACScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, pe_a='PE1', pe_b='PE3')


# ---------------------------------------------------------------------------
# A8. VNI Mismatch — wrong VNI in VXLAN encapsulation extended community
#     Silent data-plane fault: routes accepted but traffic black-holed.
# ---------------------------------------------------------------------------

# class VNIMismatchScenario(BaseScenario):
#     """PE advertises routes with a wrong VNI in the route's MPLS Label
#     field.

#     Per RFC 5512, the Encapsulation Extended Community only carries the
#     Tunnel Type (e.g. VXLAN=8); it has no VNI field at all. In EVPN-VXLAN
#     the VNI is instead carried in the NLRI's MPLS Label field, repurposed
#     as a 24-bit VNI (RFC 8365 SS5.1.1). So a real VNI mismatch corrupts
#     that label field -- the Encapsulation Extended Community's Tunnel
#     Type is correct and unmodified here.

#     No NOTIFICATION — purely silent UPDATE anomaly. Model must detect the
#     wrong VNI value in the label field of received UPDATEs.
#     """
#     FAULT_TYPE: str = 'VNI Mismatch'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None, wrong_vni: int = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[1].id
#         self.wrong_vni = wrong_vni or (config.evpn.vni + 9999)

#     def _build_wrong_vni_attrs(self, pe_router, nlri_bytes: bytes) -> bytes:
#         rt_parts = self.config.evpn.route_target.split(':')
#         rt = encode_rt_community(int(rt_parts[0]), int(rt_parts[1]))
#         encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
#         attrs = b''
#         attrs += attr_origin(0)
#         attrs += attr_as_path()
#         attrs += attr_local_pref(100)
#         attrs += attr_extended_communities([rt, encap])
#         attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.loopback, nlri_bytes)
#         return attrs

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             pe = bgp_sess.local_router
#             macs = self.topology.get_macs_for_pe(
#                 self.affected_pe_id,
#                 count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
#                                       int(self.config.evpn.mac_pool_size * 0.5)))
#             timestamps = route_burst_timestamps(t, len(macs))

#             for mac_entry, ts in zip(macs, timestamps):
#                 # Wrong VNI in the label field (the actual VNI-carrying
#                 # field), not the encapsulation community.
#                 nlri = evpn.build_mac_ip_route(
#                     pe.bgp_id, pe.esi or "0", mac_entry.mac,
#                     ip=mac_entry.ip, vni=self.wrong_vni)
#                 path_attrs = self._build_wrong_vni_attrs(pe, nlri)
#                 update = build_update(path_attributes=path_attrs)
#                 packets.extend(self._mark_event(tcp.send_data(update, ts, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))
#                 packets.extend(tcp.generate_ack(ts + ack_delay(), 'client_to_server'))

#             t = timestamps[-1] + 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = t
#         return _fill_to_target(self, packets, t)


# class VNIMismatchPE2(VNIMismatchScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# A9. FSM Error — code 5, subcode 3
#     Session receives unexpected UPDATE while in OPEN-sent state.
# ---------------------------------------------------------------------------

# class FSMErrorScenario(BaseScenario):
#     """Simulates FSM error: UPDATE sent before OPEN handshake completes.

#     Pattern: existing session reset, PE reconnects, UPDATE injected
#     before KEEPALIVE confirms the OPEN, RR sends FSM error NOTIFICATION.
#     """
#     FAULT_TYPE: str = 'FSM Error'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[1].id

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             rst_pkts, t = _reset_session(self, self.affected_pe_id, t)
#             packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#             pe = bgp_sess.local_router
#             rr = bgp_sess.remote_router
#             bad_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)

#             packets.extend(bad_tcp.connect(timestamp=t)); t += 0.02

#             # PE sends OPEN
#             open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                   pe.bgp_id, default_evpn_capabilities(self.config.as_number))
#             packets.extend(bad_tcp.send_data(open_msg, t, 'client_to_server'))
#             t += ack_delay()
#             packets.extend(bad_tcp.generate_ack(t, 'server_to_client'))
#             t += 0.005

#             # Inject UPDATE before OPEN completes (state machine violation).
#             # At this point RR has only received PE's OPEN -- neither side
#             # has sent a KEEPALIVE, so RR is still in OpenSent state per
#             # RFC 4271 SS8.2.1 (KEEPALIVE is what transitions OpenSent ->
#             # OpenConfirm), not yet Established. RFC 6608 subcode 1
#             # ("Unexpected Message in OpenSent State") is the correct
#             # subcode for this violation, not subcode 3 (Established).
#             macs = self.topology.get_macs_for_pe(self.affected_pe_id, count=1)
#             if macs:
#                 nlri = evpn.build_mac_ip_route(
#                     pe.bgp_id, pe.esi or "0", macs[0].mac,
#                     ip=macs[0].ip, vni=self.config.evpn.vni)
#                 path_attrs = build_standard_evpn_path_attrs(
#                     pe.loopback, nlri, self.config.as_number, self.config.evpn.vni)
#                 bad_update = build_update(path_attributes=path_attrs)
#                 packets.extend(self._mark_event(bad_tcp.send_data(bad_update, t, 'client_to_server'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))
#                 t += 0.005

#             # RR responds with FSM error
#             notif = build_notification(ERR_FSM, FSM_UNEXPECTED_MSG_OPEN_SENT)
#             packets.extend(self._mark_event(bad_tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: FSM Error/Unexpected Message in OpenSent'))
#             t += 0.001
#             packets.extend(self._mark_event(bad_tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class FSMErrorPE1(FSMErrorScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1')

# class FSMErrorPE3(FSMErrorScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE3')


# ---------------------------------------------------------------------------
# A10. Malformed AS_PATH — UPDATE error code 3, subcode 11
#      UPDATE with corrupt/loop-creating AS_PATH; RR rejects.
# ---------------------------------------------------------------------------

# class MalformedASPathScenario(BaseScenario):
#     """PE sends UPDATE with malformed AS_PATH; RR returns UPDATE error."""
#     FAULT_TYPE: str = 'Malformed AS Path'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[3].id

#     def _build_malformed_aspath_update(self, pe_router) -> bytes:
#         """Build UPDATE with an AS_PATH containing garbage bytes."""
#         rt_parts = self.config.evpn.route_target.split(':')
#         rt = encode_rt_community(int(rt_parts[0]), int(rt_parts[1]))
#         encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)

#         nlri = evpn.build_imet_route(pe_router.bgp_id, pe_router.loopback, self.config.evpn.vni)

#         # Malformed AS_PATH: type=2 (AS_SEQUENCE) but truncated length
#         malformed_aspath = struct.pack('!BBBB', 0x40, 0x02, 0xff, 0x01)  # length=255 but only 1 byte follows

#         attrs = b''
#         attrs += attr_origin(0)
#         attrs += malformed_aspath
#         attrs += attr_local_pref(100)
#         attrs += attr_extended_communities([rt, encap])
#         attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.loopback, nlri)
#         return build_update(path_attributes=attrs)

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
#         if tcp and tcp.is_established():
#             pe = bgp_sess.local_router
#             bad_update = self._build_malformed_aspath_update(pe)
#             packets.extend(self._mark_event(tcp.send_data(bad_update, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))
#             t += ack_delay()
#             packets.extend(tcp.generate_ack(t, 'client_to_server'))
#             t += 0.01

#             notif = build_notification(ERR_UPDATE_MSG, UPDATE_MALFORMED_ASPATH)
#             packets.extend(self._mark_event(tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Malformed AS_PATH'))
#             t += 0.001
#             packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class MalformedASPathPE2(MalformedASPathScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# A11. Out of Resources — CEASE code 6, subcode 8
#      RR memory-exhausted; drops ALL PE sessions simultaneously.
# ---------------------------------------------------------------------------

# class OutOfResourcesScenario(BaseScenario):
#     """RR sends CEASE/Out-of-Resources to all connected PEs simultaneously.

#     Simulates RR memory or table exhaustion — all sessions drop at once.
#     NOTIFICATION count equals the number of active sessions (5 for 5 PEs).
#     """
#     FAULT_TYPE: str = 'Out of Resources'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_rr: str = 'RR1'):
#         super().__init__(config, target_frames)
#         self.affected_rr = affected_rr

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         notif = build_notification(ERR_CEASE, CEASE_OUT_OF_RESOURCES)
#         # Match only genuine PE-RR sessions terminating at the affected RR
#         # (topology-role based, not "self.affected_rr in session_id" -- that
#         # substring match also caught the RR1-RR2 session itself, silently
#         # producing a 6th NOTIFICATION/RST against the peer RR contrary to
#         # this class's own documented "5 for 5 PEs" invariant).
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if not (bgp_sess.local_router.role == 'pe'
#                     and bgp_sess.remote_router.role == 'rr'
#                     and bgp_sess.remote_router.id == self.affected_rr):
#                 continue
#             tcp = self.tcp_sessions.get(bgp_sess.session_id)
#             if tcp and tcp.is_established():
#                 packets.extend(self._mark_event(tcp.send_data(notif, t, 'server_to_client'), self.FAULT_TYPE, self.affected_rr, 'BGP NOTIFICATION: Cease/Out of Resources'))
#                 t += 0.002
#                 packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='server'), self.FAULT_TYPE, self.affected_rr, 'TCP RST'))
#                 t += 0.01

#         t += 1.0
#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class OutOfResourcesRR1(OutOfResourcesScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_rr='RR1')

# class OutOfResourcesRR2(OutOfResourcesScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_rr='RR2')


# ---------------------------------------------------------------------------
# A12. Address-Family Mismatch — silent EVPN failure
#      One peer's OPEN omits the L2VPN/EVPN AFI/SAFI; the BGP session
#      establishes normally but EVPN routes are never exchanged on it.
# ---------------------------------------------------------------------------

# class AFMismatchScenario(BaseScenario):
#     """Affected PE's OPEN omits AFI=25/SAFI=70; session establishes but
#     carries zero EVPN UPDATEs -- a silent failure with no NOTIFICATION.

#     All other PE sessions establish normally and exchange EVPN routes as
#     usual; only the affected session is capability-limited.
#     """
#     FAULT_TYPE: str = 'AF Mismatch'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         self.first_affected_keepalive_t = None

#     def _establish_sessions_with_af_mismatch(self, timestamp: float):
#         """Establish all sessions, but the affected PE's OPEN advertises a
#         reduced capability set (no MP-BGP, no Graceful Restart) so its EVPN
#         AFI/SAFI is never negotiated. Mirrors BaseScenario.establish_all_sessions()
#         except for this per-session capability override.
#         """
#         packets = []
#         t = timestamp
#         vantage = self.config.capture_vantage
#         sessions = self.topology.get_sessions_at_vantage(vantage)

#         for bgp_session in sessions:
#             pe = bgp_session.local_router
#             rr = bgp_session.remote_router

#             tcp_sess = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)
#             self.tcp_sessions[bgp_session.session_id] = tcp_sess

#             pkts = tcp_sess.connect(timestamp=t)
#             packets.extend(pkts)
#             t += 0.01

#             is_affected = (pe.id == self.affected_pe_id)
#             pe_caps = ([cap_4byte_as(self.config.as_number), cap_route_refresh()]
#                        if is_affected else default_evpn_capabilities(self.config.as_number))

#             open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                   pe.bgp_id, pe_caps)
#             pkts = tcp_sess.send_data(open_msg, timestamp=t, direction='client_to_server')
#             packets.extend(pkts)
#             t += ack_delay()
#             packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
#             t += 0.005

#             open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                   rr.bgp_id, default_evpn_capabilities(self.config.as_number))
#             pkts = tcp_sess.send_data(open_msg, timestamp=t, direction='server_to_client')
#             packets.extend(pkts)
#             t += ack_delay()
#             packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
#             t += 0.002

#             ka = build_keepalive()
#             pkts = tcp_sess.send_data(ka, timestamp=t, direction='client_to_server')
#             packets.extend(pkts)
#             if is_affected and pkts:
#                 self.first_affected_keepalive_t = pkts[0].timestamp
#             t += ack_delay()
#             packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
#             t += 0.001

#             pkts = tcp_sess.send_data(ka, timestamp=t, direction='server_to_client')
#             packets.extend(pkts)
#             t += ack_delay()
#             packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

#             t += 0.05

#         return packets, t

#     def generate(self) -> list[TCPPacket]:
#         packets = []
#         t = self.start_time

#         setup_pkts, t = self._establish_sessions_with_af_mismatch(t)
#         packets.extend(setup_pkts)

#         # Hide the affected session while generating initial routes so it
#         # gets zero EVPN routes (and zero EoR marker) -- exactly what a
#         # session with no negotiated EVPN AFI/SAFI would see.
#         affected_bgp_sess, _ = _session_for_node(self, self.affected_pe_id)
#         saved_tcp = None
#         if affected_bgp_sess:
#             saved_tcp = self.tcp_sessions.pop(affected_bgp_sess.session_id, None)

#         init_pkts, t = self.generate_initial_routes(t)
#         packets.extend(init_pkts)

#         if affected_bgp_sess and saved_tcp is not None:
#             self.tcp_sessions[affected_bgp_sess.session_id] = saved_tcp

#         # The affected session only ever exchanges KEEPALIVEs from here on.
#         warmup_duration = random.randint(120, 480)
#         packets.extend(self.generate_keepalives_for_duration(t, warmup_duration))
#         t += warmup_duration

#         self._fault_start_t = self.first_affected_keepalive_t
#         self._fault_end_t = None

#         return _fill_to_target(self, packets, t)


# class AFMismatchPE1(AFMismatchScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1')

# class AFMismatchPE3(AFMismatchScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE3')


# ---------------------------------------------------------------------------
# A13. Graceful Restart (RFC 4724) — session drops but routes are NOT
#      immediately withdrawn; PE reconnects and re-advertises within the
#      restart timer. Must be distinguishable from a hard Link Down.
# ---------------------------------------------------------------------------

# class GracefulRestartScenario(BaseScenario):
#     """Affected PE's session drops abruptly (TCP RST) with no EVPN
#     WITHDRAWs, then reconnects and re-advertises its routes.

#     This is the single most important distinguishing feature from Link
#     Down: routes are kept as stale (not withdrawn) across the outage.

#     If gr_timeout=True, the PE never reconnects; once the GR restart
#     timer (120s) elapses, its stale routes are purged (WITHDRAWs sent on
#     surviving sessions) and the fault is left unresolved (_fault_end_t=None).
#     """
#     FAULT_TYPE: str = 'Graceful Restart'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None, gr_timeout: bool = False):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         self.gr_timeout = gr_timeout

#     def generate(self) -> list[TCPPacket]:
#         packets = []
#         t = self.start_time

#         setup_pkts, t = self.establish_all_sessions(t)
#         packets.extend(setup_pkts)

#         init_pkts, t = self.generate_initial_routes(t)
#         packets.extend(init_pkts)

#         warmup_duration = random.randint(120, 300)
#         packets.extend(self.generate_keepalives_for_duration(t, warmup_duration))
#         t += warmup_duration

#         affected_session, _ = _session_for_node(self, self.affected_pe_id)
#         if not affected_session:
#             self._fault_start_t = None
#             self._fault_end_t = None
#             return _fill_to_target(self, packets, t)

#         tcp_sess = self.tcp_sessions[affected_session.session_id]

#         # RESTART EVENT: abrupt TCP RST simulating a process restart.
#         # CRITICAL: no EVPN WITHDRAWs here -- this is what distinguishes
#         # Graceful Restart from Link Down.
#         fault_start_t = t
#         rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
#         packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#         t += random.uniform(2, 8)

#         if self.gr_timeout:
#             # GR restart timer elapses without reconnection -> stale
#             # routes are purged on the surviving sessions.
#             t += 120
#             pe = affected_session.local_router
#             withdraw_pkts = self._withdraw_pe_routes(pe, t, event=True)
#             packets.extend(withdraw_pkts)
#             t += 0.1

#             self._fault_start_t = fault_start_t
#             self._fault_end_t = None
#             return _fill_to_target(self, packets, t)

#         # RECONNECTION: new TCP session + OPEN with GR restart-state bit set.
#         recon_pkts, t = self._reconnect_with_gr(affected_session, t)
#         packets.extend(recon_pkts)

#         # ROUTE RE-ADVERTISEMENT restricted to the affected session; the
#         # EoR marker is emitted automatically at the end of
#         # generate_initial_routes() (see base.py _generate_eor_markers()).
#         saved_sessions = dict(self.tcp_sessions)
#         for sid in list(self.tcp_sessions):
#             if sid != affected_session.session_id:
#                 del self.tcp_sessions[sid]
#         reroute_pkts, t = self.generate_initial_routes(t)
#         self.tcp_sessions = saved_sessions
#         packets.extend(self._mark_event(reroute_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))

#         fault_end_t = t + self.BASELINE_CHECK_WINDOW
#         self._fault_start_t = fault_start_t
#         self._fault_end_t = fault_end_t

#         remaining = int(self.target_frames * 0.26) - len(packets)
#         if remaining > 0:
#             dur = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
#                       * self.config.timing.keepalive_timer)
#             packets.extend(self.generate_keepalives_for_duration(t, dur))
#             t += dur

#         # Pad with pure TCP window-update frames to reach target_frames
#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, dur, pad_count)
#             packets.extend(pad_pkts)

#         packets.sort(key=lambda p: p.timestamp)
#         return packets[:self.target_frames]

#     def _reconnect_with_gr(self, affected_session, t: float):
#         """New TCP session + OPEN advertising Graceful Restart with the
#         Restart State bit set and the EVPN AFI/SAFI Forwarding State bit set.
#         """
#         packets = []
#         pe = affected_session.local_router
#         rr = affected_session.remote_router

#         new_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)
#         self.tcp_sessions[affected_session.session_id] = new_tcp

#         connect_pkts = new_tcp.connect(timestamp=t)
#         packets.extend(connect_pkts)
#         t += 0.02

#         # is_restart=True: this OPEN is the actual post-restart reconnect --
#         # the one case where the Restart State bit should be set.
#         gr_caps = [
#             cap_multiprotocol(AFI_L2VPN, SAFI_EVPN),
#             cap_4byte_as(self.config.as_number),
#             cap_route_refresh(),
#             cap_graceful_restart(120, [(AFI_L2VPN, SAFI_EVPN, 0x80)], is_restart=True),
#         ]
#         open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                               pe.bgp_id, gr_caps)
#         pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
#         packets.extend(pkts)
#         t += ack_delay()
#         packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
#         t += 0.005

#         open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                               rr.bgp_id, default_evpn_capabilities(self.config.as_number))
#         pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
#         packets.extend(pkts)
#         t += ack_delay()
#         packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
#         t += 0.002

#         ka = build_keepalive()
#         pkts = new_tcp.send_data(ka, t, 'client_to_server')
#         packets.extend(pkts)
#         t += ack_delay()
#         packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
#         t += 0.001
#         pkts = new_tcp.send_data(ka, t, 'server_to_client')
#         packets.extend(pkts)
#         t += ack_delay()
#         packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
#         t += 0.01

#         return packets, t

#     def _withdraw_pe_routes(self, pe, timestamp: float, event: bool = False) -> list[TCPPacket]:
#         """Surviving sessions withdraw ALL of the timed-out PE's stale
#         routes, per RFC 4271 SS9.2 -- not just Type 2 MAC/IP. Mirrors
#         link_down.py's _withdraw_pe_routes_direct() completeness (Type 3
#         IMET always; Type 1/4 for multihomed PEs only).
#         """
#         packets = []
#         macs = self.topology.get_macs_for_pe(
#             pe.id,
#             count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
#                                   int(self.config.evpn.mac_pool_size * 0.5)))
#         nlris = [evpn.build_mac_ip_route(
#             pe.bgp_id, pe.esi or "0", mac_entry.mac,
#             ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
#         nlris.append(evpn.build_imet_route(pe.bgp_id, pe.loopback, self.config.evpn.vni))
#         if pe.esi and pe.esi != "0":
#             nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
#             nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
#                                                 vni=self.config.evpn.vni))
#             nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.loopback,
#                                              self.config.evpn.vni))

#         for session_id, tcp_sess in self.tcp_sessions.items():
#             if pe.id in session_id or not tcp_sess.is_established():
#                 continue
#             for nlri in nlris:
#                 path_attrs = build_evpn_withdraw_attrs(nlri)
#                 update = build_update(path_attributes=path_attrs)
#                 pkts = tcp_sess.send_data(update, timestamp=timestamp, direction='server_to_client')
#                 packets.extend(pkts)
#                 timestamp += 0.005
#                 packets.extend(tcp_sess.generate_ack(timestamp, 'client_to_server'))
#                 timestamp += 0.001

#         if event:
#             self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE')
#         return packets


# class GracefulRestartPE1(GracefulRestartScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE1', gr_timeout=False)

# class GracefulRestartPE3(GracefulRestartScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE3', gr_timeout=False)

# class GracefulRestartTimeoutPE2(GracefulRestartScenario):
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, affected_pe='PE2', gr_timeout=True)


# # ===========================================================================
# # B. MISSING PAIRWISE COMBINATIONS
# # ===========================================================================

# ---------------------------------------------------------------------------
# B1. RR Down + ESDF Toggle
#     RR session drops at the same time ESDF election instability starts.
# ---------------------------------------------------------------------------

class RRDownESDFScenario(BaseScenario):
    """RR session RST concurrent with ESDF/DF election storm on a PE.

    affected_pe MUST be a real multihomed PE (PE1 or PE2 in this topology)
    -- ES/DF toggling is only meaningful for a PE that actually shares an
    ESI with a peer.

    Note: this class's own primary ESDF withdraw/advertise events build
    Type-1 (build_ead_per_es) rather than the Type-4 ES route.
    """
    FAULT_TYPE: str = 'RR Down + ESDF Toggle'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_rr: str = 'RR1', affected_pe: str = None):
        super().__init__(config, target_frames)
        self.affected_rr = affected_rr
        self.affected_pe_id = affected_pe or config.pe_nodes[0].id
        pe = config.get_router(self.affected_pe_id)
        if not pe or not pe.esi:
            raise ValueError(
                f"PE {self.affected_pe_id} is not multihomed in this topology, "
                "cannot resolve ES/DF peer")

    def generate(self) -> list[TCPPacket]:
        packets, t = _std_preamble(self)

        fault_start_t = t
        # FAULT 1: RR session drops. Matches by topology role (not a
        # session-id substring match, which would also match PE-RR sessions).
        # affected_rr_id is the RR that is NOT the capture vantage.
        self.affected_rr_id = next(rr.id for rr in self.config.route_reflectors
                                   if rr.id != self.config.capture_vantage)
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                tcp = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp and tcp.is_established():
                    packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='client'), 'RR Down', self.affected_rr_id, 'TCP RST', phase='trigger'))
                break

        t += 1.0

        # RFC 4271 SS9.2 / RFC 4456 second hop: the vantage RR lost its only
        # path to the affected RR's clients' routes and must withdraw them
        # toward its own clients. Borrowed as an unbound method from
        # RRDownCleanRestart (rr_down.py).
        _saved_fault_type, self.FAULT_TYPE = self.FAULT_TYPE, 'RR Down'
        wd_pkts, t = RRDownCleanRestart._second_hop_withdraw_affected_rr_clients(self, t)
        self.FAULT_TYPE = _saved_fault_type
        packets.extend(wd_pkts)

        # FAULT 2: ESDF toggling — burst of Type 1 A-D per ES withdrawals +
        # re-advertisements, the mass-withdraw trigger signal per RFC 7432
        # SS8.2 / RFC 8584. Type 4 follows passively as a consequence, not
        # as the trigger.
        bgp_sess, tcp = _session_for_node(self, self.affected_pe_id)
        if bgp_sess and tcp and tcp.is_established():
            pe = bgp_sess.local_router
            # esi is guaranteed non-empty here: __init__ already raises
            # ValueError if affected_pe_id resolves to a non-multihomed PE.
            esi = pe.esi

            for _ in range(5):
                # Withdraw A-D per ES route
                nlri = evpn.build_ead_per_es(pe.bgp_id, esi, self.config.evpn.vni)
                packets.extend(self._mark_event(tcp.send_data(
                    build_update(path_attributes=build_evpn_withdraw_attrs(nlri)), t, 'server_to_client'), 'ESDF Toggle', self.affected_pe_id, 'Route UPDATE', phase='trigger'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe, esi, 'withdraw', t + 0.01, event=True,
                    fault_type='ESDF Toggle', node=self.affected_pe_id, phase='trigger')
                packets.extend(fanout_pkts)
                t += 0.1

                # Re-advertise ES route
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id, cluster_id=bgp_sess.remote_router.bgp_id)
                packets.extend(self._mark_event(tcp.send_data(
                    build_update(path_attributes=path_attrs), t, 'server_to_client'), 'ESDF Toggle', self.affected_pe_id, 'Route UPDATE', phase='recovery'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe, esi, 'advertise', t + 0.01, event=True,
                    fault_type='ESDF Toggle', node=self.affected_pe_id, phase='recovery')
                packets.extend(fanout_pkts)
                t += random.uniform(1.0, 3.0)

        self._fault_start_t = fault_start_t
        self._fault_end_t = None
        return _fill_to_target(self, packets, t)


class RRDownESDFRR1PE1(RRDownESDFScenario):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, affected_rr='RR1', affected_pe='PE1')


# ---------------------------------------------------------------------------
# B2. RR Down + RT Misconfiguration
#     RR session drops while a PE is advertising wrong RT.
# ---------------------------------------------------------------------------

class RRDownRTMisconfigScenario(BaseScenario):
    """RR session RST concurrent with a PE advertising wrong Route Target."""
    FAULT_TYPE: str = 'RR Down + RT Misconfiguration'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_rr: str = 'RR1', misconfig_pe: str = None,
                 wrong_rt: int = 999):
        super().__init__(config, target_frames)
        self.affected_rr = affected_rr
        self.misconfig_pe_id = misconfig_pe or config.pe_nodes[1].id
        self.wrong_rt = wrong_rt

    def generate(self) -> list[TCPPacket]:
        packets, t = _std_preamble(self)

        fault_start_t = t
        # FAULT 1: RR session drops. Topology-role based match.
        # affected_rr_id is the RR that is NOT the capture vantage.
        self.affected_rr_id = next(rr.id for rr in self.config.route_reflectors
                                   if rr.id != self.config.capture_vantage)
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                tcp = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp and tcp.is_established():
                    packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='client'), 'RR Down', self.affected_rr_id, 'TCP RST', phase='trigger'))
                break

        t += 0.5

        # RFC 4271 SS9.2 / RFC 4456 second hop: the vantage RR lost its only
        # path to the affected RR's clients' routes and must withdraw them
        # toward its own clients. Borrowed as an unbound method from
        # RRDownCleanRestart (rr_down.py).
        _saved_fault_type, self.FAULT_TYPE = self.FAULT_TYPE, 'RR Down'
        wd_pkts, t = RRDownCleanRestart._second_hop_withdraw_affected_rr_clients(self, t)
        self.FAULT_TYPE = _saved_fault_type
        packets.extend(wd_pkts)

        # FAULT 2: RT misconfig— PE sends routes with wrong RT
        bgp_sess, tcp = _session_for_node(self, self.misconfig_pe_id)
        if bgp_sess and tcp and tcp.is_established():
            pe = bgp_sess.local_router
            macs = self.topology.get_macs_for_pe(
                self.misconfig_pe_id,
                count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                      int(self.config.evpn.mac_pool_size * 0.5)))
            timestamps = route_burst_timestamps(t, len(macs))

            for mac_entry, ts in zip(macs, timestamps):
                nlri = evpn.build_mac_ip_route(
                    pe.bgp_id, pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni)
                wrong_rt = encode_rt_community(100, self.wrong_rt)
                encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
                         + attr_extended_communities([wrong_rt, encap])
                         + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri))
                packets.extend(self._mark_event(tcp.send_data(build_update(path_attributes=attrs), ts, 'server_to_client'), 'RT Misconfiguration', self.misconfig_pe_id, 'Route UPDATE', phase='trigger'))
                packets.extend(tcp.generate_ack(ts + ack_delay(), 'client_to_server'))

            t = timestamps[-1] + 0.5

        self._fault_start_t = fault_start_t
        self._fault_end_t = None
        return _fill_to_target(self, packets, t)


class RRDownRTRR1PE2(RRDownRTMisconfigScenario):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, affected_rr='RR1', misconfig_pe='PE2')


# ---------------------------------------------------------------------------
# B3. ESDF Toggle + RT Misconfiguration
#     DF election instability on one PE, wrong RT on another.
# ---------------------------------------------------------------------------

class ESDFRTMisconfigScenario(BaseScenario):
    """ESDF toggling on one PE concurrent with RT misconfiguration on another.

    Note: this class's own primary ESDF withdraw/advertise events build
    Type-1 (build_ead_per_es) rather than the Type-4 ES route.
    """
    FAULT_TYPE: str = 'ESDF Toggle + RT Misconfiguration'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 esdf_pe: str = None, rt_pe: str = None, wrong_rt: int = 999):
        super().__init__(config, target_frames)
        self.esdf_pe_id = esdf_pe or config.pe_nodes[0].id
        self.rt_pe_id = rt_pe or config.pe_nodes[2].id
        self.wrong_rt = wrong_rt
        esdf_pe_router = config.get_router(self.esdf_pe_id)
        if not esdf_pe_router or not esdf_pe_router.esi:
            raise ValueError(
                f"PE {self.esdf_pe_id} is not multihomed in this topology, "
                "cannot resolve ES/DF peer")

    def generate(self) -> list[TCPPacket]:
        packets, t = _std_preamble(self)

        fault_start_t = t
        # FAULT 1: ESDF toggling on esdf_pe -- Type 1 A-D per ES route, the
        # mass-withdraw trigger signal per RFC 7432 SS8.2 / RFC 8584.
        # Type 4 follows passively as a consequence, not as the trigger.
        bgp_a, tcp_a = _session_for_node(self, self.esdf_pe_id)
        if bgp_a and tcp_a and tcp_a.is_established():
            pe_a = bgp_a.local_router
            # esi is guaranteed non-empty here: __init__ already raises
            # ValueError if esdf_pe_id resolves to a non-multihomed PE.
            esi = pe_a.esi
            for _ in range(4):
                nlri = evpn.build_ead_per_es(pe_a.bgp_id, esi, self.config.evpn.vni)
                packets.extend(self._mark_event(tcp_a.send_data(
                    build_update(path_attributes=build_evpn_withdraw_attrs(nlri)), t, 'server_to_client'), 'ESDF Toggle', self.esdf_pe_id, 'Route UPDATE', phase='trigger'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe_a, esi, 'withdraw', t + 0.01, event=True,
                    fault_type='ESDF Toggle', node=self.esdf_pe_id, phase='trigger')
                packets.extend(fanout_pkts)
                t += 0.2
                path_attrs = build_standard_evpn_path_attrs(
                    pe_a.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe_a.bgp_id, cluster_id=bgp_a.remote_router.bgp_id)
                packets.extend(self._mark_event(tcp_a.send_data(
                    build_update(path_attributes=path_attrs), t, 'server_to_client'), 'ESDF Toggle', self.esdf_pe_id, 'Route UPDATE', phase='recovery'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe_a, esi, 'advertise', t + 0.01, event=True,
                    fault_type='ESDF Toggle', node=self.esdf_pe_id, phase='recovery')
                packets.extend(fanout_pkts)
                t += random.uniform(1.5, 3.0)

        # FAULT 2: RT misconfig on rt_pe (concurrent)
        bgp_b, tcp_b = _session_for_node(self, self.rt_pe_id)
        if bgp_b and tcp_b and tcp_b.is_established():
            pe_b = bgp_b.local_router
            macs = self.topology.get_macs_for_pe(
                self.rt_pe_id,
                count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                      int(self.config.evpn.mac_pool_size * 0.5)))
            timestamps = route_burst_timestamps(t, len(macs))
            for mac_entry, ts in zip(macs, timestamps):
                nlri = evpn.build_mac_ip_route(
                    pe_b.bgp_id, pe_b.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni)
                wrong_rt = encode_rt_community(100, self.wrong_rt)
                encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
                         + attr_extended_communities([wrong_rt, encap])
                         + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_b.bgp_id, nlri))
                packets.extend(self._mark_event(tcp_b.send_data(build_update(path_attributes=attrs), ts, 'server_to_client'), 'RT Misconfiguration', self.rt_pe_id, 'Route UPDATE', phase='trigger'))
                packets.extend(tcp_b.generate_ack(ts + ack_delay(), 'client_to_server'))
            t = max(t, timestamps[-1] + 0.5)

        self._fault_start_t = fault_start_t
        self._fault_end_t = None
        return _fill_to_target(self, packets, t)


class ESDFRTPe1Pe2(ESDFRTMisconfigScenario):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, esdf_pe='PE1', rt_pe='PE2')


# ===========================================================================
# C. TRIPLE COMBINATIONS
# ===========================================================================

class TripleLDRRESScenario(BaseScenario):
    """Link Down (PE1) + RR Down + ESDF Toggle (PE2) — three concurrent
    faults. esdf_pe_id MUST be a real multihomed PE (PE1 or PE2 in this
    topology) -- ES/DF toggling is only meaningful for a PE that actually
    shares an ESI with a peer. PE2 is used here since PE1 is already the
    link-down leg's target.

    Note: this class's own primary ESDF withdraw/advertise events build
    Type-1 (build_ead_per_es) rather than the Type-4 ES route.
    """
    FAULT_TYPE: str = 'Link Down + RR Down + ESDF Toggle'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000):
        super().__init__(config, target_frames)
        self.ld_pe_id = config.pe_nodes[0].id      # PE1 link down
        self.affected_rr = 'RR1'
        self.esdf_pe_id = config.pe_nodes[1].id    # PE2 ESDF
        esdf_pe = config.get_router(self.esdf_pe_id)
        if not esdf_pe or not esdf_pe.esi:
            raise ValueError(
                f"PE {self.esdf_pe_id} is not multihomed in this topology, "
                "cannot resolve ES/DF peer")

    def generate(self) -> list[TCPPacket]:
        packets, t = _std_preamble(self)

        fault_start_t = t
        # Fault 1: Link down on LD PE
        rst_pkts, t = _reset_session(self, self.ld_pe_id, t)
        packets.extend(self._mark_event(rst_pkts, 'Link Down', self.ld_pe_id, 'TCP RST', phase='trigger'))

        # Fault 2: RR session drops (30s later). Topology role match.
        # affected_rr_id is the RR that is NOT the capture vantage.
        self.affected_rr_id = next(rr.id for rr in self.config.route_reflectors
                                   if rr.id != self.config.capture_vantage)
        t += 30
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                tcp = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp and tcp.is_established():
                    packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='client'), 'RR Down', self.affected_rr_id, 'TCP RST', phase='trigger'))
                break

        # RFC 4271 SS9.2 / RFC 4456 second hop: the vantage RR lost its only
        # path to the affected RR's clients' routes and must withdraw them
        # toward its own clients. Borrowed as an unbound method from
        # RRDownCleanRestart (rr_down.py), same pattern as
        # RRDownThenLinkDownSequential borrowing LinkDownScenario's helper.
        _saved_fault_type, self.FAULT_TYPE = self.FAULT_TYPE, 'RR Down'
        wd_pkts, t = RRDownCleanRestart._second_hop_withdraw_affected_rr_clients(self, t)
        self.FAULT_TYPE = _saved_fault_type
        packets.extend(wd_pkts)

        t += 2.0

        # Fault 3: ESDF toggling on ESDF PE -- Type 1 A-D per ES route, the
        # mass-withdraw trigger signal per RFC 7432 SS8.2 / RFC 8584.
        # Type 4 follows passively as a consequence, not as the trigger.
        bgp_e, tcp_e = _session_for_node(self, self.esdf_pe_id)
        if bgp_e and tcp_e and tcp_e.is_established():
            pe_e = bgp_e.local_router
            # esi is guaranteed non-empty here: __init__ already raises
            # ValueError if esdf_pe_id resolves to a non-multihomed PE.
            esi = pe_e.esi
            for _ in range(3):
                nlri = evpn.build_ead_per_es(pe_e.bgp_id, esi, self.config.evpn.vni)
                packets.extend(self._mark_event(tcp_e.send_data(
                    build_update(path_attributes=build_evpn_withdraw_attrs(nlri)), t, 'server_to_client'), 'ESDF Toggle', self.esdf_pe_id, 'Route UPDATE', phase='trigger'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe_e, esi, 'withdraw', t + 0.01, event=True,
                    fault_type='ESDF Toggle', node=self.esdf_pe_id, phase='trigger')
                packets.extend(fanout_pkts)
                t += 0.1
                path_attrs = build_standard_evpn_path_attrs(
                    pe_e.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe_e.bgp_id, cluster_id=bgp_e.remote_router.bgp_id)
                packets.extend(self._mark_event(tcp_e.send_data(
                    build_update(path_attributes=path_attrs), t, 'server_to_client'), 'ESDF Toggle', self.esdf_pe_id, 'Route UPDATE', phase='recovery'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe_e, esi, 'advertise', t + 0.01, event=True,
                    fault_type='ESDF Toggle', node=self.esdf_pe_id, phase='recovery')
                packets.extend(fanout_pkts)
                t += random.uniform(2.0, 4.0)

        self._fault_start_t = fault_start_t
        self._fault_end_t = None
        return _fill_to_target(self, packets, t)


# ===========================================================================
# D. CROSS-COMBINATIONS — existing fault type + new fault type
# ===========================================================================

# class RRASMisconfigScenario(BaseScenario):
#     """RR Down on RR1 + AS Misconfiguration on PE2 (simultaneous)."""
#     FAULT_TYPE: str = 'RR Down + AS Misconfig'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 30000):
#         super().__init__(config, target_frames)
#         self.affected_rr = 'RR1'
#         self.misconfig_pe_id = config.pe_nodes[1].id

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         # Fault 1: RR down. Topology-role based match.
#         self.affected_rr_id = next(rr.id for rr in self.config.route_reflectors
#                                    if rr.id != self.config.capture_vantage)
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
#                 tcp = self.tcp_sessions.get(bgp_sess.session_id)
#                 if tcp and tcp.is_established():
#                     packets.extend(self._mark_event(tcp.close_reset(timestamp=t, initiator='client'), 'RR Down', self.affected_rr_id, 'TCP RST'))
#                 break

#         # RFC 4271 SS9.2 / RFC 4456 second hop: the vantage RR lost its only
#         # path to the affected RR's clients' routes and must withdraw them
#         # toward its own clients. Borrowed as an unbound method from
#         # RRDownCleanRestart (rr_down.py), same pattern as
#         # RRDownThenLinkDownSequential borrowing LinkDownScenario's helper.
#         _saved_fault_type, self.FAULT_TYPE = self.FAULT_TYPE, 'RR Down'
#         wd_pkts, t = RRDownCleanRestart._second_hop_withdraw_affected_rr_clients(self, t)
#         self.FAULT_TYPE = _saved_fault_type
#         packets.extend(wd_pkts)

#         t += 10.0

#         # Fault 2: PE2 session reset then reconnects with wrong ASN
#         bgp_sess, tcp = _session_for_node(self, self.misconfig_pe_id)
#         if bgp_sess and tcp and tcp.is_established():
#             rst_pkts, t = _reset_session(self, self.misconfig_pe_id, t)
#             packets.extend(self._mark_event(rst_pkts, 'AS Misconfig', self.misconfig_pe_id, 'TCP RST'))
#             t += 0.5

#             pe = bgp_sess.local_router
#             rr = bgp_sess.remote_router
#             bad_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)
#             packets.extend(bad_tcp.connect(timestamp=t)); t += 0.02
#             bad_open = build_open(64999, self.config.timing.hold_timer,
#                                   pe.bgp_id, default_evpn_capabilities(64999))
#             packets.extend(self._mark_event(bad_tcp.send_data(bad_open, t, 'client_to_server'), 'AS Misconfig', self.misconfig_pe_id, 'BGP OPEN'))
#             t += ack_delay()
#             packets.extend(bad_tcp.generate_ack(t, 'server_to_client'))
#             t += 0.01
#             notif = build_notification(ERR_OPEN_MSG, OPEN_BAD_PEER_AS)
#             packets.extend(self._mark_event(bad_tcp.send_data(notif, t, 'server_to_client'), 'AS Misconfig', self.misconfig_pe_id, 'BGP NOTIFICATION: Bad Peer AS'))
#             t += 0.001
#             packets.extend(self._mark_event(bad_tcp.close_reset(timestamp=t, initiator='server'), 'AS Misconfig', self.misconfig_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# class RTInvalidNextHopScenario(BaseScenario):
#     """RT Misconfiguration on PE1 + Invalid NEXT_HOP from PE3."""
#     FAULT_TYPE: str = 'RT Misconfiguration + Invalid Next Hop'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 30000):
#         super().__init__(config, target_frames)
#         self.rt_pe_id = config.pe_nodes[0].id
#         self.nexthop_pe_id = config.pe_nodes[2].id

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         # Fault 1: RT misconfig
#         bgp_r, tcp_r = _session_for_node(self, self.rt_pe_id)
#         if bgp_r and tcp_r and tcp_r.is_established():
#             pe_r = bgp_r.local_router
#             macs = self.topology.get_macs_for_pe(
#                 self.rt_pe_id,
#                 count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
#                                       int(self.config.evpn.mac_pool_size * 0.5)))
#             timestamps = route_burst_timestamps(t, len(macs))
#             for mac_entry, ts in zip(macs, timestamps):
#                 nlri = evpn.build_mac_ip_route(
#                     pe_r.bgp_id, pe_r.esi or "0", mac_entry.mac,
#                     ip=mac_entry.ip, vni=self.config.evpn.vni)
#                 wrong_rt = encode_rt_community(100, 999)
#                 encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
#                 attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
#                          + attr_extended_communities([wrong_rt, encap])
#                          + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_r.loopback, nlri))
#                 packets.extend(self._mark_event(tcp_r.send_data(build_update(path_attributes=attrs), ts, 'server_to_client'), 'RT Misconfiguration', self.rt_pe_id, 'Route UPDATE'))
#                 packets.extend(tcp_r.generate_ack(ts + ack_delay(), 'client_to_server'))
#             t = timestamps[-1] + 5.0

#         # Fault 2: Invalid NEXT_HOP on nexthop_pe
#         bgp_n, tcp_n = _session_for_node(self, self.nexthop_pe_id)
#         if bgp_n and tcp_n and tcp_n.is_established():
#             pe_n = bgp_n.local_router
#             macs = self.topology.get_macs_for_pe(
#                 self.nexthop_pe_id,
#                 count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
#                                       int(self.config.evpn.mac_pool_size * 0.5)))
#             timestamps = route_burst_timestamps(t, len(macs))
#             for mac_entry, ts in zip(macs, timestamps):
#                 nlri = evpn.build_mac_ip_route(
#                     pe_n.bgp_id, pe_n.esi or "0", mac_entry.mac,
#                     ip=mac_entry.ip, vni=self.config.evpn.vni)
#                 rt_parts = self.config.evpn.route_target.split(':')
#                 rt = encode_rt_community(int(rt_parts[0]), int(rt_parts[1]))
#                 encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
#                 attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
#                          + attr_extended_communities([rt, encap])
#                          + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, "2001:db8::dead:99", nlri))
#                 packets.extend(self._mark_event(tcp_n.send_data(build_update(path_attributes=attrs), ts, 'server_to_client'), 'Invalid Next Hop', self.nexthop_pe_id, 'Route UPDATE'))
#                 packets.extend(tcp_n.generate_ack(ts + ack_delay(), 'client_to_server'))
#             t = timestamps[-1] + 0.1
#             notif = build_notification(ERR_UPDATE_MSG, UPDATE_INVALID_NEXT_HOP)
#             packets.extend(self._mark_event(tcp_n.send_data(notif, t, 'server_to_client'), 'Invalid Next Hop', self.nexthop_pe_id, 'BGP NOTIFICATION: Invalid Next Hop'))
#             t += 0.001
#             packets.extend(self._mark_event(tcp_n.close_reset(timestamp=t, initiator='server'), 'Invalid Next Hop', self.nexthop_pe_id, 'TCP RST'))
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#         return _fill_to_target(self, packets, t)


# ---------------------------------------------------------------------------
# E. RD Collision — RFC 7432 requires RD uniqueness across MAC-VRFs; a
#    misconfigured PE that reuses another PE's RD produces a route-key
#    collision (RD+MAC+IP is the Type-2 route key), not encoding corruption.
#    A real receiver's BGP best-path selection treats the two advertisements
#    as competing paths for what it believes is the SAME route and picks a
#    winner via the standard decision process (LOCAL_PREF, AS_PATH length,
#    origin, router-ID tiebreak, etc.) -- silently masking the loser PE's
#    route. This generator only needs to produce the wire content that
#    WOULD trigger that outcome on a real receiver; best-path selection
#    itself is not simulated here.
# ---------------------------------------------------------------------------

# class RDCollisionScenario(BaseScenario):
#     """PE1 and PE3 each advertise a MAC/IP (Type 2) route for a DIFFERENT
#     MAC address but with an IDENTICAL Route Distinguisher -- PE3's RD is
#     deliberately constructed to match PE1's (rather than PE3's own,
#     naturally-unique RD derived from its own bgp_id). Not the multihomed
#     pair (PE1/PE2) since this fault is unrelated to ESI/DF -- any two
#     direct-session PEs demonstrate the collision.

#     No session disruption, no withdrawal -- same "silent" fault family as
#     RT Misconfiguration: sessions stay UP, routes are sent and accepted at
#     the BGP layer, the damage is purely in the route-key collision a real
#     receiver's decision process would resolve by picking one PE's route
#     over the other's.
#     """
#     FAULT_TYPE: str = 'RD Collision'
#     SECTION: int = 3

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  recovery: bool = False, recovery_delay: float = 120.0):
#         super().__init__(config, target_frames)
#         self.origin_pe_id = config.pe_nodes[0].id   # PE1 -- owns the RD
#         self.collide_pe_id = config.pe_nodes[2].id  # PE3 -- reuses PE1's RD
#         self.recovery = recovery
#         self.recovery_delay = recovery_delay

#     def _advertise_colliding_route(self, t: float, packets: list, event: bool):
#         """PE3 advertises a MAC/IP route using PE1's RD instead of its own."""
#         bgp_c, tcp_c = _session_for_node(self, self.collide_pe_id)
#         if not (bgp_c and tcp_c and tcp_c.is_established()):
#             return t
#         origin_pe = self.config.get_router(self.origin_pe_id)
#         collide_pe = bgp_c.local_router
#         macs = self.topology.get_macs_for_pe(self.collide_pe_id, count=3)
#         timestamps = route_burst_timestamps(t, len(macs))
#         colliding_rd = evpn.encode_rd(origin_pe.bgp_id, self.config.evpn.vni)
#         for mac_entry, ts in zip(macs, timestamps):
#             nlri = evpn.build_evpn_type2(
#                 colliding_rd, evpn.encode_esi(collide_pe.esi or "0"), 0,
#                 mac_entry.mac, ip=mac_entry.ip, label1=self.config.evpn.vni)
#             path_attrs = build_standard_evpn_path_attrs(
#                 collide_pe.loopback, nlri, self.config.as_number, self.config.evpn.vni,
#                 originator_id=collide_pe.bgp_id,
#                 cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
#             update = build_update(path_attributes=path_attrs)
#             pkts = tcp_c.send_data(update, ts, 'server_to_client')
#             packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.collide_pe_id, 'Route UPDATE') if event else pkts)
#             packets.extend(tcp_c.generate_ack(ts + ack_delay(), 'client_to_server'))
#         return timestamps[-1] + 0.5 if timestamps else t

#     def _advertise_corrected_route(self, t: float, packets: list, event: bool):
#         """PE3 re-advertises with its own, correct RD."""
#         bgp_c, tcp_c = _session_for_node(self, self.collide_pe_id)
#         if not (bgp_c and tcp_c and tcp_c.is_established()):
#             return t
#         collide_pe = bgp_c.local_router
#         macs = self.topology.get_macs_for_pe(self.collide_pe_id, count=3)
#         timestamps = route_burst_timestamps(t, len(macs))
#         for mac_entry, ts in zip(macs, timestamps):
#             nlri = evpn.build_mac_ip_route(
#                 collide_pe.bgp_id, collide_pe.esi or "0", mac_entry.mac,
#                 ip=mac_entry.ip, vni=self.config.evpn.vni)
#             path_attrs = build_standard_evpn_path_attrs(
#                 collide_pe.loopback, nlri, self.config.as_number, self.config.evpn.vni,
#                 originator_id=collide_pe.bgp_id,
#                 cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
#             update = build_update(path_attributes=path_attrs)
#             pkts = tcp_c.send_data(update, ts, 'server_to_client')
#             packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.collide_pe_id, 'Route UPDATE') if event else pkts)
#             packets.extend(tcp_c.generate_ack(ts + ack_delay(), 'client_to_server'))
#         return timestamps[-1] + 0.5 if timestamps else t

#     def generate(self) -> list[TCPPacket]:
#         packets, t = _std_preamble(self)

#         fault_start_t = t
#         t = self._advertise_colliding_route(t, packets, event=True)

#         if self.recovery:
#             recovery_update_times: dict = {}
#             self.generate_route_churn(packets, t, self.recovery_delay,
#                                       last_update_times=recovery_update_times)
#             packets.extend(self.generate_keepalives_for_duration(
#                 t, self.recovery_delay, last_update_times=recovery_update_times))
#             t += self.recovery_delay
#             t = self._advertise_corrected_route(t, packets, event=True)

#         fault_end_t = t if self.recovery else None
#         self._fault_start_t = fault_start_t
#         self._fault_end_t = fault_end_t
#         return _fill_to_target(self, packets, t)


# class RDCollisionPE1PE3(RDCollisionScenario):
#     """Persistent variant -- PE3's colliding RD is never corrected."""
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, recovery=False)


# class RDCollisionRecoveryPE1PE3(RDCollisionScenario):
#     """Recovery variant -- PE3's RD is corrected after ~120s."""
#     def __init__(self, config, target_frames=8000):
#         super().__init__(config, target_frames, recovery=True, recovery_delay=120.0)
