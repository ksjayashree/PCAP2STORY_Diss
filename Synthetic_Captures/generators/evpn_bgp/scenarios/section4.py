"""Section 4 — Additional scenarios for PCAP2STORY.

Covers cascading faults, intermittent faults, slow degradation,
and repeated session flapping.
"""

import random
from .base import BaseScenario
from .rr_down import RRDownCleanRestart
from ..config import TopologyConfig
from ..tcp.session import TCPSession, TCPPacket
from ..bgp.messages import (build_notification, build_keepalive, build_open,
                             build_update)
from ..bgp.capabilities import default_evpn_capabilities
from ..bgp.constants import ERR_HOLD_TIMER_EXPIRED, ERR_CEASE, CEASE_ADMIN_SHUTDOWN
from ..bgp.attributes import build_standard_evpn_path_attrs, build_evpn_withdraw_attrs
from ..bgp import evpn
from generators.common.utils.timing import (
    jittered_interval, ack_delay, keepalive_timestamps, route_burst_timestamps
)


# ---------------------------------------------------------------------------
# Multi-fault cascade: RR down triggers ES/DF re-election
# ---------------------------------------------------------------------------

class CascadeRRDownESDFRR1(BaseScenario):
    """RR1 goes down, triggering ES/DF re-election on multi-homed PEs.

    Pattern:
    1. Normal traffic with RR1 active
    2. RR1-RR2 session drops (fault 1)
    3. Multi-homed PEs detect loss of reflected routes and re-elect DF (fault 2 cascade)
    4. Both multihomed PEs withdraw their Type 1 A-D per ES route close
       together (the mass-withdraw trigger signal per RFC 7432 SS8.2 /
       RFC 8584), then both re-advertise together after a shared wait --
       the whole access segment briefly losing its DF candidate, not two
       independent sequential toggles. Type 4 follows passively as a
       consequence, not as the trigger.
    """
    FAULT_TYPE: str = 'RR Down + ESDF Toggle'
    SECTION: int = 4

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_rr: str = 'RR1'):
        super().__init__(config, target_frames)
        self.affected_rr = affected_rr

    def generate(self):
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        # FAULT 1: RR session drops. Topology-role based match, not a
        # substring match on session id. affected_rr_id must be the RR that
        # is NOT the capture vantage -- self.affected_rr is just this
        # class's own event label and would incorrectly attribute both the
        # RST and the withdrawal below to the vantage instead of the true
        # non-vantage RR. Covers CascadeRRDownESDFRR2 too -- it inherits
        # this generate() unchanged, only __init__ differs (affected_rr='RR2').
        fault_start_t = t
        self.affected_rr_id = next(rr.id for rr in self.config.route_reflectors
                                   if rr.id != self.config.capture_vantage)
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp_sess and tcp_sess.is_established():
                    rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
                    packets.extend(self._mark_event(rst_pkts, 'RR Down', self.affected_rr_id, 'TCP RST', phase='trigger'))
                break

        # RFC 4271 SS9.2 / RFC 4456 second hop: the vantage RR lost its only
        # path to the affected RR's clients' routes and must withdraw them
        # toward its own clients. Borrowed as an unbound method from
        # RRDownCleanRestart (rr_down.py).
        _saved_fault_type, self.FAULT_TYPE = self.FAULT_TYPE, 'RR Down'
        wd_pkts, t = RRDownCleanRestart._second_hop_withdraw_affected_rr_clients(self, t)
        self.FAULT_TYPE = _saved_fault_type
        packets.extend(wd_pkts)

        t += 1.0

        # FAULT 2 CASCADE: both multihomed PEs withdraw Type 1 A-D per ES
        # close together (no surviving DF candidate for the ESI during the
        # window), then both re-advertise together after a shared wait --
        # matches ESDFFullFailure's FULL pattern, not two independent
        # sequential TOGGLE/FLAP cycles.
        mh_pairs = self.config.get_multihomed_peers()
        for pe1, pe2 in mh_pairs:
            sessions = []
            for pe in [pe1, pe2]:
                session_id = self._find_session_for_pe(pe.id)
                tcp_sess = self.tcp_sessions.get(session_id) if session_id else None
                if tcp_sess and tcp_sess.is_established():
                    sessions.append((pe, tcp_sess))

            if not sessions:
                continue

            # esi is guaranteed non-empty here: pe is drawn from
            # config.get_multihomed_peers(), which only returns pairs
            # that already share a real ESI.
            nlris = {}

            # Withdraw Type 1 A-D per ES -- the mass-withdraw trigger signal
            # per RFC 7432 SS8.2 / RFC 8584. Type 4 follows passively as a
            # consequence, not as the trigger. PEs withdraw close together
            # (gap matches ESDFFullFailure's existing pattern).
            for i, (pe, tcp_sess) in enumerate(sessions):
                nlri = evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni)
                nlris[pe.id] = nlri
                path_attrs = build_evpn_withdraw_attrs(nlri)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'server_to_client')
                packets.extend(self._mark_event(pkts, 'ESDF Toggle', pe.id, 'Route UPDATE', phase='trigger'))
                t += 0.01
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                if i < len(sessions) - 1:
                    t += random.uniform(0.15, 0.28)
                else:
                    t += 0.005

            # Both PEs re-advertise together after a single shared wait --
            # not an independent per-PE recovery timer.
            t += random.uniform(2, 5)
            for pe, tcp_sess in sessions:
                nlri = nlris[pe.id]
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'server_to_client')
                packets.extend(pkts)
                t += 0.01
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.001

        # Continue with no RR recovery
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                * self.config.timing.keepalive_timer)
            ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
            packets.extend(ka_pkts)

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class CascadeRRDownESDFRR2(CascadeRRDownESDFRR1):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, affected_rr='RR2')


# ---------------------------------------------------------------------------
# Multi-fault cascade: link down exposes pre-existing RT misconfiguration
# ---------------------------------------------------------------------------

class CascadeLinkDownRTMisconfigPE1(BaseScenario):
    """Link down on one PE exposes a pre-existing RT misconfiguration on another PE.

    Pattern:
    1. PE with wrong RT advertises routes (silently dropped — no visible fault)
    2. Another PE's link goes down (fault 1)
    3. Convergence reveals the misconfig because traffic can't re-route (cascade)
    4. Burst of route withdrawals + continued keepalives on surviving sessions
    """
    FAULT_TYPE: str = 'Link Down + RT Misconfiguration'
    SECTION: int = 4

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 link_down_pe: str = 'PE1', misconfig_pe: str = 'PE3'):
        super().__init__(config, target_frames)
        self.link_down_pe = link_down_pe
        self.misconfig_pe = misconfig_pe

    def generate(self):
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        # Pre-existing misconfiguration: misconfig_pe advertises wrong RT (silent)
        fault_start_t = t
        misconfig_router = self.config.get_router(self.misconfig_pe)
        misconfig_session = self._find_session_for_pe(self.misconfig_pe)
        if misconfig_router and misconfig_session:
            tcp_misconfig = self.tcp_sessions.get(misconfig_session)
            if tcp_misconfig and tcp_misconfig.is_established():
                macs = self.topology.get_macs_for_pe(
                    self.misconfig_pe,
                    count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                          int(self.config.evpn.mac_pool_size * 0.5)))
                for mac_entry in macs:
                    nlri = evpn.build_mac_ip_route(
                        misconfig_router.bgp_id, misconfig_router.esi or "0",
                        mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
                    # Wrong RT
                    from ..bgp.attributes import (attr_origin, attr_as_path, attr_local_pref,
                                                   attr_extended_communities, attr_mp_reach_nlri,
                                                   encode_rt_community, encode_encapsulation_community)
                    from ..bgp.constants import AFI_L2VPN, SAFI_EVPN, TUNNEL_TYPE_VXLAN
                    wrong_rt = encode_rt_community(100, 777)
                    encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                    attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
                             + attr_extended_communities([wrong_rt, encap])
                             + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN,
                                                  misconfig_router.bgp_id, nlri))
                    update = build_update(path_attributes=attrs)
                    pkts = tcp_misconfig.send_data(update, t, 'server_to_client')
                    packets.extend(self._mark_event(pkts, 'RT Misconfiguration', self.misconfig_pe, 'Route UPDATE', phase='trigger'))
                    t += 0.005
                    packets.extend(tcp_misconfig.generate_ack(t, 'client_to_server'))
                    t += 0.001

        t += 30  # Brief normal period

        # FAULT 1: Link down on link_down_pe
        link_down_session = self._find_session_for_pe(self.link_down_pe)
        if link_down_session:
            tcp_ld = self.tcp_sessions[link_down_session]
            rst_pkts = tcp_ld.close_reset(timestamp=t, initiator='server')
            packets.extend(self._mark_event(rst_pkts, 'Link Down', self.link_down_pe, 'TCP RST', phase='trigger'))
            t += 0.01

            pe = self.config.get_router(self.link_down_pe)
            # Withdraw ALL of link_down_pe's routes, per RFC 4271 SS9.2 --
            # not just Type 2 MAC/IP. Mirrors link_down.py's
            # _withdraw_pe_routes_direct() completeness (Type 3 IMET
            # always; Type 1/4 for multihomed PEs only).
            macs = self.topology.get_macs_for_pe(
                self.link_down_pe,
                count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                      int(self.config.evpn.mac_pool_size * 0.5)))
            nlris = [evpn.build_mac_ip_route(
                pe.bgp_id, pe.esi or "0", mac_entry.mac,
                ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
            nlris.append(evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni))
            if pe.esi and pe.esi != "0":
                nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
                nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                    vni=self.config.evpn.vni))
                nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                                 self.config.evpn.vni))
            for session_id, other_tcp in self.tcp_sessions.items():
                if self.link_down_pe in session_id or not other_tcp.is_established():
                    continue
                for nlri in nlris:
                    path_attrs = build_evpn_withdraw_attrs(nlri)
                    update = build_update(path_attributes=path_attrs)
                    pkts = other_tcp.send_data(update, t, 'server_to_client')
                    packets.extend(self._mark_event(pkts, 'Link Down', self.link_down_pe, 'Route UPDATE', phase='trigger'))
                    t += 0.005

        # Remaining sessions continue — misconfigured PE still up but routes rejected
        no_recovery_duration = self._param_rng.uniform(300, 480)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.link_down_pe in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, no_recovery_duration,
                                              self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, no_recovery_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


# ---------------------------------------------------------------------------
# Intermittent link flapping
# ---------------------------------------------------------------------------

class IntermittentLinkFlap(BaseScenario):
    """Link repeatedly goes up and down over a long period.

    Distinctly different temporal signature from a single link-down event.
    """
    FAULT_TYPE: str = 'Link Down'
    SECTION: int = 4
    WARMUP_SECONDS = (90, 300)

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_pe: str = 'PE1', num_flaps: int = 6):
        super().__init__(config, target_frames)
        self.affected_pe = affected_pe
        self.num_flaps = num_flaps

    def generate(self):
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(90, 300)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        affected_session = None
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.affected_pe:
                affected_session = bgp_sess
                break

        pe_router = self.config.get_router(self.affected_pe)
        first_flap_start = None
        last_fault_end = None

        for flap_idx in range(self.num_flaps):
            # DOWN: TCP RST
            flap_start_t = t
            if first_flap_start is None:
                first_flap_start = flap_start_t
            if affected_session:
                tcp_sess = self.tcp_sessions[affected_session.session_id]
                if tcp_sess.is_established():
                    rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                    packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe, 'TCP RST', phase='trigger'))

            if pe_router:
                # Withdraw ALL of the affected PE's routes, per RFC 4271
                # SS9.2 -- not just Type 2 MAC/IP.
                withdraw_t = t + 0.01
                macs = self.topology.get_macs_for_pe(self.affected_pe, count=2)
                nlris = [evpn.build_mac_ip_route(
                    pe_router.bgp_id, pe_router.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
                nlris.append(evpn.build_imet_route(pe_router.bgp_id, pe_router.bgp_id, self.config.evpn.vni))
                if pe_router.esi and pe_router.esi != "0":
                    nlris.append(evpn.build_ead_per_es(pe_router.bgp_id, pe_router.esi, self.config.evpn.vni))
                    nlris.append(evpn.build_ead_per_evi(pe_router.bgp_id, pe_router.esi, ethernet_tag=0,
                                                        vni=self.config.evpn.vni))
                    nlris.append(evpn.build_es_route(pe_router.bgp_id, pe_router.esi, pe_router.bgp_id,
                                                     self.config.evpn.vni))
                for session_id, other_tcp in self.tcp_sessions.items():
                    if self.affected_pe in session_id or not other_tcp.is_established():
                        continue
                    for nlri in nlris:
                        update = build_update(path_attributes=build_evpn_withdraw_attrs(nlri))
                        packets.extend(self._mark_event(
                            other_tcp.send_data(update, withdraw_t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe, 'Route UPDATE', phase='trigger'))
                        withdraw_t += 0.005

            # Down period: 15-45 seconds (short, irregular)
            down_duration = self._param_rng.uniform(15, 45)
            other_ka_pkts = self._get_other_keepalives(t, down_duration, self.affected_pe)
            packets.extend(other_ka_pkts)
            t += down_duration

            # UP: reconnect
            if affected_session:
                pe = affected_session.local_router
                rr = affected_session.remote_router
                new_tcp = TCPSession(client_ip=pe.bgp_id, server_ip=rr.bgp_id,
                                     server_port=179)
                self.tcp_sessions[affected_session.session_id] = new_tcp

                connect_pkts = new_tcp.connect(timestamp=t)
                packets.extend(connect_pkts)
                t += 0.02

                open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                      pe.bgp_id, default_evpn_capabilities(self.config.as_number))
                pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
                packets.extend(pkts)
                t += ack_delay()
                packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
                t += 0.005

                open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                      rr.bgp_id, default_evpn_capabilities(self.config.as_number))
                pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
                packets.extend(pkts)
                t += ack_delay()
                packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
                t += 0.01

                ka = build_keepalive()
                pkts = new_tcp.send_data(ka, t, 'client_to_server')
                packets.extend(pkts)
                pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
                packets.extend(pkts)
                t += 0.5

            last_fault_end = t

            # Stable period between flaps: 1-3 minutes (irregular)
            stable_duration = self._param_rng.uniform(60, 180)
            ka_pkts = self.generate_keepalives_for_duration(t, stable_duration)
            packets.extend(ka_pkts)
            t += stable_duration

        # Post-flap normal traffic
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                * self.config.timing.keepalive_timer)
            ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
            packets.extend(ka_pkts)

        self._fault_start_t = first_flap_start
        self._fault_end_t = last_fault_end

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]

    def _get_other_keepalives(self, start, duration, exclude_pe):
        packets = []
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if exclude_pe in session_id or not tcp_sess.is_established():
                continue
            for t in keepalive_timestamps(start, duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'server_to_client'))
        return packets


class IntermittentLinkFlapPE1(IntermittentLinkFlap):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class IntermittentLinkFlapPE2(IntermittentLinkFlap):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# Intermittent ES/DF toggling with irregular intervals
# ---------------------------------------------------------------------------

class IntermittentESDFToggle(BaseScenario):
    """ES/DF toggling with irregular intervals between toggles.

    Unlike clean periodic toggles, this scenario has unpredictable timing
    making it harder for the model to detect from timing alone.
    """
    FAULT_TYPE: str = 'ESDF Toggle'
    SECTION: int = 4
    WARMUP_SECONDS = (90, 300)

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_pe: str = None):
        super().__init__(config, target_frames)
        mh_pairs = config.get_multihomed_peers()
        if affected_pe:
            self.affected_pe_id = affected_pe
        elif mh_pairs:
            self.affected_pe_id = mh_pairs[0][0].id
        else:
            self.affected_pe_id = config.pe_nodes[0].id if config.pe_nodes else 'PE1'

        pe = config.get_router(self.affected_pe_id)
        self.esi = pe.esi if pe and pe.esi else "00:11:22:33:44:55:66:77:88:01"

    def _get_session(self, pe_id):
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                return bgp_sess, self.tcp_sessions.get(bgp_sess.session_id)
        return None, None

    def _withdraw(self, pe, tcp_sess, t):
        """Withdraw the Type 1 A-D per ES route -- the mass-withdraw
        trigger signal per RFC 7432 SS8.2 / RFC 8584. Type 4 follows
        passively as a consequence, not as the trigger."""
        packets = []
        nlri = evpn.build_ead_per_es(pe.bgp_id, self.esi, self.config.evpn.vni)
        path_attrs = build_evpn_withdraw_attrs(nlri)
        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'server_to_client')
        packets.extend(pkts)
        packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))

        fanout_pkts, _ = self._fan_out_type4_to_other_sessions(
            pe, self.esi, 'withdraw', t + 0.01)
        packets.extend(fanout_pkts)
        return packets

    def _advertise(self, pe, tcp_sess, t):
        packets = []
        nlri = evpn.build_ead_per_es(pe.bgp_id, self.esi, self.config.evpn.vni)
        path_attrs = build_standard_evpn_path_attrs(
            pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
            originator_id=pe.bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'server_to_client')
        packets.extend(pkts)
        packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))

        fanout_pkts, _ = self._fan_out_type4_to_other_sessions(
            pe, self.esi, 'advertise', t + 0.01)
        packets.extend(fanout_pkts)
        return packets

    def generate(self):
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(90, 300)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        affected_pe = self.config.get_router(self.affected_pe_id)
        _, tcp_affected = self._get_session(self.affected_pe_id)

        # Irregular toggle intervals: some short (30-60s), some long (3-8 minutes)
        intervals = [
            self._param_rng.uniform(30, 60),
            self._param_rng.uniform(180, 480),
            self._param_rng.uniform(30, 90),
            self._param_rng.uniform(300, 600),
            self._param_rng.uniform(45, 120),
        ]

        first_toggle_start = None
        last_fault_end = None
        for interval in intervals:
            # Toggle down
            toggle_start_t = t
            if first_toggle_start is None:
                first_toggle_start = toggle_start_t
            if tcp_affected and tcp_affected.is_established():
                packets.extend(self._mark_event(self._withdraw(affected_pe, tcp_affected, t), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))
            t += 0.1

            # Down for irregular period
            ka_pkts = self.generate_keepalives_for_duration(t, interval)
            packets.extend(ka_pkts)
            t += interval

            # Toggle up
            if tcp_affected and tcp_affected.is_established():
                packets.extend(self._mark_event(self._advertise(affected_pe, tcp_affected, t), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))
            t += 0.1

            last_fault_end = t

            # Stable period (also irregular)
            stable = self._param_rng.uniform(60, 300)
            ka_pkts = self.generate_keepalives_for_duration(t, stable)
            packets.extend(ka_pkts)
            t += stable

        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                * self.config.timing.keepalive_timer)
            ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
            packets.extend(ka_pkts)

        self._fault_start_t = first_toggle_start
        self._fault_end_t = last_fault_end

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class IntermittentESDFTogglePE1(IntermittentESDFToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class IntermittentESDFTogglePE2(IntermittentESDFToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# Slow degradation — keepalive deviation increasing gradually
# ---------------------------------------------------------------------------

# class SlowDegradation(BaseScenario):
#     """Keepalive deviation increases gradually before session eventually drops.
#
#     Simulates a congested or failing link where keepalive intervals drift
#     increasingly before the session finally collapses.
#     """
#     FAULT_TYPE: str = 'Link Down'
#     SECTION: int = 4
#     WARMUP_SECONDS = (90, 300)
#
#     def __init__(self, config: TopologyConfig, target_frames: int = 30000,
#                  affected_pe: str = 'PE1'):
#         super().__init__(config, target_frames)
#         self.affected_pe = affected_pe
#
#     def generate(self):
#         packets = []
#         t = self.start_time
#
#         setup_pkts, t = self.establish_all_sessions(t)
#         packets.extend(setup_pkts)
#
#         init_routes, t = self.generate_initial_routes(t)
#         packets.extend(init_routes)
#
#         warmup_duration = random.randint(90, 300)
#         ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
#         packets.extend(ka_pkts)
#         t += warmup_duration
#
#         # Find affected session
#         affected_session = None
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.id == self.affected_pe:
#                 affected_session = bgp_sess
#                 break
#
#         base_interval = self.config.timing.keepalive_timer  # 10s
#         degradation_steps = 12
#         step_duration = 60  # 1 minute per step
#         fault_start_t = t
#
#         ka_msg = build_keepalive()
#
#         for step in range(degradation_steps):
#             # Gradually increase keepalive interval for affected PE
#             drift_factor = 1.0 + (step * 0.25)  # Grows from 1x to 3.75x
#             degraded_interval = base_interval * drift_factor
#
#             step_end = t + step_duration
#
#             # Affected PE sends keepalives at degraded interval
#             if affected_session:
#                 tcp_sess = self.tcp_sessions.get(affected_session.session_id)
#                 if tcp_sess and tcp_sess.is_established():
#                     ka_t = t
#                     while ka_t < step_end:
#                         pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
#                         packets.extend(pkts)
#                         packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#                         ka_t += degraded_interval + random.uniform(-1, 1)
#
#             # Other sessions send keepalives normally
#             for session_id, tcp_sess in self.tcp_sessions.items():
#                 if (affected_session and session_id == affected_session.session_id
#                         or not tcp_sess.is_established()):
#                     continue
#                 for ka_t in keepalive_timestamps(t, step_duration, base_interval):
#                     pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
#                     packets.extend(pkts)
#                     packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#
#             t = step_end
#
#         # Final collapse: hold timer expires, session drops
#         if affected_session:
#             tcp_sess = self.tcp_sessions.get(affected_session.session_id)
#             if tcp_sess and tcp_sess.is_established():
#                 notification = build_notification(ERR_HOLD_TIMER_EXPIRED, 0)
#                 pkts = tcp_sess.send_data(notification, t, 'server_to_client')
#                 packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe, 'BGP NOTIFICATION: Hold Timer Expired'))
#                 t += 0.001
#                 close_pkts = tcp_sess.close_graceful(t, initiator='server')
#                 packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_pe, 'Graceful FIN Close'))
#
#         # Post-collapse silence
#         post_duration = random.uniform(120, 300)
#         for session_id, tcp_sess in self.tcp_sessions.items():
#             if (affected_session and session_id == affected_session.session_id
#                     or not tcp_sess.is_established()):
#                 continue
#             ka_msg_local = build_keepalive()
#             for ka_t in keepalive_timestamps(t, post_duration, base_interval):
#                 pkts = tcp_sess.send_data(ka_msg_local, ka_t, 'client_to_server')
#                 packets.extend(pkts)
#                 packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#
#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None
#
#         # Pad with pure TCP window-update frames to reach target_frames
#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
#             packets.extend(pad_pkts)
#
#         packets.sort(key=lambda p: p.timestamp)
#         return packets[:self.target_frames]
#
#
# class SlowDegradationPE1(SlowDegradation):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')
#
# class SlowDegradationPE2(SlowDegradation):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# BGP session flap — repeated up/down cycles
# ---------------------------------------------------------------------------

# REMOVED (out of scope): FAULT_TYPE='BGP Session Flap' (BGPSessionFlap + PE1/PE2/RR1) - not one of the core four fault types
# class BGPSessionFlap(BaseScenario):
#     """BGP session repeatedly cycles up and down on the same PE or RR.

#     Distinct from intermittent link flapping — here the BGP session is
#     explicitly reset and re-established repeatedly, simulating a software
#     or policy issue rather than a physical link problem.
#     """
#     FAULT_TYPE: str = 'BGP Session Flap'
#     SECTION: int = 4
#     WARMUP_SECONDS = (90, 300)

#     def __init__(self, config: TopologyConfig, target_frames: int = 30000,
#                  affected_node: str = 'PE1', num_cycles: int = 5):
#         super().__init__(config, target_frames)
#         self.affected_node = affected_node
#         self.num_cycles = num_cycles

#     def generate(self):
#         packets = []
#         t = self.start_time

#         setup_pkts, t = self.establish_all_sessions(t)
#         packets.extend(setup_pkts)

#         init_routes, t = self.generate_initial_routes(t)
#         packets.extend(init_routes)

#         warmup_duration = random.randint(90, 300)
#         ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
#         packets.extend(ka_pkts)
#         t += warmup_duration

#         affected_session = None
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.id == self.affected_node:
#                 affected_session = bgp_sess
#                 break

#         ka_msg = build_keepalive()
#         first_cycle_start = None
#         last_fault_end = None

#         for cycle in range(self.num_cycles):
#             # RESET: Admin reset (NOTIFICATION Cease)
#             cycle_start_t = t
#             if first_cycle_start is None:
#                 first_cycle_start = cycle_start_t
#             if affected_session:
#                 tcp_sess = self.tcp_sessions.get(affected_session.session_id)
#                 if tcp_sess and tcp_sess.is_established():
#                     notification = build_notification(ERR_CEASE, 4)  # Admin Reset
#                     pkts = tcp_sess.send_data(notification, t, 'client_to_server')
#                     packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_node, 'BGP NOTIFICATION: Cease/Administrative Reset'))
#                     t += 0.001
#                     close_pkts = tcp_sess.close_graceful(t, initiator='client')
#                     packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_node, 'Graceful FIN Close'))

#             # Brief down: 10-30 seconds
#             down_duration = random.uniform(10, 30)
#             for session_id, tcp_sess in self.tcp_sessions.items():
#                 if (affected_session and session_id == affected_session.session_id
#                         or not tcp_sess.is_established()):
#                     continue
#                 for ka_t in keepalive_timestamps(t, down_duration, self.config.timing.keepalive_timer):
#                     pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
#                     packets.extend(pkts)
#                     packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#             t += down_duration

#             # RE-ESTABLISH session
#             if affected_session:
#                 pe = affected_session.local_router
#                 rr = affected_session.remote_router
#                 new_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback,
#                                      server_port=179)
#                 self.tcp_sessions[affected_session.session_id] = new_tcp

#                 connect_pkts = new_tcp.connect(timestamp=t)
#                 packets.extend(connect_pkts)
#                 t += 0.02

#                 open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                       pe.bgp_id, default_evpn_capabilities(self.config.as_number))
#                 pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
#                 packets.extend(pkts)
#                 t += ack_delay()
#                 packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
#                 t += 0.005

#                 open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                       rr.bgp_id, default_evpn_capabilities(self.config.as_number))
#                 pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
#                 packets.extend(pkts)
#                 t += ack_delay()
#                 packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
#                 t += 0.002

#                 ka = build_keepalive()
#                 pkts = new_tcp.send_data(ka, t, 'client_to_server')
#                 packets.extend(pkts)
#                 pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
#                 packets.extend(pkts)
#                 t += 0.5

#             last_fault_end = t

#             # Stable period between cycles: 2-5 minutes
#             stable_duration = random.uniform(120, 300)
#             ka_pkts = self.generate_keepalives_for_duration(t, stable_duration)
#             packets.extend(ka_pkts)
#             t += stable_duration

#         remaining = int(self.target_frames * 0.26) - len(packets)
#         if remaining > 0:
#             post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
#                                 * self.config.timing.keepalive_timer)
#             ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
#             packets.extend(ka_pkts)

#         self._fault_start_t = first_cycle_start
#         self._fault_end_t = last_fault_end

#         # Pad with pure TCP window-update frames to reach target_frames
#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
#             packets.extend(pad_pkts)

#         packets.sort(key=lambda p: p.timestamp)
#         return packets[:self.target_frames]


# class BGPSessionFlapPE1(BGPSessionFlap):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_node='PE1')

# class BGPSessionFlapPE2(BGPSessionFlap):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_node='PE2')

# class BGPSessionFlapRR1(BGPSessionFlap):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_node='RR1')


# ---------------------------------------------------------------------------
# RR Planned Maintenance — captured from a PE's perspective
# (RR1 is vantage, so RR2 maintenance is the feasible scenario)
# ---------------------------------------------------------------------------

# REMOVED (out of scope): FAULT_TYPE='Planned Maintenance' (RRPlannedMaintenance + RR1/RR2) - not one of the core four fault types
# class RRPlannedMaintenance(BaseScenario):
#     """RR graceful shutdown — sends NOTIFICATION Cease/Admin Shutdown before going down.

#     Captured from the other RR's perspective. Model must learn this is
#     planned maintenance, not an RR fault.
#     """
#     FAULT_TYPE: str = 'Planned Maintenance'
#     SECTION: int = 4

#     def __init__(self, config: TopologyConfig, target_frames: int = 30000,
#                  maintenance_rr: str = 'RR2'):
#         super().__init__(config, target_frames)
#         self.maintenance_rr = maintenance_rr
#         # Capture from the other RR
#         other_rrs = [rr for rr in config.route_reflectors if rr.id != maintenance_rr]
#         if other_rrs:
#             self.config.capture_vantage = other_rrs[0].id

#     def generate(self):
#         packets = []
#         t = self.start_time

#         setup_pkts, t = self.establish_all_sessions(t)
#         packets.extend(setup_pkts)

#         init_routes, t = self.generate_initial_routes(t)
#         packets.extend(init_routes)

#         warmup_duration = random.randint(120, 480)
#         ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
#         packets.extend(ka_pkts)
#         t += warmup_duration

#         # RR sends graceful NOTIFICATION before shutdown. Topology-role
#         # based match (not "self.maintenance_rr in session_id" -- that
#         # substring match matched PE1-RR1/PE2-RR1/PE3-RR1 before ever
#         # reaching the true RR1-RR2 session. This RRPlannedMaintenance*
#         # class is only ever used for a single RR going into maintenance,
#         # so its own RR-RR session is the sole target regardless of which
#         # RR that is.
#         fault_start_t = t
#         maint_rr_session_id = None
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
#                 maint_rr_session_id = bgp_sess.session_id
#                 tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
#                 if tcp_sess and tcp_sess.is_established():
#                     notification = build_notification(ERR_CEASE, CEASE_ADMIN_SHUTDOWN)
#                     pkts = tcp_sess.send_data(notification, t, 'client_to_server')
#                     packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.maintenance_rr, 'BGP NOTIFICATION: Cease/Administrative Shutdown'))
#                     t += 0.001
#                     close_pkts = tcp_sess.close_graceful(t, initiator='client')
#                     packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.maintenance_rr, 'Graceful FIN Close'))
#                 break

#         # Maintenance window -- every OTHER session (all PE sessions plus
#         # the RR-RR session already closed above) continues normal
#         # keepalive cadence throughout.
#         maint_duration = 60
#         ka_msg = build_keepalive()
#         for session_id, tcp_sess in self.tcp_sessions.items():
#             if session_id == maint_rr_session_id or not tcp_sess.is_established():
#                 continue
#             for ka_t in keepalive_timestamps(t, maint_duration, self.config.timing.keepalive_timer):
#                 pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
#                 packets.extend(pkts)
#                 packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#         t += maint_duration
#         fault_end_t = t

#         # Post-maintenance normal traffic
#         remaining = int(self.target_frames * 0.26) - len(packets)
#         if remaining > 0:
#             post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1))
#                                 * self.config.timing.keepalive_timer)
#             ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
#             packets.extend(ka_pkts)

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = fault_end_t

#         # Pad with pure TCP window-update frames to reach target_frames
#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
#             packets.extend(pad_pkts)

#         packets.sort(key=lambda p: p.timestamp)
#         return packets[:self.target_frames]


# class RRPlannedMaintenanceRR1(RRPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_rr='RR1')

# class RRPlannedMaintenanceRR2(RRPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_rr='RR2')


# ---------------------------------------------------------------------------
# Mixed: ES/DF toggle coinciding with link down
# ---------------------------------------------------------------------------

class MixedESDFAndLinkDown(BaseScenario):
    """ES/DF toggle happening simultaneously with a link down on a different PE.

    Tests whether the model can distinguish two concurrent fault types.
    """
    FAULT_TYPE: str = 'Link Down + ESDF Toggle'
    SECTION: int = 4

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 link_down_pe: str = 'PE1', esdf_pe: str = 'PE2'):
        super().__init__(config, target_frames)
        self.link_down_pe = link_down_pe
        self.esdf_pe = esdf_pe
        esdf_router = config.get_router(esdf_pe)
        if not esdf_router or not esdf_router.esi:
            raise ValueError(
                f"PE {esdf_pe} is not multihomed in this topology, "
                "cannot resolve ES/DF peer")
        self.esi = esdf_router.esi

    def generate(self):
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        # FAULT 1: Link down via TCP RST, then withdraw ALL of link_down_pe's
        # routes on surviving sessions per RFC 4271 SS9.2. Mirrors
        # link_down.py's _withdraw_pe_routes_direct() completeness
        # (Type 2 MAC/IP + Type 3 IMET always; Type 1/4 for multihomed
        # PEs only).
        fault_start_t = t
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.link_down_pe:
                tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                packets.extend(self._mark_event(rst_pkts, 'Link Down', self.link_down_pe, 'TCP RST', phase='trigger'))
                t += 0.01

                pe = bgp_sess.local_router
                macs = self.topology.get_macs_for_pe(
                    self.link_down_pe,
                    count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                          int(self.config.evpn.mac_pool_size * 0.5)))
                nlris = [evpn.build_mac_ip_route(
                    pe.bgp_id, pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
                nlris.append(evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni))
                if pe.esi and pe.esi != "0":
                    nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
                    nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                        vni=self.config.evpn.vni))
                    nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                                     self.config.evpn.vni))
                for session_id, other_tcp in self.tcp_sessions.items():
                    if self.link_down_pe in session_id or not other_tcp.is_established():
                        continue
                    for nlri in nlris:
                        path_attrs = build_evpn_withdraw_attrs(nlri)
                        update = build_update(path_attributes=path_attrs)
                        pkts = other_tcp.send_data(update, t, 'server_to_client')
                        packets.extend(self._mark_event(pkts, 'Link Down', self.link_down_pe, 'Route UPDATE', phase='trigger'))
                        t += 0.005
                break

        t += 0.5

        # FAULT 2: ES/DF toggle on esdf_pe (near simultaneous) -- withdraws
        # the Type 1 A-D per ES route, the mass-withdraw trigger signal per
        # RFC 7432 SS8.2 / RFC 8584. Type 4 follows passively as a
        # consequence, not as the trigger.
        esdf_router = self.config.get_router(self.esdf_pe)
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.esdf_pe:
                tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp_sess and tcp_sess.is_established():
                    nlri = evpn.build_ead_per_es(esdf_router.bgp_id, self.esi, self.config.evpn.vni)
                    path_attrs = build_evpn_withdraw_attrs(nlri)
                    update = build_update(path_attributes=path_attrs)
                    pkts = tcp_sess.send_data(update, t, 'server_to_client')
                    packets.extend(self._mark_event(pkts, 'ESDF Toggle', self.esdf_pe, 'Route UPDATE', phase='trigger'))
                    packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))

                    fanout_pkts, _ = self._fan_out_type4_to_other_sessions(
                        esdf_router, self.esi, 'withdraw', t + 0.01,
                        event=True, fault_type='ESDF Toggle', node=self.esdf_pe, phase='trigger')
                    packets.extend(fanout_pkts)
                break

        # Continue with surviving sessions
        no_recovery_duration = self._param_rng.uniform(300, 480)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.link_down_pe in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, no_recovery_duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, no_recovery_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class MixedESDFAndLinkDownPE1PE2(MixedESDFAndLinkDown):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, link_down_pe='PE1', esdf_pe='PE2')


# ---------------------------------------------------------------------------
# Mixed: RT misconfiguration with link down
# ---------------------------------------------------------------------------

class MixedRTMisconfigAndLinkDown(BaseScenario):
    """RT misconfiguration on one PE while another PE's link goes down."""
    FAULT_TYPE: str = 'Link Down + RT Misconfiguration'
    SECTION: int = 4

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 link_down_pe: str = 'PE2', misconfig_pe: str = 'PE3'):
        super().__init__(config, target_frames)
        self.link_down_pe = link_down_pe
        self.misconfig_pe = misconfig_pe

    def generate(self):
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        # RT misconfiguration
        fault_start_t = t
        misconfig_router = self.config.get_router(self.misconfig_pe)
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.misconfig_pe:
                tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp_sess and tcp_sess.is_established():
                    from ..bgp.attributes import (attr_origin, attr_as_path, attr_local_pref,
                                                   attr_extended_communities, attr_mp_reach_nlri,
                                                   encode_rt_community, encode_encapsulation_community)
                    from ..bgp.constants import AFI_L2VPN, SAFI_EVPN, TUNNEL_TYPE_VXLAN
                    macs = self.topology.get_macs_for_pe(
                        self.misconfig_pe,
                        count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                              int(self.config.evpn.mac_pool_size * 0.5)))
                    for mac_entry in macs:
                        nlri = evpn.build_mac_ip_route(
                            misconfig_router.bgp_id, misconfig_router.esi or "0",
                            mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
                        wrong_rt = encode_rt_community(100, 777)
                        encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                        attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
                                 + attr_extended_communities([wrong_rt, encap])
                                 + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN,
                                                      misconfig_router.bgp_id, nlri))
                        update = build_update(path_attributes=attrs)
                        pkts = tcp_sess.send_data(update, t, 'server_to_client')
                        packets.extend(self._mark_event(pkts, 'RT Misconfiguration', self.misconfig_pe, 'Route UPDATE', phase='trigger'))
                        t += 0.005
                        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                        t += 0.001
                break

        t += 30

        # Link down. Withdraw ALL of link_down_pe's routes on surviving
        # sessions, per RFC 4271 SS9.2. Mirrors link_down.py's
        # _withdraw_pe_routes_direct() completeness (Type 2 MAC/IP + Type 3
        # IMET always; Type 1/4 for multihomed PEs only).
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.link_down_pe:
                tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                packets.extend(self._mark_event(rst_pkts, 'Link Down', self.link_down_pe, 'TCP RST', phase='trigger'))
                t += 0.01

                pe = bgp_sess.local_router
                macs = self.topology.get_macs_for_pe(
                    self.link_down_pe,
                    count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                          int(self.config.evpn.mac_pool_size * 0.5)))
                nlris = [evpn.build_mac_ip_route(
                    pe.bgp_id, pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
                nlris.append(evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni))
                if pe.esi and pe.esi != "0":
                    nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
                    nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                        vni=self.config.evpn.vni))
                    nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                                     self.config.evpn.vni))
                for session_id, other_tcp in self.tcp_sessions.items():
                    if self.link_down_pe in session_id or not other_tcp.is_established():
                        continue
                    for nlri in nlris:
                        path_attrs = build_evpn_withdraw_attrs(nlri)
                        update = build_update(path_attributes=path_attrs)
                        pkts = other_tcp.send_data(update, t, 'server_to_client')
                        packets.extend(self._mark_event(pkts, 'Link Down', self.link_down_pe, 'Route UPDATE', phase='trigger'))
                        t += 0.005
                break

        # Surviving sessions continue
        no_recovery_duration = self._param_rng.uniform(300, 480)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.link_down_pe in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, no_recovery_duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, no_recovery_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class MixedRTMisconfigAndLinkDownPE2PE3(MixedRTMisconfigAndLinkDown):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, link_down_pe='PE2', misconfig_pe='PE3')


# ---------------------------------------------------------------------------
# Mid-session capture: no OPEN messages visible
# Tests model robustness when capture starts after sessions are already up
# ---------------------------------------------------------------------------

class MidSessionLinkDown(BaseScenario):
    """Capture starts mid-session — BGP sessions already established, 0 OPENs visible.

    TCP sessions are injected as ESTABLISHED with mid-stream sequence numbers.
    Normal keepalive/route traffic runs first, then a link-down fault is injected,
    followed by recovery (which produces the only OPEN messages in the capture).

    Pattern: [no handshake] → routes + keepalives → RST → silence → reconnect → OPEN → routes
    """
    FAULT_TYPE: str = 'Link Down'
    SECTION: int = 4

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_pe: str = None):
        super().__init__(config, target_frames)
        self.affected_pe_id = affected_pe or config.pe_nodes[0].id

    def _pre_establish_all_sessions(self, timestamp: float) -> float:
        """Inject all sessions as already ESTABLISHED — no packets generated."""
        from ..tcp.session import TCPState
        vantage = self.config.capture_vantage
        sessions = self.topology.get_sessions_at_vantage(vantage)
        t = timestamp
        for bgp_sess in sessions:
            pe = bgp_sess.local_router
            rr = bgp_sess.remote_router
            tcp_sess = TCPSession(
                client_ip=pe.bgp_id,
                server_ip=rr.bgp_id,
                server_port=179,
            )
            # Simulate a session that has been running for several minutes
            tcp_sess.client_seq = random.randint(50_000_000, 500_000_000)
            tcp_sess.server_seq = random.randint(50_000_000, 500_000_000)
            tcp_sess.client_ack = tcp_sess.server_seq
            tcp_sess.server_ack = tcp_sess.client_seq
            tcp_sess.state = TCPState.ESTABLISHED
            self.tcp_sessions[bgp_sess.session_id] = tcp_sess
            t += 0.001
        return t

    def _find_session_for_pe(self, pe_id: str):
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                return bgp_sess.session_id
        return None

    def _withdraw_pe_routes(self, pe, timestamp: float) -> list[TCPPacket]:
        """Send MP_UNREACH_NLRI withdrawals for ALL of a PE's routes on
        surviving sessions, per RFC 4271 SS9.2 -- not just Type 3 IMET.
        Mirrors link_down.py's _withdraw_pe_routes_direct() completeness
        (Type 2 MAC/IP + Type 3 IMET always; Type 1/4 for multihomed PEs
        only).
        """
        packets = []
        from ..bgp.attributes import build_evpn_withdraw_attrs
        macs = self.topology.get_macs_for_pe(
            pe.id,
            count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                  int(self.config.evpn.mac_pool_size * 0.5)))
        nlris = [evpn.build_mac_ip_route(
            pe.bgp_id, pe.esi or "0", mac_entry.mac,
            ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
        nlris.append(evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni))
        if pe.esi and pe.esi != "0":
            nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
            nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                vni=self.config.evpn.vni))
            nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                             self.config.evpn.vni))
        for session_id, tcp_sess in self.tcp_sessions.items():
            if pe.id in session_id or not tcp_sess.is_established():
                continue
            for nlri in nlris:
                attrs = build_evpn_withdraw_attrs(nlri)
                update = build_update(path_attributes=attrs)
                pkts = tcp_sess.send_data(update, timestamp, 'server_to_client')
                packets.extend(pkts)
                timestamp += 0.005
                packets.extend(tcp_sess.generate_ack(timestamp, 'client_to_server'))
                timestamp += 0.001
        return packets

    def _generate_other_keepalives(self, start: float, duration: float) -> list[TCPPacket]:
        """Generate keepalives on all sessions except the affected PE."""
        packets = []
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_pe_id in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(start, duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
        return packets

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # No session establishment — sessions already up before capture started
        t = self._pre_establish_all_sessions(t)

        # Initial routes (simulate what would already be in routing table)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Normal warmup — only keepalives, no OPENs
        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        # FAULT: link drops on affected PE (TCP RST)
        fault_start_t = t
        affected_session = None
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.affected_pe_id:
                affected_session = bgp_sess
                break

        if affected_session:
            tcp_sess = self.tcp_sessions[affected_session.session_id]
            rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
            packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST', phase='trigger'))
            t += 0.01
            withdraw_pkts = self._withdraw_pe_routes(affected_session.local_router, t)
            packets.extend(self._mark_event(withdraw_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))

        # Silence period
        silence_duration = self._param_rng.uniform(20, 30)
        packets.extend(self._generate_other_keepalives(t, silence_duration))
        t += silence_duration

        # RECOVERY: fresh TCP + OPEN exchange (first OPENs in this capture)
        if affected_session:
            pe = affected_session.local_router
            rr = affected_session.remote_router
            new_tcp = TCPSession(
                client_ip=pe.bgp_id,
                server_ip=rr.bgp_id,
                server_port=179,
            )
            self.tcp_sessions[affected_session.session_id] = new_tcp
            packets.extend(new_tcp.connect(timestamp=t))
            t += 0.02

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  pe.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
            t += 0.005

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  rr.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
            t += 0.002

            ka = build_keepalive()
            packets.extend(new_tcp.send_data(ka, t, 'client_to_server'))
            packets.extend(new_tcp.send_data(ka, t + 0.001, 'server_to_client'))
            t += 0.01

            route_pkts = self.generate_route_updates(
                affected_session.session_id, pe, num_routes=5, start_time=t)
            packets.extend(route_pkts)
            t += 1.0

        fault_end_t = t

        # Post-recovery normal traffic
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                * self.config.timing.keepalive_timer)
            packets.extend(self.generate_keepalives_for_duration(t, post_duration))

        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class MidSessionLinkDownPE1(MidSessionLinkDown):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class MidSessionLinkDownPE2(MidSessionLinkDown):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')

class MidSessionLinkDownPE3(MidSessionLinkDown):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')
