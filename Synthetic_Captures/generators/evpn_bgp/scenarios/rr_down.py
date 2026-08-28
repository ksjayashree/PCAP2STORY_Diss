"""Section 2 — Route Reflector Down fault scenarios.

Simulates RR failures where all PE sessions drop simultaneously.
Captured from the perspective of the OTHER RR (which is still up).
"""

import random
from typing import Optional
from .base import BaseScenario
from ..config import TopologyConfig, RouterConfig
from ..tcp.session import TCPSession, TCPPacket
from ..bgp.messages import build_notification, build_keepalive, build_open
from ..bgp.capabilities import default_evpn_capabilities
from ..bgp.constants import ERR_HOLD_TIMER_EXPIRED, ERR_CEASE, CEASE_ADMIN_RESET
from ..bgp.attributes import build_standard_evpn_path_attrs
from generators.common.utils.timing import (
    jittered_interval, ack_delay, keepalive_timestamps
)

_NOTIF_NAME = {
    (ERR_CEASE, CEASE_ADMIN_RESET): 'Cease/Administrative Reset',
    (ERR_HOLD_TIMER_EXPIRED, 0): 'Hold Timer Expired',
}


class RRDownCleanRestart(BaseScenario):
    """RR goes down, comes back within 25-30 seconds, all PEs reconnect.

    Captured from whichever RR is NOT affected_rr_id (the vantage is
    overridden in __init__ to the surviving RR).
    """
    FAULT_TYPE: str = 'RR Down'
    SECTION: int = 2
    
    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_rr: str = "RR1", mid_churn: bool = False):
        # Override vantage to the OTHER RR
        super().__init__(config, target_frames)
        self.affected_rr_id = affected_rr
        self.mid_churn = mid_churn  # inject fault mid-warmup-churn-burst instead of after idle
        # Find alternate vantage (the other RR)
        other_rrs = [rr for rr in config.route_reflectors if rr.id != affected_rr]
        self.vantage_rr = other_rrs[0] if other_rrs else config.route_reflectors[0]
        # Override the capture vantage
        self.config.capture_vantage = self.vantage_rr.id
        # Rebuild topology with new vantage
        self.topology = type(self.topology)(self.config)

        # {pe_id: [MACEntry, ...]} captured by
        # _second_hop_withdraw_affected_rr_clients() at withdrawal time and
        # reused (via macs_override) by every recovery re-advertisement, so
        # recovery re-advertises the exact routes the withdrawal removed.
        # For RRDownIntermittentFlap's per-cycle loop, this single dict is
        # overwritten at each cycle's withdrawal and read immediately by
        # that same cycle's recovery before the next cycle's withdrawal runs.
        self._withdrawn_macs_by_pe: dict = {}

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish sessions (from RR2 vantage - sees PE→RR2 sessions + RR1→RR2)
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Warmup with normal traffic
        warmup_duration = self._param_rng.randint(120, 480)
        t = self.warmup_with_optional_mid_churn(packets, t, warmup_duration,
                                                mid_churn=self.mid_churn)

        # FAULT: RR1 goes down
        # From RR2's perspective: the RR1→RR2 session drops
        # Then: RR2 stops receiving reflected routes from RR1
        # The PE sessions to RR2 remain UP (RR2 is still alive)
        
        fault_start_t = t

        # RR1-RR2 session drops (TCP RST)
        rr_session_id = None
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
                rr_session_id = session_id
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
                packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_rr_id, 'TCP RST', phase='trigger'))
                break

        t += 0.5

        wd_pkts, t = self._second_hop_withdraw_affected_rr_clients(t)
        packets.extend(wd_pkts)

        # Silence period (25-30 seconds) — PE→RR2 sessions still up
        silence_duration = self._param_rng.uniform(25, 30)
        # Only PE-to-vantage sessions continue
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, silence_duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
                t_s = ka_t + jittered_interval(self.config.timing.keepalive_timer / 3, 0.3)
                if t_s < t + silence_duration:
                    pkts = tcp_sess.send_data(ka_msg, t_s, 'server_to_client')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t_s + ack_delay(), 'client_to_server'))
        
        t += silence_duration

        # RECOVERY: RR1 comes back, reconnects to RR2
        recon_pkts, t = self._reconnect_and_resync(rr_session_id, t)
        packets.extend(recon_pkts)

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # Post-recovery normal traffic
        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration,
                                      last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(
                t, post_duration, last_update_times=last_update_times2))

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]

    def _rr_route_sync(self, tcp_sess: TCPSession, start_t: float,
                       event: bool = False, phase: str = None) -> tuple[list[TCPPacket], float]:
        return self.reflect_pe_routes_to_rr(tcp_sess, start_t, event=event,
                                            fault_type=self.FAULT_TYPE, node=self.affected_rr_id,
                                            phase=phase)

    def _second_hop_withdraw_affected_rr_clients(self, start_t: float,
                                                  event: bool = True) -> tuple[list[TCPPacket], float]:
        """RFC 4271/4456: when the affected RR's session to the vantage RR
        drops, the vantage RR loses its only path to that RR's clients'
        routes and must withdraw them toward its own clients -- not leave
        them silently stale. Ordinary (non-Graceful-Restart) RR Down only.
        """
        packets = []
        t = start_t
        # This method is also called as an unbound method on
        # non-RRDownCleanRestart instances (e.g. section4.py's
        # CascadeRRDownESDFRR1/RR2), so the cache dict may not exist on
        # self yet.
        if not hasattr(self, '_withdrawn_macs_by_pe'):
            self._withdrawn_macs_by_pe = {}
        affected_pes = [pe for pe in self.config.pe_nodes
                        if pe.peers and pe.peers[0] == self.affected_rr_id]
        # 2ms relay-processing gap between the RR-RR session loss landing
        # and second-hop withdrawal to the vantage RR's own clients
        # beginning (once, not per-PE in the loop below).
        t += 0.002
        for pe in affected_pes:
            # Cached so the recovery re-advertisement for this PE can pass
            # the identical MAC set via macs_override.
            macs = self.topology.get_macs_for_pe(
                pe.id, count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                            int(self.config.evpn.mac_pool_size * 0.5)))
            self._withdrawn_macs_by_pe[pe.id] = macs
            wd_pkts, t = self.reflect_to_own_clients(pe, t, action='withdraw', event=event,
                                                     fault_type=self.FAULT_TYPE, node=self.affected_rr_id,
                                                     macs_override=macs, phase='trigger')
            packets.extend(wd_pkts)
        return packets, t

    def _reconnect_and_resync(self, rr_session_id: Optional[str],
                              start_t: float) -> tuple[list[TCPPacket], float]:
        """RR1 comes back and reconnects to RR2: TCP + OPEN + KEEPALIVE
        exchange on the RR-RR session, followed by full route resync
        (reflect_pe_routes_to_rr) and second-hop re-advertisement to the
        vantage RR's own clients (reflect_to_own_clients). Relies on
        self.affected_rr_id, self.vantage_rr, self.config, self.tcp_sessions,
        self.FAULT_TYPE being set on the calling instance -- general enough
        to be called as an unbound method from any scenario that models an
        RR reconnecting after a drop. Returns (packets, t) with the
        timestamp after the full reconnect+resync sequence completes.

        No-op (returns ([], start_t)) if rr_session_id is falsy.
        """
        packets = []
        t = start_t
        if not rr_session_id:
            return packets, t

        affected_rr = self.config.get_router(self.affected_rr_id)
        # CONVENTION pcap2story DEPENDS ON: the affected RR is always the
        # TCP client on reconnect, never the surviving vantage RR --
        # pcap2story infers root_cause_node from the reconnect SYN's source
        # node. The assert below fails loudly if that convention is violated.
        new_tcp = TCPSession(
            client_ip=affected_rr.bgp_id,
            server_ip=self.vantage_rr.bgp_id,
            server_port=179
        )
        assert new_tcp.client_ip == affected_rr.bgp_id, (
            "reconnect must be initiated by the previously-affected RR -- "
            "pcap2story's root-cause attribution depends on this convention")
        self.tcp_sessions[rr_session_id] = new_tcp

        # TCP + OPEN exchange
        connect_pkts = new_tcp.connect(timestamp=t)
        packets.extend(connect_pkts)
        t += 0.02

        open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                              affected_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
        pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
        packets.extend(pkts)
        t += ack_delay()
        packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
        t += 0.005

        open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                              self.vantage_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
        pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
        packets.extend(pkts)
        t += ack_delay()
        packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
        t += 0.002

        ka = build_keepalive()
        pkts = new_tcp.send_data(ka, t, 'client_to_server')
        packets.extend(pkts)
        pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
        packets.extend(pkts)
        t += 0.01

        route_pkts, t = self._rr_route_sync(new_tcp, t, event=True, phase='recovery')
        packets.extend(route_pkts)

        # 2ms relay-processing gap between first-hop landing and second-hop
        # relay beginning (once, not per-PE in the loop below).
        t += 0.002
        affected_pes = [pe for pe in self.config.pe_nodes
                       if pe.peers and pe.peers[0] == self.affected_rr_id]
        for pe in affected_pes:
            sh_pkts, t = self.reflect_to_own_clients(pe, t, action='advertise', event=True, fault_type=self.FAULT_TYPE, node=self.affected_rr_id, macs_override=self._withdrawn_macs_by_pe.get(pe.id), phase='recovery')
            packets.extend(sh_pkts)

        return packets, t


class RRDownSlowRestart(RRDownCleanRestart):
    """RR down for 3-5 minutes before returning."""
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration
        fault_start_t = t
        rr_session_id = None
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
                rr_session_id = session_id
                notification = build_notification(ERR_HOLD_TIMER_EXPIRED, 0)
                pkts = tcp_sess.send_data(notification, t, 'client_to_server')
                packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_rr_id, 'BGP NOTIFICATION: Hold Timer Expired', phase='trigger'))
                t += 0.001
                close_pkts = tcp_sess.close_graceful(t, initiator='client')
                packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_rr_id, 'Graceful FIN Close', phase='trigger'))
                break

        t += 0.5

        wd_pkts, t = self._second_hop_withdraw_affected_rr_clients(t)
        packets.extend(wd_pkts)

        # LONG silence (3-5 minutes)
        silence_duration = self._param_rng.uniform(180, 300)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, silence_duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
                t_s = ka_t + jittered_interval(self.config.timing.keepalive_timer / 3, 0.3)
                if t_s < t + silence_duration:
                    pkts = tcp_sess.send_data(ka_msg, t_s, 'server_to_client')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t_s + ack_delay(), 'client_to_server'))
        
        t += silence_duration
        
        # Recovery (same as clean restart)
        if rr_session_id:
            affected_rr = self.config.get_router(self.affected_rr_id)
            new_tcp = TCPSession(
                client_ip=affected_rr.bgp_id,
                server_ip=self.vantage_rr.bgp_id,
                server_port=179
            )
            assert new_tcp.client_ip == affected_rr.bgp_id, (
                "reconnect must be initiated by the affected RR -- "
                "pcap2story's root-cause attribution depends on this convention")
            self.tcp_sessions[rr_session_id] = new_tcp

            connect_pkts = new_tcp.connect(timestamp=t)
            packets.extend(connect_pkts)
            t += 0.02

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  affected_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
            t += 0.005

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  self.vantage_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
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
            t += 0.02

            route_pkts, t = self._rr_route_sync(new_tcp, t, event=True, phase='recovery')
            packets.extend(route_pkts)

            # 2ms relay-processing gap between first-hop landing and
            # second-hop relay beginning (once, not per-PE in the loop below).
            t += 0.002
            affected_pes = [pe for pe in self.config.pe_nodes
                           if pe.peers and pe.peers[0] == self.affected_rr_id]
            for pe in affected_pes:
                sh_pkts, t = self.reflect_to_own_clients(pe, t, action='advertise', event=True, fault_type=self.FAULT_TYPE, node=self.affected_rr_id, macs_override=self._withdrawn_macs_by_pe.get(pe.id), phase='recovery')
                packets.extend(sh_pkts)

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t
        
        # Post-recovery
        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration,
                                      last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(
                t, post_duration, last_update_times=last_update_times2))

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class RRDownNoRecovery(RRDownCleanRestart):
    """RR stays down for remainder of capture."""
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration
        fault_start_t = t

        # FAULT: RR1 drops (TCP RST)
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
                packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_rr_id, 'TCP RST', phase='trigger'))
                break

        t += 0.5

        wd_pkts, t = self._second_hop_withdraw_affected_rr_clients(t)
        packets.extend(wd_pkts)

        # No recovery — remaining sessions continue for 8-10 minutes
        no_recovery_duration = self._param_rng.uniform(480, 600)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, no_recovery_duration, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
                t_s = ka_t + jittered_interval(self.config.timing.keepalive_timer / 3, 0.3)
                if t_s < t + no_recovery_duration:
                    pkts = tcp_sess.send_data(ka_msg, t_s, 'server_to_client')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t_s + ack_delay(), 'client_to_server'))

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, no_recovery_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


# class RRDownGracefulRestart(RRDownCleanRestart):
#     """Graceful Restart (RFC 4724), silent-drop case: affected RR's RR-RR
#     session drops abruptly via a bare TCP RST -- no NOTIFICATION -- but the
#     surviving RR does NOT withdraw the reflected PEs' routes (kept as
#     stale, not withdrawn -- the key distinguishing feature from ordinary RR
#     Down, mirroring LinkDownGracefulRestart). The restarting RR reconnects
#     advertising the Graceful Restart capability with the Restart State bit
#     set, re-reflects all PE routes, and an End-of-RIB marker (scoped to
#     just this session) signals resync complete.

#     This is RFC 4724's original base case specifically. For the RFC 8538
#     case (explicit NOTIFICATION, still graceful via the negotiated
#     Notification bit), see RRDownGracefulRestartNotified.
#     """

#     FAULT_TYPE: str = 'Graceful Restart'

#     # RFC 8538 variant hook -- overridden by RRDownGracefulRestartNotified.
#     NOTIFICATION_ERROR = None
#     # RFC 8538 SS3 applies "regardless of the reason" -- overridden by
#     # RRDownGracefulRestartNotifiedHoldTimer to precede the notification
#     # with a hold-timer-style silence window instead of firing it abruptly.
#     NOTIFICATION_SILENCE_FIRST = False

#     def generate(self) -> list[TCPPacket]:
#         packets = []
#         t = self.start_time

#         notif_session_id = None
#         if self.NOTIFICATION_ERROR is not None:
#             for bgp_sess in self.topology.get_sessions_at_vantage():
#                 if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
#                     notif_session_id = bgp_sess.session_id
#                     break
#         setup_pkts, t = self.establish_all_sessions(
#             t, notification_tolerant_session_id=notif_session_id)
#         packets.extend(setup_pkts)

#         init_routes, t = self.generate_initial_routes(t)
#         packets.extend(init_routes)

#         warmup_duration = random.randint(120, 480)
#         last_update_times: dict = {}
#         self.generate_route_churn(packets, t, warmup_duration,
#                                   last_update_times=last_update_times)
#         packets.extend(self.generate_keepalives_for_duration(
#             t, warmup_duration, last_update_times=last_update_times))
#         t += warmup_duration
#         fault_start_t = t

#         # FAULT: RR-RR session drops (RST) -- CRITICAL: no PE route
#         # withdrawal anywhere here, distinguishing GR from ordinary RR Down.
#         rr_session_id = None
#         for session_id, tcp_sess in self.tcp_sessions.items():
#             if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
#                 rr_session_id = session_id
#                 if self.NOTIFICATION_ERROR is not None:
#                     if self.NOTIFICATION_SILENCE_FIRST:
#                         hold_silence = float(self.config.timing.hold_timer) + random.uniform(2, 10)
#                         ka_msg = build_keepalive()
#                         for sid2, sess2 in self.tcp_sessions.items():
#                             if self.affected_rr_id in sid2 or not sess2.is_established():
#                                 continue
#                             for ka_t in keepalive_timestamps(t, hold_silence, self.config.timing.keepalive_timer):
#                                 pkts = sess2.send_data(ka_msg, ka_t, 'client_to_server')
#                                 packets.extend(pkts)
#                                 packets.extend(sess2.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#                                 t_s = ka_t + jittered_interval(self.config.timing.keepalive_timer / 3, 0.3)
#                                 if t_s < t + hold_silence:
#                                     pkts = sess2.send_data(ka_msg, t_s, 'server_to_client')
#                                     packets.extend(pkts)
#                                     packets.extend(sess2.generate_ack(t_s + ack_delay(), 'client_to_server'))
#                         t += hold_silence
#                     err_code, err_subcode = self.NOTIFICATION_ERROR
#                     notification = build_notification(err_code, err_subcode)
#                     pkts = tcp_sess.send_data(notification, t, 'client_to_server')
#                     notif_name = _NOTIF_NAME.get((err_code, err_subcode), 'Unknown')
#                     packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_rr_id,
#                                                     f'BGP NOTIFICATION: {notif_name}'))
#                     t += 0.001
#                     close_pkts = tcp_sess.close_graceful(t, initiator='client')
#                     packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_rr_id,
#                                                     'Graceful FIN Close'))
#                 else:
#                     rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
#                     packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_rr_id, 'TCP RST'))
#                 break

#         t += random.uniform(2, 8)  # process-restart gap

#         if rr_session_id:
#             affected_rr = self.config.get_router(self.affected_rr_id)
#             new_tcp = TCPSession(
#                 client_ip=affected_rr.loopback,
#                 server_ip=self.vantage_rr.loopback,
#                 server_port=179
#             )
#             self.tcp_sessions[rr_session_id] = new_tcp

#             connect_pkts = new_tcp.connect(timestamp=t)
#             packets.extend(connect_pkts)
#             t += 0.02

#             notif_tolerant = self.NOTIFICATION_ERROR is not None
#             gr_caps = default_evpn_capabilities(self.config.as_number, is_restart=True,
#                                                 is_notification_tolerant=notif_tolerant)
#             open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                   affected_rr.bgp_id, gr_caps)
#             pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
#             packets.extend(pkts)
#             t += ack_delay()
#             packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
#             t += 0.005

#             rr_caps = default_evpn_capabilities(self.config.as_number,
#                                                 is_notification_tolerant=notif_tolerant)
#             open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                   self.vantage_rr.bgp_id, rr_caps)
#             pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
#             packets.extend(pkts)
#             t += ack_delay()
#             packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
#             t += 0.002

#             ka = build_keepalive()
#             pkts = new_tcp.send_data(ka, t, 'client_to_server')
#             packets.extend(pkts)
#             pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
#             packets.extend(pkts)
#             t += 0.01

#             # Full resync -- all PEs, matching cold-start/ordinary-recovery default.
#             route_pkts, t = self.reflect_pe_routes_to_rr(new_tcp, t, event=True, fault_type=self.FAULT_TYPE, node=self.affected_rr_id)
#             packets.extend(route_pkts)

#             # Scoped End-of-RIB -- just this session, not every session.
#             eor_pkts, t = self._generate_eor_for_session(new_tcp, t, event=True, fault_type=self.FAULT_TYPE, node=self.affected_rr_id)
#             packets.extend(eor_pkts)

#         fault_end_t = t + self.BASELINE_CHECK_WINDOW
#         self._fault_start_t = fault_start_t
#         self._fault_end_t = fault_end_t

#         remaining = int(self.target_frames * 0.26) - len(packets)
#         post_duration = 60
#         if remaining > 0:
#             post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
#             last_update_times2: dict = {}
#             self.generate_route_churn(packets, t, post_duration,
#                                       last_update_times=last_update_times2)
#             packets.extend(self.generate_keepalives_for_duration(
#                 t, post_duration, last_update_times=last_update_times2))

#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
#             packets.extend(pad_pkts)

#         packets.sort(key=lambda p: p.timestamp)
#         return packets[:self.target_frames]


# class RRDownGracefulRestartRR2(RRDownGracefulRestart):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2')


# class RRDownGracefulRestartNotified(RRDownGracefulRestart):
#     """Graceful Restart (RFC 8538 variant): RR-RR session torn down via an
#     explicit BGP NOTIFICATION (Administrative Reset) instead of a bare RST,
#     but still treated as graceful -- no PE route withdrawal, stale routes
#     kept -- because both sides negotiate the Notification (N) bit.
#     """
#     NOTIFICATION_ERROR = (ERR_CEASE, CEASE_ADMIN_RESET)

#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2')


# class RRDownGracefulRestartNotifiedHoldTimer(RRDownGracefulRestart):
#     """Graceful Restart (RFC 8538 variant): RR-RR session torn down via an
#     explicit Hold Timer Expired NOTIFICATION (preceded by the normal
#     hold-timer silence window, unlike the abrupt Cease/Administrative-Reset
#     variant), but still treated as graceful -- no PE route withdrawal,
#     stale routes kept -- because both sides negotiate the Notification (N)
#     bit. Distinct, equally RFC 8538 SS3-valid trigger from
#     RRDownGracefulRestartNotified's Cease/Administrative-Reset case.
#     """
#     NOTIFICATION_ERROR = (ERR_HOLD_TIMER_EXPIRED, 0)
#     NOTIFICATION_SILENCE_FIRST = True

#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2')


# class RRDownGracefulRestartTimeout(RRDownCleanRestart):
#     """Graceful Restart (RFC 4724 SS4.2): restart timer expiry, no recovery.

#     Same silent-drop opening as RRDownGracefulRestart (bare RST on the
#     RR-RR session, no PE route withdrawal -- stale retention per the GR
#     contract) but the affected RR never reconnects. Per RFC 4724 SS4.2, if
#     the session isn't re-established within the Restart Time (120s, same
#     value as cap_graceful_restart(restart_time=120) elsewhere), the
#     surviving RR MUST delete the stale routes it was holding on the
#     affected RR's behalf. The withdrawal here is deliberately DELAYED until
#     the restart-timer deadline -- reuses the same second-hop withdrawal
#     helper (_second_hop_withdraw_affected_rr_clients) as ordinary RR Down,
#     just fired after the timeout instead of immediately after the RST.
#     """

#     FAULT_TYPE: str = 'Graceful Restart'
#     RESTART_TIME: int = 120

#     def __init__(self, config, target_frames=30000, affected_rr='RR2'):
#         super().__init__(config, target_frames, affected_rr=affected_rr)

#     def generate(self) -> list[TCPPacket]:
#         packets = []
#         t = self.start_time

#         setup_pkts, t = self.establish_all_sessions(t)
#         packets.extend(setup_pkts)

#         init_routes, t = self.generate_initial_routes(t)
#         packets.extend(init_routes)

#         warmup_duration = random.randint(120, 480)
#         last_update_times: dict = {}
#         self.generate_route_churn(packets, t, warmup_duration,
#                                   last_update_times=last_update_times)
#         packets.extend(self.generate_keepalives_for_duration(
#             t, warmup_duration, last_update_times=last_update_times))
#         t += warmup_duration
#         fault_start_t = t

#         for session_id, tcp_sess in self.tcp_sessions.items():
#             if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
#                 rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
#                 packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_rr_id, 'TCP RST'))
#                 break
#         t += 0.5

#         # Wait past the restart timer -- no reconnect ever occurs.
#         t += self.RESTART_TIME + random.uniform(2, 10)

#         wd_pkts, t = self._second_hop_withdraw_affected_rr_clients(t)
#         packets.extend(wd_pkts)

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None

#         remaining = int(self.target_frames * 0.26) - len(packets)
#         post_duration = 60
#         if remaining > 0:
#             post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
#                                 * self.config.timing.keepalive_timer)
#             last_update_times2: dict = {}
#             self.generate_route_churn(packets, t, post_duration,
#                                       last_update_times=last_update_times2)
#             packets.extend(self.generate_keepalives_for_duration(
#                 t, post_duration, last_update_times=last_update_times2))

#         packets.sort(key=lambda p: p.timestamp)

#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
#             packets.extend(pad_pkts)
#             packets.sort(key=lambda p: p.timestamp)

#         return packets[:self.target_frames]


# ---------------------------------------------------------------------------
# RR-specific subclasses
# ---------------------------------------------------------------------------

class RRDownCleanRestartRR1(RRDownCleanRestart):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR1')

class RRDownCleanRestartRR2(RRDownCleanRestart):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2')

# Non-idle injection timing: fault fires mid-churn-burst instead of after idle warmup.
class RRDownCleanRestartMidChurnRR2(RRDownCleanRestart):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2', mid_churn=True)

class RRDownSlowRestartRR1(RRDownSlowRestart):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR1')

class RRDownSlowRestartRR2(RRDownSlowRestart):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2')

class RRDownNoRecoveryRR1(RRDownNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_rr='RR1')

class RRDownNoRecoveryRR2(RRDownNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_rr='RR2')


class RRDownHoldTimerExpiry(RRDownCleanRestart):
    """RR1 silently stops responding — hold timer expires on RR2 side before session tears down.

    Unlike CleanRestart (TCP RST), this simulates a link degradation where
    keepalives stop arriving but no RST is sent. RR2 waits the full hold timer
    (30s) before sending NOTIFICATION Hold Timer Expired and closing the session.
    """

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        rr_session_id = None
        rr_tcp_sess = None
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
                rr_session_id = session_id
                rr_tcp_sess = tcp_sess
                break

        # Hold timer silence — RR1 stops sending KAs, PE→RR2 sessions stay active
        hold_silence = float(self.config.timing.hold_timer)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_rr_id in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, hold_silence, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
                t_s = ka_t + jittered_interval(self.config.timing.keepalive_timer / 3, 0.3)
                if t_s < t + hold_silence:
                    pkts = tcp_sess.send_data(ka_msg, t_s, 'server_to_client')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t_s + ack_delay(), 'client_to_server'))

        t += hold_silence

        # Hold timer expires — RR2 sends NOTIFICATION and closes
        notification_t = t  # first CSV-visible event for fw.json start
        if rr_tcp_sess and rr_tcp_sess.is_established():
            notification = build_notification(ERR_HOLD_TIMER_EXPIRED, 0)
            pkts = rr_tcp_sess.send_data(notification, t, 'server_to_client')
            packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_rr_id, 'BGP NOTIFICATION: Hold Timer Expired', phase='trigger'))
            t += 0.001
            close_pkts = rr_tcp_sess.close_graceful(t, initiator='server')
            packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_rr_id, 'Graceful FIN Close', phase='trigger'))

        t += 0.5

        wd_pkts, t = self._second_hop_withdraw_affected_rr_clients(t)
        packets.extend(wd_pkts)

        # RECOVERY: RR1 reconnects after a short delay
        if rr_session_id:
            affected_rr = self.config.get_router(self.affected_rr_id)
            new_tcp = TCPSession(
                client_ip=affected_rr.bgp_id,
                server_ip=self.vantage_rr.bgp_id,
                server_port=179
            )
            # See _reconnect_and_resync()'s comment: pcap2story's root-cause
            # attribution depends on the affected RR always being the client.
            assert new_tcp.client_ip == affected_rr.bgp_id, (
                "reconnect must be initiated by the affected RR -- "
                "pcap2story's root-cause attribution depends on this convention")
            self.tcp_sessions[rr_session_id] = new_tcp

            # TCP + OPEN exchange (session housekeeping — not fault events)
            connect_pkts = new_tcp.connect(timestamp=t)
            packets.extend(connect_pkts)
            t += 0.02

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  affected_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
            t += 0.005

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  self.vantage_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
            t += 0.002

            ka = build_keepalive()
            pkts = new_tcp.send_data(ka, t, 'client_to_server')
            packets.extend(pkts)
            pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
            packets.extend(pkts)
            t += 0.01

            # Full route sync — fault events
            route_pkts, t = self._rr_route_sync(new_tcp, t, event=True, phase='recovery')
            packets.extend(route_pkts)

            # 2ms relay-processing gap between first-hop landing and
            # second-hop relay beginning (once, not per-PE in the loop below).
            t += 0.002
            affected_pes = [pe for pe in self.config.pe_nodes
                           if pe.peers and pe.peers[0] == self.affected_rr_id]
            for pe in affected_pes:
                sh_pkts, t = self.reflect_to_own_clients(pe, t, action='advertise', event=True, fault_type=self.FAULT_TYPE, node=self.affected_rr_id, macs_override=self._withdrawn_macs_by_pe.get(pe.id), phase='recovery')
                packets.extend(sh_pkts)

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        # fw.json start = notification_t (first CSV-visible event).
        self._fault_start_t = notification_t
        self._fault_end_t = fault_end_t

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration,
                                      last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(
                t, post_duration, last_update_times=last_update_times2))

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class RRDownHoldTimerExpiryRR1(RRDownHoldTimerExpiry):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR1')

class RRDownHoldTimerExpiryRR2(RRDownHoldTimerExpiry):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_rr='RR2')


class RRDownIntermittentFlap(RRDownCleanRestart):
    """RR1 goes down and comes back 3 times in quick succession.

    Each cycle: RST → 15-25s silence (PE sessions still active) → full reconnect
    + route sync. Covers the flapping/instability pattern.
    """

    # Registered under section 3 in cli.py's SCENARIO_REGISTRY.
    SECTION: int = 3

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 300)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        rr_session_id = None
        for session_id in self.tcp_sessions:
            if self.affected_rr_id in session_id and self.vantage_rr.id in session_id:
                rr_session_id = session_id
                break

        first_flap_start_t = None  # first flap's RST timestamp, across all flaps

        for flap_idx in range(3):
            if first_flap_start_t is None:
                first_flap_start_t = t

            # Drop
            tcp_sess = self.tcp_sessions.get(rr_session_id)
            if tcp_sess and tcp_sess.is_established():
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
                packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_rr_id, 'TCP RST', phase='trigger'))

            t += 0.5

            wd_pkts, t = self._second_hop_withdraw_affected_rr_clients(t)
            packets.extend(wd_pkts)

            # Silence — PE→RR2 sessions keep going
            silence_duration = self._param_rng.uniform(15, 25)
            ka_msg = build_keepalive()
            for session_id, sess in self.tcp_sessions.items():
                if self.affected_rr_id in session_id or not sess.is_established():
                    continue
                for ka_t in keepalive_timestamps(t, silence_duration, self.config.timing.keepalive_timer):
                    pkts = sess.send_data(ka_msg, ka_t, 'client_to_server')
                    packets.extend(pkts)
                    packets.extend(sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
                    t_s = ka_t + jittered_interval(self.config.timing.keepalive_timer / 3, 0.3)
                    if t_s < t + silence_duration:
                        pkts = sess.send_data(ka_msg, t_s, 'server_to_client')
                        packets.extend(pkts)
                        packets.extend(sess.generate_ack(t_s + ack_delay(), 'client_to_server'))
            t += silence_duration

            # Recovery
            if rr_session_id:
                affected_rr = self.config.get_router(self.affected_rr_id)
                new_tcp = TCPSession(
                    client_ip=affected_rr.bgp_id,
                    server_ip=self.vantage_rr.bgp_id,
                    server_port=179
                )
                assert new_tcp.client_ip == affected_rr.bgp_id, (
                    "reconnect must be initiated by the previously-affected RR -- "
                    "pcap2story's root-cause attribution depends on this convention")
                self.tcp_sessions[rr_session_id] = new_tcp

                connect_pkts = new_tcp.connect(timestamp=t)
                packets.extend(connect_pkts)
                t += 0.02

                open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                      affected_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
                pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
                packets.extend(pkts)
                t += ack_delay()
                packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
                t += 0.005

                open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                      self.vantage_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
                pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
                packets.extend(pkts)
                t += ack_delay()
                packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
                t += 0.002

                ka = build_keepalive()
                pkts = new_tcp.send_data(ka, t, 'client_to_server')
                packets.extend(pkts)
                pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
                packets.extend(pkts)
                t += 0.01

                # Route sync for this flap — fault events
                route_pkts, t = self._rr_route_sync(new_tcp, t, event=True, phase='recovery')
                packets.extend(route_pkts)

                # 2ms relay-processing gap between first-hop landing and
                # second-hop relay beginning (once, not per-PE in the loop below).
                t += 0.002
                affected_pes = [pe for pe in self.config.pe_nodes
                               if pe.peers and pe.peers[0] == self.affected_rr_id]
                for pe in affected_pes:
                    sh_pkts, t = self.reflect_to_own_clients(pe, t, action='advertise', event=True, fault_type=self.FAULT_TYPE, node=self.affected_rr_id, macs_override=self._withdrawn_macs_by_pe.get(pe.id), phase='recovery')
                    packets.extend(sh_pkts)

            # Brief stable period between flaps (skip after last)
            if flap_idx < 2:
                stable_duration = self._param_rng.uniform(30, 60)
                stable_update_times: dict = {}
                self.generate_route_churn(packets, t, stable_duration,
                                          last_update_times=stable_update_times)
                packets.extend(self.generate_keepalives_for_duration(
                    t, stable_duration, last_update_times=stable_update_times))
                t += stable_duration

        # fw.json spans from first flap's RST to end of last recovery.
        self._fault_start_t = first_flap_start_t
        self._fault_end_t = t + self.BASELINE_CHECK_WINDOW

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration,
                                      last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(
                t, post_duration, last_update_times=last_update_times2))

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class RRDownIntermittentFlapRR1(RRDownIntermittentFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_rr='RR1')

class RRDownIntermittentFlapRR2(RRDownIntermittentFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_rr='RR2')


class RRDownBothSimultaneous(RRDownNoRecovery):
    """Both RR1 and RR2 fail simultaneously — all PE sessions drop at once."""

    def generate(self):
        import random
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
        fault_start_t = t

        session_lookup = {s.session_id: s for s in self.topology.get_sessions_at_vantage()}

        for session_id, tcp_sess in list(self.tcp_sessions.items()):
            if tcp_sess.is_established():
                bgp_sess = session_lookup.get(session_id)
                if bgp_sess and bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                    node = self.affected_rr_id  # the RR-RR link -- represents the peer RR failing
                else:
                    node = self.vantage_rr.id   # a direct PE session -- represents this vantage RR failing locally
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
                packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, node, 'TCP RST', phase='trigger'))
                t += random.uniform(0.01, 0.1)

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, self.BASELINE_CHECK_WINDOW, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]
