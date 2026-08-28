"""Section 3 — Mixed inference captures for robustness testing.

These simulate real-world conditions: normal traffic with faults
buried in the middle. Used ONLY for testing, not training.
"""

import random
from .base import BaseScenario
from .link_down import LinkDownScenario
from .rr_down import RRDownCleanRestart
from ..config import TopologyConfig, RouterConfig
from ..tcp.session import TCPSession, TCPPacket
from ..bgp.messages import build_notification, build_keepalive, build_open, build_update
from ..bgp.capabilities import default_evpn_capabilities
from ..bgp.constants import (
    ERR_HOLD_TIMER_EXPIRED, ERR_CEASE, CEASE_ADMIN_SHUTDOWN,
    AFI_L2VPN, SAFI_EVPN, TUNNEL_TYPE_VXLAN,
)
from ..bgp.attributes import (
    build_standard_evpn_path_attrs, build_evpn_withdraw_attrs,
    attr_origin, attr_as_path, attr_local_pref, attr_extended_communities,
    attr_mp_reach_nlri, encode_rt_community, encode_encapsulation_community,
    attr_originator_id, attr_cluster_list, encode_mac_mobility_community,
)
from ..bgp import evpn
from generators.common.utils.timing import (
    jittered_interval, ack_delay, keepalive_timestamps, route_burst_timestamps
)
from datetime import datetime, timezone


class MixedFaultRecovery(BaseScenario):
    """Normal → fault (link down) → recovery → normal.
    
    5 minutes warmup, fault injected, recovers within 45 seconds,
    then continues normally.
    """
    FAULT_TYPE: str = 'Link Down'
    SECTION: int = 3
    
    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_pe: str = None):
        super().__init__(config, target_frames)
        self.affected_pe_id = affected_pe or (config.pe_nodes[2].id if len(config.pe_nodes) > 2 else config.pe_nodes[0].id)
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        # Setup
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)
        
        # Warmup: 5 minutes normal traffic
        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration
        
        # FAULT: Link down (TCP RST)
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

            # Withdraw routes
            t += 0.01
            pe = affected_session.local_router
            # Withdraw all of the affected PE's routes (Type 3 IMET always;
            # Type 1/4 for multihomed PEs only).
            macs = self.topology.get_macs_for_pe(pe.id, count=2)
            nlris = [evpn.build_mac_ip_route(pe.bgp_id, pe.esi or "0",
                                             mac_entry.mac, ip=mac_entry.ip,
                                             vni=self.config.evpn.vni) for mac_entry in macs]
            nlris.append(evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni))
            if pe.esi and pe.esi != "0":
                nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
                nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                    vni=self.config.evpn.vni))
                nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                                 self.config.evpn.vni))
            for session_id, other_tcp in self.tcp_sessions.items():
                if pe.id in session_id or not other_tcp.is_established():
                    continue
                for nlri in nlris:
                    update = build_update(path_attributes=build_evpn_withdraw_attrs(
                        nlri, originator_id=pe.bgp_id,
                        cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id))
                    packets.extend(self._mark_event(
                        other_tcp.send_data(update, t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))
                    t += 0.005
        
        # Silence (45 seconds)
        silence = self._param_rng.uniform(40, 50)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_pe_id in session_id or not tcp_sess.is_established():
                continue
            for ka_t in keepalive_timestamps(t, silence, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
        t += silence
        
        # RECOVERY
        if affected_session:
            pe = affected_session.local_router
            rr = affected_session.remote_router
            new_tcp = TCPSession(client_ip=pe.bgp_id, server_ip=rr.bgp_id, server_port=179)
            self.tcp_sessions[affected_session.session_id] = new_tcp
            
            connect_pkts = new_tcp.connect(timestamp=t)
            packets.extend(connect_pkts)
            t += 0.02
            
            # OPEN exchange
            for direction, router, dir_str in [
                ('client_to_server', pe, 'server_to_client'),
                ('server_to_client', rr, 'client_to_server')
            ]:
                open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                      router.bgp_id, default_evpn_capabilities(self.config.as_number))
                pkts = new_tcp.send_data(open_msg, t, direction)
                packets.extend(pkts)
                t += ack_delay()
                packets.extend(new_tcp.generate_ack(t, dir_str))
                t += 0.005
            
            # Keepalive confirms
            ka = build_keepalive()
            pkts = new_tcp.send_data(ka, t, 'client_to_server')
            packets.extend(pkts)
            pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
            packets.extend(pkts)
            t += 0.01
            
            # Re-advertise
            route_pkts = self.generate_route_updates(
                affected_session.session_id, pe, num_routes=random.randint(5, 10), start_time=t)
            packets.extend(route_pkts)
            t += 0.5

        fault_end_t = t
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # Post-recovery normal traffic (fill to target)
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
            packets.extend(ka_pkts)

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class MixedFaultNoRecovery(MixedFaultRecovery):
    """Normal → fault → no recovery."""
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)
        
        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration
        
        # FAULT
        fault_start_t = t
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.affected_pe_id:
                tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST', phase='trigger'))
                break

        # Mark BGP-level evidence: withdrawals for the dropped PE on a
        # surviving session (all route types; Type 3 IMET always, Type 1/4
        # for multihomed PEs only).
        withdraw_t = t + 0.01
        pe_router = self.config.get_router(self.affected_pe_id)
        if pe_router:
            macs = self.topology.get_macs_for_pe(self.affected_pe_id, count=2)
            nlris = [evpn.build_mac_ip_route(pe_router.bgp_id, pe_router.esi or "0",
                                             mac_entry.mac, ip=mac_entry.ip,
                                             vni=self.config.evpn.vni) for mac_entry in macs]
            nlris.append(evpn.build_imet_route(pe_router.bgp_id, pe_router.bgp_id, self.config.evpn.vni))
            if pe_router.esi and pe_router.esi != "0":
                nlris.append(evpn.build_ead_per_es(pe_router.bgp_id, pe_router.esi, self.config.evpn.vni))
                nlris.append(evpn.build_ead_per_evi(pe_router.bgp_id, pe_router.esi, ethernet_tag=0,
                                                    vni=self.config.evpn.vni))
                nlris.append(evpn.build_es_route(pe_router.bgp_id, pe_router.esi, pe_router.bgp_id,
                                                 self.config.evpn.vni))
            for session_id, other_tcp in self.tcp_sessions.items():
                if self.affected_pe_id in session_id or not other_tcp.is_established():
                    continue
                for nlri in nlris:
                    update = build_update(path_attributes=build_evpn_withdraw_attrs(
                        nlri, originator_id=pe_router.bgp_id,
                        cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id))
                    packets.extend(self._mark_event(
                        other_tcp.send_data(update, withdraw_t, 'server_to_client'), self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))
                    withdraw_t += 0.005

        # No recovery — just other sessions for 6+ minutes
        no_recovery_duration = self._param_rng.uniform(360, 480)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if self.affected_pe_id in session_id or not tcp_sess.is_established():
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


class MixedOverlappingFaults(BaseScenario):
    """Two different faults happen close together (link down + RR session drop)."""
    FAULT_TYPE: str = 'Link Down + Link Down'
    SECTION: int = 3
    WARMUP_SECONDS = (120, 360)

    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames)
        pes = config.pe_nodes
        self.affected_pe_id = pes[1].id if len(pes) > 1 else pes[0].id
        # Second fault: another PE or RR-RR session
        self.second_pe_id = pes[2].id if len(pes) > 2 else pes[0].id
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)
        
        # 4 minutes warmup
        warmup_duration = self._param_rng.randint(120, 360)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration
        
        # FAULT 1: First PE goes down
        fault_start_t = t
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.affected_pe_id:
                tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                packets.extend(self._mark_event(rst_pkts, 'Link Down', self.affected_pe_id, 'TCP RST', phase='trigger'))
                break

        withdraw_t = t + 0.01
        pe1_router = self.config.get_router(self.affected_pe_id)
        if pe1_router:
            # Withdraw all of the affected PE's routes (Type 3 IMET always;
            # Type 1/4 for multihomed PEs only).
            macs = self.topology.get_macs_for_pe(self.affected_pe_id, count=2)
            nlris = [evpn.build_mac_ip_route(pe1_router.bgp_id, pe1_router.esi or "0",
                                             mac_entry.mac, ip=mac_entry.ip,
                                             vni=self.config.evpn.vni) for mac_entry in macs]
            nlris.append(evpn.build_imet_route(pe1_router.bgp_id, pe1_router.bgp_id, self.config.evpn.vni))
            if pe1_router.esi and pe1_router.esi != "0":
                nlris.append(evpn.build_ead_per_es(pe1_router.bgp_id, pe1_router.esi, self.config.evpn.vni))
                nlris.append(evpn.build_ead_per_evi(pe1_router.bgp_id, pe1_router.esi, ethernet_tag=0,
                                                    vni=self.config.evpn.vni))
                nlris.append(evpn.build_es_route(pe1_router.bgp_id, pe1_router.esi, pe1_router.bgp_id,
                                                 self.config.evpn.vni))
            for session_id, other_tcp in self.tcp_sessions.items():
                if self.affected_pe_id in session_id or not other_tcp.is_established():
                    continue
                for nlri in nlris:
                    update = build_update(path_attributes=build_evpn_withdraw_attrs(
                        nlri, originator_id=pe1_router.bgp_id,
                        cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id))
                    packets.extend(self._mark_event(
                        other_tcp.send_data(update, withdraw_t, 'server_to_client'), 'Link Down', self.affected_pe_id, 'Route UPDATE', phase='trigger'))
                    withdraw_t += 0.005

        # 30 seconds later — FAULT 2: Second PE also drops
        t += 30
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.second_pe_id:
                tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                if tcp_sess.is_established():
                    rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                    packets.extend(self._mark_event(rst_pkts, 'Link Down', self.second_pe_id, 'TCP RST', phase='trigger'))
                break

        withdraw_t = t + 0.01
        pe2_router = self.config.get_router(self.second_pe_id)
        if pe2_router:
            # Withdraw all of the second PE's routes (Type 3 IMET always;
            # Type 1/4 for multihomed PEs only).
            macs = self.topology.get_macs_for_pe(self.second_pe_id, count=2)
            nlris = [evpn.build_mac_ip_route(pe2_router.bgp_id, pe2_router.esi or "0",
                                             mac_entry.mac, ip=mac_entry.ip,
                                             vni=self.config.evpn.vni) for mac_entry in macs]
            nlris.append(evpn.build_imet_route(pe2_router.bgp_id, pe2_router.bgp_id, self.config.evpn.vni))
            if pe2_router.esi and pe2_router.esi != "0":
                nlris.append(evpn.build_ead_per_es(pe2_router.bgp_id, pe2_router.esi, self.config.evpn.vni))
                nlris.append(evpn.build_ead_per_evi(pe2_router.bgp_id, pe2_router.esi, ethernet_tag=0,
                                                    vni=self.config.evpn.vni))
                nlris.append(evpn.build_es_route(pe2_router.bgp_id, pe2_router.esi, pe2_router.bgp_id,
                                                 self.config.evpn.vni))
            for session_id, other_tcp in self.tcp_sessions.items():
                if (self.affected_pe_id in session_id or self.second_pe_id in session_id
                        or not other_tcp.is_established()):
                    continue
                for nlri in nlris:
                    update = build_update(path_attributes=build_evpn_withdraw_attrs(
                        nlri, originator_id=pe2_router.bgp_id,
                        cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id))
                    packets.extend(self._mark_event(
                        other_tcp.send_data(update, withdraw_t, 'server_to_client'), 'Link Down', self.second_pe_id, 'Route UPDATE', phase='trigger'))
                    withdraw_t += 0.005

        # Both down for a while, other sessions continue
        overlap_silence = self._param_rng.uniform(60, 90)
        ka_msg = build_keepalive()
        for session_id, tcp_sess in self.tcp_sessions.items():
            if (self.affected_pe_id in session_id or self.second_pe_id in session_id
                or not tcp_sess.is_established()):
                continue
            for ka_t in keepalive_timestamps(t, overlap_silence, self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
        t += overlap_silence
        
        # Recovery: both reconnect
        for pe_id in [self.affected_pe_id, self.second_pe_id]:
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == pe_id:
                    pe = bgp_sess.local_router
                    rr = bgp_sess.remote_router
                    new_tcp = TCPSession(client_ip=pe.bgp_id, server_ip=rr.bgp_id, server_port=179)
                    self.tcp_sessions[bgp_sess.session_id] = new_tcp
                    
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
                    t += 0.005
                    
                    ka = build_keepalive()
                    pkts = new_tcp.send_data(ka, t, 'client_to_server')
                    packets.extend(pkts)
                    pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
                    packets.extend(pkts)
                    t += 0.5
                    break

        fault_end_t = t
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # Post-recovery
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
            packets.extend(ka_pkts)

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


# class MixedPlannedMaintenance(BaseScenario):
#     """Planned maintenance — graceful BGP shutdown (NOT a fault).
    
#     PE sends NOTIFICATION with Cease/Admin Shutdown before disconnecting.
#     This should NOT trigger the model's anomaly detection.
#     """
#     FAULT_TYPE: str = 'Planned Maintenance'
#     SECTION: int = 3
    
#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  maintenance_pe: str = None):
#         super().__init__(config, target_frames)
#         self.maintenance_pe_id = maintenance_pe or (config.pe_nodes[2].id if len(config.pe_nodes) > 2 else config.pe_nodes[0].id)
    
#     def generate(self) -> list[TCPPacket]:
#         packets = []
#         t = self.start_time
        
#         setup_pkts, t = self.establish_all_sessions(t)
#         packets.extend(setup_pkts)
        
#         # Initial route table (all types)
#         init_routes, t = self.generate_initial_routes(t)
#         packets.extend(init_routes)
        
#         warmup_duration = random.randint(120, 480)
#         ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
#         packets.extend(ka_pkts)
#         t += warmup_duration
        
#         # PLANNED MAINTENANCE: Graceful NOTIFICATION (Cease/Admin Shutdown)
#         fault_start_t = t
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.id == self.maintenance_pe_id:
#                 tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                
#                 # Send NOTIFICATION with Cease (6) / Admin Shutdown (2)
#                 notification = build_notification(ERR_CEASE, CEASE_ADMIN_SHUTDOWN)
#                 pkts = tcp_sess.send_data(notification, t, 'client_to_server')
#                 packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.maintenance_pe_id, 'BGP NOTIFICATION: Cease/Administrative Shutdown'))
#                 t += 0.001

#                 # Graceful TCP close (FIN exchange, not RST)
#                 close_pkts = tcp_sess.close_graceful(t, initiator='client')
#                 packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.maintenance_pe_id, 'Graceful FIN Close'))
#                 break
        
#         # Maintenance window (30 seconds)
#         maint_duration = 30
#         ka_msg = build_keepalive()
#         for session_id, tcp_sess in self.tcp_sessions.items():
#             if self.maintenance_pe_id in session_id or not tcp_sess.is_established():
#                 continue
#             for ka_t in keepalive_timestamps(t, maint_duration, self.config.timing.keepalive_timer):
#                 pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
#                 packets.extend(pkts)
#                 packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(), 'server_to_client'))
#         t += maint_duration
#         fault_end_t = t

#         # PE comes back online (graceful reconnect)
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.id == self.maintenance_pe_id:
#                 pe = bgp_sess.local_router
#                 rr = bgp_sess.remote_router
#                 new_tcp = TCPSession(client_ip=pe.loopback, server_ip=rr.loopback, server_port=179)
#                 self.tcp_sessions[bgp_sess.session_id] = new_tcp
                
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
#                 t += 0.005
                
#                 ka = build_keepalive()
#                 pkts = new_tcp.send_data(ka, t, 'client_to_server')
#                 packets.extend(pkts)
#                 pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
#                 packets.extend(pkts)
#                 t += 0.01
                
#                 route_pkts = self.generate_route_updates(
#                     bgp_sess.session_id, pe, num_routes=random.randint(5, 10), start_time=t)
#                 packets.extend(route_pkts)
#                 t += 0.5
#                 break
        
#         # Post-maintenance normal traffic
#         remaining = int(self.target_frames * 0.26) - len(packets)
#         if remaining > 0:
#             post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
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


# # class MixedUnseenTopology(BaseScenario):
# #     """A new PE (PE6) not present in training data appears.
# #
# #     Tests whether the model generalizes to unseen topology.
# #     No fault injected — just normal traffic with an extra device.
# #     """
# #     FAULT_TYPE: str = 'Unseen Topology'
# #     SECTION: int = 3
# #
# #     def __init__(self, config: TopologyConfig, target_frames: int = 8000):
# #         super().__init__(config, target_frames)
# #         self.new_pe_ip = "2001:db8::2:6"
# #         self.new_pe_bgp_id = "10.0.0.16"
# #         self.new_pe_id = "PE6"
# #
# #     def generate(self) -> list[TCPPacket]:
# #         packets = []
# #         t = self.start_time
# #
# #         # Establish normal sessions
# #         setup_pkts, t = self.establish_all_sessions(t)
# #         packets.extend(setup_pkts)
# #
# #         # Initial route table (all types)
# #         init_routes, t = self.generate_initial_routes(t)
# #         packets.extend(init_routes)
# #
# #         # Normal traffic for a while
# #         normal_duration = 3 * 60
# #         ka_pkts = self.generate_keepalives_for_duration(t, normal_duration)
# #         packets.extend(ka_pkts)
# #         t += normal_duration
# #
# #         # NEW PE6 appears — establishes session to vantage RR
# #         vantage_rr = self.config.get_router(self.config.capture_vantage)
# #         new_tcp = TCPSession(
# #             client_ip=self.new_pe_ip,
# #             server_ip=vantage_rr.loopback,
# #             server_port=179
# #         )
# #         self.tcp_sessions["PE6-" + vantage_rr.id] = new_tcp
# #
# #         # TCP handshake
# #         connect_pkts = new_tcp.connect(timestamp=t)
# #         packets.extend(connect_pkts)
# #         t += 0.02
# #
# #         # OPEN from PE6
# #         open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
# #                               self.new_pe_bgp_id, default_evpn_capabilities(self.config.as_number))
# #         pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
# #         packets.extend(pkts)
# #         t += ack_delay()
# #         packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
# #         t += 0.005
# #
# #         # OPEN from RR
# #         open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
# #                               vantage_rr.bgp_id, default_evpn_capabilities(self.config.as_number))
# #         pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
# #         packets.extend(pkts)
# #         t += ack_delay()
# #         packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
# #         t += 0.002
# #
# #         # Keepalive confirms
# #         ka = build_keepalive()
# #         pkts = new_tcp.send_data(ka, t, 'client_to_server')
# #         packets.extend(pkts)
# #         pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
# #         packets.extend(pkts)
# #         t += 0.01
# #
# #         # PE6 advertises routes (IMET + MAC/IP)
# #         nlri = evpn.build_imet_route(self.new_pe_bgp_id, self.new_pe_ip, self.config.evpn.vni)
# #         path_attrs = build_standard_evpn_path_attrs(
# #             self.new_pe_ip, nlri, self.config.as_number, self.config.evpn.vni)
# #         update = build_update(path_attributes=path_attrs)
# #         pkts = new_tcp.send_data(update, t, 'client_to_server')
# #         packets.extend(pkts)
# #         t += 0.01
# #         packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
# #
# #         # PE6 advertises some MAC/IP routes
# #         for i in range(10):
# #             mac = f"00:aa:bb:16:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}"
# #             nlri = evpn.build_mac_ip_route(self.new_pe_bgp_id, "0", mac,
# #                                             ip=f"192.168.16.{i+1}", vni=self.config.evpn.vni)
# #             path_attrs = build_standard_evpn_path_attrs(
# #                 self.new_pe_ip, nlri, self.config.as_number, self.config.evpn.vni)
# #             update = build_update(path_attributes=path_attrs)
# #             pkts = new_tcp.send_data(update, t, 'client_to_server')
# #             packets.extend(pkts)
# #             t += 0.005
# #             packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
# #
# #         t += 0.5
# #
# #         # Continue normal traffic (now with PE6 included)
# #         remaining = int(self.target_frames * 0.26) - len(packets)
# #         if remaining > 0:
# #             post_duration = max(300, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
# #             ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
# #             packets.extend(ka_pkts)
# #
# #         # Pad with pure TCP window-update frames to reach target_frames
# #         pad_count = self.target_frames - len(packets)
# #         if pad_count > 0:
# #             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
# #             packets.extend(pad_pkts)
# #
# #         packets.sort(key=lambda p: p.timestamp)
# #         return packets[:self.target_frames]


# # ---------------------------------------------------------------------------
# # PE/RR-specific subclasses for Section 3
# # ---------------------------------------------------------------------------

# # Planned maintenance — all PEs and RRs
# class MixedPlannedMaintenancePE1(MixedPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_pe='PE1')

# class MixedPlannedMaintenancePE2(MixedPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_pe='PE2')

# class MixedPlannedMaintenancePE3(MixedPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_pe='PE3')

# class MixedPlannedMaintenanceRR1(MixedPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_pe='RR1')

# class MixedPlannedMaintenanceRR2(MixedPlannedMaintenance):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, maintenance_pe='RR2')


# Overlapping faults — different PE+RR combinations
class MixedOverlappingPE1RR2(MixedOverlappingFaults):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames)
        self.affected_pe_id = 'PE1'
        self.second_pe_id = 'PE3'


# # Unseen topology — PE removed
# class MixedUnseenTopologyPE1Removed(MixedFaultNoRecovery):
#     """PE1 gracefully decommissioned mid-capture."""
#     FAULT_TYPE: str = 'Link Down'
#     def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE1')


# ---------------------------------------------------------------------------
# Link Down on a multihomed PE causes its ES/DF peer's role to change
# ---------------------------------------------------------------------------

class LinkDownTriggersESDF(LinkDownScenario):
    """Link Down on a multihomed PE, with its ESI peer's DF re-election as an
    explicit downstream CONSEQUENCE, not an independent second fault.

    Root cause: affected_pe's session RSTs. A few seconds later, the peer PE
    sharing the same ESI withdraws its ES (Type 4) route -- the DF-election
    signal per RFC 7432 SS8.5 / RFC 8584 -- as the peer takes over as DF.
    Type 1 (EAD) is a separate aliasing/backup-path mechanism (RFC 7432
    SS8.2/SS8.4) with no bearing on DF election and is untouched throughout.
    On recovery: affected_pe reconnects and re-advertises its Type 2/3
    routes FIRST, then the peer re-advertises Type 4 to reflect DF
    reversion -- same causal ordering as the fault direction.

    Only PE1/PE2 are multihomed in this topology (see ESDFSingleToggle),
    so this scenario only exists for those two.
    """

    FAULT_TYPE: str = 'Link Down + ESDF Toggle'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_pe: str = None):
        super().__init__(config, target_frames, affected_pe=affected_pe,
                         mechanism='rst', recovery='fast')
        pe = config.get_router(self.affected_pe_id)
        if not pe or not pe.esi:
            raise ValueError(
                f"PE {self.affected_pe_id} is not multihomed in this topology, "
                "cannot model a DF-reversion consequence")
        self.esi = pe.esi
        self.peer_pe_id = None
        for other_pe in config.pe_nodes:
            if other_pe.id != self.affected_pe_id and other_pe.esi == self.esi:
                self.peer_pe_id = other_pe.id
                break

    def _peer_session(self):
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.peer_pe_id:
                return bgp_sess
        return None

    def _withdraw_peer_mh_routes(self, peer_pe, tcp_sess, t: float,
                                 event: bool = False, phase: str = None) -> list[TCPPacket]:
        """Withdraw the peer's Type 1 A-D per ES route -- the mass-withdraw
        trigger signal per RFC 7432 SS8.2 / RFC 8584. Type 4 follows
        passively as a consequence."""
        packets = []
        nlri = evpn.build_ead_per_es(peer_pe.bgp_id, self.esi, self.config.evpn.vni)
        pkts = tcp_sess.send_data(
            build_update(path_attributes=build_evpn_withdraw_attrs(
                nlri, originator_id=peer_pe.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)),
            t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

        if event:
            self._mark_event(packets, 'ESDF Toggle', self.peer_pe_id, 'Route UPDATE', phase=phase)
        return packets

    def _advertise_peer_mh_routes(self, peer_pe, tcp_sess, rr_bgp_id, t: float,
                                  event: bool = False, phase: str = None) -> list[TCPPacket]:
        """Re-advertise the peer's Type 1 A-D per ES route."""
        packets = []
        nlri = evpn.build_ead_per_es(peer_pe.bgp_id, self.esi, self.config.evpn.vni)
        path_attrs = build_standard_evpn_path_attrs(
            peer_pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
            originator_id=peer_pe.bgp_id, cluster_id=rr_bgp_id)
        pkts = tcp_sess.send_data(build_update(path_attributes=path_attrs), t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

        if event:
            self._mark_event(packets, 'ESDF Toggle', self.peer_pe_id, 'Route UPDATE', phase=phase)
        return packets

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

        pe = self.config.get_router(self.affected_pe_id)
        fault_start_t = t

        # ROOT CAUSE: affected PE's session RSTs.
        bgp_sess = self._direct_session()
        exclude_session_id = bgp_sess.session_id if bgp_sess else None
        if bgp_sess:
            tcp_sess = self.tcp_sessions[bgp_sess.session_id]
            rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
            packets.extend(self._mark_event(rst_pkts, 'Link Down', self.affected_pe_id, 'TCP RST', phase='trigger'))
            t += 0.01
            withdraw_pkts = self._withdraw_pe_routes_direct(pe, t, event=True)
            packets.extend(withdraw_pkts)
            t = max((p.timestamp for p in withdraw_pkts), default=t) + 0.01

        # CONSEQUENCE: a few seconds later, the peer withdraws Type 1/4 (DF
        # re-election) as the downstream ESDF Toggle sub-fault.
        consequence_delay = self._param_rng.uniform(2, 8)
        peer_bgp_sess = self._peer_session()
        peer_tcp_sess = self.tcp_sessions.get(peer_bgp_sess.session_id) if peer_bgp_sess else None
        if peer_bgp_sess and peer_tcp_sess and peer_tcp_sess.is_established():
            other_ka = self._other_keepalives(t, consequence_delay, exclude_session_id)
            packets.extend(other_ka)
            t += consequence_delay
            peer_pe = peer_bgp_sess.local_router
            consequence_pkts = self._withdraw_peer_mh_routes(peer_pe, peer_tcp_sess, t, event=True, phase='trigger')
            packets.extend(consequence_pkts)
            t = max((p.timestamp for p in consequence_pkts), default=t) + 0.01

        t += 0.5

        # Silence window (fast recovery: 20-30s).
        silence = self._param_rng.uniform(20, 30)
        other_ka2 = self._other_keepalives(t, silence, exclude_session_id)
        packets.extend(other_ka2)
        t += silence

        # RECOVERY: affected PE reconnects + re-advertises Type 2/3 FIRST...
        if bgp_sess:
            recover_pkts, t = self._recover_session_direct(bgp_sess, t, event=True)
            packets.extend(recover_pkts)

        # ...THEN the peer re-advertises Type 1/4 (DF reversion), same causal order.
        if peer_bgp_sess and peer_tcp_sess and peer_tcp_sess.is_established():
            rr_bgp_id = self.config.get_router(self.config.capture_vantage).bgp_id
            peer_pe = peer_bgp_sess.local_router
            reversion_pkts = self._advertise_peer_mh_routes(
                peer_pe, peer_tcp_sess, rr_bgp_id, t, event=True, phase='recovery')
            packets.extend(reversion_pkts)
            t = max((p.timestamp for p in reversion_pkts), default=t) + 0.5

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
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

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class LinkDownTriggersESDFPE1(LinkDownTriggersESDF):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class LinkDownTriggersESDFPE2(LinkDownTriggersESDF):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')


# ---------------------------------------------------------------------------
# Phase 3 — mixed mechanism/recovery pairings, independent (non-causal) faults
# ---------------------------------------------------------------------------

def _direct_session_for(scenario, pe_id):
    for bgp_sess in scenario.topology.get_sessions_at_vantage():
        if bgp_sess.local_router.id == pe_id:
            return bgp_sess
    return None


class LinkDownNoRecoveryESDFOverlap(LinkDownScenario):
    """Link Down (TCP RST, no recovery, on ld_pe_id -- passed through as
    LinkDownScenario's affected_pe) overlapping with ES/DF Toggle (recovers,
    on esdf_pe_id). Two independent faults, genuinely overlapping in time
    (not causal, not sequential). The link-down leg reuses LinkDownScenario's
    _direct_session()/_withdraw_pe_routes_direct() unchanged (inherited); the
    ES/DF leg has no existing shared method to reuse and stays as-is, and
    models a pure DF-election signal -- ES (Type 4) route only, per
    RFC 7432 SS8.5 / RFC 8584 -- leaving Type 1 untouched.

    esdf_pe_id must be a real multihomed PE (PE1 or PE2, per this topology's
    ESI assignment) -- the link-down leg (ld_pe_id) can be any direct PE.
    """
    FAULT_TYPE: str = 'Link Down + ESDF Toggle'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 ld_pe_id: str = 'PE1', esdf_pe_id: str = 'PE2'):
        super().__init__(config, target_frames, affected_pe=ld_pe_id,
                         mechanism='rst', recovery='none')
        self.ld_pe_id = ld_pe_id
        self.esdf_pe_id = esdf_pe_id
        pe = config.get_router(self.esdf_pe_id)
        if not pe or not pe.esi:
            raise ValueError(
                f"PE {self.esdf_pe_id} is not multihomed in this topology, "
                "cannot model an ES/DF toggle")
        self.esi = pe.esi

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

        fault_start_t = t

        # Fault 1: PE1 link down, TCP RST, no recovery.
        # Reuses LinkDownScenario's own helpers unchanged (inherited).
        # t is deliberately NOT advanced past the withdrawal batch here --
        # overlap_delay below is measured from the RST timestamp, not from
        # the withdrawal batch end.
        pe = self.config.get_router(self.affected_pe_id)
        ld_sess = self._direct_session()
        if ld_sess:
            ld_tcp = self.tcp_sessions[ld_sess.session_id]
            rst_pkts = ld_tcp.close_reset(timestamp=t, initiator='server')
            packets.extend(self._mark_event(rst_pkts, 'Link Down', self.ld_pe_id, 'TCP RST', phase='trigger'))
            withdraw_pkts = self._withdraw_pe_routes_direct(pe, t + 0.01, event=True)
            packets.extend(withdraw_pkts)

        # Fault 2 (overlapping): a few seconds later, PE2 ES/DF toggle begins
        # -- independent of PE1's fault, not caused by it.
        overlap_delay = self._param_rng.uniform(3, 10)
        t += overlap_delay

        # ESDF leg triggers on the Type 1 A-D per ES route -- the mass-
        # withdraw signal per RFC 7432 SS8.2 / RFC 8584. Type 4 follows
        # passively as a consequence, not as the trigger.
        esdf_sess = _direct_session_for(self, self.esdf_pe_id)
        if esdf_sess:
            esdf_pe = esdf_sess.local_router
            esdf_tcp = self.tcp_sessions[esdf_sess.session_id]
            nlri4 = evpn.build_ead_per_es(esdf_pe.bgp_id, self.esi, self.config.evpn.vni)
            pkts = esdf_tcp.send_data(
                build_update(path_attributes=build_evpn_withdraw_attrs(
                    nlri4, originator_id=esdf_pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)),
                t, 'server_to_client')
            packets.extend(self._mark_event(pkts, 'ESDF Toggle', self.esdf_pe_id, 'Route UPDATE', phase='trigger'))
            t += 0.005
            packets.extend(esdf_tcp.generate_ack(t, 'client_to_server'))

            # ESDF recovers after 10-20s (unlike PE1, which never does).
            toggle_silence = random.uniform(10, 20)
            other_ka = self.generate_keepalives_for_duration(t, toggle_silence)
            packets.extend(other_ka)
            t += toggle_silence

            rr_bgp_id = self.config.get_router(self.config.capture_vantage).bgp_id
            path_attrs4 = build_standard_evpn_path_attrs(
                esdf_pe.bgp_id, nlri4, self.config.as_number, self.config.evpn.vni,
                originator_id=esdf_pe.bgp_id, cluster_id=rr_bgp_id)
            pkts = esdf_tcp.send_data(build_update(path_attributes=path_attrs4), t, 'server_to_client')
            packets.extend(self._mark_event(pkts, 'ESDF Toggle', self.esdf_pe_id, 'Route UPDATE', phase='recovery'))
            t += 0.005
            packets.extend(esdf_tcp.generate_ack(t, 'client_to_server'))
            t += 0.5

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # PE1 never recovers -- exclude its (closed) session from post-fault churn.
        surviving_pe_sessions = [(s, s.local_router) for s in self.topology.get_sessions_at_vantage()
                                 if s.local_router.role == 'pe' and s.local_router.id != self.ld_pe_id]

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration,
                                      last_update_times=last_update_times2,
                                      pe_sessions=surviving_pe_sessions)
            packets.extend(self.generate_keepalives_for_duration(
                t, post_duration, last_update_times=last_update_times2))

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class LinkDownHoldTimerRTMisconfigOverlap(LinkDownScenario):
    """Link Down via hold-timer expiry (recovers, on ld_pe_id -- passed
    through as LinkDownScenario's affected_pe) overlapping with a
    persistent, no-recovery RT Misconfiguration (on rt_pe_id). Independent
    faults. The link-down leg reuses LinkDownScenario's own
    _direct_session()/_other_keepalives()/_withdraw_pe_routes_direct()/
    _recover_session_direct() unchanged (inherited); only the hold-timer
    NOTIFICATION+close trigger is duplicated inline, matching exactly what
    LinkDownScenario.generate() itself does for mechanism='hold_timer'
    (that specific 5-line sequence isn't factored into its own method).
    The RT-misconfig leg has no existing shared method to reuse and stays
    as-is.
    """
    FAULT_TYPE: str = 'Link Down + RT Misconfiguration'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 ld_pe_id: str = 'PE2', rt_pe_id: str = 'PE3'):
        super().__init__(config, target_frames, affected_pe=ld_pe_id,
                         mechanism='hold_timer', recovery='fast')
        self.ld_pe_id = ld_pe_id
        self.rt_pe_id = rt_pe_id
        self.wrong_rt_asn = 100
        self.wrong_rt_value = 999

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

        fault_start_t = t

        # Fault 1: PE2 link down via hold-timer expiry, recovers.
        # Reuses LinkDownScenario's own helpers unchanged (inherited).
        pe = self.config.get_router(self.affected_pe_id)
        ld_sess = self._direct_session()
        exclude_session_id = ld_sess.session_id if ld_sess else None
        if ld_sess:
            ld_tcp = self.tcp_sessions[ld_sess.session_id]
            hold_silence = float(self.config.timing.hold_timer)
            other_ka = self._other_keepalives(t, hold_silence, exclude_session_id)
            packets.extend(other_ka)
            t += hold_silence
            notification = build_notification(ERR_HOLD_TIMER_EXPIRED, 0)
            pkts = ld_tcp.send_data(notification, t, 'server_to_client')
            packets.extend(self._mark_event(pkts, 'Link Down', self.ld_pe_id, 'BGP NOTIFICATION: Hold Timer Expired', phase='trigger'))
            t += 0.001
            close_pkts = ld_tcp.close_graceful(t, initiator='server')
            packets.extend(self._mark_event(close_pkts, 'Link Down', self.ld_pe_id, 'Graceful FIN Close', phase='trigger'))
            t += 0.01

            withdraw_pkts = self._withdraw_pe_routes_direct(pe, t, event=True)
            packets.extend(withdraw_pkts)
            t += 0.5

        # Fault 2 (overlapping): PE3 RT misconfig begins a few seconds later, persists.
        overlap_delay = self._param_rng.uniform(3, 10)
        rt_sess = _direct_session_for(self, self.rt_pe_id)
        rt_tcp = self.tcp_sessions.get(rt_sess.session_id) if rt_sess else None
        if rt_tcp and rt_tcp.is_established():
            other_ka2 = self.generate_keepalives_for_duration(t, overlap_delay, )
            packets.extend(other_ka2)
            t += overlap_delay
            rt_pe = rt_sess.local_router
            macs = self.topology.get_macs_for_pe(
                self.rt_pe_id,
                count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                      int(self.config.evpn.mac_pool_size * 0.5)))
            timestamps = route_burst_timestamps(t, len(macs))
            wrong_rt = encode_rt_community(self.wrong_rt_asn, self.wrong_rt_value)
            encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
            for mac_entry, ts in zip(macs, timestamps):
                nlri = evpn.build_mac_ip_route(
                    rt_pe.bgp_id, rt_pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni)
                attrs = (attr_origin(0) + attr_as_path() + attr_local_pref(100)
                         + attr_extended_communities([wrong_rt, encap])
                         + attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, rt_pe.bgp_id, nlri))
                pkts = rt_tcp.send_data(build_update(path_attributes=attrs), ts, 'server_to_client')
                packets.extend(self._mark_event(pkts, 'RT Misconfiguration', self.rt_pe_id, 'Route UPDATE', phase='trigger'))
                packets.extend(rt_tcp.generate_ack(ts + ack_delay(), 'client_to_server'))
            t = timestamps[-1] + 0.5 if timestamps else t

        # RECOVERY: only PE2's link down recovers; PE3's RT misconfig never does.
        # Reuses LinkDownScenario's own _recover_session_direct() unchanged (inherited).
        if ld_sess:
            recover_pkts, t = self._recover_session_direct(ld_sess, t, event=True)
            packets.extend(recover_pkts)

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
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

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class RRDownThenLinkDownSequential(BaseScenario):
    """RR Down (recovers) fully completes, THEN separately a PE's link
    fails (TCP RST, no recovery) -- sequential, not overlapping. Reuses
    rr_down.py's RR1-RR2 RST/reconnect/resync logic and link_down.py's
    direct-session RST/withdraw logic, unchanged.
    """
    FAULT_TYPE: str = 'RR Down + Link Down'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_rr_id: str = 'RR2', ld_pe_id: str = 'PE1'):
        super().__init__(config, target_frames)
        self.affected_rr_id = affected_rr_id
        self.ld_pe_id = ld_pe_id
        # LinkDownScenario._withdraw_pe_routes_direct() is borrowed below as
        # an unbound method and reads self._ld_fault_type / self.affected_pe_id
        # (its own instance attributes) -- this class isn't a LinkDownScenario
        # subclass, so those must be set here too for the borrowed call to work.
        self._ld_fault_type = 'Link Down'
        self.affected_pe_id = ld_pe_id

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

        fault1_start_t = t

        # Fault 1: RR2 (RR1-RR2 session) RST. Topology-role based match,
        # not a substring match on session id.
        rr_sess_id = None
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                rr_sess_id = bgp_sess.session_id
                tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp_sess and tcp_sess.is_established():
                    rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='client')
                    packets.extend(self._mark_event(rst_pkts, 'RR Down', self.affected_rr_id, 'TCP RST', phase='trigger'))
                break
        t += 0.5

        # RFC 4271 SS9.2 / RFC 4456 second hop (fault-onset withdraw): the
        # vantage RR lost its only path to the affected RR's clients' routes
        # and must withdraw them toward its own clients before the recovery
        # side (already implemented below as the re-advertise second hop).
        # Borrowed as an unbound method from RRDownCleanRestart (rr_down.py).
        # The helper internally labels events with self.FAULT_TYPE, which
        # for this combo class is 'RR Down + Link Down', not the plain
        # 'RR Down' component label the recovery-side call below uses --
        # temporarily override so this call matches that same convention.
        _saved_fault_type, self.FAULT_TYPE = self.FAULT_TYPE, 'RR Down'
        wd_pkts, t = RRDownCleanRestart._second_hop_withdraw_affected_rr_clients(self, t)
        self.FAULT_TYPE = _saved_fault_type
        packets.extend(wd_pkts)

        silence1 = self._param_rng.uniform(25, 30)
        other_ka = self.generate_keepalives_for_duration(t, silence1, )
        packets.extend(other_ka)
        t += silence1

        # RECOVERY 1: RR2 reconnects and full route sync (existing rr_down.py logic).
        if rr_sess_id:
            affected_rr = self.config.get_router(self.affected_rr_id)
            vantage_rr = self.config.get_router(self.config.capture_vantage)
            new_tcp = TCPSession(client_ip=affected_rr.bgp_id, server_ip=vantage_rr.bgp_id, server_port=179)
            self.tcp_sessions[rr_sess_id] = new_tcp
            connect_pkts = new_tcp.connect(timestamp=t)
            packets.extend(connect_pkts)
            t += 0.02
            for direction, router, ack_dir in [
                ('client_to_server', affected_rr, 'server_to_client'),
                ('server_to_client', vantage_rr, 'client_to_server'),
            ]:
                open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                      router.bgp_id, default_evpn_capabilities(self.config.as_number))
                packets.extend(new_tcp.send_data(open_msg, t, direction))
                t += ack_delay()
                packets.extend(new_tcp.generate_ack(t, ack_dir))
                t += 0.005
            ka = build_keepalive()
            packets.extend(new_tcp.send_data(ka, t, 'client_to_server'))
            packets.extend(new_tcp.send_data(ka, t + 0.001, 'server_to_client'))
            t += 0.01
            route_pkts, t = self.reflect_pe_routes_to_rr(new_tcp, t, event=True,
                                                         fault_type='RR Down', node=self.affected_rr_id,
                                                         phase='recovery')
            packets.extend(route_pkts)

            # RFC 4456 second hop: re-advertise onward to the vantage RR's
            # own clients too, matching every other RR Down recovery path
            # (rr_down.py). This class's RR-recovery leg is a deliberate
            # inline duplicate, not a call into rr_down.py.
            # 2ms relay-processing gap between first-hop landing and
            # second-hop relay beginning (once, not per-PE in the loop below).
            t += 0.002
            affected_pes = [pe for pe in self.config.pe_nodes
                           if pe.peers and pe.peers[0] == self.affected_rr_id]
            for pe in affected_pes:
                sh_pkts, t = self.reflect_to_own_clients(pe, t, action='advertise', event=True,
                                                         fault_type='RR Down', node=self.affected_rr_id,
                                                         phase='recovery')
                packets.extend(sh_pkts)

        fault1_end_t = t + self.BASELINE_CHECK_WINDOW
        t += 0.5

        # Stable gap between the two independent faults.
        stable_duration = self._param_rng.uniform(60, 180)
        stable_update_times: dict = {}
        self.generate_route_churn(packets, t, stable_duration,
                                  last_update_times=stable_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, stable_duration, last_update_times=stable_update_times))
        t += stable_duration

        fault2_start_t = t

        # Fault 2: PE1 link down, TCP RST, no recovery (sequential, after Fault 1 fully resolved).
        # Reuses LinkDownScenario._withdraw_pe_routes_direct() as a borrowed
        # unbound method -- it only touches generic BaseScenario attributes
        # (self.topology/self.tcp_sessions/self.config), and this class is
        # itself a BaseScenario subclass, so it's directly callable without
        # needing RRDownThenLinkDownSequential to inherit from LinkDownScenario
        # (which would conflict with its own RR-vantage-swapping __init__).
        ld_sess = _direct_session_for(self, self.ld_pe_id)
        if ld_sess:
            ld_pe = ld_sess.local_router
            ld_tcp = self.tcp_sessions[ld_sess.session_id]
            rst_pkts = ld_tcp.close_reset(timestamp=t, initiator='server')
            packets.extend(self._mark_event(rst_pkts, 'Link Down', self.ld_pe_id, 'TCP RST', phase='trigger'))
            withdraw_pkts = LinkDownScenario._withdraw_pe_routes_direct(self, ld_pe, t + 0.01, event=True)
            packets.extend(withdraw_pkts)
            t += 0.5

        no_recovery_duration = self._param_rng.uniform(180, 300)
        other_ka2 = self.generate_keepalives_for_duration(t, no_recovery_duration)
        packets.extend(other_ka2)
        t += no_recovery_duration

        # fw.json spans from Fault 1's start through Fault 2's no-recovery tail.
        self._fault_start_t = fault1_start_t
        self._fault_end_t = None

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, no_recovery_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


# ---------------------------------------------------------------------------
# Phase 3 leaf classes -- explicit PE assignment per name.
# ---------------------------------------------------------------------------

# Link Down (RST, no recovery) + ES/DF Toggle (recovers). ES/DF leg is
# constrained to PE1/PE2 (the only real multihomed pair); the link-down leg
# can move to any direct PE.
class LinkDownPE1NoRecovery_ESDFPE2Overlap(LinkDownNoRecoveryESDFOverlap):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, ld_pe_id='PE1', esdf_pe_id='PE2')

class LinkDownPE3NoRecovery_ESDFPE2Overlap(LinkDownNoRecoveryESDFOverlap):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, ld_pe_id='PE3', esdf_pe_id='PE2')


# Link Down (hold-timer expiry, recovers) + RT Misconfig (persistent, no recovery).
class LinkDownPE2HoldTimer_RTMisconfigPE3Overlap(LinkDownHoldTimerRTMisconfigOverlap):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, ld_pe_id='PE2', rt_pe_id='PE3')

class LinkDownPE3HoldTimer_RTMisconfigPE1Overlap(LinkDownHoldTimerRTMisconfigOverlap):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, ld_pe_id='PE3', rt_pe_id='PE1')


# RR Down (recovers), THEN separately a PE's link fails (RST, no recovery) -- sequential.
class RRDownRR2_LinkDownPE1Sequential(RRDownThenLinkDownSequential):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, affected_rr_id='RR2', ld_pe_id='PE1')

class RRDownRR2_LinkDownPE3Sequential(RRDownThenLinkDownSequential):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, affected_rr_id='RR2', ld_pe_id='PE3')


# ---------------------------------------------------------------------------
# ES/DF Full Failure — both multihomed PEs withdraw the shared ESI's Type 1
# A-D per ES route within a short window, modeling the whole access segment
# going down (not one PE taking over DF for the other, as in
# ESDFSingleToggle). No surviving DF candidate exists for the ESI during the
# fault window. Type 1 A-D per ES withdrawal is the mass-withdraw trigger
# signal per RFC 7432 SS8.2 / RFC 8584; Type 4 (ES route) follows passively
# as a consequence, not as the trigger.
# ---------------------------------------------------------------------------

class ESDFFullFailure(BaseScenario):
    """Both PEs of an ES pair withdraw their Type 1 A-D per ES route for
    the shared ESI within ~280ms of each other -- the whole access segment
    going down, not partial degradation with one PE taking over as DF for
    the other.
    """
    FAULT_TYPE: str = 'ESDF Toggle'
    SECTION: int = 3

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 recovery: bool = True, es_pair: tuple[str, str] | None = None):
        """es_pair: explicit (pe_a_id, pe_b_id) to target, e.g. for a
        topology with multiple ES pairs. Defaults to get_multihomed_peers()'s
        first result when not specified, same auto-discovery pattern used
        by ESDFSingleToggle -- so existing 5PE/2RR callers with no es_pair
        argument keep selecting PE1/PE2, unchanged."""
        super().__init__(config, target_frames)
        if es_pair:
            self.pe1_id, self.pe2_id = es_pair
        else:
            pairs = config.get_multihomed_peers()
            if not pairs:
                raise ValueError("no ES-multihomed pair found in this topology, cannot model full ES failure")
            self.pe1_id, self.pe2_id = pairs[0][0].id, pairs[0][1].id
        pe1 = config.get_router(self.pe1_id)
        pe2 = config.get_router(self.pe2_id)
        if not pe1 or not pe1.esi or not pe2 or not pe2.esi or pe1.esi != pe2.esi:
            raise ValueError(
                f"PE {self.pe1_id}/{self.pe2_id} do not share a real ESI in "
                "this topology, cannot model full ES failure")
        self.esi = pe1.esi
        self.recovery = recovery

        # ES-paired PEs are always homed to the SAME RR, so a single
        # is_reflected flag applies uniformly to both PEs in this dual-PE
        # mechanism -- no per-PE homing divergence to handle.
        self.home_rr_id = pe1.peers[0] if pe1.peers else None
        self.is_reflected = bool(self.home_rr_id and self.home_rr_id != config.capture_vantage)

    def _session_for(self, pe_id: str):
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                return bgp_sess, self.tcp_sessions.get(bgp_sess.session_id)
        return None, None

    def _es_route_pkts(self, pe_router, tcp_sess, t: float, withdraw: bool,
                       event: bool) -> list[TCPPacket]:
        if self.is_reflected:
            # This vantage isn't the ES pair's home RR -- reflect the
            # per-ES Type-1 route over the RR-RR mesh session instead.
            # build_ead_per_es (Ethernet Tag 0xFFFFFFFF sentinel) has no
            # generic reflect_single_route_to_rr() support (that helper
            # only covers Type 4 and per-EVI Type 1), so this is a thin
            # local variant of the same pattern rather than a call into it.
            mesh_sess = self._rr_rr_session(self.home_rr_id)
            mesh_tcp = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
            if not mesh_tcp or not mesh_tcp.is_established():
                return []
            nlri = evpn.build_ead_per_es(pe_router.bgp_id, self.esi, self.config.evpn.vni)
            if withdraw:
                path_attrs = build_evpn_withdraw_attrs(nlri)
            else:
                path_attrs = build_standard_evpn_path_attrs(
                    pe_router.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe_router.bgp_id,
                    cluster_id=self.config.get_router(pe_router.peers[0]).bgp_id)
            packets = mesh_tcp.send_data(build_update(path_attributes=path_attrs), t, 'client_to_server')
            t += 0.008
            packets.extend(mesh_tcp.generate_ack(t, 'server_to_client'))
            if event:
                self._mark_event(packets, self.FAULT_TYPE, pe_router.id, 'Route UPDATE',
                                 phase='trigger' if withdraw else 'recovery')
            return packets

        packets = []
        nlri = evpn.build_ead_per_es(pe_router.bgp_id, self.esi, self.config.evpn.vni)
        if withdraw:
            path_attrs = build_evpn_withdraw_attrs(
                nlri, originator_id=pe_router.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        else:
            path_attrs = build_standard_evpn_path_attrs(
                pe_router.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=pe_router.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        pkts = tcp_sess.send_data(build_update(path_attributes=path_attrs), t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
        if event:
            self._mark_event(packets, self.FAULT_TYPE, pe_router.id, 'Route UPDATE',
                             phase='trigger' if withdraw else 'recovery')
        return packets

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

        fault_start_t = t
        pe1_router = self.config.get_router(self.pe1_id)
        pe2_router = self.config.get_router(self.pe2_id)
        bgp1, tcp1 = self._session_for(self.pe1_id)
        bgp2, tcp2 = self._session_for(self.pe2_id)
        pe1_ready = self.is_reflected or (bgp1 and tcp1 and tcp1.is_established())
        pe2_ready = self.is_reflected or (bgp2 and tcp2 and tcp2.is_established())

        # FAULT: PE1 withdraws Type-4 ES route, then PE2 within ~280ms --
        # no surviving DF candidate remains for the ESI during this window.
        if pe1_ready:
            pkts1 = self._es_route_pkts(pe1_router, tcp1, t, withdraw=True, event=True)
            packets.extend(pkts1)
            t = max((p.timestamp for p in pkts1), default=t) + 0.01

        gap = self._param_rng.uniform(0.15, 0.28)
        t += gap
        if pe2_ready:
            pkts2 = self._es_route_pkts(pe2_router, tcp2, t, withdraw=True, event=True)
            packets.extend(pkts2)
            t = max((p.timestamp for p in pkts2), default=t) + 0.01

        t += 0.5

        if self.recovery:
            silence = self._param_rng.uniform(10, 20)
            packets.extend(self.generate_keepalives_for_duration(t, silence))
            t += silence

            # RECOVERY: both re-advertise, DF re-elected normally.
            if pe1_ready:
                pkts1 = self._es_route_pkts(pe1_router, tcp1, t, withdraw=False, event=True)
                packets.extend(pkts1)
                t = max((p.timestamp for p in pkts1), default=t) + 0.01
            gap = self._param_rng.uniform(0.15, 0.28)
            t += gap
            if pe2_ready:
                pkts2 = self._es_route_pkts(pe2_router, tcp2, t, withdraw=False, event=True)
                packets.extend(pkts2)
                t = max((p.timestamp for p in pkts2), default=t) + 0.01
            t += 0.5

        fault_end_t = t if self.recovery else None
        self._fault_start_t = fault_start_t
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

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class ESDFFullFailureRecovery(ESDFFullFailure):
    def __init__(self, config, target_frames=30000, es_pair=None):
        super().__init__(config, target_frames, recovery=True, es_pair=es_pair)


class ESDFFullFailureNoRecovery(ESDFFullFailure):
    def __init__(self, config, target_frames=30000, es_pair=None):
        super().__init__(config, target_frames, recovery=False, es_pair=es_pair)


class ESDFFullFailureRecoveryPE3PE4(ESDFFullFailureRecovery):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, es_pair=("PE3", "PE4"))


class ESDFFullFailureNoRecoveryPE3PE4(ESDFFullFailureNoRecovery):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, es_pair=("PE3", "PE4"))


class ESDFFullFailureRecoveryPE6PE7(ESDFFullFailureRecovery):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, es_pair=("PE6", "PE7"))


class ESDFFullFailureNoRecoveryPE6PE7(ESDFFullFailureNoRecovery):
    def __init__(self, config, target_frames=30000):
        super().__init__(config, target_frames, es_pair=("PE6", "PE7"))


# ---------------------------------------------------------------------------
# Category C multi-incident: two DIFFERENT, UNRELATED fault types
# co-occurring in one capture (not causally linked, unlike
# LinkDownTriggersESDF/LinkDownNoRecoveryESDFOverlap above, which are
# deliberately correlated). Gap between incidents: CATEGORY_B_GAP_SECONDS
# (120s, see esdf_toggle.py's justification -- 60x the detector's 2.0s
# precedence/establishment windows), same standard as Category B.
# metadata.json schema matches the real pilot_containerlab/3rr
# pcaps/multiple/catC_* precedent: multi_incident=true, category="C",
# incidents=[...], causal_relationship="none -- ...".
# ---------------------------------------------------------------------------

CATEGORY_GAP_SECONDS = 120.0


class _CategoryCMixin:
    """Shared single-incident injection helpers for Category C scenarios.
    Each returns the timestamp after the incident completes; the incident
    dict is appended to self.incidents.
    """

    def _esdf_incident(self, packets, pe_id: str, t: float) -> float:
        pe = self.config.get_router(pe_id)
        home_rr_id = pe.peers[0] if pe.peers else None
        is_reflected = bool(home_rr_id and home_rr_id != self.config.capture_vantage)

        if is_reflected:
            mesh_sess = self._rr_rr_session(home_rr_id)
            tcp_sess = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
        else:
            tcp_sess = None
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == pe_id:
                    tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                    break
        if not tcp_sess or not tcp_sess.is_established():
            return t

        fault_start_t = t
        nlri = evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id, self.config.evpn.vni)

        if is_reflected:
            pkts, t = self.reflect_single_route_to_rr(tcp_sess, pe, route_type=4, action='withdraw', start_t=t)
            packets.extend(self._mark_event(pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='trigger'))
            fanout_pkts, t = self._fan_out_type4_to_other_sessions(pe, pe.esi, 'withdraw', t, clients_only=True)
            packets.extend(self._mark_event(fanout_pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='trigger'))
        else:
            path_attrs = build_evpn_withdraw_attrs(
                nlri, originator_id=pe.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'server_to_client')
            packets.extend(self._mark_event(pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='trigger'))
            packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))
            t += 0.5
            fanout_pkts, t = self._fan_out_type4_to_other_sessions(pe, pe.esi, 'withdraw', t)
            packets.extend(self._mark_event(fanout_pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='trigger'))
        t += 0.1

        # Re-advertise (clean recovery) 10-20s later, ordinary toggle timing.
        t += self._param_rng.uniform(10, 20)
        if is_reflected:
            pkts, t = self.reflect_single_route_to_rr(tcp_sess, pe, route_type=4, action='advertise', start_t=t)
            packets.extend(self._mark_event(pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='recovery'))
            fanout_pkts, t = self._fan_out_type4_to_other_sessions(pe, pe.esi, 'advertise', t, clients_only=True)
            packets.extend(self._mark_event(fanout_pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='recovery'))
        else:
            path_attrs = build_standard_evpn_path_attrs(
                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=pe.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'server_to_client')
            packets.extend(self._mark_event(pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='recovery'))
            packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))
            t += 0.5
            fanout_pkts, t = self._fan_out_type4_to_other_sessions(pe, pe.esi, 'advertise', t)
            packets.extend(self._mark_event(fanout_pkts, 'ESDF Toggle', pe_id, 'Route UPDATE', phase='recovery'))
        fault_end_t = t

        self.incidents.append({
            "event_affected_node": pe_id,
            "fault_type": "ESDF Toggle",
            "trigger_mechanism": "ES Route Withdrawal (Type 4)",
            "time_of_first_fault": datetime.fromtimestamp(fault_start_t, tz=timezone.utc).isoformat(),
            "recovered": True,
            "time_of_recovery": datetime.fromtimestamp(fault_end_t, tz=timezone.utc).isoformat(),
        })
        return t + 0.5

    def _rt_misconfig_incident(self, packets, pe_id: str, wrong_rt_value: int, t: float) -> float:
        pe = self.config.get_router(pe_id)
        home_rr_id = pe.peers[0] if pe.peers else None
        is_reflected = bool(home_rr_id and home_rr_id != self.config.capture_vantage)
        correct_rt_asn, correct_rt_value = (int(x) for x in self.config.evpn.route_target.split(':'))
        wrong_rt_asn = 100

        def wrong_rt_attrs(nlri_bytes, originator_id=None, cluster_id=None):
            wrong_rt = encode_rt_community(wrong_rt_asn, wrong_rt_value)
            encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
            attrs = b''
            attrs += attr_origin(0)
            attrs += attr_as_path()
            attrs += attr_local_pref(100)
            attrs += attr_extended_communities([wrong_rt, encap])
            attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri_bytes)
            if originator_id is not None and cluster_id is not None:
                attrs += attr_originator_id(originator_id)
                attrs += attr_cluster_list([cluster_id])
            return attrs

        fault_start_t = t
        es_nlri = evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id, self.config.evpn.vni)

        if is_reflected:
            mesh_sess = self._rr_rr_session(home_rr_id)
            mesh_tcp = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
            if mesh_tcp and mesh_tcp.is_established():
                wrong_rt = (wrong_rt_asn, wrong_rt_value)
                pkts, t = self.reflect_single_route_to_rr(
                    mesh_tcp, pe, route_type=4, action='advertise', start_t=t, wrong_rt=wrong_rt)
                packets.extend(self._mark_event(pkts, 'RT Misconfiguration', pe_id, 'Route UPDATE', phase='trigger'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    pe, pe.esi, 'advertise', t, clients_only=True, wrong_rt=wrong_rt)
                packets.extend(self._mark_event(fanout_pkts, 'RT Misconfiguration', pe_id, 'Route UPDATE', phase='trigger'))
                t += 0.1
        else:
            affected_tcp = None
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == pe_id:
                    affected_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    break
            if affected_tcp and affected_tcp.is_established():
                path_attrs = wrong_rt_attrs(es_nlri, originator_id=pe.bgp_id,
                                            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = affected_tcp.send_data(update, t, 'server_to_client')
                packets.extend(self._mark_event(pkts, 'RT Misconfiguration', pe_id, 'Route UPDATE', phase='trigger'))
                packets.extend(affected_tcp.generate_ack(t + ack_delay(), 'client_to_server'))
                t += 0.5
                for bgp_sess in self.topology.get_sessions_at_vantage():
                    if bgp_sess.local_router.role != 'pe' or bgp_sess.local_router.id == pe_id:
                        continue
                    other_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    if not other_tcp or not other_tcp.is_established():
                        continue
                    fanout_update = build_update(path_attributes=wrong_rt_attrs(
                        es_nlri, originator_id=pe.bgp_id,
                        cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id))
                    fanout_pkts = other_tcp.send_data(fanout_update, t, 'server_to_client')
                    packets.extend(self._mark_event(fanout_pkts, 'RT Misconfiguration', pe_id, 'Route UPDATE', phase='trigger'))
                    t += 0.005
                    packets.extend(other_tcp.generate_ack(t, 'client_to_server'))
                    t += 0.001
                t += 0.1

        fault_end_t = t
        self.incidents.append({
            "event_affected_node": pe_id,
            "fault_type": "RT Misconfiguration",
            "trigger_mechanism": "Plain Import/Export Mismatch",
            "time_of_first_fault": datetime.fromtimestamp(fault_start_t, tz=timezone.utc).isoformat(),
            "recovered": False,
            "time_of_recovery": None,
            "configured_export_rt": f"{correct_rt_asn}:{correct_rt_value} (export)",
            "configured_import_rt": f"{wrong_rt_asn}:{wrong_rt_value} (mismatched import)",
        })
        return t + 0.5

    def _mac_mobility_incident(self, packets, pe_a_id: str, pe_b_id: str, t: float) -> float:
        bgp_a = bgp_b = tcp_a = tcp_b = None
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_a_id:
                bgp_a = bgp_sess
                tcp_a = self.tcp_sessions.get(bgp_sess.session_id)
            elif bgp_sess.local_router.id == pe_b_id:
                bgp_b = bgp_sess
                tcp_b = self.tcp_sessions.get(bgp_sess.session_id)
        if not (bgp_a and bgp_b and tcp_a and tcp_b and tcp_a.is_established() and tcp_b.is_established()):
            return t

        pe_a = bgp_a.local_router
        pe_b = bgp_b.local_router
        mac_entry = self.topology.get_macs_for_pe(pe_a.id)[-1]
        fault_start_t = t

        # WITHDRAW old owner
        nlri = evpn.build_mac_ip_route(pe_a.bgp_id, pe_a.esi or "0", mac_entry.mac,
                                        ip=mac_entry.ip, vni=self.config.evpn.vni)
        path_attrs = build_evpn_withdraw_attrs(
            nlri, originator_id=pe_a.bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        update = build_update(path_attributes=path_attrs)
        wd_pkts = tcp_a.send_data(update, t, 'server_to_client')
        packets.extend(wd_pkts)
        packets.extend(tcp_a.generate_ack(t + ack_delay(), 'client_to_server'))
        t += 2.0

        # ADVERTISE new owner
        nlri = evpn.build_mac_ip_route(pe_b.bgp_id, pe_b.esi or "0", mac_entry.mac,
                                        ip=mac_entry.ip, vni=self.config.evpn.vni)
        rt_parts = self.config.evpn.route_target.split(':')
        rt = encode_rt_community(int(rt_parts[0]), int(rt_parts[1]))
        encap = encode_encapsulation_community()
        mobility = encode_mac_mobility_community(1)
        attrs = b''
        attrs += attr_origin(0)
        attrs += attr_as_path()
        attrs += attr_local_pref(100)
        attrs += attr_extended_communities([rt, encap, mobility])
        attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_b.bgp_id, nlri)
        attrs += attr_originator_id(pe_b.bgp_id)
        attrs += attr_cluster_list([self.config.get_router(self.config.capture_vantage).bgp_id])
        update = build_update(path_attributes=attrs)
        adv_pkts = tcp_b.send_data(update, t, 'server_to_client')
        packets.extend(adv_pkts)
        packets.extend(tcp_b.generate_ack(t + ack_delay(), 'client_to_server'))

        packets_for_event = wd_pkts + adv_pkts
        self._mark_event(packets_for_event, 'MAC Mobility', pe_a.id, 'Route UPDATE', phase='trigger')
        fault_end_t = t

        self.incidents.append({
            "event_affected_node": pe_a.id,
            "fault_type": "MAC Mobility",
            "trigger_mechanism": "Clean Move (rapidflap)",
            "origin_pe": pe_a.id,
            "destination_pe": pe_b.id,
            "time_of_first_fault": datetime.fromtimestamp(fault_start_t, tz=timezone.utc).isoformat(),
            "recovered": True,
            "time_of_recovery": datetime.fromtimestamp(fault_end_t, tz=timezone.utc).isoformat(),
        })
        return t + 0.5


class CatCESDFToggleRTMisconfig(_CategoryCMixin, BaseScenario):
    """Category C: ESDF Toggle on one PE + RT Misconfiguration on another,
    unrelated node, no causal relationship. For 5PE/2RR (only one ES pair
    exists), the two PEs are the two members of that pair (PE1/PE2) --
    still genuinely different nodes and different, non-causally-linked
    fault types. For 3RR (two ES pairs exist), uses PE3 (pair 1, home RR1)
    for ESDF and PE6 (pair 2, home RR2) for RT-misconfig -- different ES
    pairs, different home RRs, a cleaner "unrelated" example.
    """
    FAULT_TYPE: str = 'Mixed'
    SECTION: int = 3
    CAUSAL_RELATIONSHIP = "none -- independent nodes, independent mechanisms"

    def __init__(self, config: TopologyConfig, target_frames: int = 20000,
                 esdf_pe: str = 'PE1', rt_pe: str = 'PE2'):
        super().__init__(config, target_frames)
        self.esdf_pe_id = esdf_pe
        self.rt_pe_id = rt_pe
        for pe_id in (esdf_pe, rt_pe):
            pe = config.get_router(pe_id)
            if not pe or not pe.esi:
                raise ValueError(f"PE {pe_id} is not multihomed, required for this Category C scenario")
        self.incidents: list[dict] = []

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 300)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        t = self._esdf_incident(packets, self.esdf_pe_id, t)

        self.generate_route_churn(packets, t, CATEGORY_GAP_SECONDS, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, CATEGORY_GAP_SECONDS, last_update_times=last_update_times))
        t += CATEGORY_GAP_SECONDS

        t = self._rt_misconfig_incident(packets, self.rt_pe_id, 999, t)

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration, last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(t, post_duration, last_update_times=last_update_times2))
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            packets.extend(self.generate_tcp_window_updates(t, post_duration, pad_count))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class CatCESDFToggleRTMisconfigPE3PE6(CatCESDFToggleRTMisconfig):
    """3RR variant: PE3 (ES pair 1, home RR1) ESDF + PE6 (ES pair 2, home RR2) RT-misconfig."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, esdf_pe='PE3', rt_pe='PE6')


class CatCESDFToggleMACMobility(_CategoryCMixin, BaseScenario):
    """Category C: ESDF Toggle on PE1 + independent MAC move on PE3->PE2,
    unrelated nodes/mechanisms. 5PE/2RR only, per Phase 3's scoped plan.

    mac_pair default: PE3->PE4 crosses RR1/RR2 in the 5PE/2RR topology;
    mac_mobility has no cross-RR reflection support anywhere in this
    codebase. PE3->PE2 keeps the MAC incident within RR1's direct clients,
    alongside PE1's ESDF incident.
    """
    FAULT_TYPE: str = 'Mixed'
    SECTION: int = 3
    CAUSAL_RELATIONSHIP = "none -- independent nodes, independent mechanisms"

    def __init__(self, config: TopologyConfig, target_frames: int = 20000,
                 esdf_pe: str = 'PE1', mac_pair: tuple[str, str] = ('PE3', 'PE2')):
        super().__init__(config, target_frames)
        self.esdf_pe_id = esdf_pe
        pe = config.get_router(esdf_pe)
        if not pe or not pe.esi:
            raise ValueError(f"PE {esdf_pe} is not multihomed, required for the ESDF incident")
        self.mac_a_id, self.mac_b_id = mac_pair
        self.incidents: list[dict] = []

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 300)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        t = self._esdf_incident(packets, self.esdf_pe_id, t)

        self.generate_route_churn(packets, t, CATEGORY_GAP_SECONDS, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, CATEGORY_GAP_SECONDS, last_update_times=last_update_times))
        t += CATEGORY_GAP_SECONDS

        t = self._mac_mobility_incident(packets, self.mac_a_id, self.mac_b_id, t)

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration, last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(t, post_duration, last_update_times=last_update_times2))
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            packets.extend(self.generate_tcp_window_updates(t, post_duration, pad_count))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class CatCRTMisconfigMACMobility(_CategoryCMixin, BaseScenario):
    """Category C: RT Misconfiguration on PE3 + independent MAC move on
    PE8->PE9, unrelated nodes/mechanisms. 3RR only, per Phase 3's scoped
    plan."""
    FAULT_TYPE: str = 'Mixed'
    SECTION: int = 3
    CAUSAL_RELATIONSHIP = "none -- independent nodes, independent mechanisms"

    def __init__(self, config: TopologyConfig, target_frames: int = 20000,
                 rt_pe: str = 'PE3', mac_pair: tuple[str, str] = ('PE8', 'PE9')):
        super().__init__(config, target_frames)
        self.rt_pe_id = rt_pe
        pe = config.get_router(rt_pe)
        if not pe or not pe.esi:
            raise ValueError(f"PE {rt_pe} is not multihomed, required for the RT-misconfig incident")
        self.mac_a_id, self.mac_b_id = mac_pair
        self.incidents: list[dict] = []

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        warmup_duration = self._param_rng.randint(120, 300)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        t = self._rt_misconfig_incident(packets, self.rt_pe_id, 999, t)

        self.generate_route_churn(packets, t, CATEGORY_GAP_SECONDS, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, CATEGORY_GAP_SECONDS, last_update_times=last_update_times))
        t += CATEGORY_GAP_SECONDS

        t = self._mac_mobility_incident(packets, self.mac_a_id, self.mac_b_id, t)

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration, last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(t, post_duration, last_update_times=last_update_times2))
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            packets.extend(self.generate_tcp_window_updates(t, post_duration, pad_count))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]
