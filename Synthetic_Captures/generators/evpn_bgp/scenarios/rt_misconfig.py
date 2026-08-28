"""Section 2 — RT Misconfiguration fault scenarios.

Simulates a PE advertising routes with wrong Route Target.
Sessions stay up, routes sent, but silently dropped by receivers.
"""

import random
from .base import BaseScenario
from ..config import TopologyConfig
from ..tcp.session import TCPPacket
from ..bgp.messages import build_update, build_keepalive
from ..bgp.attributes import (
    build_standard_evpn_path_attrs, build_evpn_withdraw_attrs,
    attr_origin, attr_as_path, attr_local_pref, attr_extended_communities,
    attr_mp_reach_nlri, encode_rt_community, encode_encapsulation_community,
    attr_originator_id, attr_cluster_list
)
from ..bgp.constants import AFI_L2VPN, SAFI_EVPN, TUNNEL_TYPE_VXLAN
from ..bgp import evpn
from generators.common.utils.timing import jittered_interval, ack_delay, route_burst_timestamps


class RTMisconfigScenario(BaseScenario):
    """RT misconfiguration on a specific PE.
    
    The affected PE advertises routes with a WRONG Route Target.
    All other PEs use the correct RT.
    """
    FAULT_TYPE: str = 'RT Misconfiguration'
    SECTION: int = 2
    
    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_pe: str = None, wrong_rt_value: int = None,
                 recovery: bool = True, recovery_delay: float = 120.0):
        super().__init__(config, target_frames)
        self.affected_pe_id = affected_pe or (config.pe_nodes[1].id if len(config.pe_nodes) > 1 else config.pe_nodes[0].id)
        
        # Parse correct RT from config (e.g., "65001:100" → asn=65001, value=100)
        rt_parts = config.evpn.route_target.split(':')
        self.correct_rt_asn = int(rt_parts[0])
        self.correct_rt_value = int(rt_parts[1])
        
        # Wrong RT value
        self.wrong_rt_value = wrong_rt_value or random.choice([999, 888, 200, 50])
        self.wrong_rt_asn = 100  # Completely wrong ASN portion too
        
        self.recovery = recovery
        self.recovery_delay = recovery_delay

        pe = config.get_router(self.affected_pe_id)
        self.is_reflected = bool(pe and pe.peers and pe.peers[0] != config.capture_vantage)

        # Cached across the fault call and the recovery call so recovery
        # re-advertises the EXACT same routes the fault perturbed. Populated
        # on first use (the fault call, wrong=True) in _direct_route_burst()
        # / the reflected-path branch of generate().
        self._burst_macs = None
        self._burst_prefix = None
        self._reflected_macs_by_pe = None

    def _rr_rr_session(self):
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                return bgp_sess
        return None

    def _build_wrong_rt_path_attrs(self, pe_router, nlri_bytes: bytes) -> bytes:
        """Build path attributes with WRONG Route Target."""
        wrong_rt = encode_rt_community(self.wrong_rt_asn, self.wrong_rt_value)
        encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)

        attrs = b''
        attrs += attr_origin(0)
        attrs += attr_as_path()
        attrs += attr_local_pref(100)
        attrs += attr_extended_communities([wrong_rt, encap])
        attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.bgp_id, nlri_bytes)
        return attrs

    def _direct_route_burst(self, affected_pe, affected_tcp, t: float,
                            wrong: bool, phase: str = None) -> tuple[list[TCPPacket], float]:
        """Build the direct-session route burst -- Type 2 (MAC/IP, per-MAC),
        Type 3 (IMET, single per-PE), Type 5 (IP Prefix, single), and Type 1
        A-D per ES (single, only if affected_pe is multihomed) -- with
        either the wrong RT (wrong=True) or the correct RT (wrong=False).
        Shared by the fault-injection and recovery paths so recovery
        corrects exactly the same route-type set the fault perturbed --
        and, via self._burst_macs/self._burst_prefix, the exact same MACs
        and prefix too, not an independently-redrawn random set.
        """
        packets = []

        def attrs_for(nlri: bytes) -> bytes:
            if wrong:
                return self._build_wrong_rt_path_attrs(affected_pe, nlri)
            return build_standard_evpn_path_attrs(
                affected_pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=affected_pe.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)

        def send(nlri: bytes, ts: float) -> float:
            update = build_update(path_attributes=attrs_for(nlri))
            pkts = affected_tcp.send_data(update, ts, 'server_to_client')
            packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase))
            packets.extend(affected_tcp.generate_ack(ts + ack_delay(), 'client_to_server'))
            return ts

        # Type 2: MAC/IP (per-MAC). Cached on the first (fault) call and
        # reused on the recovery call so the same MACs get corrected.
        if self._burst_macs is None:
            self._burst_macs = self.topology.get_macs_for_pe(
                self.affected_pe_id,
                count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                      int(self.config.evpn.mac_pool_size * 0.5)))
        macs = self._burst_macs
        timestamps = route_burst_timestamps(t, len(macs))
        for mac_entry, ts in zip(macs, timestamps):
            nlri = evpn.build_mac_ip_route(
                affected_pe.bgp_id, affected_pe.esi or "0",
                mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
            send(nlri, ts)
        t_next = (timestamps[-1] + 0.1) if timestamps else t

        # Type 3: IMET (single, per-PE)
        nlri = evpn.build_imet_route(affected_pe.bgp_id, affected_pe.bgp_id, self.config.evpn.vni)
        send(nlri, t_next)
        t_next += 0.1

        # Type 5: IP Prefix (single). Cached on the first (fault) call and
        # reused on the recovery call so the same prefix gets corrected.
        if self._burst_prefix is None:
            pe_idx = int(affected_pe.bgp_id.split('.')[-1])
            self._burst_prefix = f"10.{pe_idx}.{random.randint(0, 254)}.0"
        nlri = evpn.build_ip_prefix_route(
            affected_pe.bgp_id, self._burst_prefix, 24, affected_pe.bgp_id, self.config.evpn.vni)
        send(nlri, t_next)
        t_next += 0.1

        # Type 1: A-D per ES (single, only if multihomed)
        if affected_pe.esi and affected_pe.esi != "0":
            nlri = evpn.build_ead_per_es(affected_pe.bgp_id, affected_pe.esi, self.config.evpn.vni)
            send(nlri, t_next)
            t_next += 0.1

        return packets, t_next

    def _first_hop_type5_type1(self, affected_pe, tcp_sess, t: float,
                               wrong_rt: tuple[int, int] = None) -> tuple[list[TCPPacket], float]:
        """Send Type 5 (IP Prefix, always) and Type 1 A-D per ES (only if
        affected_pe is multihomed) once over the RR-RR session -- the
        Type-5/Type-1 counterpart to reflect_pe_routes_to_rr() (correct RT,
        used for recovery) / reflect_pe_routes_to_rr_wrong_rt() (wrong RT,
        already extended with Type 5/Type 1 directly in base.py and used
        for the fault path, so this method is only needed for the
        recovery/correct-RT first hop).

        wrong_rt=None sends the correct RT (recovery); a tuple sends that
        wrong RT.
        """
        packets = []
        # Cached: reuse the same prefix the fault call (reflect_pe_routes_to_rr_wrong_rt,
        # via base.py, or an earlier call to this method) already established,
        # instead of drawing a fresh random one -- see self._burst_prefix.
        if self._burst_prefix is None:
            pe_idx = int(affected_pe.bgp_id.split('.')[-1])
            self._burst_prefix = f"10.{pe_idx}.{random.randint(0, 254)}.0"
        nlris = [evpn.build_ip_prefix_route(
            affected_pe.bgp_id, self._burst_prefix, 24, affected_pe.bgp_id, self.config.evpn.vni)]
        if affected_pe.esi and affected_pe.esi != "0":
            nlris.append(evpn.build_ead_per_es(
                affected_pe.bgp_id, affected_pe.esi, self.config.evpn.vni))

        for nlri in nlris:
            if wrong_rt is not None:
                wrong_rt_community = encode_rt_community(*wrong_rt)
                encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                path_attrs = b''
                path_attrs += attr_origin(0)
                path_attrs += attr_as_path()
                path_attrs += attr_local_pref(100)
                path_attrs += attr_extended_communities([wrong_rt_community, encap])
                path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, affected_pe.bgp_id, nlri)
            else:
                path_attrs = build_standard_evpn_path_attrs(
                    affected_pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=affected_pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'client_to_server')
            packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))
            t += 0.01
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.001

        return packets, t

    def _second_hop_type5_type1(self, affected_pe, t: float,
                                wrong_rt: tuple[int, int] = None,
                                phase: str = None) -> tuple[list[TCPPacket], float]:
        """RFC 4456 second-hop reflection of Type 5 (IP Prefix, always) and
        Type 1 A-D per ES (only if affected_pe is multihomed) onto the
        vantage RR's own direct clients (PE1-3) -- the Type-5/Type-1
        counterpart to reflect_to_own_clients(), which only forwards
        Type 3/Type 2. Kept as a separate, RT-misconfig-scoped method
        rather than extending reflect_to_own_clients() itself, since that
        method's route list is shared by RR Down / Link Down callers.

        wrong_rt=None sends the correct RT (recovery); a tuple sends that
        wrong RT (fault propagation).
        """
        packets = []
        cluster_id = self.config.get_router(affected_pe.peers[0]).bgp_id

        client_sessions = [
            bgp_sess for bgp_sess in self.topology.get_sessions_at_vantage()
            if bgp_sess.local_router.role == 'pe' and bgp_sess.local_router.id != affected_pe.id
        ]

        for bgp_sess in client_sessions:
            tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
            if not tcp_sess or not tcp_sess.is_established():
                continue

            # Cached: reuse the same prefix across every client session and
            # across the fault/recovery calls -- see self._burst_prefix.
            if self._burst_prefix is None:
                pe_idx = int(affected_pe.bgp_id.split('.')[-1])
                self._burst_prefix = f"10.{pe_idx}.{random.randint(0, 254)}.0"
            nlris = [evpn.build_ip_prefix_route(
                affected_pe.bgp_id, self._burst_prefix, 24, affected_pe.bgp_id, self.config.evpn.vni)]
            if affected_pe.esi and affected_pe.esi != "0":
                nlris.append(evpn.build_ead_per_es(
                    affected_pe.bgp_id, affected_pe.esi, self.config.evpn.vni))

            for nlri in nlris:
                if wrong_rt is not None:
                    wrong_rt_community = encode_rt_community(*wrong_rt)
                    encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                    path_attrs = b''
                    path_attrs += attr_origin(0)
                    path_attrs += attr_as_path()
                    path_attrs += attr_local_pref(100)
                    path_attrs += attr_extended_communities([wrong_rt_community, encap])
                    path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, affected_pe.bgp_id, nlri)
                else:
                    path_attrs = build_standard_evpn_path_attrs(
                        affected_pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                        originator_id=affected_pe.bgp_id, cluster_id=cluster_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'server_to_client')
                packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase))
                t += 0.008
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.001
            t += 0.02

        return packets, t

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route table (all types, correct RT)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Warmup (~5 minutes)
        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        # FAULT: Affected PE advertises routes with WRONG RT
        fault_start_t = t
        affected_pe = self.config.get_router(self.affected_pe_id)
        wrong_rt = (self.wrong_rt_asn, self.wrong_rt_value)

        if self.is_reflected:
            rr_sess = self._rr_rr_session()
            rr_tcp = self.tcp_sessions.get(rr_sess.session_id) if rr_sess else None
            affected_tcp = None
            if rr_tcp and rr_tcp.is_established():
                # Captured here (macs_out/prefix_out) so the recovery call
                # below, and the Type 5/1 second-hop calls right after, can
                # reuse the exact same MACs/prefix instead of drawing a
                # fresh random set -- reflect_pe_routes_to_rr_wrong_rt()
                # generates its own Type 5 prefix internally (independent of
                # self._burst_prefix), so it must be captured here.
                self._reflected_macs_by_pe = {}
                prefix_out: dict = {}
                wrong_pkts, t = self.reflect_pe_routes_to_rr_wrong_rt(
                    rr_tcp, t, wrong_rt, event=True, pe_list=[affected_pe], fault_type=self.FAULT_TYPE, node=self.affected_pe_id,
                    macs_out=self._reflected_macs_by_pe, prefix_out=prefix_out, phase='trigger')
                packets.extend(wrong_pkts)
                if affected_pe.id in prefix_out:
                    self._burst_prefix = prefix_out[affected_pe.id]
                # RFC 4456 second hop: RR1 forwards whatever it received
                # unfiltered -- the wrong RT propagates onward to PE1-3 too.
                # 2ms relay-processing gap between first-hop landing and
                # second-hop relay beginning.
                t += 0.002
                second_hop_pkts, t = self.reflect_to_own_clients(
                    affected_pe, t, action='advertise', wrong_rt=wrong_rt, event=True, fault_type=self.FAULT_TYPE, node=self.affected_pe_id,
                    macs_override=self._reflected_macs_by_pe.get(affected_pe.id), phase='trigger')
                packets.extend(second_hop_pkts)
                # Type 5 / Type 1 second hop -- reflect_to_own_clients() only
                # forwards Type 3/Type 2 (shared with RR Down/Link Down
                # callers), so Type 5 and conditional Type 1 are reflected
                # separately here.
                t5_t1_pkts, t = self._second_hop_type5_type1(affected_pe, t, wrong_rt=wrong_rt, phase='trigger')
                packets.extend(t5_t1_pkts)
        else:
            affected_session = None
            affected_tcp = None
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == self.affected_pe_id:
                    affected_session = bgp_sess
                    affected_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    break

            if affected_tcp and affected_tcp.is_established():
                # Send Type 2, 3, 5, and (if multihomed) Type 1 with wrong RT
                burst_pkts, t = self._direct_route_burst(affected_pe, affected_tcp, t, wrong=True, phase='trigger')
                packets.extend(burst_pkts)
                # RFC 4456 second hop: RR1 forwards whatever it received
                # unfiltered -- the wrong RT propagates onward to the other
                # direct-session PEs too. Reuses the same reflect_to_own_clients
                # + _second_hop_type5_type1 pattern already used above for the
                # reflected-path branch, with self._burst_macs so the fan-out
                # uses the same MACs the direct burst just perturbed.
                # 2ms relay-processing gap between first-hop landing and
                # second-hop relay beginning.
                t += 0.002
                second_hop_pkts, t = self.reflect_to_own_clients(
                    affected_pe, t, action='advertise', wrong_rt=wrong_rt, event=True,
                    fault_type=self.FAULT_TYPE, node=self.affected_pe_id,
                    macs_override=self._burst_macs, phase='trigger')
                packets.extend(second_hop_pkts)
                t5_t1_pkts, t = self._second_hop_type5_type1(affected_pe, t, wrong_rt=wrong_rt, phase='trigger')
                packets.extend(t5_t1_pkts)

        t += 0.5

        # Continue with traffic (sessions are still up — silent fault)
        if self.recovery:
            # Run with wrong RT for recovery_delay seconds
            recovery_update_times: dict = {}
            self.generate_route_churn(packets, t, self.recovery_delay,
                                      last_update_times=recovery_update_times)
            packets.extend(self.generate_keepalives_for_duration(
                t, self.recovery_delay, last_update_times=recovery_update_times))
            t += self.recovery_delay

            # RECOVERY: PE re-advertises with CORRECT RT -- all route types
            # perturbed by the fault (Type 2, 3, 5, and Type 1 if
            # multihomed) are re-sent correctly here, not just Type 2.
            if self.is_reflected:
                rr_sess = self._rr_rr_session()
                rr_tcp = self.tcp_sessions.get(rr_sess.session_id) if rr_sess else None
                if rr_tcp and rr_tcp.is_established():
                    correct_pkts, t = self.reflect_pe_routes_to_rr(
                        rr_tcp, t, event=True, pe_list=[affected_pe], fault_type=self.FAULT_TYPE, node=self.affected_pe_id,
                        macs_in=self._reflected_macs_by_pe, phase='recovery')
                    packets.extend(correct_pkts)
                    # 2ms relay-processing gap between first-hop landing and
                    # second-hop relay beginning.
                    t += 0.002
                    second_hop_pkts, t = self.reflect_to_own_clients(
                        affected_pe, t, action='advertise', event=True, fault_type=self.FAULT_TYPE, node=self.affected_pe_id,
                        macs_override=(self._reflected_macs_by_pe or {}).get(affected_pe.id), phase='recovery')
                    packets.extend(second_hop_pkts)
                    # Type 5 / Type 1 correction -- reflect_pe_routes_to_rr()
                    # and reflect_to_own_clients() only cover Type 3/Type 2,
                    # so both hops are corrected separately here.
                    t5_t1_first_hop_pkts, t = self._first_hop_type5_type1(affected_pe, rr_tcp, t, wrong_rt=None)
                    packets.extend(t5_t1_first_hop_pkts)
                    t5_t1_second_hop_pkts, t = self._second_hop_type5_type1(affected_pe, t, wrong_rt=None, phase='recovery')
                    packets.extend(t5_t1_second_hop_pkts)
            else:
                if affected_tcp and affected_tcp.is_established():
                    burst_pkts, t = self._direct_route_burst(affected_pe, affected_tcp, t, wrong=False, phase='recovery')
                    packets.extend(burst_pkts)
                    # 2ms relay-processing gap between first-hop landing and
                    # second-hop relay beginning.
                    t += 0.002
                    second_hop_pkts, t = self.reflect_to_own_clients(
                        affected_pe, t, action='advertise', event=True,
                        fault_type=self.FAULT_TYPE, node=self.affected_pe_id,
                        macs_override=self._burst_macs, phase='recovery')
                    packets.extend(second_hop_pkts)
                    t5_t1_pkts, t = self._second_hop_type5_type1(affected_pe, t, wrong_rt=None, phase='recovery')
                    packets.extend(t5_t1_pkts)

            t += 0.5

        fault_end_t = t if self.recovery else None
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # Post-fault/recovery normal traffic
        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
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


class RTMisconfigPE1(RTMisconfigScenario):
    """RT misconfiguration on PE1 with wrong import RT 100:999. Persistent
    -- no correction ever appears (see RTMisconfigWithRecoveryPE1 for the
    deliberate recovery-variant counterpart)."""
    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames, affected_pe='PE1', wrong_rt_value=999, recovery=False)

class RTMisconfigPE2(RTMisconfigScenario):
    """RT misconfiguration specifically on PE2 with wrong import RT 100:999.
    Persistent -- no correction ever appears."""

    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        pe2 = next((pe for pe in config.pe_nodes if pe.id == "PE2"), config.pe_nodes[1] if len(config.pe_nodes) > 1 else config.pe_nodes[0])
        super().__init__(config, target_frames, affected_pe=pe2.id, wrong_rt_value=999, recovery=False)

class RTMisconfigPE3(RTMisconfigScenario):
    """RT misconfiguration on PE3 with wrong import RT 100:999. Persistent
    -- no correction ever appears."""
    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames, affected_pe='PE3', wrong_rt_value=999, recovery=False)

class RTMisconfigPE4(RTMisconfigScenario):
    """RT misconfiguration specifically on PE4 with wrong import RT 100:888.
    Persistent -- no correction ever appears."""

    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        pe4 = next((pe for pe in config.pe_nodes if pe.id == "PE4"), config.pe_nodes[3] if len(config.pe_nodes) > 3 else config.pe_nodes[0])
        super().__init__(config, target_frames, affected_pe=pe4.id, wrong_rt_value=888, recovery=False)

class RTMisconfigPE5(RTMisconfigScenario):
    """RT misconfiguration on PE5 with wrong import RT 100:999. Persistent
    -- no correction ever appears."""
    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames, affected_pe='PE5', wrong_rt_value=999, recovery=False)


# # ---------------------------------------------------------------------------
# # Import RT wrong — all PEs
# # ---------------------------------------------------------------------------
#
# class RTMisconfigImportPE1(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE1', wrong_rt_value=999, recovery=False)
#
# class RTMisconfigImportPE2(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE2', wrong_rt_value=999, recovery=False)
#
# class RTMisconfigImportPE3(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE3', wrong_rt_value=999, recovery=False)
#
# class RTMisconfigImportPE4(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE4', wrong_rt_value=999, recovery=False)
#
# class RTMisconfigImportPE5(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE5', wrong_rt_value=999, recovery=False)
#
#
# # ---------------------------------------------------------------------------
# # Export RT wrong — all PEs
# # Wrong ASN in the RT community so the PE's routes are not accepted by others
# # ---------------------------------------------------------------------------
#
# class RTMisconfigExportPE1(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE1', wrong_rt_value=777, recovery=False)
#
# class RTMisconfigExportPE2(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE2', wrong_rt_value=777, recovery=False)
#
# class RTMisconfigExportPE3(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE3', wrong_rt_value=777, recovery=False)
#
# class RTMisconfigExportPE4(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE4', wrong_rt_value=777, recovery=False)
#
# class RTMisconfigExportPE5(RTMisconfigScenario):
#     def __init__(self, config, target_frames=20000):
#         super().__init__(config, target_frames, affected_pe='PE5', wrong_rt_value=777, recovery=False)


# ---------------------------------------------------------------------------
# RT misconfiguration with recovery — selected PEs
# ---------------------------------------------------------------------------

class RTMisconfigWithRecoveryPE1(RTMisconfigScenario):
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE1', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigWithRecoveryPE2(RTMisconfigScenario):
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE2', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigWithRecoveryPE3(RTMisconfigScenario):
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE3', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigWithRecoveryPE4(RTMisconfigScenario):
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE4', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigWithRecoveryPE5(RTMisconfigScenario):
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE5', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)


# ---------------------------------------------------------------------------
# RT Misconfiguration on the Type-4 ES route (RFC 4360/7432: RT communities
# apply generically to any EVPN route type, not just Type 2). A wrong RT
# specifically on the ES route breaks ES-Import RT matching between the
# multihomed pair -- PE1 and PE2 fail to discover each other as sharing the
# ESI, breaking multi-homing/DF election itself, a materially more severe
# and different consequence than a generic Type-2 RT mismatch (which only
# blackholes individual MAC/IP routes). Only meaningful for PE1/PE2 -- the
# only real multihomed pair in this topology; PE3/4/5 have no ES-Import
# relationship to break. Type-2 traffic on the affected PE is unaffected --
# only the ES route itself carries the wrong RT.
# ---------------------------------------------------------------------------

class RTMisconfigESImportScenario(BaseScenario):
    """Wrong RT on the affected PE's Type-4 ES route only -- breaks
    ES-Import RT matching between the multihomed pair while leaving all
    Type-2 (MAC/IP) traffic on the same PE correctly RT'd.
    """
    FAULT_TYPE: str = 'RT Misconfiguration'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 20000,
                 affected_pe: str = 'PE1', wrong_rt_value: int = 999,
                 recovery: bool = False, recovery_delay: float = 120.0):
        super().__init__(config, target_frames)
        self.affected_pe_id = affected_pe
        pe = config.get_router(self.affected_pe_id)
        if not pe or not pe.esi:
            raise ValueError(
                f"PE {self.affected_pe_id} is not multihomed in this topology, "
                "cannot break ES-Import RT matching for a non-existent ES")

        rt_parts = config.evpn.route_target.split(':')
        self.correct_rt_asn = int(rt_parts[0])
        self.correct_rt_value = int(rt_parts[1])
        self.wrong_rt_value = wrong_rt_value
        self.wrong_rt_asn = 100

        self.recovery = recovery
        self.recovery_delay = recovery_delay

        # Is this vantage the affected PE's own home RR (direct case) or a
        # different RR that only sees this fault via RR-RR mesh reflection
        # (RFC 4456)?
        self.home_rr_id = pe.peers[0] if pe.peers else None
        self.is_reflected = bool(self.home_rr_id and self.home_rr_id != config.capture_vantage)

    def _build_wrong_rt_path_attrs(self, pe_router, nlri_bytes: bytes,
                                   originator_id: str = None, cluster_id: str = None) -> bytes:
        """This fault-injection packet is an RR reflecting affected_pe's
        route to its clients, same as build_standard_evpn_path_attrs()'s
        reflected case elsewhere in this file -- RFC 4456 SS8 requires a
        real RR to always set ORIGINATOR_ID on a reflected route."""
        wrong_rt = encode_rt_community(self.wrong_rt_asn, self.wrong_rt_value)
        encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
        attrs = b''
        attrs += attr_origin(0)
        attrs += attr_as_path()
        attrs += attr_local_pref(100)
        attrs += attr_extended_communities([wrong_rt, encap])
        attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.bgp_id, nlri_bytes)
        if originator_id is not None and cluster_id is not None:
            attrs += attr_originator_id(originator_id)
            attrs += attr_cluster_list([cluster_id])
        return attrs

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
        affected_pe = self.config.get_router(self.affected_pe_id)

        affected_session = None
        affected_tcp = None
        if not self.is_reflected:
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == self.affected_pe_id:
                    affected_session = bgp_sess
                    affected_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    break

        if self.is_reflected:
            # This vantage isn't affected_pe's home RR -- reflect the
            # wrong-RT Type-4 ES route over the RR-RR mesh session instead
            # (first hop), then fan out
            # to this vantage's own PE clients only (second hop; RFC 4456
            # forbids reflecting a non-client-received route onward to
            # other non-client peers).
            mesh_sess = self._rr_rr_session(self.home_rr_id)
            mesh_tcp = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
            if mesh_tcp and mesh_tcp.is_established():
                wrong_rt = (self.wrong_rt_asn, self.wrong_rt_value)
                pkts, t = self.reflect_single_route_to_rr(
                    mesh_tcp, affected_pe, route_type=4, action='advertise', start_t=t,
                    wrong_rt=wrong_rt)
                packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))

                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    affected_pe, affected_pe.esi, 'advertise', t, clients_only=True,
                    wrong_rt=wrong_rt)
                packets.extend(self._mark_event(fanout_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))
                t += 0.1
        elif affected_tcp and affected_tcp.is_established():
            # FAULT: wrong RT on the Type-4 ES route only
            es_nlri = evpn.build_es_route(
                affected_pe.bgp_id, affected_pe.esi, affected_pe.bgp_id,
                self.config.evpn.vni)
            path_attrs = self._build_wrong_rt_path_attrs(
                affected_pe, es_nlri, originator_id=affected_pe.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = affected_tcp.send_data(update, t, 'server_to_client')
            packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))
            packets.extend(affected_tcp.generate_ack(t + ack_delay(), 'client_to_server'))
            t += 0.5

            # RFC 4456 second hop: RR1 forwards whatever it received to its
            # other PE clients too. Scoped to PE sessions only (not the
            # RR1-RR2 session) -- matching this file's own reflected-path
            # convention (reflect_to_own_clients / _second_hop_type5_type1,
            # both filtered to bgp_sess.local_router.role == 'pe'), not
            # link_down.py's broader loop: the pcap2story detector's
            # deviant_destinations fix relies on link_identity == 6 marking
            # "only PE4/PE5 content ever crosses the RR1-RR2 link" -- fanning
            # this direct-session PE1/2 fault onto that link too would falsely
            # trip that signal and misreport a resolvable fault as
            # UNRESOLVABLE.
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.role != 'pe' or bgp_sess.local_router.id == self.affected_pe_id:
                    continue
                other_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                if not other_tcp or not other_tcp.is_established():
                    continue
                fanout_attrs = self._build_wrong_rt_path_attrs(
                    affected_pe, es_nlri, originator_id=affected_pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                fanout_update = build_update(path_attributes=fanout_attrs)
                fanout_pkts = other_tcp.send_data(fanout_update, t, 'server_to_client')
                packets.extend(self._mark_event(fanout_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='trigger'))
                t += 0.005
                packets.extend(other_tcp.generate_ack(t, 'client_to_server'))
                t += 0.001
            t += 0.1

            # Correctly-RT'd Type-2 traffic on the same PE, unaffected
            macs = self.topology.get_macs_for_pe(self.affected_pe_id, count=5)
            timestamps = route_burst_timestamps(t, len(macs))
            for mac_entry, ts in zip(macs, timestamps):
                nlri = evpn.build_mac_ip_route(
                    affected_pe.bgp_id, affected_pe.esi, mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni)
                path_attrs = build_standard_evpn_path_attrs(
                    affected_pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=affected_pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = affected_tcp.send_data(update, ts, 'server_to_client')
                packets.extend(pkts)
                packets.extend(affected_tcp.generate_ack(ts + ack_delay(), 'client_to_server'))
            t = timestamps[-1] + 0.5 if timestamps else t

        if self.recovery:
            recovery_update_times: dict = {}
            self.generate_route_churn(packets, t, self.recovery_delay,
                                      last_update_times=recovery_update_times)
            packets.extend(self.generate_keepalives_for_duration(
                t, self.recovery_delay, last_update_times=recovery_update_times))
            t += self.recovery_delay

            if self.is_reflected:
                mesh_sess = self._rr_rr_session(self.home_rr_id)
                mesh_tcp = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
                if mesh_tcp and mesh_tcp.is_established():
                    pkts, t = self.reflect_single_route_to_rr(
                        mesh_tcp, affected_pe, route_type=4, action='advertise', start_t=t)
                    packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))

                    fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                        affected_pe, affected_pe.esi, 'advertise', t, clients_only=True)
                    packets.extend(self._mark_event(fanout_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))
                    t += 0.1
            elif affected_tcp and affected_tcp.is_established():
                # RECOVERY: ES route re-advertised with CORRECT RT
                es_nlri = evpn.build_es_route(
                    affected_pe.bgp_id, affected_pe.esi, affected_pe.bgp_id,
                    self.config.evpn.vni)
                path_attrs = build_standard_evpn_path_attrs(
                    affected_pe.bgp_id, es_nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=affected_pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = affected_tcp.send_data(update, t, 'server_to_client')
                packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))
                packets.extend(affected_tcp.generate_ack(t + ack_delay(), 'client_to_server'))
                t += 0.5

                for bgp_sess in self.topology.get_sessions_at_vantage():
                    if bgp_sess.local_router.role != 'pe' or bgp_sess.local_router.id == self.affected_pe_id:
                        continue
                    other_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    if not other_tcp or not other_tcp.is_established():
                        continue
                    fanout_update = build_update(path_attributes=path_attrs)
                    fanout_pkts = other_tcp.send_data(fanout_update, t, 'server_to_client')
                    packets.extend(self._mark_event(fanout_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))
                    t += 0.005
                    packets.extend(other_tcp.generate_ack(t, 'client_to_server'))
                    t += 0.001
                t += 0.1

        fault_end_t = t if self.recovery else None
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
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


class RTMisconfigESImportPE1(RTMisconfigESImportScenario):
    """Persistent -- ES route on PE1 never corrected."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE1', wrong_rt_value=999, recovery=False)

class RTMisconfigESImportPE2(RTMisconfigESImportScenario):
    """Persistent -- ES route on PE2 never corrected."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE2', wrong_rt_value=999, recovery=False)

class RTMisconfigESImportRecoveryPE1(RTMisconfigESImportScenario):
    """Recovery -- ES route on PE1 corrected after ~120s."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE1', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigESImportRecoveryPE2(RTMisconfigESImportScenario):
    """Recovery -- ES route on PE2 corrected after ~120s."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE2', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)


# 3RR/10PE topology's ES-paired PEs (PE3/PE4, PE6/PE7), mirroring the
# PE1/PE2 pattern above.
class RTMisconfigESImportPE3(RTMisconfigESImportScenario):
    """Persistent -- ES route on PE3 never corrected."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE3', wrong_rt_value=999, recovery=False)

class RTMisconfigESImportPE4(RTMisconfigESImportScenario):
    """Persistent -- ES route on PE4 never corrected."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE4', wrong_rt_value=999, recovery=False)

class RTMisconfigESImportPE6(RTMisconfigESImportScenario):
    """Persistent -- ES route on PE6 never corrected."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE6', wrong_rt_value=999, recovery=False)

class RTMisconfigESImportPE7(RTMisconfigESImportScenario):
    """Persistent -- ES route on PE7 never corrected."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE7', wrong_rt_value=999, recovery=False)

class RTMisconfigESImportRecoveryPE3(RTMisconfigESImportScenario):
    """Recovery -- ES route on PE3 corrected after ~120s."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE3', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigESImportRecoveryPE4(RTMisconfigESImportScenario):
    """Recovery -- ES route on PE4 corrected after ~120s."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE4', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigESImportRecoveryPE6(RTMisconfigESImportScenario):
    """Recovery -- ES route on PE6 corrected after ~120s."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE6', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)

class RTMisconfigESImportRecoveryPE7(RTMisconfigESImportScenario):
    """Recovery -- ES route on PE7 corrected after ~120s."""
    def __init__(self, config, target_frames=20000):
        super().__init__(config, target_frames, affected_pe='PE7', wrong_rt_value=999,
                         recovery=True, recovery_delay=120.0)


class RTMisconfigESImportX2(BaseScenario):
    """Category B multi-incident: two INDEPENDENT ES-Import RT
    misconfigurations, on the two members of one ES pair, at genuinely
    separate times (not RTMisconfigESImportScenario's own single-PE,
    single-incident model). PE_A's wrong-RT fault (persistent, no
    recovery), then CATEGORY_B_GAP_SECONDS (see esdf_toggle.py) later,
    PE_B's own independent wrong-RT fault -- different mechanism label per
    PE to mirror the real rt_misconfig_x2_pe1_pe5 precedent's
    plain/autoderive diversity (here: two distinct wrong-RT values instead,
    since synthcap's rt_misconfig ES-Import doesn't model an autoderive
    variant).

    Both PEs in an ES pair are always homed to the same RR, so one
    is_reflected flag (keyed off PE_A) is valid for both incidents.
    """
    FAULT_TYPE: str = 'RT Misconfiguration'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 20000,
                 es_pair: tuple[str, str] | None = None):
        super().__init__(config, target_frames)
        if es_pair:
            pe_a_id, pe_b_id = es_pair
        else:
            pairs = config.get_multihomed_peers()
            if not pairs:
                raise ValueError("no ES-multihomed pair found in this topology, cannot build RTMisconfigESImportX2")
            pe_a_id, pe_b_id = pairs[0][0].id, pairs[0][1].id
        self.pe_a_id = pe_a_id
        self.pe_b_id = pe_b_id

        rt_parts = config.evpn.route_target.split(':')
        self.correct_rt_asn = int(rt_parts[0])
        self.correct_rt_value = int(rt_parts[1])
        self.wrong_rt_asn = 100

        pe = config.get_router(pe_a_id)
        self.home_rr_id = pe.peers[0] if pe and pe.peers else None
        self.is_reflected = bool(self.home_rr_id and self.home_rr_id != config.capture_vantage)

        self.incidents: list[dict] = []

    def _build_wrong_rt_path_attrs(self, pe_router, nlri_bytes: bytes, wrong_rt_value: int,
                                   originator_id: str = None, cluster_id: str = None) -> bytes:
        wrong_rt = encode_rt_community(self.wrong_rt_asn, wrong_rt_value)
        encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
        attrs = b''
        attrs += attr_origin(0)
        attrs += attr_as_path()
        attrs += attr_local_pref(100)
        attrs += attr_extended_communities([wrong_rt, encap])
        attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.bgp_id, nlri_bytes)
        if originator_id is not None and cluster_id is not None:
            attrs += attr_originator_id(originator_id)
            attrs += attr_cluster_list([cluster_id])
        return attrs

    def _inject_one(self, packets, pe_id: str, wrong_rt_value: int, t: float) -> float:
        from datetime import datetime, timezone
        affected_pe = self.config.get_router(pe_id)
        fault_start_t = t

        if self.is_reflected:
            mesh_sess = self._rr_rr_session(self.home_rr_id)
            mesh_tcp = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
            if mesh_tcp and mesh_tcp.is_established():
                wrong_rt = (self.wrong_rt_asn, wrong_rt_value)
                pkts, t = self.reflect_single_route_to_rr(
                    mesh_tcp, affected_pe, route_type=4, action='advertise', start_t=t, wrong_rt=wrong_rt)
                packets.extend(self._mark_event(pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='trigger'))
                fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                    affected_pe, affected_pe.esi, 'advertise', t, clients_only=True, wrong_rt=wrong_rt)
                packets.extend(self._mark_event(fanout_pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='trigger'))
                t += 0.1
        else:
            affected_tcp = None
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == pe_id:
                    affected_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    break
            if affected_tcp and affected_tcp.is_established():
                es_nlri = evpn.build_es_route(affected_pe.bgp_id, affected_pe.esi, affected_pe.bgp_id, self.config.evpn.vni)
                path_attrs = self._build_wrong_rt_path_attrs(
                    affected_pe, es_nlri, wrong_rt_value,
                    originator_id=affected_pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = affected_tcp.send_data(update, t, 'server_to_client')
                packets.extend(self._mark_event(pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='trigger'))
                packets.extend(affected_tcp.generate_ack(t + ack_delay(), 'client_to_server'))
                t += 0.5

                for bgp_sess in self.topology.get_sessions_at_vantage():
                    if bgp_sess.local_router.role != 'pe' or bgp_sess.local_router.id == pe_id:
                        continue
                    other_tcp = self.tcp_sessions.get(bgp_sess.session_id)
                    if not other_tcp or not other_tcp.is_established():
                        continue
                    fanout_attrs = self._build_wrong_rt_path_attrs(
                        affected_pe, es_nlri, wrong_rt_value,
                        originator_id=affected_pe.bgp_id,
                        cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                    fanout_update = build_update(path_attributes=fanout_attrs)
                    fanout_pkts = other_tcp.send_data(fanout_update, t, 'server_to_client')
                    packets.extend(self._mark_event(fanout_pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='trigger'))
                    t += 0.005
                    packets.extend(other_tcp.generate_ack(t, 'client_to_server'))
                    t += 0.001
                t += 0.1

        fault_end_t = t
        self.incidents.append({
            "event_affected_node": pe_id,
            "fault_type": self.FAULT_TYPE,
            "trigger_mechanism": "Plain Import/Export Mismatch",
            "time_of_first_fault": datetime.fromtimestamp(fault_start_t, tz=timezone.utc).isoformat(),
            "recovered": False,
            "time_of_recovery": None,
            "configured_export_rt": f"{self.correct_rt_asn}:{self.correct_rt_value} (export)",
            "configured_import_rt": f"{self.wrong_rt_asn}:{wrong_rt_value} (mismatched import)",
        })
        return t

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

        # INCIDENT 1: PE_A, wrong RT value 999
        t = self._inject_one(packets, self.pe_a_id, 999, t)

        # Independent gap -- see esdf_toggle.py's CATEGORY_B_GAP_SECONDS.
        self.generate_route_churn(packets, t, 120.0, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, 120.0, last_update_times=last_update_times))
        t += 120.0

        # INCIDENT 2: PE_B, different wrong RT value (888)
        t = self._inject_one(packets, self.pe_b_id, 888, t)

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration, last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(t, post_duration, last_update_times=last_update_times2))

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class RTMisconfigESImportX2PE1PE2(RTMisconfigESImportX2):
    def __init__(self, config, target_frames=20000): super().__init__(config, target_frames, es_pair=('PE1', 'PE2'))
