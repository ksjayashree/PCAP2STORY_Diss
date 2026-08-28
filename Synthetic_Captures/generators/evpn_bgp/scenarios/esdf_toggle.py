"""Section 2 — ES/DF Toggling fault scenarios.

Simulates Ethernet Segment flapping on multi-homed PEs.
PE1 and PE2 share an ESI — when one PE's CE-facing link flaps, it causes
rapid Type 4 (ES route) changes and a DF re-election. Type 4 is the sole
DF-election signal per RFC 7432 SS8.5 / RFC 8584; Type 1 (EAD per-ES,
per-EVI) is a separate aliasing/backup-path mechanism (RFC 7432 SS8.2/SS8.4)
with no bearing on DF election, so these scenarios model a pure DF-election
signal and leave Type 1 untouched throughout.
"""


import random
from datetime import datetime, timezone
from .base import BaseScenario
from ..config import TopologyConfig
from ..tcp.session import TCPSession, TCPPacket
from ..bgp.messages import build_update, build_keepalive
from ..bgp.attributes import (build_standard_evpn_path_attrs, build_evpn_withdraw_attrs,
                              encode_df_election_community)
from ..bgp import evpn
from generators.common.utils.timing import jittered_interval, ack_delay, keepalive_timestamps


class ESDFSingleToggle(BaseScenario):
    """Single ES/DF toggle with clean recovery.

    One PE withdraws its ES (Type 4) route -- the sole DF-election signal
    per RFC 7432 SS8.5 / RFC 8584 -- then re-advertises it after 10-20
    seconds. Type 1 (EAD) is untouched throughout.
    """

    FAULT_TYPE: str = 'ESDF Toggle'
    SECTION: int = 2
    
    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_pe: str = None, mid_churn: bool = False):
        super().__init__(config, target_frames)
        self.mid_churn = mid_churn  # inject fault mid-warmup-churn-burst instead of after idle
        # Find a multi-homed PE
        mh_pairs = config.get_multihomed_peers() if hasattr(config, 'get_multihomed_peers') else []
        if affected_pe:
            self.affected_pe_id = affected_pe
        elif mh_pairs:
            self.affected_pe_id = mh_pairs[0][0].id  # default, use the first multi-homed pair's first PE
        else:
            # Fallback: use PE1
            self.affected_pe_id = config.pe_nodes[0].id if config.pe_nodes else "PE1"
        
        # Get the shared ESI
        pe = config.get_router(self.affected_pe_id)
        if not pe or not pe.esi:
            raise ValueError(
                f"PE {self.affected_pe_id} is not multihomed in this topology, "
                "cannot resolve ES/DF peer")
        self.esi = pe.esi
        
        # Get the peer PE (other PE with same ESI)
        self.peer_pe_id = None
        for other_pe in config.pe_nodes:
            if other_pe.id != self.affected_pe_id and other_pe.esi == self.esi:
                self.peer_pe_id = other_pe.id
                break

        self.home_rr_id = pe.peers[0] if pe.peers else None
        self.is_reflected = bool(self.home_rr_id and self.home_rr_id != config.capture_vantage)

    def _get_session_for_pe(self, pe_id: str):
        """Find the BGP session and TCP session for a given PE.

        When self.is_reflected, the affected/peer PE has no direct session
        at this vantage -- returns the RR-RR mesh session to the PE's home
        RR instead."""
        if self.is_reflected:
            mesh_sess = self._rr_rr_session(self.home_rr_id)
            tcp_sess = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
            return mesh_sess, tcp_sess
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                return bgp_sess, tcp_sess
        return None, None
    
    def _advertise_mh_routes(self, pe_router, tcp_sess, timestamp: float,
                             event: bool = False, phase: str = None,
                             extra_communities: list = None) -> list[TCPPacket]:
        """Advertise the ES (Type 4) route -- the sole DF-election signal
        per RFC 7432 SS8.5 / RFC 8584. Type 1 (EAD per-ES, EAD per-EVI) is a
        separate mechanism (aliasing/backup-path, RFC 7432 SS8.2/SS8.4) with
        no bearing on DF election and is intentionally left untouched here.

        extra_communities: optional additional extended communities attached
        to the primary PE->RR advertisement, e.g. the RFC 8584 DF Election
        Extended Community used by ESDFACStateToggle. Not forwarded to
        _fan_out_type4_to_other_sessions() -- reflected copies to other PE
        sessions carry the base Type-4 route without the extra community.
        """
        packets = []
        t = timestamp

        if self.is_reflected:
            # This vantage isn't pe_router's home RR -- tcp_sess is the
            # RR-RR mesh session (see _get_session_for_pe()), so the "first
            # hop" is the single-route reflection helper instead of a direct
            # PE advertisement, and the "second hop" fan-out excludes other
            # RR-RR sessions (RFC 4456: a route received from a non-client
            # peer only reflects to this vantage's own clients).
            pkts, t = self.reflect_single_route_to_rr(
                tcp_sess, pe_router, route_type=4, action='advertise', start_t=t,
                extra_communities=extra_communities)
            packets.extend(pkts)
            fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                pe_router, self.esi, 'advertise', t, clients_only=True)
            packets.extend(fanout_pkts)
            if event:
                self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
            return packets

        # Type 4: ES route
        nlri = evpn.build_es_route(pe_router.bgp_id, self.esi, pe_router.bgp_id,
                                    self.config.evpn.vni)
        path_attrs = build_standard_evpn_path_attrs(
            pe_router.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
            originator_id=pe_router.bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id,
            extra_communities=extra_communities)
        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

        # RFC 4456 second-hop reflection: fan the same route out to every
        # other established session at the vantage.
        fanout_pkts, t = self._fan_out_type4_to_other_sessions(
            pe_router, self.esi, 'advertise', t)
        packets.extend(fanout_pkts)

        if event:
            self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
        return packets

    def _withdraw_mh_routes(self, pe_router, tcp_sess, timestamp: float,
                            event: bool = False, phase: str = None) -> list[TCPPacket]:
        """Withdraw the ES (Type 4) route -- the sole DF-election signal
        per RFC 7432 SS8.5 / RFC 8584. Type 1 is intentionally untouched;
        see _advertise_mh_routes()'s docstring.
        """
        packets = []
        t = timestamp

        if self.is_reflected:
            pkts, t = self.reflect_single_route_to_rr(
                tcp_sess, pe_router, route_type=4, action='withdraw', start_t=t)
            packets.extend(pkts)
            fanout_pkts, t = self._fan_out_type4_to_other_sessions(
                pe_router, self.esi, 'withdraw', t, clients_only=True)
            packets.extend(fanout_pkts)
            if event:
                self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
            return packets

        # Withdraw Type 4: ES route
        nlri = evpn.build_es_route(pe_router.bgp_id, self.esi, pe_router.bgp_id,
                                    self.config.evpn.vni)
        path_attrs = build_evpn_withdraw_attrs(
            nlri, originator_id=pe_router.bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

        # RFC 4456 second-hop reflection: fan the same withdrawal out to
        # every other established session at the vantage.
        fanout_pkts, t = self._fan_out_type4_to_other_sessions(
            pe_router, self.esi, 'withdraw', t)
        packets.extend(fanout_pkts)

        if event:
            self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
        return packets

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (IMET, IP Prefix, MAC/IP from all PEs)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)
        
        # Advertise initial MH routes for both PE1 and PE2 (explicit Type 1/4)
        affected_pe = self.config.get_router(self.affected_pe_id)
        bgp_sess_affected, tcp_affected = self._get_session_for_pe(self.affected_pe_id)
        
        if tcp_affected:
            mh_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t)
            packets.extend(mh_pkts)
            t += 0.1
        
        if self.peer_pe_id:
            peer_pe = self.config.get_router(self.peer_pe_id)
            bgp_sess_peer, tcp_peer = self._get_session_for_pe(self.peer_pe_id)
            if tcp_peer:
                mh_pkts = self._advertise_mh_routes(peer_pe, tcp_peer, t)
                packets.extend(mh_pkts)
                t += 0.1
        
        # Also advertise some MAC/IP routes
        for bgp_session in self.topology.get_sessions_at_vantage():
            pe = bgp_session.local_router
            if pe.role == 'pe':
                route_pkts = self.generate_route_updates(
                    bgp_session.session_id, pe, num_routes=random.randint(3, 7), start_time=t)
                packets.extend(route_pkts)
                t += 0.1
        
        # Warmup (~5 minutes)
        warmup_duration = self._param_rng.randint(120, 480)
        t = self.warmup_with_optional_mid_churn(packets, t, warmup_duration,
                                                mid_churn=self.mid_churn)

        # FAULT: affected PE withdraws MH routes (ES toggle)
        fault_start_t = t
        if tcp_affected and tcp_affected.is_established():
            withdraw_pkts = self._withdraw_mh_routes(affected_pe, tcp_affected, t, event=True, phase='trigger')
            packets.extend(withdraw_pkts)

        t += 0.5

        # Continued traffic for 10-20 seconds. No session is ever torn down
        # by an ES/DF toggle (only EVPN NLRI is withdrawn), so unlike
        # link_down/rr_down there is no exclusion concern here.
        toggle_duration = self._param_rng.uniform(10, 20)
        toggle_update_times: dict = {}
        self.generate_route_churn(packets, t, toggle_duration,
                                  last_update_times=toggle_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, toggle_duration, last_update_times=toggle_update_times))
        t += toggle_duration

        # RECOVERY: PE re-advertises MH routes
        if tcp_affected and tcp_affected.is_established():
            readv_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t, event=True, phase='recovery')
            packets.extend(readv_pkts)

        t += 0.5
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


# PE-specific variants for Section 2 supervised fine-tuning

class ESDFSingleTogglePE1(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class ESDFSingleTogglePE2(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')

# Non-idle injection timing: fault fires mid-churn-burst instead of after idle warmup.
class ESDFSingleToggleMidChurnPE1(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1', mid_churn=True)

class ESDFSingleToggleMidChurnPE2(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2', mid_churn=True)

class ESDFSingleToggleMidChurnPE3(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3', mid_churn=True)

class ESDFSingleToggleMidChurnPE4(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4', mid_churn=True)

class ESDFSingleToggleMidChurnPE6(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE6', mid_churn=True)

class ESDFSingleToggleMidChurnPE7(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE7', mid_churn=True)


# 3RR/10PE topology's ES-paired PEs (PE3/PE4, PE6/PE7).
class ESDFSingleTogglePE3(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')

class ESDFSingleTogglePE4(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4')

class ESDFSingleTogglePE6(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE6')

class ESDFSingleTogglePE7(ESDFSingleToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE7')


class ESDFType1EVIToggle(BaseScenario):
    """Single ES/DF toggle triggered by a Type 1 per-EVI EAD route
    withdrawal, RFC 8584's second DF-election trigger type -- distinct
    from ESDFSingleToggle's Type 4 ES-route trigger. One PE withdraws its
    per-EVI EAD route, then re-advertises it after 10-20 seconds.

    Not a subclass of ESDFSingleToggle: mirrors its structure as an
    independent class rather than inheriting and overriding, since the two
    trigger types (Type 4 vs Type 1) don't share code.
    """

    FAULT_TYPE: str = 'ESDF Toggle'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_pe: str = None, mid_churn: bool = False):
        super().__init__(config, target_frames)
        self.mid_churn = mid_churn  # inject fault mid-warmup-churn-burst instead of after idle
        # Find a multi-homed PE
        mh_pairs = config.get_multihomed_peers() if hasattr(config, 'get_multihomed_peers') else []
        if affected_pe:
            self.affected_pe_id = affected_pe
        elif mh_pairs:
            self.affected_pe_id = mh_pairs[0][0].id  # default, use the first multi-homed pair's first PE
        else:
            # Fallback: use PE1
            self.affected_pe_id = config.pe_nodes[0].id if config.pe_nodes else "PE1"

        # Get the shared ESI
        pe = config.get_router(self.affected_pe_id)
        if not pe or not pe.esi:
            raise ValueError(
                f"PE {self.affected_pe_id} is not multihomed in this topology, "
                "cannot resolve ES/DF peer")
        self.esi = pe.esi

        # Get the peer PE (other PE with same ESI)
        self.peer_pe_id = None
        for other_pe in config.pe_nodes:
            if other_pe.id != self.affected_pe_id and other_pe.esi == self.esi:
                self.peer_pe_id = other_pe.id
                break

        self.home_rr_id = pe.peers[0] if pe.peers else None
        self.is_reflected = bool(self.home_rr_id and self.home_rr_id != config.capture_vantage)

    def _get_session_for_pe(self, pe_id: str):
        """Find the BGP session and TCP session for a given PE.

        When self.is_reflected, the affected/peer PE has no direct session
        at this vantage -- returns the RR-RR mesh session to the PE's home
        RR instead."""
        if self.is_reflected:
            mesh_sess = self._rr_rr_session(self.home_rr_id)
            tcp_sess = self.tcp_sessions.get(mesh_sess.session_id) if mesh_sess else None
            return mesh_sess, tcp_sess
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
                return bgp_sess, tcp_sess
        return None, None

    def _advertise_mh_routes_type1_evi(self, pe_router, tcp_sess, timestamp: float,
                             event: bool = False, phase: str = None) -> list[TCPPacket]:
        """Advertise the per-EVI EAD (Type 1) route as the DF-election
        trigger signal for this variant (RFC 8584's Type-1-withdrawal
        trigger type). Parallel to ESDFSingleToggle._advertise_mh_routes(),
        which uses Type 4 instead.
        """
        packets = []
        t = timestamp

        if self.is_reflected:
            pkts, t = self.reflect_single_route_to_rr(
                tcp_sess, pe_router, route_type=1, action='advertise', start_t=t, ethernet_tag=0)
            packets.extend(pkts)
            fanout_pkts, t = self._fan_out_type1_evi_to_other_sessions(
                pe_router, self.esi, 'advertise', t, clients_only=True)
            packets.extend(fanout_pkts)
            if event:
                self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
            return packets

        # Type 1: per-EVI EAD route
        nlri = evpn.build_ead_per_evi(pe_router.bgp_id, self.esi, 0,
                                       self.config.evpn.vni)
        path_attrs = build_standard_evpn_path_attrs(
            pe_router.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
            originator_id=pe_router.bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

        # RFC 4456 second-hop reflection: fan the same route out to every
        # other established session at the vantage.
        fanout_pkts, t = self._fan_out_type1_evi_to_other_sessions(
            pe_router, self.esi, 'advertise', t)
        packets.extend(fanout_pkts)

        if event:
            self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
        return packets

    def _withdraw_mh_routes_type1_evi(self, pe_router, tcp_sess, timestamp: float,
                            event: bool = False, phase: str = None) -> list[TCPPacket]:
        """Withdraw the per-EVI EAD (Type 1) route -- the DF-election
        trigger signal for this variant. Parallel to
        ESDFSingleToggle._withdraw_mh_routes(), which uses Type 4 instead.
        """
        packets = []
        t = timestamp

        if self.is_reflected:
            pkts, t = self.reflect_single_route_to_rr(
                tcp_sess, pe_router, route_type=1, action='withdraw', start_t=t, ethernet_tag=0)
            packets.extend(pkts)
            fanout_pkts, t = self._fan_out_type1_evi_to_other_sessions(
                pe_router, self.esi, 'withdraw', t, clients_only=True)
            packets.extend(fanout_pkts)
            if event:
                self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
            return packets

        # Withdraw Type 1: per-EVI EAD route
        nlri = evpn.build_ead_per_evi(pe_router.bgp_id, self.esi, 0,
                                       self.config.evpn.vni)
        path_attrs = build_evpn_withdraw_attrs(
            nlri, originator_id=pe_router.bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'server_to_client')
        packets.extend(pkts)
        t += 0.005
        packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

        # RFC 4456 second-hop reflection: fan the same withdrawal out to
        # every other established session at the vantage.
        fanout_pkts, t = self._fan_out_type1_evi_to_other_sessions(
            pe_router, self.esi, 'withdraw', t)
        packets.extend(fanout_pkts)

        if event:
            self._mark_event(packets, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase=phase)
        return packets

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route table (IMET, IP Prefix, MAC/IP from all PEs)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Advertise initial MH routes for both PE1 and PE2
        affected_pe = self.config.get_router(self.affected_pe_id)
        bgp_sess_affected, tcp_affected = self._get_session_for_pe(self.affected_pe_id)

        if tcp_affected:
            mh_pkts = self._advertise_mh_routes_type1_evi(affected_pe, tcp_affected, t)
            packets.extend(mh_pkts)
            t += 0.1

        if self.peer_pe_id:
            peer_pe = self.config.get_router(self.peer_pe_id)
            bgp_sess_peer, tcp_peer = self._get_session_for_pe(self.peer_pe_id)
            if tcp_peer:
                mh_pkts = self._advertise_mh_routes_type1_evi(peer_pe, tcp_peer, t)
                packets.extend(mh_pkts)
                t += 0.1

        # Also advertise some MAC/IP routes
        for bgp_session in self.topology.get_sessions_at_vantage():
            pe = bgp_session.local_router
            if pe.role == 'pe':
                route_pkts = self.generate_route_updates(
                    bgp_session.session_id, pe, num_routes=random.randint(3, 7), start_time=t)
                packets.extend(route_pkts)
                t += 0.1

        # Warmup (~5 minutes)
        warmup_duration = self._param_rng.randint(120, 480)
        t = self.warmup_with_optional_mid_churn(packets, t, warmup_duration,
                                                mid_churn=self.mid_churn)

        # FAULT: affected PE withdraws MH routes (ES toggle, Type 1 per-EVI trigger)
        fault_start_t = t
        if tcp_affected and tcp_affected.is_established():
            withdraw_pkts = self._withdraw_mh_routes_type1_evi(affected_pe, tcp_affected, t, event=True, phase='trigger')
            packets.extend(withdraw_pkts)

        t += 0.5

        # Continued traffic for 10-20 seconds. No session is ever torn down
        # by an ES/DF toggle (only EVPN NLRI is withdrawn), so unlike
        # link_down/rr_down there is no exclusion concern here.
        toggle_duration = self._param_rng.uniform(10, 20)
        toggle_update_times: dict = {}
        self.generate_route_churn(packets, t, toggle_duration,
                                  last_update_times=toggle_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, toggle_duration, last_update_times=toggle_update_times))
        t += toggle_duration

        # RECOVERY: PE re-advertises MH routes
        if tcp_affected and tcp_affected.is_established():
            readv_pkts = self._advertise_mh_routes_type1_evi(affected_pe, tcp_affected, t, event=True, phase='recovery')
            packets.extend(readv_pkts)

        t += 0.5
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


class ESDFType1EVITogglePE1(ESDFType1EVIToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class ESDFType1EVITogglePE2(ESDFType1EVIToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')


class ESDFType1EVITogglePE3(ESDFType1EVIToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')

class ESDFType1EVITogglePE4(ESDFType1EVIToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4')

class ESDFType1EVITogglePE6(ESDFType1EVIToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE6')

class ESDFType1EVITogglePE7(ESDFType1EVIToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE7')


class ESDFACStateToggle(ESDFSingleToggle):
    """ES/DF toggle triggered by local AC (attachment circuit) state,
    RFC 8584's first DF-election trigger type -- distinct from both the
    Type-4 ES-route-withdrawal trigger (ESDFSingleToggle) and the Type-1
    per-EVI-withdrawal trigger (ESDFType1EVIToggle).

    The DF Election Extended Community is attached to an ADVERTISED ES
    route, not carried via a withdraw/re-advertise pair -- so unlike the
    other two ESDF mechanisms, this one never withdraws the Type-4 route at
    all. The AC-down event is represented as a Type-4 re-advertisement with
    the community's AC-DF capability bit cleared; the AC-up recovery is a
    second re-advertisement with the bit set again.

    Subclasses ESDFSingleToggle since this mechanism reuses the same Type-4
    NLRI/advertise machinery unchanged -- only the extended-community
    payload differs, via _advertise_mh_routes()'s extra_communities
    parameter. This class calls the existing _advertise_mh_routes() twice
    (trigger, recovery).

    Note: the reflected copies of this advertisement reaching other PE
    sessions carry the base Type-4 route without the DF Election Extended
    Community -- only the primary PE->RR1 packet carries it.
    """

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route table (IMET, IP Prefix, MAC/IP from all PEs)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Advertise initial MH routes for both PE1 and PE2 (base Type 4, no AC-DF community)
        affected_pe = self.config.get_router(self.affected_pe_id)
        bgp_sess_affected, tcp_affected = self._get_session_for_pe(self.affected_pe_id)

        if tcp_affected:
            mh_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t)
            packets.extend(mh_pkts)
            t += 0.1

        if self.peer_pe_id:
            peer_pe = self.config.get_router(self.peer_pe_id)
            bgp_sess_peer, tcp_peer = self._get_session_for_pe(self.peer_pe_id)
            if tcp_peer:
                mh_pkts = self._advertise_mh_routes(peer_pe, tcp_peer, t)
                packets.extend(mh_pkts)
                t += 0.1

        # Also advertise some MAC/IP routes
        for bgp_session in self.topology.get_sessions_at_vantage():
            pe = bgp_session.local_router
            if pe.role == 'pe':
                route_pkts = self.generate_route_updates(
                    bgp_session.session_id, pe, num_routes=random.randint(3, 7), start_time=t)
                packets.extend(route_pkts)
                t += 0.1

        # Warmup (~5 minutes)
        warmup_duration = self._param_rng.randint(120, 480)
        t = self.warmup_with_optional_mid_churn(packets, t, warmup_duration,
                                                mid_churn=self.mid_churn)

        # TRIGGER: local AC on the affected PE goes DOWN -- re-advertise the
        # SAME Type-4 ES route with the AC-DF capability bit cleared. No
        # withdrawal at any point.
        fault_start_t = t
        if tcp_affected and tcp_affected.is_established():
            ac_down_pkts = self._advertise_mh_routes(
                affected_pe, tcp_affected, t, event=True, phase='trigger',
                extra_communities=[encode_df_election_community(df_alg=0, ac_df=False)])
            packets.extend(ac_down_pkts)

        t += 0.5

        # Continued traffic for 10-20 seconds. No session is ever torn down
        # and no route is ever withdrawn by this mechanism.
        toggle_duration = self._param_rng.uniform(10, 20)
        toggle_update_times: dict = {}
        self.generate_route_churn(packets, t, toggle_duration,
                                  last_update_times=toggle_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, toggle_duration, last_update_times=toggle_update_times))
        t += toggle_duration

        # RECOVERY: local AC comes back UP -- re-advertise the same Type-4
        # ES route with the AC-DF capability bit set again.
        if tcp_affected and tcp_affected.is_established():
            ac_up_pkts = self._advertise_mh_routes(
                affected_pe, tcp_affected, t, event=True, phase='recovery',
                extra_communities=[encode_df_election_community(df_alg=0, ac_df=True)])
            packets.extend(ac_up_pkts)

        t += 0.5
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


class ESDFACStateTogglePE1(ESDFACStateToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class ESDFACStateTogglePE2(ESDFACStateToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')


class ESDFACStateTogglePE3(ESDFACStateToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')

class ESDFACStateTogglePE4(ESDFACStateToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4')

class ESDFACStateTogglePE6(ESDFACStateToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE6')

class ESDFACStateTogglePE7(ESDFACStateToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE7')


class ESDFRepeatedToggle(ESDFSingleToggle):
    """Repeated ES/DF toggling: 3-4 cycles within a minute, at ordinary
    per-toggle withdraw-to-advertise timing (not accelerated) -- the
    distinguishing factor is toggle repetition count, not move speed."""
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        # Setup + initial routes
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)
        
        affected_pe = self.config.get_router(self.affected_pe_id)
        bgp_sess_affected, tcp_affected = self._get_session_for_pe(self.affected_pe_id)
        
        if tcp_affected:
            mh_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t)
            packets.extend(mh_pkts)
            t += 0.1
        
        if self.peer_pe_id:
            peer_pe = self.config.get_router(self.peer_pe_id)
            _, tcp_peer = self._get_session_for_pe(self.peer_pe_id)
            if tcp_peer:
                mh_pkts = self._advertise_mh_routes(peer_pe, tcp_peer, t)
                packets.extend(mh_pkts)
                t += 0.1
        
        # Warmup
        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        # REPEATED TOGGLING: 3-4 cycles within 60 seconds
        num_toggles = random.randint(3, 4)
        toggle_interval = 60.0 / num_toggles
        
        first_toggle_start = None
        last_fault_end = None
        for i in range(num_toggles):
            toggle_start_t = t
            if first_toggle_start is None:
                first_toggle_start = toggle_start_t
            # WITHDRAW (toggle down)
            if tcp_affected and tcp_affected.is_established():
                withdraw_pkts = self._withdraw_mh_routes(affected_pe, tcp_affected, t, event=True, phase='trigger')
                packets.extend(withdraw_pkts)
            
            # Brief down period (5-15 seconds)
            down_time = random.uniform(5, toggle_interval * 0.6)
            t += down_time
            
            # RE-ADVERTISE (toggle up)
            if tcp_affected and tcp_affected.is_established():
                readv_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t, event=True, phase='recovery')
                packets.extend(readv_pkts)

            t += toggle_interval - down_time
            last_fault_end = t + self.BASELINE_CHECK_WINDOW

        self._fault_start_t = first_toggle_start
        self._fault_end_t = last_fault_end

        # Post-toggle continued traffic
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


class ESDFNoRecovery(ESDFSingleToggle):
    """ES/DF toggle with no recovery — PE permanently withdraws its ES
    (Type 4) route, the sole DF-election signal (RFC 7432 SS8.5 /
    RFC 8584). Type 1 is untouched throughout."""
    
    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time
        
        # Setup + initial routes
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)
        
        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)
        
        affected_pe = self.config.get_router(self.affected_pe_id)
        bgp_sess_affected, tcp_affected = self._get_session_for_pe(self.affected_pe_id)
        
        if tcp_affected:
            mh_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t)
            packets.extend(mh_pkts)
            t += 0.1
        
        if self.peer_pe_id:
            peer_pe = self.config.get_router(self.peer_pe_id)
            _, tcp_peer = self._get_session_for_pe(self.peer_pe_id)
            if tcp_peer:
                mh_pkts = self._advertise_mh_routes(peer_pe, tcp_peer, t)
                packets.extend(mh_pkts)
                t += 0.1
        
        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        # FAULT: Withdraw MH routes permanently
        fault_start_t = t
        if tcp_affected and tcp_affected.is_established():
            withdraw_pkts = self._withdraw_mh_routes(affected_pe, tcp_affected, t, event=True, phase='trigger')
            packets.extend(withdraw_pkts)
        
        t += 0.5

        # No recovery — just continued baseline traffic for 8+ minutes
        no_recovery_duration = self._param_rng.uniform(480, 600)
        last_update_times2: dict = {}
        self.generate_route_churn(packets, t, no_recovery_duration,
                                  last_update_times=last_update_times2)
        packets.extend(self.generate_keepalives_for_duration(
            t, no_recovery_duration, last_update_times=last_update_times2))

        self._fault_start_t = fault_start_t
        self._fault_end_t = None

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, no_recovery_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class ESDFSlowToggle(ESDFSingleToggle):
    """Slow ES/DF toggling: 2 toggles with long intervals between them (2-5 minutes apart).

    Tests whether the model detects ES/DF instability when transitions
    occur far apart in time.
    """

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_pe: str = None):
        super().__init__(config, target_frames, affected_pe)

    def generate(self):
        import random
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        affected_pe = self.config.get_router(self.affected_pe_id)
        bgp_sess_affected, tcp_affected = self._get_session_for_pe(self.affected_pe_id)

        if tcp_affected:
            mh_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t)
            packets.extend(mh_pkts)
            t += 0.1

        if self.peer_pe_id:
            peer_pe = self.config.get_router(self.peer_pe_id)
            _, tcp_peer = self._get_session_for_pe(self.peer_pe_id)
            if tcp_peer:
                mh_pkts = self._advertise_mh_routes(peer_pe, tcp_peer, t)
                packets.extend(mh_pkts)
                t += 0.1

        # Warmup
        warmup_duration = self._param_rng.randint(120, 480)
        last_update_times: dict = {}
        self.generate_route_churn(packets, t, warmup_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, warmup_duration, last_update_times=last_update_times))
        t += warmup_duration

        fault_start_t = t

        # TOGGLE 1: withdraw
        if tcp_affected and tcp_affected.is_established():
            withdraw_pkts = self._withdraw_mh_routes(affected_pe, tcp_affected, t, event=True, phase='trigger')
            packets.extend(withdraw_pkts)

        # Long down period: 2-5 minutes
        down_time = random.uniform(120, 300)
        down_update_times: dict = {}
        self.generate_route_churn(packets, t, down_time,
                                  last_update_times=down_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, down_time, last_update_times=down_update_times))
        t += down_time

        # TOGGLE 1 recovery: re-advertise
        if tcp_affected and tcp_affected.is_established():
            readv_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t, event=True, phase='recovery')
            packets.extend(readv_pkts)

        # TOGGLE 2: withdraw again -- fires shortly after Toggle 1's
        # recovery, so the withdraw-to-withdraw cycle spacing is down_time
        # alone (2-5 min).
        t += random.uniform(0.5, 2.0)
        if tcp_affected and tcp_affected.is_established():
            withdraw_pkts = self._withdraw_mh_routes(affected_pe, tcp_affected, t, event=True, phase='trigger')
            packets.extend(withdraw_pkts)

        # Long down period: 2-5 minutes
        down_time2 = random.uniform(120, 300)
        down_update_times2: dict = {}
        self.generate_route_churn(packets, t, down_time2,
                                  last_update_times=down_update_times2)
        packets.extend(self.generate_keepalives_for_duration(
            t, down_time2, last_update_times=down_update_times2))
        t += down_time2

        # TOGGLE 2 recovery
        if tcp_affected and tcp_affected.is_established():
            readv_pkts = self._advertise_mh_routes(affected_pe, tcp_affected, t, event=True, phase='recovery')
            packets.extend(readv_pkts)

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


class ESDFRepeatedTogglePE1(ESDFRepeatedToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

class ESDFRepeatedTogglePE2(ESDFRepeatedToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')

class ESDFRepeatedTogglePE3(ESDFRepeatedToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')

class ESDFRepeatedTogglePE4(ESDFRepeatedToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4')

class ESDFRepeatedTogglePE6(ESDFRepeatedToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE6')

class ESDFRepeatedTogglePE7(ESDFRepeatedToggle):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE7')


class ESDFNoRecoveryPE1(ESDFNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE1')

class ESDFNoRecoveryPE2(ESDFNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE2')

class ESDFNoRecoveryPE3(ESDFNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE3')

class ESDFNoRecoveryPE4(ESDFNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE4')

class ESDFNoRecoveryPE6(ESDFNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE6')

class ESDFNoRecoveryPE7(ESDFNoRecovery):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE7')


# Gap between the two independent incidents in a Category B multi-incident
# capture, large enough that neither incident's fault window overlaps the
# other's detection window.
CATEGORY_B_GAP_SECONDS = 120.0


class ESDFToggleX2(ESDFSingleToggle):
    """Category B multi-incident: two INDEPENDENT single-PE ES/DF toggles
    within one capture -- PE_A's toggle completes (advertise+withdraw+
    re-advertise) fully, then CATEGORY_B_GAP_SECONDS later, PE_B's own
    independent toggle happens. Not ESDFFullFailure (mixed.py): that class
    is near-simultaneous/correlated (models the whole ES failing together);
    this is the opposite -- two genuinely separate incidents that happen to
    share a capture, each independently detectable (metadata.json:
    multi_incident=true, category="B", incidents=[...]).

    Inherits ESDFSingleToggle for _advertise_mh_routes/_withdraw_mh_routes/
    _get_session_for_pe/is_reflected -- both PE_A and PE_B are always the
    two members of the SAME ES pair and share one home RR, so the single
    is_reflected flag computed from PE_A in __init__ is valid for PE_B's
    incident too.

    self.incidents, consumed by the multi-incident driver script, is a list
    of two dicts built directly in the real metadata schema.
    """

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 es_pair: tuple[str, str] | None = None):
        if es_pair:
            pe_a_id, pe_b_id = es_pair
        else:
            pairs = config.get_multihomed_peers()
            if not pairs:
                raise ValueError("no ES-multihomed pair found in this topology, cannot build ESDFToggleX2")
            pe_a_id, pe_b_id = pairs[0][0].id, pairs[0][1].id
        super().__init__(config, target_frames, affected_pe=pe_a_id)
        self.pe_b_id = pe_b_id
        self.incidents: list[dict] = []

    def _one_incident(self, packets, pe_id: str, t: float) -> float:
        pe_router = self.config.get_router(pe_id)
        _, tcp_sess = self._get_session_for_pe(pe_id)
        if not tcp_sess:
            return t

        fault_start_t = t
        withdraw_pkts = self._withdraw_mh_routes(pe_router, tcp_sess, t, event=True, phase='trigger')
        packets.extend(withdraw_pkts)
        t = max((p.timestamp for p in withdraw_pkts), default=t) + self._param_rng.uniform(10, 20)

        readv_pkts = self._advertise_mh_routes(pe_router, tcp_sess, t, event=True, phase='recovery')
        packets.extend(readv_pkts)
        t = max((p.timestamp for p in readv_pkts), default=t)
        fault_end_t = t

        self.incidents.append({
            "event_affected_node": pe_id,
            "fault_type": self.FAULT_TYPE,
            "trigger_mechanism": "ES Route Withdrawal (Type 4)",
            "time_of_first_fault": datetime.fromtimestamp(fault_start_t, tz=timezone.utc).isoformat(),
            "recovered": True,
            "time_of_recovery": datetime.fromtimestamp(fault_end_t, tz=timezone.utc).isoformat(),
        })
        return t + 0.5

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

        # INCIDENT 1: PE_A's independent toggle
        t = self._one_incident(packets, self.affected_pe_id, t)

        # Gap between the two independent incidents.
        gap_start = t
        self.generate_route_churn(packets, t, CATEGORY_B_GAP_SECONDS, last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(t, CATEGORY_B_GAP_SECONDS, last_update_times=last_update_times))
        t = gap_start + CATEGORY_B_GAP_SECONDS

        # INCIDENT 2: PE_B's independent toggle
        t = self._one_incident(packets, self.pe_b_id, t)

        post_duration = 60
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1)) * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration, last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(t, post_duration, last_update_times=last_update_times2))

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class ESDFToggleX2PE1PE2(ESDFToggleX2):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, es_pair=('PE1', 'PE2'))

class ESDFToggleX2PE3PE4(ESDFToggleX2):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, es_pair=('PE3', 'PE4'))
