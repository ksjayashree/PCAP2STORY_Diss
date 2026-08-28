"""Section 1 — Normal traffic generators (quiet, moderate, busy).

No faults anywhere. The model trains on these to learn healthy patterns.
"""

import ipaddress
import random

from .base import BaseScenario, SILENCE_GUARD_THRESHOLD
from ..config import TopologyConfig
from ..tcp.session import TCPPacket, TCPSession
from ..bgp.messages import (
    build_keepalive, build_update, build_open,
    build_notification,
)
from ..bgp.capabilities import default_evpn_capabilities
from ..bgp.attributes import (
    build_standard_evpn_path_attrs, build_evpn_withdraw_attrs,
    attr_origin, attr_as_path, attr_local_pref, attr_extended_communities,
    attr_mp_reach_nlri, encode_rt_community, encode_encapsulation_community,
    encode_mac_mobility_community, attr_originator_id, attr_cluster_list,
)
from ..bgp.constants import (
    AFI_L2VPN, SAFI_EVPN, ERR_CEASE, CEASE_CONNECTION_COLLISION,
)
from ..bgp import evpn
from generators.common.utils.timing import (
    jittered_interval, route_burst_timestamps, ack_delay,
    route_advertisement_delay
)

# ROUTE_REFRESH_ATTACH_PROB and SILENCE_GUARD_THRESHOLD live on BaseScenario
# (base.py) as part of the shared generate_route_churn()/_generate_churn_batch()
# helpers. SILENCE_GUARD_THRESHOLD is imported above for
# AsymmetricBusyScenario's own inline silence-guard check on its
# weighted-subset session selection.


class QuietNormalScenario(BaseScenario):
    """Quiet normal traffic: sessions up, healthy idle, occasional keepalives.

    Minimal route activity. ~90% keepalives, ~10% occasional updates.
    ROUTE-REFRESH is modeled as occasionally following route-churn activity
    on the same session (see ROUTE_REFRESH_ATTACH_PROB) -- a proxy for the
    real-world policy/filter-change triggers behind RFC 2918 refresh, not a
    literal simulation of a policy change.

    CAPTURE_DURATION is derived from PPT target: 14,704 KA messages across
    6 sessions (bidirectional, 10s interval) = 14,704 / (6*2/10) = 12,253 s.
    The remainder of target_frames is filled with TCP window-update frames so
    the BGP-to-TCP ratio (~13% / 87%) matches real production captures.
    """

    CAPTURE_DURATION = 12253  # seconds

    def __init__(self, config: TopologyConfig, target_frames: int = 116000):
        super().__init__(config, target_frames)

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route advertisement (full: IMET, EAD, ES, MAC/IP, IP Prefix)
        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        # Sparse route updates (with occasional attached route-refreshes) —
        # generated before keepalives so their timestamps can be used to
        # suppress keepalives per RFC 4271 SS4.4 (no KEEPALIVE need be sent
        # if another BGP message went out recently).
        last_update_times: dict = {}
        self._add_sparse_updates(packets, t, self.CAPTURE_DURATION, last_update_times)

        # Keepalives at natural BGP rate for calibrated capture window
        ka_pkts = self.generate_keepalives_for_duration(
            t, self.CAPTURE_DURATION, last_update_times=last_update_times)
        packets.extend(ka_pkts)

        packets.sort(key=lambda p: p.timestamp)

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, self.CAPTURE_DURATION, pad_count)
            packets.extend(pad_pkts)
            packets.sort(key=lambda p: p.timestamp)

        return packets[:self.target_frames]

    def _add_sparse_updates(self, packets: list, start: float, duration: float,
                            last_update_times: dict = None):
        """Add occasional route updates and withdrawals throughout the quiet period.

        ~75% advertisements, ~25% withdrawals. Interval calibrated to produce
        ~166 advertise + ~10 withdraw over 12,253s (PPT quiet target). Each
        batch has a small chance (ROUTE_REFRESH_ATTACH_PROB) of being
        followed by a ROUTE-REFRESH on the same session shortly after.

        Thin wrapper over the shared BaseScenario.generate_route_churn() --
        kept as its own method (rather than inlined in generate()) so
        AsymmetricQuietScenario can still override just this piece.
        """
        # One event every 60–90 s → ~166 updates over 12,253 s.
        self.generate_route_churn(
            packets, start, duration,
            interval_range=(60, 90), advertise_prob=0.75,
            advertise_count_range=(1, 1), withdraw_count_range=(1, 1),
            last_update_times=last_update_times, round_robin=False)

class ModerateNormalScenario(BaseScenario):
    """Moderate normal traffic: some route churn, CEs coming/going.

    ~60% keepalives, ~35% updates. ROUTE-REFRESH is modeled as occasionally
    following route-churn activity on the same session (see
    ROUTE_REFRESH_ATTACH_PROB) -- a proxy for the real-world policy/filter-
    change triggers behind RFC 2918 refresh, not a literal simulation of a
    policy change.

    CAPTURE_DURATION derived from PPT: 13,426 KA / (6*2/10) = 11,188 s.
    """

    CAPTURE_DURATION = 11188  # seconds

    def __init__(self, config: TopologyConfig, target_frames: int = 121000):
        super().__init__(config, target_frames)

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route burst (full: IMET, EAD, ES, MAC/IP, IP Prefix)
        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        # Route churn (with occasional attached route-refreshes) — generated
        # before keepalives so their timestamps can be used to suppress
        # keepalives per RFC 4271 SS4.4 (no KEEPALIVE need be sent if
        # another BGP message went out recently).
        last_update_times: dict = {}
        self._add_route_churn(packets, t, self.CAPTURE_DURATION, last_update_times)

        # Keepalives at natural BGP rate for calibrated capture window
        ka_pkts = self.generate_keepalives_for_duration(
            t, self.CAPTURE_DURATION, last_update_times=last_update_times)
        packets.extend(ka_pkts)

        packets.sort(key=lambda p: p.timestamp)

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, self.CAPTURE_DURATION, pad_count)
            packets.extend(pad_pkts)
            packets.sort(key=lambda p: p.timestamp)

        return packets[:self.target_frames]

    def _add_route_churn(self, packets: list, start: float, duration: float,
                         last_update_times: dict = None):
        """CE churn calibrated to ~2,932 updates over 11,188 s (PPT moderate target).

        Interval 15–30 s, 5–9 routes advertised or 2–4 withdrawn per event.
        Sessions are chosen round-robin (not randomly) so no single session
        can go multiple churn intervals without activity. Each batch has a
        small chance (ROUTE_REFRESH_ATTACH_PROB) of being followed by a
        ROUTE-REFRESH on the same session shortly after.

        Thin wrapper over the shared BaseScenario.generate_route_churn().
        """
        self.generate_route_churn(
            packets, start, duration,
            interval_range=(15, 30), advertise_prob=0.6,
            advertise_count_range=(5, 9), withdraw_count_range=(2, 4),
            last_update_times=last_update_times, round_robin=True)


class BusyNormalScenario(BaseScenario):
    """Busy normal traffic: high route activity but all healthy.

    ~30% keepalives, ~65% updates. Lots of MAC/IP advertisements, frequent
    churn, but no faults. ROUTE-REFRESH is modeled as occasionally following
    route-churn activity on the same session (see ROUTE_REFRESH_ATTACH_PROB)
    -- a proxy for the real-world policy/filter-change triggers behind
    RFC 2918 refresh, not a literal simulation of a policy change.

    CAPTURE_DURATION derived from PPT: 6,572 KA / (6*2/10) = 5,477 s.
    """

    CAPTURE_DURATION = 5477  # seconds

    def __init__(self, config: TopologyConfig, target_frames: int = 114000):
        super().__init__(config, target_frames)

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        # Establish all sessions
        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Large initial route burst (full: IMET, EAD, ES, MAC/IP, IP Prefix)
        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        # Additional large MAC/IP burst per PE (busy scenario has more).
        # Post-EOR, steady-state-shaped despite its position here -- uses
        # the Type-2-only path (not the full weighted-roll function) since
        # it's not part of the real initial-sync event; Type-5 diversity
        # for Busy is already covered separately by _add_ip_prefix_routes().
        last_update_times: dict = {}
        for bgp_session in self.topology.get_sessions_at_vantage():
            pe = bgp_session.local_router
            if pe.role != 'pe':
                continue
            route_pkts = self._generate_type2_updates(
                bgp_session.session_id, pe, num_routes=random.randint(20, 35), start_time=t)
            packets.extend(route_pkts)
            if route_pkts:
                last_t = max(p.timestamp for p in route_pkts if p.payload)
                last_update_times.setdefault(bgp_session.session_id, []).append(last_t)
            t += 0.5

        # Heavy route churn (with occasional attached route-refreshes) and
        # IP prefix routes — generated before keepalives so their timestamps
        # can be used to suppress keepalives per RFC 4271 SS4.4.
        self._add_heavy_churn(packets, t, self.CAPTURE_DURATION, last_update_times)
        self._add_ip_prefix_routes(packets, t, self.CAPTURE_DURATION, last_update_times)

        # Keepalives at natural BGP rate for calibrated capture window
        ka_pkts = self.generate_keepalives_for_duration(
            t, self.CAPTURE_DURATION, last_update_times=last_update_times)
        packets.extend(ka_pkts)

        packets.sort(key=lambda p: p.timestamp)

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, self.CAPTURE_DURATION, pad_count)
            packets.extend(pad_pkts)
            packets.sort(key=lambda p: p.timestamp)

        return packets[:self.target_frames]

    def _add_heavy_churn(self, packets: list, start: float, duration: float,
                         last_update_times: dict = None):
        """Heavy churn calibrated to ~11,946 updates over 5,477 s (PPT busy target).

        Interval 4–7 s, 8–16 routes advertised or 4–8 withdrawn per event.
        Sessions are chosen round-robin (not randomly) so no single session
        can go multiple churn intervals without activity. Round-robin alone
        bounds the gap between churn *events* per session, but at Busy's
        tight 4-7s interval the round-robin cycle length lands close enough
        to the 10s keepalive interval that scheduled keepalives can still
        chain-suppress across several consecutive cycles by chance -- so a
        silence guard (SILENCE_GUARD_THRESHOLD) forces an out-of-cycle churn
        event on any session that's gone too long without one, on top of
        round-robin. Each batch has a small chance (ROUTE_REFRESH_ATTACH_PROB)
        of being followed by a ROUTE-REFRESH on the same session shortly after.

        Thin wrapper over the shared BaseScenario.generate_route_churn() --
        kept as its own method so AsymmetricBusyScenario can still override
        just this piece.
        """
        self.generate_route_churn(
            packets, start, duration,
            interval_range=(4, 7), advertise_prob=0.7,
            advertise_count_range=(8, 16), withdraw_count_range=(4, 8),
            last_update_times=last_update_times, round_robin=True,
            silence_guard=True)

    def _add_ip_prefix_routes(self, packets: list, start: float, duration: float,
                              last_update_times: dict = None):
        """Add Type 5 IP prefix routes for L3 EVPN."""
        sessions = self.topology.get_sessions_at_vantage()
        pe_sessions = [(s, s.local_router) for s in sessions if s.local_router.role == 'pe']
        if not pe_sessions:
            return

        t = start + random.uniform(10, 20)
        prefix_counter = 1

        while t < start + duration and prefix_counter < 100:
            bgp_sess, pe = random.choice(pe_sessions)
            tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
            if not tcp_sess or not tcp_sess.is_established():
                t += 10
                continue

            # Generate IP prefix route
            prefix = f"10.{prefix_counter}.0.0"
            nlri = evpn.build_ip_prefix_route(
                pe.bgp_id, prefix, 24, pe.bgp_id, self.config.evpn.vni)
            path_attrs = build_standard_evpn_path_attrs(
                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=pe.bgp_id, cluster_id=bgp_sess.remote_router.bgp_id)
            update = build_update(path_attributes=path_attrs)

            pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))
            if last_update_times is not None:
                last_update_times.setdefault(bgp_sess.session_id, []).append(t)

            prefix_counter += 1
            t += random.uniform(10, 20)


# ---------------------------------------------------------------------------
# MAC Mobility (Normal) — a MAC address moves cleanly between two PEs
# (e.g. VM live migration). Distinct from eval_scenarios.DuplicateMACScenario,
# which models the pathological storm case; this is the single clean move
# that should be classified as Normal traffic.
# ---------------------------------------------------------------------------

class MACMobilityNormalScenario(BaseScenario):
    """A MAC address moves cleanly back and forth between two PEs.

    Pattern per move event: the new PE advertises a Type 2 MAC/IP UPDATE
    with a MAC Mobility extended community (sequence = prev_sequence + 1),
    then shortly after the old PE withdraws its Type 2 advertisement for
    the same MAC. This is healthy, expected EVPN behaviour (VM migration,
    multi-homing failover) and must not be classified as a fault.
    """
    FAULT_TYPE: str = 'Normal'
    SECTION: int = 1

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 pe_a: str = None, pe_b: str = None):
        super().__init__(config, target_frames)
        self.pe_a_id = pe_a or config.pe_nodes[0].id
        self.pe_b_id = pe_b or (config.pe_nodes[1].id if len(config.pe_nodes) > 1
                                else config.pe_nodes[0].id)

    def _build_attrs_with_mobility(self, pe_router, nlri_bytes: bytes,
                                    sequence: int) -> bytes:
        rt_parts = self.config.evpn.route_target.split(':')
        rt = encode_rt_community(int(rt_parts[0]), int(rt_parts[1]))
        encap = encode_encapsulation_community()
        mobility = encode_mac_mobility_community(sequence)
        attrs = b''
        attrs += attr_origin(0)
        attrs += attr_as_path()
        attrs += attr_local_pref(100)
        attrs += attr_extended_communities([rt, encap, mobility])
        attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe_router.bgp_id, nlri_bytes)
        # ORIGINATOR_ID/CLUSTER_LIST (RFC 4456): sent server_to_client
        # (RR->PE at the wire level), so a consumer deriving node identity
        # from raw src IP would otherwise resolve the vantage RR, not the
        # true advertising PE.
        attrs += attr_originator_id(pe_router.bgp_id)
        attrs += attr_cluster_list([self.config.get_router(self.config.capture_vantage).bgp_id])
        return attrs

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        warmup_duration = random.randint(120, 480)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration))
        t += warmup_duration

        bgp_a, tcp_a = self._session_for_pe(self.pe_a_id)
        bgp_b, tcp_b = self._session_for_pe(self.pe_b_id)

        if bgp_a and bgp_b and tcp_a and tcp_b:
            pe_a = bgp_a.local_router
            pe_b = bgp_b.local_router
            mac_entry = self.topology.get_macs_for_pe(pe_a.id)[-1]
            # Last entry, not the first: background/warmup traffic never
            # touches it, avoiding a pre-existing advertisement for this MAC.

            # MAC currently lives on pe_a; each move flips ownership.
            owner_session = {'pe': pe_a, 'tcp': tcp_a}
            other_session = {'pe': pe_b, 'tcp': tcp_b}
            sequence = 0

            num_moves = random.randint(3, 6)
            for _ in range(num_moves):
                sequence += 1
                new_owner = other_session
                old_owner = owner_session

                # Old owner withdraws the MAC first.
                nlri = evpn.build_mac_ip_route(
                    old_owner['pe'].bgp_id, old_owner['pe'].esi or "0",
                    mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
                path_attrs = build_evpn_withdraw_attrs(
                    nlri, originator_id=old_owner['pe'].bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                update = build_update(path_attributes=path_attrs)
                packets.extend(old_owner['tcp'].send_data(update, t, 'server_to_client'))
                packets.extend(old_owner['tcp'].generate_ack(t + ack_delay(), 'client_to_server'))

                # New owner advertises the MAC with an incremented sequence,
                # 100-500ms later.
                t += random.uniform(0.1, 0.5)
                nlri = evpn.build_mac_ip_route(
                    new_owner['pe'].bgp_id, new_owner['pe'].esi or "0",
                    mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
                path_attrs = self._build_attrs_with_mobility(new_owner['pe'], nlri, sequence)
                update = build_update(path_attributes=path_attrs)
                packets.extend(new_owner['tcp'].send_data(update, t, 'server_to_client'))
                packets.extend(new_owner['tcp'].generate_ack(t + ack_delay(), 'client_to_server'))

                owner_session, other_session = new_owner, old_owner
                t += random.uniform(5, 10)

                t += random.uniform(60, 180)

        # Post-move keepalives to fill target_frames.
        remaining = self.target_frames - len(packets)
        if remaining > 0:
            dur = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1))
                      * self.config.timing.keepalive_timer)
            packets.extend(self.generate_keepalives_for_duration(t, dur))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]

    def _session_for_pe(self, pe_id: str):
        """Return (bgp_session, tcp_session) for a PE id, or (None, None)."""
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                tcp = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp and tcp.is_established():
                    return bgp_sess, tcp
        return None, None


class MACMobilityPE1toPE2(MACMobilityNormalScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames, pe_a='PE1', pe_b='PE2')


class MACMobilityPE2toPE1(MACMobilityNormalScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames, pe_a='PE2', pe_b='PE1')


# ---------------------------------------------------------------------------
# Asymmetric PE variants — specific PEs are primary advertisers
# ---------------------------------------------------------------------------

class AsymmetricQuietScenario(QuietNormalScenario):
    """Quiet normal traffic where specified PEs advertise significantly more routes."""

    def __init__(self, config: TopologyConfig, target_frames: int = 116000,
                 primary_pes: list = None):
        super().__init__(config, target_frames)
        self.primary_pes = primary_pes or []

    def _add_sparse_updates(self, packets: list, start: float, duration: float,
                            last_update_times: dict = None):
        sessions = self.topology.get_sessions_at_vantage()
        all_pe_sessions = [(s, s.local_router) for s in sessions if s.local_router.role == 'pe']
        primary_sessions = [(s, pe) for s, pe in all_pe_sessions if pe.id in self.primary_pes]
        other_sessions = [(s, pe) for s, pe in all_pe_sessions if pe.id not in self.primary_pes]

        if not all_pe_sessions:
            return

        # 60–90 s interval — same as base QuietNormalScenario
        t = start + random.uniform(60, 90)
        while t < start + duration:
            if primary_sessions and random.random() < 0.8:
                bgp_sess, pe = random.choice(primary_sessions)
                num = random.randint(2, 4)
            elif other_sessions:
                bgp_sess, pe = random.choice(other_sessions)
                num = 1
            else:
                bgp_sess, pe = random.choice(all_pe_sessions)
                num = 1

            withdraw = random.random() < 0.25
            self._generate_churn_batch(packets, bgp_sess, pe, t, num, withdraw,
                                       last_update_times)
            t += random.uniform(60, 90)


class AsymmetricModerateScenario(ModerateNormalScenario):
    """Moderate normal traffic where specified PEs generate most of the route churn."""

    def __init__(self, config: TopologyConfig, target_frames: int = 121000,
                 primary_pes: list = None):
        super().__init__(config, target_frames)
        self.primary_pes = primary_pes or []

    def _add_route_churn(self, packets: list, start: float, duration: float,
                         last_update_times: dict = None):
        sessions = self.topology.get_sessions_at_vantage()
        all_pe_sessions = [(s, s.local_router) for s in sessions if s.local_router.role == 'pe']
        primary_sessions = [(s, pe) for s, pe in all_pe_sessions if pe.id in self.primary_pes]
        other_sessions = [(s, pe) for s, pe in all_pe_sessions if pe.id not in self.primary_pes]

        if not all_pe_sessions:
            return

        # 15–30 s interval — same as base ModerateNormalScenario
        t = start + random.uniform(15, 30)
        # Round-robin within each weighted subset (not random.choice) so no
        # single session within a subset can go many consecutive draws
        # without activity -- see the round-robin rationale in
        # ModerateNormalScenario._add_route_churn().
        primary_idx = other_idx = all_idx = 0
        while t < start + duration:
            if primary_sessions and random.random() < 0.75:
                bgp_sess, pe = primary_sessions[primary_idx % len(primary_sessions)]
                primary_idx += 1
                num = random.randint(6, 11)
            elif other_sessions:
                bgp_sess, pe = other_sessions[other_idx % len(other_sessions)]
                other_idx += 1
                num = random.randint(2, 4)
            else:
                bgp_sess, pe = all_pe_sessions[all_idx % len(all_pe_sessions)]
                all_idx += 1
                num = random.randint(5, 9)

            withdraw = random.random() >= 0.6
            num_routes = max(1, num // 2) if withdraw else num
            self._generate_churn_batch(packets, bgp_sess, pe, t, num_routes, withdraw,
                                       last_update_times)
            t += random.uniform(15, 30)



class AsymmetricBusyScenario(BusyNormalScenario):
    """Busy normal traffic where specified PEs dominate route advertisement."""

    def __init__(self, config: TopologyConfig, target_frames: int = 114000,
                 primary_pes: list = None):
        super().__init__(config, target_frames)
        self.primary_pes = primary_pes or []

    def _add_heavy_churn(self, packets: list, start: float, duration: float,
                         last_update_times: dict = None):
        sessions = self.topology.get_sessions_at_vantage()
        all_pe_sessions = [(s, s.local_router) for s in sessions if s.local_router.role == 'pe']
        primary_sessions = [(s, pe) for s, pe in all_pe_sessions if pe.id in self.primary_pes]
        other_sessions = [(s, pe) for s, pe in all_pe_sessions if pe.id not in self.primary_pes]

        if not all_pe_sessions:
            return

        # 4–7 s interval — same as base BusyNormalScenario
        t = start + random.uniform(4, 7)
        # Round-robin within each weighted subset (not random.choice) so no
        # single session within a subset can go many consecutive draws
        # without activity, plus a silence guard across all sessions --
        # see the rationale in BusyNormalScenario._add_heavy_churn().
        primary_idx = other_idx = all_idx = 0
        while t < start + duration:
            forced = None
            if last_update_times is not None:
                for cand_sess, cand_pe in all_pe_sessions:
                    times = last_update_times.get(cand_sess.session_id)
                    last_t = times[-1] if times else start
                    if t - last_t > SILENCE_GUARD_THRESHOLD:
                        forced = (cand_sess, cand_pe)
                        break

            if forced is not None:
                bgp_sess, pe = forced
                num = (random.randint(14, 28) if pe.id in self.primary_pes
                      else random.randint(2, 6))
            elif primary_sessions and random.random() < 0.8:
                bgp_sess, pe = primary_sessions[primary_idx % len(primary_sessions)]
                primary_idx += 1
                num = random.randint(14, 28)
            elif other_sessions:
                bgp_sess, pe = other_sessions[other_idx % len(other_sessions)]
                other_idx += 1
                num = random.randint(2, 6)
            else:
                bgp_sess, pe = all_pe_sessions[all_idx % len(all_pe_sessions)]
                all_idx += 1
                num = random.randint(8, 16)

            withdraw = random.random() >= 0.7
            num_routes = max(1, num // 2) if withdraw else num
            self._generate_churn_batch(packets, bgp_sess, pe, t, num_routes, withdraw,
                                       last_update_times)
            t += random.uniform(4, 7)



# Concrete subclasses for each PE combination

class QuietPE1PE3Scenario(AsymmetricQuietScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 116000):
        super().__init__(config, target_frames, primary_pes=['PE1', 'PE3'])

class QuietPE4PE5Scenario(AsymmetricQuietScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 116000):
        super().__init__(config, target_frames, primary_pes=['PE4', 'PE5'])

class ModeratePE2PE4Scenario(AsymmetricModerateScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 121000):
        super().__init__(config, target_frames, primary_pes=['PE2', 'PE4'])

class ModeratePE1PE5Scenario(AsymmetricModerateScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 121000):
        super().__init__(config, target_frames, primary_pes=['PE1', 'PE5'])

class BusyPE2PE3Scenario(AsymmetricBusyScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 114000):
        super().__init__(config, target_frames, primary_pes=['PE2', 'PE3'])

class BusyPE1PE4Scenario(AsymmetricBusyScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 114000):
        super().__init__(config, target_frames, primary_pes=['PE1', 'PE4'])


# ---------------------------------------------------------------------------
# Connection Collision — both peers of one PE-RR session initiate TCP
# simultaneously (common during session restarts). Collision resolution
# per RFC 4271 SS6.8 is NORMAL behaviour and must not be flagged as a fault.
# ---------------------------------------------------------------------------

class ConnectionCollisionScenario(BaseScenario):
    """One PE-RR session experiences a TCP connection collision at setup.

    Both peers initiate a TCP connection to each other at nearly the same
    time. Per RFC 4271 SS6.8, the peer with the *lower* BGP Router ID keeps
    its connection; the other connection is closed with a CEASE/Connection
    Collision Resolution NOTIFICATION. All other sessions establish
    normally. This is healthy, expected behaviour -- no fault window.
    """
    FAULT_TYPE: str = 'Normal'
    SECTION: int = 1

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 collision_pe: str = 'PE1', collision_rr: str = 'RR1'):
        super().__init__(config, target_frames)
        self.collision_pe_id = collision_pe
        self.collision_rr_id = collision_rr

    def _establish_with_collision(self, timestamp: float):
        """Establish all sessions; the collision_pe/collision_rr pair goes
        through a simultaneous-open collision before settling on the
        surviving connection.
        """
        packets = []
        t = timestamp
        vantage = self.config.capture_vantage
        sessions = self.topology.get_sessions_at_vantage(vantage)

        for bgp_session in sessions:
            pe = bgp_session.local_router
            rr = bgp_session.remote_router

            if pe.id == self.collision_pe_id and rr.id == self.collision_rr_id:
                coll_pkts, t = self._collision_pair(bgp_session, pe, rr, t)
                packets.extend(coll_pkts)
                t += 0.05
                continue

            # Normal establishment for every other session.
            tcp_sess = TCPSession(client_ip=pe.bgp_id, server_ip=rr.bgp_id, server_port=179)
            self.tcp_sessions[bgp_session.session_id] = tcp_sess

            pkts = tcp_sess.connect(timestamp=t)
            packets.extend(pkts)
            t += 0.01

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  pe.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = tcp_sess.send_data(open_msg, timestamp=t, direction='client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.005

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  rr.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = tcp_sess.send_data(open_msg, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
            t += 0.002

            ka = build_keepalive()
            pkts = tcp_sess.send_data(ka, timestamp=t, direction='client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.001

            pkts = tcp_sess.send_data(ka, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))

            t += 0.05

        return packets, t

    def _collision_pair(self, bgp_session, pe, rr, t: float):
        """Both PE and RR initiate a TCP connection to each other nearly
        simultaneously; the higher-RID peer's connection is closed with a
        CEASE/Connection Collision Resolution NOTIFICATION, and the
        lower-RID peer's connection survives and proceeds to Established.
        """
        packets = []

        # conn_pe: PE-initiated connection (PE is TCP client).
        conn_pe = TCPSession(client_ip=pe.bgp_id, server_ip=rr.bgp_id, server_port=179)
        pkts = conn_pe.connect(timestamp=t)
        packets.extend(pkts)

        # conn_rr: RR-initiated connection, simultaneous with conn_pe
        # (RR is TCP client on this second connection).
        conn_rr = TCPSession(client_ip=rr.bgp_id, server_ip=pe.bgp_id, server_port=179)
        pkts = conn_rr.connect(timestamp=t + 0.001)
        packets.extend(pkts)

        t += 0.02

        pe_rid = int(ipaddress.IPv4Address(pe.bgp_id))
        rr_rid = int(ipaddress.IPv4Address(rr.bgp_id))
        pe_is_higher = pe_rid > rr_rid

        # Both connections reach OPEN.
        open_pe = build_open(self.config.as_number, self.config.timing.hold_timer,
                             pe.bgp_id, default_evpn_capabilities(self.config.as_number))
        open_rr = build_open(self.config.as_number, self.config.timing.hold_timer,
                             rr.bgp_id, default_evpn_capabilities(self.config.as_number))

        packets.extend(conn_pe.send_data(open_pe, timestamp=t, direction='client_to_server'))
        t += ack_delay()
        packets.extend(conn_pe.generate_ack(t, 'server_to_client'))
        t += 0.005
        packets.extend(conn_pe.send_data(open_rr, timestamp=t, direction='server_to_client'))
        t += ack_delay()
        packets.extend(conn_pe.generate_ack(t, 'client_to_server'))
        t += 0.005

        packets.extend(conn_rr.send_data(open_rr, timestamp=t, direction='client_to_server'))
        t += ack_delay()
        packets.extend(conn_rr.generate_ack(t, 'server_to_client'))
        t += 0.005
        packets.extend(conn_rr.send_data(open_pe, timestamp=t, direction='server_to_client'))
        t += ack_delay()
        packets.extend(conn_rr.generate_ack(t, 'client_to_server'))
        t += 0.01

        # Collision resolution: the connection initiated by the
        # higher-Router-ID peer is closed with a NOTIFICATION.
        losing_conn = conn_pe if pe_is_higher else conn_rr
        surviving_conn = conn_rr if pe_is_higher else conn_pe
        # Direction from the peer that decides to close (the one that
        # *received* the duplicate OPEN on its passive/local role): use
        # server_to_client as the closing side sends the NOTIFICATION.
        notif = build_notification(ERR_CEASE, CEASE_CONNECTION_COLLISION)
        packets.extend(losing_conn.send_data(notif, timestamp=t, direction='server_to_client'))
        t += 0.002
        packets.extend(losing_conn.close_reset(timestamp=t, initiator='server'))
        t += 0.01

        # Surviving connection proceeds to Established via KEEPALIVE exchange.
        ka = build_keepalive()
        packets.extend(surviving_conn.send_data(ka, timestamp=t, direction='client_to_server'))
        t += ack_delay()
        packets.extend(surviving_conn.generate_ack(t, 'server_to_client'))
        t += 0.001
        packets.extend(surviving_conn.send_data(ka, timestamp=t, direction='server_to_client'))
        t += ack_delay()
        packets.extend(surviving_conn.generate_ack(t, 'client_to_server'))

        self.tcp_sessions[bgp_session.session_id] = surviving_conn
        return packets, t

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self._establish_with_collision(t)
        packets.extend(setup_pkts)

        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        last_update_times: dict = {}
        for sess_id in self.tcp_sessions:
            last_update_times[sess_id] = t

        remaining_duration = 600
        # Sparse keepalives with occasional updates, similar to QuietNormalScenario.
        remaining = self.target_frames - len(packets)
        if remaining > 0:
            dur = max(remaining_duration,
                      (remaining / max(len(self.tcp_sessions) * 4, 1))
                      * self.config.timing.keepalive_timer)
            packets.extend(self.generate_keepalives_for_duration(t, dur, last_update_times))
            t += dur

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class ConnectionCollisionPE1(ConnectionCollisionScenario):
    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        super().__init__(config, target_frames, collision_pe='PE1', collision_rr='RR1')
