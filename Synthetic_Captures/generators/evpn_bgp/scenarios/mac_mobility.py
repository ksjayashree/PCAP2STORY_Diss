"""Section 2 — MAC Mobility rapid-flap fault scenarios.

Real testbed clean-move deltas: 1.74-6.70s. Withdraw-to-advertise interval
for both classes here: 2.0s, inside that range.

Event ordering matters: the rule_based detector's mac_mobility.py scans
for a WITHDRAW, then looks forward in time for a later ADVERTISE from a
different node within its timing bound. Both classes below use
withdraw-then-advertise exclusively.
"""

import random

from .base import BaseScenario
from ..config import TopologyConfig
from ..tcp.session import TCPPacket
from ..bgp.messages import build_update
from ..bgp.attributes import (
    build_evpn_withdraw_attrs, attr_origin, attr_as_path, attr_local_pref,
    attr_originator_id, attr_cluster_list,
    attr_extended_communities, attr_mp_reach_nlri, encode_rt_community,
    encode_encapsulation_community, encode_mac_mobility_community,
)
from ..bgp.constants import AFI_L2VPN, SAFI_EVPN
from ..bgp import evpn
from generators.common.utils.timing import ack_delay


class MACMobilityRapidFlap(BaseScenario):
    """Single MAC Mobility rapid-flap event: one MAC moves from PE A to
    PE B via WITHDRAW (old owner) then ADVERTISE (new owner, incremented
    RFC 7432 SS15 sequence number), 2.0s apart -- inside the real testbed
    clean-move delta range of 1.74-6.70s.

    Event ordering (withdraw-then-advertise) matches what the rule_based
    detector's mac_mobility.py scans for, unlike MACMobilityNormalScenario
    (normal.py) which uses the reverse ordering.
    """
    FAULT_TYPE: str = 'MAC Mobility'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 pe_a: str = None, pe_b: str = None):
        super().__init__(config, target_frames)
        self.pe_a_id = pe_a or config.pe_nodes[0].id
        self.pe_b_id = pe_b or (config.pe_nodes[1].id if len(config.pe_nodes) > 1
                                else config.pe_nodes[0].id)

    def _session_for_pe(self, pe_id: str):
        """Return (bgp_session, tcp_session) for a PE id, or (None, None)."""
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == pe_id:
                tcp = self.tcp_sessions.get(bgp_sess.session_id)
                if tcp and tcp.is_established():
                    return bgp_sess, tcp
        return None, None

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
        # ORIGINATOR_ID/CLUSTER_LIST (RFC 4456): this advertisement is sent
        # server_to_client (RR->PE at the wire level, same convention as
        # the withdrawal above), so a consumer deriving node identity from
        # raw src IP would otherwise resolve the vantage RR, not the true
        # advertising PE.
        attrs += attr_originator_id(pe_router.bgp_id)
        attrs += attr_cluster_list([self.config.get_router(self.config.capture_vantage).bgp_id])
        return attrs

    def _flap(self, mac_entry, old_owner: dict, new_owner: dict, sequence: int,
              timestamp: float, event: bool = False, phase: str = None) -> tuple[list[TCPPacket], float]:
        """WITHDRAW the old owner's MAC/IP advertisement, then (2.0s later)
        ADVERTISE from the new owner with an incremented MAC Mobility
        sequence number. Returns (packets, next_t).
        """
        packets = []
        t = timestamp

        # WITHDRAW old owner first -- detector-expected ordering.
        nlri = evpn.build_mac_ip_route(
            old_owner['pe'].bgp_id, old_owner['pe'].esi or "0",
            mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
        path_attrs = build_evpn_withdraw_attrs(
            nlri, originator_id=old_owner['pe'].bgp_id,
            cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
        update = build_update(path_attributes=path_attrs)
        wd_pkts = old_owner['tcp'].send_data(update, t, 'server_to_client')
        packets.extend(wd_pkts)
        packets.extend(old_owner['tcp'].generate_ack(t + ack_delay(), 'client_to_server'))

        # Withdraw-to-advertise gap: 2.0s, inside the real testbed
        # clean-move delta range of 1.74-6.70s.
        t += 2.0

        # ADVERTISE new owner with incremented sequence.
        nlri = evpn.build_mac_ip_route(
            new_owner['pe'].bgp_id, new_owner['pe'].esi or "0",
            mac_entry.mac, ip=mac_entry.ip, vni=self.config.evpn.vni)
        path_attrs = self._build_attrs_with_mobility(new_owner['pe'], nlri, sequence)
        update = build_update(path_attributes=path_attrs)
        adv_pkts = new_owner['tcp'].send_data(update, t, 'server_to_client')
        packets.extend(adv_pkts)
        packets.extend(new_owner['tcp'].generate_ack(t + ack_delay(), 'client_to_server'))

        if event:
            self._mark_event(packets, self.FAULT_TYPE, old_owner['pe'].id, 'Route UPDATE', phase=phase)

        t += 0.1
        return packets, t

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        warmup_duration = self._param_rng.randint(120, 480)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration))
        t += warmup_duration

        bgp_a, tcp_a = self._session_for_pe(self.pe_a_id)
        bgp_b, tcp_b = self._session_for_pe(self.pe_b_id)

        fault_start_t = t
        if bgp_a and bgp_b and tcp_a and tcp_b:
            pe_a = bgp_a.local_router
            pe_b = bgp_b.local_router
            mac_entry = self.topology.get_macs_for_pe(pe_a.id)[-1]
            # Last entry, not the first: generate_initial_routes(),
            # generate_route_updates(), and generate_route_churn() all draw
            # only macs[:N] with N never exceeding ~25 of the 50-entry
            # pool, so the last entry is never touched by background/
            # warmup traffic -- avoids the detector's isolation check
            # rejecting the flap because the destination PE already had a
            # pre-existing advertisement for this MAC.

            old_owner = {'pe': pe_a, 'tcp': tcp_a}
            new_owner = {'pe': pe_b, 'tcp': tcp_b}

            flap_pkts, t = self._flap(mac_entry, old_owner, new_owner, sequence=1,
                                      timestamp=t, event=True, phase='trigger')
            packets.extend(flap_pkts)

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        # Post-flap keepalives to fill target_frames.
        remaining = self.target_frames - len(packets)
        if remaining > 0:
            dur = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1))
                      * self.config.timing.keepalive_timer)
            packets.extend(self.generate_keepalives_for_duration(t, dur))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class MACMobilityRapidFlapPE1toPE2(MACMobilityRapidFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE1', pe_b='PE2')

class MACMobilityRapidFlapPE2toPE1(MACMobilityRapidFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE2', pe_b='PE1')


# PE4/PE5 variants: the PE1/PE2 default above is the 5PE/2RR topology's
# only ESI-multihomed pair, which makes mac_mobility.py's own ESI-partner
# fan-out exclusion block detection of every PE1/PE2 rapid-flap file.
# PE4/PE5 are both standalone (no ESI) and both home to RR2, avoiding
# both the ESI-partner exclusion and the cross-RR reflection gap (see
# MACMobilityX2's pair2 comment below).
class MACMobilityRapidFlapPE4toPE5(MACMobilityRapidFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE4', pe_b='PE5')

class MACMobilityRapidFlapPE5toPE4(MACMobilityRapidFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE5', pe_b='PE4')


class MACMobilityRepeatedFlap(MACMobilityRapidFlap):
    """MAC Mobility flap storm: the same MAC moves back and forth between
    PE A and PE B 3-6 times within a single capture (move-count convention
    matches MACMobilityNormalScenario's existing 3-6-move range), each
    flap using the same 2.0s withdraw-then-advertise gap as
    MACMobilityRapidFlap. The MAC Mobility sequence number increments
    monotonically across the whole capture (1, 2, 3, ...), never resetting
    per flap, per RFC 7432 SS15's sequence-number semantics (a receiver
    must be able to tell which advertisement is most recent across the
    entire history of moves for that MAC, not just within one flap).

    Spacing between successive flap start times: 10-20s, mirroring
    ESDFRapidToggle's "rapid" convention (esdf_toggle.py: 3-4 toggle
    cycles spread across 60s). Comfortably clear of the ~2.1s a single
    flap itself takes (withdraw + 2.0s gap + advertise), so successive
    flaps never overlap, while remaining clearly distinct from
    MACMobilityNormalScenario's 60-180s between-move spacing.
    """

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        warmup_duration = self._param_rng.randint(120, 480)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration))
        t += warmup_duration

        bgp_a, tcp_a = self._session_for_pe(self.pe_a_id)
        bgp_b, tcp_b = self._session_for_pe(self.pe_b_id)

        fault_start_t = t
        last_fault_end = None
        if bgp_a and bgp_b and tcp_a and tcp_b:
            pe_a = bgp_a.local_router
            pe_b = bgp_b.local_router
            mac_entry = self.topology.get_macs_for_pe(pe_a.id)[-1]
            # Last entry, not the first: generate_initial_routes(),
            # generate_route_updates(), and generate_route_churn() all draw
            # only macs[:N] with N never exceeding ~25 of the 50-entry
            # pool, so the last entry is never touched by background/
            # warmup traffic -- avoids the detector's isolation check
            # rejecting the flap because the destination PE already had a
            # pre-existing advertisement for this MAC.

            # MAC currently lives on pe_a; each flap flips ownership.
            owner_session = {'pe': pe_a, 'tcp': tcp_a}
            other_session = {'pe': pe_b, 'tcp': tcp_b}
            sequence = 0

            num_flaps = self._param_rng.randint(3, 6)
            for i in range(num_flaps):
                sequence += 1
                new_owner = other_session
                old_owner = owner_session

                # Every flap is marked 'trigger', not an alternating
                # trigger/recovery pair: unlike ESDF/RT-Misconfig recovery
                # variants, a flap storm has no "back to baseline" moment
                # mid-capture -- each flap is an independent anomalous move
                # event, not one fault followed by its own recovery.
                flap_pkts, t = self._flap(mac_entry, old_owner, new_owner, sequence,
                                          timestamp=t, event=True, phase='trigger')
                packets.extend(flap_pkts)

                owner_session, other_session = new_owner, old_owner
                last_fault_end = t + self.BASELINE_CHECK_WINDOW

                if i < num_flaps - 1:
                    # Spacing between successive flap starts -- see class
                    # docstring for why 10-20s.
                    t += random.uniform(10, 20)

        self._fault_start_t = fault_start_t
        self._fault_end_t = last_fault_end

        # Post-flap keepalives to fill target_frames.
        remaining = self.target_frames - len(packets)
        if remaining > 0:
            dur = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1))
                      * self.config.timing.keepalive_timer)
            packets.extend(self.generate_keepalives_for_duration(t, dur))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]


class MACMobilityRepeatedFlapPE1toPE2(MACMobilityRepeatedFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE1', pe_b='PE2')

class MACMobilityRepeatedFlapPE2toPE1(MACMobilityRepeatedFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE2', pe_b='PE1')


# PE4/PE5 variants -- see MACMobilityRapidFlapPE4toPE5's comment above for
# the full justification (same reasoning, same pair, same reason repeated
# flap needs its own non-ESI/non-cross-RR pair).
class MACMobilityRepeatedFlapPE4toPE5(MACMobilityRepeatedFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE4', pe_b='PE5')

class MACMobilityRepeatedFlapPE5toPE4(MACMobilityRepeatedFlap):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, pe_a='PE5', pe_b='PE4')


class MACMobilityX2(MACMobilityRapidFlap):
    """Category B multi-incident: two INDEPENDENT MAC moves, on two
    DIFFERENT PE pairs (not the same MAC repeatedly flapping, which is what
    MACMobilityRepeatedFlap already models -- one continuous monotonic
    sequence-number history, a single incident). Each move here is its own
    distinct MAC, its own PE pair, its own sequence number starting at 1,
    separated by CATEGORY_B_GAP_SECONDS (see esdf_toggle.py's definition/
    justification -- 120s, 60x the detector's 2.0s precedence/establishment
    windows).
    """

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 pair1: tuple[str, str] = ('PE1', 'PE3'),
                 pair2: tuple[str, str] = ('PE2', 'PE3')):
        # PE1/PE2 share an ESI (the only multihomed pair in the 5PE/2RR
        # topology), and _is_isolated_move()'s destination search
        # excludes the origin's own ESI partner from candidate
        # destinations, so (PE1,PE3) and (PE2,PE3) avoid the ESI-partner
        # exclusion entirely (PE3 has no ESI) while staying within RR1's
        # direct clients.
        #
        # mac_mobility.py has no cross-RR reflection support, so a
        # cross-RR pair silently produces zero incident content at either
        # vantage. (PE2, PE3) keeps both pair1 and pair2 within RR1's
        # direct clients, so both incidents are genuinely visible at the
        # RR1 vantage.
        super().__init__(config, target_frames, pe_a=pair1[0], pe_b=pair1[1])
        self.pair2_a_id, self.pair2_b_id = pair2
        self.incidents: list[dict] = []

    def _one_move(self, packets, pe_a_id, pe_b_id, t):
        from datetime import datetime, timezone
        bgp_a, tcp_a = self._session_for_pe(pe_a_id)
        bgp_b, tcp_b = self._session_for_pe(pe_b_id)
        if not (bgp_a and bgp_b and tcp_a and tcp_b):
            return t
        pe_a = bgp_a.local_router
        pe_b = bgp_b.local_router
        mac_entry = self.topology.get_macs_for_pe(pe_a.id)[-1]
        old_owner = {'pe': pe_a, 'tcp': tcp_a}
        new_owner = {'pe': pe_b, 'tcp': tcp_b}

        fault_start_t = t
        flap_pkts, t = self._flap(mac_entry, old_owner, new_owner, sequence=1,
                                  timestamp=t, event=True, phase='trigger')
        packets.extend(flap_pkts)
        fault_end_t = t

        self.incidents.append({
            "event_affected_node": pe_a.id,
            "fault_type": self.FAULT_TYPE,
            "trigger_mechanism": "Clean Move (rapidflap)",
            "origin_pe": pe_a.id,
            "destination_pe": pe_b.id,
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

        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        warmup_duration = self._param_rng.randint(120, 300)
        packets.extend(self.generate_keepalives_for_duration(t, warmup_duration))
        t += warmup_duration

        # INCIDENT 1: pair1's move
        t = self._one_move(packets, self.pe_a_id, self.pe_b_id, t)

        # Independent gap (CATEGORY_B_GAP_SECONDS -- see esdf_toggle.py)
        packets.extend(self.generate_keepalives_for_duration(t, 120.0))
        t += 120.0

        # INCIDENT 2: pair2's move (different PEs, different MAC)
        t = self._one_move(packets, self.pair2_a_id, self.pair2_b_id, t)

        remaining = self.target_frames - len(packets)
        if remaining > 0:
            dur = max(120, (remaining / max(len(self.tcp_sessions) * 4, 1))
                      * self.config.timing.keepalive_timer)
            packets.extend(self.generate_keepalives_for_duration(t, dur))

        packets.sort(key=lambda p: p.timestamp)
        return packets[:self.target_frames]
