"""Base class for all scenario generators."""

import bisect
import json
import random
import warnings
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

# Window that per-scenario start times are drawn from: one arbitrary single
# calendar day (2024-03-11, an unremarkable Monday), varying only time-of-day
# — mirrors how a real capture is pulled from one monitoring session, not
# spread across years, while still giving every scenario file a distinct,
# realistic wall-clock start instead of a single dataset-wide constant.
START_TIME_RANGE: tuple[float, float] = (
    datetime(2024, 3, 11, 0, 0, 0, tzinfo=timezone.utc).timestamp(),
    datetime(2024, 3, 11, 23, 59, 59, tzinfo=timezone.utc).timestamp(),
)

# Sentinel: generate() never stored fault timing (excluded or forgot).
# Distinct from None, which means "no-recovery — window stays open".
_FAULT_WINDOW_UNSET = object()

# Probability that a given route-churn batch is immediately followed by a
# ROUTE-REFRESH on the same session, a short delay after the batch's last
# packet. Real BGP ROUTE-REFRESH (RFC 2918) is triggered by an inbound
# policy/filter change or capability renegotiation on a specific session --
# concepts this generator does not model anywhere. Attaching a low-probability
# refresh to route-churn activity is a proxy for that causal trigger (churn
# is the closest session-scoped event available), not a literal simulation
# of a policy change.
ROUTE_REFRESH_ATTACH_PROB = 0.015  # 1.5%

# Maximum time a single session may go without a churn event before it's
# force-churned out of round-robin order (when silence_guard=True). Round-
# robin alone bounds the gap between churn *events* on a session, but when
# the round-robin cycle length lands close to the keepalive interval (10s),
# scheduled keepalives can keep landing inside the "recently updated"
# suppression window across several consecutive cycles by chance, producing
# a much longer KEEPALIVE-silence run than the event-to-event bound
# suggests. 20s gives a 10s margin below the 30s RR-down hold-timer
# threshold and the low end of the 32-40s link-down threshold range.
SILENCE_GUARD_THRESHOLD = 20.0  # seconds
from ..config import TopologyConfig, load_config, RouterConfig
from ..topology import NetworkTopology, BGPSession
from ..tcp.session import TCPSession, TCPPacket
from generators.common.writers.pcap_writer import PcapWriter, write_pcap
from generators.common.writers.csv_writer import write_csv
from ..bgp.messages import build_open, build_keepalive, build_update, build_route_refresh
from ..bgp.capabilities import default_evpn_capabilities
from ..bgp.attributes import (
    build_standard_evpn_path_attrs, build_evpn_withdraw_attrs, attr_mp_unreach_nlri,
    attr_origin, attr_as_path, attr_local_pref, attr_extended_communities,
    attr_mp_reach_nlri, encode_rt_community, encode_encapsulation_community,
    attr_originator_id, attr_cluster_list, encode_df_election_community,
)
from ..bgp import evpn
from ..bgp.constants import AFI_L2VPN, SAFI_EVPN, TUNNEL_TYPE_VXLAN
from generators.common.utils.timing import (
    jittered_interval, keepalive_timestamps, ack_delay,
    route_burst_timestamps, route_advertisement_delay
)


class BaseScenario(ABC):
    """Base class for pcap generation scenarios."""

    # Warmup duration range (seconds of normal traffic before fault injection).
    # Randomised per-generate() call — stored as (min, max) for metadata documentation.
    # Subclasses override this when they use a different range.
    WARMUP_SECONDS: tuple = (120, 480)  # 2–8 min default

    FAULT_TYPE: str = 'Normal'
    SECTION: int = 1

    # Seconds of stable post-recovery traffic required before the fault window
    # closes.  fault_end_t = last_recovery_packet_t + BASELINE_CHECK_WINDOW.
    # For no-recovery scenarios fault_end stays None, so this value is unused.
    BASELINE_CHECK_WINDOW: int = 30

    def __init__(self, config: TopologyConfig, target_frames: int = 8000):
        self.config = config
        self.topology = NetworkTopology(config)
        self.target_frames = target_frames
        self.packets: list[TCPPacket] = []
        self.tcp_sessions: dict[str, TCPSession] = {}  # session_id → TCPSession
        # Set in write(), from a locally-seeded RNG that never touches the
        # shared `random` sequence — see write() for why.
        self.start_time: float | None = None
        # Set alongside start_time in write() — a second, distinctly-keyed
        # local RNG for vantage-independent scenario parameters. See
        # write()'s docstring for why this needs to be separate from both
        # the shared `random` sequence and the start_time RNG.
        self._param_rng: random.Random | None = None
        # Set by generate() in each scenario.  None = no-recovery (open-ended window).
        # _FAULT_WINDOW_UNSET = generate() never stored timing (excluded scenario).
        self._fault_start_t = _FAULT_WINDOW_UNSET
        self._fault_end_t   = _FAULT_WINDOW_UNSET

    @abstractmethod
    def generate(self) -> list[TCPPacket]:
        """Generate all packets for this scenario."""
        ...

    def write(self, output_path: str | Path, vantage_ip: str = None,
              section: int = None, seed: int = 42, copy_idx: int = 1,
              write_csv_sidecar: bool = True) -> int:
        """Generate and write packets to pcap file, then write companion CSV and
        a .json fault-window file consumed by scripts/generate_json.py.

        write_csv_sidecar: the .csv is write-only, nothing reads it back in.
        Default True preserves existing behavior for callers that still want
        it (e.g. direct cli.py runs); scripts/generate_dual_vantage.py's
        multi-vantage pipeline passes False, since that convention's
        deliverable is pcap+metadata.json only.

        Pass section= to override the class-level SECTION (e.g. section=3 for
        section3_mixed outputs so the CSV column reflects the correct section).

        seed/copy_idx: same (global_seed, copy_idx) the caller used to seed the
        shared `random` sequence for this scenario (see cli.py's _scenario_seed).
        Used only to key two *local* RNGs, self.start_time's above and
        self._param_rng below — neither reseeds or draws from `random`
        itself, so both stay independent of vantage config, scenario class
        internals, or any other random call ordering.

        self._param_rng (distinct key suffix ":params", so it never collides
        with the start_time RNG's own draws) is for scenario-level scalar
        parameters that are meant to be identical regardless of capture
        vantage (warmup_duration, silence/toggle durations, etc.) but were
        previously drawn from the shared `random` sequence -- which made
        their values depend on how many vantage-session-count-scoped draws
        establish_all_sessions()/generate_initial_routes()/route-churn had
        already consumed by that point, differing between an RR1 run (4
        vantage sessions) and an RR2 run (3), corrupting fault_start_t
        deltas with RNG drift on top of genuine reflection delay. generate()
        methods in link_down.py/rr_down.py/esdf_toggle.py/rt_misconfig.py
        draw those specific parameters from self._param_rng instead.
        """
        if self.start_time is None:
            cls_path = f"{type(self).__module__}.{type(self).__name__}"
            local_rng = random.Random(f"{seed}:{cls_path}:{copy_idx}")
            self.start_time = local_rng.uniform(*START_TIME_RANGE)
            self._param_rng = random.Random(f"{seed}:{cls_path}:{copy_idx}:params")
        if not self.packets:
            self.packets = self.generate()
        self.packets.sort(key=lambda p: p.timestamp)
        vip = vantage_ip or self.config.get_router(self.config.capture_vantage).bgp_id
        n = write_pcap(self.packets, output_path, vantage_ip=vip)
        if write_csv_sidecar:
            csv_path = Path(output_path).with_suffix('.csv')
            write_csv(self.packets, csv_path,
                      pcap_file=Path(output_path).name,
                      fault_type=self.FAULT_TYPE,
                      section=section if section is not None else self.SECTION,
                      config=self.config)

        # Real PE/ESI identity the generator actually targeted, for
        # generate_json.py's merge step to cross-check against its own
        # static CATALOGUE guess. Read generically via getattr, since the
        # attribute names are not uniform across scenario classes:
        #   - ESDFFullFailure family (mixed.py):            pe1_id, pe2_id, esi
        #   - ESDFSingleToggle/Type1EVIToggle families
        #     (esdf_toggle.py, incl. their AC-state/no-recovery/
        #     slow/midchurn/repeated subclasses):            affected_pe_id, esi
        #   - RTMisconfigESImportScenario family
        #     (rt_misconfig.py):                              affected_pe_id only
        #     (esi is not stored on these instances)
        #   - MACMobilityRapidFlap/RepeatedFlap family
        #     (mac_mobility.py):                              pe_a_id, pe_b_id
        #     (no esi attribute at all -- MAC mobility isn't ESI-based)
        # All read defensively with getattr(..., None); whichever are
        # actually set on a given instance are the ones written out, no
        # per-class special-casing.
        generator_identity = {}
        pe1 = getattr(self, "pe1_id", None) or getattr(self, "pe_a_id", None)
        pe2 = getattr(self, "pe2_id", None) or getattr(self, "pe_b_id", None)
        affected_pe = getattr(self, "affected_pe_id", None)
        esi = getattr(self, "esi", None)
        if pe1 or pe2:
            generator_identity["pe_pair"] = [p for p in (pe1, pe2) if p]
        if affected_pe:
            generator_identity["affected_pe_id"] = affected_pe
        if esi:
            generator_identity["esi"] = esi

        # Write fault-window sidecar so JSON uses runtime values, not a hardcoded constant.
        if self._fault_start_t is not _FAULT_WINDOW_UNSET:
            fault_start_utc = datetime.fromtimestamp(self._fault_start_t, tz=timezone.utc).isoformat()
            if self._fault_end_t is _FAULT_WINDOW_UNSET:
                warnings.warn(
                    f"{type(self).__name__}: _fault_start_t was set but "
                    f"_fault_end_t was never set — check generate()",
                    stacklevel=2,
                )
                fault_end_utc = None
            else:
                fault_end_utc = (datetime.fromtimestamp(self._fault_end_t, tz=timezone.utc).isoformat()
                                  if self._fault_end_t is not None else None)
            fw_path = Path(output_path).with_suffix('.json')
            with open(fw_path, 'w') as fw:
                json.dump({"fault_window": {"fault_start_datetime_utc": fault_start_utc,
                                             "fault_end_datetime_utc": fault_end_utc},
                           **({"generator_identity": generator_identity} if generator_identity else {})}, fw)
        else:
            warnings.warn(
                f"{type(self).__name__}: generate() did not set _fault_start_t — "
                f"fault_window in JSON will use the static catalogue fallback. "
                f"Expected for Normal-traffic scenarios (generators.evpn_bgp.scenarios.normal), "
                f"which inject no fault by design. For any other scenario, this likely means "
                f"generate() is missing a fault-window assignment and should be investigated.",
                stacklevel=2,
            )
            # Even with no fault_window, still record generator_identity if
            # any PE/ESI attribute was set -- a scenario could in principle
            # have real PE identity without a fault-window (not observed in
            # any active class today, but this must not silently drop the
            # signal if one exists).
            if generator_identity:
                fw_path = Path(output_path).with_suffix('.json')
                with open(fw_path, 'w') as fw:
                    json.dump({"generator_identity": generator_identity}, fw)

        return n

    def _mark_event(self, pkts: list, fault_type: str, node: str, trigger: str,
                    phase: str = None) -> list:
        """Mark packets as direct fault-injection events (event_label=1). Returns pkts.

        phase: 'trigger' | 'propagation' | 'recovery' -- which phase of the
        fault lifecycle this event belongs to. 'propagation' is reserved for
        a genuine third phase distinct from trigger/recovery fan-out; no
        current call site uses it, since reflection/fan-out helpers fire
        during both trigger and recovery flows and are tagged with whichever
        phase their caller is in.
        """
        for p in pkts:
            p.event_label = True
            p.event_fault_type = fault_type
            p.event_affected_node = node
            p.event_trigger_mechanism = trigger
            p.event_phase = phase
        return pkts

    def establish_all_sessions(self, timestamp: float,
                               notification_tolerant_session_id: str = None
                               ) -> tuple[list[TCPPacket], float]:
        """Establish all BGP sessions visible from vantage.

        notification_tolerant_session_id: if given, that one session's
        original OPEN exchange (both directions) advertises the RFC 8538 N
        bit. Per RFC 8538 SS3, graceful-restart-on-notification MUST have
        been negotiated on the session that later experiences the
        notification-triggered restart -- negotiating it only on the
        reconnect OPEN (after the fault) is too late. Every other session
        is unaffected.

        Returns (packets, end_timestamp) after all sessions are up
        with OPEN exchange and initial keepalives.
        """
        packets = []
        t = timestamp
        vantage = self.config.capture_vantage
        sessions = self.topology.get_sessions_at_vantage(vantage)

        for bgp_session in sessions:
            # Create TCP session (PE is client, RR is server)
            pe = bgp_session.local_router
            rr = bgp_session.remote_router
            notif_tolerant = bgp_session.session_id == notification_tolerant_session_id

            tcp_sess = TCPSession(
                client_ip=pe.bgp_id,
                server_ip=rr.bgp_id,
                server_port=179,
            )
            self.tcp_sessions[bgp_session.session_id] = tcp_sess

            # TCP handshake
            pkts = tcp_sess.connect(timestamp=t)
            packets.extend(pkts)
            t += 0.01

            # BGP OPEN from client (PE)
            open_msg = build_open(
                self.config.as_number,
                self.config.timing.hold_timer,
                pe.bgp_id,
                default_evpn_capabilities(self.config.as_number,
                                          is_notification_tolerant=notif_tolerant)
            )
            pkts = tcp_sess.send_data(open_msg, timestamp=t, direction='client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.005

            # BGP OPEN from server (RR)
            open_msg = build_open(
                self.config.as_number,
                self.config.timing.hold_timer,
                rr.bgp_id,
                default_evpn_capabilities(self.config.as_number,
                                          is_notification_tolerant=notif_tolerant)
            )
            pkts = tcp_sess.send_data(open_msg, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
            t += 0.002

            # KEEPALIVE from both sides (confirms OPEN)
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

            t += 0.05  # Small gap before next session

        return packets, t

    def generate_keepalives_for_duration(self, start_time: float, duration: float,
                                          last_update_times: dict = None) -> list[TCPPacket]:
        """Generate keepalive exchanges across all sessions for a time period.

        last_update_times: optional dict mapping session_id -> the UPDATE
        timestamps sent on that session, either a single float (one update,
        or a pre-collapsed scalar from an older caller) or a list/tuple of
        floats in chronological order (multiple updates over the capture).
        RFC 4271 SS4.4 only mandates that a KEEPALIVE MUST NOT be sent more
        than once per second and permits scaling frequency down from the
        hold-time interval -- it does not literally forbid a redundant
        KEEPALIVE shortly after an UPDATE. Suppressing that redundant
        KEEPALIVE here is a realistic implementation choice consistent with
        hold-timer semantics (an UPDATE already resets the peer's hold
        timer, so an immediately-following KEEPALIVE is unnecessary
        chatter), not something the RFC text requires. A would-be keepalive
        at time t is suppressed if t falls within one interval of the
        *nearest update at or before t* on that session -- not the
        session's single latest update across the whole capture, which
        would incorrectly suppress every earlier keepalive once any later
        update exists. Defaults to None (no suppression) for backward
        compatibility.
        """
        packets = []
        ka_msg = build_keepalive()
        interval = self.config.timing.keepalive_timer
        last_update_times = last_update_times or {}

        def _is_suppressed(update_times, t: float) -> bool:
            if not update_times:
                return False
            if isinstance(update_times, (int, float)):
                return t - update_times < interval
            # update_times is a chronological list; find the nearest entry
            # at or before t via binary search (bisect_right - 1).
            idx = bisect.bisect_right(update_times, t) - 1
            if idx < 0:
                return False
            return t - update_times[idx] < interval

        for session_id, tcp_sess in self.tcp_sessions.items():
            if not tcp_sess.is_established():
                continue
            update_times = last_update_times.get(session_id)
            # Generate keepalives from both sides with jitter
            for t in keepalive_timestamps(start_time, duration, interval):
                # Client sends keepalive
                if not _is_suppressed(update_times, t):
                    pkts = tcp_sess.send_data(ka_msg, timestamp=t, direction='client_to_server')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'server_to_client'))

                # Server sends keepalive (slightly offset)
                t_server = t + jittered_interval(interval / 3, 0.3)
                if t_server < start_time + duration and not _is_suppressed(update_times, t_server):
                    pkts = tcp_sess.send_data(ka_msg, timestamp=t_server, direction='server_to_client')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t_server + ack_delay(), 'client_to_server'))

        return packets

    def generate_tcp_window_updates(self, start_time: float, duration: float,
                                     num_frames: int) -> list[TCPPacket]:
        """Generate pure TCP window-update frames (no BGP payload) to pad to target_frames.

        In real network captures the majority of frames are TCP ACKs and window
        probes between BGP messages — typically ~87% for normal BGP sessions.
        This method generates those TCP-only frames so the overall frame mix
        matches real captures rather than being 50/50 BGP/TCP.

        Frames are distributed uniformly across the capture duration with small
        jitter so they interleave naturally with BGP messages after sorting.
        """
        if num_frames <= 0 or duration <= 0:
            return []
        sessions = [(sid, sess) for sid, sess in self.tcp_sessions.items()
                    if sess.is_established()]
        if not sessions:
            return []

        packets = []
        interval = duration / num_frames
        t_prev = start_time
        for i in range(num_frames):
            t = start_time + i * interval + random.uniform(-interval * 0.05, interval * 0.05)
            t = max(start_time, min(start_time + duration - 0.001, t))
            if t <= t_prev:
                t = t_prev + 0.000002
            t_prev = t
            _, tcp_sess = sessions[i % len(sessions)]
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
        return packets

    def generate_initial_routes(self, timestamp: float) -> tuple[list[TCPPacket], float]:
        """Generate the initial EVPN route table after session establishment.

        In a real network, after BGP sessions are established each PE advertises:
        1. Type 3 (IMET) — one per VNI, declares BUM replication interest
        2. Type 1 (EAD) + Type 4 (ES) — for multi-homed PEs
        3. Type 2 (MAC/IP) — already-learned MACs
        4. Type 5 (IP Prefix) — inter-subnet routes (some PEs)

        Two-pass structure ensures every PE's IMET arrives before any Type 2
        that references its next-hop — this prevents false EVPN-003 findings
        when multi-homed peers advertise duplicate MACs.

        Returns (packets, end_timestamp).
        """
        import random
        packets = []
        t = timestamp

        # Collect PE sessions for both passes
        pe_sessions = []
        for bgp_session in self.topology.get_sessions_at_vantage():
            pe = bgp_session.local_router
            if pe.role != 'pe':
                continue
            tcp_sess = self.tcp_sessions.get(bgp_session.session_id)
            if not tcp_sess or not tcp_sess.is_established():
                continue
            pe_sessions.append((bgp_session, pe, tcp_sess))

        # --- Pass 1: IMET + EAD/ES routes (establishes BUM tree) ---
        for bgp_session, pe, tcp_sess in pe_sessions:
            # Type 3: IMET route (every PE sends this for each VNI)
            nlri = evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni)
            path_attrs = build_standard_evpn_path_attrs(
                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=pe.bgp_id, cluster_id=bgp_session.remote_router.bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += 0.005
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
            t += 0.003

            # Type 1 + Type 4: EAD and ES routes for multi-homed PEs
            if pe.esi and pe.esi != "0":
                # Per-ES EAD (Ethernet Tag = 0xFFFFFFFF)
                nlri = evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni)
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id, cluster_id=bgp_session.remote_router.bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
                packets.extend(pkts)
                t += 0.005
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.003

                # Per-EVI EAD
                nlri = evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                              vni=self.config.evpn.vni)
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id, cluster_id=bgp_session.remote_router.bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
                packets.extend(pkts)
                t += 0.005
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.003

                # Type 4: Ethernet Segment route (for DF election)
                nlri = evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                           self.config.evpn.vni)
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id, cluster_id=bgp_session.remote_router.bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
                packets.extend(pkts)
                t += 0.005
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.003

            t += 0.02  # Small gap between PEs

        # --- Pass 2: Type 2 MAC/IP + Type 5 prefix routes ---
        for bgp_session, pe, tcp_sess in pe_sessions:
            # Type 2: Some initial MAC/IP routes (already learned)
            num_initial_macs = random.randint(15, 25)
            route_pkts = self._generate_type2_updates(
                bgp_session.session_id, pe, num_initial_macs, t)
            packets.extend(route_pkts)
            t += num_initial_macs * 0.008

            # For multi-homed PEs: also advertise these MACs from the ESI peer
            if pe.esi and pe.esi != "0":
                esi_peers = self.topology.get_multihomed_esi_peers(pe.id)
                for peer_pe in esi_peers:
                    peer_session = self._find_session_for_pe(peer_pe.id)
                    if peer_session:
                        macs = self.topology.get_macs_for_pe(pe.id, count=num_initial_macs)
                        peer_pkts = self._generate_type2_for_peer(
                            peer_session, peer_pe, macs, pe.esi, t)
                        packets.extend(peer_pkts)
                        t += num_initial_macs * 0.008

            # Type 5: IP prefix routes (some PEs have inter-subnet routes)
            if random.random() < 0.6:
                pe_idx = int(pe.bgp_id.split('.')[-1])
                num_prefixes = random.randint(2, 5)
                for i in range(num_prefixes):
                    prefix = f"10.{pe_idx}.{i}.0"
                    nlri = evpn.build_ip_prefix_route(
                        pe.bgp_id, prefix, 24, pe.bgp_id, self.config.evpn.vni)
                    path_attrs = build_standard_evpn_path_attrs(
                        pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                        originator_id=pe.bgp_id, cluster_id=bgp_session.remote_router.bgp_id)
                    update = build_update(path_attributes=path_attrs)
                    pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
                    packets.extend(pkts)
                    t += 0.005
                    packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                    t += 0.003

            t += 0.05  # Gap before next PE's routes

        # --- RR-RR reflection: peer RR's own clients' routes crossing over
        # to the vantage RR at cold start (RFC 4456). Only the direction that
        # adds new visibility at the vantage is modeled: the peer RR's
        # clients are otherwise invisible here, whereas the vantage RR's own
        # clients are already fully covered by Pass 1/2 above via their
        # direct PE sessions, so reflecting them back out over the RR-RR
        # session would be pure duplication with no new information.
        vantage = self.config.capture_vantage
        for bgp_session in self.topology.get_sessions_at_vantage():
            if bgp_session.local_router.role != 'rr' or bgp_session.remote_router.role != 'rr':
                continue
            rr_tcp_sess = self.tcp_sessions.get(bgp_session.session_id)
            if not rr_tcp_sess or not rr_tcp_sess.is_established():
                continue
            peer_rr = (bgp_session.remote_router if bgp_session.local_router.id == vantage
                      else bgp_session.local_router)
            peer_pes = [pe for pe in self.config.pe_nodes if pe.peers and pe.peers[0] == peer_rr.id]
            if peer_pes:
                rr_pkts, t = self.reflect_pe_routes_to_rr(
                    rr_tcp_sess, t, event=False, pe_list=peer_pes)
                packets.extend(rr_pkts)

        # End-of-RIB markers: every real BGP speaker signals "initial RIB
        # fully sent" once its startup route advertisement completes
        # (RFC 4724 SS2). Both peers on each established session emit one.
        eor_pkts, t = self._generate_eor_markers(t)
        packets.extend(eor_pkts)

        return packets, t

    def _generate_eor_markers(self, timestamp: float) -> tuple[list[TCPPacket], float]:
        """Generate End-of-RIB markers for every established session.

        For EVPN (AFI=25/SAFI=70), End-of-RIB is a BGP UPDATE carrying an
        empty MP_UNREACH_NLRI for that AFI/SAFI and nothing else. Both the
        PE (client) and the RR (server) send one, 5ms apart, once the
        initial route advertisement for that session is complete.
        """
        packets = []
        t = timestamp

        for session_id, tcp_sess in self.tcp_sessions.items():
            if not tcp_sess.is_established():
                continue
            pkts, t = self._generate_eor_for_session(tcp_sess, t)
            packets.extend(pkts)

        return packets, t

    def _generate_eor_for_session(self, tcp_sess: TCPSession, t: float,
                                  event: bool = False, fault_type: str = None,
                                  node: str = None, phase: str = None) -> tuple[list[TCPPacket], float]:
        """Generate an End-of-RIB marker pair for a single established session.

        Extracted from _generate_eor_markers() so a fault scenario (e.g. a
        Graceful Restart reconnect on one session) can emit EoR scoped to
        just that session, without re-emitting it on every other established
        session the way the all-sessions loop does.
        """
        packets = []
        eor_update = build_update(path_attributes=attr_mp_unreach_nlri(AFI_L2VPN, SAFI_EVPN, b''))

        pkts = tcp_sess.send_data(eor_update, timestamp=t, direction='client_to_server')
        packets.extend(pkts)
        packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'server_to_client'))
        t += 0.005

        pkts = tcp_sess.send_data(eor_update, timestamp=t, direction='server_to_client')
        packets.extend(pkts)
        packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))
        t += 0.005

        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)

        return packets, t

    def generate_route_updates(self, session_id: str, pe_router,
                               num_routes: int, start_time: float,
                               withdraw: bool = False) -> list[TCPPacket]:
        """Generate a realistic mix of EVPN route UPDATE messages from a PE.

        Steady-state churn is restricted to route types that legitimately
        recur without an underlying topology/membership change per RFC
        7432/8584: Type 1/3/4 all require a real ES/VNI/link-state change
        to justify appearing, which nothing in this steady-state churn loop
        models.
        - ~78.6% Type 2 (MAC/IP) — ordinary host learning, continuous by design
        - ~21.4% Type 5 (IP Prefix) — inter-subnet route updates

        Weights preserve the original 55:15 (Type2:Type5) ratio renormalized
        over the 70% of roll-space no longer spent on Type 1/3/4. Type 1
        (EAD), Type 3 (IMET), and Type 4 (ES/DF) are still sent, but only
        once, unconditionally, as part of the real initial-sync event in
        generate_initial_routes() -- never from this steady-state churn path.
        """
        import random
        packets = []
        tcp_sess = self.tcp_sessions.get(session_id)
        if not tcp_sess:
            return packets

        macs = self.topology.get_macs_for_pe(pe_router.id, count=num_routes)
        pe_idx = int(pe_router.bgp_id.split('.')[-1])
        t = start_time  # single shared monotonic clock -- every packet below advances it

        for i in range(num_routes):
            # Pick route type based on weighted distribution
            roll = random.random()
            if roll < 0.786:
                # Type 2: MAC/IP
                mac_entry = macs[i % len(macs)]
                nlri = evpn.build_mac_ip_route(
                    pe_router.bgp_id,
                    pe_router.esi or "0",
                    mac_entry.mac,
                    ip=mac_entry.ip,
                    vni=self.config.evpn.vni
                )
            else:
                # Type 5: IP Prefix
                prefix = f"10.{pe_idx}.{random.randint(0, 254)}.0"
                nlri = evpn.build_ip_prefix_route(
                    pe_router.bgp_id, prefix, 24, pe_router.bgp_id,
                    self.config.evpn.vni)

            if withdraw:
                path_attrs = build_evpn_withdraw_attrs(nlri)
            else:
                path_attrs = build_standard_evpn_path_attrs(
                    next_hop=pe_router.bgp_id,
                    nlri_bytes=nlri,
                    asn=self.config.as_number,
                    vni=self.config.evpn.vni,
                    originator_id=pe_router.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id,
                )

            update_msg = build_update(path_attributes=path_attrs)

            # RR reflects to vantage (server_to_client direction from RR's perspective)
            pkts = tcp_sess.send_data(update_msg, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += random.uniform(0.0003, 0.0008)
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
            t += random.uniform(0.001, 0.0075)

            # Mirror Type 2 routes to ESI peer for multi-homed PEs
            if (roll < 0.786 and pe_router.esi and pe_router.esi != "0"):
                esi_peers = self.topology.get_multihomed_esi_peers(pe_router.id)
                for peer_pe in esi_peers:
                    peer_session_id = self._find_session_for_pe(peer_pe.id)
                    if peer_session_id:
                        peer_tcp = self.tcp_sessions.get(peer_session_id)
                        if peer_tcp and peer_tcp.is_established():
                            peer_nlri = evpn.build_mac_ip_route(
                                peer_pe.bgp_id, pe_router.esi,
                                mac_entry.mac, ip=mac_entry.ip,
                                vni=self.config.evpn.vni)
                            if withdraw:
                                peer_attrs = build_evpn_withdraw_attrs(peer_nlri)
                            else:
                                peer_attrs = build_standard_evpn_path_attrs(
                                    next_hop=peer_pe.bgp_id,
                                    nlri_bytes=peer_nlri,
                                    asn=self.config.as_number,
                                    vni=self.config.evpn.vni,
                                    originator_id=peer_pe.bgp_id,
                                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
                            peer_update = build_update(path_attributes=peer_attrs)
                            peer_pkts = peer_tcp.send_data(
                                peer_update, timestamp=t,
                                direction='server_to_client')
                            packets.extend(peer_pkts)
                            t += random.uniform(0.0003, 0.0008)
                            packets.extend(peer_tcp.generate_ack(t, 'client_to_server'))
                            t += random.uniform(0.0005, 0.0025)

        return packets

    def _generate_type2_updates(self, session_id: str, pe_router,
                                num_routes: int, start_time: float,
                                withdraw: bool = False) -> list[TCPPacket]:
        """Generate only Type 2 (MAC/IP) routes — used for initial table sync."""
        packets = []
        tcp_sess = self.tcp_sessions.get(session_id)
        if not tcp_sess:
            return packets

        macs = self.topology.get_macs_for_pe(pe_router.id, count=num_routes)
        timestamps = route_burst_timestamps(start_time, len(macs))

        for mac_entry, t in zip(macs, timestamps):
            nlri = evpn.build_mac_ip_route(
                pe_router.bgp_id,
                pe_router.esi or "0",
                mac_entry.mac,
                ip=mac_entry.ip,
                vni=self.config.evpn.vni
            )

            if withdraw:
                path_attrs = build_evpn_withdraw_attrs(nlri)
            else:
                path_attrs = build_standard_evpn_path_attrs(
                    next_hop=pe_router.bgp_id,
                    nlri_bytes=nlri,
                    asn=self.config.as_number,
                    vni=self.config.evpn.vni,
                    originator_id=pe_router.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id,
                )

            update_msg = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update_msg, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))

        return packets

    def reflect_pe_routes_to_rr(self, tcp_sess: TCPSession, start_t: float,
                                event: bool = False,
                                pe_list: list = None,
                                fault_type: str = None,
                                node: str = None,
                                macs_in: dict = None,
                                phase: str = None) -> tuple[list[TCPPacket], float]:
        """Reflect PE IMET + MAC/IP routes onto an RR-RR session (RFC 4456).

        Shared by rr_down.py's post-reconnect resync and this class's
        cold-start initial sync. pe_list defaults to all PE nodes (matching
        the original reconnect-resync behavior); callers modeling a single
        cluster's worth of routes crossing to a peer RR pass an explicit,
        filtered pe_list.

        macs_in: optional {pe_id: [MACEntry, ...]} to reuse an exact MAC set
        instead of drawing a fresh random one -- lets a correct-RT recovery
        call reuse the same MACs a prior reflect_pe_routes_to_rr_wrong_rt()
        fault call drew (via that method's macs_out), so the recovery
        genuinely re-advertises the same routes the fault perturbed instead
        of an independently-redrawn set. None (default) preserves the
        original random-draw behavior for every existing caller.
        """
        packets = []
        t = start_t
        for pe in (pe_list if pe_list is not None else self.config.pe_nodes):
            cluster_id = self.config.get_router(pe.peers[0]).bgp_id
            nlri = evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni)
            path_attrs = build_standard_evpn_path_attrs(
                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=pe.bgp_id, cluster_id=cluster_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'client_to_server')
            packets.extend(pkts)
            t += 0.01
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.001

            if macs_in is not None and pe.id in macs_in:
                macs = macs_in[pe.id]
            else:
                macs = self.topology.get_macs_for_pe(pe.id, count=random.randint(3, 6))
            for mac_entry in macs:
                nlri = evpn.build_mac_ip_route(
                    pe.bgp_id, pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni)
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id, cluster_id=cluster_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'client_to_server')
                packets.extend(pkts)
                t += 0.008
                packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
                t += 0.001
            t += 0.02
        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def reflect_pe_routes_to_rr_wrong_rt(self, tcp_sess: TCPSession, start_t: float,
                                         wrong_rt: tuple[int, int],
                                         event: bool = False,
                                         pe_list: list = None,
                                         fault_type: str = None,
                                         node: str = None,
                                         macs_out: dict = None,
                                         prefix_out: dict = None,
                                         phase: str = None) -> tuple[list[TCPPacket], float]:
        """Reflect PE IMET + MAC/IP routes onto an RR-RR session with a
        deliberately WRONG Route Target community, for RT-misconfiguration
        scenarios where the affected PE has no direct session at the
        capture vantage (PE4/PE5).

        Sibling to reflect_pe_routes_to_rr() -- same loop/NLRI-building/
        session-targeting structure, but the attrs-building step is swapped
        to construct the wrong RT (mirroring
        RTMisconfigScenario._build_wrong_rt_path_attrs()) instead of calling
        build_standard_evpn_path_attrs(). reflect_pe_routes_to_rr() itself
        is untouched; this is a separate method, not a parameterization of it.

        Also sends Type 5 (IP Prefix, always) and Type 1 A-D per ES (only
        if pe.esi is set and not "0") with the same wrong RT, for parity
        with the direct-session fault path's route-type coverage
        (RTMisconfigScenario._direct_route_burst()) -- RT communities apply
        to any EVPN route type carrying import-relevant RT (RFC 4360/7432),
        not just Type 2/3.

        macs_out: optional {} dict that this call records {pe_id: [MACEntry,
        ...]} into as a side effect -- lets a caller capture exactly which
        MACs this fault call drew and pass that same dict as macs_in to a
        later reflect_pe_routes_to_rr() recovery call, so the recovery
        genuinely re-advertises the same routes the fault perturbed. None
        (default) skips recording, preserving existing behavior.

        prefix_out: optional {} dict that this call records {pe_id: prefix}
        into as a side effect -- lets a caller capture the Type 5 prefix
        this fault call drew and reuse it for the correct-RT recovery
        (e.g. seeding RTMisconfigScenario._burst_prefix before it calls
        _first_hop_type5_type1()/_second_hop_type5_type1() for recovery).
        None (default) skips recording, preserving existing behavior.
        """
        packets = []
        t = start_t
        wrong_rt_community = encode_rt_community(*wrong_rt)
        encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
        for pe in (pe_list if pe_list is not None else self.config.pe_nodes):
            nlri = evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni)
            path_attrs = b''
            path_attrs += attr_origin(0)
            path_attrs += attr_as_path()
            path_attrs += attr_local_pref(100)
            path_attrs += attr_extended_communities([wrong_rt_community, encap])
            path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'client_to_server')
            packets.extend(pkts)
            t += 0.01
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.001

            macs = self.topology.get_macs_for_pe(pe.id, count=random.randint(3, 6))
            if macs_out is not None:
                macs_out[pe.id] = macs
            for mac_entry in macs:
                nlri = evpn.build_mac_ip_route(
                    pe.bgp_id, pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni)
                path_attrs = b''
                path_attrs += attr_origin(0)
                path_attrs += attr_as_path()
                path_attrs += attr_local_pref(100)
                path_attrs += attr_extended_communities([wrong_rt_community, encap])
                path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'client_to_server')
                packets.extend(pkts)
                t += 0.008
                packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
                t += 0.001

            pe_idx = int(pe.bgp_id.split('.')[-1])
            prefix = f"10.{pe_idx}.{random.randint(0, 254)}.0"
            if prefix_out is not None:
                prefix_out[pe.id] = prefix
            nlri = evpn.build_ip_prefix_route(pe.bgp_id, prefix, 24, pe.bgp_id, self.config.evpn.vni)
            path_attrs = b''
            path_attrs += attr_origin(0)
            path_attrs += attr_as_path()
            path_attrs += attr_local_pref(100)
            path_attrs += attr_extended_communities([wrong_rt_community, encap])
            path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'client_to_server')
            packets.extend(pkts)
            t += 0.008
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.001

            if pe.esi and pe.esi != "0":
                nlri = evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni)
                path_attrs = b''
                path_attrs += attr_origin(0)
                path_attrs += attr_as_path()
                path_attrs += attr_local_pref(100)
                path_attrs += attr_extended_communities([wrong_rt_community, encap])
                path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'client_to_server')
                packets.extend(pkts)
                t += 0.008
                packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
                t += 0.001

            t += 0.02
        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def reflect_pe_withdrawal_to_rr(self, tcp_sess: TCPSession, pe,
                                    start_t: float,
                                    event: bool = False,
                                    fault_type: str = None,
                                    node: str = None,
                                    macs_out: dict = None,
                                    phase: str = None) -> tuple[list[TCPPacket], float]:
        """Withdraw one PE's IMET + MAC/IP routes over an RR-RR session.

        The withdrawal-direction counterpart to reflect_pe_routes_to_rr().
        A PE with no direct session at the capture vantage (e.g. PE4/PE5
        under RR2 when the vantage is RR1) failing is otherwise invisible
        at the vantage -- its home RR reflects the resulting withdrawal
        onward to the peer RR over their existing RR-RR session, the only
        wire visibility the vantage has into that PE's failure. Reuses the
        same WITHDRAW construction link_down.py's direct-session path
        already uses (build_evpn_withdraw_attrs over an IMET + MAC/IP route
        set, same MAC-count randomization), just targeted at a single PE
        and sent over the RR-RR session instead of iterating every other
        direct session.

        Per RFC 4271 SS9.2, session loss withdraws ALL routes learned from
        that peer -- if pe has a real ESI, also withdraws its Type 1
        (EAD per-ES, EAD per-EVI) and Type 4 (ES route), matching
        generate_initial_routes()'s unconditional cold-start advertisement
        of those for multihomed PEs. No-op for non-multihomed PEs, which
        never had them.

        macs_out: optional {} dict that this call records {pe_id: [MACEntry,
        ...]} into as a side effect -- lets a caller capture exactly which
        MACs this withdrawal drew and pass that same dict as macs_in to a
        later reflect_pe_routes_to_rr() recovery call (and/or as
        macs_override to reflect_to_own_clients()), so the recovery
        genuinely re-advertises the same routes the withdrawal removed
        instead of an independently-redrawn set. None (default) skips
        recording, preserving existing behavior.
        """
        packets = []
        t = start_t

        nlris = [evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni)]
        macs = self.topology.get_macs_for_pe(
            pe.id, count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                        int(self.config.evpn.mac_pool_size * 0.5)))
        if macs_out is not None:
            macs_out[pe.id] = macs
        nlris.extend(evpn.build_mac_ip_route(
            pe.bgp_id, pe.esi or "0", mac_entry.mac,
            ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs)
        if pe.esi and pe.esi != "0":
            nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
            nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                vni=self.config.evpn.vni))
            nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                             self.config.evpn.vni))

        for nlri in nlris:
            path_attrs = build_evpn_withdraw_attrs(nlri)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, t, 'client_to_server')
            packets.extend(pkts)
            t += 0.008
            packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
            t += 0.001

        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def reflect_single_route_to_rr(self, tcp_sess: TCPSession, pe, route_type: int,
                                   action: str, start_t: float,
                                   ethernet_tag: int = 0,
                                   extra_communities: list[bytes] = None,
                                   event: bool = False, fault_type: str = None,
                                   node: str = None, phase: str = None,
                                   wrong_rt: tuple[int, int] = None) -> tuple[list[TCPPacket], float]:
        """Withdraw or advertise ONE specific route (Type 4 ES route, or
        Type 1 per-EVI EAD route) over an RR-RR mesh session, for
        esdf_toggle.py/rt_misconfig.py multi-vantage support.

        Deliberately NOT reusing reflect_pe_withdrawal_to_rr() -- that
        helper withdraws a PE's ENTIRE route set (IMET + MAC/IP + Type 1/4),
        correct for link_down.py's full-session-loss semantics (RFC 4271
        SS9.2) but wrong for esdf_toggle's/rt_misconfig ES-Import's
        semantics, where the BGP session stays up and only ONE specific
        route type toggles while Type-2 traffic continues unaffected.

        route_type: 1 (per-EVI EAD) or 4 (ES route). action: 'withdraw' or
        'advertise'. extra_communities: for AC-state's DF Election
        Extended Community (route_type=4, action='advertise' only).
        wrong_rt: for rt_misconfig ES-Import's deviant-RT advertise case.
        """
        packets = []
        t = start_t
        if route_type == 4:
            nlri = evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id, self.config.evpn.vni)
        elif route_type == 1:
            nlri = evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag, self.config.evpn.vni)
        else:
            raise ValueError(f"reflect_single_route_to_rr: unsupported route_type {route_type}")

        if action == 'withdraw':
            path_attrs = build_evpn_withdraw_attrs(nlri)
        elif wrong_rt is not None:
            wrong_rt_community = encode_rt_community(*wrong_rt)
            encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
            communities = [wrong_rt_community, encap] + (extra_communities or [])
            path_attrs = b''
            path_attrs += attr_origin(0)
            path_attrs += attr_as_path()
            path_attrs += attr_local_pref(100)
            path_attrs += attr_extended_communities(communities)
            path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
            path_attrs += attr_originator_id(pe.bgp_id)
            path_attrs += attr_cluster_list([self.config.get_router(pe.peers[0]).bgp_id])
        else:
            path_attrs = build_standard_evpn_path_attrs(
                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                extra_communities=extra_communities,
                originator_id=pe.bgp_id,
                cluster_id=self.config.get_router(pe.peers[0]).bgp_id)

        update = build_update(path_attributes=path_attrs)
        pkts = tcp_sess.send_data(update, t, 'client_to_server')
        packets.extend(pkts)
        t += 0.008
        packets.extend(tcp_sess.generate_ack(t, 'server_to_client'))
        t += 0.001

        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def reflect_to_own_clients(self, pe, start_t: float, action: str = 'advertise',
                               wrong_rt: tuple[int, int] = None,
                               event: bool = False,
                               fault_type: str = None,
                               node: str = None,
                               macs_override: list = None,
                               phase: str = None) -> tuple[list[TCPPacket], float]:
        """RFC 4456 second-hop reflection: forward one PE's route content,
        already reflected onto the RR1-RR2 session, onward to the vantage
        RR's own direct clients (PE1-3).

        A route reflector receiving a route from a non-client peer (here,
        RR1 receiving PE4/PE5 content from RR2 over the RR1-RR2 session)
        must reflect it to its own clients. ORIGINATOR_ID/CLUSTER_LIST stay
        set to the true origin -- the PE and its home RR -- exactly as they
        were on the first hop; this method does not add RR1 to the cluster
        path, keeping the origin attribution unchanged from what
        reflect_pe_routes_to_rr() et al. already establish.

        action: 'advertise' (correct RT, or wrong_rt if given) or 'withdraw'.

        macs_override: optional [MACEntry, ...] to reuse the exact same MAC
        set across every client session and across separate fault/recovery
        calls, instead of drawing a fresh random set per client session
        (the original behavior, preserved when None). Lets a correct-RT
        recovery call reuse the same MACs an earlier wrong-RT fault call
        used, so the recovery genuinely re-advertises what the fault
        perturbed.
        """
        packets = []
        t = start_t
        cluster_id = self.config.get_router(pe.peers[0]).bgp_id

        client_sessions = [
            bgp_sess for bgp_sess in self.topology.get_sessions_at_vantage()
            if bgp_sess.local_router.role == 'pe' and bgp_sess.local_router.id != pe.id
        ]

        for bgp_sess in client_sessions:
            tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
            if not tcp_sess or not tcp_sess.is_established():
                continue

            routes = [evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni)]
            if macs_override is not None:
                macs = macs_override
            else:
                macs = self.topology.get_macs_for_pe(
                    pe.id, count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                                int(self.config.evpn.mac_pool_size * 0.5)))
            for mac_entry in macs:
                routes.append(evpn.build_mac_ip_route(
                    pe.bgp_id, pe.esi or "0", mac_entry.mac,
                    ip=mac_entry.ip, vni=self.config.evpn.vni))

            for nlri in routes:
                if action == 'withdraw':
                    path_attrs = build_evpn_withdraw_attrs(nlri)
                elif wrong_rt is not None:
                    wrong_rt_community = encode_rt_community(*wrong_rt)
                    encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                    path_attrs = b''
                    path_attrs += attr_origin(0)
                    path_attrs += attr_as_path()
                    path_attrs += attr_local_pref(100)
                    path_attrs += attr_extended_communities([wrong_rt_community, encap])
                    path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
                    path_attrs += attr_originator_id(pe.bgp_id)
                    path_attrs += attr_cluster_list([cluster_id])
                else:
                    path_attrs = build_standard_evpn_path_attrs(
                        pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                        originator_id=pe.bgp_id, cluster_id=cluster_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, t, 'server_to_client')
                packets.extend(pkts)
                t += 0.008
                packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.001
            t += 0.02

        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def _fan_out_type4_to_other_sessions(self, pe, esi: str, action: str,
                                         start_t: float, event: bool = False,
                                         fault_type: str = None,
                                         node: str = None,
                                         phase: str = None,
                                         clients_only: bool = False,
                                         extra_communities: list[bytes] = None,
                                         wrong_rt: tuple[int, int] = None) -> tuple[list[TCPPacket], float]:
        """Fan a single PE's Type 4 ES route (withdraw or advertise) out to
        every other established direct session at the vantage -- same
        fan-out shape as LinkDownScenario._withdraw_pe_routes_direct()
        (RFC 4456: RR1 must reflect content it receives from a client to its
        other clients too, not just record the single PE-to-RR1 packet).

        Shared by esdf_toggle.py and every other ESDF-Toggle-leg call site
        (section4.py's IntermittentESDFToggle/MixedESDFAndLinkDown,
        eval_scenarios.py's RRDownESDFScenario/ESDFRTMisconfigScenario/
        TripleLDRRESScenario) so the fan-out logic isn't duplicated six
        times. action: 'advertise' or 'withdraw'.

        This builds a genuine Type-4 ES route. The five other callers' own
        primary withdraw/advertise events still independently build Type-1
        (see the "TODO Type-1/Type-4" comment at the top of each affected
        class).

        clients_only: when True, excludes RR-RR sessions from the fan-out
        targets, sending only to this vantage's own PE client sessions.
        REQUIRED for a reflected-
        vantage caller (one that received this route from a non-client RR
        peer over the mesh) -- RFC 4456 prohibits reflecting a
        non-client-received route onward to OTHER non-client peers (that's
        what full RR-RR mesh exists to avoid: no double-hop through a third
        RR). False (default) preserves the original behavior exactly: a
        DIRECT/home-RR caller received this route from a CLIENT, so it
        correctly fans out to BOTH other clients AND RR-RR peers.
        extra_communities/wrong_rt: same meaning as reflect_single_route_to_rr.
        """
        packets = []
        # 2ms relay-processing gap between the first-hop landing and
        # second-hop reflection beginning, matching the same fix already
        # applied to link_down.py/rt_misconfig.py/rr_down.py/mixed.py's
        # own first-hop-to-second-hop fan-out transitions.
        t = start_t + 0.002
        nlri = evpn.build_es_route(pe.bgp_id, esi, pe.bgp_id, self.config.evpn.vni)
        for session_id, tcp_sess in self.tcp_sessions.items():
            if pe.id in session_id or not tcp_sess.is_established():
                continue
            if clients_only:
                _a, _b = session_id.split('-', 1)
                if _a.startswith('RR') and _b.startswith('RR'):
                    continue
            if action == 'withdraw':
                path_attrs = build_evpn_withdraw_attrs(nlri)
            elif wrong_rt is not None:
                wrong_rt_community = encode_rt_community(*wrong_rt)
                encap = encode_encapsulation_community(TUNNEL_TYPE_VXLAN)
                communities = [wrong_rt_community, encap] + (extra_communities or [])
                path_attrs = b''
                path_attrs += attr_origin(0)
                path_attrs += attr_as_path()
                path_attrs += attr_local_pref(100)
                path_attrs += attr_extended_communities(communities)
                path_attrs += attr_mp_reach_nlri(AFI_L2VPN, SAFI_EVPN, pe.bgp_id, nlri)
                path_attrs += attr_originator_id(pe.bgp_id)
                path_attrs += attr_cluster_list([self.config.get_router(self.config.capture_vantage).bgp_id])
            else:
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    extra_communities=extra_communities,
                    originator_id=pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += 0.005
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
            t += 0.001

        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def _fan_out_type1_evi_to_other_sessions(self, pe, esi: str, action: str,
                                         start_t: float, event: bool = False,
                                         fault_type: str = None,
                                         node: str = None,
                                         phase: str = None,
                                         ethernet_tag: int = 0,
                                         clients_only: bool = False) -> tuple[list[TCPPacket], float]:
        """Fan a single PE's Type 1 per-EVI EAD route (withdraw or
        advertise) out to every other established direct session at the
        vantage -- same fan-out shape as _fan_out_type4_to_other_sessions(),
        parallel helper for the Type-1-per-EVI-withdrawal DF-election
        trigger (RFC 8584). Does NOT touch or replace
        _fan_out_type4_to_other_sessions(), which remains the Type-4
        ES-route fan-out used by the existing ESDFSingleToggle/RapidToggle/
        NoRecovery/SlowToggle classes. action: 'advertise' or 'withdraw'.

        clients_only: same meaning as _fan_out_type4_to_other_sessions()'s.
        """
        packets = []
        # 2ms relay-processing gap, matching _fan_out_type4_to_other_sessions().
        t = start_t + 0.002
        nlri = evpn.build_ead_per_evi(pe.bgp_id, esi, ethernet_tag, self.config.evpn.vni)
        for session_id, tcp_sess in self.tcp_sessions.items():
            if pe.id in session_id or not tcp_sess.is_established():
                continue
            if clients_only:
                _a, _b = session_id.split('-', 1)
                if _a.startswith('RR') and _b.startswith('RR'):
                    continue
            if action == 'withdraw':
                path_attrs = build_evpn_withdraw_attrs(nlri)
            else:
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id,
                    cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            t += 0.005
            packets.extend(tcp_sess.generate_ack(t, 'client_to_server'))
            t += 0.001

        if event:
            self._mark_event(packets, fault_type, node, 'Route UPDATE', phase=phase)
        return packets, t

    def _rr_rr_session(self, other_rr_id: str = None) -> Optional[BGPSession]:
        """Find an RR-RR mesh session at the capture vantage.

        other_rr_id: if given, find the specific session connecting THIS
        vantage to that RR (needed once a topology has more than one RR-RR
        link at a vantage, e.g. a 3RR full mesh -- RR1's vantage has both
        an RR1-RR2 and an RR1-RR3 session, and a reflected-fault caller
        needs the ONE connecting to the affected PE's actual home RR, not
        just "the first RR-RR session found"). None (default) returns the
        first RR-RR session found, correct for any topology with only one
        RR-RR link at the vantage (5PE/2RR has exactly one).

        RR-RR BGPSession objects are built ONCE by
        NetworkTopology._build_sessions() with a FIXED local/remote
        orientation (first-listed router in the peers config becomes
        "local"), independent of which RR's vantage later queries them --
        RR1-RR2's session is always local=RR1, remote=RR2, whether queried
        from RR1's OR RR2's own vantage. Checking BOTH sides ensures a
        query from either vantage still finds the session."""
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
                if other_rr_id is None or other_rr_id in (bgp_sess.local_router.id, bgp_sess.remote_router.id):
                    return bgp_sess
        return None

    def _find_session_for_pe(self, pe_id: str) -> Optional[str]:
        """Find the TCP session ID for a given PE."""
        for bgp_session in self.topology.get_sessions_at_vantage():
            if bgp_session.local_router.id == pe_id:
                session_id = bgp_session.session_id
                tcp_sess = self.tcp_sessions.get(session_id)
                if tcp_sess and tcp_sess.is_established():
                    return session_id
        return None

    def _generate_type2_for_peer(self, session_id: str, peer_pe,
                                  mac_entries: list, esi: str,
                                  start_time: float) -> list[TCPPacket]:
        """Generate Type 2 routes from an ESI peer for shared-segment MACs.

        In all-active multi-homing, both PEs on a shared Ethernet Segment
        advertise the same MACs (same ESI, but each PE's own next-hop).
        """
        packets = []
        tcp_sess = self.tcp_sessions.get(session_id)
        if not tcp_sess:
            return packets

        timestamps = route_burst_timestamps(start_time, len(mac_entries))

        for mac_entry, t in zip(mac_entries, timestamps):
            nlri = evpn.build_mac_ip_route(
                peer_pe.bgp_id,
                esi,
                mac_entry.mac,
                ip=mac_entry.ip,
                vni=self.config.evpn.vni
            )
            path_attrs = build_standard_evpn_path_attrs(
                next_hop=peer_pe.bgp_id,
                nlri_bytes=nlri,
                asn=self.config.as_number,
                vni=self.config.evpn.vni,
                originator_id=peer_pe.bgp_id,
                cluster_id=self.config.get_router(self.config.capture_vantage).bgp_id,
            )
            update_msg = build_update(path_attributes=path_attrs)
            pkts = tcp_sess.send_data(update_msg, timestamp=t, direction='server_to_client')
            packets.extend(pkts)
            packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'client_to_server'))

        return packets

    def _generate_churn_batch(self, packets: list, bgp_sess, pe,
                              t: float, num_routes: int, withdraw: bool,
                              last_update_times: dict = None) -> Optional[float]:
        """Generate one route-churn batch (advertise or withdraw) for a
        session, record its timestamp for keepalive suppression, and
        probabilistically attach a ROUTE-REFRESH afterward.

        Shared by normal.py's Quiet/Moderate/Busy churn generators and any
        fault scenario reusing the same baseline via generate_route_churn().
        Returns the batch's last timestamp, or None if no packets resulted.
        """
        route_pkts = self.generate_route_updates(
            bgp_sess.session_id, pe, num_routes=num_routes, start_time=t,
            withdraw=withdraw)
        packets.extend(route_pkts)
        if not route_pkts:
            return None

        last_t = max(p.timestamp for p in route_pkts if p.payload)
        if last_update_times is not None:
            last_update_times.setdefault(bgp_sess.session_id, []).append(last_t)

        if random.random() < ROUTE_REFRESH_ATTACH_PROB:
            tcp_sess = self.tcp_sessions.get(bgp_sess.session_id)
            if tcp_sess and tcp_sess.is_established():
                refresh_t = last_t + random.uniform(1, 5)
                rr_msg = build_route_refresh(AFI_L2VPN, SAFI_EVPN)
                pkts = tcp_sess.send_data(rr_msg, timestamp=refresh_t, direction='server_to_client')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(refresh_t + ack_delay(), 'client_to_server'))
                if last_update_times is not None:
                    last_update_times.setdefault(bgp_sess.session_id, []).append(refresh_t)

        return last_t

    def warmup_with_optional_mid_churn(self, packets: list, t: float,
                                       warmup_duration: float,
                                       mid_churn: bool = False) -> float:
        """Standard churn+keepalive warmup (mid_churn=False, the existing
        behavior every scenario already uses -- default, zero change).

        mid_churn=True: truncate the warmup partway through and kick off one
        more churn batch, returning a timestamp that lands while that batch
        is still in flight, so the caller's fault injection (unchanged) ends
        up interleaved with active churn traffic instead of following an
        idle gap. Caller should inject its fault immediately at the returned
        t -- no additional silence first.
        """
        last_update_times: dict = {}
        if not mid_churn:
            self.generate_route_churn(packets, t, warmup_duration,
                                      last_update_times=last_update_times)
            packets.extend(self.generate_keepalives_for_duration(
                t, warmup_duration, last_update_times=last_update_times))
            return t + warmup_duration

        pre_duration = warmup_duration * self._param_rng.uniform(0.4, 0.7)
        self.generate_route_churn(packets, t, pre_duration,
                                  last_update_times=last_update_times)
        packets.extend(self.generate_keepalives_for_duration(
            t, pre_duration, last_update_times=last_update_times))
        t += pre_duration

        sessions = self.topology.get_sessions_at_vantage()
        pe_sessions = [(s, s.local_router) for s in sessions if s.local_router.role == 'pe']
        if pe_sessions:
            bgp_sess, pe = random.choice(pe_sessions)
            self._generate_churn_batch(packets, bgp_sess, pe, t,
                                       num_routes=7, withdraw=False)
        return t + random.uniform(0.05, 0.3)

    def generate_route_churn(self, packets: list, start: float, duration: float,
                             interval_range: tuple = (15, 30),
                             advertise_prob: float = 0.6,
                             advertise_count_range: tuple = (5, 9),
                             withdraw_count_range: tuple = (2, 4),
                             last_update_times: dict = None,
                             pe_sessions: list = None,
                             round_robin: bool = True,
                             silence_guard: bool = False) -> None:
        """Shared route-churn baseline generator.

        Backs normal.py's Quiet/Moderate/Busy profiles (via profile-specific
        parameter presets) and is reusable as a pre/post-fault baseline by
        fault scenarios that want realistic background churn instead of a
        keepalive-only silence.

        interval_range: (min, max) seconds between churn events.
        advertise_prob: probability a given event advertises rather than
            withdraws.
        advertise_count_range / withdraw_count_range: (min, max) routes per
            event for each branch. Pass equal bounds (e.g. (1, 1)) for a
            fixed count -- no extra random draw is consumed in that case, to
            keep the call-site-specific RNG sequence as close to the
            pre-refactor implementation as possible.
        pe_sessions: optional pre-filtered (bgp_session, pe) list (e.g. a
            weighted primary/other subset); defaults to all PE-role sessions
            at vantage.
        round_robin: cycle through pe_sessions in order instead of
            random.choice, so no single session goes many consecutive
            events without activity.
        silence_guard: additionally force an out-of-cycle event on any
            session that's gone longer than SILENCE_GUARD_THRESHOLD without
            one (see constant docstring for why round-robin alone isn't
            always sufficient at tight intervals).
        """
        if pe_sessions is None:
            sessions = self.topology.get_sessions_at_vantage()
            pe_sessions = [(s, s.local_router) for s in sessions if s.local_router.role == 'pe']
        if not pe_sessions:
            return

        lo, hi = interval_range
        t = start + random.uniform(lo, hi)
        session_idx = 0
        while t < start + duration:
            forced = None
            if silence_guard and last_update_times is not None:
                for cand_sess, cand_pe in pe_sessions:
                    times = last_update_times.get(cand_sess.session_id)
                    last_t = times[-1] if times else start
                    if t - last_t > SILENCE_GUARD_THRESHOLD:
                        forced = (cand_sess, cand_pe)
                        break

            if forced is not None:
                bgp_sess, pe = forced
            elif round_robin:
                bgp_sess, pe = pe_sessions[session_idx % len(pe_sessions)]
                session_idx += 1
            else:
                bgp_sess, pe = random.choice(pe_sessions)

            withdraw = random.random() >= advertise_prob
            count_range = withdraw_count_range if withdraw else advertise_count_range
            num = (count_range[0] if count_range[0] == count_range[1]
                  else random.randint(*count_range))

            self._generate_churn_batch(packets, bgp_sess, pe, t, num, withdraw,
                                       last_update_times)
            t += random.uniform(lo, hi)
