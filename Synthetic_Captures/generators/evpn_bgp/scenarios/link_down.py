"""Section 2 — Link Down fault scenarios.

Simulates PE-RR link failures with various detection mechanisms (TCP RST,
hold-timer expiry) and recovery patterns (none, fast, slow), for both PEs
with a direct session at the capture vantage (PE1-3, vantage=RR1) and PEs
with no direct session at vantage (PE4/PE5, whose only session is to RR2) --
the latter's failure is only observable at RR1 via RR2 reflecting the
resulting withdrawal onward over the RR1-RR2 session (see
BaseScenario.reflect_pe_withdrawal_to_rr()).

For the reflected path, TCP RST and hold-timer expiry produce no
distinguishable observable difference at RR1's vantage beyond timing -- RR1
never sees the PE4/PE5-RR2 session directly either way, only whatever RR2
chooses to reflect. The mechanism dimension for the reflected path
therefore only varies *when* the reflected withdrawal appears (immediately
for RST-style, delayed by RR2's own hold-timer detection for
hold-timer-style), not *what* it contains.
"""

import random
from typing import Optional
from .base import BaseScenario
from ..config import TopologyConfig, RouterConfig
from ..topology import BGPSession
from ..tcp.session import TCPSession, TCPPacket
from ..bgp.messages import build_notification, build_keepalive, build_open, build_update
from ..bgp.capabilities import default_evpn_capabilities
from ..bgp.constants import ERR_HOLD_TIMER_EXPIRED, ERR_CEASE, CEASE_ADMIN_SHUTDOWN, CEASE_ADMIN_RESET, CEASE_HARD_RESET
from ..bgp.attributes import build_evpn_withdraw_attrs, build_standard_evpn_path_attrs
from ..bgp import evpn
from generators.common.utils.timing import (
    hold_timer_expiry_delay, reconnection_delay, jittered_interval, ack_delay,
    keepalive_timestamps
)


_NOTIF_NAME = {
    (ERR_CEASE, CEASE_ADMIN_RESET): 'Cease/Administrative Reset',
    (ERR_HOLD_TIMER_EXPIRED, 0): 'Hold Timer Expired',
}


def _first_bgp_ts(pkts: list, fallback: float) -> float:
    """Return the timestamp of the first TCP packet with a non-empty payload.

    Used to pin _fault_start_t to the actual first CSV-visible event rather
    than a hardcoded offset, so fw.json stays correct if timing constants change.
    """
    for p in pkts:
        if getattr(p, 'payload', None):
            return p.timestamp
    return fallback


class LinkDownScenario(BaseScenario):
    """Unified Section 2 Link Down scenario: mechanism x recovery x node.

    mechanism: 'rst' (abrupt TCP RST) or 'hold_timer' (silence -> NOTIFICATION
        Hold Timer Expired -> graceful close).
    recovery: 'none' (never recovers), 'fast' (20-30s silence then
        reconnect), 'slow' (2-5min silence then reconnect).
    affected_pe: PE1-PE5. PE1-3 have a direct session at the RR1 vantage and
        use the direct-session RST/withdraw/recover path. PE4/PE5 have no
        direct session at vantage -- their failure is only observable via
        RR2 reflecting the withdrawal onward over the RR1-RR2 session
        (reflect_pe_withdrawal_to_rr()), and recovery is modeled as RR2
        re-reflecting that PE's routes (reflect_pe_routes_to_rr()).

    Pre-fault and post-fault/recovery traffic uses the shared Moderate-
    profile route churn (BaseScenario.generate_route_churn()) rather than a
    keepalive-only baseline, so the fault is a distinct event layered on top
    of realistic background traffic, not the entire capture's content.
    """

    FAULT_TYPE: str = 'Link Down'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 30000,
                 affected_pe: str = None, mechanism: str = 'rst',
                 recovery: str = 'fast', mid_churn: bool = False):
        super().__init__(config, target_frames)
        self.affected_pe_id = affected_pe or config.pe_nodes[0].id
        self.mechanism = mechanism  # 'rst' | 'hold_timer'
        self.recovery = recovery    # 'none' | 'fast' | 'slow'
        self.mid_churn = mid_churn  # inject fault mid-warmup-churn-burst instead of after idle
        pe = config.get_router(self.affected_pe_id)
        self.is_reflected = bool(pe and pe.peers and pe.peers[0] != config.capture_vantage)
        # Single-mechanism label for this class's own link-down packets, kept
        # separate from FAULT_TYPE: mixed subclasses (LinkDownTriggersESDF
        # etc.) override FAULT_TYPE to a combined string like 'Link Down +
        # ESDF Toggle', but every _mark_event() call inside THIS class's own
        # inherited methods must still report the single mechanism 'Link
        # Down', never the combined label.
        self._ld_fault_type = 'Link Down'
        # {pe_id: [nlri_bytes, ...]} captured by _withdraw_pe_routes_direct()
        # at withdrawal time and reused by _recover_session_direct() so
        # recovery genuinely re-advertises the exact NLRI set that was
        # withdrawn (same route types: Type 2/3, plus Type 1/4 if
        # multihomed).
        self._withdrawn_nlris_by_pe: dict = {}
        # {pe_id: [MACEntry, ...]} captured by reflect_pe_withdrawal_to_rr()
        # at withdrawal time (reflected/PE4-PE5 path only) and reused via
        # macs_in/macs_override on the corresponding recovery calls.
        self._reflected_macs_by_pe: dict = {}

    def _direct_session(self) -> Optional[BGPSession]:
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.affected_pe_id:
                return bgp_sess
        return None

    def _other_keepalives(self, start: float, duration: float,
                          exclude_session_id: str = None) -> list[TCPPacket]:
        """Keepalives for every established session except the one currently
        under fault (or none, if no session is excluded)."""
        packets = []
        ka_msg = build_keepalive()
        interval = self.config.timing.keepalive_timer

        for session_id, tcp_sess in self.tcp_sessions.items():
            if session_id == exclude_session_id or not tcp_sess.is_established():
                continue
            for t in keepalive_timestamps(start, duration, interval):
                pkts = tcp_sess.send_data(ka_msg, t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(t + ack_delay(), 'server_to_client'))

                t_s = t + jittered_interval(interval / 3, 0.3)
                if t_s < start + duration:
                    pkts = tcp_sess.send_data(ka_msg, t_s, 'server_to_client')
                    packets.extend(pkts)
                    packets.extend(tcp_sess.generate_ack(t_s + ack_delay(), 'client_to_server'))

        return packets

    def _withdraw_pe_routes_direct(self, pe: RouterConfig, timestamp: float,
                                   event: bool = False) -> list[TCPPacket]:
        """RR withdraws the dead PE's routes to other direct sessions.

        Per RFC 4271 SS9.2, loss of a session means ALL routes learned from
        that peer are withdrawn, not just its MAC/IP (Type 2) routes. For a
        multihomed PE (real ESI), generate_initial_routes() unconditionally
        advertises Type 1 (EAD per-ES, EAD per-EVI) and Type 4 (ES route) at
        cold start, so those need withdrawing here too -- skipped entirely
        for non-multihomed PEs (PE3/4/5), which never had them.
        """
        packets = []
        # This method is also called as an unbound method on
        # non-LinkDownScenario instances (e.g. mixed.py's
        # RRDownThenLinkDownSequential, link_down.py's own
        # LinkDownHardReset), which never ran LinkDownScenario.__init__.
        if not hasattr(self, '_withdrawn_nlris_by_pe'):
            self._withdrawn_nlris_by_pe = {}
        macs = self.topology.get_macs_for_pe(
            pe.id,
            count=random.randint(int(self.config.evpn.mac_pool_size * 0.2),
                                  int(self.config.evpn.mac_pool_size * 0.5)))

        nlris = [evpn.build_mac_ip_route(
            pe.bgp_id, pe.esi or "0", mac_entry.mac,
            ip=mac_entry.ip, vni=self.config.evpn.vni) for mac_entry in macs]
        # Type 3 (IMET): every PE advertises this at cold start
        # (generate_initial_routes()), so it must be withdrawn here too --
        # same RFC 4271 SS9.2 completeness principle as the Type 1/4
        # handling below.
        nlris.append(evpn.build_imet_route(pe.bgp_id, pe.bgp_id, self.config.evpn.vni))
        if pe.esi and pe.esi != "0":
            nlris.append(evpn.build_ead_per_es(pe.bgp_id, pe.esi, self.config.evpn.vni))
            nlris.append(evpn.build_ead_per_evi(pe.bgp_id, pe.esi, ethernet_tag=0,
                                                vni=self.config.evpn.vni))
            nlris.append(evpn.build_es_route(pe.bgp_id, pe.esi, pe.bgp_id,
                                             self.config.evpn.vni))

        self._withdrawn_nlris_by_pe[pe.id] = nlris

        for session_id, tcp_sess in self.tcp_sessions.items():
            if pe.id in session_id or not tcp_sess.is_established():
                continue

            for nlri in nlris:
                path_attrs = build_evpn_withdraw_attrs(nlri)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, timestamp=timestamp,
                                          direction='server_to_client')
                packets.extend(pkts)
                timestamp += 0.005
                packets.extend(tcp_sess.generate_ack(timestamp, 'client_to_server'))
                timestamp += 0.001

        if event:
            self._mark_event(packets, getattr(self, '_ld_fault_type', self.FAULT_TYPE), self.affected_pe_id, 'Route UPDATE', phase='trigger')
        return packets

    def _recover_session_direct(self, affected_session: BGPSession,
                                t: float, event: bool = False) -> tuple[list[TCPPacket], float]:
        """Full BGP session re-establishment after link recovery (direct
        path). Re-advertises the EXACT NLRI set _withdraw_pe_routes_direct()
        withdrew for this PE (cached in self._withdrawn_nlris_by_pe), on the
        PE's own reconnected session AND fanned out to the other
        established sessions (RFC 4456 second hop) -- mirroring
        _withdraw_pe_routes_direct()'s own fan-out shape, so recovery has
        the same shape as the fault did.
        """
        packets = []
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
        t += 0.002

        ka = build_keepalive()
        pkts = new_tcp.send_data(ka, t, 'client_to_server')
        packets.extend(pkts)
        t += ack_delay()
        packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
        t += 0.001
        pkts = new_tcp.send_data(ka, t, 'server_to_client')
        packets.extend(pkts)
        t += ack_delay()
        packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
        t += 0.01

        nlris = getattr(self, '_withdrawn_nlris_by_pe', {}).get(pe.id, [])

        route_pkts = []
        for nlri in nlris:
            path_attrs = build_standard_evpn_path_attrs(
                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                originator_id=pe.bgp_id, cluster_id=rr.bgp_id)
            update = build_update(path_attributes=path_attrs)
            pkts = new_tcp.send_data(update, t, 'client_to_server')
            route_pkts.extend(pkts)
            t += 0.005
            route_pkts.extend(new_tcp.generate_ack(t, 'server_to_client'))
            t += 0.001
        packets.extend(route_pkts)
        t += 0.5

        if event:
            self._mark_event(route_pkts, getattr(self, '_ld_fault_type', self.FAULT_TYPE), self.affected_pe_id, 'Route UPDATE', phase='recovery')

        # RFC 4456 second hop: fan the same re-advertised NLRI set out to
        # the other established sessions too.
        second_hop_pkts = []
        for session_id, tcp_sess in self.tcp_sessions.items():
            if pe.id in session_id or not tcp_sess.is_established():
                continue
            for nlri in nlris:
                path_attrs = build_standard_evpn_path_attrs(
                    pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                    originator_id=pe.bgp_id, cluster_id=rr.bgp_id)
                update = build_update(path_attributes=path_attrs)
                pkts = tcp_sess.send_data(update, timestamp=t, direction='server_to_client')
                second_hop_pkts.extend(pkts)
                t += 0.005
                second_hop_pkts.extend(tcp_sess.generate_ack(t, 'client_to_server'))
                t += 0.001
        packets.extend(second_hop_pkts)
        if event and second_hop_pkts:
            self._mark_event(second_hop_pkts, getattr(self, '_ld_fault_type', self.FAULT_TYPE), self.affected_pe_id, 'Route UPDATE', phase='recovery')

        return packets, t

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Pre-fault baseline: Moderate-profile churn, not keepalive-only.
        warmup_duration = self._param_rng.randint(120, 480)
        t = self.warmup_with_optional_mid_churn(packets, t, warmup_duration,
                                                mid_churn=self.mid_churn)

        pe = self.config.get_router(self.affected_pe_id)
        fault_start_t = t
        withdraw_pkts: list = []
        exclude_session_id = None

        if self.is_reflected:
            rr_sess = self._rr_rr_session()
            rr_tcp = self.tcp_sessions.get(rr_sess.session_id) if rr_sess else None
            # Do NOT exclude the RR1-RR2 session here: it never fails in a
            # PE4/PE5 link-down scenario, only that PE's link to RR2 does.
            # RR1-RR2 keeps its normal keepalive cadence throughout,
            # disturbed only by the single withdrawal/re-advertisement
            # event -- excluding it would make this fault indistinguishable
            # on the wire from RR-down (RR1-RR2 itself failing).
            if rr_tcp and rr_tcp.is_established():
                if self.mechanism == 'hold_timer':
                    # RR2's own detection delay before it reflects the
                    # withdrawal onward -- same observable content as 'rst'
                    # at this vantage, only later.
                    delay = self.config.timing.hold_timer + random.uniform(2, 10)
                else:
                    delay = random.uniform(0.5, 2.0)
                other_ka = self._other_keepalives(t, delay, exclude_session_id)
                packets.extend(other_ka)
                t += delay
                withdraw_pkts, t = self.reflect_pe_withdrawal_to_rr(
                    rr_tcp, pe, t, event=True, fault_type=self._ld_fault_type, node=self.affected_pe_id,
                    macs_out=self._reflected_macs_by_pe, phase='trigger')
                packets.extend(withdraw_pkts)
                # RFC 4456 second hop: RR1 must also withdraw this PE's
                # routes toward its own clients (PE1-3), not just RR2.
                # 2ms relay-processing gap between first-hop landing and
                # second-hop relay beginning (see base.py's reflection
                # helpers for the same convention).
                t += 0.002
                second_hop_pkts, t = self.reflect_to_own_clients(
                    pe, t, action='withdraw', event=True, fault_type=self._ld_fault_type, node=self.affected_pe_id,
                    macs_override=self._reflected_macs_by_pe.get(pe.id), phase='trigger')
                packets.extend(second_hop_pkts)
        else:
            bgp_sess = self._direct_session()
            exclude_session_id = bgp_sess.session_id if bgp_sess else None
            if bgp_sess:
                tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                if self.mechanism == 'hold_timer':
                    delay = self.config.timing.hold_timer + random.uniform(2, 10)
                    other_ka = self._other_keepalives(t, delay, exclude_session_id)
                    packets.extend(other_ka)
                    t += delay
                    notification = build_notification(ERR_HOLD_TIMER_EXPIRED, 0)
                    pkts = tcp_sess.send_data(notification, t, 'server_to_client')
                    packets.extend(self._mark_event(pkts, self._ld_fault_type, self.affected_pe_id, 'BGP NOTIFICATION: Hold Timer Expired', phase='trigger'))
                    t += 0.001
                    close_pkts = tcp_sess.close_graceful(t, initiator='server')
                    packets.extend(self._mark_event(close_pkts, self._ld_fault_type, self.affected_pe_id, 'Graceful FIN Close', phase='trigger'))
                    t += 0.01
                else:
                    rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                    packets.extend(self._mark_event(rst_pkts, self._ld_fault_type, self.affected_pe_id, 'TCP RST', phase='trigger'))
                    t += 0.01
                withdraw_pkts = self._withdraw_pe_routes_direct(pe, t, event=True)
                packets.extend(withdraw_pkts)

        # Silence window, scaled by recovery type.
        if self.recovery == 'fast':
            silence = self._param_rng.uniform(20, 30)
        elif self.recovery == 'slow':
            silence = self._param_rng.uniform(120, 300)
        else:
            silence = self._param_rng.uniform(480, 600)

        other_ka2 = self._other_keepalives(t, silence, exclude_session_id)
        packets.extend(other_ka2)
        t += silence

        if self.recovery in ('fast', 'slow'):
            if self.is_reflected:
                rr_sess = self._rr_rr_session()
                rr_tcp = self.tcp_sessions.get(rr_sess.session_id) if rr_sess else None
                if rr_tcp and rr_tcp.is_established():
                    recover_pkts, t = self.reflect_pe_routes_to_rr(
                        rr_tcp, t, event=True, pe_list=[pe], fault_type=self._ld_fault_type, node=self.affected_pe_id,
                        macs_in=self._reflected_macs_by_pe, phase='recovery')
                    packets.extend(recover_pkts)
                    # RFC 4456 second hop: re-advertise onward to PE1-3 too.
                    # 2ms relay-processing gap, matching the withdrawal path above.
                    t += 0.002
                    second_hop_pkts, t = self.reflect_to_own_clients(
                        pe, t, action='advertise', event=True, fault_type=self._ld_fault_type, node=self.affected_pe_id,
                        macs_override=self._reflected_macs_by_pe.get(pe.id), phase='recovery')
                    packets.extend(second_hop_pkts)
            else:
                bgp_sess = self._direct_session()
                if bgp_sess:
                    recover_pkts, t = self._recover_session_direct(bgp_sess, t, event=True)
                    packets.extend(recover_pkts)

        post_duration = 60
        if self.recovery in ('fast', 'slow'):
            # Post-recovery continuation baseline (Moderate churn again).
            remaining = int(self.target_frames * 0.26) - len(packets)
            if remaining > 0:
                post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                    * self.config.timing.keepalive_timer)
                last_update_times2: dict = {}
                self.generate_route_churn(packets, t, post_duration,
                                          last_update_times=last_update_times2)
                packets.extend(self.generate_keepalives_for_duration(
                    t, post_duration, last_update_times=last_update_times2))

        if self.recovery == 'none':
            self._fault_start_t = _first_bgp_ts(withdraw_pkts, fallback=fault_start_t)
            self._fault_end_t = None
        else:
            fault_end_t = t + self.BASELINE_CHECK_WINDOW
            self._fault_start_t = _first_bgp_ts(withdraw_pkts, fallback=fault_start_t)
            self._fault_end_t = fault_end_t

        packets.sort(key=lambda p: p.timestamp)

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)
            packets.sort(key=lambda p: p.timestamp)

        return packets[:self.target_frames]


# ---------------------------------------------------------------------------
# PE-specific subclasses -- full mechanism x recovery x node matrix.
# Slot names mirror the pre-existing registry naming where a class already
# existed (no-recovery-*, fast-recovery-*, slow-recovery-*, hold-timer-*);
# rst-slow-* and hold-timer-fast-* are new, completing the 2x3 matrix.
# ---------------------------------------------------------------------------

# RST + no recovery (was LinkDownNoRecoveryPE*)
class LinkDownNoRecoveryPE1(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='rst', recovery='none')

class LinkDownNoRecoveryPE2(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='rst', recovery='none')

class LinkDownNoRecoveryPE3(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='rst', recovery='none')

class LinkDownNoRecoveryPE4(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE4', mechanism='rst', recovery='none')

class LinkDownNoRecoveryPE5(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE5', mechanism='rst', recovery='none')


# RST + fast recovery (was LinkDownFastRecoveryPE*)
class LinkDownFastRecoveryPE1(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='rst', recovery='fast')

class LinkDownFastRecoveryPE2(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='rst', recovery='fast')

class LinkDownFastRecoveryPE3(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='rst', recovery='fast')

class LinkDownFastRecoveryPE4(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4', mechanism='rst', recovery='fast')

class LinkDownFastRecoveryPE5(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE5', mechanism='rst', recovery='fast')


# Non-idle injection timing: fault fires mid-churn-burst instead of after idle warmup.
class LinkDownFastRecoveryMidChurnPE1(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='rst', recovery='fast', mid_churn=True)

class LinkDownFastRecoveryMidChurnPE2(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='rst', recovery='fast', mid_churn=True)

class LinkDownFastRecoveryMidChurnPE3(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='rst', recovery='fast', mid_churn=True)


# RST + slow recovery (new: RST-mechanism counterpart to the old hold-timer-based "slow")
class LinkDownRstSlowPE1(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='rst', recovery='slow')

class LinkDownRstSlowPE2(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='rst', recovery='slow')

class LinkDownRstSlowPE3(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='rst', recovery='slow')

class LinkDownRstSlowPE4(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4', mechanism='rst', recovery='slow')

class LinkDownRstSlowPE5(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE5', mechanism='rst', recovery='slow')


# Hold-timer + no recovery (was LinkDownHoldTimerExpiryPE*)
class LinkDownHoldTimerExpiryPE1(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='hold_timer', recovery='none')

class LinkDownHoldTimerExpiryPE2(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='hold_timer', recovery='none')

class LinkDownHoldTimerExpiryPE3(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='hold_timer', recovery='none')

class LinkDownHoldTimerExpiryPE4(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE4', mechanism='hold_timer', recovery='none')

class LinkDownHoldTimerExpiryPE5(LinkDownScenario):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE5', mechanism='hold_timer', recovery='none')


# Hold-timer + fast recovery (new)
class LinkDownHoldTimerFastPE1(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='hold_timer', recovery='fast')

class LinkDownHoldTimerFastPE2(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='hold_timer', recovery='fast')

class LinkDownHoldTimerFastPE3(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='hold_timer', recovery='fast')

class LinkDownHoldTimerFastPE4(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4', mechanism='hold_timer', recovery='fast')

class LinkDownHoldTimerFastPE5(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE5', mechanism='hold_timer', recovery='fast')


# Hold-timer + slow recovery (was LinkDownSlowRecoveryPE*)
class LinkDownSlowRecoveryPE1(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1', mechanism='hold_timer', recovery='slow')

class LinkDownSlowRecoveryPE2(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2', mechanism='hold_timer', recovery='slow')

class LinkDownSlowRecoveryPE3(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3', mechanism='hold_timer', recovery='slow')

class LinkDownSlowRecoveryPE4(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4', mechanism='hold_timer', recovery='slow')

class LinkDownSlowRecoveryPE5(LinkDownScenario):
    def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE5', mechanism='hold_timer', recovery='slow')


class LinkDownSimultaneous(BaseScenario):
    """Two PEs lose their links to the RR at the same time."""

    FAULT_TYPE: str = 'Link Down'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_pes: list[str] = None):
        super().__init__(config, target_frames)
        if affected_pes and len(affected_pes) >= 2:
            self.affected_pe_ids = affected_pes[:2]
        else:
            pes = config.pe_nodes
            self.affected_pe_ids = ([pes[0].id, pes[1].id] if len(pes) >= 2
                                    else [pes[0].id])

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        # Initial route table (all types)
        init_routes, t = self.generate_initial_routes(t)
        packets.extend(init_routes)

        # Warmup
        warmup_duration = self._param_rng.randint(120, 480)
        ka_pkts = self.generate_keepalives_for_duration(t, warmup_duration)
        packets.extend(ka_pkts)
        t += warmup_duration

        # FAULT: Both PEs drop simultaneously (within ~1 second of each other)
        fault_start_t = t
        first_withdrawal_pkts: list = []
        # {pe_id: [nlri_bytes, ...]} captured here and reused by the
        # recovery loop below, so recovery genuinely re-advertises the same
        # NLRI set that was withdrawn.
        nlris_by_pe: dict = {}
        for pe_id in self.affected_pe_ids:
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == pe_id:
                    tcp_sess = self.tcp_sessions[bgp_sess.session_id]
                    rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
                    packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, pe_id, 'TCP RST', phase='trigger'))

                    pe = bgp_sess.local_router
                    # RR withdraws ALL routes learned from this dead PE, per
                    # RFC 4271 SS9.2 -- not just its MAC/IP (Type 2) routes.
                    # Mirrors _withdraw_pe_routes_direct()'s completeness
                    # (Type 3 IMET always; Type 1/4 for multihomed PEs only).
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
                    nlris_by_pe[pe.id] = nlris
                    wd_t = t + 0.01
                    for session_id, other_tcp in self.tcp_sessions.items():
                        if pe.id in session_id or not other_tcp.is_established():
                            continue
                        for nlri in nlris:
                            path_attrs = build_evpn_withdraw_attrs(nlri)
                            update = build_update(path_attributes=path_attrs)
                            pkts = other_tcp.send_data(update, wd_t,
                                                       'server_to_client')
                            packets.extend(self._mark_event(pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='trigger'))
                            wd_t += 0.005
                            packets.extend(other_tcp.generate_ack(
                                wd_t, 'client_to_server'))
                            wd_t += 0.001
                            if not first_withdrawal_pkts:
                                first_withdrawal_pkts = pkts
                    break
            t += random.uniform(0.1, 1.0)  # Nearly simultaneous

        # Silence + other sessions continue
        silence_duration = self._param_rng.uniform(20, 30)
        other_sessions = {
            sid: tcp for sid, tcp in self.tcp_sessions.items()
            if all(pe_id not in sid for pe_id in self.affected_pe_ids)
            and tcp.is_established()
        }

        ka_msg = build_keepalive()
        for sid, tcp_sess in other_sessions.items():
            for ka_t in keepalive_timestamps(t, silence_duration,
                                             self.config.timing.keepalive_timer):
                pkts = tcp_sess.send_data(ka_msg, ka_t, 'client_to_server')
                packets.extend(pkts)
                packets.extend(tcp_sess.generate_ack(ka_t + ack_delay(),
                                                     'server_to_client'))
        t += silence_duration

        # Recovery for both PEs — only route re-advertisements are fault events
        for pe_id in self.affected_pe_ids:
            for bgp_sess in self.topology.get_sessions_at_vantage():
                if bgp_sess.local_router.id == pe_id:
                    pe = bgp_sess.local_router
                    rr = bgp_sess.remote_router
                    new_tcp = TCPSession(client_ip=pe.bgp_id,
                                         server_ip=rr.bgp_id, server_port=179)
                    self.tcp_sessions[bgp_sess.session_id] = new_tcp

                    connect_pkts = new_tcp.connect(timestamp=t)
                    packets.extend(connect_pkts)
                    t += 0.02

                    # OPEN exchange — session housekeeping, not fault events
                    open_msg = build_open(
                        self.config.as_number, self.config.timing.hold_timer,
                        pe.bgp_id, default_evpn_capabilities(self.config.as_number))
                    pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
                    packets.extend(pkts)
                    t += ack_delay()
                    packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
                    t += 0.005

                    open_msg = build_open(
                        self.config.as_number, self.config.timing.hold_timer,
                        rr.bgp_id, default_evpn_capabilities(self.config.as_number))
                    pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
                    packets.extend(pkts)
                    t += ack_delay()
                    packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
                    t += 0.002

                    # KA exchange — session housekeeping, not fault events
                    ka = build_keepalive()
                    pkts = new_tcp.send_data(ka, t, 'client_to_server')
                    packets.extend(pkts)
                    pkts = new_tcp.send_data(ka, t + 0.001, 'server_to_client')
                    packets.extend(pkts)
                    t += 0.01

                    # Re-advertise routes — observable recovery signal.
                    # Re-advertises the EXACT NLRI set withdrawn above
                    # (nlris_by_pe).
                    nlris = nlris_by_pe.get(pe.id, [])
                    route_pkts = []
                    for nlri in nlris:
                        path_attrs = build_standard_evpn_path_attrs(
                            pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                            originator_id=pe.bgp_id, cluster_id=rr.bgp_id)
                        update = build_update(path_attributes=path_attrs)
                        pkts = new_tcp.send_data(update, t, 'client_to_server')
                        route_pkts.extend(pkts)
                        t += 0.005
                        route_pkts.extend(new_tcp.generate_ack(t, 'server_to_client'))
                        t += 0.001
                    packets.extend(self._mark_event(route_pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='recovery'))
                    t += 0.5

                    # RFC 4456 second hop: fan the same re-advertised NLRI
                    # set out to the other established sessions too --
                    # mirrors the withdrawal loop's own fan-out shape above.
                    second_hop_pkts = []
                    for session_id, other_tcp in self.tcp_sessions.items():
                        if pe.id in session_id or not other_tcp.is_established():
                            continue
                        for nlri in nlris:
                            path_attrs = build_standard_evpn_path_attrs(
                                pe.bgp_id, nlri, self.config.as_number, self.config.evpn.vni,
                                originator_id=pe.bgp_id, cluster_id=rr.bgp_id)
                            update = build_update(path_attributes=path_attrs)
                            pkts = other_tcp.send_data(update, timestamp=t, direction='server_to_client')
                            second_hop_pkts.extend(pkts)
                            t += 0.005
                            second_hop_pkts.extend(other_tcp.generate_ack(t, 'client_to_server'))
                            t += 0.001
                    if second_hop_pkts:
                        packets.extend(self._mark_event(second_hop_pkts, self.FAULT_TYPE, pe_id, 'Route UPDATE', phase='recovery'))
                    break

        # Post-recovery
        remaining = int(self.target_frames * 0.26) - len(packets)
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                * self.config.timing.keepalive_timer)
            ka_pkts = self.generate_keepalives_for_duration(t, post_duration)
            packets.extend(ka_pkts)

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        # RSTs are TCP-only (not in CSV) — derive fw.json start from the actual first
        # payload-bearing withdrawal packet so timing constants can change safely.
        self._fault_start_t = _first_bgp_ts(first_withdrawal_pkts, fallback=fault_start_t)
        self._fault_end_t = fault_end_t

        packets.sort(key=lambda p: p.timestamp)

        # Pad with pure TCP window-update frames to reach target_frames
        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)
            packets.sort(key=lambda p: p.timestamp)

        packets = packets[:self.target_frames]
        return packets


# class LinkDownGracefulRestart(BaseScenario):
#     """Graceful Restart (RFC 4724), silent-drop case: affected PE's session
#     drops abruptly via a bare TCP RST -- no BGP NOTIFICATION at all -- with
#     NO EVPN WITHDRAWs (routes kept as stale, not withdrawn -- the key
#     distinguishing feature from ordinary Link Down), reconnects advertising
#     the Graceful Restart capability with the Restart State bit set (see
#     cap_graceful_restart()'s is_restart param), re-advertises all its
#     routes, and an End-of-RIB marker signals resync complete.

#     This is RFC 4724's original base case specifically: no NOTIFICATION is
#     exchanged before the session drops. For the RFC 8538 case -- session
#     torn down via an explicit NOTIFICATION but still treated as graceful
#     because both sides negotiated the Notification (N) bit -- see
#     LinkDownGracefulRestartNotified.

#     PE4/PE5 (no direct session at vantage): there is nothing to RST
#     directly, and no ongoing per-PE traffic is reflected onto RR1-RR2
#     outside of the one-time cold-start reflection -- so the outage itself
#     produces no observable packets at this vantage either way. The GR
#     signal that *is* observable is the recovery: RR2 reflecting the PE's
#     full route set back over RR1-RR2 (reflect_pe_routes_to_rr()), which is
#     what actually distinguishes this from a bare "nothing happened."
#     """

#     FAULT_TYPE: str = 'Graceful Restart'
#     SECTION: int = 2

#     # RFC 8538 variant hook -- overridden by LinkDownGracefulRestartNotified.
#     # None = silent RST (RFC 4724 base case, this class's default).
#     NOTIFICATION_ERROR: Optional[tuple] = None
#     # RFC 8538 SS3 applies "regardless of the reason" in the NOTIFICATION --
#     # overridden by LinkDownGracefulRestartNotifiedHoldTimer to precede the
#     # notification with a hold-timer-style silence window instead of firing
#     # it abruptly, distinguishing "graceful after hold-timer detection" from
#     # "graceful after explicit admin action".
#     NOTIFICATION_SILENCE_FIRST: bool = False

#     def __init__(self, config: TopologyConfig, target_frames: int = 30000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         pe = config.get_router(self.affected_pe_id)
#         self.is_reflected = bool(pe and pe.peers and pe.peers[0] != config.capture_vantage)

#     def _direct_session(self) -> Optional[BGPSession]:
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.id == self.affected_pe_id:
#                 return bgp_sess
#         return None

#     def _rr_rr_session(self) -> Optional[BGPSession]:
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
#                 return bgp_sess
#         return None

#     def generate(self) -> list[TCPPacket]:
#         packets = []
#         t = self.start_time

#         notif_session_id = None
#         if self.NOTIFICATION_ERROR is not None:
#             affected_sess = self._direct_session()
#             notif_session_id = affected_sess.session_id if affected_sess else None
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

#         pe = self.config.get_router(self.affected_pe_id)
#         fault_start_t = t

#         if self.is_reflected:
#             t += random.uniform(2, 8)  # process-restart gap
#             rr_sess = self._rr_rr_session()
#             rr_tcp = self.tcp_sessions.get(rr_sess.session_id) if rr_sess else None
#             if rr_tcp and rr_tcp.is_established():
#                 recovery_pkts, t = self.reflect_pe_routes_to_rr(
#                     rr_tcp, t, event=True, pe_list=[pe], fault_type=self.FAULT_TYPE, node=self.affected_pe_id)
#                 packets.extend(recovery_pkts)
#         else:
#             bgp_sess = self._direct_session()
#             if bgp_sess:
#                 tcp_sess = self.tcp_sessions[bgp_sess.session_id]
#                 # CRITICAL: no EVPN WITHDRAWs -- distinguishes GR from Link Down.
#                 if self.NOTIFICATION_ERROR is not None:
#                     # RFC 8538: session torn down via explicit NOTIFICATION,
#                     # still graceful because both sides negotiated the N bit.
#                     if self.NOTIFICATION_SILENCE_FIRST:
#                         hold_silence = float(self.config.timing.hold_timer) + random.uniform(2, 10)
#                         other_ka = LinkDownScenario._other_keepalives(
#                             self, t, hold_silence, bgp_sess.session_id)
#                         packets.extend(other_ka)
#                         t += hold_silence
#                     err_code, err_subcode = self.NOTIFICATION_ERROR
#                     notification = build_notification(err_code, err_subcode)
#                     pkts = tcp_sess.send_data(notification, t, 'server_to_client')
#                     notif_name = _NOTIF_NAME.get((err_code, err_subcode), 'Unknown')
#                     packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id,
#                                                     f'BGP NOTIFICATION: {notif_name}'))
#                     t += 0.001
#                     close_pkts = tcp_sess.close_graceful(t, initiator='server')
#                     packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_pe_id,
#                                                     'Graceful FIN Close'))
#                 else:
#                     rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
#                     packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#                 t += random.uniform(2, 8)

#                 pe_r = bgp_sess.local_router
#                 rr_r = bgp_sess.remote_router
#                 new_tcp = TCPSession(client_ip=pe_r.loopback, server_ip=rr_r.loopback,
#                                      server_port=179)
#                 self.tcp_sessions[bgp_sess.session_id] = new_tcp

#                 connect_pkts = new_tcp.connect(timestamp=t)
#                 packets.extend(connect_pkts)
#                 t += 0.02

#                 notif_tolerant = self.NOTIFICATION_ERROR is not None
#                 gr_caps = default_evpn_capabilities(self.config.as_number, is_restart=True,
#                                                     is_notification_tolerant=notif_tolerant)
#                 open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                       pe_r.bgp_id, gr_caps)
#                 pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
#                 packets.extend(pkts)
#                 t += ack_delay()
#                 packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
#                 t += 0.005

#                 rr_caps = default_evpn_capabilities(self.config.as_number,
#                                                     is_notification_tolerant=notif_tolerant)
#                 open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
#                                       rr_r.bgp_id, rr_caps)
#                 pkts = new_tcp.send_data(open_msg, t, 'server_to_client')
#                 packets.extend(pkts)
#                 t += ack_delay()
#                 packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
#                 t += 0.002

#                 ka = build_keepalive()
#                 pkts = new_tcp.send_data(ka, t, 'client_to_server')
#                 packets.extend(pkts)
#                 t += ack_delay()
#                 packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
#                 t += 0.001
#                 pkts = new_tcp.send_data(ka, t, 'server_to_client')
#                 packets.extend(pkts)
#                 t += ack_delay()
#                 packets.extend(new_tcp.generate_ack(t, 'client_to_server'))
#                 t += 0.01

#                 # Re-advertise all routes restricted to just this session;
#                 # EoR is emitted automatically at the end of
#                 # generate_initial_routes() (base.py _generate_eor_markers()).
#                 saved_sessions = dict(self.tcp_sessions)
#                 for sid in list(self.tcp_sessions):
#                     if sid != bgp_sess.session_id:
#                         del self.tcp_sessions[sid]
#                 reroute_pkts, t = self.generate_initial_routes(t)
#                 self.tcp_sessions = saved_sessions
#                 packets.extend(self._mark_event(reroute_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE'))

#         fault_end_t = t + self.BASELINE_CHECK_WINDOW
#         self._fault_start_t = fault_start_t
#         self._fault_end_t = fault_end_t

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


# class LinkDownGracefulRestartPE1(LinkDownGracefulRestart):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

# class LinkDownGracefulRestartPE2(LinkDownGracefulRestart):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')

# class LinkDownGracefulRestartPE3(LinkDownGracefulRestart):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')

# class LinkDownGracefulRestartPE4(LinkDownGracefulRestart):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE4')

# class LinkDownGracefulRestartPE5(LinkDownGracefulRestart):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE5')


# class LinkDownGracefulRestartNotified(LinkDownGracefulRestart):
#     """Graceful Restart (RFC 8538 variant): session torn down via an
#     explicit BGP NOTIFICATION (Administrative Reset) instead of a bare RST,
#     but still treated as graceful -- no EVPN WITHDRAWs, stale routes kept --
#     because both sides negotiate the Notification (N) bit in their GR
#     capability. PE1-3 only (direct session at vantage): the NOTIFICATION
#     itself is only observable on a direct session, same constraint as the
#     RST it replaces.
#     """
#     NOTIFICATION_ERROR = (ERR_CEASE, CEASE_ADMIN_RESET)


# class LinkDownGracefulRestartNotifiedPE1(LinkDownGracefulRestartNotified):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

# class LinkDownGracefulRestartNotifiedPE2(LinkDownGracefulRestartNotified):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')

# class LinkDownGracefulRestartNotifiedPE3(LinkDownGracefulRestartNotified):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')


# class LinkDownGracefulRestartNotifiedHoldTimer(LinkDownGracefulRestart):
#     """Graceful Restart (RFC 8538 variant): session torn down via an
#     explicit Hold Timer Expired NOTIFICATION (preceded by the normal
#     ~30-40s silence window, unlike the abrupt Cease/Administrative-Reset
#     variant), but still treated as graceful -- no EVPN WITHDRAWs, stale
#     routes kept -- because both sides negotiate the Notification (N) bit.
#     RFC 8538 SS3's graceful-on-notification behavior applies "regardless
#     of the reason specified in the NOTIFICATION message", so this is a
#     distinct, equally valid trigger from LinkDownGracefulRestartNotified's
#     Cease/Administrative-Reset case -- the ground truth label is
#     operationally distinguishable: "graceful restart after hold-timer
#     detection" vs. "graceful restart after explicit administrative action".
#     """
#     NOTIFICATION_ERROR = (ERR_HOLD_TIMER_EXPIRED, 0)
#     NOTIFICATION_SILENCE_FIRST = True


# class LinkDownGracefulRestartNotifiedHoldTimerPE1(LinkDownGracefulRestartNotifiedHoldTimer):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE1')

# class LinkDownGracefulRestartNotifiedHoldTimerPE2(LinkDownGracefulRestartNotifiedHoldTimer):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE2')

# class LinkDownGracefulRestartNotifiedHoldTimerPE3(LinkDownGracefulRestartNotifiedHoldTimer):
#     def __init__(self, config, target_frames=30000): super().__init__(config, target_frames, affected_pe='PE3')


# class LinkDownGracefulRestartTimeout(BaseScenario):
#     """Graceful Restart (RFC 4724 SS4.2): restart timer expiry, no recovery.

#     Same silent-drop opening as LinkDownGracefulRestart (bare RST, no EVPN
#     WITHDRAWs -- routes held as stale per the GR contract) but the PE never
#     reconnects. Per RFC 4724 SS4.2: "If, before the expiration of the
#     Restart Time, the BGP speaker... does not re-establish the session...
#     it MUST... delete all the stale routes." This class models exactly that
#     deferred flush -- the distinguishing signature is that the withdrawal
#     is deliberately DELAYED until the restart-timer deadline (120s, the
#     same value already encoded via cap_graceful_restart(restart_time=120)
#     elsewhere in this codebase), not an ordinary immediate no-recovery
#     withdrawal like LinkDownNoRecoveryPE1.
#     """

#     FAULT_TYPE: str = 'Graceful Restart'
#     SECTION: int = 2
#     RESTART_TIME: int = 120

#     def __init__(self, config: TopologyConfig, target_frames: int = 8000,
#                  affected_pe: str = None):
#         super().__init__(config, target_frames)
#         self.affected_pe_id = affected_pe or config.pe_nodes[0].id
#         pe = config.get_router(self.affected_pe_id)
#         self.is_reflected = bool(pe and pe.peers and pe.peers[0] != config.capture_vantage)

#     def _direct_session(self) -> Optional[BGPSession]:
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.id == self.affected_pe_id:
#                 return bgp_sess
#         return None

#     def _rr_rr_session(self) -> Optional[BGPSession]:
#         for bgp_sess in self.topology.get_sessions_at_vantage():
#             if bgp_sess.local_router.role == 'rr' and bgp_sess.remote_router.role == 'rr':
#                 return bgp_sess
#         return None

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

#         pe = self.config.get_router(self.affected_pe_id)
#         fault_start_t = t

#         if self.is_reflected:
#             # PE4/PE5: nothing directly observable at fault time -- same as
#             # LinkDownGracefulRestart's reflected-path behavior.
#             pass
#         else:
#             bgp_sess = self._direct_session()
#             if bgp_sess:
#                 tcp_sess = self.tcp_sessions[bgp_sess.session_id]
#                 rst_pkts = tcp_sess.close_reset(timestamp=t, initiator='server')
#                 packets.extend(self._mark_event(rst_pkts, self.FAULT_TYPE, self.affected_pe_id, 'TCP RST'))
#                 t += 0.01

#         # Wait past the restart timer -- no reconnect ever occurs.
#         t += self.RESTART_TIME + random.uniform(2, 10)

#         # RFC 4724 SS4.2: restart timer expired without recovery -- flush
#         # the stale routes.
#         if self.is_reflected:
#             rr_sess = self._rr_rr_session()
#             rr_tcp = self.tcp_sessions.get(rr_sess.session_id) if rr_sess else None
#             if rr_tcp and rr_tcp.is_established():
#                 withdraw_pkts, t = self.reflect_pe_withdrawal_to_rr(rr_tcp, pe, t, event=True, fault_type=self.FAULT_TYPE, node=self.affected_pe_id)
#                 packets.extend(withdraw_pkts)
#         else:
#             withdraw_pkts = LinkDownScenario._withdraw_pe_routes_direct(self, pe, t, event=True)
#             packets.extend(withdraw_pkts)
#             t += 0.5

#         self._fault_start_t = fault_start_t
#         self._fault_end_t = None  # session never re-establishes

#         # Affected PE never reconnects -- exclude its (closed) session from
#         # post-fault churn (same fix as LinkDownNoRecoveryESDFOverlap).
#         surviving_pe_sessions = [(s, s.local_router) for s in self.topology.get_sessions_at_vantage()
#                                  if s.local_router.role == 'pe' and s.local_router.id != self.affected_pe_id]

#         remaining = int(self.target_frames * 0.26) - len(packets)
#         post_duration = 60
#         if remaining > 0:
#             post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
#                                 * self.config.timing.keepalive_timer)
#             last_update_times2: dict = {}
#             self.generate_route_churn(packets, t, post_duration,
#                                       last_update_times=last_update_times2,
#                                       pe_sessions=surviving_pe_sessions)
#             packets.extend(self.generate_keepalives_for_duration(
#                 t, post_duration, last_update_times=last_update_times2))

#         packets.sort(key=lambda p: p.timestamp)

#         pad_count = self.target_frames - len(packets)
#         if pad_count > 0:
#             pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
#             packets.extend(pad_pkts)
#             packets.sort(key=lambda p: p.timestamp)

#         return packets[:self.target_frames]


# class LinkDownGracefulRestartTimeoutPE1(LinkDownGracefulRestartTimeout):
#     def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE1')

# class LinkDownGracefulRestartTimeoutPE2(LinkDownGracefulRestartTimeout):
#     def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE2')

# class LinkDownGracefulRestartTimeoutPE3(LinkDownGracefulRestartTimeout):
#     def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE3')


class LinkDownHardReset(BaseScenario):
    """RFC 8538 SS4 Hard Reset: the affected PE's session was established
    with the Notification (N) bit negotiated (both sides, on the ORIGINAL
    OPEN exchange -- same as LinkDownGracefulRestartNotified), so a peer
    could reasonably expect notification-triggered teardowns to be handled
    gracefully. Instead, the session is torn down with an explicit Cease /
    Hard Reset (subcode 9) NOTIFICATION -- RFC 8538's defined mechanism for
    a peer to explicitly override the negotiated graceful handling for this
    one teardown. Unlike every other Graceful-Restart-family class, a full
    immediate withdrawal DOES appear here despite N having been negotiated
    -- that's precisely the point of Hard Reset. Recovery proceeds as an
    ordinary reconnect, not a restart-flagged one.
    """

    FAULT_TYPE: str = 'Link Down'
    SECTION: int = 2

    def __init__(self, config: TopologyConfig, target_frames: int = 8000,
                 affected_pe: str = None):
        super().__init__(config, target_frames)
        self.affected_pe_id = affected_pe or config.pe_nodes[0].id

    def _direct_session(self) -> Optional[BGPSession]:
        for bgp_sess in self.topology.get_sessions_at_vantage():
            if bgp_sess.local_router.id == self.affected_pe_id:
                return bgp_sess
        return None

    def generate(self) -> list[TCPPacket]:
        packets = []
        t = self.start_time

        affected_sess = self._direct_session()
        notif_session_id = affected_sess.session_id if affected_sess else None
        setup_pkts, t = self.establish_all_sessions(
            t, notification_tolerant_session_id=notif_session_id)
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

        bgp_sess = self._direct_session()
        if bgp_sess:
            tcp_sess = self.tcp_sessions[bgp_sess.session_id]
            notification = build_notification(ERR_CEASE, CEASE_HARD_RESET)
            pkts = tcp_sess.send_data(notification, t, 'server_to_client')
            packets.extend(self._mark_event(pkts, self.FAULT_TYPE, self.affected_pe_id, 'BGP NOTIFICATION: Cease/Hard Reset', phase='trigger'))
            t += 0.001
            close_pkts = tcp_sess.close_graceful(t, initiator='server')
            packets.extend(self._mark_event(close_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Graceful FIN Close', phase='trigger'))
            t += 0.01

            # Hard Reset overrides the negotiated graceful handling: full
            # immediate withdrawal, NOT held stale.
            withdraw_pkts = LinkDownScenario._withdraw_pe_routes_direct(self, pe, t, event=True)
            packets.extend(withdraw_pkts)
            t += 0.5

        silence = self._param_rng.uniform(20, 30)
        exclude_session_id = bgp_sess.session_id if bgp_sess else None
        other_ka = LinkDownScenario._other_keepalives(self, t, silence, exclude_session_id)
        packets.extend(other_ka)
        t += silence

        if bgp_sess:
            # Ordinary reconnect -- not restart-flagged, this was never
            # actually a graceful restart.
            pe_r = bgp_sess.local_router
            rr_r = bgp_sess.remote_router
            new_tcp = TCPSession(client_ip=pe_r.bgp_id, server_ip=rr_r.bgp_id,
                                 server_port=179)
            self.tcp_sessions[bgp_sess.session_id] = new_tcp

            connect_pkts = new_tcp.connect(timestamp=t)
            packets.extend(connect_pkts)
            t += 0.02

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  pe_r.bgp_id, default_evpn_capabilities(self.config.as_number))
            pkts = new_tcp.send_data(open_msg, t, 'client_to_server')
            packets.extend(pkts)
            t += ack_delay()
            packets.extend(new_tcp.generate_ack(t, 'server_to_client'))
            t += 0.005

            open_msg = build_open(self.config.as_number, self.config.timing.hold_timer,
                                  rr_r.bgp_id, default_evpn_capabilities(self.config.as_number))
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

            reroute_pkts, t = self.generate_initial_routes(t)
            packets.extend(self._mark_event(reroute_pkts, self.FAULT_TYPE, self.affected_pe_id, 'Route UPDATE', phase='recovery'))

        fault_end_t = t + self.BASELINE_CHECK_WINDOW
        self._fault_start_t = fault_start_t
        self._fault_end_t = fault_end_t

        remaining = int(self.target_frames * 0.26) - len(packets)
        post_duration = 60
        if remaining > 0:
            post_duration = max(60, (remaining / max(len(self.tcp_sessions) * 4, 1))
                                * self.config.timing.keepalive_timer)
            last_update_times2: dict = {}
            self.generate_route_churn(packets, t, post_duration,
                                      last_update_times=last_update_times2)
            packets.extend(self.generate_keepalives_for_duration(
                t, post_duration, last_update_times=last_update_times2))

        packets.sort(key=lambda p: p.timestamp)

        pad_count = self.target_frames - len(packets)
        if pad_count > 0:
            pad_pkts = self.generate_tcp_window_updates(t, post_duration, pad_count)
            packets.extend(pad_pkts)
            packets.sort(key=lambda p: p.timestamp)

        return packets[:self.target_frames]


class LinkDownHardResetPE1(LinkDownHardReset):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE1')

class LinkDownHardResetPE2(LinkDownHardReset):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE2')

class LinkDownHardResetPE3(LinkDownHardReset):
    def __init__(self, config, target_frames=8000): super().__init__(config, target_frames, affected_pe='PE3')
