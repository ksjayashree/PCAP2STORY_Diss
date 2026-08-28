"""Layer 4 rule: Link Down (bfd, holdtimer, tcpfail).

Signals confirmed in Layer 2/3 checkpoints (LAYER4_DESIGN.md #1):
BFD_STATE_CHANGE->Down / TCP_FIN / TCP_RESET, node_involved src_node-
attributed directly to the affected PE, followed by BGP_WITHDRAWAL for
that PE's routes (matched via route_distinguisher against
ground_truth.expected_rd, not assumed from node_involved alone since
reflected withdrawals fall back to the relaying RR -- see
GENERICITY_RULES.md's documented limitation).
"""

# CONCURRENCY CONTRACT (added 2026-08-14, orchestrator.py now dispatches
# all 7 rule modules' detect() calls concurrently via ThreadPoolExecutor):
# detect() must remain READ-ONLY with respect to its fused_events/topo
# arguments -- no .sort()/.append()/.pop()/.update() on them, no writes
# into individual event dicts or topo entries. Also must not introduce
# any shared mutable state (module-level cache, counter, or other global
# written during detect()) without re-verifying thread safety against the
# other 6 modules running concurrently. Verified safe as of this date by
# direct inspection of every detect() body across all 7 modules -- see
# orchestrator.py's run_all_rules() docstring for the full contract.

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rules.schema import build_result

# Tightened 2026-08-09 from 60s, measured directly against the full real
# corpus (90/90 link_down folders, both datasets, all three mechanisms):
# real recovered_time - t_fault ranges 4.068s-38.689s overall (bfd
# 13.53-31.60s, holdtimer 19.05-38.69s, tcpfail 4.07-20.59s, n=15 each).
# This constant is only the cascade-consumption fallback for the
# genuinely-NOT_RECOVERED case (recovery detection itself stays
# unbounded, unaffected by this value) -- and every real NOT_RECOVERED
# file's capture ends within 39.43s of t_fault at the latest (measured
# across all 45 real NOT_RECOVERED files), so no real cascade activity
# between the old 60s and any actual event has ever been observed either
# way. 50s gives ~1.29x margin over the largest genuine FRR recovery gap
# measured (38.689s), with the remaining headroom deliberately reserved
# for cross-vendor/cross-hardware recovery-timing variance this corpus
# cannot exercise (this lab is FRR-only) -- not additional margin against
# measurement noise within the existing FRR-only data, which is already
# tight and consistent.
RECOVERY_WINDOW_SECONDS = 50
# Tightened 2026-08-09 from 10s, measured directly against all 90 real
# link_down incidents: gap from t_fault to the furthest BGP_WITHDRAWAL
# attributed via ground_truth.expected_rd ranges 0.1113s-2.7637s (the
# single 2.7637s outlier is link_down_bfd_xpe10_notrecovered; every other
# file clusters at ~0.111-0.114s regardless of mechanism). 7s gives
# >2.5x margin over the largest real gap (2.7637s) -- most of that margin
# is deliberately reserved for cross-vendor/cross-hardware withdrawal-
# propagation timing this FRR-only lab cannot exercise, not for noise
# within the existing corpus, which is otherwise extremely tight.
WITHDRAWAL_WINDOW_SECONDS = 7
# RFC 4271 SS6.8 Connection Collision Resolution: wire-confirmed (this
# session's investigation) that a TCP_FIN closing the collision-losing
# connection lands 0.3-0.9ms after its own BGP_NOTIFICATION
# Cease/subcode=7. 10ms is a generous margin over the largest observed
# gap (~0.9ms), not tuned to any specific file.
COLLISION_NOTIFICATION_WINDOW_SECONDS = 0.01
CEASE_ERROR_CODE = 6
CEASE_SUBCODE_CONNECTION_COLLISION_RESOLUTION = 7

# Retroactive correctness fix: the "preceded by SESSION_ESTABLISHED" check
# below previously had NO lower time bound -- it matched any prior
# establishment of the same session, however long ago, not just a recent
# reconnect. Every real session has a normal SESSION_ESTABLISHED from its
# original warmup/convergence phase, so an unbounded check could in
# principle misclassify a genuine, much-later fault trigger as
# collision-tail noise just because that session happened to exist once,
# long before. Confirmed via cross-module wire investigation (rr_down.py
# subcode=9 case): genuine collision-tail gaps are sub-millisecond
# (0.3-0.9ms measured here; 0.546ms in the rr_down case), while a real
# fault-triggering session's own prior establishment sits tens of seconds
# to minutes earlier. 2.0s gives >2000x margin over the largest observed
# genuine collision-tail gap while remaining far below any observed real-
# trigger gap -- reused from PEER_BREADTH_ECHO_WINDOW_SECONDS's existing
# precedent value in rr_down.py, not a new arbitrary number.
RECENT_ESTABLISHMENT_WINDOW_SECONDS = 2.0


def _pe_nodes(topo):
    return [n["id"] for n in topo["nodes"] if n.get("role") == "PE"]


def _ip_to_node(topo):
    return {n["router_id"]: n["id"] for n in topo["nodes"]}


def _bfd_session_pe(e, ip_to_node, pe_ids):
    """BFD_STATE_CHANGE's node_involved is whichever side SENT that
    specific control packet -- either end of a BFD session can send a
    Down notification, so node_involved is not reliably the affected PE
    (confirmed: RR1 sent the Down packet for the PE1-RR1 session in
    link_down_bfd_pe1_recovered, giving node_involved=RR1). Resolve the
    actual PE side from the session's own src_ip/dst_ip instead."""
    pd = e["protocol_detail"]
    for ip in (pd.get("src_ip"), pd.get("dst_ip")):
        node = ip_to_node.get(ip)
        if node in pe_ids:
            return node
    return None


# BFD diag codes (RFC 5880 sec 4.1): 1 = Control Detection Time Expired
# (a genuine timeout-triggered Down -- the real `bfd` mechanism). 3 =
# Neighbor Signaled Down (FRR's own side-effect of administratively
# removing BFD via "no neighbor X bfd", which is exactly what
# link_down_holdtimer_inject() does before bringing the link down --
# confirmed this session: this diag=3 event genuinely appears in every
# holdtimer capture and was being misread as the bfd mechanism's real
# diag=1 signal).
BFD_DIAG_CONTROL_DETECTION_TIME_EXPIRED = 1
# 3 = Neighbor Signaled Down -- holdtimer's confirmed administrative
# BFD-disable side-effect (see comment above). Used below to disambiguate
# an RR-sent FIN between holdtimer (this diag precedes it) and tcpfail
# (no BFD involvement at all, so this never appears).
BFD_DIAG_NEIGHBOR_SIGNALED_DOWN = 3


def _tcp_event_pe(e, ip_to_node, pe_ids):
    """TCP_FIN/TCP_RESET's node_involved is whichever side SENT the packet
    (src_node). For tcpfail specifically, the confirmed real signal is the
    RR's own FIN after ~30s of unacked keepalives toward the affected PE --
    node_involved is then the RR, not the PE. Resolve the actual affected PE
    from src_ip/dst_ip instead of trusting node_involved alone, mirroring
    _bfd_session_pe's approach for the same reason."""
    pd = e["protocol_detail"]
    for ip in (pd.get("src_ip"), pd.get("dst_ip")):
        node = ip_to_node.get(ip)
        if node in pe_ids:
            return node
    return None


def _bfd_diag3_precedes(events, pe, ip_to_node, pe_ids, before_ts):
    """True if a diag=3 (administrative BFD-disable) BFD_STATE_CHANGE for
    this PE's session appears earlier in the stream than before_ts --
    holdtimer's confirmed signature, used to disambiguate an RR-sent FIN
    between holdtimer (admin BFD-disable, then hold-timer expiry) and
    tcpfail (no BFD involvement at all). Fixes a regression where the
    RR-side FIN branch added for tcpfail was mechanism-agnostic and
    misclassified holdtimer's RR-sent FIN as TcpConnectionFails whenever
    the RR happened to send it before any PE-side event."""
    for e in events:
        if e["timestamp"] >= before_ts:
            break
        if e["event_type"] != "BFD_STATE_CHANGE" or e["protocol_detail"].get("state") != "Down":
            continue
        if e["protocol_detail"].get("diag") != BFD_DIAG_NEIGHBOR_SIGNALED_DOWN:
            continue
        if _bfd_session_pe(e, ip_to_node, pe_ids) == pe:
            return True
    return False


def _recently_reestablished(pe, t, events):
    """True if `pe`'s own SESSION_ESTABLISHED landed within
    RECENT_ESTABLISHMENT_WINDOW_SECONDS immediately before `t` -- a
    candidate trigger this close behind a fresh reconnect is treated as
    noise from a session that just came back up, not a new independent
    fault (2026-08-08 fix). Reuses RECENT_ESTABLISHMENT_WINDOW_SECONDS,
    already established and validated for the RFC 4271 collision-tail
    exclusion below, rather than a new constant.

    Measured basis (esdf_toggle_link_pe1_notrecovered investigation):
    every one of the 90 real bfd/holdtimer/tcpfail scenarios across both
    datasets has this gap as None for its genuine trigger (no prior
    SESSION_ESTABLISHED for that PE exists at all in a clean single-fault
    file) -- so this check is a confirmed no-op against all real,
    currently-passing data. In esdf_toggle_link_pe1_notrecovered's noisy
    capture, PE1's spurious second incident measured 0.0006s and PE5's
    spurious incident measured 1.276s -- both caught by this window; PE4's
    separate spurious incident has no prior SESSION_ESTABLISHED either
    (same None signature as genuine data) and is NOT caught by this
    check -- a known, explicitly unresolved residual gap, not silently
    covered."""
    for e in events:
        if e["timestamp"] >= t:
            continue
        if e["event_type"] != "SESSION_ESTABLISHED" or e["node_involved"] != pe:
            continue
        if t - e["timestamp"] <= RECENT_ESTABLISHMENT_WINDOW_SECONDS:
            return True
    return False


def _closer_near_miss(current, candidate):
    """Keeps whichever of two near_miss dicts (or None) has the smaller
    gap_seconds -- None is always replaced by any real candidate."""
    if candidate is None:
        return current
    if current is None or candidate["gap_seconds"] < current["gap_seconds"]:
        return candidate
    return current


def _reestablishment_near_miss(pe, t, events):
    """Only meaningful when _recently_reestablished(pe, t, events) is
    already True (i.e. this trigger-shaped candidate is about to be
    rejected as reconnect noise) -- returns the near_miss dict describing
    how close it came to the RECENT_ESTABLISHMENT_WINDOW_SECONDS boundary
    (gap_seconds = the margin between the window and the actual
    reestablishment gap; smaller means the candidate landed nearer the
    boundary, not nearer to t itself, since this window rejects
    candidates that are TOO CLOSE to a reconnect, the opposite shape from
    every other window in this module)."""
    best = None
    for e in events:
        if e["timestamp"] >= t:
            continue
        if e["event_type"] != "SESSION_ESTABLISHED" or e["node_involved"] != pe:
            continue
        actual_gap = t - e["timestamp"]
        if actual_gap <= RECENT_ESTABLISHMENT_WINDOW_SECONDS:
            margin = RECENT_ESTABLISHMENT_WINDOW_SECONDS - actual_gap
            candidate = {
                "candidate_timestamp": t,
                "gap_seconds": margin,
                "window_seconds": RECENT_ESTABLISHMENT_WINDOW_SECONDS,
                "window_name": "RECENT_ESTABLISHMENT_WINDOW_SECONDS",
            }
            best = _closer_near_miss(best, candidate)
    return best


def _is_collision_resolution_teardown(fin_event, events):
    """True only if BOTH hold for this teardown event (TCP_FIN or
    TCP_RESET -- the collision-losing connection can be closed either
    way, confirmed session investigation, this function's own body was
    always type-agnostic, only its caller's gate was FIN-only):
    (1) it's immediately preceded (within COLLISION_NOTIFICATION_WINDOW_SECONDS)
        by a BGP_NOTIFICATION Cease/subcode=7 (RFC 4271 SS6.8 Connection
        Collision Resolution) for the SAME session, AND
    (2) a SESSION_ESTABLISHED for that same session occurred RECENTLY
        (within RECENT_ESTABLISHMENT_WINDOW_SECONDS) before this teardown --
        not merely at any point earlier in the capture.

    Condition (2) is the real discriminator, not a refinement of
    convenience: a Cease/subcode=7 NOTIFICATION immediately before a
    teardown can also be the fault's OWN first wire signature in at least
    one confirmed injection variant (ab_test_tcpfail_pe1_recovered -- the
    Cease/FIN pair IS the earliest fault-relevant event in that file,
    nearly 2s before any real recovery). What distinguishes genuine
    post-recovery collision-tail noise from that case is chronological
    position relative to recovery: the tail-noise teardown always follows
    its session's own SESSION_ESTABLISHED, while a fault-triggering
    teardown never does (recovery hasn't happened yet). Matched by session
    (src_ip/dst_ip, unordered) throughout, since neither BGP_NOTIFICATION
    nor SESSION_ESTABLISHED carry TCP ports."""
    fin_pd = fin_event["protocol_detail"]
    fin_ts = fin_event["timestamp"]
    fin_endpoints = frozenset({fin_pd.get("src_ip"), fin_pd.get("dst_ip")})

    has_preceding_cease = False
    for e in events:
        if e["event_type"] != "BGP_NOTIFICATION":
            continue
        if not (fin_ts - COLLISION_NOTIFICATION_WINDOW_SECONDS <= e["timestamp"] <= fin_ts):
            continue
        pd = e["protocol_detail"]
        if pd.get("error_code") != CEASE_ERROR_CODE or pd.get("subcode") != CEASE_SUBCODE_CONNECTION_COLLISION_RESOLUTION:
            continue
        if frozenset({pd.get("src_ip"), pd.get("dst_ip")}) == fin_endpoints:
            has_preceding_cease = True
            break
    if not has_preceding_cease:
        return False

    for e in events:
        if e["event_type"] != "SESSION_ESTABLISHED":
            continue
        if not (fin_ts - RECENT_ESTABLISHMENT_WINDOW_SECONDS <= e["timestamp"] < fin_ts):
            continue
        pd = e["protocol_detail"]
        if frozenset({pd.get("src_ip"), pd.get("dst_ip")}) == fin_endpoints:
            return True
    return False


def _session_key(pd):
    """Unordered TCP 4-tuple session identity for a TCP_FIN/TCP_RESET
    event, built from its own protocol_detail (sport/dport now exposed by
    vantage_parser.py). Unordered (frozenset of endpoints) because either
    side of a session can be captured as src or dst on a given packet.
    Returns None when sport/dport aren't present (older event shapes),
    so callers must treat None as "identity unknown", not "matches
    everything"."""
    src_ip, dst_ip = pd.get("src_ip"), pd.get("dst_ip")
    sport, dport = pd.get("sport"), pd.get("dport")
    if sport is None or dport is None:
        return None
    return frozenset({(src_ip, sport), (dst_ip, dport)})


def _candidate_pe(e, ip_to_node, pe_ids):
    """The PE a given fault-relevant event would be attributed to, using
    the exact same resolution rules _find_one_trigger applies -- shared so
    cascade-window filtering never drifts out of sync with trigger
    detection. Returns None for events that aren't trigger material at
    all (e.g. a diag=3 BFD event, which _find_one_trigger also skips)."""
    if e["event_type"] == "BFD_STATE_CHANGE" and e["protocol_detail"].get("state") == "Down":
        if e["protocol_detail"].get("diag") != BFD_DIAG_CONTROL_DETECTION_TIME_EXPIRED:
            return None
        return _bfd_session_pe(e, ip_to_node, pe_ids)
    if e["node_involved"] in pe_ids:
        if e["event_type"] in ("TCP_RESET", "TCP_FIN"):
            return e["node_involved"]
        return None
    if e["event_type"] == "TCP_FIN":
        return _tcp_event_pe(e, ip_to_node, pe_ids)
    return None


def _find_one_trigger(candidate_events, all_events, ip_to_node, pe_ids):
    """Unchanged single-incident selection logic from the original
    detect(), just returning instead of breaking so the caller can loop.
    `all_events` (not `candidate_events`) is used for _bfd_diag3_precedes'
    backward lookup, since that's context lookup, not itself a trigger
    source, and must always see the full stream regardless of what a
    prior incident's cascade window already consumed from `candidate_events`.

    Every acceptance point below also requires `not _recently_reestablished`
    (2026-08-08 fix): a candidate whose resolved PE just had its own
    SESSION_ESTABLISHED within RECENT_ESTABLISHMENT_WINDOW_SECONDS is
    treated as noise from a session that just came back up, not a new
    independent fault -- confirmed via measurement against all 90 real
    scenarios (see _recently_reestablished's own docstring) that this
    never rejects a genuine trigger, only the esdf_toggle_link_pe1_
    notrecovered false positives it targets.

    Returns (event, mechanism, pe, near_miss) -- near_miss only ever set
    (and only meaningful) when no trigger at all was found (event is
    None): the single closest _recently_reestablished near-miss
    encountered across the whole scan (see _reestablishment_near_miss)."""
    best_near_miss = None
    for e in candidate_events:
        if e["event_type"] == "BFD_STATE_CHANGE" and e["protocol_detail"].get("state") == "Down":
            if e["protocol_detail"].get("diag") != BFD_DIAG_CONTROL_DETECTION_TIME_EXPIRED:
                continue  # diag=3 (or other) -- not a real BFD-timeout Down, keep looking
            pe = _bfd_session_pe(e, ip_to_node, pe_ids)
            if pe is not None:
                if not _recently_reestablished(pe, e["timestamp"], all_events):
                    return e, "BFD Down", pe, None
                best_near_miss = _closer_near_miss(best_near_miss, _reestablishment_near_miss(pe, e["timestamp"], all_events))
            continue
        if e["node_involved"] in pe_ids:
            if e["event_type"] == "TCP_RESET":
                if not _recently_reestablished(e["node_involved"], e["timestamp"], all_events):
                    return e, "TcpConnectionFails", e["node_involved"], None
                best_near_miss = _closer_near_miss(best_near_miss, _reestablishment_near_miss(e["node_involved"], e["timestamp"], all_events))
                continue
            if e["event_type"] == "TCP_FIN":
                pe = e["node_involved"]
                if _recently_reestablished(pe, e["timestamp"], all_events):
                    best_near_miss = _closer_near_miss(best_near_miss, _reestablishment_near_miss(pe, e["timestamp"], all_events))
                    continue
                # Mirror the RR-sourced-FIN branch's discriminator below --
                # a PE-sourced FIN is holdtimer's signature only if preceded
                # by the diag=3 admin BFD-disable; otherwise it's tcpfail
                # (confirmed: ab_test_tcpfail_pe1_recovered's PE-sourced FIN
                # has no preceding BFD_STATE_CHANGE at all).
                if _bfd_diag3_precedes(all_events, pe, ip_to_node, pe_ids, e["timestamp"]):
                    return e, "Hold Timer Expired", pe, None
                else:
                    return e, "TcpConnectionFails", pe, None
            continue
        # node_involved (sender) is not a PE -- e.g. the RR. Confirmed real
        # tcpfail signature: the RR's own FIN after ~30s of unacked
        # keepalives toward the affected PE, once the PE's outbound path is
        # blocked by the injected REJECT rule. Not a substitute for the
        # PE-side RST branch above -- accepted in addition to it.
        if e["event_type"] == "TCP_FIN":
            pe = _tcp_event_pe(e, ip_to_node, pe_ids)
            if pe is not None:
                if not _recently_reestablished(pe, e["timestamp"], all_events):
                    if _bfd_diag3_precedes(all_events, pe, ip_to_node, pe_ids, e["timestamp"]):
                        return e, "Hold Timer Expired", pe, None
                    else:
                        return e, "TcpConnectionFails", pe, None
                best_near_miss = _closer_near_miss(best_near_miss, _reestablishment_near_miss(pe, e["timestamp"], all_events))
    return None, None, None, best_near_miss


def detect(fused_events, topo):
    """Returns a list of incident dicts -- always a list, never a bare
    dict, same convention as mac_mobility.py/rd_collision.py. Repeatedly
    runs the original single-incident selection logic (_find_one_trigger,
    unchanged) against a shrinking pool of unconsumed events: once an
    incident is found, every remaining candidate event that resolves to
    the SAME PE within that incident's cascade window (bounded by its own
    recovery time, or by RECOVERY_WINDOW_SECONDS if unrecovered) is
    removed before searching for the next, independent incident -- so a
    single fault's own cascade of correlated signals (BFD Down, then
    TCP_RESET/FIN, etc.) is never double-counted as multiple incidents.

    Beyond the PE+window cascade filter, TCP_FIN/TCP_RESET events also
    carry genuine session identity (src/dst IP + port, unordered) once
    consumed as part of a recorded incident's cascade window -- any later
    candidate sharing that exact session identity is excluded from
    triggering a new incident regardless of timing, since it's teardown
    noise from a connection already accounted for, not a new fault. This
    is a real session match, not a time margin: a same-PE FIN/RESET on a
    genuinely different session (e.g. the freshly re-established
    post-recovery connection) is NOT excluded by this and can still start
    a new incident if it otherwise qualifies.

    A third, independent exclusion: any TCP_FIN or TCP_RESET confirmed as
    an RFC 4271 SS6.8 connection-collision-resolution teardown (see
    _is_collision_resolution_teardown) is dropped from candidacy up front,
    unconditionally -- it is never a fault trigger regardless of cascade
    window or session-consumption state, so it's excluded at
    classification time rather than by adjusting either window.
    _is_collision_resolution_teardown's own body was always generic (it
    only reads protocol_detail/timestamp, no event_type check) -- TCP_RESET
    was just never routed through it (confirmed session gap: RFC 4271's
    collision-losing connection can be torn down via RST as well as FIN,
    same 0.3-0.9ms timing signature after its own Cease/subcode=7
    NOTIFICATION, wire-confirmed in link_down_holdtimer_xpe2_recovered,
    where a PE-sourced collision-tail RST was wrongly accepted as a fresh
    TcpConnectionFails trigger since the PE-sourced branch below has no
    exclusion check at all)."""
    pe_ids = set(_pe_nodes(topo))
    ip_to_node = _ip_to_node(topo)
    events = sorted(fused_events, key=lambda e: e["timestamp"])
    remaining = [
        e for e in events
        if not (e["event_type"] in ("TCP_FIN", "TCP_RESET") and _is_collision_resolution_teardown(e, events))
    ]
    consumed_sessions = set()

    incidents = []
    near_miss = None
    while True:
        remaining = [
            e for e in remaining
            if not (e["event_type"] in ("TCP_FIN", "TCP_RESET")
                    and _session_key(e["protocol_detail"]) in consumed_sessions)
        ]

        trigger_event, trigger_mechanism, trigger_pe, this_near_miss = _find_one_trigger(remaining, events, ip_to_node, pe_ids)
        if trigger_event is None:
            near_miss = _closer_near_miss(near_miss, this_near_miss)
            break

        root_cause_node = trigger_pe
        t_fault = trigger_event["timestamp"]

        recovery_status = "NOT_RECOVERED"
        recovered_time = None
        # Recovery detection is unbounded -- searches the whole remaining
        # capture, not a fixed duration, since no protocol-level upper
        # bound on real recovery time is documented anywhere in this
        # codebase (checked: no configured max reconnect-backoff, only
        # the 30s hold-timer itself). A genuine slow recovery (2-5+ min)
        # must not be misreported as NOT_RECOVERED just because it
        # exceeds an arbitrary fixed window. RECOVERY_WINDOW_SECONDS is
        # still used below, but ONLY as the cascade-consumption fallback
        # for the genuinely-NOT_RECOVERED case -- a different concern
        # from this search.
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            if e["event_type"] == "SESSION_ESTABLISHED" and e["node_involved"] == root_cause_node:
                recovery_status = "RECOVERED"
                recovered_time = e["timestamp"]
                break

        incidents.append(build_result(
            fault_type="Link Down",
            trigger_mechanism=trigger_mechanism,
            root_cause_node=root_cause_node,
            time_of_first_fault=t_fault,
            recovery_status=recovery_status,
            recovered_time=recovered_time,
        ))

        cascade_end = recovered_time if recovery_status == "RECOVERED" else (t_fault + RECOVERY_WINDOW_SECONDS)
        kept = []
        for e in remaining:
            if (t_fault <= e["timestamp"] <= cascade_end
                    and _candidate_pe(e, ip_to_node, pe_ids) == root_cause_node):
                if e["event_type"] in ("TCP_FIN", "TCP_RESET"):
                    key = _session_key(e["protocol_detail"])
                    if key is not None:
                        consumed_sessions.add(key)
                continue  # consumed as cascade of this incident
            kept.append(e)
        remaining = kept

    if not incidents:
        return []
    return incidents
