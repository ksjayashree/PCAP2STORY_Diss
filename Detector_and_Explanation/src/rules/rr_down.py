"""Layer 4 rule: RR Down (bgpdkill, graceful).

Signals confirmed in Layer 2/3 checkpoints (LAYER4_DESIGN.md #2):
- bgpdkill: simultaneous TCP_FIN/TCP_RESET/BFD_STATE_CHANGE->Down across
  all of one RR's sessions.
- graceful: sequential BGP_NOTIFICATION (Cease/Administrative Shutdown)
  across the RR's sessions.

containerkill (a third mechanism, isolated FIN with no BFD nearby --
tcpdump dies with the killed container, leaving only a lone TCP_FIN on
the RR-RR link) was removed 2026-08-02: its recovery mechanism is a full
fabric destroy+redeploy, which also destroys the SURVIVING RR's own
capture process, so "recovery" was never a genuine, isolated
single-RR-down-and-back observation for this mechanism -- confirmed via
direct investigation that no capture window extension could fix this
(the capturing container itself gets torn down). Real captures archived
to pilot_containerlab/_archived_rr_down_containerkill/. This isolated-FIN
shape is no longer a recognized RR Down trigger at all -- confirmed safe:
bgpdkill's trigger always has BFD nearby, graceful's is always a
BGP_NOTIFICATION, neither mechanism's own real signature ever falls into
the now-removed third case.
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
from topology import direct_peers
from rules.schema import build_result

# Tightened 2026-08-09 from 90s, measured directly against the full real
# corpus (20/20 rr_down folders, both datasets, bgpdkill+graceful): real
# recovered_time - t_fault ranges 11.770s-20.948s (bgpdkill 17.60-20.95s,
# graceful 11.77-14.31s, n=10). This is only the cascade-consumption
# fallback for the genuinely-NOT_RECOVERED case; every real NOT_RECOVERED
# file's capture ends within 1.013s-3.192s of t_fault (n=10), so there is
# no real data anywhere near 90s this constant was ever actually
# covering. 40s gives ~1.9x margin over the largest genuine FRR recovery
# gap measured (20.948s) -- most of that margin is deliberately reserved
# for cross-vendor/cross-hardware RR recovery-timing variance this
# FRR-only lab cannot exercise, not for noise within the existing corpus,
# which is tight and consistent.
RECOVERY_WINDOW_SECONDS = 40


def _rr_nodes(topo):
    return {n["id"] for n in topo["nodes"] if n.get("role") == "RR"}


def _ip_to_node(topo):
    return {n["router_id"]: n["id"] for n in topo["nodes"]}


def _event_peer(e, root_cause_node, ip_to_node):
    """The peer node on the other end of this event's session, given the
    event is already attributed to root_cause_node (node_involved). Every
    event type used here (BFD_STATE_CHANGE, TCP_FIN, TCP_RESET,
    BGP_NOTIFICATION, SESSION_ESTABLISHED) already carries src_ip/dst_ip
    in protocol_detail -- no vantage_parser.py change needed. Returns
    None if neither endpoint resolves to root_cause_node (shouldn't
    happen for events already filtered to node_involved == root_cause_node,
    defensive only)."""
    pd = e["protocol_detail"]
    src_node = ip_to_node.get(pd.get("src_ip"))
    dst_node = ip_to_node.get(pd.get("dst_ip"))
    if src_node == root_cause_node:
        return dst_node
    if dst_node == root_cause_node:
        return src_node
    return None


FAULT_EVENT_TYPES = {"BGP_NOTIFICATION", "BFD_STATE_CHANGE", "TCP_FIN", "TCP_RESET"}
# NOT tightened (2026-08-09 attempt reverted): a prior measurement pass
# looked only at bgpdkill's own RR-BFD-Down-to-peer-fault-event gap
# (0.0013s-0.0049s across the real corpus) and proposed narrowing this to
# 0.75s on that basis. That measurement was incomplete -- this same
# constant also gates _full_peer_breadth's window for GRACEFUL's own
# trigger (see _find_one_trigger's graceful branch above), and graceful's
# real signature is SEQUENTIAL per-session Cease notifications, not a
# near-simultaneous BFD event, so it needs a fundamentally different
# (slower) real timing than bgpdkill's sub-5ms figure. Confirmed via a
# full before/after regression run across both real corpora (pilot
# rr1 graceful pair + all 6 real 3rr graceful files, 8 files total) that
# 0.75s breaks every one of them from DETECTED to NO_SIGNAL_FOUND, with
# the real fault reclassified as an undemoted cross-module "Link Down"
# false positive instead. Left at the original 2s pending a proper
# separate measurement of graceful's own real full-peer-breadth timing
# before this is revisited -- do not narrow this constant using only
# bgpdkill's BFD-gap data again.
BFD_NEARBY_WINDOW_SECONDS = 2

# Reciprocal RR-RR link echo exclusion (wire-confirmed across all 8 real
# bgpdkill/graceful captures, see detect()'s docstring for the full
# analysis): when one RR genuinely fails, the surviving RR's own side of
# their shared link independently produces its own fault-shaped event,
# which _find_one_trigger would otherwise treat as a second, unrelated RR
# failure. (A second, containerkill-specific vantage-authority
# discriminator existed here until 2026-08-02 -- removed along with
# containerkill itself, confirmed exclusive to that mechanism, not shared
# with this one.)
#
# PEER_BREADTH_ECHO_WINDOW_SECONDS (bgpdkill/graceful): the real RR always
# shows its FULL direct-peer set dropping; the reciprocal RR only ever
# shows the one link to the real RR. Observed real-vs-reciprocal gaps:
# bgpdkill 0.46-1.67ms, graceful 593-920ms. 2.0s gives >2x margin over the
# largest observed gap (920ms, graceful) -- reused from
# BFD_NEARBY_WINDOW_SECONDS's existing precedent in this module for a
# similar near-simultaneous check, not a new arbitrary number.
PEER_BREADTH_ECHO_WINDOW_SECONDS = 2.0

# RFC 4271 SS6.8 Connection Collision Resolution, ported from
# link_down.py's _is_collision_resolution_teardown (same constants, same
# justification -- wire-confirmed there that a TCP_FIN closing the
# collision-losing connection lands 0.3-0.9ms after its own
# BGP_NOTIFICATION Cease/subcode=7). Re-confirmed here in
# rr_down_bgpdkill_rr1_recovered: a PE2 session reconnecting a second
# time during RR1's recovery burst produces the identical
# NOTIFICATION(625.494505)->SESSION_ESTABLISHED(625.494705)->FIN(625.494848)
# shape.
COLLISION_NOTIFICATION_WINDOW_SECONDS = 0.01
CEASE_ERROR_CODE = 6
CEASE_SUBCODE_CONNECTION_COLLISION_RESOLUTION = 7
# RFC 8538 SS4 Hard Reset -- confirmed via wire investigation
# (rr_down_bgpdkill_rr1_recovered) to produce the identical
# SESSION_ESTABLISHED->NOTIFICATION->FIN collision-tail shape as
# subcode=7, just a different Cease reason code. NOT safe to treat as
# "always noise" though -- graceful's own real, per-session fault trigger
# ALSO uses subcode=9 (confirmed: 14 occurrences across the 4 graceful
# files, all with recovery_status="RECOVERED"/"NOT_RECOVERED" and none
# preceded by their own session's SESSION_ESTABLISHED, i.e. genuine
# faults, not noise). The RECENT_ESTABLISHMENT_WINDOW_SECONDS bound below
# is what correctly separates the one genuine collision-tail occurrence
# from graceful's 14 genuine fault triggers -- confirmed via testing, not
# assumed.
CEASE_SUBCODE_HARD_RESET = 9
_COLLISION_TAIL_SUBCODES = (CEASE_SUBCODE_CONNECTION_COLLISION_RESOLUTION, CEASE_SUBCODE_HARD_RESET)

# Retroactive correctness fix, ported from link_down.py: the "preceded by
# SESSION_ESTABLISHED" checks below previously had NO lower time bound --
# see link_down.py's own constant docstring for the full justification
# (same reasoning, same value, reused rather than a new number). Without
# this bound, extending subcode matching to include 9 would have wrongly
# excluded graceful's real per-session Cease/subcode=9 triggers (each of
# whose sessions has a normal, much-earlier SESSION_ESTABLISHED from
# warmup) -- confirmed this would have broken graceful detection before
# adding this bound.
RECENT_ESTABLISHMENT_WINDOW_SECONDS = 2.0


def _is_collision_resolution_teardown(fin_event, events):
    """True only if BOTH hold for this TCP_FIN, same two-condition design
    as link_down.py's version and for the same reason (a bare Cease
    proximity check alone is not enough -- see that module's docstring
    for the ab_test_tcpfail_pe1_recovered case that proved it):
    (1) it's immediately preceded (within COLLISION_NOTIFICATION_WINDOW_SECONDS)
        by a BGP_NOTIFICATION Cease/subcode in {7, 9} for the SAME session, AND
    (2) a SESSION_ESTABLISHED for that same session occurred RECENTLY
        (within RECENT_ESTABLISHMENT_WINDOW_SECONDS) before this FIN --
        the discriminator between genuine post-recovery collision-tail
        noise and a Cease/FIN pair that might itself be a real fault's
        own first signature (or, for subcode=9, graceful's own real
        per-session trigger)."""
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
        if pd.get("error_code") != CEASE_ERROR_CODE or pd.get("subcode") not in _COLLISION_TAIL_SUBCODES:
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


def _is_collision_resolution_notification(notif_event, events):
    """True if this BGP_NOTIFICATION Cease/subcode in {7, 9} is itself
    part of a collision-tail sequence for a session that RECENTLY
    reconnected (a SESSION_ESTABLISHED for the same session occurred
    within RECENT_ESTABLISHMENT_WINDOW_SECONDS before it). Needed IN
    ADDITION to _is_collision_resolution_teardown (the FIN check) because
    rr_down.py, unlike link_down.py, treats BGP_NOTIFICATION itself as a
    trigger-worthy event type (graceful's core signature) -- confirmed
    via testing: the NOTIFICATION fires before its own trailing FIN
    chronologically and can win _find_one_trigger's candidacy before the
    FIN-only exclusion ever gets a chance to act. The RECENT (not
    unbounded) establishment check is what lets graceful's genuine
    fault-triggering Cease/subcode=9 notifications (whose own session's
    SESSION_ESTABLISHED is tens of seconds in the past, from warmup) sail
    through un-excluded, confirmed via testing -- a bare subcode==9 check
    without this bound would have wrongly excluded them."""
    pd = notif_event["protocol_detail"]
    if pd.get("error_code") != CEASE_ERROR_CODE or pd.get("subcode") not in _COLLISION_TAIL_SUBCODES:
        return False
    ts = notif_event["timestamp"]
    endpoints = frozenset({pd.get("src_ip"), pd.get("dst_ip")})
    for e in events:
        if e["event_type"] != "SESSION_ESTABLISHED":
            continue
        if not (ts - RECENT_ESTABLISHMENT_WINDOW_SECONDS <= e["timestamp"] < ts):
            continue
        pd2 = e["protocol_detail"]
        if frozenset({pd2.get("src_ip"), pd2.get("dst_ip")}) == endpoints:
            return True
    return False


def _candidate_peers_touched(rr, t_fault, events, ip_to_node, window):
    """Distinct peers of `rr` with a qualifying fault-event within
    `window` seconds after t_fault -- the peer-breadth measure."""
    peers = set()
    for e in events:
        if e["node_involved"] != rr:
            continue
        if e["event_type"] not in FAULT_EVENT_TYPES:
            continue
        if not (t_fault <= e["timestamp"] <= t_fault + window):
            continue
        peer = _event_peer(e, rr, ip_to_node)
        if peer:
            peers.add(peer)
    return peers


def _is_reciprocal_rr_echo(candidate_event, all_events, rr_ids, ip_to_node, topo):
    """True if `candidate_event` is the OTHER RR's own local view of a
    shared RR-RR link teardown -- not a real independent fault for its
    own node_involved. See the module-level constants above for the two
    discriminators and their window justifications."""
    rr = candidate_event["node_involved"]
    t_fault = candidate_event["timestamp"]
    other_rrs = rr_ids - {rr}

    own_peers = _candidate_peers_touched(rr, t_fault, all_events, ip_to_node, PEER_BREADTH_ECHO_WINDOW_SECONDS)

    # Discriminator 1: peer breadth (bgpdkill/graceful). Only applies when
    # this candidate's own touched-peer set is EXACTLY the single other RR
    # -- the confirmed shape of a reciprocal echo, not a partial/ambiguous
    # match.
    if len(own_peers) == 1:
        (only_peer,) = own_peers
        if only_peer in other_rrs:
            for e in all_events:
                if e["node_involved"] != only_peer or e["event_type"] not in FAULT_EVENT_TYPES:
                    continue
                if not (abs(e["timestamp"] - t_fault) <= PEER_BREADTH_ECHO_WINDOW_SECONDS):
                    continue
                other_peers = _candidate_peers_touched(only_peer, e["timestamp"], all_events, ip_to_node, PEER_BREADTH_ECHO_WINDOW_SECONDS)
                if len(other_peers) > len(own_peers):
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


def _full_peer_breadth(rr, t, all_events, topo, ip_to_node):
    """Positive confirmation that ALL of `rr`'s real topology direct peers
    (never hardcoded -- direct_peers(topo, rr)) show a qualifying
    fault-shaped event within BFD_NEARBY_WINDOW_SECONDS of `t`. This is
    the actual enforcement of the "across ALL of one RR's sessions" shape
    this module's own docstring has always claimed but never checked --
    confirmed via direct measurement (2026-08-08) against every one of
    the 20 real bgpdkill/graceful scenarios in both datasets: every single
    one shows 100% of the RR's real direct peers touched within this same
    window, so requiring full breadth here costs nothing against real
    data. Also confirmed against the false-positive this fix targets
    (esdf_toggle_link_pe1_notrecovered's three spurious RR Down
    incidents): none of them reach full breadth (3/4, 1/3, 1/4 peers
    touched respectively) -- a looser "2+ peers" threshold would still
    have wrongly accepted the first of those three, so full breadth is
    the threshold that actually separates real RR-wide failures from a
    single PE-side event seen from the RR's own vantage, not an
    arbitrary choice.

    Deliberately reuses _candidate_peers_touched (previously only used
    inside _is_reciprocal_rr_echo's narrow exclusion) as a POSITIVE
    confirmation here instead -- same helper, different role. Does not
    replace or overlap with _is_reciprocal_rr_echo: that runs earlier, in
    detect()'s upfront `remaining` filter, removing single-peer-touching
    candidates (touched-peer-set exactly {the other RR}) before search
    even starts; this function instead requires FULL breadth from
    whatever candidates remain, a different and later gate.

    Returns (bool, near_miss_or_None) -- both call sites in
    _find_one_trigger only ever invoke this once their own content check
    (bfd_nearby, or the Cease/subcode match) already passed via Python's
    `and` short-circuit, so a False return here always means "content was
    right, only the peer-breadth timing wasn't" -- exactly the near-miss
    case this session's investigation targets. near_miss is the single
    closest still-missing peer's own qualifying fault event that landed
    AFTER the window closed (a peer that never produces any such event at
    all, ever, in the whole capture contributes no near-miss, since there
    is no real candidate timestamp to report for it)."""
    real_peers = direct_peers(topo, rr)
    if not real_peers:
        return False, None
    touched = _candidate_peers_touched(rr, t, all_events, ip_to_node, BFD_NEARBY_WINDOW_SECONDS)
    if real_peers <= touched:
        return True, None

    missing = real_peers - touched
    near_miss = None
    window_end = t + BFD_NEARBY_WINDOW_SECONDS
    for e in all_events:
        if e["node_involved"] != rr or e["event_type"] not in FAULT_EVENT_TYPES:
            continue
        if e["timestamp"] <= window_end:
            continue  # within window (would already be "touched") or before t_fault -- not a late arrival
        peer = _event_peer(e, rr, ip_to_node)
        if peer not in missing:
            continue
        gap = e["timestamp"] - window_end
        if near_miss is None or gap < near_miss["gap_seconds"]:
            near_miss = {
                "candidate_timestamp": e["timestamp"],
                "gap_seconds": gap,
                "window_seconds": BFD_NEARBY_WINDOW_SECONDS,
                "window_name": "BFD_NEARBY_WINDOW_SECONDS",
            }
    return False, near_miss


def _find_one_trigger(candidate_events, all_events, rr_ids, topo, ip_to_node):
    """Chronologically-first fault-relevant RR event wins -- do NOT
    hard-prioritize by event type. Confirmed bug (predates this version):
    preferring BGP_NOTIFICATION unconditionally misclassified bgpdkill
    (whose real signature -- mass TCP_FIN/BFD_STATE_CHANGE->Down -- fires
    earlier) as graceful, because an incidental NOTIFICATION during later
    reconnect churn also existed in the stream.

    Mechanism classification now happens inline (merged 2026-08-02 when
    containerkill was removed): a candidate is only accepted as a trigger
    if it classifies as bgpdkill (BFD nearby) or graceful (a
    BGP_NOTIFICATION Cease/subcode=9 -- graceful's confirmed real
    signature, NOT just "any BGP_NOTIFICATION") -- a bare isolated
    FIN/RESET with neither (the old containerkill signature) is skipped,
    not accepted, so it's no longer a recognized RR Down trigger shape at
    all. Confirmed safe: neither bgpdkill's nor graceful's own real
    signature ever falls into this now-rejected case.

    The subcode==9 check (added 2026-08-02, fixing a regression caught
    during containerkill's removal) is required, not optional: with
    containerkill's bare-isolated-FIN branch removed, _find_one_trigger
    now scans PAST tcpfail's own confirmed isolated-FIN artifact on the
    RR-RR link instead of stopping there -- and tcpfail's artifact has a
    companion, Cease/subcode=0 (unspecified) BGP_NOTIFICATION ~6.8s later
    on the SAME single PE session (link_down_tcpfail_pe1_notrecovered,
    confirmed via direct wire inspection), which a bare "any
    BGP_NOTIFICATION" check would wrongly accept as a genuine graceful
    trigger. This was a pre-existing gap (subcode was never checked),
    just never previously reachable, since containerkill's now-removed
    branch always won first for every real tcpfail file.

    BOTH branches now additionally require _full_peer_breadth (2026-08-08
    fix): the previous "bfd_nearby" check only required SOME other
    BFD_STATE_CHANGE->Down attributed to ANY RR within the window --
    never that it belonged to the SAME RR's OWN peer set, let alone that
    multiple distinct peers were affected. That let a single PE-side link
    bounce, seen from its own RR's vantage as one BFD session dropping,
    register as a full RR-wide failure whenever unrelated background
    churn on any other RR's session happened to be nearby (confirmed via
    esdf_toggle_link_pe1_notrecovered's spurious RR1/RR2 incidents). See
    _full_peer_breadth's own docstring for the measurement backing this.

    Returns (event, mechanism, near_miss) -- near_miss only ever set (and
    only meaningful) when no trigger was found at all (event is None): the
    single closest _full_peer_breadth near-miss encountered across the
    whole scan (see that function's own docstring)."""
    best_near_miss = None
    for e in candidate_events:
        if e["node_involved"] not in rr_ids:
            continue
        if e["event_type"] == "BFD_STATE_CHANGE" and e["protocol_detail"].get("state") != "Down":
            continue
        if e["event_type"] not in FAULT_EVENT_TYPES:
            continue
        rr = e["node_involved"]
        t = e["timestamp"]
        bfd_nearby = any(
            e2["event_type"] == "BFD_STATE_CHANGE" and e2["protocol_detail"].get("state") == "Down"
            and e2["node_involved"] in rr_ids
            and abs(e2["timestamp"] - t) <= BFD_NEARBY_WINDOW_SECONDS
            for e2 in all_events
        )
        if bfd_nearby:
            breadth_ok, breadth_near_miss = _full_peer_breadth(rr, t, all_events, topo, ip_to_node)
            best_near_miss = _closer_near_miss(best_near_miss, breadth_near_miss)
            if breadth_ok:
                return e, "TCP_connection_closed", None
        if e["event_type"] == "BGP_NOTIFICATION":
            pd = e["protocol_detail"]
            if pd.get("error_code") == CEASE_ERROR_CODE and pd.get("subcode") == CEASE_SUBCODE_HARD_RESET:
                breadth_ok, breadth_near_miss = _full_peer_breadth(rr, t, all_events, topo, ip_to_node)
                best_near_miss = _closer_near_miss(best_near_miss, breadth_near_miss)
                if breadth_ok:
                    return e, "Cease/Administrative Shutdown", None
            # Cease with some other subcode (e.g. subcode=0/unspecified,
            # confirmed tcpfail artifact), or a qualifying subcode that
            # failed the breadth check -- not graceful's real signature,
            # keep scanning.
            continue
        # bare isolated FIN/RESET, no BFD nearby, not a qualifying
        # NOTIFICATION -- containerkill's old signature, no longer
        # recognized; keep scanning for a later, real trigger instead of
        # stopping here.
    return None, None, best_near_miss


def detect(fused_events, topo):
    """Returns a list of incident dicts -- always a list, never a bare
    dict, same convention established in mac_mobility.py/rd_collision.py/
    link_down.py. bgpdkill and graceful both produce a documented cascade
    of multiple correlated RR-attributed events for one real fault
    (simultaneous mass TCP_FIN/RESET/BFD-Down across all of the RR's
    sessions for bgpdkill; sequential per-session Cease NOTIFICATIONs for
    graceful) -- repeatedly running the original single-incident selection
    logic against a shrinking pool of unconsumed events, consuming all
    same-RR candidate events within each incident's cascade window
    (recovery-bounded, falling back to RECOVERY_WINDOW_SECONDS when
    unrecovered) before searching for the next, keeps that cascade from
    being double-counted, same design as link_down.py.

    KNOWN, DOCUMENTED LIMITATION (not fixed here, no data exists to
    fix it against): a genuine SECOND, independent failure of the SAME RR
    landing inside the first incident's cascade window would be
    absorbed as cascade noise rather than reported as its own incident --
    the mirror-image risk to what nearly excluded a real fault trigger in
    link_down.py's ab_test_tcpfail_pe1_recovered. Structurally still
    possible, but pilot_containerlab's dataset has no multi-fault-per-file
    rr_down capture to investigate it against -- confirmed via the 8-file
    baseline (bgpdkill/graceful only, since containerkill's removal), all
    single-fault-per-file by design.

    Cascade boundary is per-peer, not a single timestamp: an RR has up to
    len(direct_peers) independent BGP sessions, each reconnecting on its
    own schedule during recovery (confirmed via wire investigation --
    bgpdkill's 4 sessions re-established 1-3ms to ~3s apart, each with its
    own BFD Init/Down churn along the way). recovery_status/recovered_time
    (2026-08-15, reworked from first-session to all-peers semantics)
    require EVERY one of the RR's real direct peers to have genuinely
    reconnected -- recovered_time is the LAST (slowest) peer's own
    establishment, not the first -- since "recovered" for an RR-wide
    fault means the RR is fully back to serving all its clients, not just
    the first one to reconnect. The separate cascade CONSUMPTION window
    still extends until every peer has independently either shown its own
    SESSION_ESTABLISHED or hit RECOVERY_WINDOW_SECONDS as a fallback --
    that fallback boundary is never used for the reported fields, only
    for bounding how much of the event stream this incident consumes."""
    rr_ids = _rr_nodes(topo)
    ip_to_node = _ip_to_node(topo)
    events = sorted(fused_events, key=lambda e: e["timestamp"])
    remaining = [
        e for e in events
        if not (e["node_involved"] in rr_ids and e["event_type"] == "TCP_FIN"
                and _is_collision_resolution_teardown(e, events))
        if not (e["node_involved"] in rr_ids and e["event_type"] == "BGP_NOTIFICATION"
                and _is_collision_resolution_notification(e, events))
        if not (e["node_involved"] in rr_ids and e["event_type"] in FAULT_EVENT_TYPES
                and _is_reciprocal_rr_echo(e, events, rr_ids, ip_to_node, topo))
    ]

    incidents = []
    near_miss = None
    while True:
        trigger_event, mechanism, this_near_miss = _find_one_trigger(remaining, events, rr_ids, topo, ip_to_node)
        if trigger_event is None:
            near_miss = _closer_near_miss(near_miss, this_near_miss)
            break

        root_cause_node = trigger_event["node_involved"]
        t_fault = trigger_event["timestamp"]

        # Per-peer recovery, computed ONCE and reduced two different ways
        # (2026-08-15, reworked): recovery_status/recovered_time now
        # require EVERY one of the RR's real direct peers to have
        # genuinely reconnected, not just the first -- previously the
        # reported fields came from whichever session re-established
        # first, while this same per-peer computation was already being
        # done separately (below) purely for cascade-consumption
        # purposes. Empirically verified (2026-08-15) against the full
        # 28-scenario real corpus: zero status flips, every recovered_time
        # shift (0.0004s-1.18s, largest for "graceful" mechanism's
        # sequential per-neighbor reconnects) stays well within
        # scorer_lib.py's existing 5.0s default recovery_tolerance.
        #
        # Search is unbounded per-peer, same reasoning as the old
        # single-session search: no protocol-level upper bound on real
        # recovery time is documented anywhere in this codebase, so a
        # genuine slow recovery must not be misreported as NOT_RECOVERED
        # just because it exceeds a fixed window.
        peer_recovered_raw = {}
        for peer in direct_peers(topo, root_cause_node):
            peer_recovered = None
            for e in events:
                if e["timestamp"] <= t_fault:
                    continue
                if e["event_type"] != "SESSION_ESTABLISHED" or e["node_involved"] != root_cause_node:
                    continue
                if _event_peer(e, root_cause_node, ip_to_node) == peer:
                    peer_recovered = e["timestamp"]
                    break
            peer_recovered_raw[peer] = peer_recovered

        # Reduction 1: reported recovery_status/recovered_time -- RECOVERED
        # only if every real peer genuinely reconnected (raw None values,
        # not the window fallback, disqualify this).
        all_recovered = bool(peer_recovered_raw) and all(v is not None for v in peer_recovered_raw.values())
        recovery_status = "RECOVERED" if all_recovered else "NOT_RECOVERED"
        recovered_time = max(peer_recovered_raw.values()) if all_recovered else None

        # Reduction 2: cascade-consumption boundary -- a different concern
        # from the reported fields above. Each peer that never genuinely
        # recovers still needs a concrete fallback boundary so the
        # incident's event-consumption window has an upper bound;
        # RECOVERY_WINDOW_SECONDS only applies here, never to the reported
        # recovery_status/recovered_time.
        peer_ends = [
            v if v is not None else (t_fault + RECOVERY_WINDOW_SECONDS)
            for v in peer_recovered_raw.values()
        ]
        cascade_end = max(peer_ends) if peer_ends else (t_fault + RECOVERY_WINDOW_SECONDS)

        incidents.append(build_result(
            fault_type="RR Down",
            trigger_mechanism=mechanism,
            root_cause_node=root_cause_node,
            time_of_first_fault=t_fault,
            recovery_status=recovery_status,
            recovered_time=recovered_time,
        ))

        remaining = [
            e for e in remaining
            if not (t_fault <= e["timestamp"] <= cascade_end and e["node_involved"] == root_cause_node)
        ]

    if not incidents:
        return []
    return incidents
