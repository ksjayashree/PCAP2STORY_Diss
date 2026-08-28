"""Layer 4 rule: MAC Mobility.

clean-move: full DETECTED rule with affected_node_pair (origin/
destination). Signal confirmed in Layer 2/3 checkpoints and this
session's MAC Mobility work: a BGP_WITHDRAWAL for mac_address=M from the
origin PE, followed by a BGP_UPDATE (advertise) for the same
mac_address=M from a different PE (destination). sequence_incremented is
always reported False -- a confirmed protocol-structural fact about this
injection method (RFC 7432 Sec 15 sequence number never increments under
it), not a detection failure, carried through explicitly rather than
omitted.

Confirmed false-positive fix (this session): the original naive pattern
("any withdraw followed by a different-PE advertise for the same MAC
within 30s") fired on all 18 normal baseline files, because ordinary
background MAC churn in the traffic generator produces the exact same
shape -- e.g. two PEs independently advertising the same synthetic MAC
close together, one later withdrawing and the other re-advertising, with
no real "move" involved. The rule does NOT use any scenario ground truth
or generation parameters (no hardcoded test MAC) -- it must work
identically on an unlabeled real capture. Instead it requires the
candidate MAC's entire event history in the fused stream to match a
strictly isolated transfer shape (see _is_isolated_move), and a
withdraw-to-advertise timing gap bounded by the actual observed real
transfer deltas this session (1.74-1.82s across 3 confirmed clean-move
captures) with a >2.7x margin -- background churn in the one normal file
checked showed a ~0.1s withdraw-to-readvertise gap for the same MAC,
which the isolation check rejects regardless of timing (a third
pre-existing advertise from the eventual "destination" node before the
withdrawal), so timing alone was confirmed insufficient and isolation is
the real filter.

rapid-flap / repeated-flap: run the same genuine search as clean-move --
no mechanism parameter (removed 2026-08-16), no hardcoded status. The
search logic itself never distinguished rapid/repeated flaps from a
single clean move; both are the same withdraw-then-advertise shape to
this module, just with different flap counts/timing. trigger_mechanism is
now classified purely from the per-MAC move count found on the wire in
detect() (1 = clean_move, 2 = rapid_flap, 3+ = repeated_flap) -- see
detect()'s own docstring for the full justification and corpus evidence.
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
from topology import ground_truth
from rules.schema import build_result

# WITHDRAW_TO_ADVERTISE_MAX_SECONDS / BACKWARD_ADVERTISE_MAX_SECONDS
# removed (2026-08-16): both were pure timing cutoffs on the withdraw<->
# readvertise match itself. Investigated and confirmed a genuine risk in
# naively removing them without replacement -- a real Normal-baseline
# case (pilot_containerlab/normal_heavy_2min, MAC 52:54:00:00:00:77,
# steady-state PE1/PE2 ES co-advertisement unrelated to any move) flips
# from correctly-rejected to wrongly-accepted if the backward window is
# simply deleted with no other change, because the destination's
# pre-existing advertisement (~6.16s before the withdrawal) no longer
# gets caught by anything. Replaced by two content-only conditions
# applied at match-selection time, both required: (1) the matched
# candidate is the first content-correct readvertisement found searching
# forward from the withdrawal, or -- only if no forward candidate
# qualifies -- the nearest content-correct readvertisement found
# searching backward from it; (2) the origin node itself never
# readvertises this same MAC at any point between the withdrawal and the
# matched candidate. Condition (2) is what actually closes the
# background-churn case above: in that history, origin PE1 re-advertises
# the MAC 0.05s after its own withdrawal, before PE2's candidate
# advertisement -- proof the address never left PE1. Validated against
# the full real+synthetic+Normal corpus (see detect()'s docstring).


def _pe_nodes(topo):
    return [n["id"] for n in topo["nodes"] if n.get("role") == "PE"]


def _esi_partners(topo, pe, pe_ids):
    """Other PEs sharing the same non-null ESI as `pe`, per topology.json's
    ground_truth (confirmed session investigation: 3RR's XPE3/XPE4 and
    XPE6/XPE7 ES-multihoming pairs). Either PE in an ES pair can
    independently advertise a locally-learned MAC -- this is genuine EVPN
    multihoming behavior, not noise, and previously caused 9/20 real 3RR
    clean-move files to be wrongly rejected by _is_isolated_move's
    single-party "third node touched this MAC" check."""
    esi = (ground_truth(topo, pe) or {}).get("esi")
    if not esi:
        return set()
    return {p for p in pe_ids if p != pe and (ground_truth(topo, p) or {}).get("esi") == esi}


def _origin_readvertised_between(events, mac, origin, t_a, t_b):
    """True if `origin` has an advertise event for `mac` strictly between
    t_a and t_b (order-agnostic -- t_a may be before or after t_b, since
    this is used for both the forward and backward candidate searches).
    This is condition (2) of the unbounded match replacement for
    WITHDRAW_TO_ADVERTISE_MAX_SECONDS/BACKWARD_ADVERTISE_MAX_SECONDS
    (removed 2026-08-16): if the origin itself re-advertises the MAC
    anywhere in the interval between its own withdrawal and a candidate
    readvertisement, the address never actually left -- the candidate is
    not a real destination, regardless of how close in time it is."""
    lo, hi = (t_a, t_b) if t_a < t_b else (t_b, t_a)
    for e in events:
        if not (lo < e["timestamp"] < hi):
            continue
        if e["node_involved"] != origin:
            continue
        pd = e["protocol_detail"]
        if e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise" and pd.get("mac_address") == mac:
            return True
    return False


def _mac_event_history(events, mac, pe_ids):
    """(timestamp, action, node) for every advertise/withdraw touching mac,
    across the WHOLE stream, node_involved restricted to PEs."""
    out = []
    for e in events:
        if e["node_involved"] not in pe_ids:
            continue
        pd = e["protocol_detail"]
        if pd.get("mac_address") != mac:
            continue
        if e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise":
            out.append((e["timestamp"], "advertise", e["node_involved"]))
        elif e["event_type"] == "BGP_WITHDRAWAL":
            out.append((e["timestamp"], "withdraw", e["node_involved"]))
    return sorted(out)


# Narrowed 2026-08-01 (confirmed via full investigation: 65/65 real
# background-churn false positives across the 18-file baseline set
# verified computationally, plus end-to-end detect() testing against a
# genuine repeated-flap capture). The real discriminator is not raw
# alternation between two nodes -- it's that background churn's
# destination already had a pre-existing advertisement before any
# withdrawal in the sequence, a signal fully carried by the "someone
# already had it" check below, independent of the second-withdrawal
# condition this replaces. The old node != origin gate on withdrawals
# rejected legitimate role-swaps across repeated flap cycles (origin and
# destination alternate cycle to cycle in a real multi-cycle flap
# sequence) -- removed in favor of a same-two-parties-only check that
# tolerates role-swapping.
#
# ESI-partner fan-out fix (this session, 3RR investigation): confirmed
# via direct wire inspection of 2 real failing 3RR files
# (mac_mobility_cleanmove_xpe2to6_settled, _xpe6to3_settled) that a third
# PE touching the MAC is NOT always background noise -- when that PE
# shares an ESI with the origin or destination (topology.json's own
# ground_truth, exact-match check via _esi_partners), its independent
# advertisement is genuine EVPN multihoming fan-out, not a different real
# host stealing the same MAC. This affected 9/20 real 3RR clean-move
# files (all involving XPE3/XPE4 or XPE6/XPE7, 3RR's two ES pairs) --
# pilot_containerlab's dataset never exposed this because its only ES
# pair (PE1/PE2) was never used as a move's origin/destination there.
#
# Confirmed this is NOT safe to fix by simply widening `parties`: 3RR's
# real normal-baseline traffic shows 157 background-churn MACs touched by
# exactly {XPE3, XPE4} (steady-state ES co-advertisement of ordinary
# locally-attached hosts, unrelated to any move) -- a naive "allow if
# ES-partner" change would have reintroduced mass false positives on
# these. The actual fix keeps the "already had it before withdrawal"
# check as the real discriminator, but widens it from the single
# `destination` node to the whole DESTINATION SIDE (destination + its own
# ES-partner, if any) -- the origin side's pre-existing ownership
# (including via origin's own ES-partner) is still never disqualifying,
# since a multihomed origin's partner necessarily already carried the MAC
# before any move, same reasoning as the original origin-only exemption.
# This also correctly still rejects the degenerate background-churn case
# where origin and destination happen to be literal ES-partners of each
# other (e.g. a coincidental XPE3-withdraw/XPE4-advertise shape): in that
# case XPE3 (origin) IS destination's ES-partner, so its own steady
# pre-existing advertisement now falls inside destination_side and
# correctly disqualifies it -- verified by hand against both real move
# files and the 157 real background-churn instances before implementing.
def _is_isolated_move(history, origin, destination, t_withdraw, origin_partners, destination_partners, t_transfer):
    """A real move's (possibly multi-cycle) MAC history contains only
    events from {origin, destination} plus their genuine ESI partners (if
    any) -- no node OUTSIDE that set ever touches this MAC -- and no node
    on the DESTINATION SIDE (destination itself or its ESI partner) may
    have already been advertising the MAC before the first withdrawal
    anywhere in the sequence (the shape that made background churn look
    like a move: the eventual arrival side already had it independently).
    The ORIGIN side's prior advertisement (including via origin's own ESI
    partner) is never grounds for rejection -- every genuine move requires
    the origin side to have owned the MAC before withdrawing it.

    Make-before-break exemption (added investigating xpe7to5_settled,
    reworked 2026-08-16 to remove BACKWARD_ADVERTISE_MAX_SECONDS): a
    destination-side advertise before the earliest withdrawal is exempted
    from the pre-existing-ownership rejection ONLY when it IS the specific
    t_transfer already selected by detect()'s own search (which applied
    the origin-non-readvertisement content check before ever choosing this
    candidate) -- ANY OTHER destination-side advertise before the earliest
    withdrawal still triggers rejection, since that's a second, unrelated
    prior appearance, not the one already-vetted transfer event."""
    parties = {origin, destination} | origin_partners | destination_partners
    destination_side = {destination} | destination_partners
    withdraw_times = [ts for ts, action, node in history if action == "withdraw"]
    earliest_withdraw = min(withdraw_times) if withdraw_times else t_withdraw
    for ts, action, node in history:
        if node not in parties:
            return False  # a node unrelated to either side's ESI touched this MAC
        if node in destination_side and action == "advertise" and ts < earliest_withdraw:
            if ts == t_transfer:
                continue  # the already-vetted make-before-break candidate itself
            return False  # some OTHER destination-side advertise predates the move -- pre-existing ownership
    return True


def _finalize(result, move_completed=None):
    """MAC Mobility replaces the shared schema's recovery_status field
    with move_completed (2026-08-14): 'recovery_status' as a session-
    up/down enum doesn't apply here -- a MAC move isn't a session going
    down and coming back, and this module only ever constructs a
    candidate incident once a genuine move has already been found
    complete (the destination's re-advertisement already located, see
    detect()'s search loop below), so recovery_status was always the
    same hardcoded "RECOVERED" value for every DETECTED incident, never a
    real wire-observed session-recovery signal. move_completed is a
    plain boolean, set only when a move was actually found (True);
    omitted entirely otherwise -- schema.py's null-filtering already
    drops not-applicable fields from NO_SIGNAL_FOUND/NOT_DETECTABLE_
    STRUCTURAL rows, so passing move_completed=None here (the default)
    leaves it out of those rows the same way root_cause_node etc. are
    already left out.

    recovered_time/recovered_time_readable renamed to move_completed_time/
    move_completed_time_readable (2026-08-16): same leftover-naming
    inconsistency as recovery_status -- "recovered" implies a session
    going down and coming back, which a MAC move never was. schema.py's
    build_result() still emits the shared recovered_time/recovered_time_
    readable field names (unchanged there, and unchanged for every other
    module) -- this module-local rename happens here, after build_result()
    has already run, so it never touches schema.py or any other module's
    output."""
    result.pop("recovery_status", None)
    if "recovered_time" in result:
        result["move_completed_time"] = result.pop("recovered_time")
    if "recovered_time_readable" in result:
        result["move_completed_time_readable"] = result.pop("recovered_time_readable")
    if move_completed is not None:
        result["move_completed"] = move_completed
    return result


def detect(fused_events, topo):
    """Returns a list of incident dicts -- always a list, never a bare dict,
    since a single capture can contain multiple genuine flap cycles for the
    same or different MACs (confirmed: synthcap's repeated-flap scenarios),
    not just the single move pilot_containerlab's clean-move captures
    happen to contain. Each qualifying withdrawal in the stream is
    evaluated independently; every one that passes the isolation check
    produces its own incident, not just the first.

    No mechanism parameter (2026-08-16, removed): the prior "cleanmove"/
    "rapidflap" hint never actually branched this module's matching logic
    (confirmed the same session it was reworked to a no-op) -- it only
    gated a ValueError on an unrecognized string. trigger_mechanism is now
    classified purely from what's found on the wire: every final incident
    is grouped by mac_address (tracked internally via mm_candidates, never
    exposed in the output schema), and the per-MAC count of genuine moves
    in THIS capture decides the label -- 1 move = "clean_move", 2 =
    "rapid_flap", 3+ = "repeated_flap" (same 2-vs-3+ split rd_collision.py
    uses for its own pair/multi distinction). Confirmed via full real+
    synthetic corpus investigation: real captures never exceed 2 moves for
    a single MAC (mac_mobility_cleanmove_xpe8to4_settled, same MAC
    XPE4->XPE8->XPE4), and the only real corpus files with 2 incidents for
    DIFFERENT MACs (catB_mac_mobility_x2's independent PE-pair moves)
    correctly stay "clean_move" each under this per-MAC grouping, not
    "rapid_flap" -- grouping by mac_address, not by file-level incident
    count, is what keeps that distinction correct."""
    events = sorted(fused_events, key=lambda e: e["timestamp"])
    pe_ids = set(_pe_nodes(topo))

    withdrawals = [
        e for e in events
        if e["event_type"] == "BGP_WITHDRAWAL" and e["node_involved"] in pe_ids
        and e["protocol_detail"].get("mac_address")
    ]

    incidents = []
    mm_candidates = []  # parallel (mac, incident_dict) list -- lets the
    # ESI-partner byproduct filter below compare candidates for the same
    # MAC without adding mac_address to the returned incident schema. Named
    # distinctly from the `candidates` local used further below inside the
    # per-withdrawal make-before-break fallback search, which is a raw-event
    # list for an unrelated purpose -- reusing the same name shadowed this
    # one across loop iterations.
    # Set when a withdrawal's ONLY candidate re-advertisement(s) for its MAC
    # came from the origin's own ESI partner -- i.e. the partner-exclusion
    # below is exactly why no destination was found for that withdrawal,
    # not because no re-advertisement existed at all. Only meaningful if
    # `incidents` ends up empty (see bottom of function); a withdrawal that
    # also has this flag set but still finds a genuine non-partner
    # destination elsewhere never reaches this distinction.
    esi_partner_collision = False

    for withdrawal in withdrawals:
        origin = withdrawal["node_involved"]
        mac = withdrawal["protocol_detail"]["mac_address"]
        t_fault = withdrawal["timestamp"]
        origin_partners = _esi_partners(topo, origin, pe_ids)

        destination = None
        t_transfer = None
        esi_partner_advertise_seen = False
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            if e["event_type"] != "BGP_UPDATE" or e["protocol_detail"].get("route_action") != "advertise":
                continue
            pd = e["protocol_detail"]
            if pd.get("mac_address") != mac:
                continue
            if e["node_involved"] not in pe_ids or e["node_involved"] == origin:
                continue
            # Skip origin's own ESI partner here -- its post-withdrawal
            # re-advertisement is origin-side fan-out, not the real
            # destination (confirmed: mac_mobility_cleanmove_xpe6to3_settled's
            # origin XPE6's partner XPE7 re-advertises ~0.1s after XPE6's own
            # withdrawal, well before the real destination XPE3 does at
            # +2.4s -- without this exclusion the loop below picks XPE7).
            if e["node_involved"] in origin_partners:
                esi_partner_advertise_seen = True
                continue
            # Unbounded (2026-08-16): no timing cutoff. Condition (2) --
            # origin never readvertised this MAC between the withdrawal and
            # this candidate -- is what actually protects against
            # background churn here, not a window. Events are
            # chronologically sorted, so the first candidate that passes
            # this check is the closest genuine one for this direction.
            if _origin_readvertised_between(events, mac, origin, t_fault, e["timestamp"]):
                continue  # origin re-advertised in between -- address never left, keep looking
            destination = e["node_involved"]
            t_transfer = e["timestamp"]
            break

        if destination is None:
            # Make-before-break fallback: only tried when no forward match
            # exists. Unbounded (2026-08-16): searches the whole capture
            # backward for an advertise before the withdrawal -- confirmed
            # via xpe7to5_settled (destination advertised 0.101s before
            # origin's withdrawal, verified on the wire) that real
            # transfers can arrive in this order. Condition (2) below and
            # _is_isolated_move (called after this loop) are what protect
            # against background churn matching here, not a window.
            candidates = []
            for e in events:
                if e["timestamp"] >= t_fault:
                    continue
                if e["event_type"] != "BGP_UPDATE" or e["protocol_detail"].get("route_action") != "advertise":
                    continue
                pd = e["protocol_detail"]
                if pd.get("mac_address") != mac:
                    continue
                if e["node_involved"] not in pe_ids or e["node_involved"] == origin:
                    continue
                if e["node_involved"] in origin_partners:
                    esi_partner_advertise_seen = True
                    continue
                if _origin_readvertised_between(events, mac, origin, e["timestamp"], t_fault):
                    continue  # origin re-advertised in between -- not a genuine make-before-break
                candidates.append(e)
            if candidates:
                # closest advertise to the withdrawal -- the most likely
                # true transfer partner if more than one candidate exists
                best = max(candidates, key=lambda e: e["timestamp"])
                destination = best["node_involved"]
                t_transfer = best["timestamp"]

        if destination is None:
            if esi_partner_advertise_seen:
                esi_partner_collision = True
            continue

        destination_partners = _esi_partners(topo, destination, pe_ids)
        history = _mac_event_history(events, mac, pe_ids)
        if not _is_isolated_move(history, origin, destination, t_fault, origin_partners, destination_partners, t_transfer):
            continue  # matches the shape but fails isolation -- likely background churn

        mm_candidates.append((mac, _finalize(build_result(
            fault_type="MAC Mobility",
            trigger_mechanism="clean_move",
            affected_node_pair={"origin": origin, "destination": destination},
            time_of_first_fault=t_fault,
            recovery_status="RECOVERED",
            recovered_time=t_transfer,
            extra={"sequence_incremented": False},
        ), move_completed=True)))

    # ESI-sync origin-partner byproduct filter (confirmed pattern across 6
    # real 3RR files: xpe3to0/xpe4to9/xpe6to0/xpe6to3/xpe7to5/xpe7to8_settled
    # -- when a real move's origin PE withdraws, its ESI-multihoming partner
    # (topology.json ground_truth) independently re-emits its own withdrawal
    # for the same MAC ~2.5-2.6s later (real move fault) or within
    # microseconds (xpe7to5's backward-matched case), which the outer loop
    # above -- one candidate per withdrawal event -- treats as a second,
    # independent move to the SAME destination. In all 6 confirmed cases the
    # genuine move's withdrawal is chronologically EARLIER than the
    # ESI-partner echo's. A candidate is suppressed as a byproduct only when
    # a DIFFERENT candidate for the SAME mac exists whose own origin fired
    # strictly earlier and whose ESI partner set contains this candidate's
    # origin -- this does not touch xpe8to4_settled (a confirmed SEPARATE,
    # not-yet-understood zebra-race byproduct where neither origin has an
    # ESI partner at all -- see mac_mobility.py's task history; deliberately
    # left alone here, not silently absorbed by this condition).
    survivors = []  # (mac, incident) pairs, ESI-partner byproducts removed
    for i, (mac_i, inc_i) in enumerate(mm_candidates):
        origin_i = inc_i["affected_node_pair"]["origin"]
        t_i = inc_i["time_of_first_fault"]
        is_esi_partner_byproduct = False
        for j, (mac_j, inc_j) in enumerate(mm_candidates):
            if j == i or mac_j != mac_i:
                continue
            origin_j = inc_j["affected_node_pair"]["origin"]
            t_j = inc_j["time_of_first_fault"]
            if t_j < t_i and origin_i in _esi_partners(topo, origin_j, pe_ids):
                is_esi_partner_byproduct = True
                break
        if not is_esi_partner_byproduct:
            survivors.append((mac_i, inc_i))

    if not survivors:
        # esi_partner_collision (a real withdrawal AND a real
        # re-advertisement of the same MAC both exist on the wire, but the
        # only re-advertiser is the origin's own ESI-multihomed partner --
        # genuinely indistinguishable from ordinary fan-out given available
        # signals) previously got its own NOT_DETECTABLE_STRUCTURAL status;
        # now collapses to the same bare [] every other "nothing to
        # report" case uses (2026-08-15) -- no status field survives to
        # carry that distinction.
        return []

    # Flap classification (2026-08-16): count genuine moves per MAC among
    # the surviving incidents -- 1 = clean_move, 2 = rapid_flap, 3+ =
    # repeated_flap. Grouping by mac_address (not by file-level incident
    # count) is what correctly keeps catB_mac_mobility_x2's two
    # INDEPENDENT single moves (different MACs, different PE pairs) as two
    # separate "clean_move" incidents rather than misreading the file as
    # one 2-move flap.
    move_counts = {}
    for mac, _ in survivors:
        move_counts[mac] = move_counts.get(mac, 0) + 1

    incidents = []
    for mac, inc in survivors:
        count = move_counts[mac]
        if count == 1:
            inc["trigger_mechanism"] = "clean_move"
        elif count == 2:
            inc["trigger_mechanism"] = "rapid_flap"
        else:
            inc["trigger_mechanism"] = "repeated_flap"
        incidents.append(inc)
    return incidents
