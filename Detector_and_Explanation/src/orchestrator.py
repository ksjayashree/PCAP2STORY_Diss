"""Layer 4 orchestrator: raw collector, no merging, no precedence logic.

Runs all six rule modules unconditionally against one fused event stream
and returns their complete raw output, keyed by fault_type. Deliberately
does NOT attempt to resolve cross-module co-detection (e.g. a real
link_down fault also tripping RR Down and PE Cease's own generic
signatures, confirmed this session across 49 of 85 real files) -- that's
a separate, not-yet-solved precedence problem. This module's only job is
packaging each rule's already-independently-verified behavior into one
call; it introduces no new detection logic.

rd_collision.py and mac_mobility.py still require a `mechanism` argument
that isn't derivable from wire data alone (a scenario-design choice, not
a wire-observable fact). rt_misconfiguration.py no longer takes one (2026-08-15,
reworked): its mechanism classification is now fully wire-derived from
the matched deviant event's own evpn_route_type, same as esdf_toggle.py
already was.
"""
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "rules"))

from rules import link_down, rr_down, pe_cease, rt_misconfiguration, rd_collision, mac_mobility, esdf_toggle
from topology import direct_peers, ground_truth


def run_all_rules(fused_events, topo, rd_collision_mechanism):
    """Returns {"Link Down": [...], "RR Down": [...], "PE Cease": [...],
    "RT Misconfiguration": [...], "RD Collision": [...], "MAC Mobility": [...],
    "ESDF Toggle": [...]} -- every value always a list[dict] (each module's
    own established convention), and always [] (bare empty list, no
    placeholder object) when that module found nothing. No merging across
    keys, no precedence applied. esdf_toggle.py, rt_misconfiguration.py, and
    mac_mobility.py (2026-08-16) take no mechanism argument -- all three
    are fully wire-derivable (route type + Ethernet Tag + DF Election
    community presence for esdf_toggle.py; route_target-vs-expected_rt
    deviation + the matched event's own route type for rt_misconfiguration.py;
    per-MAC move count found in the capture for mac_mobility.py's
    clean/rapid/repeated flap classification), confirmed against real
    data, not a scenario-design choice needing an external hint.
    rd_collision.py still does (its "simple"/"masking" split gates a
    genuinely different, currently-unimplemented detection path for
    "masking", not a post-search classification).

    CONCURRENCY CONTRACT (verified 2026-08-14, both real-file safety
    investigation and full-corpus validation before this was adopted): the
    7 detect() calls below are dispatched concurrently via
    ThreadPoolExecutor, one worker per module, all reading the same
    fused_events/topo objects. This is safe ONLY because every module's
    detect() treats fused_events/topo as read-only (each makes its own
    defensive sorted()/list() copy before doing any work) and none of the
    7 modules holds any shared mutable state (module-level cache, counter,
    or global written during detect()) -- confirmed directly against every
    detect() function body, not inferred from naming. Return dict key
    order is fixed explicitly below (via the `keys`/`futures` zip), NOT by
    whichever thread happens to finish first, so callers see the same key
    order as the prior sequential implementation regardless of thread
    scheduling. If any future edit to a rule module ever introduces
    caching, memoization, or in-place mutation of fused_events/topo, this
    concurrency contract breaks silently (non-deterministic incident
    counts/ordering or `RuntimeError: list changed size during iteration`,
    not a clean crash) -- re-verify read-only/no-shared-state before
    changing any of the 7 modules' detect() internals."""
    calls = [
        ("Link Down", link_down.detect, (fused_events, topo)),
        ("RR Down", rr_down.detect, (fused_events, topo)),
        ("PE Cease", pe_cease.detect, (fused_events, topo)),
        ("RT Misconfiguration", rt_misconfiguration.detect, (fused_events, topo)),
        ("RD Collision", rd_collision.detect, (fused_events, topo, rd_collision_mechanism)),
        ("MAC Mobility", mac_mobility.detect, (fused_events, topo)),
        ("ESDF Toggle", esdf_toggle.detect, (fused_events, topo)),
    ]
    with ThreadPoolExecutor(max_workers=len(calls)) as executor:
        futures = [executor.submit(fn, *args) for _, fn, args in calls]
        results = [f.result() for f in futures]
    return {key: result for (key, _, _), result in zip(calls, results)}


# Split 2026-08-09 from the single shared PRECEDENCE_WINDOW_SECONDS (was
# 2.0s, used identically across Rules 1-4's forward branch) into four
# separate named constants, one per rule -- direct measurement against
# the full real corpus (both projects) found these four use cases are NOT
# the same phenomenon: measured real ceilings span over three orders of
# magnitude between them (Rule 3's genuine cluster tops out at 0.536ms
# while Rule 1/Rule 2 reach 0.75-1.0s), so one shared constant was always
# just the loosest common denominator across four genuinely different
# real-world timings, not a deliberate bound for any one of them.

# Rule 1 (RR Down vs Link Down fault-onset): measured real max 0.751248s
# across n=60 (both real corpora, full -- pilot_containerlab + 3rr, every
# real bgpdkill/graceful co-occurring pair). 1.5s gives ~2x margin.
# bgpdkill's own real gap is sub-millisecond in BOTH topologies (max
# 0.000133s pilot, 0.000165s 3rr) -- no topology-scaling signal there at
# all. graceful's real gap, by contrast, increases meaningfully with
# topology size (max 0.601s pilot -> 0.751s 3rr, ~25% larger), consistent
# with the same sequential-per-peer-notification mechanism Rule 5's own
# GRACEFUL_PER_NEIGHBOR_DELAY_SECONDS already models via fan-out. Same
# re-validation caveat already applied there: derived from only 2
# topology instances, so a topology with meaningfully larger RR fan-out
# could push this real ceiling higher -- not yet a settled number.
RR_LINKDOWN_ONSET_WINDOW_SECONDS = 1.5

# Rule 2 (RR Down's own recovery cascade vs Link Down/PE Cease reconnect-
# churn): UNVERIFIED -- only 3 real samples exist total (1 pilot PE Cease
# @1.008984s, 2 3rr PE Cease @0.000693s/0.003448s; zero real Link Down
# samples in either project), and the single largest sample comes from
# the SMALLER topology, not the larger one, directly contradicting a
# naive scaling story. This is far too sparse to support any specific
# tightened value -- kept at the original 2.0s not because it has been
# re-validated, but because 3 noisy samples cannot responsibly justify
# any other number either. Do not treat this constant as evidence-based
# the way the other three now are.
RR_RECOVERY_CHURN_WINDOW_SECONDS = 2.0

# Rule 3 (PE Cease vs Link Down, same node): measured real genuine-
# cluster max 0.000536s across n=30 (full corpus, both projects) --
# confirmed FLAT, not topology-scaled (pilot genuine cluster tops out at
# 0.000536s, 3rr at 0.000429s, essentially identical), consistent with
# this being a single-node same-wire-event co-detection with no cascade
# or fan-out involved. Enormous, clean separation from the nearest
# artifact-cluster floor (13.5s, reconnect-phase noise) -- 1.0s gives
# >1800x margin over the genuine max while staying >13x below the
# artifact floor, leaving room on both sides for cross-vendor timing
# variance without any risk of the two clusters ever touching.
PE_CEASE_LINKDOWN_COOCCURRENCE_WINDOW_SECONDS = 1.0

# Rule 4 forward branch (MAC Mobility -> ESDF Toggle, exact origin,
# forward-only): measured real max 0.304516s across n=5 -- 3rr topology
# ONLY, zero pilot samples (pilot's only ES-multihoming pair is never
# used as a mac_mobility mover there, confirmed structurally absent, not
# merely unobserved). 1.0s gives >3.3x margin over the measured max, but
# this is single-topology evidence -- flagged explicitly, unlike Rule 1's
# two-topology comparison above.
MAC_MOBILITY_ESDF_FORWARD_WINDOW_SECONDS = 1.0

# Link Down <-> RR Down / PE Cease genuine co-occurrence window (this
# session's investigation): a real physical link-down event can ALSO be
# independently, correctly detected by RR Down's and PE Cease's own
# signatures, since BFD/TCP-level teardown signals are protocol-
# indistinguishable between "cable pulled" and "session/process killed".
# Deliberately NOT a single flat constant -- an earlier flat 1.0s design
# was rejected: hop-distance from the RR was checked directly (BFS over
# topology.json's own links) across every real graceful cascade in both
# projects and found CONSTANT (every affected PE is exactly 1 hop from
# its RR, confirmed both projects), so hop count cannot be the scaling
# variable. What DOES correlate, confirmed against topology.json's own
# direct_peers list order matching the observed per-PE gap order exactly:
# graceful RR shutdown notifies its PE clients SEQUENTIALLY, not
# simultaneously, so the cumulative gap for the LAST PE in a cascade
# scales with how many PEs that specific RR serves (fan-out), not with
# any network-distance measure. Per-step deltas measured across all 20
# real step-transitions in both projects: min=0.216s, max=0.320s,
# avg=0.254s -- GRACEFUL_PER_NEIGHBOR_DELAY_SECONDS uses the observed
# CEILING (0.320s), since the window must cover the worst real step seen,
# not the typical one. bgpdkill's near-zero jitter (0.000s-0.001s,
# confirmed in every real case, both projects -- a single abrupt
# session-kill is visible near-simultaneously to all peers, unlike
# graceful's real per-neighbor processing loop) is covered by
# BASE_MARGIN_SECONDS alone regardless of fan-out.
#
# CAVEAT: derived from 2 topology instances (2-RR fan-out 2-3, 3-RR
# fan-out 3-4) -- the linear-in-fan-out SHAPE is well-supported (20 real
# transitions), but GRACEFUL_PER_NEIGHBOR_DELAY_SECONDS itself should be
# re-validated if a topology with meaningfully larger per-RR fan-out
# (e.g. 10+) is ever added, same caution already applied to other
# single/few-topology-derived constants this session (TOL_FAULT_
# MACMOBILITY; mac_mobility.py's own former WITHDRAW_TO_ADVERTISE_MAX_
# SECONDS/BACKWARD_ADVERTISE_MAX_SECONDS were removed entirely 2026-08-16,
# replaced by content-only match criteria -- see mac_mobility.py).
GRACEFUL_PER_NEIGHBOR_DELAY_SECONDS = 0.320
BASE_MARGIN_SECONDS = 0.1


def _pe_fanout(topo, rr_node):
    """PE (not RR) direct clients of rr_node, per topology.json's own
    visibility.direct_peers -- the fan-out that drives graceful's
    sequential per-neighbor notification delay."""
    pe_ids = {n["id"] for n in topo["nodes"] if n.get("role") == "PE"}
    return direct_peers(topo, rr_node) & pe_ids


def cooccurrence_window_for_rr(topo, rr_node):
    """Worst-case Link-Down-co-occurrence window for THIS specific RR,
    scaled by how many PEs it actually serves (topology.json's own
    adjacency) -- not a flat constant tuned against whichever topologies
    happen to exist today. Covers the last PE in that RR's own graceful
    cascade with real margin: pilot RR1 (fan-out 3) -> 0.74s (observed
    max 0.601s, ~1.23x margin); 3rr XRR1 (fan-out 4) -> 1.06s (observed
    max 0.751s, ~1.4x margin)."""
    fanout = len(_pe_fanout(topo, rr_node))
    return BASE_MARGIN_SECONDS + max(0, fanout - 1) * GRACEFUL_PER_NEIGHBOR_DELAY_SECONDS


# Rule 6 (DF role vs ESDF Toggle, UNVERIFIED -- 2026-08-16): links a Link
# Down or PE Cease incident to the segment's next ESDF Toggle event when
# the failing PE was RFC 7432 SS8.5's Designated Forwarder for a shared
# Ethernet Segment at the moment of failure. No ground truth exists
# anywhere in this codebase (metadata.json, generator source, or a
# wire-decoded "DF role" field -- confirmed absent, only the DF Election
# Extended Community's AC-DF capability bit and algorithm-id are decoded)
# to confirm this against real data at scale. Every firing must be
# individually hand-traced against the raw capture before being trusted --
# see the validation report accompanying this change for exactly which
# firings were checked and what was found. Unlike Rules 1-5, this rule's
# match condition has NO time window at all -- it links to whichever
# ESDF Toggle incident is chronologically the segment's NEXT one after
# the failure, with no other incident on that segment intervening,
# by explicit design request (not a measured-then-omitted window).
def _esi_members(topo, esi):
    return {n["id"] for n in topo["nodes"] if n.get("role") == "PE"
            and (ground_truth(topo, n["id"]) or {}).get("esi") == esi}


def _active_type4_originators(esi, t, events):
    """PEs whose most recent Type-4 ES route action for this ESI, among
    all events with timestamp < t, was an advertise (not yet withdrawn) --
    RFC 7432 SS8.5's "currently advertising" candidate set for the DF
    election ordinal computation below. events must be chronologically
    sorted; only events strictly before t are considered ("immediately
    before the failure", per this rule's own explicit condition)."""
    last_action = {}  # pe -> "advertise" | "withdraw"
    for e in events:
        if e["timestamp"] >= t:
            break
        pd = e["protocol_detail"]
        if pd.get("evpn_route_type") != 4 or pd.get("esi") != esi:
            continue
        pe = e["node_involved"]
        if e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise":
            last_action[pe] = "advertise"
        elif e["event_type"] == "BGP_WITHDRAWAL":
            last_action[pe] = "withdraw"
    return {pe for pe, action in last_action.items() if action == "advertise"}


def _compute_df(topo, esi, t, events):
    """RFC 7432 SS8.5 default DF election: candidates are the ESI's members
    currently advertising a live Type-4 ES route (see
    _active_type4_originators above), sorted by router_id (IP) ascending;
    the DF is the candidate at ordinal (VNI mod N). Returns None if no
    candidate exists (segment fully withdrawn) -- no DF question applies
    then."""
    members = _esi_members(topo, esi)
    if not members:
        return None
    active = _active_type4_originators(esi, t, events) & members
    if not active:
        return None
    router_id_of = {n["id"]: n["router_id"] for n in topo["nodes"]}
    candidates = sorted(active, key=lambda pe: [int(x) for x in router_id_of[pe].split(".")])
    n = len(candidates)
    vni = topo["evpn"]["vni"]
    return candidates[vni % n]


def annotate_precedence(raw_results, topo, fused_events=None):
    """Strictly additive: takes run_all_rules()'s own output and returns a
    NEW dict of precedence annotations. Never mutates raw_results or any
    incident dict within it -- the six modules' own already-verified
    output is untouched, this is a pure interpretive layer on top.

    fused_events (2026-08-16, added for Rule 6 only): the same raw fused
    event stream passed to run_all_rules(), needed because Rule 6's DF
    election computation must scan raw Type-4 ES route advertise/withdraw
    history, which no rule module's own output exposes. Optional and
    defaults to None so every existing caller keeps working unchanged --
    Rule 6 is simply skipped (never fires) when it isn't supplied, rather
    than raising, since Rules 1-5 never needed raw events at all.

    Returns {"RR Down": [...], "PE Cease": [...], "Link Down": [...],
    "MAC Mobility": [...], "ESDF Toggle": [...]} -- "RR Down"/"PE Cease"/
    "MAC Mobility"/"ESDF Toggle" entries cover every DETECTED incident in
    those lists; "Link Down" entries are added only for incidents that
    anchor at least one LIKELY_ARTIFACT_OF_LINK_DOWN finding elsewhere (a
    Link Down incident may have zero, one, or multiple corroborated_by
    entries)."""
    link_down_list = raw_results.get("Link Down", [])
    rr_down_list = raw_results.get("RR Down", [])
    pe_cease_list = raw_results.get("PE Cease", [])

    precedence = {"RR Down": [], "PE Cease": [], "Link Down": []}
    link_down_anchors = {}  # link_down_index -> list of {"fault_type", "index"}
    rr_recovery_anchors = {}  # rr_down_index -> list of {"fault_type", "index"}

    def _add_anchor(ld_index, fault_type, incident_index):
        link_down_anchors.setdefault(ld_index, []).append(
            {"fault_type": fault_type, "index": incident_index}
        )

    def _add_rr_recovery_anchor(rr_index, fault_type, incident_index):
        rr_recovery_anchors.setdefault(rr_index, []).append(
            {"fault_type": fault_type, "index": incident_index}
        )

    # RR Down vs Link Down (fault-onset based). Computed FIRST, ahead of
    # the RR-Down-own-recovery rule below, because that rule must only
    # treat an RR Down incident as a genuine anchor -- an RR Down that is
    # ITSELF a spurious co-detection of a real Link Down/PE Cease fault
    # (this rule's own LIKELY_ARTIFACT_OF_LINK_DOWN outcome) must not be
    # used to demote that same real fault's incidents as "artifacts of the
    # RR's own recovery". Confirmed via testing: without this ordering/
    # gate, link_down_bfd_pe2_recovered and link_down_holdtimer_pe3_recovered
    # (real Link Down faults that also produce a spurious co-detected RR
    # Down, already known/documented cross-module co-detection) both had
    # their genuine PE Cease incidents wrongly demoted using that spurious
    # RR Down's own recovered_time as the anchor -- a regression introduced
    # while first implementing the RR-Down-own-recovery rule, caught by
    # the required all-85-file regression check before this was reported
    # as complete.
    rr_down_status = {}  # rr_down_index -> "GENUINE" or "LIKELY_ARTIFACT_OF_LINK_DOWN"
    for i, rr_inc in enumerate(rr_down_list):
        rr_root = rr_inc["root_cause_node"]
        rr_t = rr_inc["time_of_first_fault"]
        peers = direct_peers(topo, rr_root)
        matches = [
            j for j, ld_inc in enumerate(link_down_list)
            if ld_inc.get("root_cause_node") in peers
            and ld_inc.get("time_of_first_fault") is not None
            and abs(ld_inc["time_of_first_fault"] - rr_t) <= RR_LINKDOWN_ONSET_WINDOW_SECONDS
        ]
        if len(matches) == 1:
            j = matches[0]
            entry = {
                "index": i,
                "status": "LIKELY_ARTIFACT_OF_LINK_DOWN",
                "reason": (
                    f"1 co-occurring Link Down incident (root_cause_node="
                    f"{link_down_list[j]['root_cause_node']}) within "
                    f"{RR_LINKDOWN_ONSET_WINDOW_SECONDS}s"
                ),
                "corroborating_incidents": [{"fault_type": "Link Down", "index": j}],
            }
            _add_anchor(j, "RR Down", i)
        else:
            entry = {
                "index": i,
                "status": "GENUINE",
                "reason": f"{len(matches)} co-occurring Link Down incidents among RR's peers (expected exactly 1 for an artifact)",
            }
        precedence["RR Down"].append(entry)
        rr_down_status[i] = entry["status"]

    # RR Down's OWN recovery cascade vs Link Down/PE Cease (rr_down_bgpdkill_
    # rr1_recovered's PE2 second-flap case, this session's investigation):
    # a peer PE reconnecting a second time immediately after the RR's own
    # recovery completes produces the same RFC 4271 SS6.8 collision-tail
    # shape as a genuine fault, wrongly surfacing as an independent Link
    # Down + PE Cease pair. Confirmed single-occurrence across all 12 real
    # rr_down files (every other file's Link Down/PE Cease count matches
    # the RR's own peer count exactly; only this one has 1 extra of each).
    #
    # Reuses recovered_time (already an output field, no schema change) and
    # RR_RECOVERY_CHURN_WINDOW_SECONDS (already established, UNVERIFIED --
    # see its own docstring) rather than the per-peer cascade_end computed
    # internally by rr_down.py's detect() --
    # that internal value isn't exposed in the incident dict, and even if
    # it were, it falls 87 microseconds SHORT of covering the confirmed
    # spurious trigger (t=...488725 vs cascade_end=...488638), so it would
    # not have worked as a clean boundary anyway. recovered_time instead
    # covers this case with wide margin (3.2ms and 1.009s gaps, both well
    # inside the 2.0s window).
    #
    # Must run BEFORE the PE-Cease-vs-Link-Down rule below: without this,
    # that rule independently concludes "GENUINE, near a Link Down" using
    # the spurious Link Down (itself artifact of this same RR recovery) as
    # its anchor -- the actual mechanism behind the false positive this
    # rule fixes. PE Cease incidents claimed here are skipped there.
    #
    # KNOWN LIMITATION (documented, not fixed): no real file exists with a
    # genuine independent second PE fault landing within
    # RR_RECOVERY_CHURN_WINDOW_SECONDS of an RR's own recovery, so this rule
    # can't be tested against that specific false-negative risk -- same
    # caveat already carried by rr_down.py's own cascade-window logic.
    pe_cease_claimed_by_rr_recovery = set()
    for i, rr_inc in enumerate(rr_down_list):
        if rr_inc.get("recovery_status") != "RECOVERED":
            continue
        if rr_down_status.get(i) != "GENUINE":
            continue  # spurious co-detected RR Down -- never a valid anchor for this rule
        rr_root = rr_inc["root_cause_node"]
        rr_recovered_t = rr_inc.get("recovered_time")
        if rr_recovered_t is None:
            continue
        peers = direct_peers(topo, rr_root)

        for j, ld_inc in enumerate(link_down_list):
            if ld_inc.get("root_cause_node") not in peers:
                continue
            ld_t = ld_inc.get("time_of_first_fault")
            if ld_t is None or not (rr_recovered_t < ld_t <= rr_recovered_t + RR_RECOVERY_CHURN_WINDOW_SECONDS):
                continue
            precedence["Link Down"].append({
                "index": j,
                "status": "LIKELY_ARTIFACT_OF_RR_DOWN_RECOVERY",
                "reason": (
                    f"{ld_t - rr_recovered_t:.6f}s after RR Down incident's own "
                    f"recovered_time (root_cause_node={rr_root}), within "
                    f"{RR_RECOVERY_CHURN_WINDOW_SECONDS}s -- reconnect-churn artifact of "
                    f"the RR's own recovery, not an independent fault"
                ),
                "corroborating_incidents": [{"fault_type": "RR Down", "index": i}],
            })
            _add_rr_recovery_anchor(i, "Link Down", j)

        for k, pec_inc in enumerate(pe_cease_list):
            if pec_inc.get("root_cause_node") not in peers:
                continue
            pec_t = pec_inc.get("time_of_first_fault")
            if pec_t is None or not (rr_recovered_t < pec_t <= rr_recovered_t + RR_RECOVERY_CHURN_WINDOW_SECONDS):
                continue
            precedence["PE Cease"].append({
                "index": k,
                "status": "LIKELY_ARTIFACT_OF_RR_DOWN_RECOVERY",
                "reason": (
                    f"{pec_t - rr_recovered_t:.6f}s after RR Down incident's own "
                    f"recovered_time (root_cause_node={rr_root}), within "
                    f"{RR_RECOVERY_CHURN_WINDOW_SECONDS}s -- reconnect-churn artifact of "
                    f"the RR's own recovery, not an independent fault"
                ),
                "corroborating_incidents": [{"fault_type": "RR Down", "index": i}],
            })
            _add_rr_recovery_anchor(i, "PE Cease", k)
            pe_cease_claimed_by_rr_recovery.add(k)

    # PE Cease vs Link Down
    for i, pec_inc in enumerate(pe_cease_list):
        if i in pe_cease_claimed_by_rr_recovery:
            continue  # already annotated above, against the correct anchor (RR Down's own recovery)
        pec_root = pec_inc["root_cause_node"]
        pec_t = pec_inc["time_of_first_fault"]
        same_node_ld = [
            (j, ld_inc) for j, ld_inc in enumerate(link_down_list)
            if ld_inc.get("root_cause_node") == pec_root
            and ld_inc.get("time_of_first_fault") is not None
        ]
        if not same_node_ld:
            entry = {
                "index": i,
                "status": "GENUINE",
                "reason": "no co-occurring Link Down incident found for this PE",
            }
        else:
            j, nearest = min(same_node_ld, key=lambda pair: abs(pair[1]["time_of_first_fault"] - pec_t))
            gap = abs(nearest["time_of_first_fault"] - pec_t)
            if gap <= PE_CEASE_LINKDOWN_COOCCURRENCE_WINDOW_SECONDS:
                entry = {
                    "index": i,
                    "status": "GENUINE",
                    "reason": f"gap to nearest Link Down incident ({gap:.6f}s) within {PE_CEASE_LINKDOWN_COOCCURRENCE_WINDOW_SECONDS}s, same root_cause_node -- same real event, not a reconnect artifact",
                }
            else:
                entry = {
                    "index": i,
                    "status": "LIKELY_ARTIFACT_OF_LINK_DOWN",
                    "reason": f"gap to nearest same-PE Link Down incident ({gap:.6f}s) exceeds {PE_CEASE_LINKDOWN_COOCCURRENCE_WINDOW_SECONDS}s -- reconnect-phase artifact of an earlier, unrelated fault",
                    "corroborating_incidents": [{"fault_type": "Link Down", "index": j}],
                }
                _add_anchor(j, "PE Cease", i)
        precedence["PE Cease"].append(entry)

    # MAC Mobility / ESDF Toggle co-occurrence (this session's investigation):
    # moving a MAC on an ES-multihoming member PE genuinely produces BOTH a
    # real MAC Mobility event AND a real ESDF Toggle (Type-4 ES route
    # withdraw/re-advertise) as FRR's own downstream reaction -- confirmed
    # via wire timing across all 5 real 3RR files where both fire:
    # ESDF Toggle's trigger consistently and tightly follows MAC Mobility's
    # own trigger by 0.282-0.305s, and ESDF Toggle's root_cause_node always
    # equals MAC Mobility's ORIGIN PE (never destination). Confirmed
    # restricted to ES-paired PEs only (topology's ground_truth esi field):
    # pilot_containerlab's only ESI pair (PE1/PE2) is never used as a
    # mac_mobility mover in its 3 real files, so the pattern is structurally
    # absent there, not merely unobserved.
    #
    # Deliberately NOT a demotion rule like the others above: unlike Rules
    # 1-4, where the demoted side was genuine reconnect/collision-tail
    # NOISE (not a real independent fault at all), BOTH detections here are
    # confirmed real, correctly-detected, distinct protocol events. Tagging
    # ESDF Toggle as an "artifact" would misrepresent an accurate detection
    # as spurious. Both sides are tagged CONFIRMED_COOCCURRENCE (not
    # GENUINE, not an artifact status) with a symmetric cross-reference,
    # noting MAC Mobility as the temporally leading/triggering side without
    # implying the other side is wrong or should be discounted.
    #
    # ESI-partner + reversed-timing extension, CORRECTED 2026-08-08: this
    # rule was originally written believing mac_mobility_cleanmove_
    # xpe7to5_settled (3rr) needed an ESI-partner match -- ESDF Toggle
    # firing on XPE6 (XPE7's ESI partner), 2.146s BEFORE MAC Mobility's
    # own reported time_of_first_fault. Direct re-trace (2026-08-08,
    # prompted by this file surfacing as a live, still-undemoted
    # cross-module false positive) found that premise was simply wrong:
    # ESDF Toggle actually fires on XPE7 itself (the ORIGIN, not its ESI
    # partner) in this file, still 2.145852s backward. Checked directly
    # against all 6 real 3rr files where MAC Mobility and ESDF Toggle both
    # fire (pilot_containerlab has zero -- its only ESI pair, PE1/PE2, is
    # never a mac_mobility mover there, confirmed structurally absent, not
    # merely unobserved): every one of the 6 is an exact origin-node
    # match, never an ESI-partner match -- 5 forward (0.282-0.305s,
    # already covered by the exact-origin/forward-only search above) and
    # this 1 backward (-2.145852s). No genuine ESI-partner case has ever
    # been observed, so the fallback below now checks BOTH the same-origin
    # backward case and the ESI-partner case (kept for the scenario this
    # rule was originally meant to cover, should one ever appear) --
    # neither branch touches the 5 already-matching forward cases, which
    # still resolve via the unchanged exact-origin/forward-only search
    # above and never reach this fallback at all.
    #
    # Implemented as a SEPARATE fallback search tried only when the
    # original exact-origin/forward-only search above finds nothing --
    # this guarantees every previously-matching case keeps matching via
    # the exact same code path as before, unchanged, rather than risking
    # a single merged condition subtly reordering or reclassifying an
    # existing match.
    #
    # PROVISIONAL, NOT a measured relationship like Group 1-3's fan-out
    # window: this rests on a SINGLE observed sample (gap=-2.145852s).
    # 5.0s each direction gives real margin over that one gap (~2.3x) but
    # is a single-sample margin pick, not a derived constant -- re-derive
    # if more backward-matched ESDF Toggle co-occurrences (origin or
    # ESI-partner) are ever confirmed, same caution already applied to
    # TOL_FAULT_MACMOBILITY elsewhere this session (mac_mobility.py's own
    # former WITHDRAW_TO_ADVERTISE_MAX_SECONDS/BACKWARD_ADVERTISE_MAX_
    # SECONDS were removed entirely 2026-08-16, not merely re-derived).
    ESI_PARTNER_COOCCURRENCE_WINDOW_SECONDS = 5.0

    mac_mobility_list = raw_results.get("MAC Mobility", [])
    esdf_toggle_list = raw_results.get("ESDF Toggle", [])
    precedence["MAC Mobility"] = []
    precedence["ESDF Toggle"] = []
    pe_ids_for_esi = set(mac_mobility._pe_nodes(topo))

    # MAC-Mobility-side exemption REMOVED (retired once mac_mobility.py's
    # own ESI-partner byproduct filter started suppressing the artifact at
    # the source -- see mac_mobility.py's "ESI-sync origin-partner
    # byproduct filter" comment). That filter used a co-occurring ESDF
    # Toggle incident to explain away a SECOND MAC Mobility incident for
    # the same move; now that mac_mobility.py itself never emits that
    # second incident for the 6 confirmed ESI-partner-echo files, there is
    # nothing left for this side of the rule to exempt -- every surviving
    # DETECTED MAC Mobility incident is already the real move. (Does NOT
    # cover mac_mobility_cleanmove_xpe8to4_settled -- a separate, still
    # open, not-ESI-partner-shaped byproduct left deliberately unfiltered
    # in mac_mobility.py; its second incident is correctly still flagged
    # GENUINE below and surfaces as an undemoted false positive, same as
    # before this change.)
    for i, mm_inc in enumerate(mac_mobility_list):
        precedence["MAC Mobility"].append({
            "index": i, "status": "GENUINE",
            "reason": "no exemption path remains here -- mac_mobility.py's own ESI-partner byproduct filter already suppresses the artifact this rule used to explain away",
        })

    # ESDF-Toggle-side KEPT INTACT: this answers a separate, still-valid
    # question -- does a genuine ESDF Toggle incident correspond to a
    # genuine, co-occurring MAC Mobility move (both real, both correctly
    # detected, FRR's own downstream ES-route reaction to the move)? This
    # has nothing to do with MAC Mobility's own duplicate-incident problem
    # and is unaffected by mac_mobility.py's fix.
    for j, ed_inc in enumerate(esdf_toggle_list):
        ed_t = ed_inc.get("time_of_first_fault")
        ed_node = ed_inc.get("root_cause_node")
        match = None
        match_kind = None

        for i, mm_inc in enumerate(mac_mobility_list):
            pair = mm_inc.get("affected_node_pair") or {}
            origin = pair.get("origin")
            mm_t = mm_inc.get("time_of_first_fault")
            if origin is None or mm_t is None or ed_t is None:
                continue
            # Original search: exact origin, forward-only.
            if ed_node == origin and mm_t < ed_t <= mm_t + MAC_MOBILITY_ESDF_FORWARD_WINDOW_SECONDS:
                match = i
                match_kind = "origin"
                break
            # Fallback search 1 (2026-08-08): exact origin, BACKWARD in
            # time, within the provisional symmetric window -- the actual
            # shape of xpe7to5_settled's real sample (see comment above),
            # not an ESI-partner case as originally believed.
            if ed_node == origin and ed_t < mm_t and abs(ed_t - mm_t) <= ESI_PARTNER_COOCCURRENCE_WINDOW_SECONDS:
                match = i
                match_kind = "origin_backward"
                break
            # Fallback search 2: origin's ESI partner, either direction,
            # within the provisional symmetric window. Kept for the
            # scenario this rule was originally written for; no confirmed
            # real sample has ever matched this branch (see comment above).
            partners = mac_mobility._esi_partners(topo, origin, pe_ids_for_esi)
            if ed_node in partners and abs(ed_t - mm_t) <= ESI_PARTNER_COOCCURRENCE_WINDOW_SECONDS:
                match = i
                match_kind = "esi_partner"
                break

        if match is None:
            precedence["ESDF Toggle"].append({
                "index": j, "status": "GENUINE",
                "reason": "no co-occurring MAC Mobility incident on this PE",
            })
            continue

        origin = mac_mobility_list[match]["affected_node_pair"]["origin"]
        mm_t = mac_mobility_list[match]["time_of_first_fault"]
        gap = ed_t - mm_t
        if match_kind == "origin":
            reason = (
                f"follows MAC Mobility incident {match}'s trigger by {gap:.6f}s on the "
                f"same (origin) PE -- genuine downstream reaction, not an independent fault"
            )
        elif match_kind == "origin_backward":
            reason = (
                f"occurs {gap:+.6f}s relative to MAC Mobility incident {match}'s trigger, "
                f"same (origin) PE, ahead of it (make-before-break) -- genuine downstream "
                f"reaction, not an independent fault"
            )
        else:
            reason = (
                f"occurs {gap:+.6f}s relative to MAC Mobility incident {match}'s trigger "
                f"on {origin} (this node is {origin}'s ESI partner) -- genuine downstream "
                f"reaction, not an independent fault"
            )
        precedence["ESDF Toggle"].append({
            "index": j,
            "status": "CONFIRMED_COOCCURRENCE",
            "reason": reason,
            "co_occurring_with": [{"fault_type": "MAC Mobility", "index": match}],
        })

    # Link Down <-> RR Down / PE Cease genuine co-occurrence
    # (cooccurrence_window_for_rr() above, this session's investigation):
    # unlike Rules 1-4 above (where the demoted side was genuine
    # reconnect/collision-tail NOISE, not an independent fault at all),
    # both sides here are confirmed real, correctly-detected, distinct-
    # module observations of the SAME real event -- a physical link
    # failure is also visible to RR Down's/PE Cease's own BFD/TCP-level
    # signatures. Same CONFIRMED_COOCCURRENCE treatment as the MAC
    # Mobility/ESDF Toggle rule above, not a demotion.
    #
    # Computed LAST and PREPENDED (list.insert(0, ...)) to each affected
    # precedence list rather than appended, deliberately: scorer_lib.py's
    # lookup takes the FIRST list entry matching a given index, and the
    # existing rules above already unconditionally append an entry (often
    # GENUINE, not exempt) for every DETECTED RR Down/PE Cease incident.
    # Prepending guarantees this rule's CONFIRMED_COOCCURRENCE entry is
    # the one found, without needing to touch the existing rules' own
    # internal logic (rr_down_status, pe_cease_claimed_by_rr_recovery)
    # at all -- this rule only ever ADDS an explanation, never removes or
    # reorders the pre-existing ones for indices it doesn't claim.
    #
    # Explicitly excludes indices already explained a DIFFERENT way by the
    # rules above, since those are genuinely different mechanisms, not
    # this one: a Link Down index already in link_down_anchors is the
    # CAUSE of an artifact elsewhere (RR Down is fake, not co-occurring);
    # an RR Down index already LIKELY_ARTIFACT_OF_LINK_DOWN is itself the
    # fake side (same reasoning); a PE Cease index already claimed by the
    # RR-recovery-cascade rule is reconnect-churn noise, not this
    # mechanism.
    new_link_down_entries = []
    new_rr_down_entries = []
    new_pe_cease_entries = []
    link_down_cooccurrence_claimed = set()

    for i, rr_inc in enumerate(rr_down_list):
        if rr_down_status.get(i) == "LIKELY_ARTIFACT_OF_LINK_DOWN":
            continue  # already explained the opposite way -- RR Down is the fake side there
        rr_root = rr_inc["root_cause_node"]
        rr_t = rr_inc.get("time_of_first_fault")
        if rr_t is None:
            continue
        window = cooccurrence_window_for_rr(topo, rr_root)
        pe_clients = _pe_fanout(topo, rr_root)
        for j, ld_inc in enumerate(link_down_list):
            if j in link_down_anchors or j in link_down_cooccurrence_claimed:
                continue
            if ld_inc.get("root_cause_node") not in pe_clients:
                continue
            ld_t = ld_inc.get("time_of_first_fault")
            if ld_t is None:
                continue
            gap = ld_t - rr_t
            # Only forward gaps within this RR's own fan-out-scaled window
            # count -- e.g. the confirmed +20.733s later, independent
            # second re-flap (rr_down_bgpdkill_rr1_recovered) stays
            # outside every real RR's window (max 1.06s) and is correctly
            # left unexplained, not swept in.
            if not (0 <= gap <= window):
                continue
            new_link_down_entries.append({
                "index": j,
                "status": "CONFIRMED_COOCCURRENCE",
                "reason": (
                    f"{gap:.6f}s after RR Down incident's own trigger (root_cause_node="
                    f"{rr_root}), within that RR's fan-out-scaled window ({window:.3f}s, "
                    f"{len(pe_clients)} PE clients) -- genuine BFD/TCP-level co-detection "
                    f"of the same real event, not an independent fault"
                ),
                "co_occurring_with": [{"fault_type": "RR Down", "index": i}],
            })
            new_rr_down_entries.append({
                "index": i,
                "status": "CONFIRMED_COOCCURRENCE",
                "reason": (
                    f"co-occurring Link Down incident (root_cause_node="
                    f"{ld_inc.get('root_cause_node')}) {gap:.6f}s later, within this "
                    f"RR's fan-out-scaled window ({window:.3f}s) -- same real event, "
                    f"not an independent fault"
                ),
                "co_occurring_with": [{"fault_type": "Link Down", "index": j}],
            })
            link_down_cooccurrence_claimed.add(j)

    for i, pec_inc in enumerate(pe_cease_list):
        if i in pe_cease_claimed_by_rr_recovery:
            continue  # already explained as reconnect-churn artifact of the RR's own recovery, a different mechanism
        pec_root = pec_inc["root_cause_node"]
        pec_t = pec_inc.get("time_of_first_fault")
        if pec_t is None:
            continue
        for j, ld_inc in enumerate(link_down_list):
            if j in link_down_anchors or j in link_down_cooccurrence_claimed:
                continue
            if ld_inc.get("root_cause_node") != pec_root:
                continue
            ld_t = ld_inc.get("time_of_first_fault")
            if ld_t is None:
                continue
            gap = abs(ld_t - pec_t)
            # Same-node, near-simultaneous (observed 0.000-0.001s in every
            # real case, both projects) -- no fan-out scaling needed,
            # this is a single-node event pair, not a cascading one, so
            # BASE_MARGIN_SECONDS alone is the right bound.
            if gap > BASE_MARGIN_SECONDS:
                continue
            new_link_down_entries.append({
                "index": j,
                "status": "CONFIRMED_COOCCURRENCE",
                "reason": (
                    f"{gap:.6f}s from PE Cease incident's own trigger (same node "
                    f"{pec_root}), within {BASE_MARGIN_SECONDS}s -- genuine same-event "
                    f"co-detection, not an independent fault"
                ),
                "co_occurring_with": [{"fault_type": "PE Cease", "index": i}],
            })
            new_pe_cease_entries.append({
                "index": i,
                "status": "CONFIRMED_COOCCURRENCE",
                "reason": (
                    f"co-occurring Link Down incident (same node) {gap:.6f}s away, "
                    f"within {BASE_MARGIN_SECONDS}s -- same real event, not an "
                    f"independent fault"
                ),
                "co_occurring_with": [{"fault_type": "Link Down", "index": j}],
            })
            link_down_cooccurrence_claimed.add(j)
            break

    precedence["Link Down"][0:0] = new_link_down_entries
    precedence["RR Down"][0:0] = new_rr_down_entries
    precedence["PE Cease"][0:0] = new_pe_cease_entries

    # RESOLVED 2026-08-08 (was a "KNOWN GAP, NOT YET IMPLEMENTED" pointer
    # here): mac_mobility_cleanmove_xpe7to5_settled's real co-occurrence is
    # now handled by the origin_backward fallback in the MAC Mobility/ESDF
    # Toggle rule above -- see that rule's own comment for the corrected
    # finding (exact origin match, not ESI-partner as originally believed).

    # Link Down: only entries for incidents anchoring at least one artifact finding
    for j in sorted(link_down_anchors):
        precedence["Link Down"].append({
            "index": j,
            "status": "CONFIRMED_ROOT_CAUSE",
            "corroborated_by": link_down_anchors[j],
        })

    # RR Down: attach corroborated_by onto its EXISTING entry (from the RR
    # Down vs Link Down rule above -- every DETECTED RR Down incident
    # already gets exactly one entry there) rather than appending a
    # second, duplicate row for the same index. An RR Down incident's own
    # GENUINE/LIKELY_ARTIFACT_OF_LINK_DOWN status (about whether IT is
    # real) is a separate question from whether it, in turn, anchors other
    # incidents' artifacts -- both can be true on the same entry.
    for entry in precedence["RR Down"]:
        if entry["index"] in rr_recovery_anchors:
            entry["corroborated_by"] = rr_recovery_anchors[entry["index"]]

    # Rule 6 (DF role vs ESDF Toggle) -- see its own module-level comment
    # above _esi_members for the full justification and UNVERIFIED status.
    # Only runs when fused_events was supplied.
    if fused_events is not None:
        events = sorted(fused_events, key=lambda e: e["timestamp"])
        esdf_by_esi = {}
        for j, ed_inc in enumerate(esdf_toggle_list):
            nodes = set()
            if ed_inc.get("root_cause_node"):
                nodes.add(ed_inc["root_cause_node"])
            pair = ed_inc.get("affected_node_pair")
            if pair:
                nodes.update(pair.values())
            for node in nodes:
                esi = (ground_truth(topo, node) or {}).get("esi")
                if esi:
                    esdf_by_esi.setdefault(esi, []).append((j, ed_inc))

        def _link_df_rule(list_name, incidents_list):
            for i, inc in enumerate(incidents_list):
                node = inc.get("root_cause_node")
                t_fault = inc.get("time_of_first_fault")
                if node is None or t_fault is None:
                    continue
                esi = (ground_truth(topo, node) or {}).get("esi")
                if not esi:
                    continue  # not multihomed -- no DF question applies
                df = _compute_df(topo, esi, t_fault, events)
                if df != node:
                    continue  # failing PE was not the DF -- rule doesn't apply

                members = _esi_members(topo, esi)
                candidates = esdf_by_esi.get(esi, [])
                later = [(j, e) for j, e in candidates if e.get("time_of_first_fault", -1) > t_fault]
                if not later:
                    continue
                j, matched = min(later, key=lambda pair: pair[1]["time_of_first_fault"])
                et_t = matched["time_of_first_fault"]

                # "Nothing else intervening": no OTHER incident (any fault
                # type, any list) attributed to a member of this same ES
                # may land strictly between t_fault and et_t.
                intervening = False
                for other_list in raw_results.values():
                    for other_inc in other_list:
                        other_nodes = set()
                        if other_inc.get("root_cause_node"):
                            other_nodes.add(other_inc["root_cause_node"])
                        other_pair = other_inc.get("affected_node_pair")
                        if other_pair:
                            other_nodes.update(other_pair.values())
                        for nd in (other_inc.get("affected_nodes") or []):
                            other_nodes.add(nd)
                        if not (other_nodes & members):
                            continue
                        other_t = other_inc.get("time_of_first_fault")
                        if other_t is None:
                            continue
                        if t_fault < other_t < et_t:
                            intervening = True
                            break
                    if intervening:
                        break
                if intervening:
                    continue

                precedence[list_name].insert(0, {
                    "index": i,
                    "status": "CONFIRMED_COOCCURRENCE",
                    "reason": (
                        f"{node} was the RFC 7432 SS8.5 Designated Forwarder for its "
                        f"Ethernet Segment at the moment of failure, and ESDF Toggle "
                        f"incident {j} ({et_t - t_fault:.6f}s later) is that segment's "
                        f"next DF election event with nothing else intervening -- "
                        f"UNVERIFIED against ground truth, hand-check before trusting"
                    ),
                    "co_occurring_with": [{"fault_type": "ESDF Toggle", "index": j}],
                })
                for et_entry in precedence["ESDF Toggle"]:
                    if et_entry["index"] == j:
                        et_entry.setdefault("corroborated_by", []).append({"fault_type": list_name, "index": i})

        _link_df_rule("Link Down", link_down_list)
        _link_df_rule("PE Cease", pe_cease_list)

    return precedence
