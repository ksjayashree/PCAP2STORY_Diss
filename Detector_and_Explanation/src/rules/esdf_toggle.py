"""Layer 4 rule: ESDF Toggle (ES/DF re-election triggers, RFC 8584).

No `mechanism` parameter, unlike rt_misconfiguration.py/rd_collision.py/
mac_mobility.py -- unlike those, ESDF's mechanism is fully derivable from
the wire alone (route type + Ethernet Tag + DF Election Extended
Community presence + single-PE vs dual-PE-same-ESI shape), confirmed by
reading the synthcap generator source directly
(generators/evpn_bgp/scenarios/esdf_toggle.py, mixed.py's
ESDFFullFailure, bgp/evpn.py, bgp/attributes.py's
encode_df_election_community) rather than assuming from RFC text alone:

- Type-4 ES route withdraw/re-advertise (RFC 7432/8584's primary
  DF-election signal): evpn_route_type == 4, withdrawn then re-advertised
  by a single PE.
- Type-1 per-EVI EAD withdraw/re-advertise (RFC 8584's second
  DF-election trigger type): evpn_route_type == 1, Ethernet Tag != the
  per-ES sentinel (0xFFFFFFFF) -- confirmed via build_ead_per_evi's own
  ethernet_tag=0 usage, distinct from build_ead_per_es's 0xFFFFFFFF.
  Single PE.
- AC-state DF Election Extended Community toggle (RFC 8584 SS2.2/SS3,
  first trigger type): evpn_route_type == 4, NEVER withdrawn -- the same
  route is re-advertised carrying the DF Election Extended Community
  (ext-comm type 0x06/sub-type 0x06) with the AC-DF capability bit
  cleared, then re-advertised again with it set. Confirmed: ESDFACStateToggle
  overrides generate() to skip withdrawal entirely.
- Dual-PE Type-1 per-ES withdrawal (ES Full Failure, no single surviving
  DF candidate): evpn_route_type == 1, Ethernet Tag == 0xFFFFFFFF
  (per-ES sentinel, via build_ead_per_es), withdrawn independently by
  BOTH PEs in a topology-confirmed ESI pair within a small window.
  Confirmed generator gap: 150-280ms (mixed.py's ESDFFullFailure, uniform
  random 0.15-0.28s), max observed on real data 0.2817s.
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

# 60s is a fallback cascade-consumption bound for the NOT_RECOVERED case
# only -- real recovery detection above is unbounded (validated against 27
# real PE Cease incidents, gaps 10.0-301.7s, and 7 ESDF Toggle incidents,
# gaps 10.4-19.7s, 0 discrepancies). No real NOT_RECOVERED multi-incident
# same-node data exists in the corpus to calibrate this fallback further;
# 60s is a conservative placeholder, not a measured value.
RECOVERY_WINDOW_SECONDS = 60

# Per-ES EAD route sentinel Ethernet Tag (RFC 7432, confirmed via the
# generator's own build_ead_per_es -> build_evpn_type1(..., 0xFFFFFFFF, ...)).
PER_ES_ETHERNET_TAG = 0xFFFFFFFF

# Confirmed generator gap for the two independent per-ES withdrawals in a
# genuine dual-PE full failure: uniform(0.15, 0.28)s, max observed on real
# data 0.2817s. 1.0s gives >3.5x margin over the largest observed gap --
# single real file measured (only one full_failure_recovered/no_recovery
# pair exists), so kept generous rather than tight, same caution already
# applied to single-sample windows earlier this session.
FULL_FAILURE_PAIR_WINDOW_SECONDS = 1.0

TRIGGER_TYPE4 = "Type-4 ES Route Withdrawal"
TRIGGER_TYPE1_EVI = "Type-1 Per-EVI EAD Withdrawal"
TRIGGER_TYPE1_ES_DUAL = "Dual-PE Type-1 Per-ES Withdrawal (ES Full Failure)"
TRIGGER_AC_STATE = "AC-State DF Election Community Toggle"


def _pe_nodes(topo):
    return {n["id"] for n in topo["nodes"] if n.get("role") == "PE"}


def _esi_partner(topo, pe, pe_ids):
    """The other PE sharing pe's non-null ESI, if any -- same structural
    lookup as mac_mobility.py's _esi_partners, needed here to identify the
    second PE in a genuine dual-PE ES Full Failure."""
    esi = (ground_truth(topo, pe) or {}).get("esi")
    if not esi:
        return None
    for p in pe_ids:
        if p != pe and (ground_truth(topo, p) or {}).get("esi") == esi:
            return p
    return None


def _is_type4_withdrawal(e, pe_ids):
    return (e["event_type"] == "BGP_WITHDRAWAL" and e["node_involved"] in pe_ids
            and e["protocol_detail"].get("evpn_route_type") == 4)


def _is_type1_evi_withdrawal(e, pe_ids):
    if e["event_type"] != "BGP_WITHDRAWAL" or e["node_involved"] not in pe_ids:
        return False
    pd = e["protocol_detail"]
    return pd.get("evpn_route_type") == 1 and pd.get("ethernet_tag") != PER_ES_ETHERNET_TAG


def _is_type1_es_withdrawal(e, pe_ids):
    if e["event_type"] != "BGP_WITHDRAWAL" or e["node_involved"] not in pe_ids:
        return False
    pd = e["protocol_detail"]
    return pd.get("evpn_route_type") == 1 and pd.get("ethernet_tag") == PER_ES_ETHERNET_TAG


# Cross-module false-positive investigation (this session, run against
# all 254 real pilot_containerlab/3RR files): real FRR attaches a genuine
# RFC 8584 DF Election Extended Community to EVERY Type-4 advertisement as
# standard practice (confirmed via raw byte inspection of a real capture --
# ec bytes 06 06 02 00 00 00 00 64, i.e. df_alg=2, AC-DF bit clear), with
# the AC-DF bit permanently clear in steady state (confirmed: True never
# appears anywhere in any of the 254 real files' fused streams). Synthcap's
# synthetic generator, by contrast, OMITS this community entirely except
# during an actual AC-state fault. So "presence with the bit clear" alone
# is not a safe discriminator against real traffic -- naively checking it
# produced 25/103 false positives on pilot_containerlab. The genuine
# signature is a real OBSERVED TRANSITION (False, later reversed to True
# for the same PE), not a static snapshot -- confirmed True is never seen
# at all in real background traffic, so requiring it as part of the
# trigger condition itself (not just the recovery-status field) is safe
# and mirrors the unbounded-recovery-search convention used everywhere
# else tonight rather than inventing a new bounded window.
def _is_ac_state_fault(e, all_events, pe_ids):
    if e["event_type"] != "BGP_UPDATE" or e["node_involved"] not in pe_ids:
        return False
    pd = e["protocol_detail"]
    if not (pd.get("route_action") == "advertise" and pd.get("evpn_route_type") == 4
            and pd.get("df_election_ac_df") is False):
        return False
    pe = e["node_involved"]
    t = e["timestamp"]
    return any(
        e2["timestamp"] > t and e2["node_involved"] == pe
        and e2["event_type"] == "BGP_UPDATE"
        and e2["protocol_detail"].get("route_action") == "advertise"
        and e2["protocol_detail"].get("evpn_route_type") == 4
        and e2["protocol_detail"].get("df_election_ac_df") is True
        for e2 in all_events
    )


def _closer_near_miss(current, candidate):
    """Keeps whichever of two near_miss dicts (or None) has the smaller
    gap_seconds -- None is always replaced by any real candidate."""
    if candidate is None:
        return current
    if current is None or candidate["gap_seconds"] < current["gap_seconds"]:
        return candidate
    return current


def _find_one_trigger(candidate_events, all_events, topo, pe_ids):
    """Chronologically-first fault-relevant event wins, same convention as
    every other module tonight. Returns (kind, event, pe, partner_pe,
    near_miss) -- partner_pe only set for the dual-PE ES Full Failure
    case, near_miss only set (and only meaningful) when no trigger at all
    was found (kind is None): the single closest content-correct-but-
    timed-out type1_es_dual candidate encountered during the scan (this
    is currently the only branch in this module with a real timing gate
    that can reject an otherwise-qualifying candidate -- type4/type1_evi/
    ac_state have no comparable window to miss)."""
    best_near_miss = None
    for e in candidate_events:
        if _is_type4_withdrawal(e, pe_ids):
            return "type4", e, e["node_involved"], None, None
        if _is_type1_evi_withdrawal(e, pe_ids):
            return "type1_evi", e, e["node_involved"], None, None
        if _is_type1_es_withdrawal(e, pe_ids):
            pe = e["node_involved"]
            partner = _esi_partner(topo, pe, pe_ids)
            if partner is None:
                continue  # no ESI partner in this topology -- not a genuine dual-PE shape
            t = e["timestamp"]
            partner_withdraw = next(
                (e2 for e2 in all_events
                 if _is_type1_es_withdrawal(e2, pe_ids) and e2["node_involved"] == partner
                 and abs(e2["timestamp"] - t) <= FULL_FAILURE_PAIR_WINDOW_SECONDS),
                None,
            )
            if partner_withdraw is None:
                # Content-correct (partner IS this PE's real ESI partner,
                # and it DID withdraw its own per-ES route at some point)
                # but outside the pairing window -- record the closest
                # such partner withdrawal as a near-miss candidate rather
                # than discarding it silently, per this session's
                # near-miss investigation. Only the CLOSEST (by absolute
                # gap) partner withdrawal anywhere in the capture is kept.
                closest_partner_withdraw = min(
                    (e2 for e2 in all_events
                     if _is_type1_es_withdrawal(e2, pe_ids) and e2["node_involved"] == partner),
                    key=lambda e2: abs(e2["timestamp"] - t),
                    default=None,
                )
                if closest_partner_withdraw is not None:
                    gap = abs(closest_partner_withdraw["timestamp"] - t)
                    best_near_miss = _closer_near_miss(best_near_miss, {
                        "candidate_timestamp": closest_partner_withdraw["timestamp"],
                        "gap_seconds": gap,
                        "window_seconds": FULL_FAILURE_PAIR_WINDOW_SECONDS,
                        "window_name": "FULL_FAILURE_PAIR_WINDOW_SECONDS",
                    })
                continue  # partner never withdrew nearby -- not a confirmed full-failure shape
            return "type1_es_dual", e, pe, partner, None
        if _is_ac_state_fault(e, all_events, pe_ids):
            return "ac_state", e, e["node_involved"], None, None
    return None, None, None, None, best_near_miss


def _recovery_search(events, t_fault, kind, pe, partner):
    """Unbounded forward search, same convention as every other module --
    no protocol-level upper bound on real recovery time is documented
    anywhere in this codebase."""
    if kind == "type4":
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            pd = e["protocol_detail"]
            if (e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise"
                    and e["node_involved"] == pe and pd.get("evpn_route_type") == 4):
                return e["timestamp"]
        return None
    if kind == "type1_evi":
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            pd = e["protocol_detail"]
            if (e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise"
                    and e["node_involved"] == pe and pd.get("evpn_route_type") == 1
                    and pd.get("ethernet_tag") != PER_ES_ETHERNET_TAG):
                return e["timestamp"]
        return None
    if kind == "type1_es_dual":
        recovered = {}
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            pd = e["protocol_detail"]
            if not (e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise"
                    and pd.get("evpn_route_type") == 1 and pd.get("ethernet_tag") == PER_ES_ETHERNET_TAG):
                continue
            if e["node_involved"] in (pe, partner) and e["node_involved"] not in recovered:
                recovered[e["node_involved"]] = e["timestamp"]
            if len(recovered) == 2:
                break
        if len(recovered) == 2:
            return max(recovered.values())
        return None
    if kind == "ac_state":
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            pd = e["protocol_detail"]
            if (e["event_type"] == "BGP_UPDATE" and pd.get("route_action") == "advertise"
                    and e["node_involved"] == pe and pd.get("evpn_route_type") == 4
                    and pd.get("df_election_ac_df") is True):
                return e["timestamp"]
        return None
    return None


def _candidate_pe(e, pe_ids):
    """The PE a given event would be attributed to, for cascade-window
    consumption -- mirrors link_down.py's _candidate_pe, but keyed on
    node_involved directly since vantage_parser.py's originator_id
    fallback already resolves reflected RR copies to the true owning PE."""
    if e["node_involved"] in pe_ids:
        pd = e["protocol_detail"]
        if pd.get("evpn_route_type") in (1, 4):
            return e["node_involved"]
    return None


def detect(fused_events, topo):
    """Returns a list of incident dicts -- always a list, never a bare
    dict, same convention as all six existing modules. repeated/slow
    variants have multiple genuine, independent toggle cycles by design
    (confirmed via the 15-file byte-level audit this session: repeated
    has 4 cycles, slow has 2) -- handled the same way as
    link_down.py/mac_mobility.py's repeated-trigger loop: after recording
    an incident, every remaining candidate event attributable to the SAME
    PE (or PE pair, for the dual-PE case) within that incident's cascade
    window is consumed before searching for the next, independent
    incident, so one real toggle's own cascade (including RR-reflected
    duplicate copies of the same withdrawal/advertisement, already
    resolved to the true owning PE via vantage_parser.py's originator_id
    fallback) is never double-counted, and a genuinely independent later
    cycle is never absorbed into an earlier one's window."""
    pe_ids = _pe_nodes(topo)
    events = sorted(fused_events, key=lambda e: e["timestamp"])
    remaining = list(events)

    incidents = []
    near_miss = None
    while True:
        kind, trigger_event, pe, partner, this_near_miss = _find_one_trigger(remaining, events, topo, pe_ids)
        if trigger_event is None:
            near_miss = _closer_near_miss(near_miss, this_near_miss)
            break

        t_fault = trigger_event["timestamp"]
        recovered_time = _recovery_search(events, t_fault, kind, pe, partner)
        recovery_status = "RECOVERED" if recovered_time is not None else "NOT_RECOVERED"

        if kind == "type1_es_dual":
            node_field = {"affected_node_pair": {"pe_a": min(pe, partner), "pe_b": max(pe, partner)}}
            trigger_mechanism = TRIGGER_TYPE1_ES_DUAL
            cascade_pes = {pe, partner}
        else:
            node_field = {"root_cause_node": pe}
            cascade_pes = {pe}
            trigger_mechanism = {
                "type4": TRIGGER_TYPE4,
                "type1_evi": TRIGGER_TYPE1_EVI,
                "ac_state": TRIGGER_AC_STATE,
            }[kind]

        incidents.append(build_result(
            fault_type="ESDF Toggle",
            trigger_mechanism=trigger_mechanism,
            time_of_first_fault=t_fault,
            recovery_status=recovery_status,
            recovered_time=recovered_time,
            **node_field,
        ))

        cascade_end = recovered_time if recovery_status == "RECOVERED" else (t_fault + RECOVERY_WINDOW_SECONDS)
        remaining = [
            e for e in remaining
            if not (t_fault <= e["timestamp"] <= cascade_end and _candidate_pe(e, pe_ids) in cascade_pes)
        ]

    if not incidents:
        return []
    return incidents
