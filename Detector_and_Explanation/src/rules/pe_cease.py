"""Layer 4 rule: PE Cease.

Signal confirmed in Layer 2/3 checkpoints (LAYER4_DESIGN.md #3):
BGP_NOTIFICATION (Cease/Administrative Shutdown) sourced from the ceasing
PE's own IP -- confirmed clean sender-attribution across pe1/pe2/pe4.
No downstream fan-out: PE Cease only affects the ceasing PE's own routes.
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

# 60s is a fallback cascade-consumption bound for the NOT_RECOVERED case
# only -- real recovery detection above is unbounded (validated against 27
# real PE Cease incidents, gaps 10.0-301.7s, and 7 ESDF Toggle incidents,
# gaps 10.4-19.7s, 0 discrepancies). No real NOT_RECOVERED multi-incident
# same-node data exists in the corpus to calibrate this fallback further;
# 60s is a conservative placeholder, not a measured value.
RECOVERY_WINDOW_SECONDS = 60


def _pe_nodes(topo):
    return {n["id"] for n in topo["nodes"] if n.get("role") == "PE"}


def _find_one_trigger(candidate_events, pe_ids):
    """Unchanged single-incident selection logic from the original
    detect(), just returning instead of using next()'s default so the
    caller can loop."""
    return next(
        (e for e in candidate_events if e["event_type"] == "BGP_NOTIFICATION" and e["node_involved"] in pe_ids),
        None,
    )


def detect(fused_events, topo):
    """Returns a list of incident dicts -- always a list, never a bare
    dict, same convention established in mac_mobility.py/rd_collision.py/
    link_down.py/rr_down.py/rt_misconfiguration.py. Cascade/collision-noise risk
    investigated directly against real wire data (this session) and found
    genuinely clean: PE Cease only ever evaluates BGP_NOTIFICATION as a
    trigger (no TCP_FIN/TCP_RESET/BFD_STATE_CHANGE branch to over-count),
    exactly one PE-attributed BGP_NOTIFICATION appears per real fault
    across all 10 files, and none of the 5 recovered files' reconnects
    show the RFC 4271 SS6.8 / RFC 8538 SS4 collision-tail pattern found
    in link_down.py/rr_down.py. The repeatable-loop structure is applied
    anyway for consistency with the other 5 modules and to stay ready if
    a genuine multi-PE-Cease file is ever added, even though current data
    shows no real multiplicity.

    Recovery detection is unbounded (matching link_down.py/rr_down.py/
    rt_misconfiguration.py's item 2+4 fix) -- searches the whole remaining
    capture, not a fixed duration, since no protocol-level upper bound on
    real recovery time is documented anywhere in this codebase. The
    cascade-consumption fallback below is a different concern and stays
    bounded at RECOVERY_WINDOW_SECONDS for the genuinely-NOT_RECOVERED
    case only -- unbounding it too would make a genuinely independent
    second PE Cease on the same PE impossible to ever detect."""
    pe_ids = _pe_nodes(topo)
    events = sorted(fused_events, key=lambda e: e["timestamp"])
    remaining = list(events)

    incidents = []
    while True:
        trigger_event = _find_one_trigger(remaining, pe_ids)
        if trigger_event is None:
            break

        root_cause_node = trigger_event["node_involved"]
        t_fault = trigger_event["timestamp"]

        recovery_status = "NOT_RECOVERED"
        recovered_time = None
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            if e["event_type"] == "SESSION_ESTABLISHED" and e["node_involved"] == root_cause_node:
                recovery_status = "RECOVERED"
                recovered_time = e["timestamp"]
                break

        incidents.append(build_result(
            fault_type="PE Cease",
            trigger_mechanism="Cease/Administrative Shutdown",
            root_cause_node=root_cause_node,
            time_of_first_fault=t_fault,
            recovery_status=recovery_status,
            recovered_time=recovered_time,
        ))

        cascade_end = recovered_time if recovery_status == "RECOVERED" else (t_fault + RECOVERY_WINDOW_SECONDS)
        remaining = [
            e for e in remaining
            if not (t_fault <= e["timestamp"] <= cascade_end and e["node_involved"] == root_cause_node)
        ]

    if not incidents:
        return []
    return incidents
