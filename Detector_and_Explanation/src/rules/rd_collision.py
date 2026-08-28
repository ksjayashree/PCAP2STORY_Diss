"""Layer 4 rule: RD Collision.

simple: full DETECTED rule with affected_node_pair. Signal confirmed in
Layer 2/3 checkpoints (LAYER4_DESIGN.md #5): two distinct BGP_UPDATE
(advertise) events sharing the same route_distinguisher (a value that
matches neither PE's own ground_truth.expected_rd), differentiated by
mac_address, both correctly resolved to their true owning PE.

masking: fixed UNKNOWN_UNTESTED, no detection logic attempted -- closed
by an earlier project decision before any wire-level testing occurred
(not confirmed detectable or undetectable, unlike RT Misconfig-plain).
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
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from topology import ground_truth
from rules.schema import build_result, route_type_label


def _pe_nodes(topo):
    return [n["id"] for n in topo["nodes"] if n.get("role") == "PE"]


def _route_key(pd):
    # evpn_route_type/ethernet_tag added (2026-08-14) to disambiguate route
    # types that otherwise collide on (mac_address, ip_prefix, esi) alone --
    # Type-3 IMET and Type-1 AD-per-EVI both reduce to (None, None, None),
    # and Type-1 AD-per-ES/Type-4 both reduce to (None, None, <esi>) when
    # ESI matches. Same disambiguation convention esdf_toggle.py already
    # uses (PER_ES_ETHERNET_TAG sentinel), applied consistently here.
    return (pd.get("mac_address"), pd.get("ip_prefix"), pd.get("esi"),
            pd.get("evpn_route_type"), pd.get("ethernet_tag"))


def detect(fused_events, topo, mechanism):
    """Returns a list of incident dicts -- always a list, never a bare dict,
    same convention as mac_mobility.py. A capture could in principle contain
    more than one distinct colliding-RD group; every qualifying group
    produces its own incident, not just the first found.

    masking (2026-08-15, reworked): no detection logic exists for this
    mechanism (closed, untested, out of scope per an earlier project
    decision) -- returns [] like any other nothing-to-report case, no
    special status distinguishing "out of scope" from "genuinely searched
    and found nothing"."""
    if mechanism == "masking":
        return []
    if mechanism != "simple":
        raise ValueError(f"unknown rd_collision mechanism: {mechanism}")

    events = sorted(fused_events, key=lambda e: e["timestamp"])
    pe_ids = set(_pe_nodes(topo))
    expected_rd_by_pe = {pe: (ground_truth(topo, pe) or {}).get("expected_rd") for pe in pe_ids}
    own_expected_rds = set(v for v in expected_rd_by_pe.values() if v)

    # Group advertisements by (route_distinguisher, node_involved, route_key),
    # tracking the earliest event per distinct route a node advertised under
    # a given foreign RD -- a colliding node commonly advertises more than
    # one route (e.g. a Type-3 IMET route plus one or more Type-2 MAC
    # routes) under the same RD, and the prior single-event-per-node
    # bookkeeping silently discarded all but the first-seen one. Restructured
    # 2026-08-14 to track every distinct route per node; node-level
    # membership (which nodes collide on which RD -- the actual detection
    # trigger) is unchanged, since len(node_map) below still counts distinct
    # nodes, not routes -- confirmed no detection-outcome change, only
    # output detail changes (see docs_internal investigation this session).
    by_rd = defaultdict(lambda: defaultdict(dict))  # rd -> {node: {route_key: earliest_event}}
    for e in events:
        if e["event_type"] != "BGP_UPDATE":
            continue
        if e["node_involved"] not in pe_ids:
            continue
        pd = e["protocol_detail"]
        rd = pd.get("route_distinguisher")
        if not rd or rd in own_expected_rds:
            continue  # not a foreign/colliding RD
        node = e["node_involved"]
        rk = _route_key(pd)
        if rk not in by_rd[rd][node]:
            by_rd[rd][node][rk] = e

    collision_groups = [(rd, node_map) for rd, node_map in by_rd.items() if len(node_map) >= 2]

    if not collision_groups:
        return []

    incidents = []
    for collision_rd, collision_nodes in collision_groups:
        # Generalized to N colliding PEs (was truncated to the first 2 --
        # confirmed no real 3+-PE file exists in pilot_containerlab to
        # test this against, documented limitation, same treatment as
        # other untestable cases). One real colliding-RD event, however
        # many PEs it involves, is ONE incident, not multiple pairwise
        # ones -- reporting it as several would over-count a single real
        # event the same way the cascade fixes tonight avoided.
        members = sorted(collision_nodes.keys())
        # min over every tracked route's event per member -- equals the old
        # single-earliest-event value exactly, since that was always the
        # first-seen (and therefore earliest) route for the node anyway.
        t_fault = min(ev["timestamp"] for m in members for ev in collision_nodes[m].values())

        # Recovery detection is unbounded -- searches the whole remaining
        # capture, not a fixed duration, matching link_down.py/pe_cease.py/
        # rr_down.py/esdf_toggle.py. A fixed CORRECTION_WINDOW_SECONDS cap
        # here previously scored genuinely-recovered collisions (correction
        # landing after the cap) as NOT_RECOVERED -- confirmed against real
        # catE_rd_collision recoverdelay 60/120/300s files.
        recovered_time_by_node = {m: None for m in members}
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            if e["event_type"] != "BGP_UPDATE":
                continue
            node = e["node_involved"]
            if node not in recovered_time_by_node or recovered_time_by_node[node] is not None:
                continue
            rd = e["protocol_detail"].get("route_distinguisher")
            if rd == expected_rd_by_pe.get(node):
                recovered_time_by_node[node] = e["timestamp"]

        all_recovered = all(t is not None for t in recovered_time_by_node.values())
        recovery_status = "RECOVERED" if all_recovered else "NOT_RECOVERED"
        # RECOVERED requires EVERY colliding PE to have reverted -- the
        # incident isn't actually recovered until the last one, not the
        # first. Only meaningful (non-None) when all fired.
        recovered_time = max(recovered_time_by_node.values()) if all_recovered else None

        # affected_node_pair (dict, 2-PE-only) and affected_node_group
        # (removed 2026-08-14) both replaced by affected_nodes (2026-08-16):
        # a single sorted list of every colliding PE, works identically for
        # 2, 3, or any number of members -- no lettered/positional keys, no
        # branch on len(members). Investigated this session: confirmed no
        # detection-outcome dependency on this field anywhere in this
        # module (only node_field's own construction reads `members`);
        # downstream consumers updated in the same change (scorer_lib.py,
        # explanation/pipeline.py).
        node_field = {"affected_nodes": members}

        colliding_routes = {
            m: sorted({route_type_label(rk[3]) for rk in collision_nodes[m].keys()})
            for m in members
        }

        incidents.append(build_result(
            fault_type="RD Collision",
            trigger_mechanism="Shared Route Distinguisher (RD Collision)",
            **node_field,
            time_of_first_fault=t_fault,
            recovery_status=recovery_status,
            recovered_time=recovered_time,
            extra={
                "colliding_route_distinguisher": collision_rd,
                "colliding_routes": colliding_routes,
            },
        ))

    return incidents
