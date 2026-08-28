"""Shared output-schema builder for all Layer 4 rule modules.

Not a rule itself -- centralizes the output shape so every fault type's
module produces a structurally identical result, per LAYER4_DESIGN.md's
resolved schema decisions (root_cause_node vs. affected_node_pair,
recovery_status enum).

detectability_status/affected_nodes REMOVED (2026-08-15): every module
now returns either a list of genuinely-found incidents (every one of
which is, by construction, DETECTED -- there is no other kind of object
in the list anymore) or a bare empty list [] when nothing is found --
same convention regardless of WHY nothing was found (no wire signal,
out-of-scope mechanism, or genuinely structurally unobservable). Callers
must use list truthiness ("if incidents:") instead of checking a status
field. not_detectable_structural()/UNKNOWN_UNTESTED-style placeholder
objects are gone entirely -- see individual rule modules' detect() for
where those branches now return [] directly instead of a status object.
"""
from datetime import datetime, timezone

RECOVERY_STATUSES = {"RECOVERED", "NOT_RECOVERED", "NOT_CAPTURED", "UNKNOWN"}

# Human-readable EVPN route type labels (RFC 7432 SS7), shared by
# rt_misconfiguration.py's affected_routes and rd_collision.py's colliding_routes
# (2026-08-14) -- both report which route TYPE was involved rather than
# the specific mac_address/ip_prefix/esi tuple.
EVPN_ROUTE_TYPE_NAME = {
    1: "Type-1 (Ethernet Auto-Discovery)",
    2: "Type-2 (MAC/IP Advertisement)",
    3: "Type-3 (Inclusive Multicast Ethernet Tag)",
    4: "Type-4 (Ethernet Segment)",
    5: "Type-5 (IP Prefix)",
}


def route_type_label(evpn_route_type):
    if evpn_route_type is None:
        return "Unknown"
    return EVPN_ROUTE_TYPE_NAME.get(evpn_route_type, f"Type-{evpn_route_type}")


def fmt_epoch(t):
    """Moved here 2026-08-09 from run_single.py (its only prior home) so
    both run_single.py and build_result() below can share one
    implementation. Display-only formatting, UTC, matching the same
    ISO-with-milliseconds-and-Z convention already established everywhere
    else in this codebase that ever converts one of these raw epoch
    floats for a human (vantage_parser.py's _iso(), fusion.py's __main__
    block, metadata.json's own ground-truth timestamp fields) -- NOT a
    new format invented here. Never touches the raw float value itself;
    time_of_first_fault/recovered_time stay exactly as rule modules
    produce them, since scorer_lib.py/orchestrator.py/score_synthcap.py/
    run_single.py all do direct arithmetic on those exact fields."""
    if t is None:
        return None
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_result(
    fault_type,
    trigger_mechanism=None,
    root_cause_node=None,
    affected_node_pair=None,
    affected_nodes=None,
    time_of_first_fault=None,
    recovery_status="UNKNOWN",
    recovered_time=None,
    extra=None,
):
    """Only ever called for a genuinely-found incident now -- there is no
    longer a "not found"/"can't tell" object this schema builds; those
    cases return [] directly from the calling module instead.

    affected_nodes (2026-08-16): plain list of every affected node, for
    fault types with 2+ symmetric members and no natural pairwise/lettered
    roles (currently only rd_collision.py's simple mechanism, replacing
    its old affected_node_pair 2-PE-only dict and the affected_node_group
    field removed 2026-08-14). Mutually exclusive with root_cause_node and
    affected_node_pair, same as those two are with each other."""
    if recovery_status not in RECOVERY_STATUSES:
        raise ValueError(f"invalid recovery_status: {recovery_status}")
    if sum(x is not None for x in (root_cause_node, affected_node_pair, affected_nodes)) > 1:
        raise ValueError("root_cause_node, affected_node_pair, and affected_nodes are mutually exclusive")

    result = {
        "fault_type": fault_type,
        "trigger_mechanism": trigger_mechanism,
        "root_cause_node": root_cause_node,
        "affected_node_pair": affected_node_pair,
        "affected_nodes": affected_nodes,
        "time_of_first_fault": time_of_first_fault,
        # Display-only derivative, added directly here (not via `extra`)
        # since every incident dict should carry it automatically -- unlike
        # `reason`/`near_miss`/etc, which are genuinely module-specific
        # opt-in additions, this is a pure function of a field already in
        # this base schema and needs no per-module wiring. NEVER read by
        # scorer_lib.py/orchestrator.py/score_synthcap.py/run_single.py's
        # own comparison logic -- those all keep reading the raw epoch
        # float above, unchanged.
        "time_of_first_fault_readable": fmt_epoch(time_of_first_fault),
        "recovery_status": recovery_status,
        "recovered_time": recovered_time,
        "recovered_time_readable": fmt_epoch(recovered_time),
    }
    if extra:
        result.update(extra)
    # Omit null-valued fields entirely rather than emitting explicit nulls
    # -- e.g. a single-node fault type's affected_node_pair. Every
    # downstream consumer already reads these fields via .get(), never via
    # `in`/key-presence checks (confirmed by repo-wide grep), so dropping
    # absent keys entirely is safe.
    return {k: v for k, v in result.items() if v is not None}
