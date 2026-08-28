"""Layer 4 rule: RT Misconfig.

No `mechanism` parameter (2026-08-15, reworked): a single, unified,
unrestricted search finds any BGP_UPDATE whose route_target deviates from
its own node's ground_truth.expected_rt -- no route-type restriction on
the search itself, since the underlying wire signal (route_target !=
expected_rt) doesn't depend on route type. Once a deviant anchor event is
found, it is classified PURELY from its own evpn_route_type field: Type-4
-> "ES-Import RT Mismatch" (RFC 7432 SS7.6's ES-Import Route Target is
scoped specifically and only to the Type-4 Ethernet Segment route,
confirmed both by RFC text and by direct trace of the synthcap
generator's RTMisconfigESImportScenario, which only ever perturbs a
Type-4 route's RT); anything else -> "Auto-Derived Mismatch". Each
classification then gets its own grouping window (GROUP_WINDOW_SECONDS
vs ES_IMPORT_GROUP_WINDOW_SECONDS below), chosen the same way, from the
anchor's own route type -- not from an external hint.

Empirically verified (2026-08-15) against the full 84-scenario real+
synthetic corpus that this reproduces the prior mechanism-parameter
design's output for every properly-named single-mechanism scenario
(autoderive_export/es_import/import_only), and additionally FIXES 2
combined-fault ("multiple/") scenarios whose folder names didn't contain
either mechanism substring and were previously mis-defaulted to
"import_only" (2.5s window) by every caller's folder-name-derivation
heuristic -- those files' two genuinely-separate Type-4 deviant events
(2.29s apart) were wrongly merged into one incident under the old
external-hint system; this wire-derived design correctly reports them as
two.

import_only, as a distinct concept, is retired: a real 30-file search (10
pilot_containerlab + 20 3rr, prior session) found zero deviant RT values
anywhere for that scenario class, consistent with RFC 4360 (import-only
RT filters are never serialized in outbound BGP UPDATE messages) -- but
that's an empirical property of what this search finds on those specific
files, not a separate code path. Those files still run through the exact
same unified search as every other file; they simply continue to find
nothing, exactly as already verified.
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
from rules.schema import build_result, route_type_label

# Same-PE deviant BGP_UPDATEs within this window are ONE misconfiguration
# event (multiple existing routes re-advertised at once when the RT
# config changes), not separate incidents.
#
# Widened 2026-08-02 (was 0.1s) then again 2026-08-08 (was 1.0s):
# pilot_containerlab's 10 real autoderive files show zero jitter (all
# deviant routes share the identical fused-event timestamp), but a direct
# check across all 22 real autoderive_export files in both datasets
# (2026-08-08, prompted by rt_misconfig_autoderive_export_xpe5_notfixed
# surfacing as a self cross-module false positive -- two DETECTED
# incidents for what's really one misconfiguration) found 3rr's XPE5
# case fans the same deviant RT out to its RR vantages 1.588s after the
# first-seen copy (confirmed same route_target/mac_address/route-type on
# both timestamps -- genuinely the same event, just seen first via one
# RR's direct session then later via full 3-RR propagation), not the
# 0.0s pilot's 10 files show. Every OTHER multi-timestamp file in either
# dataset is a genuine fault-then-correction pair (13.7-16.7s apart, the
# _fixed variants), never anything between 1.588s and that range, so 2.5s
# (>1.5x margin over the observed 1.588s real span) cannot merge two
# genuinely separate incidents anywhere in the currently-passing set,
# while staying far below the 13.7s correction floor. A recovery-bounded
# window (link_down/rr_down's pattern) is still NOT used here -- there is
# no reconnection concept for RT Misconfig, just a single instantaneous
# config change; a tens-of-seconds window would be semantically wrong.
#
# Selected for a Type-4-anchored incident vs. any other route type
# (2026-08-15, reworked from a mechanism-string selection to a
# route-type-anchored one): see ES_IMPORT_GROUP_WINDOW_SECONDS below.
GROUP_WINDOW_SECONDS = 2.5

# ES-Import-shaped (Type-4-anchored) grouping window (2026-08-08,
# measured directly, not estimated) across all 8 real synthcap es_import
# files (output + output_3rr, notfixed + recovery, all PEs): the fan-out
# gap between the direct-session deviant advertisement and its RFC 4456
# second-hop copy ranges 1.08-1.26s across these 8 files. GROUP_WINDOW_
# SECONDS=1.0 is too narrow for this -- every one of the 8 files split
# into 2 incidents instead of 1 under it. 2.0s gives margin over the
# observed 1.26s max. Scoped to Type-4-anchored incidents only (not a
# change to GROUP_WINDOW_SECONDS itself) since non-Type-4 real data has
# zero jitter and doesn't need widening, and a shared wider window would
# be unjustified risk for that case.
ES_IMPORT_GROUP_WINDOW_SECONDS = 2.0

TRIGGER_ES_IMPORT = "ES-Import RT Mismatch"
TRIGGER_AUTO_DERIVED = "Auto-Derived Mismatch"


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


def _in_consumed_group(e, root_cause_node, t_fault, group_window, anchor_is_type4, expected_rt):
    """Shared predicate for both (a) collecting every distinct deviant route
    consumed into one incident's group, for affected_routes, and (b) the
    remaining-events removal filter below -- factored out so the two uses
    can never silently diverge.

    anchor_is_type4 (2026-08-15, replaces the old external require_route_type
    parameter): when the anchor deviant itself is Type-4, grouping is
    restricted to further Type-4 deviants only -- the real ES-Import fault
    only ever touches the Type-4 ES route (confirmed via the synthcap
    generator: correctly-RT'd Type-2 traffic on the same PE is explicitly
    left untouched), so nothing is lost by restricting. When the anchor is
    NOT Type-4, grouping stays unrestricted by type -- a real Auto-Derived
    misconfiguration legitimately touches Type-2/Type-3/Type-5 routes
    together as one incident, confirmed by this session's own affected_routes
    field showing multiple route types per real incident."""
    return (
        e["event_type"] == "BGP_UPDATE"
        and e["node_involved"] == root_cause_node
        and t_fault <= e["timestamp"] <= t_fault + group_window
        and (not anchor_is_type4 or e["protocol_detail"].get("evpn_route_type") == 4)
        and e["protocol_detail"].get("route_target") is not None
        and e["protocol_detail"].get("route_target") != expected_rt
    )


def _find_one_deviant(candidate_events, pe_ids, topo):
    """Single, unified, unrestricted search -- no route-type filter at all.
    Confirmed (2026-08-15 investigation) that route type is never needed to
    FIND the deviant event, only to classify it afterward: the underlying
    wire signal (route_target != expected_rt) doesn't depend on route type,
    and a direct 3-way test against a real ES-Import file found all three
    of the old mechanism strings independently locating the identical
    anchor event."""
    for e in candidate_events:
        if e["event_type"] != "BGP_UPDATE":
            continue
        if e["node_involved"] not in pe_ids:
            continue
        pd = e["protocol_detail"]
        rt = pd.get("route_target")
        if rt is None:
            continue
        gt = ground_truth(topo, e["node_involved"]) or {}
        expected_rt = gt.get("expected_rt")
        if expected_rt and rt != expected_rt:
            return e
    return None


def detect(fused_events, topo):
    """Returns a list of incident dicts -- always a list, never a bare
    dict, same convention established in mac_mobility.py/rd_collision.py/
    link_down.py/rr_down.py. Repeatedly runs the unified single-incident
    selection logic (_find_one_deviant) against a shrinking pool of
    unconsumed events: once an incident is found, every remaining deviant
    BGP_UPDATE from the SAME PE within that incident's OWN classification's
    grouping window is consumed as part of that ONE misconfiguration event
    before searching for the next, genuinely independent incident."""
    events = sorted(fused_events, key=lambda e: e["timestamp"])
    pe_ids = set(_pe_nodes(topo))
    remaining = list(events)

    incidents = []
    while True:
        deviant = _find_one_deviant(remaining, pe_ids, topo)
        if deviant is None:
            break

        root_cause_node = deviant["node_involved"]
        t_fault = deviant["timestamp"]
        deviant_key = _route_key(deviant["protocol_detail"])
        expected_rt = (ground_truth(topo, root_cause_node) or {}).get("expected_rt")

        # Classification happens AFTER finding, purely from the anchor's
        # own wire-observed route type -- no external hint.
        anchor_is_type4 = deviant["protocol_detail"].get("evpn_route_type") == 4
        trigger_mechanism = TRIGGER_ES_IMPORT if anchor_is_type4 else TRIGGER_AUTO_DERIVED
        group_window = ES_IMPORT_GROUP_WINDOW_SECONDS if anchor_is_type4 else GROUP_WINDOW_SECONDS

        recovery_status = "NOT_RECOVERED"
        recovered_time = None
        for e in events:
            if e["timestamp"] <= t_fault:
                continue
            if e["event_type"] != "BGP_UPDATE":
                continue
            # Confirmed false-positive fix (earlier session): a correction
            # match must come from the SAME node as the original deviant
            # advertisement -- matching on route content alone let PE2's
            # legitimate, always-correctly-configured advertisement of a
            # shared-ESI MAC (PE1/PE2 multihoming pair) be misread as PE1's
            # own correction, since both PEs' advertisements carry the same
            # mac_address/ip_prefix/esi.
            if e["node_involved"] != root_cause_node:
                continue
            pd = e["protocol_detail"]
            if _route_key(pd) != deviant_key:
                continue
            if pd.get("route_target") == expected_rt:
                recovery_status = "RECOVERED"
                recovered_time = e["timestamp"]
                break

        distinct_route_types = set()
        for e in remaining:
            if _in_consumed_group(e, root_cause_node, t_fault, group_window, anchor_is_type4, expected_rt):
                distinct_route_types.add(e["protocol_detail"].get("evpn_route_type"))
        affected_routes = [route_type_label(rt) for rt in sorted(distinct_route_types, key=lambda x: (x is None, x))]

        incidents.append(build_result(
            fault_type="RT Misconfiguration",
            trigger_mechanism=trigger_mechanism,
            root_cause_node=root_cause_node,
            time_of_first_fault=t_fault,
            recovery_status=recovery_status,
            recovered_time=recovered_time,
            extra={
                "misconfigured_route_target": deviant["protocol_detail"].get("route_target"),
                "affected_routes": affected_routes,
            },
        ))

        remaining = [
            e for e in remaining
            if not _in_consumed_group(e, root_cause_node, t_fault, group_window, anchor_is_type4, expected_rt)
        ]

    if not incidents:
        return []
    return incidents
