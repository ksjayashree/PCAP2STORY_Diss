"""
Layer 3: fusion of N per-vantage normalized event streams (from
vantage_parser.py) into one deduplicated, chronologically ordered,
corroboration-tagged timeline.

Takes {vantage_id: [event, ...]}, arbitrary N (no rr1/rr2 naming
assumption) -- every lookup about "who can see whom" goes through
topology.py's visibility/adjacency functions, never a hardcoded vantage
branch, per GENERICITY_RULES.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from topology import load_topology, authoritative_vantages_for_node

# Two events are dedup candidates only if their timestamps are within this
# window. Chosen from observed data: reflected copies of the same BGP
# UPDATE/WITHDRAWAL across RR-to-RR hops in this lab consistently land
# within single-digit-to-low-tens of milliseconds of each other (e.g.
# 04:39:44.016524 vs 04:39:44.016407 for the same withdrawal reflected
# PE->RR1->RR2 in an earlier session capture), and shared-link events
# (TCP_FIN/BFD on the RR1-RR2 link, seen from both ends) are captured
# within microseconds of each other since it's the same wire. 500ms gives
# roughly 25-50x margin over the largest observed real propagation gap,
# while staying far short of the shortest real gap between two genuinely
# distinct occurrences of the same event on the same route in this
# dataset (RT Misconfig's correction is ~15s+ after the original
# mismatch; MAC Mobility moves are >=1.5s apart) -- no risk of merging
# unrelated repeats at this tolerance.
DEDUP_WINDOW_SECONDS = 0.5

# Event types whose identity for dedup purposes is the route/route content
# itself (survives being re-transmitted at a different hop with different
# src_ip/dst_ip), vs. link-local events whose identity is the specific
# session/link they occurred on.
_ROUTE_EVENT_TYPES = {"BGP_UPDATE", "BGP_WITHDRAWAL"}
_LINK_EVENT_TYPES = {
    "BFD_STATE_CHANGE", "TCP_FIN", "TCP_RESET", "BGP_OPEN",
    "SESSION_ESTABLISHED", "BGP_NOTIFICATION", "OSPF_NEIGHBOR_CHANGE",
}


def _dedup_key(event):
    et = event["event_type"]
    pd = event.get("protocol_detail", {})
    if et in _ROUTE_EVENT_TYPES:
        # Route identity: what changed, not which hop relayed it. Two
        # advertisements of the SAME mac/prefix/esi with the SAME RT/RD are
        # the same real-world event even if seen via different src/dst IPs
        # at different hops.
        return (
            event["node_involved"], et,
            pd.get("evpn_route_type"), pd.get("route_action"),
            pd.get("mac_address"), pd.get("ip_prefix"), pd.get("esi"),
            pd.get("route_distinguisher"), pd.get("route_target"),
            pd.get("mac_mobility_seq"),
        )
    if et in _LINK_EVENT_TYPES:
        # Link/session identity: the same exchange seen from both ends of
        # a shared vantage-vantage link has swapped src/dst -- use an
        # unordered pair so both directions collapse together.
        src = pd.get("src_ip")
        dst = pd.get("dst_ip")
        if et in ("TCP_FIN", "TCP_RESET") and pd.get("sport") is not None and pd.get("dport") is not None:
            # Genuine TCP session identity (4-tuple), not just endpoint
            # IPs -- sport/dport now available in protocol_detail (added
            # this session for link_down.py's session-identity matching).
            # Unordered pairing of (ip, port) so a reflected/opposite-
            # direction view of the same real packet still collapses.
            # Safe for cross-vantage dedup: sport/dport are read directly
            # from the TCP header, identical regardless of which vantage
            # observed the same physical packet -- confirmed, this does
            # not risk under-deduping a genuinely shared event.
            endpoints = frozenset({(src, pd.get("sport")), (dst, pd.get("dport"))})
        else:
            endpoints = frozenset(x for x in (src, dst) if x is not None)
        return (event["node_involved"], et, endpoints, pd.get("state"), pd.get("error_code"))
    # Fallback: never merge event types we don't recognize -- safer to
    # under-deduplicate (duplicate entries visible, correctable later) than
    # to silently conflate two different things.
    return None


def _try_merge(clusters, event):
    """Append event to an existing cluster if it's a dedup match within the
    time window, else start a new cluster. clusters: list of lists."""
    key = _dedup_key(event)
    if key is None:
        clusters.append([event])
        return
    for cluster in clusters:
        rep = cluster[0]
        if _dedup_key(rep) != key:
            continue
        if abs(event["timestamp"] - rep["timestamp"]) <= DEDUP_WINDOW_SECONDS:
            cluster.append(event)
            return
    clusters.append([event])


def _fuse_cluster(cluster, topo):
    cluster_sorted = sorted(cluster, key=lambda e: e["timestamp"])
    earliest = cluster_sorted[0]
    source_vantages = sorted({e["source_vantage"] for e in cluster})
    node_involved = earliest["node_involved"]
    authoritative = authoritative_vantages_for_node(topo, node_involved) if node_involved else []
    return {
        "timestamp": earliest["timestamp"],
        "node_involved": node_involved,
        "event_type": earliest["event_type"],
        "protocol_detail": earliest["protocol_detail"],
        "source_vantages": source_vantages,
        "corroboration_count": len(source_vantages),
        "authoritative_vantages": authoritative,
        "from_authoritative_vantage": bool(set(source_vantages) & set(authoritative)),
    }


def fuse_event_streams(vantage_event_streams, topology_path=None):
    """vantage_event_streams: {vantage_id: [event, ...]} as produced by
    vantage_parser.parse_vantages(). Returns one chronologically ordered
    list of fused events, each carrying source_vantages/corroboration_count
    and, for events with a resolvable node_involved, the topology-derived
    authoritative_vantages for that node."""
    topo = load_topology(topology_path) if topology_path else load_topology()

    all_events = []
    for vantage_id, events in vantage_event_streams.items():
        for e in events:
            if e.get("source_vantage") != vantage_id:
                e = dict(e)
                e["source_vantage"] = vantage_id
            all_events.append(e)
    all_events.sort(key=lambda e: e["timestamp"])

    clusters = []
    for event in all_events:
        _try_merge(clusters, event)

    fused = [_fuse_cluster(c, topo) for c in clusters]
    fused.sort(key=lambda e: e["timestamp"])
    return fused


if __name__ == "__main__":
    import json
    from datetime import datetime, timezone
    from vantage_parser import parse_vantages

    if len(sys.argv) < 2:
        print("usage: fusion.py <scenario_dir>")
        sys.exit(1)
    scenario_dir = sys.argv[1]
    vmap = {
        "RR1": os.path.join(scenario_dir, "rr1.pcap"),
        "RR2": os.path.join(scenario_dir, "rr2.pcap"),
    }
    streams = parse_vantages(vmap)
    fused = fuse_event_streams(streams)
    for e in fused:
        ts = datetime.fromtimestamp(e["timestamp"], tz=timezone.utc).isoformat()
        print(f"{ts} {e['event_type']:20s} node={e['node_involved']} "
              f"src_vantages={e['source_vantages']} corrob={e['corroboration_count']} "
              f"authoritative={e['authoritative_vantages']} from_auth={e['from_authoritative_vantage']} "
              f"{e['protocol_detail']}")
