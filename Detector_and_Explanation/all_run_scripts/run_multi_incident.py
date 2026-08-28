"""
Minimal runner + scorer for the multi-incident (pcaps/multiple/) files
generated for pilot_containerlab and 3rr. Not a rewrite of any existing
scorer (none existed in this repo outside synthcap, which we do not
touch) -- a new, small, clearly-scoped script.

Scorer design decision (documented per task instructions): ground truth
for these files is metadata.json["incidents"], a list of {event_affected_node,
fault_type, ...}. We treat detection as a set-matching problem: for each
ground-truth incident, count it "hit" if orchestrator.run_all_rules()
produced at least one non-NOT_DETECTABLE_STRUCTURAL/NO_SIGNAL_FOUND
detection entry for that (fault_type, node) pair anywhere in its raw
per-module output (pre-precedence). We report raw per-module hits AND,
separately, tally how often known precedence-window co-detections
(module A firing on the same node/time as module B) occur, to observe
rule-firing rates per the task's Category D instructions. This is a
recall-oriented, per-incident metric (did the right node+fault_type get
flagged by the right module), not a strict single-detection-per-file
metric, because these files intentionally contain >1 ground-truth event.
"""
import sys, os, json, glob

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "rules"))

from vantage_parser import parse_vantages
from fusion import fuse_event_streams
from topology import load_topology
from orchestrator import run_all_rules, annotate_precedence

TOPO_PATH = os.path.join(os.path.dirname(__file__), "config", "topology.json")
TOPO_PATH_3RR = os.path.join(os.path.dirname(__file__), "config", "topology_3rr.json")

PROJECTS = {
    "pilot_containerlab": {
        "pcaps_multiple": r"C:\simulation pcap\pilot_containerlab\pcaps\multiple",
        "topology": TOPO_PATH,  # pilot topology.json matches config/topology.json (5PE/2RR)
    },
    "3rr": {
        "pcaps_multiple": r"C:\simulation pcap\3rr\pcaps\multiple",
        "topology": TOPO_PATH_3RR if os.path.exists(TOPO_PATH_3RR) else TOPO_PATH,
    },
}


def find_scenarios(base):
    out = []
    for root, dirs, files in os.walk(base):
        pcaps = [f for f in files if f.endswith(".pcap")]
        if "metadata.json" in files and len(pcaps) >= 2:
            out.append(root)
    return out


def vantage_map_for(scenario_dir):
    """Builds {VANTAGE_ID: pcap_path} generically from whatever *.pcap files exist
    (rr1/rr2 for pilot_containerlab, xrr1/xrr2/xrr3 for 3rr) -- vantage id is the
    pcap basename uppercased, matching each project's topology.json 'vantages' list."""
    vmap = {}
    for fn in os.listdir(scenario_dir):
        if fn.endswith(".pcap"):
            vantage_id = os.path.splitext(fn)[0].upper()
            vmap[vantage_id] = os.path.join(scenario_dir, fn)
    return vmap


def normalize_fault_type(s):
    """Canonicalize a fault_type string for comparison: lowercase, strip,
    collapse underscores/multiple spaces to single spaces. Makes
    'mac_mobility' (ground truth) and 'MAC Mobility' (detector module key)
    compare equal, along with any other case/format variant."""
    if not s:
        return s
    return " ".join(s.replace("_", " ").split()).lower()


def flatten_hits(raw_results):
    """raw_results: {fault_type: [dict,...]}. Returns list of (fault_type, node, mechanism_tag) for
    real (non-placeholder) detections. Keys are normalized (see normalize_fault_type)
    so ground-truth strings in any case/format match the detector's own keys."""
    hits = []
    for fault_type, entries in raw_results.items():
        norm_ft = normalize_fault_type(fault_type)
        for e in entries:
            if not isinstance(e, dict):
                continue
            # detectability_status removed (2026-08-15) -- every entry in
            # a module's list is now, by construction, a genuine finding
            # (modules return [] for "nothing found" instead of a
            # DETECTED/NOT_DETECTABLE_STRUCTURAL/NO_SIGNAL_FOUND
            # placeholder object), so no status filter is needed anymore.
            node = (e.get("root_cause_node") or e.get("node") or e.get("node_involved")
                    or e.get("affected_node"))
            nodes = [node] if node else []
            # affected_node_group removed (2026-08-14) -- for RD
            # Collision's 3+-PE case, colliding_routes' own dict keys are
            # the only remaining place those PE names are named.
            # affected_node_pair (RD Collision 2-PE case, MAC Mobility,
            # ESDF Toggle ES-pair case) is always a dict of role->node
            # (e.g. {"origin":...,"destination":...},
            # {"colliding_pe_a":...,"colliding_pe_b":...},
            # {"pe_a":...,"pe_b":...}) per every module's build_result()
            # call (confirmed by reading all 7 rule modules) -- take its
            # values, not the dict itself.
            grp = e.get("affected_node_pair") or e.get("colliding_routes")
            if isinstance(grp, dict) and grp and all(isinstance(v, str) for v in grp.values()):
                nodes.extend(grp.values())
            elif isinstance(grp, dict):
                nodes.extend(grp.keys())
            for n in nodes:
                if n:
                    hits.append((norm_ft, n))
    return hits


def ground_truth_fault_type_key(inc):
    """Ground truth fault_type, normalized, with one special case: RD-Collision
    -tagged incidents self-report fault_type='RT Misconfiguration' (with
    fault_subtype='RD Collision' or a colliding_rd field) but the detector's
    corresponding output lives under the separate 'RD Collision' module key --
    a plain case-insensitive match on fault_type alone would never look there.
    Redirect those incidents to the 'rd collision' normalized key instead."""
    ft = inc.get("fault_type")
    if inc.get("fault_subtype") == "RD Collision" or inc.get("colliding_rd"):
        return normalize_fault_type("RD Collision")
    return normalize_fault_type(ft)


def ground_truth_nodes(inc):
    """Read both the singular (event_affected_node, the majority form: 62 of 78
    incidents in this dataset) and list (event_affected_nodes, 16 of 78 --
    used only by RD-Collision-style two-node-group incidents) ground-truth
    node fields. Returns a list of node names to check (usually length 1)."""
    nodes = []
    single = inc.get("event_affected_node")
    if single:
        nodes.append(single)
    multi = inc.get("event_affected_nodes")
    if isinstance(multi, (list, tuple)):
        nodes.extend(n for n in multi if n)
    return nodes


def score_scenario(scenario_dir, topo):
    meta_path = os.path.join(scenario_dir, "metadata.json")
    with open(meta_path) as f:
        meta = json.load(f)
    incidents = meta.get("incidents") or [meta]  # fall back to flat single-incident schema

    vmap = vantage_map_for(scenario_dir)
    try:
        streams = parse_vantages(vmap, topology_path=topo)
        fused = fuse_event_streams(streams, topology_path=topo)
        topo_obj = load_topology(topo)

        # rt_misconfig (2026-08-15) and mac_mobility (2026-08-16) take no
        # mechanism hint anymore -- both are fully wire-derived, so a single
        # run_all_rules() call already finds every real incident regardless
        # of route type / flap count. This retires the previous
        # rt_variants=["plain", "autoderive"] union-retry block (itself
        # broken -- neither value was ever valid) and the mm_variants=
        # ["cleanmove", "rapidflap"] union-retry block (mac_mobility.py's
        # detect() never branched on that string in the first place, so the
        # union added nothing beyond ValueError-avoidance; classification is
        # now a genuine post-search per-MAC move count, so there's no
        # per-mechanism call to union at all).
        #
        # rd_collision.py still takes a mechanism hint ("simple" vs
        # "masking" gate a genuinely different code path -- "masking" is an
        # unconditional stub, not a post-search classification). Fixed
        # 2026-08-03: "simple" is rd_collision.py's fully-implemented, real
        # detection path (confirmed via direct code read -- it's already
        # generalized to handle multiple distinct collision groups in one
        # capture). The previous rd_variants=["masking"] hardcode never
        # tried "simple", so every RD Collision incident hit the stub
        # regardless of what actually happened.
        raw = run_all_rules(fused, topo_obj, rd_collision_mechanism="simple")
    except Exception as ex:
        return {"scenario": scenario_dir, "error": str(ex), "incidents": incidents}

    try:
        precedence = annotate_precedence(raw, load_topology(topo), fused)
    except Exception as ex:
        precedence = {"error": str(ex)}

    hits = flatten_hits(raw)
    hit_nodes_by_type = {}
    for ft, node in hits:
        hit_nodes_by_type.setdefault(ft, set()).add(node)

    per_incident = []
    for inc in incidents:
        nodes = ground_truth_nodes(inc)
        ft = inc.get("fault_type")
        norm_ft = ground_truth_fault_type_key(inc)
        hit_set = hit_nodes_by_type.get(norm_ft, set())
        detected = any(n in hit_set for n in nodes)
        per_incident.append({
            "node": nodes[0] if nodes else None,
            "nodes": nodes if len(nodes) > 1 else None,
            "fault_type": ft,
            "detected": detected,
        })

    precedence_rule_counts = {}
    if isinstance(precedence, dict) and "error" not in precedence:
        for module, entries in precedence.items():
            for e in entries:
                status = e.get("status", "UNKNOWN")
                key = f"{module}:{status}"
                precedence_rule_counts[key] = precedence_rule_counts.get(key, 0) + 1

    return {
        "scenario": scenario_dir,
        "n_incidents": len(incidents),
        "n_detected": sum(1 for p in per_incident if p["detected"]),
        "per_incident": per_incident,
        "raw_module_counts": {k: len(v) for k, v in raw.items()},
        "precedence_rule_firing_counts": precedence_rule_counts,
    }


def main():
    all_results = []
    for proj, cfg in PROJECTS.items():
        base = cfg["pcaps_multiple"]
        if not os.path.isdir(base):
            print(f"[{proj}] no pcaps/multiple dir found, skipping")
            continue
        scenarios = find_scenarios(base)
        print(f"[{proj}] found {len(scenarios)} generated multi-incident scenarios")
        for sc in scenarios:
            res = score_scenario(sc, cfg["topology"])
            res["project"] = proj
            all_results.append(res)
            print(json.dumps(res, indent=2, default=str))

    out_path = r"C:\simulation pcap\rule_based detector\multi_incident_scoring_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[WRITTEN] {out_path}")

    # aggregate precedence-rule firing counts across all scenarios (Category D observation)
    agg = {}
    for r in all_results:
        for k, v in (r.get("precedence_rule_firing_counts") or {}).items():
            agg[k] = agg.get(k, 0) + v
    print("\n=== AGGREGATE PRECEDENCE RULE FIRING COUNTS (across all new files) ===")
    print(json.dumps(agg, indent=2))


if __name__ == "__main__":
    main()
