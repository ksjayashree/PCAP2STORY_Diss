"""Real, reusable synthcap comparator -- NOT a scratch script.

Compares the detector's own output against synthcap's generator-produced
ground truth (metadata.json), for a given file under C:\\synthcap\\output
or C:\\synthcap\\output_3rr. Distinct from score_detector.py/
score_detector_3rr.py (which score real pilot_containerlab/3rr captures
against a differently-shaped metadata.json) -- synthcap's ground truth
carries no trigger_mechanism string at all (the mechanism/shape is
implied by the folder name and description text, not recorded as a
separate field), and mac_mobility's synthcap metadata has no `recovered`
field whatsoever (every synthcap mac_mobility file has recovery: false,
and its populated fault_window.fault_end_datetime_utc is the LAST-FLAP
timestamp of a repeated-flap sequence, not a recovery signal -- comparing
recovered_time against it would be comparing against the wrong ground
truth, so this comparator explicitly skips that comparison for
mac_mobility rather than silently mis-scoring it).

Reuses scorer_lib.py's own fault_tolerance()/synthcap_recovery_tolerance().
"""
import sys
import os
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "rules"))

from topology import load_topology
from vantage_parser import parse_vantages
from fusion import fuse_event_streams
from orchestrator import run_all_rules
from scorer_lib import fault_tolerance, synthcap_recovery_tolerance

FOLDER_TYPE_TO_MODULE = {
    "rt_misconfig": "RT Misconfiguration",
    "mac_mobility": "MAC Mobility",
    "esdf_toggle": "ESDF Toggle",
}

# Display-only normalization, identical to run_single.py's own
# DISPLAY_FAULT_TYPE dict (confirmed by reading it directly): mac_mobility.py's
# build_result() calls use fault_type="mac_mobility" (lowercase/snake_case)
# internally, while synthcap's own ground truth uses the display string
# "MAC Mobility" (confirmed via metadata.json's fault_type field). This
# string is never load-bearing for scoring -- scorer_lib.py's real
# production scorers never compare fault_type for mac_mobility at all
# (see MODULE_FOR_FOLDER's own is_mac_mobility branch) -- so normalizing
# it here is purely cosmetic, same as run_single.py. Does NOT touch
# mac_mobility.py's actual internal fault_type value.
DISPLAY_FAULT_TYPE = {
    "mac_mobility": "MAC Mobility",
}


def iso_epoch(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def mechanism_args(folder_type, folder_name):
    """rd_collision is the one remaining module that takes a mechanism
    argument. rt_misconfig (2026-08-15) and mac_mobility (2026-08-16) take
    none -- both are fully wire-derived; mac_mobility's rapid/repeated
    flap classification now comes from the per-MAC move count detect()
    finds in the capture, not from an external hint (there never was any
    real behavioral difference to hint at -- confirmed this session by
    reading mac_mobility.py directly)."""
    rdm = "simple"
    return rdm


def vmap2(d):
    return {"RR1": os.path.join(d, "rr1.pcap"), "RR2": os.path.join(d, "rr2.pcap")}


def vmap3(d):
    return {"RR1": os.path.join(d, "rr1.pcap"), "RR2": os.path.join(d, "rr2.pcap"), "RR3": os.path.join(d, "rr3.pcap")}


SYNTH_TOPO_2RR = os.path.join(os.path.dirname(__file__), "config", "topology.json")
SYNTH_TOPO_3RR = os.path.join(os.path.dirname(__file__), "config", "topology_3rr.json")


def corpus_for(base):
    base = os.path.normpath(base)
    if base.lower().endswith("output_3rr"):
        return "synthcap/output_3rr", SYNTH_TOPO_3RR, vmap3
    return "synthcap/output", SYNTH_TOPO_2RR, vmap2


def score_synthcap_file(base, folder_type, folder, print_table=True):
    """Returns a dict of {field: (got, expected, match_or_NA)} plus the
    raw incident and metadata, for both direct printing and Step 2's
    bucketing self-check to inspect without re-parsing pcaps."""
    corpus, topo_path, vmap_builder = corpus_for(base)
    module_key = FOLDER_TYPE_TO_MODULE[folder_type]
    d = os.path.join(base, folder_type, "single", folder)
    meta_path = os.path.join(d, "metadata.json")
    result = {"corpus": corpus, "folder_type": folder_type, "folder": folder, "path": d}
    if not os.path.exists(meta_path):
        result["status"] = "SKIP_NO_META"
        return result
    meta = json.load(open(meta_path))
    topo = load_topology(topo_path)
    vmap = {k: v for k, v in vmap_builder(d).items() if os.path.exists(v)}
    streams = parse_vantages(vmap, topo_path)
    fused = fuse_event_streams(streams, topo_path)
    rdm = mechanism_args(folder_type, folder)
    raw = run_all_rules(fused, topo, rdm)
    primary = raw[module_key]
    # Every entry in primary is now, by construction, a genuine finding
    # (2026-08-15: modules return [] for "nothing found" instead of a
    # DETECTED/NOT_DETECTABLE_STRUCTURAL/NO_SIGNAL_FOUND placeholder object).
    inc = primary[0] if primary else {}

    gt_fault_type = meta.get("fault_type")
    gt_node = meta.get("affected_device")
    is_mac_mobility = folder_type == "mac_mobility"
    gt_recovered = None if is_mac_mobility else meta.get("recovery")
    fw = (meta.get("fault_window") or {}).get("rr1") or {}
    gt_t_fault = iso_epoch(fw.get("fault_start_datetime_utc"))
    gt_t_recov = None if is_mac_mobility else iso_epoch(fw.get("fault_end_datetime_utc"))

    got_ft = inc.get("fault_type")
    got_mech = inc.get("trigger_mechanism")
    # mac_mobility.py no longer emits recovery_status at all (2026-08-14,
    # replaced with a plain move_completed boolean -- 'recovery_status' as
    # a session-up/down enum never applied to a MAC move). This comparator
    # already treats mac_mobility's recovered field as N/A on the ground-
    # truth side (gt_recovered is always None here), so this only affects
    # what's displayed, not any pass/fail verdict.
    got_rs = inc.get("move_completed") if is_mac_mobility else inc.get("recovery_status")
    got_t_fault = inc.get("time_of_first_fault")
    # mac_mobility.py renamed recovered_time/recovered_time_readable to
    # move_completed_time/move_completed_time_readable (2026-08-16) --
    # same leftover-naming fix as recovery_status/move_completed above.
    got_t_recov = inc.get("move_completed_time") if is_mac_mobility else inc.get("recovered_time")
    gn = inc.get("root_cause_node") or inc.get("affected_node_pair") or inc.get("affected_node_group")
    if isinstance(gn, dict):
        got_nodes = set(v.upper() for v in gn.values() if v)
    elif isinstance(gn, (list, set)):
        got_nodes = set(x.upper() for x in gn)
    elif isinstance(gn, str):
        got_nodes = {gn.upper()}
    else:
        got_nodes = set()
    exp_nodes = set(x.strip().upper() for x in (gt_node or "").split(",") if x.strip())
    got_recovered_bool = True if got_rs == "RECOVERED" else (False if got_rs == "NOT_RECOVERED" else None)

    ftol = fault_tolerance(folder_type, folder)
    rtol = synthcap_recovery_tolerance(folder_type, folder)

    got_ft_display = DISPLAY_FAULT_TYPE.get(got_ft, got_ft)

    fields = {}
    fields["fault_type"] = (got_ft_display, gt_fault_type, (got_ft_display == gt_fault_type) if got_ft_display else False)
    fields["node(s)"] = (sorted(got_nodes) or None, sorted(exp_nodes) or None,
                          (got_nodes == exp_nodes) if got_nodes and exp_nodes else False)
    fields["trigger_mechanism"] = (got_mech, "N/A (no ground-truth mechanism string on synthcap side)", "N/A")
    if gt_recovered is not None:
        fields["recovered"] = (got_rs, gt_recovered,
                                (got_recovered_bool == gt_recovered) if got_rs and got_rs != "UNKNOWN" else False)
    else:
        fields["recovered"] = (got_rs, "N/A (mac_mobility synthcap metadata has no recovered field)", "N/A")
    if gt_t_fault is not None and got_t_fault is not None:
        fields["time_of_first_fault"] = (got_t_fault, f"{gt_t_fault:.6f} (tol={ftol}s)",
                                          abs(got_t_fault - gt_t_fault) <= ftol)
    else:
        fields["time_of_first_fault"] = (got_t_fault, gt_t_fault, False)
    if gt_t_recov is not None and got_t_recov is not None:
        fields["time_of_recovery"] = (got_t_recov, f"{gt_t_recov:.6f} (tol={rtol}s)",
                                       abs(got_t_recov - gt_t_recov) <= rtol)
    elif gt_t_recov is None and got_t_recov is None:
        fields["time_of_recovery"] = (got_t_recov, "N/A", "N/A")
    else:
        fields["time_of_recovery"] = (got_t_recov, "N/A (mac_mobility synthcap: no ground-truth recovery time)" if is_mac_mobility else gt_t_recov, "N/A" if is_mac_mobility else False)

    ref_only = {
        "description": meta.get("description"),
        "fault_description": meta.get("fault_description"),
        "expected_bgp_events": meta.get("expected_bgp_events"),
        "base_variant": meta.get("base_variant"),
        "scenario_stem": meta.get("scenario_stem"),
        "affected_link_ids": meta.get("affected_link_ids"),
        "frame_counts": meta.get("frame_counts"),
    }
    ref_only = {k: v for k, v in ref_only.items() if v is not None}

    result.update({
        "status": "SCORED", "fields": fields, "ref_only": ref_only,
        "fault_tolerance": ftol, "recovery_tolerance": rtol,
    })

    if print_table:
        print("=" * 100)
        print(f"corpus={corpus}  folder_type={folder_type}  folder={folder}")
        print(f"path={d}  mechanism_args={ (rdm,) }")
        field_w = max(len("Field"), max(len(k) for k in fields)) + 2
        det_w = max(len("Detected"), max(len(str(v[0])) for v in fields.values())) + 2
        gt_w = max(len("Ground Truth"), max(len(str(v[1])) for v in fields.values()), 20) + 2

        def line(a, b, c, dd):
            print(f"{a:<{field_w}}| {b:<{det_w}}| {c:<{gt_w}}| {dd}")

        line("Field", "Detected", "Ground Truth", "Match?")
        print("-" * (field_w + det_w + gt_w + 10))
        for name, (got, exp, match) in fields.items():
            verdict = "MATCH" if match is True else ("N/A" if match == "N/A" else "MISMATCH")
            line(name, str(got), str(exp), verdict)
        if ref_only:
            print("--- reference-only (no detector equivalent, not compared) ---")
            for k, v in ref_only.items():
                vs = str(v)
                if len(vs) > 300:
                    vs = vs[:300] + "...(truncated)"
                print(f"  {k}: {vs}")
        print()

    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("base", help=r"C:\synthcap\output or C:\synthcap\output_3rr")
    ap.add_argument("folder_type", choices=list(FOLDER_TYPE_TO_MODULE))
    ap.add_argument("folder")
    args = ap.parse_args()
    score_synthcap_file(args.base, args.folder_type, args.folder)
