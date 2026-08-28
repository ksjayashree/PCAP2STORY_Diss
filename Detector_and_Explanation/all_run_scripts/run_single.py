"""Single-file detection runner. Takes one pcap scenario folder and runs
the same detection path run_scorer() uses (parse_vantages -> fuse_event_streams
-> run_all_rules), against just that one folder, then prints a side-by-side
Detected vs Ground Truth table.

Does NOT modify scorer_lib.py, score_detector.py, or score_detector_3rr.py --
this is a new, separate entry point that reuses their detection logic
(imported, not reimplemented) for ad-hoc single-file inspection.

Dataset (pilot_containerlab vs 3rr) and folder_type (link_down, rt_misconfig,
etc.) are both inferred from the given folder path, not passed separately --
one argument is all this needs.

Usage:
    python run_single.py "C:\\simulation pcap\\pilot_containerlab\\pcaps\\link_down\\single\\link_down_bfd_pe1_recovered"
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "rules"))

from datetime import datetime, timezone

from topology import load_topology
from vantage_parser import parse_vantages
from fusion import fuse_event_streams
from orchestrator import run_all_rules
from scorer_lib import MODULE_FOR_FOLDER, fault_tolerance, recovery_tolerance, iso_to_epoch
from rules.schema import fmt_epoch

# Display-only normalization: mac_mobility.py's build_result() calls use
# fault_type="mac_mobility" (lowercase/snake_case) internally, while every
# metadata.json's ground truth and every other rule module use Title Case
# ("Link Down", "RT Misconfiguration", etc.). Confirmed via grep across
# scorer_lib.py/score_detector.py/score_detector_3rr.py/orchestrator.py
# (2026-08-07) that this exact string is NEVER read back or compared
# anywhere in the scoring path -- orchestrator.py's own "fault_type" usages
# are unrelated hardcoded literals for its own cross-module annotations,
# not reads of mac_mobility.py's returned value. Safe to normalize here,
# display-only, without touching mac_mobility.py or scorer_lib.py.
DISPLAY_FAULT_TYPE = {
    "mac_mobility": "MAC Mobility",
}

# Established structural-limitation statuses: when the detector itself
# reports one of these, an N/A/UNKNOWN detected value for the affected
# fields is a documented wire-observability limit, not a detection gap.
# Currently the only rule module that ever sets this is rt_misconfiguration.py's
# import_only branch (RFC 4360: import-side RT filters are never
# serialized in outbound BGP UPDATE messages -- confirmed via schema.py's
# not_detectable_structural()). ESDF Toggle's NO_SIGNAL_FOUND fallback is
# deliberately NOT in this set -- see run_single.py's Step-1 investigation
# notes below fault_type's row-building for why that's a real gap, not an
# established limitation.
STRUCTURALLY_UNOBSERVABLE_STATUSES = ("NOT_DETECTABLE_STRUCTURAL",)

PILOT_TOPO = os.path.join(os.path.dirname(__file__), "config", "topology.json")
RR3_TOPO = r"C:\simulation pcap\3rr\config\topology.json"


def resolve_dataset(folder_dir):
    """Figures out which dataset this folder belongs to (and therefore
    which topology.json + vmap_builder to use) from the path itself --
    same distinction score_detector.py vs score_detector_3rr.py encode
    via which script you run, just inferred here instead of asked for."""
    norm = os.path.normpath(folder_dir).lower()
    if "3rr" in norm.split(os.sep):
        return "3rr", RR3_TOPO
    if "pilot_containerlab" in norm.split(os.sep):
        return "pilot_containerlab", PILOT_TOPO
    raise ValueError(
        f"Could not tell which dataset {folder_dir!r} belongs to (expected "
        "'3rr' or 'pilot_containerlab' as a path component). Pass a folder "
        "under one of those two pcaps trees."
    )


def vmap_pilot(folder_dir):
    rr1 = os.path.join(folder_dir, "rr1.pcap")
    rr2 = os.path.join(folder_dir, "rr2.pcap")
    vmap = {"RR1": rr1}
    if os.path.exists(rr2):
        vmap["RR2"] = rr2
    return vmap


def vmap_3rr(folder_dir):
    return {
        "XRR1": os.path.join(folder_dir, "xrr1.pcap"),
        "XRR2": os.path.join(folder_dir, "xrr2.pcap"),
        "XRR3": os.path.join(folder_dir, "xrr3.pcap"),
    }


def folder_type_from_path(folder_dir):
    """folder_type is the directory two levels up from the scenario folder
    itself, e.g. .../rt_misconfig/single/rt_misconfig_..._pe1_fixed ->
    "rt_misconfig". Same convention run_scorer's own os.path.join(pcaps_base,
    folder_type, "single") walk assumes, just read backwards here."""
    parent = os.path.basename(os.path.dirname(os.path.normpath(folder_dir)))
    if parent.lower() != "single":
        raise ValueError(
            f"Expected {folder_dir!r} to be a scenario folder directly under "
            f"a '.../<folder_type>/single/' directory, but its parent is "
            f"{parent!r}, not 'single'."
        )
    grandparent = os.path.basename(os.path.dirname(os.path.dirname(os.path.normpath(folder_dir))))
    return grandparent


def mechanism_args(folder_type, folder_name):
    """Same derivation run_scorer() uses -- only matters for rd_collision,
    the one remaining module that consumes a mechanism argument.
    rt_misconfig and mac_mobility take no mechanism hint at all anymore
    (2026-08-15/2026-08-16) -- both are fully wire-derived."""
    rdm = "masking" if "masking" in folder_name else "simple"
    return rdm


def detect_one(folder_dir):
    folder_dir = os.path.normpath(folder_dir)
    dataset, topo_path = resolve_dataset(folder_dir)
    topo = load_topology(topo_path)
    vmap_builder = vmap_3rr if dataset == "3rr" else vmap_pilot
    folder_type = folder_type_from_path(folder_dir)
    if folder_type not in MODULE_FOR_FOLDER:
        raise ValueError(
            f"folder_type {folder_type!r} (inferred from path) is not a "
            f"recognized fault-type folder -- expected one of "
            f"{sorted(set(MODULE_FOR_FOLDER))}."
        )
    module_key = MODULE_FOR_FOLDER[folder_type]
    folder_name = os.path.basename(folder_dir)

    meta_path = os.path.join(folder_dir, "metadata.json")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"No metadata.json in {folder_dir}")
    meta = json.load(open(meta_path))

    vmap = vmap_builder(folder_dir)
    streams = parse_vantages(vmap, topo_path)
    fused = fuse_event_streams(streams, topo_path)

    rdm = mechanism_args(folder_type, folder_name)
    raw = run_all_rules(fused, topo, rdm)
    primary_incidents = raw[module_key]

    is_mac_mobility = folder_type == "mac_mobility"

    # Every entry in primary_incidents is now, by construction, a genuine
    # finding (2026-08-15: modules return [] for "nothing found" instead of
    # a DETECTED/NOT_DETECTABLE_STRUCTURAL/NO_SIGNAL_FOUND placeholder
    # object) -- so the first (and, for these single-fault scenario files,
    # only) entry is simply primary_incidents[0], or {} if nothing at all
    # was found.
    inc = primary_incidents[0] if primary_incidents else {}

    return dataset, folder_type, folder_name, module_key, meta, inc, is_mac_mobility


def na(v):
    return "N/A" if v is None else v


# Step 1 finding, recorded here (not just in the report) so it stays next
# to the code it explains: fault_type below is genuine rule-module output,
# not something run_single.py infers from the folder path -- detect_one()
# reads it straight off `inc["fault_type"]`, which every module (including
# esdf_toggle.py's own NO_SIGNAL_FOUND fallback, see esdf_toggle.py lines
# 286-291) sets as a literal identity label for which module answered,
# unconditionally, whether or not it actually found a trigger. So a
# fault_type MATCH is real (this file's module really did run and really
# did self-report "ESDF Toggle"), but it is NOT evidence the module
# detected the fault itself -- root_cause_node/mechanism/recovered coming
# back N/A/UNKNOWN alongside a matching fault_type is the genuinely
# informative combination, not a display inconsistency.
#
# For esdf_toggle_link_pe1_notrecovered specifically: this is the ONLY
# esdf_toggle single-scenario file in the dataset (pilot_containerlab/
# pcaps/esdf_toggle/single/ has exactly one folder), and its
# trigger_mechanism, "Link Down (bond100 slave eth2)", produces a full
# BGP session teardown+reconnect on the wire (BFD Down -> NOTIFICATION
# Cease -> TCP FIN/RESET -> fresh BGP_OPEN/SESSION_ESTABLISHED -> fresh
# Type-1/2/3 EVPN *advertisements*), confirmed directly against this
# file's own fused event stream -- zero BGP_WITHDRAWAL events anywhere in
# it. esdf_toggle.py's detect() only recognizes DF-election triggers built
# on a withdraw-then-readvertise shape (Type-4 ES route, Type-1 per-EVI/
# per-ES EAD, or the AC-state community toggle); none of those shapes
# occur here, so detect() correctly falls through to NO_SIGNAL_FOUND. This
# is NOT the FRR 10.6.1 zebra ES-EVI defect (that was root-caused and
# fixed via the bond100 conversion, per docs_internal/SESSION_SUMMARY_
# 2026-08-05.md section 1 -- confirmed still in effect, not reverted).
# esdf_toggle.py also never sets NOT_DETECTABLE_STRUCTURAL for any
# mechanism at all (grepped, zero occurrences) so there is no established-
# limitation status here to defer to. This is a real, unexplained gap
# between this file's declared fault_type/trigger_mechanism and what the
# rule module was built to recognize -- reported here, not fixed, per the
# task's explicit scope boundary (esdf_toggle.py/rule-module changes need
# separate confirmation first).


def build_rows(meta, inc, is_mac_mobility):
    rows = []
    # detectability_status removed (2026-08-15) -- there is no longer a
    # status field to distinguish "structurally couldn't look" from
    # "genuinely searched, found nothing"; an empty inc ({}) from
    # detect_one() covers both uniformly now.
    structurally_unobservable = not inc

    def nwo(flag):
        return "NOT_WIRE_OBSERVABLE" if flag else None

    # fault_type
    got_ft = inc.get("fault_type")
    got_ft_display = DISPLAY_FAULT_TYPE.get(got_ft, got_ft)
    exp_ft = "MAC Mobility" if is_mac_mobility else meta.get("fault_type")
    rows.append(("fault_type", na(got_ft_display), na(exp_ft), None))

    # node / pair / group
    if is_mac_mobility:
        got_pair = inc.get("affected_node_pair")
        got_repr = ",".join(sorted(got_pair.values())) if got_pair else None
        exp_nodes = {meta.get("origin_pe", ""), meta.get("destination_pe", "")}
        exp_repr = ",".join(sorted(x for x in exp_nodes if x)) or None
        rows.append(("affected_node(s)", na(got_repr), na(exp_repr), None))
    elif "event_affected_nodes" in meta:
        # affected_node_group removed from output (2026-08-14) -- for a
        # 3+-PE RD Collision, colliding_routes' own keys are the only
        # remaining place the colliding PE identities are named.
        got_group = inc.get("affected_node_pair") or (list(inc["colliding_routes"].keys()) if inc.get("colliding_routes") else None)
        if isinstance(got_group, dict):
            got_repr = ",".join(sorted(got_group.values()))
        elif isinstance(got_group, (list, set)):
            got_repr = ",".join(sorted(got_group))
        else:
            got_repr = None
        exp_repr = ",".join(sorted(x.upper() for x in meta["event_affected_nodes"]))
        rows.append(("affected_node(s)", na(got_repr), na(exp_repr), nwo(structurally_unobservable and got_repr is None)))
    else:
        got_node = inc.get("root_cause_node")
        exp_node = meta.get("event_affected_node")
        rows.append(("root_cause_node", na(got_node), na(exp_node), nwo(structurally_unobservable and got_node is None)))

    # mechanism
    got_mech = inc.get("trigger_mechanism")
    exp_mech = meta.get("mechanism") if is_mac_mobility else meta.get("trigger_mechanism")
    rows.append(("mechanism", na(got_mech), na(exp_mech), None))

    # recovered status
    if is_mac_mobility:
        rows.append(("recovered", "N/A", "N/A", None))
    else:
        got_rs = inc.get("recovery_status")
        exp_recovered = meta.get("recovered")
        if exp_recovered == "NOT_CAPTURED":
            exp_repr = "NOT_CAPTURED"
        elif exp_recovered is True:
            exp_repr = "RECOVERED"
        elif exp_recovered is False:
            exp_repr = "NOT_RECOVERED"
        else:
            exp_repr = None
        rows.append(("recovered", na(got_rs), na(exp_repr), nwo(structurally_unobservable and got_rs == "UNKNOWN")))

    return rows, structurally_unobservable


def build_time_rows(meta, inc, is_mac_mobility, folder_type, folder_name, structurally_unobservable):
    """fault_time_detected / recovery_time_detected: build_result() (schema.py)
    DOES carry time_of_first_fault/recovered_time internally on every real
    incident dict -- confirmed by reading schema.py's build_result() and
    every rule module's call sites -- so these are genuinely tracked
    detector-side timestamps when a module found something, not values
    run_single.py has to invent. They are None when the module never found
    a trigger at all (NO_SIGNAL_FOUND) or structurally couldn't look
    (NOT_DETECTABLE_STRUCTURAL), and are printed as NOT_TRACKED in that
    case rather than fabricated -- that absence is itself the reportable
    fact, not a display gap."""
    rows = []

    exp_fault_key = "time_of_move" if is_mac_mobility else "time_of_first_fault"
    exp_fault_iso = meta.get(exp_fault_key)
    got_fault_epoch = inc.get("time_of_first_fault")
    got_fault_disp = fmt_epoch(got_fault_epoch) or "NOT_TRACKED"
    if got_fault_epoch is None:
        verdict_override = "NOT_WIRE_OBSERVABLE" if structurally_unobservable else "MISMATCH"
    else:
        exp_epoch = iso_to_epoch(exp_fault_iso)
        tol = fault_tolerance(folder_type, folder_name)
        # Explicit MATCH/MISMATCH here, not None -- these two rows compare
        # a formatted display string against tolerance-adjusted epoch math,
        # so falling through to verdict_for()'s default (plain string
        # equality) would almost always read MISMATCH even when well
        # within tolerance, since the two timestamps are independently
        # sourced (wire-observed vs injection-command-issued) and were
        # never going to render identically.
        verdict_override = "MATCH" if (exp_epoch is not None and abs(exp_epoch - got_fault_epoch) <= tol) else "MISMATCH"
    rows.append(("fault_time_detected", got_fault_disp, na(exp_fault_iso), verdict_override))

    if is_mac_mobility:
        # mac_mobility's metadata.json shape has no recovery-time ground
        # truth field at all (confirmed in scorer_lib.py's own comments) --
        # nothing to compare on either side.
        rows.append(("recovery_time_detected", "NOT_TRACKED", "N/A", "MATCH"))
    else:
        exp_recovered = meta.get("recovered")
        exp_recov_iso = meta.get("time_of_recovery")
        got_recov_epoch = inc.get("recovered_time")
        got_recov_disp = fmt_epoch(got_recov_epoch) or "NOT_TRACKED"
        if exp_recovered is not True:
            # Ground truth says it never recovered (or recovery wasn't
            # captured) -- no recovery timestamp is expected on either
            # side. A detector-side None here is correct, not a gap.
            verdict_override = "MATCH" if got_recov_epoch is None else "MISMATCH"
        elif got_recov_epoch is None:
            verdict_override = "NOT_WIRE_OBSERVABLE" if structurally_unobservable else "MISMATCH"
        else:
            exp_epoch = iso_to_epoch(exp_recov_iso)
            tol = recovery_tolerance(folder_type, folder_name)
            verdict_override = "MATCH" if (exp_epoch is not None and abs(exp_epoch - got_recov_epoch) <= tol) else "MISMATCH"
        rows.append(("recovery_time_detected", got_recov_disp, na(exp_recov_iso), verdict_override))

    return rows


def verdict_for(got, exp, override):
    if override is not None:
        return override
    # Both sides N/A (field doesn't apply to this fault type/schema) counts
    # as MATCH -- there's nothing to disagree about, not a detector miss.
    return "MATCH" if got == exp else "MISMATCH"


def print_table(rows):
    verdicts = [verdict_for(got, exp, override) for _, got, exp, override in rows]
    field_w = max(len("Field"), max(len(r[0]) for r in rows)) + 2
    det_w = max(len("Detected"), max(len(str(r[1])) for r in rows)) + 2
    gt_w = max(len("Ground Truth"), max(len(str(r[2])) for r in rows)) + 2
    match_w = max(len("Match?"), max(len(v) for v in verdicts)) + 2

    def line(a, b, c, d):
        print(f"{a:<{field_w}}| {b:<{det_w}}| {c:<{gt_w}}| {d:<{match_w}}")

    line("Field", "Detected", "Ground Truth", "Match?")
    print("-" * (field_w + det_w + gt_w + match_w + 6))
    for (name, got, exp, override), verdict in zip(rows, verdicts):
        line(name, got, exp, verdict)


def main():
    if len(sys.argv) != 2:
        print("Usage: python run_single.py <path-to-scenario-folder>")
        sys.exit(1)
    folder_dir = sys.argv[1]

    dataset, folder_type, folder_name, module_key, meta, inc, is_mac_mobility = detect_one(folder_dir)
    print(f"Dataset: {dataset}   Folder type: {folder_type}   Rule module: {module_key}")
    print()
    rows, structurally_unobservable = build_rows(meta, inc, is_mac_mobility)
    rows += build_time_rows(meta, inc, is_mac_mobility, folder_type, folder_name, structurally_unobservable)
    print_table(rows)


if __name__ == "__main__":
    main()
