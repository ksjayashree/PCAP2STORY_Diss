"""Shared scorer logic for both pilot_containerlab (2RR) and 3rr (3RR)
datasets -- field-comparison/tolerance logic, MODULE_FOR_FOLDER, and the
whole scoring/false-positive-check loop live here ONCE so neither
dataset's caller script duplicates them. Callers (`_score_detector.py`,
`_score_detector_3rr.py`) only supply dataset-specific glue: the pcaps
base dir, the loaded topology dict + its explicit topology_path, and a
vmap_builder function that knows that dataset's own pcap filename/vantage
naming convention.
"""
import os
import json
from datetime import datetime, timezone

from vantage_parser import parse_vantages
from fusion import fuse_event_streams
from orchestrator import run_all_rules, annotate_precedence

# Precedence-layer statuses meaning "orchestrator confirmed this
# cross-module detection is legitimately real, not a detector error" --
# exempts a finding from the cross-module false-positive penalty.
# LIKELY_ARTIFACT_OF_*: a correctly-demoted artifact -- flagged as noise
# by design, exactly what's supposed to happen, not itself a false
# positive of the demotion system. CONFIRMED_COOCCURRENCE: both sides of
# a genuine, distinct, correctly-detected co-occurring event (see
# orchestrator.py's MAC Mobility <-> ESDF Toggle rule) -- tagging either
# side as spurious would misrepresent an accurate detection.
# CONFIRMED_ROOT_CAUSE: Link Down's own status when it anchors other
# incidents' artifacts. Deliberately excludes "GENUINE" -- that status
# means "orchestrator found no relationship to explain this," which for
# an unrelated other-module detection is exactly the ambiguous case this
# check exists to surface, not silently exempt.
CROSS_MODULE_EXEMPT_STATUSES = (
    "LIKELY_ARTIFACT_OF_LINK_DOWN",
    "LIKELY_ARTIFACT_OF_RR_DOWN_RECOVERY",
    "CONFIRMED_COOCCURRENCE",
    "CONFIRMED_ROOT_CAUSE",
)


def _cross_module_undemoted(raw, prec, other_key, exclude_key=None, exclude_primary_index=None):
    """True if `other_key`'s DETECTED incidents in `raw` are NOT all
    covered by a CROSS_MODULE_EXEMPT_STATUSES precedence entry -- i.e. a
    genuine, unexplained cross-module false positive. `exclude_key` no
    longer skips the fault type being scored wholesale -- it only exempts
    that module's own `exclude_primary_index` entry, the single DETECTED
    incident already matched as the correct primary detection for the
    fault under test. Any OTHER DETECTED entry in that same module's list
    (a second, extra incident) is checked for precedence exemption exactly
    like a cross-module entry would be, not exempted by default. The
    normal-baseline loop passes exclude_key=None (and leaves
    exclude_primary_index at its default None) since no fault was injected
    there at all, so every module and every entry is in scope."""
    other_list = raw.get(other_key, [])
    # Every entry in other_list is now, by construction, a genuine finding
    # (2026-08-15: no more DETECTED/NOT_DETECTABLE_STRUCTURAL/NO_SIGNAL_FOUND
    # placeholder objects -- a module returns [] for "nothing found" instead).
    detected_indices = list(range(len(other_list)))
    if not detected_indices:
        return False
    prec_list = prec.get(other_key, [])
    for idx in detected_indices:
        if other_key == exclude_key and idx == exclude_primary_index:
            continue
        entry = next((p for p in prec_list if p["index"] == idx), None)
        if entry is None or entry["status"] not in CROSS_MODULE_EXEMPT_STATUSES:
            return True
    return False

MODULE_FOR_FOLDER = {
    "link_down": "Link Down",
    "rr_down": "RR Down",
    "pe_cease": "PE Cease",
    "rt_misconfig": "RT Misconfiguration",
    "rd_collision": "RD Collision",
    # Confirmed pre-existing gap (not 3RR-specific): mac_mobility was never
    # scored by the original pilot_containerlab-only script. Its
    # metadata.json shape is genuinely different from the other five fault
    # types (no trigger_mechanism/time_of_first_fault/recovered/
    # event_affected_node keys -- uses mechanism/time_of_move/origin_pe/
    # destination_pe instead, confirmed identical shape in both datasets),
    # handled via the is_mac_mobility branch in score_file below.
    "mac_mobility": "MAC Mobility",
    # Both folder-types map to the same orchestrator key/rule module:
    # esdf_toggle.py's detect() handles Full ES Failure as a trigger_mechanism
    # variant (TRIGGER_TYPE1_ES_DUAL) within the same function, always
    # returning fault_type="ESDF Toggle" -- confirmed via direct read
    # (2026-08-05), there is no separate "Full ES Failure" module or
    # orchestrator key to point to.
    "esdf_toggle": "ESDF Toggle",
    "full_es_failure": "ESDF Toggle",
}

# Mechanism-aware timing tolerances, justified against the actual deltas
# measured across all 82 real pilot_containerlab files (not a flat guess):
#
# FAULT-ONSET (time_of_first_fault):
#   - tcpfail: observed -25.8s to -34.1s (from the 10 properly-generated
#     link_down_tcpfail_pe*_recovered/notrecovered files -- confirmed this
#     range does NOT depend on ab_test_tcpfail_pe1_recovered/
#     pe2_notrecovered, which were archived to
#     pilot_containerlab/_archived_ab_test_tcpfail/ as leftover manual-
#     harness artifacts, not standard-pipeline scenarios) -- the RR's own
#     ~30s hold-timer wait before the fault becomes wire-visible
#     (documented in All_Scenarios.py). 40s gives ~1.2x margin over the
#     largest observed gap (34.1s).
#   - every other mechanism (bfd/holdtimer fault-onset, graceful, bgpdkill,
#     rt_misconfig, rd_collision, mac_mobility clean_move): observed up to
#     4.164s for the original five types. 5s gives >1.2x margin over that
#     ceiling.
#   - mac_mobility clean_move: NOT covered by the 5s default -- originally
#     measured directly against the 3 real pilot_containerlab cleanmove
#     files (6.526s-6.700s, all a few hundred ms clear of the 5s bucket).
#     Same class of injection-command-issued-at vs wire-visible-event
#     definitional gap as the other mechanisms above, just a wider one.
#     9.0s gave ~1.34x margin over that original observed max (6.700s).
#
#     Revised 2026-08-06 after mac_mobility.py's backward-matching fix
#     (make-before-break support, see mac_mobility.py's BACKWARD_
#     ADVERTISE_MAX_SECONDS comment): xpe7to5_settled (3rr, the first and
#     only backward-matched file in either dataset) measured at 9.401s --
#     exceeded the old 9.0s tolerance despite being a correct detection
#     (verified: origin/destination pair matches metadata exactly). Full
#     22-file gap distribution re-measured across both projects: the
#     forward-matched cluster (21 files) sits 5.732s-7.365s; xpe7to5_settled
#     is the dataset's sole outlier at 9.401s. 12.6s = same ~1.34x margin
#     methodology applied to this new observed max (9.401 * 1.34 = 12.6).
#
#     CAVEAT -- this value rests on a SINGLE backward-matched sample. If
#     additional backward-matched mac_mobility files are added to either
#     dataset in future, re-run the gap-distribution measurement and
#     re-derive this constant; do not assume 12.6s remains a valid margin
#     without re-checking.
#
#     UNRESOLVED CONFOUND -- xpe7to8_settled (3rr, FORWARD-matched, origin
#     XPE7) measured at 7.365s, the second-highest gap in the whole
#     dataset and well clear of every other origin's 5.7s-6.8s range. Both
#     of the two highest gaps in the dataset have XPE7 as origin. This
#     means part of xpe7to5_settled's 9.401s outlier may be XPE7-specific
#     injection/wire latency rather than a backward-matching effect --
#     with n=1 backward sample this is not separable from the match-
#     direction effect and is flagged here unresolved, not ruled out.
TOL_FAULT_TCPFAIL = 40.0
TOL_FAULT_MACMOBILITY = 12.6
TOL_FAULT_DEFAULT = 5.0

# RECOVERY (recovered_time):
#   - bfd/holdtimer recovery: observed -20.6s to -23.7s -- the same
#     recover_fn()-call-time vs SESSION_ESTABLISHED definitional gap. 30s
#     gives >1.25x margin over the largest observed gap (23.7s).
#   - tcpfail recovery: observed -0.591s to -7.466s. 10s gives ~1.3x margin
#     over the largest observed gap.
#   - every other mechanism's recovery: observed up to 2.664s. 5s default
#     applies, same margin reasoning as fault-onset's default bucket.
#   mac_mobility has no comparable recovery-time ground truth field at all
#   (metadata.json carries only a single time_of_move, no separate
#   recovery timestamp) -- recovered_time is never scored for it, see
#   score_file's is_mac_mobility branch.
TOL_RECOV_BFDHOLDTIMER = 30.0
TOL_RECOV_TCPFAIL = 10.0
TOL_RECOV_DEFAULT = 5.0


def fault_tolerance(folder_type, folder):
    if folder_type == "link_down" and "tcpfail" in folder:
        return TOL_FAULT_TCPFAIL
    if folder_type == "mac_mobility":
        return TOL_FAULT_MACMOBILITY
    return TOL_FAULT_DEFAULT


def recovery_tolerance(folder_type, folder):
    if folder_type == "link_down":
        if "bfd" in folder or "holdtimer" in folder:
            return TOL_RECOV_BFDHOLDTIMER
        if "tcpfail" in folder:
            return TOL_RECOV_TCPFAIL
    return TOL_RECOV_DEFAULT


# SYNTHCAP-SPECIFIC recovery tolerance (2026-08-08): a separate function,
# NOT a change to recovery_tolerance() above -- no production scorer calls
# this yet (confirmed: score_detector.py/score_detector_3rr.py, the only
# real callers of recovery_tolerance(), score pilot_containerlab/3rr only;
# every synthcap comparison so far has been an ad hoc scratch script, so
# this is new capability, not a fix to any currently-running path).
#
# Same recover_fn()-call-time vs SESSION_ESTABLISHED/wire-completed-
# recovery definitional gap already reconciled for bfd/holdtimer above,
# but synthcap's ESDF Toggle scenarios need their OWN tolerance set: a
# flat number can't work here the way TOL_RECOV_BFDHOLDTIMER does for
# link_down, because the measured gap clusters by SCENARIO SHAPE, not by
# a single mechanism -- confirmed via direct measurement of ALL 28 real
# synthcap ESDF Toggle recovery:true files (both corpora; mac_mobility
# has NO comparable field -- every mac_mobility file's recovery is false,
# even though fault_window.fault_end_datetime_utc is non-null there too,
# which is the last-flap timestamp of a repeated-flap sequence, not a
# recovery signal -- do not compare recovered_time against it):
#   full_failure_recovery*  (4 files): 1.027610s - 1.351088s
#   default (ac_state/single/single_midchurn/type1_evi, 20 files): 30.500000s - 31.436488s
#   repeated*                (2 files, output corpus only): 82.644520s - 82.715513s
#   slow                     (2 files, one per corpus): 162.137040s - 198.208337s
# Each bucket's tolerance = ~2x the worst measured gap in that bucket,
# same convention as TOL_RECOV_BFDHOLDTIMER/TOL_FAULT_TCPFAIL above:
#   full_failure_recovery: 1.351088 * 2 = 2.70 -> 3.0s
#   default:                31.436488 * 2 = 62.87 -> 65.0s
#   repeated:                82.715513 * 2 = 165.43 -> 170.0s
#   slow:                   198.208337 * 2 = 396.42 -> 400.0s
SYNTHCAP_TOL_RECOV_FULL_FAILURE = 3.0
SYNTHCAP_TOL_RECOV_REPEATED = 170.0
SYNTHCAP_TOL_RECOV_SLOW = 400.0
SYNTHCAP_TOL_RECOV_DEFAULT = 65.0


def synthcap_recovery_tolerance(folder_type, folder):
    if folder_type == "esdf_toggle":
        if "full_failure_recovery" in folder:
            return SYNTHCAP_TOL_RECOV_FULL_FAILURE
        if "repeated" in folder:
            return SYNTHCAP_TOL_RECOV_REPEATED
        if "slow" in folder:
            return SYNTHCAP_TOL_RECOV_SLOW
    return SYNTHCAP_TOL_RECOV_DEFAULT


def iso_to_epoch(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def tm_match(got, expected):
    if got is None or expected is None:
        return False
    if got == expected:
        return True
    return got in expected or expected in got


def score_file(module_key, primary_incidents, meta, folder, folder_type):
    fields_checked = 0
    fields_correct = 0
    mismatches = []

    is_mac_mobility = folder_type == "mac_mobility"

    expected_recovered = meta.get("recovered")

    # Structurally-undetectable-expected case (rt_misconfig import_only,
    # 2026-08-15 reworked): import_only now runs the same genuine wire
    # search as every other mechanism (no more hardcoded status) -- a
    # real 30-file search this session found zero deviant RT values
    # anywhere, consistent with RFC 4360 (import-only RT filters are
    # never serialized outbound), so the CORRECT detector output here is
    # an empty list, same as any other genuinely-nothing-found case, not
    # a special status string.
    if "rt_misconfig_import_only" in folder:
        fields_checked += 1
        ok = primary_incidents == []
        fields_correct += ok
        if not ok:
            mismatches.append(("import_only expected []", "[]", primary_incidents))
        return fields_checked, fields_correct, mismatches, "NOT_DETECTABLE", None, []

    # Read the FULL detected list, not just index 0 -- ground truth for a
    # single-fault folder expects exactly one incident, so any entry beyond
    # the first (`extra_detected`) is a same-module extra detection. It is
    # not decided here whether it's a false positive: that determination
    # goes through _cross_module_undemoted()'s precedence-exemption check
    # in run_scorer (same mechanism used for cross-module false positives),
    # so a legitimately-exempted extra (e.g. CONFIRMED_COOCCURRENCE) isn't
    # double-flagged by two different code paths.
    # Every entry in primary_incidents is now, by construction, a genuine
    # finding (2026-08-15: modules return [] for "nothing found" instead
    # of a DETECTED/NOT_DETECTABLE_STRUCTURAL/NO_SIGNAL_FOUND placeholder
    # object), so "detected" is just every (index, incident) pair present.
    detected = list(enumerate(primary_incidents))
    fields_checked += 1
    if detected:
        fields_correct += 1
    else:
        mismatches.append(("primary_incidents", "at least one incident", "[]"))
        return fields_checked, fields_correct, mismatches, "MISSED", None, []

    primary_idx, inc = detected[0]
    extra_detected = detected[1:]

    # root_cause_node / affected_node_pair / affected_node_group vs metadata
    fields_checked += 1
    if is_mac_mobility:
        expected_nodes = {meta.get("origin_pe", "").upper(), meta.get("destination_pe", "").upper()}
        got_nodes = set(inc["affected_node_pair"].values()) if inc.get("affected_node_pair") else set()
        ok = got_nodes == expected_nodes
        expected_repr = expected_nodes
    elif "event_affected_nodes" in meta:
        expected_nodes = set(x.upper() for x in meta["event_affected_nodes"])
        got_nodes = set()
        if inc.get("affected_node_pair"):
            got_nodes = set(inc["affected_node_pair"].values())
        elif inc.get("affected_nodes"):
            # affected_nodes (2026-08-16): RD Collision's own field now,
            # a plain list covering 2-PE and 3+-PE cases uniformly --
            # replaces the old affected_node_pair (2-PE dict) and the
            # colliding_routes-keys fallback previously needed for 3+-PE.
            got_nodes = set(x.upper() for x in inc["affected_nodes"])
        ok = got_nodes == expected_nodes
        expected_repr = expected_nodes
    else:
        expected_node = meta.get("event_affected_node")
        got_node = inc.get("root_cause_node")
        ok = got_node == expected_node
        expected_repr = expected_node
    fields_correct += ok
    if not ok:
        mismatches.append(("root_cause_node/pair/group", expected_repr, inc.get("root_cause_node") or inc.get("affected_node_pair") or inc.get("affected_nodes")))

    # trigger_mechanism (mac_mobility's metadata key is "mechanism", not
    # "trigger_mechanism" -- confirmed via direct inspection of real
    # metadata.json files in both datasets, same shape in both)
    fields_checked += 1
    expected_mechanism = meta.get("mechanism") if is_mac_mobility else meta.get("trigger_mechanism")
    ok = tm_match(inc.get("trigger_mechanism"), expected_mechanism)
    fields_correct += ok
    if not ok:
        mismatches.append(("trigger_mechanism", expected_mechanism, inc.get("trigger_mechanism")))

    # time_of_first_fault (mac_mobility's metadata key is "time_of_move")
    fields_checked += 1
    expected_time_key = "time_of_move" if is_mac_mobility else "time_of_first_fault"
    exp_t = iso_to_epoch(meta.get(expected_time_key))
    got_t = inc.get("time_of_first_fault")
    fault_tol = fault_tolerance(folder_type, folder)
    ok = exp_t is not None and got_t is not None and abs(exp_t - got_t) <= fault_tol
    fields_correct += ok
    if not ok:
        mismatches.append(("time_of_first_fault", meta.get(expected_time_key), got_t, f"tol={fault_tol}s"))

    if is_mac_mobility:
        # No recovery_status/recovered_time ground truth exists in
        # mac_mobility's metadata.json shape at all (confirmed: no
        # "recovered" or "time_of_recovery" key present in real files in
        # either dataset) -- detect()'s own recovery_status is always
        # "RECOVERED" by construction for a DETECTED clean-move incident,
        # not a wire-observed outcome being verified here, so neither
        # field is scored. Not silently skipped: this comment plus the
        # early return make the scope explicit.
        return fields_checked, fields_correct, mismatches, "SCORED", primary_idx, extra_detected

    # recovery_status vs recovered
    # containerkill special-case removed (2026-08-02, along with the
    # mechanism itself): its real captures are archived to
    # pilot_containerlab/_archived_rr_down_containerkill/, and rr_down.py
    # no longer recognizes containerkill's trigger shape at all, so no
    # folder-name check is needed here anymore -- expected_recovered's
    # own value (including the already-corrected NOT_CAPTURED sentinel on
    # both former containerkill variants) is followed generically like
    # every other mechanism.
    fields_checked += 1
    rs = inc.get("recovery_status")
    if expected_recovered == "NOT_CAPTURED":
        ok = rs == "NOT_CAPTURED"
    elif expected_recovered is True:
        ok = rs == "RECOVERED"
    elif expected_recovered is False:
        ok = rs == "NOT_RECOVERED"
    else:
        ok = False
    fields_correct += ok
    if not ok:
        mismatches.append(("recovery_status", expected_recovered, rs))

    # recovered_time vs time_of_recovery (only when recovered)
    if expected_recovered is True:
        fields_checked += 1
        exp_rt = iso_to_epoch(meta.get("time_of_recovery"))
        got_rt = inc.get("recovered_time")
        recov_tol = recovery_tolerance(folder_type, folder)
        ok = exp_rt is not None and got_rt is not None and abs(exp_rt - got_rt) <= recov_tol
        fields_correct += ok
        if not ok:
            mismatches.append(("recovered_time", meta.get("time_of_recovery"), got_rt, f"tol={recov_tol}s"))

    return fields_checked, fields_correct, mismatches, "SCORED", primary_idx, extra_detected


def run_scorer(*, pcaps_base, topo, topo_path, vmap_builder, exclude=None, normal_base=None):
    """Runs the full scoring + cross-module false-positive check + normal-
    baseline check, printing the same report format as the original
    pilot_containerlab-only script.

    topo_path is REQUIRED and must be the explicit path string for THIS
    dataset's topology.json -- parse_vantages/fuse_event_streams silently
    reload the 2RR pilot_containerlab topology via their own DEFAULT_PATH
    if no path is given, which would be wrong for any other dataset. This
    guard exists specifically so a 3RR (or any future) caller can never
    silently fall back to the 2RR topology.

    vmap_builder(folder_dir_path) -> {vantage_id: pcap_path, ...} lets each
    dataset supply its own pcap-filename/vantage-naming convention (e.g.
    pilot_containerlab's RR1/RR2 -> rr1.pcap/rr2.pcap vs 3rr's
    XRR1/XRR2/XRR3 -> xrr1.pcap/xrr2.pcap/xrr3.pcap).

    exclude: optional {(folder_type, folder_name): "reason string"} -- these
    folders are skipped but explicitly reported as excluded, never silently
    dropped.
    """
    if not topo_path:
        raise ValueError(
            "run_scorer() requires an explicit topo_path -- omitting it would let "
            "parse_vantages/fuse_event_streams silently reload the 2RR "
            "pilot_containerlab topology via their own DEFAULT_PATH, which is wrong "
            "for any other dataset. Pass the caller's own topology.json path explicitly."
        )
    exclude = exclude or {}

    results_summary = {}
    all_mismatches = []
    fp_count = 0
    fp_details = []
    excluded_report = []

    for folder_type, module_key in MODULE_FOR_FOLDER.items():
        base = os.path.join(pcaps_base, folder_type, "single")
        if not os.path.isdir(base):
            continue
        folders = sorted(os.listdir(base))
        tc = tcorrect = 0
        detected_expected = detected_correct = 0
        notdet_expected = notdet_correct = 0
        total_folders = len(folders)
        scored_count = 0
        skipped_no_meta = 0
        excluded_count = 0

        for folder in folders:
            if (folder_type, folder) in exclude:
                reason = exclude[(folder_type, folder)]
                excluded_count += 1
                excluded_report.append((folder_type, folder, reason))
                continue

            d = os.path.join(base, folder)
            meta_path = os.path.join(d, "metadata.json")
            if not os.path.exists(meta_path):
                print(f"SKIP (no metadata.json): {folder_type}/{folder}")
                skipped_no_meta += 1
                continue
            meta = json.load(open(meta_path))
            vmap = vmap_builder(d)
            streams = parse_vantages(vmap, topo_path)
            fused = fuse_event_streams(streams, topo_path)

            rdm = "masking" if "masking" in folder else "simple"

            raw = run_all_rules(fused, topo, rdm)
            prec = annotate_precedence(raw, topo, fused)

            primary = raw[module_key]
            fc, fok, mism, outcome, primary_idx, extra_detected = score_file(module_key, primary, meta, folder, folder_type)
            scored_count += 1
            tc += fc
            tcorrect += fok
            if outcome == "NOT_DETECTABLE":
                notdet_expected += 1
                notdet_correct += (fok == fc)
            else:
                detected_expected += 1
                detected_correct += (outcome == "SCORED" and fok == fc)
            for m in mism:
                all_mismatches.append((folder_type, folder, m))
            for idx, einc in extra_detected:
                all_mismatches.append((folder_type, folder, (
                    "extra_detected_incident", idx,
                    einc.get("root_cause_node") or einc.get("affected_node_pair") or einc.get("affected_nodes"),
                    einc.get("trigger_mechanism"),
                )))

            # false-positive check: every fault-type key from
            # MODULE_FOR_FOLDER is in scope, INCLUDING the module being
            # scored itself -- exclude_primary_index exempts only the one
            # entry already matched as the correct primary detection
            # (score_file's `inc`); any other DETECTED entry in this same
            # module's own list (a second, extra incident) or in any OTHER
            # module while scoring this file is only acceptable if the
            # precedence layer explicitly confirms it's legitimate (see
            # CROSS_MODULE_EXEMPT_STATUSES).
            for other_key in sorted(set(MODULE_FOR_FOLDER.values())):
                if _cross_module_undemoted(raw, prec, other_key, exclude_key=module_key, exclude_primary_index=primary_idx):
                    fp_count += 1
                    fp_details.append((folder_type, folder, other_key))

        results_summary[folder_type] = {
            "fields_checked": tc, "fields_correct": tcorrect,
            "field_accuracy_pct": round(100 * tcorrect / tc, 2) if tc else None,
            "detected_expected_files": detected_expected, "detected_correct_files": detected_correct,
            "notdetectable_expected_files": notdet_expected, "notdetectable_correct_files": notdet_correct,
            "total_folders": total_folders, "scored_folders": scored_count,
            "skipped_no_metadata": skipped_no_meta, "excluded_folders": excluded_count,
        }

    print("=== PER-FAULT-TYPE RESULTS ===")
    for k, v in results_summary.items():
        print(k, v)

    print()
    print("=== EXCLUDED (known pre-existing dataset issue, not scored either way) ===")
    if excluded_report:
        for folder_type, folder, reason in excluded_report:
            print(f"  {folder_type}/{folder}: {reason}")
    else:
        print("  (none)")

    print()
    print("=== FIELD MISMATCHES ===")
    for m in all_mismatches:
        print(m)

    print()
    print("=== CROSS-MODULE FALSE POSITIVES (not correctly demoted) ===")
    print("count:", fp_count)
    for f in fp_details:
        print(" ", f)

    normal_fp = 0
    normal_folders = []
    if normal_base:
        print()
        print("=== NORMAL BASELINE FALSE POSITIVE CHECK ===")
        # normal_base is the pcaps ROOT, not the scenario-folder directory
        # itself -- the real normal_* scenario folders live one level
        # deeper, inside a "Normal" (pilot_containerlab) or "normal" (3rr)
        # subdirectory. Case differs between the two datasets, so resolve
        # it case-insensitively rather than hardcoding either spelling.
        normal_dir = normal_base
        for entry in os.listdir(normal_base):
            if entry.lower() == "normal" and os.path.isdir(os.path.join(normal_base, entry)):
                normal_dir = os.path.join(normal_base, entry)
                break
        normal_folders = [f for f in os.listdir(normal_dir) if f.startswith("normal_")]
        for folder in sorted(normal_folders):
            d = os.path.join(normal_dir, folder)
            vmap = vmap_builder(d)
            if not all(os.path.exists(p) for p in vmap.values()):
                continue
            streams = parse_vantages(vmap, topo_path)
            fused = fuse_event_streams(streams, topo_path)
            raw = run_all_rules(fused, topo, "simple")
            prec = annotate_precedence(raw, topo, fused)
            any_undemoted = False
            # No fault was injected in normal-baseline traffic at all, so
            # every fault-type key is in scope with no exclusion -- any
            # DETECTED incident anywhere needs an explicit
            # CROSS_MODULE_EXEMPT_STATUSES precedence entry to not count
            # as a false positive (in practice none should ever apply to
            # genuinely fault-free traffic, but the check is uniform
            # rather than special-cased per module).
            for key in sorted(set(MODULE_FOR_FOLDER.values())):
                if _cross_module_undemoted(raw, prec, key, exclude_key=None):
                    any_undemoted = True
                    detected_idxs = list(range(len(raw.get(key, []))))
                    for idx in detected_idxs:
                        print(f"  FALSE POSITIVE: {folder} -> {key}[{idx}] root={raw[key][idx].get('root_cause_node')}")
            if any_undemoted:
                normal_fp += 1
        print("Normal files scanned:", len(normal_folders))
        print("Normal files with undemoted false positive:", normal_fp)

    return {
        "results_summary": results_summary,
        "excluded": excluded_report,
        "mismatches": all_mismatches,
        "fp_count": fp_count,
        "fp_details": fp_details,
        "normal_fp": normal_fp,
        "normal_scanned": len(normal_folders),
    }
