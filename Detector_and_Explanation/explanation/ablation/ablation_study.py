"""Full 35-file x 6-condition ablation runner. Reuses file_list_35.py's
exact file list (the finalized stratified ablation sample -- not rebuilt).

Before making any LLM call, computes and prints a REAL estimated call
count (not a guess) by running detection-only (no API calls) across all
35 files first, counting files with at least one incident, then applying
CONDITION_SPEC's real flags: rule_based_only is free (0 calls), every
other condition is 1 call per file regardless of incident count (there
is no per-incident mode anymore).

No confirmation prompt is built into this script (per task instruction)
-- the estimate is printed clearly before any spend happens, and running
this script IS the spend decision.

Every file/condition's full result is saved to disk under a timestamped
results\ subfolder (results\run_<YYYYMMDD_HHMMSS>\<condition>\<file_stem>.json)
-- never overwrites a prior run. A single failure (rate limit, API error,
encoding issue, anything) is caught, logged with file/condition identity,
and does NOT stop the run -- every remaining file/condition still gets
attempted, and every failure is reported together at the end.
"""
import sys
import os
import io
import json
import time
import traceback
from datetime import datetime

# Same Windows console encoding fix as run_single.py (see its comment) --
# a real single-file test crashed on this mid-run, after billed API calls
# had already succeeded.
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from pipeline import CONDITIONS, CONDITION_SPEC, run_one_condition, detect_incidents, _client
from file_list_35 import FILE_LIST_35

RESULTS_ROOT = os.path.join(os.path.dirname(__file__), "..", "results")


def estimate_call_count():
    """Returns (per_file_incident_counts, total_calls, breakdown_by_condition)."""
    counts = {}
    for folder_dir in FILE_LIST_35:
        try:
            _, _, _, incidents, _ = detect_incidents(folder_dir)
            counts[folder_dir] = len(incidents)
        except Exception as e:
            counts[folder_dir] = 0
            print(f"  !!! detection failed for {folder_dir}: {e}", file=sys.stderr)

    n_files_with_incidents = sum(1 for v in counts.values() if v > 0)
    total_incidents = sum(counts.values())

    breakdown = {}
    total = 0
    for condition in CONDITIONS:
        if condition == "rule_based_only":
            breakdown[condition] = 0
        else:
            breakdown[condition] = n_files_with_incidents
        total += breakdown[condition]

    return counts, total, breakdown


def _corpus_segment(folder_dir):
    """Disambiguates the save path by corpus source (2026-08-08 fix): file
    STEMS are not unique across corpora -- confirmed 3 real collisions in
    the prior run (esdf_toggle_full_failure_no_recovery/_recovery/_slow
    all exist verbatim under both synthcap/output and synthcap/output_3rr),
    silently overwriting each other's saved JSON despite both files'
    LLM calls having genuinely been made and billed. Mirrors
    pipeline.py's own _resolve_topology_and_vmap dataset-detection logic
    (same path-substring checks, same precedence order: 3rr before
    output_3rr, since "3rr" alone is a substring collision risk against
    "output_3rr" otherwise) rather than reimplementing it differently."""
    norm = os.path.normpath(folder_dir).lower()
    parts = norm.split(os.sep)
    if "3rr" in parts and "output_3rr" not in norm:
        return "3rr"
    if "output_3rr" in norm:
        return "synthcap_output_3rr"
    if "synthcap" in norm and "output" in parts:
        return "synthcap_output"
    if "pilot_containerlab" in parts:
        return "pilot_containerlab"
    return "unknown_corpus"


def _incident_summary(incidents):
    return [
        {
            "fault_type": i.get("fault_type"),
            "trigger_mechanism": i.get("trigger_mechanism"),
            "root_cause_node": i.get("root_cause_node"),
            "affected_node_pair": i.get("affected_node_pair"),
            "affected_node_group": i.get("affected_node_group"),
            "recovery_status": i.get("recovery_status"),
            "time_of_first_fault": i.get("time_of_first_fault"),
            # mac_mobility.py renamed recovered_time to move_completed_time
            # (2026-08-16) -- fall back to it so this summary doesn't lose
            # the completion timestamp for MAC Mobility incidents.
            "recovered_time": i.get("recovered_time", i.get("move_completed_time")),
        }
        for i in incidents
    ]


def _record_for_result(folder_dir, condition, incidents_summary, result, n_calls_made, elapsed, error=None):
    rec = {
        "file": folder_dir,
        "condition": condition,
        "spec": CONDITION_SPEC.get(condition),
        "incident_data": incidents_summary,
        "llm_called": result.get("llm_called", False) if result else False,
        "n_calls": n_calls_made,
        "elapsed_seconds": elapsed,
        "error": error,
    }
    if error is not None:
        return rec

    # 2026-08-18: "tag" is only written into `rec` when a real tag exists
    # -- never as tag: None. rule_based_only is structurally tag-less by
    # design (never runs in "free" next-step mode). result["tag"] is read
    # via .get("tag") since pipeline.py's own result dicts may legitimately
    # omit the key (all-recovered jobs, or a persistent parse failure
    # after retry).
    if condition == "rule_based_only":
        rec["explanation"] = result["explanation"]
        rec["citations"] = []
        rec["groundedness"] = None
        return rec

    rec["explanation"] = result["explanation"]
    rec["citations"] = result["citations"]
    if result.get("tag") is not None:
        rec["tag"] = result["tag"]
    rec["causal_text"] = result.get("causal_text")
    rec["groundedness"] = result["groundedness"]
    rec["n_incidents"] = result.get("n_incidents")
    return rec


def main():
    print(f"Computing real call estimate across {len(FILE_LIST_35)} files (detection-only, no API calls)...")
    counts, total, breakdown = estimate_call_count()
    print()
    print("=" * 70)
    print("ESTIMATED LLM CALL COUNT (before any spend)")
    print("=" * 70)
    for condition in CONDITIONS:
        print(f"  {condition:35s}  {breakdown[condition]:4d} calls")
    print("-" * 70)
    print(f"  {'TOTAL':35s}  {total:4d} calls")
    print("=" * 70)
    print()

    run_id = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    run_dir = os.path.join(RESULTS_ROOT, run_id)
    os.makedirs(run_dir, exist_ok=True)
    print(f"Results will be saved under: {run_dir}\n")

    client = _client()
    actual_calls = 0
    failures = []
    run_start = time.time()

    for file_idx, folder_dir in enumerate(FILE_LIST_35, 1):
        file_stem = os.path.basename(folder_dir)
        corpus_segment = _corpus_segment(folder_dir)
        try:
            _, _, _, incidents, _ = detect_incidents(folder_dir)
            incidents_summary = _incident_summary(incidents)
        except Exception as e:
            incidents_summary = []
            print(f"[{file_idx}/{len(FILE_LIST_35)}] {file_stem}: DETECTION FAILED: {e}")

        for condition in CONDITIONS:
            cond_dir = os.path.join(run_dir, condition)
            os.makedirs(cond_dir, exist_ok=True)
            out_path = os.path.join(cond_dir, f"{corpus_segment}__{file_stem}.json")

            t0 = time.time()
            try:
                result = run_one_condition(folder_dir, condition, client=client)
                elapsed = time.time() - t0
                n_calls_made = result.get("n_calls", 0) if result.get("llm_called") else 0
                actual_calls += n_calls_made
                rec = _record_for_result(folder_dir, condition, incidents_summary, result, n_calls_made, elapsed)
                status = "OK"
            except Exception as e:
                elapsed = time.time() - t0
                err_str = f"{type(e).__name__}: {e}"
                tb = traceback.format_exc()
                failures.append({"file": file_stem, "condition": condition, "error": err_str, "traceback": tb})
                rec = _record_for_result(folder_dir, condition, incidents_summary, None, 0, elapsed, error=err_str)
                status = "FAILED"

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=1, default=str)

            print(f"[{file_idx}/{len(FILE_LIST_35)}] {file_stem} [{condition}]: {status}"
                  + (f"  n_calls={rec.get('n_calls', 0)}" if status == "OK" else f"  {rec.get('error')}"))

    run_elapsed = time.time() - run_start
    _print_summary(run_dir, total, actual_calls, failures, run_elapsed)


def _print_summary(run_dir, estimated_calls, actual_calls, failures, run_elapsed):
    print("\n" + "=" * 70)
    print("RUN COMPLETE")
    print("=" * 70)
    print(f"Results directory: {run_dir}")
    print(f"Wall-clock time: {run_elapsed:.1f}s ({run_elapsed / 60:.1f} min)")
    print(f"Estimated calls: {estimated_calls}   Actual calls made: {actual_calls}"
          + (f"   (diff: {actual_calls - estimated_calls:+d})" if actual_calls != estimated_calls else "   (exact match)"))

    print(f"\nFailures: {len(failures)}")
    for f in failures:
        print(f"  [{f['file']}] [{f['condition']}]: {f['error']}")

    print("\n" + "=" * 70)
    print("GROUNDEDNESS BREAKDOWN BY CONDITION (per-category, not averaged across conditions)")
    print("=" * 70)
    for condition in CONDITIONS:
        cond_dir = os.path.join(run_dir, condition)
        if not os.path.isdir(cond_dir):
            continue
        records = []
        for fn in sorted(os.listdir(cond_dir)):
            with open(os.path.join(cond_dir, fn), encoding="utf-8") as fh:
                records.append(json.load(fh))

        print(f"\n--- {condition} ---")
        if condition == "rule_based_only":
            print(f"  {len(records)} files, no LLM call / no groundedness check applicable.")
            continue

        all_grounded = []
        for r in records:
            if r.get("error"):
                continue
            if r.get("groundedness"):
                all_grounded.append(r["groundedness"])

        n = len(all_grounded)
        n_errors = sum(1 for r in records if r.get("error"))
        print(f"  {n} generations evaluated ({n_errors} failed, excluded from groundedness stats)")

        # 2026-08-18: persistent tag-parse failures (tag missing after
        # pipeline.py's own retry, on a NOT_RECOVERED "free"-mode
        # incident specifically) reported separately from n_errors --
        # these are NOT API/pipeline errors (rec["error"] is None,
        # llm_called is True, the explanation generated fine), and they
        # no longer show up as a visible "tag: None" in individual
        # records now that the key is omitted instead, so without this
        # count they'd be invisible in the summary. Distinguished from
        # an all-recovered job's correct, by-design lack of a tag by
        # checking incident_data's own recovery_status -- a record with
        # no "tag" key whose incidents are NOT all RECOVERED is a real
        # persistent failure, not a recovered job working as intended.
        if CONDITION_SPEC[condition]["next_step"] == "free":
            n_persistent_tag_failures = 0
            for r in records:
                if r.get("error"):
                    continue
                if "tag" in r:
                    continue
                incidents_here = r.get("incident_data") or []
                all_recovered_here = bool(incidents_here) and all(
                    i.get("recovery_status") == "RECOVERED" for i in incidents_here
                )
                if not all_recovered_here:
                    n_persistent_tag_failures += 1
            print(f"  {n_persistent_tag_failures} persistent tag-parse failures (missing after retry, excludes all-recovered jobs)")

        if n == 0:
            continue

        cat_pass = {"1_fault_type": 0, "2_affected_nodes": 0, "3_trigger_mechanism": 0, "4_root_cause_self_consistent": 0}
        cat_applicable = {k: 0 for k in cat_pass}
        n_fabrications = 0
        n_rfc_checked = 0
        rfc_overlaps = []
        n_fully_clean = 0

        for g in all_grounded:
            per_inc_all_ok = True
            for inc in g.get("per_incident", []):
                for key, field in [
                    ("1_fault_type", "fault_type_ok"), ("2_affected_nodes", "affected_nodes_ok"),
                    ("3_trigger_mechanism", "trigger_mechanism_ok"), ("4_root_cause_self_consistent", "root_cause_self_consistent"),
                ]:
                    v = inc.get(field)
                    if v is not None:
                        cat_applicable[key] += 1
                        if v:
                            cat_pass[key] += 1
                        else:
                            per_inc_all_ok = False
            has_fab = bool(g.get("fabrications"))
            if has_fab:
                n_fabrications += 1
            if g.get("rfc_grounding_checked"):
                n_rfc_checked += 1
                rfc_overlaps.append(g["rfc_grounding_overlap"])
            if per_inc_all_ok and not has_fab:
                n_fully_clean += 1

        for key, label in [
            ("1_fault_type", "1.fault_type"), ("2_affected_nodes", "2.affected_nodes"),
            ("3_trigger_mechanism", "3.trigger_mechanism"), ("4_root_cause_self_consistent", "4.root_cause_self_consistent"),
        ]:
            if cat_applicable[key]:
                pct = 100 * cat_pass[key] / cat_applicable[key]
                print(f"  {label}: {cat_pass[key]}/{cat_applicable[key]} = {pct:.0f}%")
            else:
                print(f"  {label}: n/a (no applicable incidents)")
        print(f"  5.fabrications: {n_fabrications}/{n} generations had >=1 fabricated claim")
        if n_rfc_checked:
            avg_overlap = sum(rfc_overlaps) / len(rfc_overlaps)
            print(f"  6.rfc_grounding_content: {n_rfc_checked}/{n} checked, avg word-overlap={avg_overlap:.1f}")
        else:
            print(f"  6.rfc_grounding_content: 0/{n} checked (no RFC-mentioning sentences or no grounding retrieved)")
        print(f"  FULLY CLEAN (all applicable categories pass, zero fabrications): {n_fully_clean}/{n} = {100 * n_fully_clean / n:.0f}%")


if __name__ == "__main__":
    main()
