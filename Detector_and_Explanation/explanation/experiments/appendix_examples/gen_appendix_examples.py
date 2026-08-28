"""Generate final appendix-ready explanations for the 13-item thesis
appendix table. Reuses validated logic verbatim from this session's
already-confirmed scripts (regen_esdf_type4_fix.py for base-pipeline/DISC,
self_refine_loop.py for the real Self-Refine loop) -- not imported where
that would trigger a side-effect dispatch, imported where safe (checked
each module for an unguarded top-level dispatch before importing).

Categories:
  Group A (8 files, generate base + DISC): most of the single-example files.
  Group B (2 files, generate base + Self-Refine cap=10 + DISC): the RD
    Collision pair illustrating Self-Refine's caught-one-missed-one
    inconsistency vs DISC's correction.
  Reuse-only (3 files, no generation): esdf_toggle_full_failure_no_recovery_pe3pe4
    (existing MAD v2 text), rt_misconfig_import_only_pe2_fixed (existing
    "no incidents detected" text), esdf_toggle_single_pe1 (existing
    before/after DISC text from this session's retrieval-fix verification).

Usage:
    python gen_appendix_examples.py
"""
import sys, os, json, time, io
from concurrent.futures import ThreadPoolExecutor, as_completed

EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
sys.path.insert(0, EXPLAIN_DIR)
sys.path.insert(0, os.path.join(EXPLAIN_DIR, "experiments", "discriminability_check"))
sys.path.insert(0, os.path.join(EXPLAIN_DIR, "experiments", "self_refine"))

import pipeline
from pipeline import detect_incidents, build_context, _client, SEED, MODEL

# Reuse: safe to import, both have __main__ guards / no top-level dispatch.
import regen_esdf_type4_fix as rg  # base-pipeline (_UsageLoggingClient, run_layer1-style) + DISC (process_disc-style)
from self_refine_loop import run_self_refine, CRITIQUE_SYSTEM_PROMPT, MAX_CRITIQUE_ITERATIONS

OUT_DIR = os.path.join(EXPLAIN_DIR, "experiments", "appendix_examples", "output")
os.makedirs(OUT_DIR, exist_ok=True)

CACHE_PATH = os.path.join(EXPLAIN_DIR, "experiments", "results", "cached_detection_results.json")
cache = json.load(open(CACHE_PATH, encoding="utf-8"))
by_basename = {}
for key, entry in cache.items():
    by_basename[os.path.basename(entry["path"])] = (key, entry["path"])

CONDITION = "KG_RAG"
spec = pipeline.CONDITION_SPEC[CONDITION]
INPUT_PRICE = 1.25
OUTPUT_PRICE = 10.0
SELF_REFINE_MAX_ITER = 10

GROUP_A = [
    "link_down_holdtimer_xpe1_recovered",
    "rr_down_graceful_xrr1_recovered",
    "pe_cease_pe1_notrecovered",
    "rt_misconfig_autoderive_export_pe1_notfixed",
    "mac_mobility_cleanmove_pe3to4_settled",
    "catC_pecease_xpe2_rdcollision_xpe8xpe9",
    "rr_down_graceful_xrr3_recovered",
    "link_down_bfd_pe1_recovered",
]
GROUP_B = [
    "rd_collision_pe3_pe4_notfixed",
    "rd_collision_xpe3_xpe4_fixed",
]

# Precedence label/reason needed for files 6, 7, 8 (indices in GROUP_A: catC_pecease.., rr_down_graceful_xrr3.., link_down_bfd_pe1_recovered)
PRECEDENCE_NEEDED = {"catC_pecease_xpe2_rdcollision_xpe8xpe9", "rr_down_graceful_xrr3_recovered", "link_down_bfd_pe1_recovered"}


def get_precedence_summary(key):
    entry = cache.get(key)
    if not entry:
        return None
    prec = entry.get("precedence") or {}
    out = []
    for ft, entries in prec.items():
        for e in entries:
            if e.get("status") and e.get("status") != "GENUINE":
                out.append({"fault_type": ft, "status": e["status"], "reason": e.get("reason")})
            elif e.get("status") == "GENUINE" and "CONFIRMED_COOCCURRENCE" not in [x["status"] for x in out]:
                pass
    # also include GENUINE entries with a reason for completeness
    for ft, entries in prec.items():
        for e in entries:
            if e.get("status") == "GENUINE" and e.get("reason"):
                out.append({"fault_type": ft, "status": "GENUINE", "reason": e.get("reason")})
    return out


def gen_base(basename):
    key, folder_dir = by_basename[basename]
    out_path = os.path.join(OUT_DIR, f"{basename}__base.json")
    if os.path.exists(out_path):
        return json.load(open(out_path, encoding="utf-8"))
    wrapped = rg._UsageLoggingClient(_client())
    result = pipeline.run_one_condition(folder_dir, CONDITION, client=wrapped)
    call_log = [{"label": "kg_rag_explanation", "model": "gpt-5", "usage": u} for u in wrapped.usage_log]
    record = {"key": key, "folder_dir": folder_dir, "basename": basename, "call_log": call_log, **result}
    json.dump(record, open(out_path, "w", encoding="utf-8"), indent=1, default=str)
    return record


def gen_disc(basename):
    key, folder_dir = by_basename[basename]
    out_path = os.path.join(OUT_DIR, f"{basename}__disc.json")
    if os.path.exists(out_path):
        return json.load(open(out_path, encoding="utf-8"))
    rec = rg.process_disc(key, folder_dir)
    # process_disc already writes its own checkpoint under regen_esdf_type4_fix's DISC_DIR;
    # copy the result into this task's own output dir too, under this task's naming.
    json.dump(rec, open(out_path, "w", encoding="utf-8"), indent=1, default=str)
    return rec


def gen_self_refine(basename):
    key, folder_dir = by_basename[basename]
    out_path = os.path.join(OUT_DIR, f"{basename}__selfrefine.json")
    if os.path.exists(out_path):
        return json.load(open(out_path, encoding="utf-8"))

    client = _client()
    t_start = time.time()
    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )
    t0 = time.time()
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": context}],
        seed=SEED,
    )
    gen_elapsed = time.time() - t0
    initial_text = response.choices[0].message.content
    gen_usage = response.usage.model_dump() if response.usage else None
    if spec["next_step"] == "free" and all_recovered:
        initial_text = pipeline._splice_self_resolved_next_steps(initial_text, described_incidents)

    critique_call_log = []

    def critique_fn(user_prompt, iteration):
        t0c = time.time()
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "system", "content": CRITIQUE_SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}],
            seed=SEED,
        )
        elapsed = time.time() - t0c
        text = resp.choices[0].message.content
        usage = resp.usage.model_dump() if resp.usage else None
        critique_call_log.append({"iteration": iteration, "elapsed": elapsed, "usage": usage})
        return text

    out = run_self_refine(initial_text, context, critique_fn, max_iterations=SELF_REFINE_MAX_ITER)
    t_elapsed = time.time() - t_start

    record = {
        "key": key, "folder_dir": folder_dir, "basename": basename,
        "all_recovered": all_recovered, "initial_explanation": initial_text,
        "final_explanation": out["final_explanation"],
        "n_critique_calls": out["n_critique_calls"], "stop_reason": out["stop_reason"],
        "verdict_sequence": [it["verdict"] for it in out["iterations"]],
        "iterations": out["iterations"],
        "generate_usage": gen_usage, "critique_call_log": critique_call_log,
        "total_elapsed_seconds": t_elapsed,
    }
    json.dump(record, open(out_path, "w", encoding="utf-8"), indent=1, default=str)
    return record


def compute_cost_generic(records):
    total_cost = total_prompt = total_completion = 0.0
    for r in records:
        usages = []
        if r.get("generate_usage"):
            usages.append(r["generate_usage"])
        for c in r.get("call_log", []):
            if c.get("usage"):
                usages.append(c["usage"])
        for c in r.get("critique_call_log", []):
            if c.get("usage"):
                usages.append(c["usage"])
        for u in usages:
            pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
            total_prompt += pt
            total_completion += ct
            total_cost += pt * INPUT_PRICE / 1e6 + ct * OUTPUT_PRICE / 1e6
    return total_cost, total_prompt, total_completion


if __name__ == "__main__":
    # NOTE: regen_esdf_type4_fix (imported as rg above) already wraps
    # sys.stdout at its own import time -- wrapping it again here closed
    # the underlying buffer and crashed on the very first print (confirmed
    # via a real failed run). Do not re-wrap.
    all_records = []
    failures = []

    print("=" * 70)
    print("GROUP A: base + DISC (8 files)")
    print("=" * 70)
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(gen_base, b): b for b in GROUP_A}
        for fut in as_completed(futs):
            b = futs[fut]
            try:
                rec = fut.result()
                all_records.append(rec)
                print(f"  [base done] {b}")
            except Exception as e:
                print(f"  [BASE FAILED] {b}: {type(e).__name__}: {e}")
                failures.append((b, "base", str(e)))

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(gen_disc, b): b for b in GROUP_A}
        for fut in as_completed(futs):
            b = futs[fut]
            try:
                rec = fut.result()
                all_records.append(rec)
                print(f"  [disc done] {b}: stop_reason={rec.get('stop_reason')} n_cycles={rec.get('n_cycles')}")
            except Exception as e:
                print(f"  [DISC FAILED] {b}: {type(e).__name__}: {e}")
                failures.append((b, "disc", str(e)))

    print("\n" + "=" * 70)
    print("GROUP B: base + Self-Refine(cap=10) + DISC (2 files)")
    print("=" * 70)
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(gen_self_refine, b): b for b in GROUP_B}
        for fut in as_completed(futs):
            b = futs[fut]
            try:
                rec = fut.result()
                all_records.append(rec)
                print(f"  [self-refine done] {b}: stop_reason={rec.get('stop_reason')} verdicts={rec.get('verdict_sequence')}")
            except Exception as e:
                print(f"  [SELF-REFINE FAILED] {b}: {type(e).__name__}: {e}")
                failures.append((b, "self_refine", str(e)))

    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(gen_disc, b): b for b in GROUP_B}
        for fut in as_completed(futs):
            b = futs[fut]
            try:
                rec = fut.result()
                all_records.append(rec)
                print(f"  [disc done] {b}: stop_reason={rec.get('stop_reason')} n_cycles={rec.get('n_cycles')}")
            except Exception as e:
                print(f"  [DISC FAILED] {b}: {type(e).__name__}: {e}")
                failures.append((b, "disc", str(e)))

    total_cost, total_prompt, total_completion = compute_cost_generic(all_records)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Records produced: {len(all_records)}")
    print(f"Failures: {len(failures)}")
    for b, stage, err in failures:
        print(f"  [{stage}] {b}: {err}")
    print(f"Total tokens: prompt={total_prompt} completion={total_completion}")
    print(f"TOTAL REAL COST: ${total_cost:.4f}")
