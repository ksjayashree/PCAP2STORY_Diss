import sys, os, json, time, io
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
SCRATCH = r"C:\Users\KSJAYA~1\AppData\Local\Temp\claude\C--simulation-pcap\2728fa27-f217-4791-81ce-27424551174a\scratchpad"
sys.path.insert(0, r"C:\simulation pcap\rule_based detector\explanation")
sys.path.insert(0, SCRATCH)

import pipeline
from pipeline import detect_incidents, build_context, _client, SEED
from part2_files import FILES_20  # the exact, already-established 20-file list

CONDITION = "KG_RAG"
spec = pipeline.CONDITION_SPEC[CONDITION]

MODEL_A = "gpt-5"
MODEL_B = "gpt-5.6"
RECONCILE_MODEL = "gpt-5.6"

INPUT_PRICE = 1.25
CACHED_INPUT_PRICE = 0.125
OUTPUT_PRICE = 10.0
# gpt-5.6 pricing not independently billing-verified this session; using the
# same $1.25/$10 per 1M schedule as gpt-5 for both models' cost accounting,
# consistent with this session's established convention of not inventing
# unverified per-model rates. Flagged explicitly in the final cost report.

OUT_DIR = os.path.join(SCRATCH, "cross_model_debate_results")
os.makedirs(OUT_DIR, exist_ok=True)

CRITIQUE_SYSTEM_PROMPT = (
    "You are a network-protocol fact-checker reviewing an EVPN/BGP fault "
    "explanation written by another engineer. You will be given the same "
    "DETECTOR FACTS, TOPOLOGY, and RFC GROUNDING excerpts that were used to "
    "write it, plus the explanation itself. Check the explanation against "
    "ONLY that material -- do not use outside knowledge of EVPN/BGP beyond "
    "what is stated in the RFC excerpts given.\n\n"
    "The explanation is expected to combine the RFC rule with incident-"
    "specific facts (node names, timestamps, RD/RT values) drawn from the "
    "DETECTOR FACTS and TOPOLOGY given. Do not flag this combination itself "
    "as unsupported -- only flag it if the specific fact used does not "
    "actually appear anywhere in the facts or topology provided.\n\n"
    "Identify anything in the explanation that is:\n"
    "- UNSUPPORTED: a claim (node name, timestamp, RD/RT value, ESI, "
    "mechanism) not present anywhere in the facts or topology given.\n"
    "- FACTUALLY WRONG: a claim that contradicts the facts or topology given.\n"
    "- RFC-INACCURATE: a citation whose normative force, section scope, or "
    "rule content is overstated, understated, or misstated relative to the "
    "RFC excerpt text actually provided -- including claiming a rule "
    "applies more broadly (e.g. across PEs, VRFs, or sessions) than the "
    "excerpt itself establishes.\n"
    "- OVERSTATED CERTAINTY: a claim stated as definite when the facts given "
    "only support a qualified or uncertain conclusion.\n\n"
    "Do not flag stylistic choices, phrasing, or omissions that are simply "
    "less detailed than you would have written -- only flag things that are "
    "actually unsupported, wrong, or misstated against the material given.\n\n"
    "Respond in exactly this format, one entry per issue found (or the "
    "single line \"NO ISSUES FOUND\" if there are none):\n"
    "ISSUE: <one-sentence description of the specific problem>\n"
    "EVIDENCE: <the exact fact, topology line, or RFC excerpt text that "
    "contradicts or fails to support the claim>"
)

RECONCILE_SUFFIX = (
    "\n\nYou are producing a FINAL explanation by reconciling two independent "
    "drafts of the same incident, each of which was cross-checked by a "
    "separate reviewer. Keep any claim neither critique challenged. Where a "
    "critique correctly identifies something unsupported, factually wrong, "
    "or RFC-inaccurate, fix it using only the facts, topology, and RFC "
    "excerpts given below -- never using either draft's own unsupported "
    "wording. Where the two critiques disagree with each other about the "
    "same claim, resolve it yourself against the facts/RFC excerpts given, "
    "not by preferring one draft's phrasing over the other's. Your final "
    "answer must still follow the exact section structure above -- do not "
    "mention the drafts, the critiques, or the reconciliation process itself "
    "anywhere in your response."
)


def make_client():
    return _client()


def call_model(client, model, system_prompt, user_prompt, label, key, call_log):
    t0 = time.time()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        seed=SEED,
    )
    elapsed = time.time() - t0
    text = response.choices[0].message.content
    usage = response.usage.model_dump() if response.usage else None
    call_log.append({"step": label, "model": model, "elapsed": elapsed, "usage": usage})
    return text


def process_file(key, folder_dir):
    client = make_client()
    call_log = []
    t_start = time.time()

    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )
    # BASE_SYSTEM_PROMPT vs BASE_SYSTEM_PROMPT_NO_NEXT_STEPS + FREE_NEXT_STEP_SUFFIX
    # selection already happened inside build_context(); `system_prompt` here
    # is exactly what production/Part 1-3 used for generation, unmodified.

    # --- PROMPT 1: independent draft generation, gpt-5 and gpt-5.6 ---
    draft_a = call_model(client, MODEL_A, system_prompt, context, "draft_a_gpt5", key, call_log)
    draft_b = call_model(client, MODEL_B, system_prompt, context, "draft_b_gpt56", key, call_log)

    if spec["next_step"] == "free" and all_recovered:
        draft_a = pipeline._splice_self_resolved_next_steps(draft_a, described_incidents)
        draft_b = pipeline._splice_self_resolved_next_steps(draft_b, described_incidents)

    # --- PROMPT 2: cross-critique ---
    critique_a_of_b_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{draft_b}"
    critique_b_of_a_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{draft_a}"
    critique_of_b = call_model(client, MODEL_A, CRITIQUE_SYSTEM_PROMPT, critique_a_of_b_user, "critique_gpt5_of_draftB", key, call_log)
    critique_of_a = call_model(client, MODEL_B, CRITIQUE_SYSTEM_PROMPT, critique_b_of_a_user, "critique_gpt56_of_draftA", key, call_log)

    # --- PROMPT 3: reconciliation ---
    if all_recovered:
        reconcile_system_prompt = pipeline.BASE_SYSTEM_PROMPT_NO_NEXT_STEPS + RECONCILE_SUFFIX
    else:
        reconcile_system_prompt = system_prompt + RECONCILE_SUFFIX
    reconcile_user = (
        f"{context}\n\n"
        f"DRAFT A:\n{draft_a}\n\n"
        f"CRITIQUE OF DRAFT A:\n{critique_of_a}\n\n"
        f"DRAFT B:\n{draft_b}\n\n"
        f"CRITIQUE OF DRAFT B:\n{critique_of_b}"
    )
    final_explanation = call_model(client, RECONCILE_MODEL, reconcile_system_prompt, reconcile_user, "reconcile_gpt56", key, call_log)
    if spec["next_step"] == "free" and all_recovered:
        final_explanation = pipeline._splice_self_resolved_next_steps(final_explanation, described_incidents)

    t_elapsed = time.time() - t_start

    record = {
        "file": key,
        "folder_dir": folder_dir,
        "all_recovered": all_recovered,
        "n_incidents": len(described_incidents),
        "draft_a_gpt5": draft_a,
        "draft_b_gpt56": draft_b,
        "critique_gpt5_of_draftB": critique_of_b,
        "critique_gpt56_of_draftA": critique_of_a,
        "final_reconciled_gpt56": final_explanation,
        "n_calls": 5,
        "call_log": call_log,
        "total_elapsed_seconds": t_elapsed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    out_path = os.path.join(OUT_DIR, f"{key}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, default=str)

    return record


print(f"Dispatching {len(FILES_20)} files, max_workers=8, 5 real calls per file (100 total)")
run_start = time.time()
records = []
with ThreadPoolExecutor(max_workers=8) as ex_pool:
    futures = {ex_pool.submit(process_file, key, folder_dir): key for key, folder_dir in FILES_20.items()}
    for fut in as_completed(futures):
        key = futures[fut]
        try:
            rec = fut.result()
            records.append(rec)
            print(f"[{len(records)}/{len(FILES_20)}] {key}: OK ({rec['total_elapsed_seconds']:.1f}s)")
        except Exception as e:
            print(f"[FAILED] {key}: {type(e).__name__}: {e}")
            records.append({"file": key, "status": "FAILED", "error": f"{type(e).__name__}: {e}"})

run_elapsed = time.time() - run_start

total_cost = 0.0
total_prompt = total_completion = 0
for r in records:
    for c in r.get("call_log", []):
        if c.get("usage"):
            u = c["usage"]
            total_prompt += u.get("prompt_tokens", 0)
            total_completion += u.get("completion_tokens", 0)
            total_cost += u.get("prompt_tokens", 0) * INPUT_PRICE / 1e6
            total_cost += u.get("completion_tokens", 0) * OUTPUT_PRICE / 1e6

summary_path = os.path.join(SCRATCH, "cross_model_debate_summary.json")
with open(summary_path, "w", encoding="utf-8") as f:
    json.dump({
        "total_wall_clock_seconds": run_elapsed,
        "n_files": len(FILES_20),
        "n_ok": sum(1 for r in records if "final_reconciled_gpt56" in r),
        "n_failed": sum(1 for r in records if r.get("status") == "FAILED"),
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_cost_usd": total_cost,
        "records": records,
    }, f, indent=1, default=str)

print(f"\nTOTAL WALL CLOCK: {run_elapsed:.1f}s ({run_elapsed/60:.1f} min)")
print(f"Total tokens: prompt={total_prompt} completion={total_completion}")
print(f"Total real cost: ${total_cost:.4f}")
print(f"Summary saved: {summary_path}")
print(f"Per-file records under: {OUT_DIR}")
