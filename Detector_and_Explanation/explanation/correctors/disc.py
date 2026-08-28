"""Full-corpus DISC (Denoising Iterative Self-Correction) run: verify-question
generation, independent evidence-answering, judge, and corrector loop --
across all 315 distinct real-corpus files (317 minus the 2 confirmed-
defective files, esdf_toggle_link_pe1_notrecovered and
mac_mobility_cleanmove_xpe6to7_settled, per the detect_incidents() root-cause
investigation).

Reuses disc_pipeline.py's exact prompts/logic (PROMPT_A/B/C/D, parse_questions/
parse_answer/parse_judge/strip_spliced_next_steps, MAX_CYCLES=10) verbatim --
not imported (disc_pipeline.py has no __main__ guard and would trigger its own
20-file dispatch), reproduced inline below, same precaution as
mad_full_corpus.py.

Two additions over disc_pipeline.py:
1. Checkpointing/resume, matching mad_full_corpus.py's validated pattern:
   one per-file JSON written immediately to output/per_file/<key>.json
   (skip-if-exists = resume), plus an aggregate rewrite every 20 completions
   and once at the end.
2. Draft generation fallback: disc_pipeline.py's FILES_20 all had a
   pre-existing gpt-5 "draft_a_gpt5" cached under
   scratchpad/cross_model_debate_results/<basename>.json (from an earlier,
   separate experiment) -- only those exact 20 files have this. Every other
   file in the full corpus has no cached draft, so this script generates one
   with the same call (gpt-5, system_prompt, context) MAD's r1_draft_a_gpt5
   step already uses, when no cached draft is found. Each per-file record
   notes "draft_source": "cached" or "generated" so this is auditable, not
   silent. This adds one extra real LLM call per non-cached file, which was
   NOT included in the earlier $61 cost estimate (that estimate assumed the
   already-cached draft, matching the 20-file pilot's cost profile) --
   expect a modest per-file cost increase for the ~295 uncached files.

File list: built directly from cached_detection_results.json (same 445-
folder cache mad_full_corpus.py used), same DETECTED + non-null
trigger_mechanism filter, keyed by full cache path (not folder basename --
confirmed 3 basename collisions exist across corpora: esdf_toggle_full_
failure_no_recovery, esdf_toggle_full_failure_recovery, esdf_toggle_slow),
excluding the 2 defective files by cache key.

Usage:
    python disc_full_corpus.py
"""
import sys, os, json, time, re, io
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
SCRATCH = r"C:\Users\KSJAYA~1\AppData\Local\Temp\claude\C--simulation-pcap\2728fa27-f217-4791-81ce-27424551174a\scratchpad"
sys.path.insert(0, EXPLAIN_DIR)

import pipeline
from pipeline import detect_incidents, build_context, _client, SEED

CONDITION = "KG_RAG"
spec = pipeline.CONDITION_SPEC[CONDITION]

MODEL_VERIFIER_JUDGE = "gpt-5.6"
MODEL_GEN_CORRECTOR = "gpt-5"
MODEL_DRAFT = "gpt-5"
MAX_CYCLES = 10
MAX_WORKERS = 8

INPUT_PRICE = 1.25
OUTPUT_PRICE = 10.0

DRAFTS_DIR = os.path.join(SCRATCH, "cross_model_debate_results")  # only has the original 20
DC_DIR = os.path.join(EXPLAIN_DIR, "experiments", "disc")
OUT_DIR = os.path.join(DC_DIR, "output_full_corpus")
PER_FILE_DIR = os.path.join(OUT_DIR, "per_file")
os.makedirs(PER_FILE_DIR, exist_ok=True)
FINAL_OUT_PATH = os.path.join(OUT_DIR, "disc_corrected_corpus.json")
CACHE_PATH = os.path.join(EXPLAIN_DIR, "experiments", "results", "cached_detection_results.json")

EXCLUDE_KEYS = {
    "sim_pilot_fault/esdf_toggle/single/esdf_toggle_link_pe1_notrecovered",
    "sim_3rr_fault/mac_mobility/single/mac_mobility_cleanmove_xpe6to7_settled",
}

# ---------------------------------------------------------------------
# Build the full file list (same filter as mad_full_corpus.py).
# ---------------------------------------------------------------------
cache = json.load(open(CACHE_PATH, encoding="utf-8"))
file_path = {}
for key, entry in cache.items():
    if key in EXCLUDE_KEYS:
        continue
    raw = entry.get("raw") or {}
    has_real = any(
        inc.get("detectability_status") == "DETECTED" and inc.get("trigger_mechanism")
        for entries in raw.values() for inc in entries
    )
    if has_real:
        file_path[key] = entry["path"]

FILES = sorted(file_path.keys())
print(f"Loaded {len(FILES)} distinct files from cached_detection_results.json (2 defective files excluded)")

# Basename -> cached-draft-record lookup, ONLY for the original 20-file
# pilot set (confirmed collision-free within that set). Never used for
# any other file, even if a basename happens to match, to avoid the 3
# known cross-corpus basename collisions silently reusing the wrong draft.
CACHED_DRAFT_KEYS = set()
if os.path.isdir(DRAFTS_DIR):
    for fn in os.listdir(DRAFTS_DIR):
        if fn.endswith(".json"):
            CACHED_DRAFT_KEYS.add(fn[:-5])

# ---------------------------------------------------------------------
# Prompts -- verbatim from disc_pipeline.py.
# ---------------------------------------------------------------------
PROMPT_A_SYSTEM = (
    "You are a verification-question generator auditing an EVPN/BGP fault "
    "explanation before it is finalized. You will be given the full context "
    "(TOPOLOGY, DETECTOR FACTS, RFC GROUNDING excerpts) and the DRAFT "
    "explanation written from that context.\n\n"
    "Generate 3 to 5 targeted yes/no or short-answer questions whose answers "
    "would reveal an error in the draft, if one exists. Do not generate "
    "generic or stylistic questions. Each question must be independently "
    "answerable from the given context alone, without reference to the "
    "draft's own wording -- phrase each question as a neutral, standalone "
    "question about the facts/topology/RFC text, not as \"does the draft "
    "correctly say X.\"\n\n"
    "Cover, wherever the draft gives you material to check:\n"
    "- For each RFC citation the draft uses: does that RFC section, as "
    "excerpted, actually establish the rule, scope, and normative force "
    "(MUST/SHOULD/MAY/RECOMMENDED) the draft attributes to it?\n"
    "- For each specific fact the draft states (node name, timestamp, "
    "RD/RT value, ESI, trigger mechanism): does that fact appear, in that "
    "form, in the DETECTOR FACTS or TOPOLOGY given?\n"
    "- Does the draft's stated certainty (CERTAIN/UNCERTAIN, or an "
    "unqualified claim) match what the given evidence actually supports, "
    "or does the evidence only support a weaker conclusion?\n\n"
    "Respond with ONLY a numbered list of questions, no preamble, no "
    "commentary, no reference to \"the draft\" in the question text itself."
)

PROMPT_B_SYSTEM = (
    "You are answering a single factual question using ONLY the material "
    "given below -- DETECTOR FACTS, TOPOLOGY, and RFC GROUNDING excerpts. Do "
    "not use outside knowledge of EVPN/BGP beyond what these excerpts state. "
    "Do not consult or assume anything about any draft explanation; you have "
    "not been shown one.\n\n"
    "Answer the question directly and specifically, quoting or closely "
    "paraphrasing the exact supporting text from what's given. If the given "
    "material does not address the question at all, say so explicitly rather "
    "than guessing.\n\n"
    "Respond in exactly this format:\n"
    "ANSWER: <your direct answer>\n"
    "SUPPORT: <the exact fact, topology line, or RFC excerpt text this "
    "answer is based on, or \"not addressed in the given material\" if none>"
)

PROMPT_C_SYSTEM = (
    "You are judging whether an EVPN/BGP fault explanation (the DRAFT) "
    "contains a mistake, based on a set of independently-answered "
    "verification questions about the same underlying facts/topology/RFC "
    "excerpts the draft was written from.\n\n"
    "Compare the DRAFT against each verification Q&A pair. Answer Mistake "
    "only if you can point to a SPECIFIC, NAMED contradiction: a claim in "
    "the DRAFT that is directly contradicted, or shown unsupported, by a "
    "specific answer. Quote the exact conflicting text from both the DRAFT "
    "and the Q&A pair.\n\n"
    "Do not answer Mistake for: vague unease, a claim that is merely less "
    "detailed than the Q&A answer, a stylistic or phrasing difference, or an "
    "answer that is simply silent on something the draft states (silence is "
    "not a contradiction unless the question directly asked about that claim "
    "and the answer said it wasn't addressed).\n\n"
    "If you find no such specific, named contradiction in any Q&A pair, "
    "answer No_Mistake.\n\n"
    "Respond in exactly this format:\n"
    "VERDICT: Mistake or No_Mistake\n"
    "If Mistake:\n"
    "DRAFT CLAIM: <the exact sentence or phrase in the draft that is "
    "contradicted>\n"
    "CONTRADICTING ANSWER: <the exact verification answer that contradicts "
    "it, and which question it answered>\n"
    "EXPLANATION: <one sentence on why this is a direct contradiction, not "
    "just a difference in detail or phrasing>"
)

PROMPT_D_SUFFIX = (
    "\n\nYou are correcting exactly one specific, named error in your own "
    "earlier explanation. You will be given your previous explanation and a "
    "judge's finding of a specific contradiction between a claim in it and a "
    "verified answer from the DETECTOR FACTS/TOPOLOGY/RFC GROUNDING. Fix only "
    "the claim the judge identified, using only the facts, topology, and RFC "
    "excerpts given below to determine the correct statement. Leave every "
    "other claim, sentence, and section exactly as it was in the previous "
    "explanation -- do not rewrite, rephrase, or \"improve\" anything the "
    "judge did not flag. Your output must still follow the exact section "
    "structure above, and must not mention the judge, the verification "
    "process, or this correction instruction anywhere in your response."
)


def call_model(client, model, system_prompt, user_prompt, label, call_log):
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


def parse_questions(text):
    questions = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+[\.\)]\s*(.+)$", line.strip())
        if m:
            questions.append(m.group(1).strip())
    if not questions:
        questions = [l.strip() for l in text.splitlines() if l.strip()]
    return questions[:5]


def parse_answer(text):
    def grab(field, stop_fields):
        pattern = rf"{field}:\s*(.*?)(?=\n(?:{'|'.join(stop_fields)}):|\Z)"
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else None
    answer = grab("ANSWER", ["SUPPORT"])
    support = grab("SUPPORT", [])
    return {"answer": answer or text.strip(), "support": support}


def strip_spliced_next_steps(text):
    """See disc_pipeline.py's identical function for the full rationale
    (confirmed fix, carried verbatim): the judge must never see the
    deterministic self-resolved NEXT STEPS splice, or it creates an
    unfixable Mistake verdict every cycle."""
    return re.sub(r"\n\nNEXT STEPS:.*?\n\n(?=RFC CITATIONS:)", "\n\n", text, flags=re.DOTALL)


def parse_judge(text):
    upper = text.upper()
    if "VERDICT: NO_MISTAKE" in upper or "VERDICT: NO MISTAKE" in upper:
        verdict = "No_Mistake"
    elif "VERDICT: MISTAKE" in upper:
        verdict = "Mistake"
    else:
        verdict = None

    def grab(field, stop_fields):
        pattern = rf"{field}:\s*(.*?)(?=\n(?:{'|'.join(stop_fields)}):|\Z)"
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else None

    draft_claim = grab("DRAFT CLAIM", ["CONTRADICTING ANSWER", "EXPLANATION"])
    contradicting = grab("CONTRADICTING ANSWER", ["EXPLANATION"])
    explanation = grab("EXPLANATION", [])
    return {"verdict": verdict, "draft_claim": draft_claim, "contradicting_answer": contradicting, "explanation": explanation}


def process_file(key, folder_dir):
    per_file_out = os.path.join(PER_FILE_DIR, f"{key.replace('/', '__')}.json")
    if os.path.exists(per_file_out):
        # Resume support: skip files already completed in a prior partial run.
        return json.load(open(per_file_out, encoding="utf-8"))

    client = _client()
    call_log = []
    t_start = time.time()

    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )

    basename = os.path.basename(folder_dir)
    draft_source = None
    draft = None
    if basename in CACHED_DRAFT_KEYS:
        draft_path = os.path.join(DRAFTS_DIR, f"{basename}.json")
        with open(draft_path, encoding="utf-8") as f:
            draft_record = json.load(f)
        draft = draft_record["draft_a_gpt5"]
        draft_source = "cached"
    else:
        draft = call_model(client, MODEL_DRAFT, system_prompt, context, "draft_a_gpt5_generated", call_log)
        draft_source = "generated"

    # --- Prompt A: verification questions (gpt-5.6) ---
    a_user = f"{context}\n\nDRAFT explanation:\n{draft}"
    a_text = call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_A_SYSTEM, a_user, "A_questions", call_log)
    questions = parse_questions(a_text)

    # --- Prompt B: independent answers, one call per question (gpt-5.6) ---
    qa_pairs = []
    for q in questions:
        b_user = f"{context}\n\nQUESTION: {q}"
        b_text = call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_B_SYSTEM, b_user, "B_answer", call_log)
        parsed = parse_answer(b_text)
        qa_pairs.append({"question": q, "raw_answer": b_text, "answer": parsed["answer"], "support": parsed["support"]})

    qa_block = "\n".join(
        f"Q{i}: {p['question']}\nA{i}: {p['raw_answer']}" for i, p in enumerate(qa_pairs, 1)
    )

    current_draft = draft
    cycles = []
    stop_reason = None

    for cycle in range(1, MAX_CYCLES + 1):
        judge_view_draft = strip_spliced_next_steps(current_draft) if all_recovered else current_draft
        c_user = f"{context}\n\nDRAFT explanation:\n{judge_view_draft}\n\nVERIFICATION Q&A PAIRS:\n{qa_block}"
        c_text = call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_C_SYSTEM, c_user, f"C_judge_cycle{cycle}", call_log)
        judge = parse_judge(c_text)

        cycle_record = {"cycle": cycle, "judge_raw": c_text, "judge": judge, "corrected": False}

        if judge["verdict"] == "No_Mistake":
            cycles.append(cycle_record)
            stop_reason = "no_mistake"
            break
        elif judge["verdict"] == "Mistake":
            if all_recovered:
                corrector_system = pipeline.BASE_SYSTEM_PROMPT_NO_NEXT_STEPS + PROMPT_D_SUFFIX
            else:
                corrector_system = system_prompt + PROMPT_D_SUFFIX
            d_user = (
                f"{context}\n\nPREVIOUS explanation:\n{current_draft}\n\n"
                f"JUDGE'S FINDING:\nDRAFT CLAIM: {judge['draft_claim']}\n"
                f"CONTRADICTING ANSWER: {judge['contradicting_answer']}\n"
                f"EXPLANATION: {judge['explanation']}"
            )
            d_text = call_model(client, MODEL_GEN_CORRECTOR, corrector_system, d_user, f"D_correct_cycle{cycle}", call_log)
            if spec["next_step"] == "free" and all_recovered:
                d_text = pipeline._splice_self_resolved_next_steps(d_text, described_incidents)
            cycle_record["corrected"] = True
            cycle_record["corrected_draft"] = d_text
            cycles.append(cycle_record)
            current_draft = d_text
            if cycle == MAX_CYCLES:
                stop_reason = "cap_reached_not_resolved"
        else:
            cycle_record = cycle_record
            cycles.append(cycle_record)
            stop_reason = "judge_parse_failure"
            break

    t_elapsed = time.time() - t_start

    record = {
        "key": key,
        "folder_dir": folder_dir,
        "all_recovered": all_recovered,
        "n_incidents": len(described_incidents),
        "draft_source": draft_source,
        "initial_draft_gpt5": draft,
        "verification_questions_raw": a_text,
        "verification_questions": questions,
        "qa_pairs": qa_pairs,
        "cycles": cycles,
        "n_cycles": len(cycles),
        "n_corrections": sum(1 for c in cycles if c["corrected"]),
        "stop_reason": stop_reason,
        "final_explanation": current_draft,
        "call_log": call_log,
        "n_calls": len(call_log),
        "total_elapsed_seconds": t_elapsed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    with open(per_file_out, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, default=str)

    return record


def compute_cost(records):
    total_cost = 0.0
    total_prompt = total_completion = 0
    for r in records:
        for c in r.get("call_log", []):
            u = c.get("usage")
            if not u:
                continue
            pt = u.get("prompt_tokens", 0)
            ct = u.get("completion_tokens", 0)
            total_prompt += pt
            total_completion += ct
            total_cost += pt * INPUT_PRICE / 1e6 + ct * OUTPUT_PRICE / 1e6
    return total_cost, total_prompt, total_completion


def write_aggregate(records, run_elapsed, done, total):
    total_cost, total_prompt, total_completion = compute_cost(records)
    n_ok = sum(1 for r in records if r.get("stop_reason") == "no_mistake")
    n_cap = sum(1 for r in records if r.get("stop_reason") == "cap_reached_not_resolved")
    n_parsefail = sum(1 for r in records if r.get("stop_reason") == "judge_parse_failure")
    n_error = sum(1 for r in records if r.get("stop_reason") == "error")
    n_generated_draft = sum(1 for r in records if r.get("draft_source") == "generated")

    slim_records = []
    for r in records:
        slim_records.append({
            "key": r.get("key"), "folder_dir": r.get("folder_dir"),
            "all_recovered": r.get("all_recovered"), "draft_source": r.get("draft_source"),
            "n_cycles": r.get("n_cycles"), "n_corrections": r.get("n_corrections"),
            "stop_reason": r.get("stop_reason"), "final_explanation": r.get("final_explanation"),
            "total_elapsed_seconds": r.get("total_elapsed_seconds"),
        })

    with open(FINAL_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "max_cycles": MAX_CYCLES,
            "n_files_total": total,
            "n_files_done": done,
            "n_no_mistake": n_ok,
            "n_cap_reached": n_cap,
            "n_judge_parse_failure": n_parsefail,
            "n_error": n_error,
            "n_generated_draft": n_generated_draft,
            "wall_clock_seconds_so_far": run_elapsed,
            "total_prompt_tokens": total_prompt,
            "total_completion_tokens": total_completion,
            "total_cost_usd_so_far": total_cost,
            "records": slim_records,
        }, f, indent=1, default=str)


if __name__ == "__main__":
    target_files = FILES
    if len(sys.argv) > 1 and sys.argv[1] == "smoke_test_5":
        target_files = FILES[:5]

    print(f"Dispatching {len(target_files)} files, max_workers={MAX_WORKERS}, DISC (cap={MAX_CYCLES} cycles)")
    run_start = time.time()
    records = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex_pool:
        futures = {ex_pool.submit(process_file, key, file_path[key]): key for key in target_files}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                rec = fut.result()
                records.append(rec)
                print(f"[{len(records)}/{len(target_files)}] {key}: draft_source={rec.get('draft_source')} "
                      f"n_cycles={rec.get('n_cycles')} n_corrections={rec.get('n_corrections')} "
                      f"stop={rec.get('stop_reason')} ({rec.get('total_elapsed_seconds', 0):.1f}s)")
            except Exception as e:
                print(f"[FAILED] {key}: {type(e).__name__}: {e}")
                records.append({
                    "key": key, "folder_dir": file_path[key], "all_recovered": None,
                    "draft_source": None, "n_cycles": 0, "n_corrections": 0,
                    "stop_reason": "error", "final_explanation": None, "call_log": [],
                    "total_elapsed_seconds": 0, "error": f"{type(e).__name__}: {e}",
                })

            n_done = len(records)
            elapsed_so_far = time.time() - run_start
            if n_done % 20 == 0 or n_done == len(target_files):
                write_aggregate(records, elapsed_so_far, n_done, len(target_files))
                cost_so_far, _, _ = compute_cost(records)
                print(f"    --- CHECKPOINT: {n_done}/{len(target_files)} done, cost so far ${cost_so_far:.2f} ---")

    run_elapsed = time.time() - run_start
    write_aggregate(records, run_elapsed, len(records), len(target_files))
    total_cost, total_prompt, total_completion = compute_cost(records)
    n_ok = sum(1 for r in records if r.get("stop_reason") == "no_mistake")
    n_cap = sum(1 for r in records if r.get("stop_reason") == "cap_reached_not_resolved")

    print(f"\nTOTAL WALL CLOCK: {run_elapsed:.1f}s ({run_elapsed/60:.1f} min)")
    print(f"No_Mistake: {n_ok}/{len(target_files)}   Cap reached: {n_cap}/{len(target_files)}")
    print(f"Total tokens: prompt={total_prompt} completion={total_completion}")
    print(f"TOTAL REAL COST: ${total_cost:.4f}")
    print(f"Saved: {FINAL_OUT_PATH}")
