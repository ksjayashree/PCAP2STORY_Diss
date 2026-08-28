"""Regenerate the 40 ESDF Toggle / Type-4 ES Route Withdrawal files
(excluding the already-known-defective mac_mobility_cleanmove_xpe6to7_settled)
after the RFC 8584 Section 2.1 retrieval-gap fix (citations.py query terms +
traversal.py hop-budget), across 3 layers:
  1. Base pipeline.py KG_RAG explanation (run_one_condition)
  2. MAD correction (v2 preservation-instruction loop, verbatim from
     mad_full_corpus.py -- not imported, same anti-side-effect precaution)
  3. DISC correction (verbatim from disc_full_corpus.py, same precaution)

Per-file checkpointing/resume throughout, same pattern as the full-corpus
runs. Each layer writes to its own output dir under
experiments/discriminability_check/output/esdf_type4_refix/<layer>/.

Usage:
    python regen_esdf_type4_fix.py            # all 3 layers, all 40 files
    python regen_esdf_type4_fix.py smoke_5     # first 5 files only, all 3 layers
"""
import sys, os, json, time, re, io
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
sys.path.insert(0, EXPLAIN_DIR)

import pipeline
from pipeline import detect_incidents, build_context, _client, SEED

CACHE_PATH = os.path.join(EXPLAIN_DIR, "experiments", "results", "cached_detection_results.json")
OUT_ROOT = os.path.join(EXPLAIN_DIR, "experiments", "discriminability_check", "output", "esdf_type4_refix")
BASE_DIR = os.path.join(OUT_ROOT, "base_pipeline")
MAD_DIR = os.path.join(OUT_ROOT, "mad")
DISC_DIR = os.path.join(OUT_ROOT, "disc")
for d in (BASE_DIR, MAD_DIR, DISC_DIR):
    os.makedirs(d, exist_ok=True)

EXCLUDE_KEYS = {"sim_3rr_fault/mac_mobility/single/mac_mobility_cleanmove_xpe6to7_settled"}

cache = json.load(open(CACHE_PATH, encoding="utf-8"))
file_path = {}
for key, entry in cache.items():
    if key in EXCLUDE_KEYS:
        continue
    raw = entry.get("raw") or {}
    for inc in raw.get("ESDF Toggle", []):
        if inc.get("detectability_status") == "DETECTED" and inc.get("trigger_mechanism") == "Type-4 ES Route Withdrawal":
            file_path[key] = entry["path"]
            break

FILES = sorted(file_path.keys())
print(f"Loaded {len(FILES)} ESDF Toggle Type-4 files (defective file already excluded)")

CONDITION = "KG_RAG"
spec = pipeline.CONDITION_SPEC[CONDITION]
INPUT_PRICE = 1.25
OUTPUT_PRICE = 10.0
JUDGE_INPUT_PRICE = 5.0
JUDGE_OUTPUT_PRICE = 30.0

# ======================================================================
# LAYER 1: base pipeline.py KG_RAG explanation
# ======================================================================

class _UsageLoggingClient:
    """Wraps a real OpenAI client's chat.completions.create so real token
    usage can be captured -- run_one_condition() calls the client directly
    via _generate_explanation() and never returns/exposes usage itself, so
    without this wrapper Layer 1's real cost would be silently uncaptured
    (confirmed: the first 5-file smoke test showed llm_called=True,
    n_calls=1 per file, but cost=$0.00 in the summary purely because
    nothing captured it -- the calls were real and billed regardless)."""
    def __init__(self, real_client):
        self._real = real_client
        self.usage_log = []
        self.chat = self

    @property
    def completions(self):
        return self

    def create(self, **kwargs):
        response = self._real.chat.completions.create(**kwargs)
        if response.usage:
            self.usage_log.append(response.usage.model_dump())
        return response


def run_layer1(key, folder_dir):
    out_path = os.path.join(BASE_DIR, f"{key.replace('/', '__')}.json")
    if os.path.exists(out_path):
        return json.load(open(out_path, encoding="utf-8"))
    wrapped_client = _UsageLoggingClient(_client())
    result = pipeline.run_one_condition(folder_dir, CONDITION, client=wrapped_client)
    call_log = [{"label": "kg_rag_explanation", "model": "gpt-5", "usage": u} for u in wrapped_client.usage_log]
    record = {"key": key, "folder_dir": folder_dir, "call_log": call_log, **result}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, default=str)
    return record


# ======================================================================
# LAYER 2: MAD v2 (verbatim from mad_full_corpus.py)
# ======================================================================
MODEL_A, MODEL_B, RECONCILE_MODEL, JUDGE_MODEL = "gpt-5", "gpt-5.6", "gpt-5.6", "gpt-5.6"
MAX_ROUNDS = 10
MAX_WORKERS = 8

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
    "match the given evidence, or if the RFC rule is misstated, or if a "
    "precision gap exists between what's claimed and what's actually "
    "supported."
)
RECONCILE_SUFFIX_ROUND1 = (
    "\n\nYou will be given two draft explanations of the same incident and "
    "a critique of each. Produce a single, reconciled final explanation "
    "that incorporates every valid correction from both critiques. Follow "
    "the exact section structure above."
)
PRESERVE_INSTRUCTION = (
    "\n\nBefore producing your revised draft, review every issue the judge "
    "has flagged in any previous round on this file, not just the current "
    "round's feedback. Your revised draft must address the current round's "
    "flagged issue while also preserving every fix already made in earlier "
    "rounds. Do not reintroduce a claim, phrasing, or omission that a prior "
    "round's judge already flagged and that was already corrected."
)
RECONCILE_SUFFIX_ROUND1 += PRESERVE_INSTRUCTION
RECONCILE_SUFFIX_ROUND2PLUS = (
    "\n\nYou are revising your own previous reconciled explanation based on "
    "a judge's finding of a remaining issue. Fix only what the judge "
    "flagged; preserve everything else. Follow the exact section structure "
    "above." + PRESERVE_INSTRUCTION
)
JUDGE_SYSTEM_PROMPT = (
    "You are judging whether an EVPN/BGP fault explanation has any "
    "remaining MEANING_CHANGE or PRECISION_GAP issue relative to the given "
    "DETECTOR FACTS, TOPOLOGY, and RFC GROUNDING excerpts.\n\n"
    "MEANING_CHANGE: the explanation states something that contradicts or "
    "meaningfully alters what the RFC excerpt or detector facts actually "
    "say. PRECISION_GAP: the explanation makes a claim more specific or "
    "more general than what the evidence actually supports, in a way that "
    "changes what a reader would conclude.\n\n"
    "If you find no such issue, respond with exactly:\nVERDICT: RESOLVED\n\n"
    "If you find one or more issues, respond with:\nVERDICT: NOT_RESOLVED\n"
    "ISSUE 1:\nTYPE: MEANING_CHANGE or PRECISION_GAP\nCLAIM: <the exact "
    "text>\nPROBLEM: <one sentence>\n(repeat ISSUE N: for additional "
    "issues)"
)


def mad_call_model(client, model, system_prompt, user_prompt, call_log, label):
    t0 = time.time()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        seed=SEED,
    )
    elapsed = time.time() - t0
    text = response.choices[0].message.content
    usage = response.usage.model_dump() if response.usage else None
    call_log.append({"label": label, "model": model, "elapsed": elapsed, "usage": usage})
    return text


def mad_parse_sections(text):
    if not text:
        return {}
    parts = re.split(r"\n+(?=(?:SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING|CONFIDENCE):)", text)
    out = {}
    for p in parts:
        m = re.match(r"(SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING|CONFIDENCE):\s*(.*)", p, re.DOTALL)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def mad_parse_judge_verdict(text):
    upper = text.upper()
    if "VERDICT: RESOLVED" in upper and "NOT_RESOLVED" not in upper:
        return "RESOLVED", 0
    n_issues = len(re.findall(r"ISSUE \d+:", text))
    return "NOT_RESOLVED", max(n_issues, 1)


def mad_build_judge_user_prompt(draft, all_recovered):
    note = ""
    if all_recovered:
        note = "\n\n(Note: NEXT STEPS is a deterministic self-resolved splice -- do not evaluate it.)"
    return f"EXPLANATION TO JUDGE:\n{draft}{note}"


def mad_format_history_block(history):
    if not history:
        return ""
    lines = ["\n\nPRIOR ROUNDS' JUDGE FINDINGS (all must remain fixed):"]
    for h in history:
        lines.append(f"--- Round {h['round']} judge finding ---\n{h['judge_raw']}")
    return "\n".join(lines)


def process_mad(key, folder_dir):
    out_path = os.path.join(MAD_DIR, f"{key.replace('/', '__')}.json")
    if os.path.exists(out_path):
        return json.load(open(out_path, encoding="utf-8"))

    client = _client()
    call_log = []
    t_start = time.time()

    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )

    draft_a = mad_call_model(client, MODEL_A, system_prompt, context, call_log, "r1_draft_a_gpt5")
    draft_b = mad_call_model(client, MODEL_B, system_prompt, context, call_log, "r1_draft_b_gpt56")
    if spec["next_step"] == "free" and all_recovered:
        draft_a = pipeline._splice_self_resolved_next_steps(draft_a, described_incidents)
        draft_b = pipeline._splice_self_resolved_next_steps(draft_b, described_incidents)

    critique_a_of_b_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{draft_b}"
    critique_b_of_a_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{draft_a}"
    critique_of_b = mad_call_model(client, MODEL_A, CRITIQUE_SYSTEM_PROMPT, critique_a_of_b_user, call_log, "r1_critique_gpt5_of_draftB")
    critique_of_a = mad_call_model(client, MODEL_B, CRITIQUE_SYSTEM_PROMPT, critique_b_of_a_user, call_log, "r1_critique_gpt56_of_draftA")

    if all_recovered:
        reconcile_system_prompt_r1 = pipeline.BASE_SYSTEM_PROMPT_NO_NEXT_STEPS + RECONCILE_SUFFIX_ROUND1
        reconcile_system_prompt_r2p = pipeline.BASE_SYSTEM_PROMPT_NO_NEXT_STEPS + RECONCILE_SUFFIX_ROUND2PLUS
    else:
        reconcile_system_prompt_r1 = system_prompt + RECONCILE_SUFFIX_ROUND1
        reconcile_system_prompt_r2p = system_prompt + RECONCILE_SUFFIX_ROUND2PLUS

    reconcile_user_r1 = (
        f"{context}\n\nDRAFT A:\n{draft_a}\n\nCRITIQUE OF DRAFT A:\n{critique_of_a}\n\n"
        f"DRAFT B:\n{draft_b}\n\nCRITIQUE OF DRAFT B:\n{critique_of_b}"
    )
    current_draft = mad_call_model(client, RECONCILE_MODEL, reconcile_system_prompt_r1, reconcile_user_r1, call_log, "r1_reconcile")
    if spec["next_step"] == "free" and all_recovered:
        current_draft = pipeline._splice_self_resolved_next_steps(current_draft, described_incidents)

    judge_user = mad_build_judge_user_prompt(current_draft, all_recovered)
    judge_raw = mad_call_model(client, JUDGE_MODEL, JUDGE_SYSTEM_PROMPT, judge_user, call_log, "r1_judge")
    verdict, issue_counts = mad_parse_judge_verdict(judge_raw)

    history = [{"round": 1, "judge_raw": judge_raw}]
    resolved_at_round = None
    stop_reason = "cap_reached_not_resolved"

    if verdict == "RESOLVED":
        resolved_at_round = 1
        stop_reason = "resolved"
    else:
        for round_num in range(2, MAX_ROUNDS + 1):
            critique_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{current_draft}"
            critique_a = mad_call_model(client, MODEL_A, CRITIQUE_SYSTEM_PROMPT, critique_user, call_log, f"r{round_num}_critique_gpt5")
            critique_b = mad_call_model(client, MODEL_B, CRITIQUE_SYSTEM_PROMPT, critique_user, call_log, f"r{round_num}_critique_gpt56")

            history_block = mad_format_history_block(history)
            reconcile_user = (
                f"{context}\n\nCURRENT EXPLANATION:\n{current_draft}\n\n"
                f"CRITIQUE 1 (from a gpt-5 reviewer):\n{critique_a}\n\n"
                f"CRITIQUE 2 (from a gpt-5.6 reviewer):\n{critique_b}"
                f"{history_block}"
            )
            new_draft = mad_call_model(client, RECONCILE_MODEL, reconcile_system_prompt_r2p, reconcile_user, call_log, f"r{round_num}_reconcile")
            if spec["next_step"] == "free" and all_recovered:
                new_draft = pipeline._splice_self_resolved_next_steps(new_draft, described_incidents)

            judge_user = mad_build_judge_user_prompt(new_draft, all_recovered)
            judge_raw = mad_call_model(client, JUDGE_MODEL, JUDGE_SYSTEM_PROMPT, judge_user, call_log, f"r{round_num}_judge")
            verdict, issue_counts = mad_parse_judge_verdict(judge_raw)

            history.append({"round": round_num, "judge_raw": judge_raw})
            current_draft = new_draft

            if verdict == "RESOLVED":
                resolved_at_round = round_num
                stop_reason = "resolved"
                break

    final_sections = mad_parse_sections(current_draft)
    elapsed = time.time() - t_start

    record = {
        "key": key, "folder_dir": folder_dir, "all_recovered": all_recovered,
        "resolved_at_round": resolved_at_round, "stop_reason": stop_reason,
        "n_calls": len(call_log),
        "final_sections": {
            "SUMMARY": final_sections.get("SUMMARY", ""), "NEXT STEPS": final_sections.get("NEXT STEPS", ""),
            "RFC CITATIONS": final_sections.get("RFC CITATIONS", ""), "RFC GROUNDING": final_sections.get("RFC GROUNDING", ""),
        },
        "final_explanation": current_draft, "call_log": call_log, "elapsed_seconds": elapsed,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, default=str)
    return record


# ======================================================================
# LAYER 3: DISC (verbatim from disc_full_corpus.py)
# ======================================================================
MODEL_VERIFIER_JUDGE = "gpt-5.6"
MODEL_GEN_CORRECTOR = "gpt-5"
MODEL_DRAFT = "gpt-5"
MAX_CYCLES = 10

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


def disc_call_model(client, model, system_prompt, user_prompt, label, call_log):
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


def disc_parse_questions(text):
    questions = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+[\.\)]\s*(.+)$", line.strip())
        if m:
            questions.append(m.group(1).strip())
    if not questions:
        questions = [l.strip() for l in text.splitlines() if l.strip()]
    return questions[:5]


def disc_parse_answer(text):
    def grab(field, stop_fields):
        pattern = rf"{field}:\s*(.*?)(?=\n(?:{'|'.join(stop_fields)}):|\Z)"
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else None
    answer = grab("ANSWER", ["SUPPORT"])
    support = grab("SUPPORT", [])
    return {"answer": answer or text.strip(), "support": support}


def disc_strip_spliced_next_steps(text):
    return re.sub(r"\n\nNEXT STEPS:.*?\n\n(?=RFC CITATIONS:)", "\n\n", text, flags=re.DOTALL)


def disc_parse_judge(text):
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


def process_disc(key, folder_dir):
    out_path = os.path.join(DISC_DIR, f"{key.replace('/', '__')}.json")
    if os.path.exists(out_path):
        return json.load(open(out_path, encoding="utf-8"))

    client = _client()
    call_log = []
    t_start = time.time()

    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )

    draft = disc_call_model(client, MODEL_DRAFT, system_prompt, context, "draft_a_gpt5_generated", call_log)

    a_user = f"{context}\n\nDRAFT explanation:\n{draft}"
    a_text = disc_call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_A_SYSTEM, a_user, "A_questions", call_log)
    questions = disc_parse_questions(a_text)

    qa_pairs = []
    for q in questions:
        b_user = f"{context}\n\nQUESTION: {q}"
        b_text = disc_call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_B_SYSTEM, b_user, "B_answer", call_log)
        parsed = disc_parse_answer(b_text)
        qa_pairs.append({"question": q, "raw_answer": b_text, "answer": parsed["answer"], "support": parsed["support"]})

    qa_block = "\n".join(f"Q{i}: {p['question']}\nA{i}: {p['raw_answer']}" for i, p in enumerate(qa_pairs, 1))

    current_draft = draft
    cycles = []
    stop_reason = None

    for cycle in range(1, MAX_CYCLES + 1):
        judge_view_draft = disc_strip_spliced_next_steps(current_draft) if all_recovered else current_draft
        c_user = f"{context}\n\nDRAFT explanation:\n{judge_view_draft}\n\nVERIFICATION Q&A PAIRS:\n{qa_block}"
        c_text = disc_call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_C_SYSTEM, c_user, f"C_judge_cycle{cycle}", call_log)
        judge = disc_parse_judge(c_text)

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
            d_text = disc_call_model(client, MODEL_GEN_CORRECTOR, corrector_system, d_user, f"D_correct_cycle{cycle}", call_log)
            if spec["next_step"] == "free" and all_recovered:
                d_text = pipeline._splice_self_resolved_next_steps(d_text, described_incidents)
            cycle_record["corrected"] = True
            cycle_record["corrected_draft"] = d_text
            cycles.append(cycle_record)
            current_draft = d_text
            if cycle == MAX_CYCLES:
                stop_reason = "cap_reached_not_resolved"
        else:
            cycles.append(cycle_record)
            stop_reason = "judge_parse_failure"
            break

    t_elapsed = time.time() - t_start
    record = {
        "key": key, "folder_dir": folder_dir, "all_recovered": all_recovered,
        "n_incidents": len(described_incidents), "draft_source": "generated",
        "initial_draft_gpt5": draft, "verification_questions": questions, "qa_pairs": qa_pairs,
        "cycles": cycles, "n_cycles": len(cycles), "n_corrections": sum(1 for c in cycles if c["corrected"]),
        "stop_reason": stop_reason, "final_explanation": current_draft,
        "call_log": call_log, "n_calls": len(call_log), "total_elapsed_seconds": t_elapsed,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, default=str)
    return record


# ======================================================================
def compute_cost(records, call_log_key="call_log", judge_aware=False):
    total_cost = total_prompt = total_completion = 0.0
    for r in records:
        for c in r.get(call_log_key, []):
            u = c.get("usage")
            if not u:
                continue
            pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
            total_prompt += pt
            total_completion += ct
            label = c.get("label") or c.get("step") or ""
            if judge_aware and "judge" in label:
                total_cost += pt * JUDGE_INPUT_PRICE / 1e6 + ct * JUDGE_OUTPUT_PRICE / 1e6
            else:
                total_cost += pt * INPUT_PRICE / 1e6 + ct * OUTPUT_PRICE / 1e6
    return total_cost, total_prompt, total_completion


def run_layer(layer_name, fn, target_files):
    print(f"\n{'='*70}\nLAYER: {layer_name} -- {len(target_files)} files, max_workers={MAX_WORKERS}\n{'='*70}")
    t0 = time.time()
    records = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(fn, key, file_path[key]): key for key in target_files}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                rec = fut.result()
                records.append(rec)
                print(f"  [{len(records)}/{len(target_files)}] {key}: done")
            except Exception as e:
                print(f"  [FAILED] {key}: {type(e).__name__}: {e}")
                records.append({"key": key, "error": f"{type(e).__name__}: {e}"})
    elapsed = time.time() - t0
    cost, pt, ct = compute_cost(records, judge_aware=(layer_name == "MAD"))
    print(f"LAYER {layer_name} DONE: {elapsed:.1f}s, cost=${cost:.4f}, prompt={pt} completion={ct}")
    return records, cost, elapsed


if __name__ == "__main__":
    target_files = FILES
    if len(sys.argv) > 1 and sys.argv[1] == "smoke_5":
        target_files = FILES[:5]

    total_cost = 0.0
    l1_records, c1, e1 = run_layer("base_pipeline", run_layer1, target_files)
    total_cost += c1
    l2_records, c2, e2 = run_layer("MAD", process_mad, target_files)
    total_cost += c2
    l3_records, c3, e3 = run_layer("DISC", process_disc, target_files)
    total_cost += c3

    print(f"\n{'='*70}\nALL LAYERS DONE\n{'='*70}")
    print(f"Files: {len(target_files)}")
    print(f"Layer 1 (base): ${c1:.4f} ({e1:.1f}s)")
    print(f"Layer 2 (MAD):  ${c2:.4f} ({e2:.1f}s)")
    print(f"Layer 3 (DISC): ${c3:.4f} ({e3:.1f}s)")
    print(f"TOTAL REAL COST: ${total_cost:.4f}")
