"""Multi-round Multi-Agent Debate, v2: adds a cross-round fix-preservation
instruction to the reconciler prompt (both round 1 and round 2+), fixing
the gap confirmed empirically in v1 (link_down_holdtimer_xpe1_recovered
regressed a correct "mandatory FSM attributes" classification between
round 4 and round 5 because the reconciler had no instruction to check
against prior-round judge findings, only the current round's critiques).

New in v2: every round's reconcile call now receives an accumulated list
of every issue any earlier round's judge flagged on this file (not just
the current round's two critiques), and the reconciler prompt explicitly
instructs it not to reintroduce any of them.

Usage:
    python mad_multiround_v2.py single_file_test    -- runs ONLY
        link_down_holdtimer_xpe1_recovered (Step 3a)
    python mad_multiround_v2.py full_run            -- runs the other
        19 files (Step 3b), reusing the confirmed single-file result
"""
import sys, os, json, time, re, io
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
sys.path.insert(0, EXPLAIN_DIR)
sys.path.insert(0, os.path.join(EXPLAIN_DIR, "experiments", "shared"))

import pipeline
from pipeline import detect_incidents, build_context, _client, SEED
from part2_files import FILES_20

CONDITION = "KG_RAG"
spec = pipeline.CONDITION_SPEC[CONDITION]

MODEL_A = "gpt-5"
MODEL_B = "gpt-5.6"
RECONCILE_MODEL = "gpt-5.6"
JUDGE_MODEL = "gpt-5.6"
MAX_ROUNDS = 10

INPUT_PRICE = 1.25
OUTPUT_PRICE = 10.0
JUDGE_INPUT_PRICE = 5.0
JUDGE_OUTPUT_PRICE = 30.0

MAD_DIR = os.path.join(EXPLAIN_DIR, "experiments", "multi_agent_debate")
OUT_PATH = os.path.join(MAD_DIR, "output", "mad_multiround_v2_results.json")

corpus = json.load(open(os.path.join(EXPLAIN_DIR, "rfc_corpus.json"), encoding="utf-8"))
corpus_by_citation = {e["citation"]: e["text"] for e in corpus}

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

PRESERVE_INSTRUCTION = (
    "\n\nBefore producing your revised draft, review every issue the judge "
    "has flagged in any previous round on this file, not just the current "
    "round's feedback. Your revised draft must address the current round's "
    "flagged issue while also preserving every fix already made in earlier "
    "rounds. Do not reintroduce a claim, phrasing, or omission that a prior "
    "round's judge already flagged and that was already corrected."
)

RECONCILE_SUFFIX_ROUND1 = (
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
    + PRESERVE_INSTRUCTION
)

RECONCILE_SUFFIX_ROUND2PLUS = (
    "\n\nYou are revising your own current explanation using two independent "
    "critiques of it (from two separate reviewers). Keep any claim neither "
    "critique challenged. Where a critique correctly identifies something "
    "unsupported, factually wrong, or RFC-inaccurate, fix it using only the "
    "facts, topology, and RFC excerpts given below -- never using the "
    "current explanation's own unsupported wording. Where the two critiques "
    "disagree with each other about the same claim, resolve it yourself "
    "against the facts/RFC excerpts given, not by favoring one critique "
    "over the other. Your revised answer must still follow the exact "
    "section structure above -- do not mention the critiques or this "
    "revision process itself anywhere in your response."
    + PRESERVE_INSTRUCTION
)

JUDGE_SYSTEM_PROMPT = (
    "An automated pipeline detects EVPN/BGP faults from packet captures and "
    "generates an explanation for each one. Part of that explanation is a "
    "passage of RFC-grounded reasoning, citing specific RFC text to justify "
    "why the detected condition is a fault.\n\n"
    "The explanation is expected to combine the RFC's general rule with "
    "specific facts about the detected incident, such as node names, "
    "timestamps, and the observed event. That combination is correct and "
    "expected. Do not flag a sentence merely for stating an incident-specific "
    "fact that the RFC text itself does not mention, that fact comes from the "
    "detector, not from the RFC, and citing the RFC to explain why that fact "
    "matters is exactly what this passage is supposed to do.\n\n"
    "Only flag a place where the passage's own claim about what the RFC "
    "itself says has changed in meaning from the real RFC text, an inversion, "
    "a contradiction, a wrong definition, a term substituted for a different "
    "term, or a rule's scope broadened or narrowed in a way that changes what "
    "the rule actually requires or permits.\n\n"
    "For each such place, classify it as one of two types:\n"
    "MEANING_CHANGE: the passage asserts something about the RFC that "
    "directly contradicts, inverts, or is materially wrong about what the RFC "
    "text says.\n"
    "PRECISION_GAP: the passage's claim about the RFC is still directionally "
    "correct, but drops or softens a real qualifier, condition, or exact term "
    "in a way that is imprecise rather than wrong.\n\n"
    "Do not flag phrasing, style, or word choice differences that do not "
    "change what is being claimed about the RFC. Do not flag a sentence for "
    "combining RFC content with incident-specific facts.\n\n"
    "For each issue found, answer in exactly this format:\n"
    "ISSUE <n>:\n"
    "TYPE: MEANING_CHANGE or PRECISION_GAP\n"
    "EXPECTED: <what the real RFC text actually says>\n"
    "FOUND: <what the passage actually claims about the RFC>\n"
    "LOCATION: <the specific sentence or phrase>\n"
    "REASON: <why this changes or softens the RFC's actual meaning>\n\n"
    "If no issues are found, respond with:\n"
    "NO ISSUES FOUND"
)


def parse_sections(text):
    if not text:
        return {}
    parts = re.split(r"\n+(?=(?:SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING|CONFIDENCE):)", text)
    out = {}
    for p in parts:
        m = re.match(r"(SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING|CONFIDENCE):\s*(.*)", p, re.DOTALL)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def extract_citations(citations_text):
    if not citations_text:
        return []
    cites = []
    for line in citations_text.splitlines():
        line = line.strip().lstrip("-*").strip()
        if re.match(r"^RFC\s*\d{3,5}", line) and len(line) <= 120:
            cites.append(line)
    return cites


def strip_spliced_next_steps(text):
    return re.sub(r"\n\nNEXT STEPS:.*?\n\n(?=RFC CITATIONS:)", "\n\n", text, flags=re.DOTALL)


def build_judge_user_prompt(explanation_text, all_recovered):
    sections = parse_sections(explanation_text)
    grounding = sections.get("RFC GROUNDING", "")
    grounding = re.split(r"\nCONFIDENCE:", grounding)[0].strip()
    citations_text = sections.get("RFC CITATIONS", "")
    citations = [c for c in extract_citations(citations_text) if c in corpus_by_citation]
    passages_block = [f"=== {c} ===\n{corpus_by_citation[c]}" for c in citations]
    passages_joined = "\n\n".join(passages_block) if passages_block else "(no citations parsed)"
    judge_view_draft = strip_spliced_next_steps(explanation_text) if all_recovered else explanation_text
    return (
        f"RFC-GROUNDED REASONING PASSAGE:\n{judge_view_draft}\n\n"
        f"ACTUAL RFC TEXT IT WAS GROUNDED IN (all cited passages, full text):\n{passages_joined}"
    )


def parse_judge_verdict(raw_text):
    if raw_text is None:
        return "NOT_RESOLVED", None
    upper = raw_text.upper()
    if "NO ISSUES FOUND" in upper and "ISSUE 1:" not in upper:
        return "RESOLVED", []
    n_meaning = len(re.findall(r"TYPE:\s*MEANING_CHANGE", raw_text, re.IGNORECASE))
    n_precision = len(re.findall(r"TYPE:\s*PRECISION_GAP", raw_text, re.IGNORECASE))
    return "NOT_RESOLVED", {"meaning_change": n_meaning, "precision_gap": n_precision}


def call_model(client, model, system_prompt, user_prompt, call_log, label):
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


def format_history_block(history):
    if not history:
        return ""
    parts = ["\n\nPREVIOUSLY CONFIRMED ISSUES (already flagged and fixed in earlier rounds -- do not reintroduce any of these):"]
    for h in history:
        parts.append(f"Round {h['round']}:\n{h['judge_raw']}")
    return "\n\n".join(parts)


def process_file_full(key, folder_dir):
    """Runs the COMPLETE pipeline from round 1 (draft_a, draft_b, both
    critiques, reconcile, judge), then round 2+ if needed -- used for the
    Step 3a single-file test, which must re-run from round 1 with the
    v2 prompt, not reuse v1's round-1 data."""
    client = _client()
    call_log = []

    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )

    # --- Round 1: real two-draft cross-critique flow ---
    draft_a = call_model(client, MODEL_A, system_prompt, context, call_log, "r1_draft_a_gpt5")
    draft_b = call_model(client, MODEL_B, system_prompt, context, call_log, "r1_draft_b_gpt56")
    if spec["next_step"] == "free" and all_recovered:
        draft_a = pipeline._splice_self_resolved_next_steps(draft_a, described_incidents)
        draft_b = pipeline._splice_self_resolved_next_steps(draft_b, described_incidents)

    critique_a_of_b_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{draft_b}"
    critique_b_of_a_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{draft_a}"
    critique_of_b = call_model(client, MODEL_A, CRITIQUE_SYSTEM_PROMPT, critique_a_of_b_user, call_log, "r1_critique_gpt5_of_draftB")
    critique_of_a = call_model(client, MODEL_B, CRITIQUE_SYSTEM_PROMPT, critique_b_of_a_user, call_log, "r1_critique_gpt56_of_draftA")

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
    current_draft = call_model(client, RECONCILE_MODEL, reconcile_system_prompt_r1, reconcile_user_r1, call_log, "r1_reconcile")
    if spec["next_step"] == "free" and all_recovered:
        current_draft = pipeline._splice_self_resolved_next_steps(current_draft, described_incidents)

    judge_user = build_judge_user_prompt(current_draft, all_recovered)
    judge_raw = call_model(client, JUDGE_MODEL, JUDGE_SYSTEM_PROMPT, judge_user, call_log, "r1_judge")
    verdict, issue_counts = parse_judge_verdict(judge_raw)

    rounds = [{
        "round": 1, "draft_a": draft_a, "draft_b": draft_b,
        "critique_of_a": critique_of_a, "critique_of_b": critique_of_b,
        "reconciled_draft": current_draft, "judge_raw": judge_raw,
        "verdict": verdict, "issue_counts": issue_counts,
    }]
    history = [{"round": 1, "judge_raw": judge_raw}]

    resolved_at_round = None
    stop_reason = "cap_reached_not_resolved"
    if verdict == "RESOLVED":
        resolved_at_round = 1
        stop_reason = "resolved"
    else:
        for round_num in range(2, MAX_ROUNDS + 1):
            critique_user = f"{context}\n\nEXPLANATION TO REVIEW:\n{current_draft}"
            critique_a = call_model(client, MODEL_A, CRITIQUE_SYSTEM_PROMPT, critique_user, call_log, f"r{round_num}_critique_gpt5")
            critique_b = call_model(client, MODEL_B, CRITIQUE_SYSTEM_PROMPT, critique_user, call_log, f"r{round_num}_critique_gpt56")

            history_block = format_history_block(history)
            reconcile_user = (
                f"{context}\n\nCURRENT EXPLANATION:\n{current_draft}\n\n"
                f"CRITIQUE 1 (from a gpt-5 reviewer):\n{critique_a}\n\n"
                f"CRITIQUE 2 (from a gpt-5.6 reviewer):\n{critique_b}"
                f"{history_block}"
            )
            new_draft = call_model(client, RECONCILE_MODEL, reconcile_system_prompt_r2p, reconcile_user, call_log, f"r{round_num}_reconcile")
            if spec["next_step"] == "free" and all_recovered:
                new_draft = pipeline._splice_self_resolved_next_steps(new_draft, described_incidents)

            judge_user = build_judge_user_prompt(new_draft, all_recovered)
            judge_raw = call_model(client, JUDGE_MODEL, JUDGE_SYSTEM_PROMPT, judge_user, call_log, f"r{round_num}_judge")
            verdict, issue_counts = parse_judge_verdict(judge_raw)

            rounds.append({
                "round": round_num, "critique_a": critique_a, "critique_b": critique_b,
                "reconciled_draft": new_draft, "judge_raw": judge_raw,
                "verdict": verdict, "issue_counts": issue_counts,
            })
            history.append({"round": round_num, "judge_raw": judge_raw})
            current_draft = new_draft

            if verdict == "RESOLVED":
                resolved_at_round = round_num
                stop_reason = "resolved"
                break

    return {
        "file": key, "resolved_at_round": resolved_at_round, "stop_reason": stop_reason,
        "n_calls": len(call_log), "rounds": rounds, "call_log": call_log,
        "final_explanation": current_draft, "all_recovered": all_recovered,
    }


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
            if "judge" in c["label"]:
                total_cost += pt * JUDGE_INPUT_PRICE / 1e6 + ct * JUDGE_OUTPUT_PRICE / 1e6
            else:
                total_cost += pt * INPUT_PRICE / 1e6 + ct * OUTPUT_PRICE / 1e6
    return total_cost, total_prompt, total_completion


def save_results(records, mode, run_elapsed):
    total_cost, total_prompt, total_completion = compute_cost(records)
    n_resolved = sum(1 for r in records if r["resolved_at_round"] is not None)
    n_cap = sum(1 for r in records if r["stop_reason"] == "cap_reached_not_resolved")
    by_round = {}
    for r in records:
        if r["resolved_at_round"] is not None:
            by_round[r["resolved_at_round"]] = by_round.get(r["resolved_at_round"], 0) + 1

    existing = {}
    if os.path.exists(OUT_PATH):
        existing = json.load(open(OUT_PATH, encoding="utf-8"))
    existing_records = existing.get("records", [])
    existing_files = {r["file"] for r in existing_records}
    merged_records = [r for r in existing_records if r["file"] not in {rec["file"] for rec in records}] + records

    all_resolved = sum(1 for r in merged_records if r["resolved_at_round"] is not None)
    all_cap = sum(1 for r in merged_records if r["stop_reason"] == "cap_reached_not_resolved")
    all_by_round = {}
    for r in merged_records:
        if r["resolved_at_round"] is not None:
            all_by_round[r["resolved_at_round"]] = all_by_round.get(r["resolved_at_round"], 0) + 1

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "max_rounds": MAX_ROUNDS,
            "preserve_instruction_added": True,
            "n_files_total_so_far": len(merged_records),
            "n_resolved_total_so_far": all_resolved,
            "n_cap_reached_total_so_far": all_cap,
            "resolved_count_by_round_total_so_far": all_by_round,
            "last_run_mode": mode,
            "last_run_wall_clock_seconds": run_elapsed,
            "last_run_n_resolved": n_resolved,
            "last_run_n_cap_reached": n_cap,
            "last_run_resolved_count_by_round": by_round,
            "last_run_new_prompt_tokens": total_prompt,
            "last_run_new_completion_tokens": total_completion,
            "last_run_new_cost_usd": total_cost,
            "records": merged_records,
        }, f, indent=1, default=str)

    print(f"\nRUN MODE: {mode}")
    print(f"TOTAL WALL CLOCK (this run): {run_elapsed:.1f}s ({run_elapsed/60:.1f} min)")
    print(f"This run -- resolved: {n_resolved}/{len(records)}  (by round: {by_round})  cap reached: {n_cap}/{len(records)}")
    print(f"This run -- new tokens: prompt={total_prompt} completion={total_completion}")
    print(f"This run -- new real cost: ${total_cost:.4f}")
    print(f"Cumulative so far: {all_resolved}/{len(merged_records)} resolved (by round: {all_by_round}), {all_cap} cap-reached")
    print(f"Saved: {OUT_PATH}")


mode = sys.argv[1] if len(sys.argv) > 1 else "single_file_test"

if mode == "single_file_test":
    target_file = "link_down_holdtimer_xpe1_recovered"
    print(f"SINGLE-FILE TEST MODE: running only {target_file} from round 1 with v2 (preservation) prompt")
    run_start = time.time()
    rec = process_file_full(target_file, FILES_20[target_file])
    run_elapsed = time.time() - run_start
    print(f"[{rec['file']}] resolved_at_round={rec['resolved_at_round']} stop_reason={rec['stop_reason']} n_calls={rec['n_calls']}")
    save_results([rec], "single_file_test", run_elapsed)

elif mode == "full_run":
    remaining_files = {k: v for k, v in FILES_20.items() if k != "link_down_holdtimer_xpe1_recovered"}
    print(f"FULL RUN MODE: running remaining {len(remaining_files)} files from round 1 with v2 (preservation) prompt")
    run_start = time.time()
    records = []
    with ThreadPoolExecutor(max_workers=8) as ex_pool:
        futures = {ex_pool.submit(process_file_full, key, folder_dir): key for key, folder_dir in remaining_files.items()}
        for fut in as_completed(futures):
            rec = fut.result()
            records.append(rec)
            print(f"[{len(records)}/{len(remaining_files)}] {rec['file']}: resolved_at_round={rec['resolved_at_round']} "
                  f"stop_reason={rec['stop_reason']} n_calls={rec['n_calls']}")
    run_elapsed = time.time() - run_start
    save_results(records, "full_run", run_elapsed)

else:
    print(f"Unknown mode: {mode}. Use 'single_file_test' or 'full_run'.")
    sys.exit(1)
