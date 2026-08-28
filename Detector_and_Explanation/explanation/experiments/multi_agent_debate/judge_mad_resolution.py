"""RESOLVED/NOT_RESOLVED judgment for Multi-Agent Debate's final reconciled
output, using the same MEANING_CHANGE/PRECISION_GAP judge pattern already
established in deep_audit_v2.py (Section 5.3.4), applied here to
final_reconciled_gpt56 instead of a self-consistency rerun. Judge model:
gpt-5.6, matching the judge model used throughout Section 5.3.

RESOLVED = judge found zero issues (NO ISSUES FOUND) against the real RFC
text and citations the reconciled explanation itself cites.
NOT_RESOLVED = at least one MEANING_CHANGE or PRECISION_GAP issue found.

Source data: experiments/multi_agent_debate/output/cross_model_debate_summary.json
(no existing verdict field -- confirmed in the preceding investigation step).
"""
import sys, os, json, time, re, io
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
sys.path.insert(0, EXPLAIN_DIR)
from pipeline import _client

INPUT_SUMMARY = os.path.join(EXPLAIN_DIR, "experiments", "multi_agent_debate", "output", "cross_model_debate_summary.json")
OUT_PATH = os.path.join(EXPLAIN_DIR, "experiments", "multi_agent_debate", "output", "mad_resolution_results.json")

MODEL = "gpt-5.6"
INPUT_PRICE = 5.0
OUTPUT_PRICE = 30.0

corpus = json.load(open(os.path.join(EXPLAIN_DIR, "rfc_corpus.json"), encoding="utf-8"))
corpus_by_citation = {e["citation"]: e["text"] for e in corpus}

SYSTEM_PROMPT = (
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
    # Section boundaries use "\n\n" in most records but plain "\n" in some
    # (confirmed directly against a real record: catC_pecease_xpe2_rdcollision_xpe8xpe9's
    # final_reconciled_gpt56 has "...UNCERTAIN -- ...\nRFC CITATIONS:\n..." with a
    # single newline) -- match one-or-more newlines before a header, not exactly two,
    # so both formats split correctly.
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
        # Real citation lines are short ("RFC #### Section #.# (Title)");
        # guard against accidentally matching a long RFC GROUNDING prose
        # sentence that happens to start with "RFC ####" (confirmed real
        # case: esdf_toggle_single_pe1's RFC GROUNDING opens with "RFC 8584
        # Section 4 explains that..." and got mis-captured as a citation
        # before this length guard was added).
        if re.match(r"^RFC\s*\d{3,5}", line) and len(line) <= 120:
            cites.append(line)
    return cites


def build_user_prompt(grounding_text, citations):
    passages_block = []
    for c in citations:
        text = corpus_by_citation.get(c, "[PASSAGE NOT FOUND -- citation string did not match corpus exactly]")
        passages_block.append(f"=== {c} ===\n{text}")
    passages_joined = "\n\n".join(passages_block) if passages_block else "(no citations parsed from this explanation)"
    return (
        f"RFC-GROUNDED REASONING PASSAGE (final reconciled Multi-Agent Debate output):\n{grounding_text}\n\n"
        f"ACTUAL RFC TEXT IT WAS GROUNDED IN (all cited passages, full text):\n{passages_joined}"
    )


def parse_verdict(raw_text):
    if raw_text is None:
        return "NOT_RESOLVED", None, "no response"
    upper = raw_text.upper()
    if "NO ISSUES FOUND" in upper and "ISSUE 1:" not in upper:
        return "RESOLVED", [], None
    n_meaning = len(re.findall(r"TYPE:\s*MEANING_CHANGE", raw_text, re.IGNORECASE))
    n_precision = len(re.findall(r"TYPE:\s*PRECISION_GAP", raw_text, re.IGNORECASE))
    return "NOT_RESOLVED", {"meaning_change": n_meaning, "precision_gap": n_precision}, None


d = json.load(open(INPUT_SUMMARY, encoding="utf-8"))
records_in = d["records"]
print(f"Loaded {len(records_in)} Multi-Agent Debate records from {INPUT_SUMMARY}")

examples = []
for r in records_in:
    sections = parse_sections(r["final_reconciled_gpt56"])
    grounding = sections.get("RFC GROUNDING", "")
    grounding = re.split(r"\nCONFIDENCE:", grounding)[0].strip()
    citations_text = sections.get("RFC CITATIONS", "")
    citations = extract_citations(citations_text)
    matched = [c for c in citations if c in corpus_by_citation]
    unmatched = [c for c in citations if c not in corpus_by_citation]
    user_prompt = build_user_prompt(grounding, matched)
    examples.append({
        "file": r["file"], "user_prompt": user_prompt,
        "citations_parsed": citations, "citations_matched": matched, "citations_unmatched": unmatched,
        "reconciled_explanation": r["final_reconciled_gpt56"],
    })

print(f"Built {len(examples)} judge prompts. Citation match check:")
for ex in examples:
    if ex["citations_unmatched"]:
        print(f"  WARNING [{ex['file']}]: unmatched citations against corpus: {ex['citations_unmatched']}")

client = _client()


def job(ex):
    t0 = time.time()
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": ex["user_prompt"]},
            ],
        )
        raw = response.choices[0].message.content
        usage = response.usage.model_dump() if response.usage else None
        status = "OK"
        error = None
    except Exception as e:
        raw = None
        usage = None
        status = "FAILED"
        error = f"{type(e).__name__}: {e}"
    elapsed = time.time() - t0
    verdict, issue_counts, note = parse_verdict(raw) if status == "OK" else ("FAILED", None, error)
    return {
        "file": ex["file"], "judge_model": MODEL, "raw_response": raw,
        "verdict": verdict, "issue_counts": issue_counts, "note": note,
        "citations_parsed": ex["citations_parsed"], "citations_matched": ex["citations_matched"],
        "citations_unmatched": ex["citations_unmatched"],
        "status": status, "error": error, "elapsed": elapsed, "usage": usage,
    }


run_start = time.time()
records = []
with ThreadPoolExecutor(max_workers=8) as ex_pool:
    futures = {ex_pool.submit(job, ex): ex["file"] for ex in examples}
    for fut in as_completed(futures):
        rec = fut.result()
        records.append(rec)
        print(f"[{len(records)}/{len(examples)}] {rec['file']}: verdict={rec['verdict']} "
              f"issue_counts={rec['issue_counts']} status={rec['status']} ({rec['elapsed']:.1f}s)")

run_elapsed = time.time() - run_start

total_cost = 0.0
total_prompt = total_completion = 0
for r in records:
    if r["usage"]:
        pt = r["usage"].get("prompt_tokens", 0)
        ct = r["usage"].get("completion_tokens", 0)
        total_prompt += pt
        total_completion += ct
        total_cost += pt * INPUT_PRICE / 1e6
        total_cost += ct * OUTPUT_PRICE / 1e6

n_resolved = sum(1 for r in records if r["verdict"] == "RESOLVED")
n_not_resolved = sum(1 for r in records if r["verdict"] == "NOT_RESOLVED")
n_failed = sum(1 for r in records if r["verdict"] == "FAILED")

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump({
        "judge_model": MODEL,
        "source": INPUT_SUMMARY,
        "total_wall_clock_seconds": run_elapsed,
        "n_files": len(examples),
        "n_resolved": n_resolved,
        "n_not_resolved": n_not_resolved,
        "n_failed": n_failed,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_cost_usd": total_cost,
        "records": records,
    }, f, indent=1, default=str)

print(f"\nTOTAL WALL CLOCK: {run_elapsed:.1f}s ({run_elapsed/60:.1f} min)")
print(f"RESOLVED: {n_resolved}/{len(examples)}   NOT_RESOLVED: {n_not_resolved}/{len(examples)}   FAILED: {n_failed}/{len(examples)}")
print(f"Total tokens: prompt={total_prompt} completion={total_completion}")
print(f"Total real cost: ${total_cost:.4f}")
print(f"Saved: {OUT_PATH}")
