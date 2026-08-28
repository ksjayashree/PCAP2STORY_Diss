"""Atomic fact decomposition + checking for the SUMMARY and RFC GROUNDING
sections of the pipeline's generated explanations, over the same 20-file
set used by Self-Refine, DISC, and Multi-Agent Debate (Section 5.3.4-7).

Method: for each file, decompose SUMMARY + RFC GROUNDING into individual
atomic factual claims, then check each claim against the real DETECTOR
FACTS/TOPOLOGY (for incident-fact claims) or the real RFC excerpt text
(for RFC-content claims), classifying each as SUPPORTED, UNSUPPORTED, or
CONTRADICTED. Decomposition and checking both use gpt-5.6 in a single
combined call per file, matching the LLM-as-Judge setup already used
elsewhere in this evaluation (Section 5.3.4) for direct comparability.

Source explanation: reuses the existing gpt-5 matched-context production
draft already generated for Multi-Agent Debate (draft_a_gpt5 in
../multi_agent_debate/output/cross_model_debate_results/<file>.json) --
not regenerated, per this session's established convention.

Usage: python atomic_fact_decomposition.py
"""
import sys, os, json, time, re, io
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
EXPERIMENTS_DIR = os.path.join(EXPLAIN_DIR, "experiments")
sys.path.insert(0, EXPLAIN_DIR)
sys.path.insert(0, os.path.join(EXPERIMENTS_DIR, "shared"))

import pipeline
from pipeline import detect_incidents, build_context, _client, SEED
from part2_files import FILES_20

CONDITION = "KG_RAG"
spec = pipeline.CONDITION_SPEC[CONDITION]
MODEL = "gpt-5.6"

INPUT_PRICE = 1.25
OUTPUT_PRICE = 10.0

DRAFTS_DIR = os.path.join(EXPERIMENTS_DIR, "multi_agent_debate", "output", "cross_model_debate_results")
OUT_DIR = os.path.join(EXPERIMENTS_DIR, "atomic_fact_decomposition", "output")
os.makedirs(OUT_DIR, exist_ok=True)

SYSTEM_PROMPT = (
    "You are decomposing and fact-checking the SUMMARY and RFC GROUNDING "
    "sections of a network-fault explanation.\n\n"
    "You will be given: (1) the SUMMARY and RFC GROUNDING text to check, "
    "(2) the real DETECTOR FACTS AND TOPOLOGY the explanation should be "
    "consistent with, and (3) the real RFC excerpt text the RFC GROUNDING "
    "section was supposedly grounded in (embedded within the same context "
    "block, alongside the facts/topology).\n\n"
    "STEP 1 -- Decompose the SUMMARY and RFC GROUNDING text into individual "
    "atomic factual claims. Each claim must assert exactly ONE checkable "
    "fact: a specific node name, timestamp, fault type, trigger mechanism, "
    "recovery status, relatedness/causal claim, or a specific statement "
    "about what a cited RFC section requires, permits, or recommends. Do "
    "not split a single fact across multiple claims, and do not combine "
    "two distinct facts into one claim. Skip pure connective/narration "
    "text with no checkable content.\n\n"
    "STEP 2 -- For each atomic claim, check it against ONLY the material "
    "given below: DETECTOR FACTS/TOPOLOGY for incident-fact claims, or the "
    "RFC excerpt text for RFC-content claims. Never use outside knowledge "
    "beyond what is given. Classify each claim as:\n"
    "SUPPORTED: the claim is stated or directly implied by the given "
    "facts/topology or RFC excerpt text.\n"
    "UNSUPPORTED: the claim is not addressed one way or the other by the "
    "given material -- neither confirmed nor denied.\n"
    "CONTRADICTED: the claim is directly contradicted by the given "
    "material.\n\n"
    "Respond with ONLY a JSON array, no prose, no markdown fences, no "
    "trailing commentary:\n"
    "[{\"claim\": \"...\", \"claim_type\": \"incident_fact\"|\"rfc_content\", "
    "\"verdict\": \"SUPPORTED\"|\"UNSUPPORTED\"|\"CONTRADICTED\", "
    "\"evidence\": \"the exact fact/topology line or RFC excerpt text this "
    "verdict is based on\"}, ...]"
)


def parse_sections(text):
    if not text:
        return {}
    parts = re.split(r"\n\n(?=(?:SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING|CONFIDENCE):)", text)
    out = {}
    for p in parts:
        m = re.match(r"(SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING|CONFIDENCE):\s*(.*)", p, re.DOTALL)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def parse_claims(text):
    t = text.strip()
    t = re.sub(r"^```(json)?", "", t).strip()
    t = re.sub(r"```$", "", t).strip()
    try:
        claims = json.loads(t)
    except Exception as e:
        return None, f"JSON_PARSE_FAILED: {e}"
    if not isinstance(claims, list):
        return None, "NOT_A_LIST"
    cleaned = []
    for c in claims:
        v = (c.get("verdict") or "").upper()
        if v not in ("SUPPORTED", "UNSUPPORTED", "CONTRADICTED"):
            continue
        cleaned.append({
            "claim": c.get("claim"),
            "claim_type": c.get("claim_type"),
            "verdict": v,
            "evidence": c.get("evidence"),
        })
    return cleaned, None


def make_client():
    return _client()


def process_file(key, folder_dir):
    client = make_client()
    t0 = time.time()

    topo, folder_dir_r, module_key, incidents, raw = detect_incidents(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(
        folder_dir_r, incidents, raw, topo, spec
    )

    draft_path = os.path.join(DRAFTS_DIR, f"{key}.json")
    with open(draft_path, encoding="utf-8") as f:
        draft_record = json.load(f)
    draft = draft_record["draft_a_gpt5"]

    sections = parse_sections(draft)
    summary_text = sections.get("SUMMARY", "")
    grounding_text = sections.get("RFC GROUNDING", "")
    # RFC GROUNDING sometimes runs into a trailing CONFIDENCE line if not
    # cleanly split (matches the pattern already handled elsewhere this
    # session) -- strip defensively.
    grounding_text = re.split(r"\nCONFIDENCE:", grounding_text)[0].strip()

    user_prompt = (
        f"SUMMARY:\n{summary_text}\n\n"
        f"RFC GROUNDING:\n{grounding_text}\n\n"
        f"DETECTOR FACTS, TOPOLOGY, AND RFC EXCERPT TEXT (the exact context "
        f"the drafting model was given):\n{context}"
    )

    status = "OK"
    error = None
    usage = None
    claims = None
    raw_response = None
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}],
            seed=SEED,
        )
        raw_response = response.choices[0].message.content
        usage = response.usage.model_dump() if response.usage else None
        claims, parse_err = parse_claims(raw_response)
        if claims is None:
            status = "PARSE_FAILED"
            error = parse_err
    except Exception as e:
        status = "FAILED"
        error = f"{type(e).__name__}: {e}"

    elapsed = time.time() - t0

    n_supported = sum(1 for c in (claims or []) if c["verdict"] == "SUPPORTED")
    n_unsupported = sum(1 for c in (claims or []) if c["verdict"] == "UNSUPPORTED")
    n_contradicted = sum(1 for c in (claims or []) if c["verdict"] == "CONTRADICTED")
    n_total = len(claims or [])

    record = {
        "file": key,
        "folder_dir": folder_dir,
        "status": status,
        "error": error,
        "summary_text": summary_text,
        "grounding_text": grounding_text,
        "raw_response": raw_response,
        "claims": claims,
        "n_claims_total": n_total,
        "n_supported": n_supported,
        "n_unsupported": n_unsupported,
        "n_contradicted": n_contradicted,
        "pct_supported": (n_supported / n_total * 100) if n_total else None,
        "usage": usage,
        "elapsed_seconds": elapsed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    out_path = os.path.join(OUT_DIR, f"{key}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1, default=str)

    return record


print(f"Dispatching {len(FILES_20)} files, max_workers=8, atomic fact decomposition (gpt-5.6, single call/file)")
run_start = time.time()
records = []
with ThreadPoolExecutor(max_workers=8) as ex_pool:
    futures = {ex_pool.submit(process_file, key, folder_dir): key for key, folder_dir in FILES_20.items()}
    for fut in as_completed(futures):
        key = futures[fut]
        try:
            rec = fut.result()
            records.append(rec)
            print(f"[{len(records)}/{len(FILES_20)}] {key}: status={rec['status']} "
                  f"n_claims={rec['n_claims_total']} supported={rec['n_supported']} "
                  f"unsupported={rec['n_unsupported']} contradicted={rec['n_contradicted']} "
                  f"({rec['elapsed_seconds']:.1f}s)")
        except Exception as e:
            print(f"[FAILED] {key}: {type(e).__name__}: {e}")
            records.append({"file": key, "status": "FAILED", "error": f"{type(e).__name__}: {e}"})

run_elapsed = time.time() - run_start

total_cost = 0.0
total_prompt = total_completion = 0
for r in records:
    if r.get("usage"):
        u = r["usage"]
        pt = u.get("prompt_tokens", 0)
        ct = u.get("completion_tokens", 0)
        total_prompt += pt
        total_completion += ct
        total_cost += pt * INPUT_PRICE / 1e6
        total_cost += ct * OUTPUT_PRICE / 1e6

agg_total = sum(r.get("n_claims_total") or 0 for r in records)
agg_supported = sum(r.get("n_supported") or 0 for r in records)
agg_unsupported = sum(r.get("n_unsupported") or 0 for r in records)
agg_contradicted = sum(r.get("n_contradicted") or 0 for r in records)

summary_path = os.path.join(OUT_DIR, "atomic_fact_decomposition_summary.json")
with open(summary_path, "w", encoding="utf-8") as f:
    json.dump({
        "model": MODEL,
        "condition": CONDITION,
        "n_files": len(FILES_20),
        "n_ok": sum(1 for r in records if r.get("status") == "OK"),
        "n_failed": sum(1 for r in records if r.get("status") != "OK"),
        "total_wall_clock_seconds": run_elapsed,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_cost_usd": total_cost,
        "aggregate": {
            "total_claims": agg_total,
            "supported": agg_supported,
            "unsupported": agg_unsupported,
            "contradicted": agg_contradicted,
            "pct_supported": (agg_supported / agg_total * 100) if agg_total else None,
        },
        "records": records,
    }, f, indent=1, default=str)

print(f"\nTOTAL WALL CLOCK: {run_elapsed:.1f}s ({run_elapsed/60:.1f} min)")
print(f"n_ok: {sum(1 for r in records if r.get('status')=='OK')}/{len(records)}")
print(f"Total claims: {agg_total}  supported={agg_supported}  unsupported={agg_unsupported}  contradicted={agg_contradicted}")
print(f"Total real cost: ${total_cost:.4f}")
print(f"Summary saved: {summary_path}")
print(f"Per-file records under: {OUT_DIR}")
