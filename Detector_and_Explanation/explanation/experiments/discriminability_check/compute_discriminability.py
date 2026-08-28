"""Within-group cosine similarity across MAD-corrected explanations, to
test whether the same fault_type/trigger_mechanism combination produces
consistent RFC grounding while still varying on incident-specific facts.

No LLM calls -- embeddings only (all-mpnet-base-v2, same model used
elsewhere in this project for retrieval and self-consistency).

Input: experiments/discriminability_check/output/mad_corrected_corpus.json
Output: experiments/discriminability_check/output/discriminability_results.json
"""
import sys, os, json, time, io
from itertools import combinations
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
EXPLAIN_DIR = r"C:\simulation pcap\rule_based detector\explanation"
DC_DIR = os.path.join(EXPLAIN_DIR, "experiments", "discriminability_check")
IN_PATH = os.path.join(DC_DIR, "output", "mad_corrected_corpus.json")
OUT_PATH = os.path.join(DC_DIR, "output", "discriminability_results.json")

SECTIONS = ["SUMMARY", "NEXT STEPS", "RFC CITATIONS", "RFC GROUNDING"]
MODEL_NAME = "all-mpnet-base-v2"

FLAG_GROUNDING_GAP = 0.15   # RFC section mean more than this below SUMMARY mean -> flag
FLAG_TEMPLATE_COLLAPSE = 0.95  # SUMMARY/NEXT STEPS mean at/above this -> flag

t_start = time.time()

d = json.load(open(IN_PATH, encoding="utf-8"))
records = d["records"]
print(f"Loaded {len(records)} corrected records from {IN_PATH}")

# Group by (fault_type, trigger_mechanism) -- a file can belong to more
# than one group if it has multiple real incidents/combos.
groups = defaultdict(list)  # (fault_type, tm) -> list of record dicts (deduped by key within a group)
for r in records:
    seen_combos_for_this_record = set()
    for combo in r.get("combos", []):
        key = (combo["fault_type"], combo["trigger_mechanism"])
        if key in seen_combos_for_this_record:
            continue  # same file, same combo listed twice (multi-incident with repeat) -- count once
        seen_combos_for_this_record.add(key)
        groups[key].append(r)

print(f"Built {len(groups)} groups:")
for k, v in sorted(groups.items(), key=lambda kv: (kv[0][0], -len(kv[1]))):
    print(f"  {k[0]:20s} | {k[1]:55s} | n_files={len(v)}")

import numpy as np
from sentence_transformers import SentenceTransformer

print(f"\nLoading {MODEL_NAME}...")
model = SentenceTransformer(MODEL_NAME)

# Embed every (file, section) text once, globally, to avoid re-embedding
# the same text multiple times across groups a file belongs to.
embed_cache = {}  # (record_key, section) -> normalized embedding vector

def get_text(record, section):
    return (record.get("final_sections") or {}).get(section, "") or ""

def embed_batch(texts):
    if not texts:
        return np.zeros((0, 768), dtype=np.float32)
    emb = model.encode(texts, convert_to_numpy=True, show_progress_bar=False, normalize_embeddings=True)
    return emb

# Collect all unique (key, section, text) to embed in one batch per section for speed.
for section in SECTIONS:
    to_embed_keys = []
    to_embed_texts = []
    for r in records:
        rk = r["key"]
        cache_key = (rk, section)
        if cache_key in embed_cache:
            continue
        text = get_text(r, section)
        to_embed_keys.append(cache_key)
        to_embed_texts.append(text if text.strip() else " ")  # avoid embedding truly empty string oddly
    if to_embed_texts:
        vecs = embed_batch(to_embed_texts)
        for ck, v in zip(to_embed_keys, vecs):
            embed_cache[ck] = v

print(f"Embedded {len(embed_cache)} (file, section) pairs across {len(records)} files x {len(SECTIONS)} sections")

results = {}
flags = []

for (fault_type, tm), files in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1])):
    group_key = f"{fault_type} | {tm}"
    results[group_key] = {"fault_type": fault_type, "trigger_mechanism": tm, "n_files": len(files), "sections": {}}
    n_files = len(files)
    n_pairs = n_files * (n_files - 1) // 2

    section_means = {}
    for section in SECTIONS:
        if n_files < 2:
            results[group_key]["sections"][section] = {
                "n_pairs": 0, "mean": None, "min": None, "max": None, "std": None,
                "note": "fewer than 2 files -- should not occur (all groups confirmed >=2 during scoping)",
            }
            continue

        vecs = np.stack([embed_cache[(r["key"], section)] for r in files])
        sims = []
        for i, j in combinations(range(n_files), 2):
            sim = float(np.dot(vecs[i], vecs[j]))  # already normalized -> dot product == cosine similarity
            sims.append(sim)
        sims_arr = np.array(sims)
        mean_v = float(sims_arr.mean())
        min_v = float(sims_arr.min())
        max_v = float(sims_arr.max())
        std_v = float(sims_arr.std())
        section_means[section] = mean_v
        results[group_key]["sections"][section] = {
            "n_pairs": n_pairs, "mean": mean_v, "min": min_v, "max": max_v, "std": std_v,
        }

    # Flag checks, once all 4 section means are known for this group.
    summary_mean = section_means.get("SUMMARY")
    if summary_mean is not None:
        for rfc_section in ("RFC CITATIONS", "RFC GROUNDING"):
            m = section_means.get(rfc_section)
            if m is not None and (summary_mean - m) > FLAG_GROUNDING_GAP:
                flags.append({
                    "type": "low_rfc_grounding_consistency",
                    "group": group_key, "section": rfc_section,
                    "section_mean": m, "summary_mean": summary_mean,
                    "gap": summary_mean - m,
                    "explanation": (
                        f"{rfc_section} mean similarity ({m:.3f}) is {summary_mean - m:.3f} lower than "
                        f"SUMMARY mean ({summary_mean:.3f}) for this group -- RFC grounding is less "
                        f"consistent across files sharing the same fault_type/trigger_mechanism than "
                        f"expected, given they should be citing/explaining largely the same RFC rule."
                    ),
                })
    for narrative_section in ("SUMMARY", "NEXT STEPS"):
        m = section_means.get(narrative_section)
        if m is not None and m >= FLAG_TEMPLATE_COLLAPSE:
            flags.append({
                "type": "possible_template_collapse",
                "group": group_key, "section": narrative_section,
                "section_mean": m,
                "explanation": (
                    f"{narrative_section} mean similarity ({m:.3f}) is at or above {FLAG_TEMPLATE_COLLAPSE} "
                    f"for this group -- suspiciously high, suggesting incident-specific facts (node names, "
                    f"timestamps, recovery status) may not be varying enough across files, i.e. templated "
                    f"rather than genuinely incident-specific text."
                ),
            })

elapsed = time.time() - t_start

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump({
        "model": MODEL_NAME,
        "n_groups": len(groups),
        "n_files_total": len(records),
        "flag_thresholds": {
            "grounding_gap_below_summary": FLAG_GROUNDING_GAP,
            "template_collapse_at_or_above": FLAG_TEMPLATE_COLLAPSE,
        },
        "elapsed_seconds": elapsed,
        "results": results,
        "flags": flags,
    }, f, indent=1, default=str)

print(f"\nELAPSED: {elapsed:.1f}s (embeddings only, no LLM calls -- real cost $0.00)")
print(f"\n=== RESULTS TABLE ===")
for group_key, gdata in results.items():
    print(f"\n{group_key}  (n_files={gdata['n_files']})")
    for section in SECTIONS:
        s = gdata["sections"][section]
        if s["mean"] is None:
            print(f"  {section:16s}: {s.get('note')}")
        else:
            print(f"  {section:16s}: mean={s['mean']:.3f}  min={s['min']:.3f}  max={s['max']:.3f}  std={s['std']:.3f}  (n_pairs={s['n_pairs']})")

print(f"\n=== FLAGS ({len(flags)}) ===")
for fl in flags:
    print(f"[{fl['type']}] {fl['group']} / {fl['section']}: {fl['explanation']}")

print(f"\nSaved: {OUT_PATH}")
