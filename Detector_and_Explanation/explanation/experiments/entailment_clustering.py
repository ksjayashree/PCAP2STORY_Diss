"""Step 1/2 of the entailment-clustering follow-up: bidirectional NLI
entailment clustering over the same 64 saved reruns
(results/reliability_20260808_131124/), matching Kuhn et al. 2023 /
Farquhar et al. 2024's actual clustering rule instead of the cosine
approximation used in semantic_entropy.py / semantic_entropy_isolated.py.
No new LLM API calls -- reuses the already-generated reruns and the
already-built content-isolated text (content_isolation.py).

MODEL CHOICE (confirmed installed/loadable in this environment before
committing, not assumed):
  microsoft/deberta-large-mnli -- a standard pretrained NLI model
  (SNLI+MultiNLI fine-tuned DeBERTa-large, 3-way CONTRADICTION/NEUTRAL/
  ENTAILMENT output). Verified it loads via transformers 5.14.1 +
  torch 2.12.0+cpu (both already installed in this environment) --
  confirmed by an actual from_pretrained() call this session, ~1.5GB
  download, no GPU required. This is not an arbitrary substitute: this
  same DeBERTa-large-MNLI checkpoint is the NLI model Farquhar et al.
  2024 themselves used for entailment clustering in the published
  semantic-entropy method, so this is a direct reproduction of their
  model choice, not just "a comparable model."

COST/SPEED ESTIMATE (confirmed by timing a real inference call before
running the full batch, not assumed):
  Measured steady-state: ~4.4s per single (text_A, text_B) forward pass
  on this CPU-only machine (no GPU available -- confirmed via
  torch.cuda.is_available() == False).
  Per group: 8 reruns -> C(8,2) = 28 unordered pairs -> bidirectional
  (A->B and B->A checked separately, since NLI entailment is not
  symmetric) = 56 forward passes per group.
  8 groups (4 files x 2 conditions) x 56 = 448 forward passes total.
  448 x ~4.4s ~= 1970s (~33 min) wall-clock, all local CPU inference,
  zero additional API spend. Batched inference was tried first to cut
  this down and stalled/hung on this machine's CPU setup (observed
  directly, not assumed) -- proceeding with the slower but confirmed-
  reliable unbatched path rather than risk a silent hang mid-run.

CLUSTERING RULE (confirmed from the method before implementing, not
re-approximated): Kuhn et al. 2023 ("Semantic Uncertainty") define two
generations as belonging to the same semantic-equivalence class if they
BIDIRECTIONALLY ENTAIL each other -- A entails B AND B entails A (both
directions classified as ENTAILMENT, not just "not CONTRADICTION").
Farquhar et al. 2024 uses this same bidirectional-entailment
equivalence relation for clustering before computing semantic entropy
over the resulting cluster-probability distribution. Implemented here
as: compute all 28 pairs' bidirectional NLI labels for a group, treat
mutual-ENTAILMENT pairs as edges in a graph over the 8 reruns, and take
CONNECTED COMPONENTS as the semantic clusters (the standard way to
build equivalence classes from a pairwise relation, and the same
connected-components construction Kuhn et al./Farquhar et al. use --
not a greedy seed-comparison approximation like cluster_by_cosine()'s).

Usage:
    python entailment_clustering.py [run_dir]
"""
import sys
import os
import json
import glob
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from semantic_entropy import normalized_entropy, majority_tag, RESULTS_ROOT
from content_isolation import isolate

FILES = [
    "link_down_bfd_pe1_notrecovered",
    "rr_down_bgpdkill_rr1_notrecovered",
    "rt_misconfig_autoderive_export_pe1_fixed",
    "mac_mobility_cleanmove_pe3to4_settled",
]
CONDITIONS = ["llm_rag_kg_free", "llm_rag_flat_free"]
NLI_MODEL_NAME = "microsoft/deberta-large-mnli"

_tok = None
_model = None


def _load_nli():
    global _tok, _model
    if _model is None:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        _tok = AutoTokenizer.from_pretrained(NLI_MODEL_NAME)
        _model = AutoModelForSequenceClassification.from_pretrained(NLI_MODEL_NAME)
        _model.eval()
    return _tok, _model


def entails(premise, hypothesis):
    """Returns True iff the NLI model's argmax label for (premise,
    hypothesis) is ENTAILMENT. id2label for this checkpoint:
    {0: CONTRADICTION, 1: NEUTRAL, 2: ENTAILMENT} -- read directly off
    model.config.id2label rather than hardcoded, in case of a future
    checkpoint swap."""
    import torch
    tok, model = _load_nli()
    with torch.no_grad():
        inputs = tok(premise, hypothesis, return_tensors="pt", truncation=True, max_length=512)
        logits = model(**inputs).logits[0]
    label = model.config.id2label[int(logits.argmax())]
    return label.upper() == "ENTAILMENT"


def _latest_reliability_run():
    candidates = sorted(glob.glob(os.path.join(RESULTS_ROOT, "reliability_*")))
    if not candidates:
        raise RuntimeError(f"No reliability_* run directories found under {RESULTS_ROOT}")
    return candidates[-1]


def _load_reruns(run_dir, condition, file_stem):
    cond_dir = os.path.join(run_dir, condition, file_stem)
    records = []
    for i in range(1, 9):
        path = os.path.join(cond_dir, f"rerun_{i}.json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        if rec.get("error"):
            continue
        records.append(rec)
    return records


class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def components(self):
        groups = {}
        for i in range(len(self.parent)):
            r = self.find(i)
            groups.setdefault(r, []).append(i)
        return list(groups.values())


def entailment_cluster_group(texts, log_prefix=""):
    """Full pairwise bidirectional entailment check (28 pairs, 56 NLI
    calls for n=8), mutual-entailment edges -> connected components."""
    n = len(texts)
    uf = UnionFind(n)
    edge_log = []
    pair_idx = 0
    total_pairs = n * (n - 1) // 2
    for i in range(n):
        for j in range(i + 1, n):
            pair_idx += 1
            t0 = time.time()
            a_entails_b = entails(texts[i], texts[j])
            b_entails_a = entails(texts[j], texts[i])
            mutual = a_entails_b and b_entails_a
            if mutual:
                uf.union(i, j)
            edge_log.append({"i": i, "j": j, "a_entails_b": a_entails_b, "b_entails_a": b_entails_a, "mutual": mutual})
            elapsed = time.time() - t0
            print(f"  {log_prefix} pair {pair_idx}/{total_pairs} ({i},{j}): A->B={a_entails_b} B->A={b_entails_a} mutual={mutual}  ({elapsed:.1f}s)")
    clusters = uf.components()
    return clusters, edge_log


def analyze(run_dir, files=None, conditions=None):
    """files/conditions: optional overrides for the default 4-file/2-
    condition FILES/CONDITIONS module constants. None (the default)
    preserves original behavior unchanged."""
    files = files if files is not None else FILES
    conditions = conditions if conditions is not None else CONDITIONS
    results = {}
    for file_stem in files:
        for condition in conditions:
            records = _load_reruns(run_dir, condition, file_stem)
            if len(records) < 2:
                continue
            texts = [isolate(r)["content"] for r in records]
            key = f"{file_stem}|{condition}"
            print(f"\n=== {key} ===")
            clusters, edge_log = entailment_cluster_group(texts, log_prefix=f"[{key}]")
            sizes = sorted([len(c) for c in clusters], reverse=True)
            n = len(records)
            entropy = normalized_entropy(sizes, n)
            majority, n_certain, n_uncertain = majority_tag(records)
            results[key] = {
                "n": n, "n_clusters": len(clusters), "cluster_sizes": sizes,
                "dominant_cluster_frac": sizes[0] / n, "normalized_entropy": entropy,
                "self_reported_tag_majority": majority, "self_reported_n_certain": n_certain,
                "self_reported_n_uncertain": n_uncertain, "edge_log": edge_log,
            }
            print(f"  -> clusters={len(clusters)} sizes={sizes} entropy={entropy:.3f}")
    return results


def main(run_dir=None, files=None, conditions=None):
    run_dir = run_dir if run_dir is not None else (sys.argv[1] if len(sys.argv) > 1 else _latest_reliability_run())
    print(f"Analyzing reliability run: {run_dir}")
    print(f"NLI model: {NLI_MODEL_NAME}")
    print("Loading NLI model (one-time load)...")
    _load_nli()
    print("Loaded.\n")

    t0 = time.time()
    results = analyze(run_dir, files=files, conditions=conditions)
    elapsed = time.time() - t0
    print(f"\nTotal entailment-clustering wall-clock time: {elapsed:.1f}s ({elapsed/60:.1f} min)")

    out_path = os.path.join(run_dir, "_entailment_clustering_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1, default=str)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
