import json, os, sys, io, time
from itertools import combinations

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"C:\simulation pcap\rule_based detector\explanation\experiments")
sys.path.insert(0, r"C:\simulation pcap\rule_based detector\explanation")

DATA_PATH = r"C:\Users\KSJAYA~1\AppData\Local\Temp\claude\C--simulation-pcap\2728fa27-f217-4791-81ce-27424551174a\scratchpad\extracted_texts_20.json"
extracted = json.load(open(DATA_PATH, encoding="utf-8"))

# build the 52 groups: (file, field) -> list of 5 texts
groups = {}
for fstem, v in extracted.items():
    for field in ("SUMMARY", "RFC GROUNDING"):
        groups[(fstem, field)] = v["runs"][field]
    if v["has_recommendation"]:
        groups[(fstem, "recommendation")] = v["runs"]["recommendation"]

print(f"Total groups: {len(groups)}")

# === METHOD 1: DeBERTa-MNLI entailment clustering ===
from entailment_clustering import entails, _load_nli
import numpy as np


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
        d = {}
        for i in range(len(self.parent)):
            r = self.find(i)
            d.setdefault(r, []).append(i)
        return list(d.values())


print("Loading NLI model...")
_load_nli()
print("Loaded.\n")

method1_results = {}
t0 = time.time()
for gi, ((fstem, field), texts) in enumerate(groups.items(), 1):
    n = len(texts)
    uf = UnionFind(n)
    edge_log = []
    for i, j in combinations(range(n), 2):
        a_e_b = entails(texts[i], texts[j])
        b_e_a = entails(texts[j], texts[i])
        mutual = a_e_b and b_e_a
        if mutual:
            uf.union(i, j)
        edge_log.append({"i": i, "j": j, "a_entails_b": a_e_b, "b_entails_a": b_e_a, "mutual": mutual})
    clusters = uf.components()
    sizes = sorted([len(c) for c in clusters], reverse=True)
    method1_results[f"{fstem}|{field}"] = {"n_clusters": len(clusters), "sizes": sizes, "edge_log": edge_log}
    elapsed = time.time() - t0
    print(f"[{gi}/{len(groups)}] {fstem} | {field}: clusters={len(clusters)} sizes={sizes}  (total elapsed {elapsed:.0f}s)")

m1_elapsed = time.time() - t0
print(f"\nMethod 1 total wall-clock: {m1_elapsed:.1f}s ({m1_elapsed/60:.1f} min)\n")

# === METHOD 2: all-mpnet-base-v2 cosine similarity ===
from retrieval import MODEL_NAME as EMB_MODEL_NAME
from sentence_transformers import SentenceTransformer

print("Loading embedding model...")
emb_model = SentenceTransformer(EMB_MODEL_NAME)
method2_results = {}
t0 = time.time()
for (fstem, field), texts in groups.items():
    embs = emb_model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
    n = len(texts)
    pair_sims = []
    for i, j in combinations(range(n), 2):
        pair_sims.append(float(embs[i] @ embs[j]))
    avg = sum(pair_sims) / len(pair_sims)
    method2_results[f"{fstem}|{field}"] = {"avg_cosine": avg}
m2_elapsed = time.time() - t0
print(f"Method 2 total wall-clock: {m2_elapsed:.1f}s\n")

# === METHOD 3: BERTScore ===
from bert_score import score as bertscore

print("Running BERTScore...")
method3_results = {}
t0 = time.time()
for (fstem, field), texts in groups.items():
    pairs = list(combinations(range(5), 2))
    cands = [texts[i] for i, j in pairs]
    refs = [texts[j] for i, j in pairs]
    P, R, F1 = bertscore(cands, refs, lang="en", verbose=False)
    avg_f1 = float(F1.mean())
    method3_results[f"{fstem}|{field}"] = {"avg_f1": avg_f1}
m3_elapsed = time.time() - t0
print(f"Method 3 total wall-clock: {m3_elapsed:.1f}s\n")

out = {
    "method1_entailment": method1_results,
    "method2_cosine": method2_results,
    "method3_bertscore": method3_results,
    "wall_clock": {"method1": m1_elapsed, "method2": m2_elapsed, "method3": m3_elapsed},
}
out_path = r"C:\Users\KSJAYA~1\AppData\Local\Temp\claude\C--simulation-pcap\2728fa27-f217-4791-81ce-27424551174a\scratchpad\methods_all_52_results.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1, default=str)
print(f"Saved: {out_path}")
