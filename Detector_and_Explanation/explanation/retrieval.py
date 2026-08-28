"""Flat cosine-similarity RFC retrieval for this project's explanation
layer. Originally the same embedding model as pcap2story (all-MiniLM-L6-v2,
384-dim, sentence-transformers, cosine similarity, min_score=0.30) --
fresh implementation and fresh index built against THIS project's own
rfc_corpus.json (see build_rfc_corpus.py), not pointed at pcap2story's
.npy cache (that cache reflects pcap2story's old query tuning and a
corpus built the same way but independently -- reusing it would silently
couple this project to embeddings computed against text chunk boundaries
this project's own build_rfc_corpus.py might drift from over time).

2026-08-17: switched to all-mpnet-base-v2 (768-dim), after a standalone
side-by-side comparison against the prior all-MiniLM-L6-v2 model showed
it gave more topically confident/correct top-1 results on real queries
(e.g. both ES-Import RT Mismatch scenarios: all-MiniLM ranked the less
specific "Constructing the Ethernet Segment Route" above the directly
on-topic "ES-Import Route Target" section; all-mpnet ranked the correct
section #1 with a notably higher, more decisive score). cosine similarity
and min_score=0.30 semantics are unchanged; only the embedding model and
its dimensionality changed (384 -> 768), which invalidates and forces a
full rebuild of the cached rfc_corpus_embeddings.npy (handled
automatically by build_embeddings()'s model-name check below)."""
import os
import json
import hashlib
import numpy as np

EXPLAIN_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_PATH = os.path.join(EXPLAIN_DIR, "rfc_corpus.json")
EMB_PATH = os.path.join(EXPLAIN_DIR, "rfc_corpus_embeddings.npy")
EMB_META_PATH = os.path.join(EXPLAIN_DIR, "rfc_corpus_embeddings.meta.json")

MODEL_NAME = "all-mpnet-base-v2"
MIN_SCORE = 0.30
# 2026-08-17: added after sampling real #2/#3 score gaps across 10 real
# incidents (both flat and KG conditions) -- near-ties at the k=2 cutoff
# turned out to be common, not rare (5/10 flat and 3/10 KG queries had a
# #2-#3 gap <= 0.01; e.g. rt_misconfig_es_import_pe1's flat gap was
# 0.0006). 0.01 was picked as conservative: it catches genuine near-ties
# (the dense low end of the observed gap distribution) without pushing
# nearly every query to k+1 the way a looser threshold like 0.02 would
# (which would have caught 9/10 flat and 7/10 KG queries -- effectively
# "always k+1", not "occasionally break a tie").
SCORE_TIE_TOLERANCE = 0.01

_model = None
_corpus = None
_embeddings = None


def _corpus_hash(corpus):
    h = hashlib.sha256()
    for entry in corpus:
        h.update(entry["id"].encode())
        h.update(entry["text"].encode())
    return h.hexdigest()


def _load_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def load_corpus():
    global _corpus
    if _corpus is None:
        with open(CORPUS_PATH, encoding="utf-8") as f:
            _corpus = json.load(f)
    return _corpus


def build_embeddings(force=False):
    """Builds (or reuses a cache-hash-matched) embeddings .npy for the
    current rfc_corpus.json. Cache key is a content hash of the corpus
    itself (id+text per chunk) -- any chunking change invalidates it
    automatically, same convention as pcap2story's own cache design."""
    corpus = load_corpus()
    chash = _corpus_hash(corpus)
    if not force and os.path.exists(EMB_PATH) and os.path.exists(EMB_META_PATH):
        meta = json.load(open(EMB_META_PATH))
        if meta.get("corpus_hash") == chash and meta.get("model") == MODEL_NAME:
            return np.load(EMB_PATH)
    model = _load_model()
    texts = [f"{e['citation']}: {e['text']}" for e in corpus]
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True, normalize_embeddings=True)
    np.save(EMB_PATH, embeddings)
    json.dump({"corpus_hash": chash, "model": MODEL_NAME, "n": len(corpus)}, open(EMB_META_PATH, "w"))
    return embeddings


def _get_embeddings():
    global _embeddings
    if _embeddings is None:
        _embeddings = build_embeddings()
    return _embeddings


def select_top_k_with_tie_tolerance(ranked, k, tolerance=SCORE_TIE_TOLERANCE):
    """`ranked` is a list of dicts with a "score" key, already sorted
    descending with ties broken deterministically (by chunk id, not by
    set()/argsort() iteration order -- see retrieve()/
    graph_traverse_retrieve() callers). Returns ranked[:k], extended by
    exactly one more entry (never more than one, per spec) if the entry
    at position k+1 (0-indexed k) scores within `tolerance` of the entry
    at position k (0-indexed k-1) -- i.e. output length is k or k+1,
    never fewer than what min_score already filtered to. This does not
    chain into k+2, k+3, etc., even if those are also within tolerance of
    each other -- only the single boundary at the requested cutoff is
    checked, matching the exact behavior specified when this was added."""
    if len(ranked) <= k:
        return ranked
    if ranked[k - 1]["score"] - ranked[k]["score"] <= tolerance:
        return ranked[:k + 1]
    return ranked[:k]


def retrieve(query, k=5, min_score=MIN_SCORE, tolerance=SCORE_TIE_TOLERANCE):
    """Returns [{"entry": corpus_entry, "score": float}], sorted
    descending, score >= min_score only, length k or k+1 (see
    select_top_k_with_tie_tolerance). Ordering is fully deterministic
    given identical corpus+embeddings: ties are broken by chunk id
    (corpus["id"]), not by np.argsort()'s implementation-defined order
    for equal keys, which is what previously let two runs against the
    unchanged corpus return different candidates at a tie (confirmed via
    real re-runs before this fix -- not a hypothetical)."""
    corpus = load_corpus()
    embeddings = _get_embeddings()
    model = _load_model()
    q_emb = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)[0]
    scores = embeddings @ q_emb  # both normalized -> dot product == cosine similarity
    order = sorted(range(len(corpus)), key=lambda i: (-float(scores[i]), corpus[i]["id"]))
    ranked = []
    for idx in order:
        score = float(scores[idx])
        if score < min_score:
            break
        ranked.append({"entry": corpus[idx], "score": score})
    return select_top_k_with_tie_tolerance(ranked, k, tolerance)


if __name__ == "__main__":
    build_embeddings(force=True)
    print(f"Built embeddings for {len(load_corpus())} chunks -> {EMB_PATH}")
    hits = retrieve("MAC mobility sequence number extended community", k=3)
    for h in hits:
        print(f"  {h['score']:.3f}  {h['entry']['citation']}")
