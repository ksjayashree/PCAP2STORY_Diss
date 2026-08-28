"""KG-based RFC retrieval: seed from the same flat-search query, expand
1-2 hops over rfc_kg.json, then cosine-rerank the wider candidate pool
before truncating to the final output -- same design principle as
pcap2story's hybrid_retrieval.py (referenced for design only, fresh
implementation): don't just take flat search's top match, use the graph
to surface related sections a pure similarity search might miss, but
still rank the final list by actual query relevance rather than graph
distance alone."""
import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from retrieval import retrieve, load_corpus, _get_embeddings, _load_model, select_top_k_with_tie_tolerance, SCORE_TIE_TOLERANCE
import numpy as np

_KG_PATH = os.path.join(os.path.dirname(__file__), "rfc_kg.json")
_graph = None


def _load_graph():
    global _graph
    if _graph is None:
        with open(_KG_PATH, encoding="utf-8") as f:
            _graph = json.load(f)
    return _graph


def _adjacency():
    graph = _load_graph()
    adj = {}
    for e in graph["edges"]:
        adj.setdefault(e["from"], set()).add(e["to"])
        adj.setdefault(e["to"], set()).add(e["from"])  # undirected traversal
    return adj


def graph_traverse_retrieve(query, k=5, seed_k=3, max_hops=2, max_candidates=25, min_score=0.30, tolerance=SCORE_TIE_TOLERANCE):
    """Seeds from flat retrieve()'s top seed_k hits, expands up to
    max_hops over the KG's undirected adjacency, then cosine-reranks the
    UNION of seeds + expanded neighbors (capped at max_candidates before
    reranking, to keep this bounded on densely-connected shared_concept
    terms) against the same query -- returns the top k (or k+1 on a near
    tie, see select_top_k_with_tie_tolerance) by that rerank, not by hop
    distance. Falls back to plain flat retrieval if the graph expansion
    finds nothing beyond the seeds.

    2026-08-17a: candidate_ids was sorted by chunk id BEFORE the
    max_candidates truncation, to make the previous run's hash-order
    non-determinism deterministic. That fixed determinism but introduced
    a real, confirmed regression: id is an alphabetical sort on strings
    like "rfc5880_...", so whenever visited exceeded max_candidates, every
    candidate belonging to an RFC number that sorts late (5880, 6608,
    6793, 7432, 8538, 8584, 9136) got silently truncated out BEFORE
    scoring -- regardless of actual relevance. Confirmed on a real query
    (link_down_bfd_pe1_notrecovered's BFD query): two RFC 5880 seed
    chunks scoring 0.5213 and 0.5179 (the two highest scores in the
    entire 404-chunk corpus for that query) were dropped by this
    truncation before ever being reranked, because "rfc5880_..." sorts
    after roughly 24 other candidates' ids alphabetically in that query's
    95-chunk visited set.

    2026-08-17b: fixed by scoring every visited candidate FIRST, then
    sorting by (-score, chunk id) -- score is the primary sort key now,
    id is only a deterministic tiebreak for exact/near-equal scores --
    and only THEN truncating to max_candidates. This keeps the fix's
    original goal (deterministic candidate selection, no hash-order
    dependence) while no longer discarding high-scoring candidates for
    an unrelated alphabetical reason."""
    seeds = retrieve(query, k=seed_k, min_score=min_score)
    if not seeds:
        return []

    adj = _adjacency()
    corpus = load_corpus()
    by_id = {c["id"]: c for c in corpus}

    # 2026-08-21: removed the old "break once visited >= max_candidates"
    # early exit -- confirmed via direct investigation that a single
    # well-connected seed's hop-1 expansion alone can exceed max_candidates
    # (e.g. rfc8584_4 has 55+ hop-1 neighbors), which silently disabled
    # hop 2 entirely for that query and made a real, useful, graph-
    # connected hop-2-only node (rfc8584_2.1, reachable from rfc8584_4 at
    # hop 2 but not hop 1) structurally unreachable regardless of its
    # score. The corpus graph is small (324 nodes total), so letting every
    # hop run to completion before the score-based truncation below is
    # cheap (worst case: the entire graph gets scored, still ~324 dot
    # products) -- the max_candidates cap is still enforced, just after
    # scoring (line ~111 below), same as the existing id-vs-score
    # truncation-order fix already applied there for the same reason.
    frontier = {s["entry"]["id"] for s in seeds}
    visited = set(frontier)
    for _hop in range(max_hops):
        next_frontier = set()
        for node_id in frontier:
            next_frontier |= adj.get(node_id, set())
        next_frontier -= visited
        visited |= next_frontier
        frontier = next_frontier

    model = _load_model()
    embeddings = _get_embeddings()
    corpus_index = {c["id"]: i for i, c in enumerate(corpus)}
    q_emb = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)[0]

    # Score every visited candidate BEFORE truncating to max_candidates --
    # the cap must keep the highest-scoring chunks regardless of which
    # RFC number they belong to.
    all_scored = []
    for cid in visited:
        entry = by_id.get(cid)
        idx = corpus_index.get(cid)
        if entry is None or idx is None:
            continue
        score = float(embeddings[idx] @ q_emb)
        all_scored.append({"node": entry, "score": score})

    # Score descending is the primary key; chunk id is only the
    # deterministic tiebreak for exact/near-equal scores (including right
    # at the max_candidates cutoff boundary) -- never the primary sort.
    all_scored.sort(key=lambda x: (-x["score"], x["node"]["id"]))
    scored = all_scored[:max_candidates]

    return select_top_k_with_tie_tolerance(scored, k, tolerance)


if __name__ == "__main__":
    hits = graph_traverse_retrieve("MAC mobility sequence number extended community", k=5)
    for h in hits:
        print(f"  {h['score']:.3f}  {h['node']['citation']}")
