"""Builds a citation + shared-concept knowledge graph over this project's
own rfc_corpus.json. Fresh implementation -- referenced against
pcap2story's rfc_knowledge_graph/build_graph.py for design only (same two
edge kinds: RFC cross-reference citations, and shared-term co-occurrence;
same explicit exclusion of fault-causality edges, since no textual basis
for those exists in RFC prose -- e.g. RFC 8584 never cites RFC 4271
anywhere in this corpus either, confirmed by the same grep approach)."""
import json
import os
import re

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "..", "rfc_corpus.json")
_OUT_PATH = os.path.join(os.path.dirname(__file__), "rfc_kg.json")

with open(_CORPUS_PATH, encoding="utf-8") as _fh:
    RFC_CORPUS = json.load(_fh)

_BY_RFC = {}
for c in RFC_CORPUS:
    _BY_RFC.setdefault(c["rfc"], []).append(c)
for num in _BY_RFC:
    _BY_RFC[num].sort(key=lambda c: c["id"])

_CITE_PATTERN = re.compile(r"RFC\s?0*(\d{3,5})", re.I)
_SECTION_OF_RFC = re.compile(r"Section\s+([0-9]+(?:\.[0-9]+)*)\s+of\s+\[?RFC\s?0*(\d{3,5})\]?", re.I)

# Domain terms confirmed present verbatim in this corpus's own text
# (grepped, not assumed) -- shared-concept co-occurrence edges connect any
# two sections that both contain one of these, since that's a real,
# textually-grounded relationship (same defined term), unlike a fault-
# causality edge.
_SHARED_TERMS = [
    "Route Reflector", "Graceful Restart", "Designated Forwarder",
    "Ethernet Segment", "MAC Mobility", "Route Distinguisher",
    "Route Target", "Extended Community", "Cease", "WITHDRAW",
    "ES-Import", "CLUSTER_ID",
]


def _find_citation_edges():
    edges = []
    for c in RFC_CORPUS:
        text = c["text"]
        for m in _SECTION_OF_RFC.finditer(text):
            section, rfc_num = m.group(1), m.group(2)
            if rfc_num == c["rfc"]:
                continue  # self-reference, not a cross-RFC edge
            target_id = f"rfc{rfc_num}_{section}"
            if target_id in {e["id"] for e in RFC_CORPUS}:
                edges.append({"from": c["id"], "to": target_id, "type": "citation", "granularity": "section"})
        for m in _CITE_PATTERN.finditer(text):
            rfc_num = m.group(1)
            if rfc_num == c["rfc"] or rfc_num not in _BY_RFC:
                continue
            target_id = _BY_RFC[rfc_num][0]["id"]  # document-level stand-in, first section
            edge = {"from": c["id"], "to": target_id, "type": "citation", "granularity": "document"}
            if edge not in edges:
                edges.append(edge)
    return edges


def _find_shared_concept_edges():
    term_to_ids = {t: [] for t in _SHARED_TERMS}
    for c in RFC_CORPUS:
        for term in _SHARED_TERMS:
            if term.lower() in c["text"].lower() or term.lower() in c["title"].lower():
                term_to_ids[term].append(c["id"])

    edges = []
    for term, ids in term_to_ids.items():
        if len(ids) < 2:
            continue
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                edges.append({"from": ids[i], "to": ids[j], "type": "shared_concept", "term": term})
    return edges


def build_graph():
    nodes = [{"id": c["id"], "rfc": c["rfc"], "section": c["section"], "title": c["title"], "citation": c["citation"]} for c in RFC_CORPUS]
    citation_edges = _find_citation_edges()
    shared_edges = _find_shared_concept_edges()
    return {"nodes": nodes, "edges": citation_edges + shared_edges}


if __name__ == "__main__":
    graph = build_graph()
    with open(_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=1)
    n_citation = sum(1 for e in graph["edges"] if e["type"] == "citation")
    n_shared = sum(1 for e in graph["edges"] if e["type"] == "shared_concept")
    print(f"Built KG: {len(graph['nodes'])} nodes, {n_citation} citation edges, {n_shared} shared_concept edges -> {_OUT_PATH}")
