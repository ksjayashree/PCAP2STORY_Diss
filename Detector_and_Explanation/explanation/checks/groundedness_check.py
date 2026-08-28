"""Full 6-category groundedness check for this project's explanation
layer. Read pcap2story's eval_groundedness.py fully before writing this
(C:\\PCAP2STORY\\rule_based\\explain\\eval_groundedness.py) -- referenced
for design/category definitions only, not copied. The 6 categories,
same names/scope as pcap2story's module docstring:

  1. fault_type       -- does the text state the correct fault type?
  2. affected_nodes    -- does the text mention every ground-truth node
                          (min-required-set, not exact-set)?
  3. trigger_mechanism -- does the text describe the real mechanism
                          (keyword match against THIS project's own real
                          trigger_mechanism values, not pcap2story's)?
  4. root_cause_node self-consistency -- does the text name the SAME
                          node/pair the rule engine itself attributed the
                          fault to (explanation-vs-detection, not
                          explanation-vs-ground-truth)?
  5. fabrication        -- node/fault-type/RFC mentions not traceable to
                          any fact actually given to the model. RFC
                          mentions specifically (2026-08-16 format
                          change) are now scanned only within the
                          response's RFC CITATIONS + RFC GROUNDING
                          sections, via format_sections.rfc_relevant_text(),
                          instead of the whole free-text response, since
                          citations now live in their own structured
                          section rather than being scattered through
                          prose.
  6. RFC grounding content -- heuristic word-overlap between RFC-citing
                          sentences and the actually-retrieved passage
                          text (not just whether the right RFC number
                          appears). Same 2026-08-16 change: sentences are
                          now drawn only from the RFC CITATIONS/RFC
                          GROUNDING sections, not the whole response.

Deviations from pcap2story, each because this project's real data shape
differs (confirmed by reading the actual detector output/metadata
schemas this session, not assumed compatible):
  - Category 2's ground-truth node reader handles 3 different
    metadata.json shapes (sim standard, sim mac_mobility, synthcap) --
    pcap2story had one uniform shape.
  - Category 3's keyword table is built from THIS project's own ~13 real
    trigger_mechanism values (grepped from the rule modules directly),
    not pcap2story's 5.
  - Category 5's RFC-fabrication check scans the WHOLE explanation text,
    not just this project's CERTAIN/UNCERTAIN tag clause (the version
    this module replaces only checked the tag).
"""
import os
import re
import json

from format_sections import rfc_relevant_text

DISPLAY_FAULT_TYPE = {"mac_mobility": "MAC Mobility"}
RFC_RE = re.compile(r"RFC\s?\d{3,5}")
# This project's real node-naming convention: PE1-PE10, XPE1-XPE10,
# RR1-RR2, XRR1-XRR3 (confirmed via topology.json node id lists both
# datasets) -- \d{1,2} (not pcap2story's hardcoded [1-5]/[1-2]) so
# multi-digit ids like XPE10 match.
NODE_RE = re.compile(r"\b([A-Z]{2,4}\d{1,2})\b")

ALL_FAULT_TYPES = (
    "Link Down", "RR Down", "PE Cease", "RT Misconfiguration",
    "RD Collision", "MAC Mobility", "ESDF Toggle",
)

_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "is", "are",
    "was", "were", "be", "been", "this", "that", "with", "for", "as",
    "at", "by", "from", "it", "its", "not", "may", "must", "shall",
    "when", "which", "than", "also", "if", "such", "other", "any", "all",
    "one", "two", "per", "into", "onto", "will", "can", "should", "each",
}


def _significant_words(text):
    return {
        w for w in re.findall(r"[a-zA-Z][a-zA-Z\-]{4,}", text.lower())
        if w not in _STOPWORDS
    }


# Built directly from every trigger_mechanism string literal found by
# reading link_down.py, rr_down.py, pe_cease.py, rt_misconfiguration.py,
# rd_collision.py, mac_mobility.py, esdf_toggle.py's own build_result()
# call sites this session -- not guessed, not reused from pcap2story's
# table (different mechanism vocabulary entirely).
TRIGGER_KEYWORDS = {
    "BFD Down": [r"\bbfd\b"],
    "Hold Timer Expired": [r"\bhold timers?\b"],
    "TcpConnectionFails": [r"\btcp\b.{0,20}\b(fail|reset|rst|fin)", r"\bconnection\s+(fail|reset)"],
    "TCP_connection_closed": [r"\btcp\b.{0,20}\b(closed?|fail|reset)"],
    "Cease/Administrative Shutdown": [r"\bcease\b", r"\badministrative\s+shutdown\b"],
    "Auto-Derived Mismatch": [r"\bauto[- ]derived?\b", r"\bmismatch(ed)?\b"],
    "ES-Import RT Mismatch": [r"\bes[- ]import\b"],
    "Shared Route Distinguisher (RD Collision)": [r"\broute distinguisher\b", r"\bshared\b.{0,20}\brd\b", r"\bcollision\b"],
    "clean_move": [r"\bmac\s+mov(e|ed|ing)\b", r"\bclean\s+move\b", r"\bmobility\b"],
    "Type-4 ES Route Withdrawal": [r"\btype[- ]?4\b", r"\bethernet segment\b.{0,20}\broute\b"],
    "Type-1 Per-EVI EAD Withdrawal": [r"\btype[- ]?1\b", r"\bead\b"],
    "AC-State DF Election Community Toggle": [r"\bac[- ]state\b", r"\bdf election\b"],
    "Dual-PE Type-1 Per-ES Withdrawal (ES Full Failure)": [r"\bfull failure\b", r"\bboth\b.{0,20}\bwithdr"],
}


def _ground_truth_nodes(folder_dir, meta):
    """Reads ground-truth node names from whichever of this project's 4
    real metadata.json shapes applies (confirmed this session, not
    assumed uniform like pcap2story's data):
      - multiple/ (multi-incident, 2026-08-19): {"multi_incident": true,
        "incidents": [{"event_affected_node": ..., ...}, ...]} -- a LIST
        of incidents, not one flat incident; collect nodes across every
        entry in the list, not just the first. Checked first since
        "multi_incident" is a distinctive key that can't collide with
        any of the other 3 shapes below.
      - sim standard (link_down/rr_down/pe_cease/rt_misconfig/rd_collision):
        event_affected_node (str) or event_affected_nodes (list)
      - sim mac_mobility: origin_pe + destination_pe
      - synthcap (all 3 fault types it produces): affected_device
        ("PE1" or "PE1,PE2")
    Returns a set of upper-cased node names, possibly empty."""
    if meta.get("multi_incident") and isinstance(meta.get("incidents"), list):
        nodes = set()
        for inc in meta["incidents"]:
            single_n = inc.get("event_affected_node")
            if single_n:
                nodes.add(single_n.upper())
            multi_n = inc.get("event_affected_nodes")
            if isinstance(multi_n, (list, tuple)):
                nodes |= {x.upper() for x in multi_n if x}
        return nodes
    if "scenario_stem" in meta:  # synthcap shape
        raw = meta.get("affected_device") or ""
        return {x.strip().upper() for x in raw.split(",") if x.strip()}
    if "origin_pe" in meta and "mechanism" in meta:  # sim mac_mobility shape
        return {x.upper() for x in (meta.get("origin_pe"), meta.get("destination_pe")) if x}
    single = meta.get("event_affected_node")
    multi = meta.get("event_affected_nodes")
    nodes = set()
    if single:
        nodes.add(single.upper())
    if isinstance(multi, (list, tuple)):
        nodes |= {n.upper() for n in multi if n}
    return nodes


# Fallback patterns for check_fault_type, checked only when the literal
# display_ft substring isn't found. Built from every real fault_type_ok=
# False case in the 44-file run (42 instances, all 8 LLM conditions) --
# not guessed. Every one of these except the Link Down hyphenation
# variant is the SAME mechanism: the raw fault_type label uses an
# internal abbreviation (PE/RR/RT/RD/ESDF) that GPT-5 consistently
# expands to its natural full form in prose (confirmed by reading the
# actual failing explanation text, not assumed) -- e.g. "BGP Cease with
# Administrative Shutdown" for "PE Cease", "Route Reflector Down" for
# "RR Down", "Route-Target Misconfiguration" for "RT Misconfiguration".
# A fixed per-fault-type table, not an open-ended fuzzy matcher, because
# the real failures are this narrow and specific -- keeps every accepted
# alternate phrasing auditable, same spirit as TRIGGER_KEYWORDS below.
#
# Each entry is a list of "clauses" (OR'd together); each clause is a
# list of independent whole-text keyword regexes that must ALL be found
# ANYWHERE in the explanation (AND'd, no proximity window). A proximity
# window was tried first and missed a real case -- "Ethernet Segment
# Designated Forwarder (ESDF) role change occurred... triggered by an
# AC-State DF Election Community toggle" (esdf_toggle_ac_state_pe1.json,
# llm_rag_flat_free) has "Designated Forwarder" and "toggle" ~140 chars
# apart, well outside any reasonable window -- confirmed by testing the
# windowed version against this exact real text before switching to the
# whole-text AND approach, which matches the original literal check's
# own "anywhere in the text" semantics instead of inventing new
# proximity semantics that can silently miss real matches.
FAULT_TYPE_ALIAS_PATTERNS = {
    "PE Cease": [
        [r"\bcease\b", r"\badministrative shutdown\b"],
        [r"\bbgp cease\b"],
    ],
    "RR Down": [
        [r"\broute reflector\b", r"\b(down|fault|failure|failed)\b"],
    ],
    "RT Misconfiguration": [
        [r"\broute[- ]target\b", r"\bmisconfig"],
    ],
    "RD Collision": [
        [r"\broute distinguisher\b", r"\bcollision\b"],
        [r"\bshared\b", r"\brd\b"],
    ],
    "ESDF Toggle": [
        [r"\bes[- ]?df\b", r"\btoggle"],
        [r"\bdesignated forwarder\b", r"\btoggle"],
        [r"\bdesignated forwarder\b", r"\brole change\b"],
        [r"\bdesignated forwarder\b", r"\bre-?election\b"],
    ],
    "Link Down": [
        [r"\blink[- ]down\b"],
        [r"\blink\b", r"\bwent down\b"],
    ],
}


def check_fault_type(explanation, incident):
    ft = incident.get("fault_type")
    display_ft = DISPLAY_FAULT_TYPE.get(ft, ft)
    if not display_ft:
        return None
    text_lower = explanation.lower()
    if display_ft.lower() in text_lower:
        return True
    for clause in FAULT_TYPE_ALIAS_PATTERNS.get(display_ft, []):
        if all(re.search(p, text_lower) for p in clause):
            return True
    return False


def check_affected_nodes(explanation, folder_dir, meta):
    gt_nodes = _ground_truth_nodes(folder_dir, meta)
    if not gt_nodes:
        return None, []
    missing = [n for n in sorted(gt_nodes) if n not in explanation.upper()]
    return len(missing) == 0, missing


def check_trigger_mechanism(explanation, incident):
    tm = incident.get("trigger_mechanism")
    if not tm:
        return None, None
    patterns = TRIGGER_KEYWORDS.get(tm)
    if not patterns:
        return None, tm
    text_lower = explanation.lower()
    return any(re.search(p, text_lower) for p in patterns), tm


def _root_cause_or_pair_repr(incident):
    node = incident.get("root_cause_node")
    if node:
        return {node.upper()}
    pair = incident.get("affected_node_pair")
    group = incident.get("affected_node_group")
    if pair:
        return {v.upper() for v in pair.values() if v}
    if group:
        return {n.upper() for n in group if n}
    return set()


def check_root_cause_self_consistency(explanation, incident):
    """Self-consistency, NOT ground truth (same distinction pcap2story's
    check 4 makes explicitly) -- does the text mention the node(s)/pair
    THIS DETECTOR itself attributed the fault to."""
    nodes = _root_cause_or_pair_repr(incident)
    if not nodes:
        return None
    text_upper = explanation.upper()
    return all(n in text_upper for n in nodes)


def check_fabrication(explanation, incidents, grounding_by_incident, topo, topology_shown=False):
    """Returns a list of fabricated-claim strings (empty if none). Three
    sub-checks, same as pcap2story's check_fabrication/check_fabrication_
    group: node mentions not traceable to any incident's own fields,
    OTHER fault-type names mentioned, and RFC numbers cited anywhere in
    the WHOLE explanation that weren't actually retrieved (widened from
    the prior version, which only checked the CERTAIN/UNCERTAIN tag).

    topology_shown (2026-08-08 fix, found via this task's own self-check
    against the real checkpoint output): build_context() legitimately
    shows the model an explicit "Topology: N PEs (PE1, PE2, ...)" line
    whenever spec["topology"] is True -- every one of those PE names is
    a real fact the model actually saw, not a fabrication, but the
    tighter incident-only allowed_nodes set (matching pcap2story's own
    design intent) doesn't know that. Same class of false positive
    pcap2story itself found and fixed via _topology_derivable_nodes
    (14/88 flags traced to topology text the model legitimately had).
    Confirmed via direct testing against the real checkpoint run: PE5
    (never involved in the link_down_bfd_pe1_notrecovered incident)
    was wrongly flagged on every topology=True condition before this
    fix, and correctly stopped being flagged after it."""
    findings = []

    allowed_nodes = set()
    for inc in incidents:
        allowed_nodes |= _root_cause_or_pair_repr(inc)
        # affected_nodes removed from the incident schema (2026-08-15) --
        # for RD Collision's 3+-PE case (the one shape whose colliding-PE
        # identities aren't already covered by root_cause_node/
        # affected_node_pair above, since affected_node_group was removed
        # in the same change), colliding_routes' own dict keys are the
        # only remaining place those PE names are named.
        for n in (inc.get("colliding_routes") or {}).keys():
            allowed_nodes.add(n.upper())
    if topology_shown and topo:
        allowed_nodes |= {n["id"].upper() for n in topo["nodes"]}
    mentioned_nodes = {n.upper() for n in NODE_RE.findall(explanation)}
    fabricated_nodes = mentioned_nodes - allowed_nodes
    for n in sorted(fabricated_nodes):
        findings.append(f"[fabrication] mentions node {n!r}, not present in any fact given to the model")

    incident_fault_types = {DISPLAY_FAULT_TYPE.get(i.get("fault_type"), i.get("fault_type")) for i in incidents}
    for other_ft in ALL_FAULT_TYPES:
        if other_ft in incident_fault_types:
            continue
        if other_ft.lower() in explanation.lower():
            findings.append(f"[fabrication] mentions fault type {other_ft!r}, not one of this job's actual fault_type(s) {sorted(incident_fault_types)}")

    allowed_rfcs = set()
    for grounding in grounding_by_incident:
        for g in grounding:
            allowed_rfcs.update(m.replace(" ", "") for m in RFC_RE.findall(g["entry"]["citation"]))
    mentioned_rfcs = {m.replace(" ", "") for m in RFC_RE.findall(rfc_relevant_text(explanation))}
    fabricated_rfcs = mentioned_rfcs - allowed_rfcs
    for r in sorted(fabricated_rfcs):
        findings.append(f"[fabrication] cites {r!r}, not present in any retrieved grounding text given to the model")

    return findings


def check_rfc_grounding_content(explanation, grounding_by_incident):
    """Heuristic word-overlap between the generated text's RFC-mentioning
    sentence(s) and the actual retrieved passage text. Returns
    (checked: bool, overlap_count: int|None, note: str|None). Citation is
    "load-bearing" here whenever grounding was actually retrieved for
    this job (select_citation()/graph_traverse_retrieve() returned
    something non-empty) -- this project's natural equivalent of
    pcap2story's _citation_is_load_bearing gate."""
    grounding_texts = []
    for grouping in grounding_by_incident:
        for g in grouping:
            grounding_texts.append(g["entry"]["text"])
    if not grounding_texts:
        return False, None, None

    sentences = re.split(r"(?<=[.!?])\s+", rfc_relevant_text(explanation))
    rfc_sentences = [s for s in sentences if RFC_RE.search(s)]
    if not rfc_sentences:
        return False, None, "grounding was retrieved but no RFC-mentioning sentence found in output"

    grounding_words = set()
    for t in grounding_texts:
        grounding_words |= _significant_words(t)

    overlap_total = 0
    for s in rfc_sentences:
        overlap_total += len(_significant_words(s) & grounding_words)

    return True, overlap_total, None


def evaluate_groundedness(explanation, incidents, grounding_by_incident, folder_dir, meta, topo, topology_shown=False):
    """Runs all 6 categories for one generated text (a "job" -- one file's
    incidents, or a causal-pair job's incidents). Returns a dict with
    per-incident results for categories 1-4 and job-level results for
    categories 5-6, same split pcap2story's group-level design uses
    (fabrication/RFC-grounding are properties of the shared text, not of
    each incident separately)."""
    per_incident = []
    for inc in incidents:
        per_incident.append({
            "fault_type": inc.get("fault_type"),
            "root_cause_node_or_pair": sorted(_root_cause_or_pair_repr(inc)) or None,
            "fault_type_ok": check_fault_type(explanation, inc),
            "affected_nodes_ok": check_affected_nodes(explanation, folder_dir, meta)[0],
            "affected_nodes_missing": check_affected_nodes(explanation, folder_dir, meta)[1],
            "trigger_mechanism_ok": check_trigger_mechanism(explanation, inc)[0],
            "trigger_mechanism_expected": check_trigger_mechanism(explanation, inc)[1],
            "root_cause_self_consistent": check_root_cause_self_consistency(explanation, inc),
        })

    fabrications = check_fabrication(explanation, incidents, grounding_by_incident, topo, topology_shown=topology_shown)
    rfc_checked, rfc_overlap, rfc_note = check_rfc_grounding_content(explanation, grounding_by_incident)

    return {
        "per_incident": per_incident,
        "fabrications": fabrications,
        "rfc_grounding_checked": rfc_checked,
        "rfc_grounding_overlap": rfc_overlap,
        "rfc_grounding_note": rfc_note,
    }
