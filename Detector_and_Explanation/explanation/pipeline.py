"""Shared 9-condition explanation driver for this project. Fresh
implementation -- referenced against pcap2story's pipeline2.py
(C:\\PCAP2STORY\\rule_based\\explain\\experiment_ablation\\pipeline2.py)
for design only (the CONDITION_SPEC shape, sibling/causal/RAG/next-step
stage sequencing, CERTAIN/UNCERTAIN free-text tag + regex parse
approach), not copied.

Detection: reuses this project's own detector modules directly
(topology/vantage_parser/fusion/orchestrator), the same call chain
run_single.py and score_synthcap.py already use -- no reimplementation.

Incident shape: a "job" is one file's full list of DETECTED incidents
from its primary fault-type module (may be length 1, 2, or more --
this project's rt_misconfiguration.py/mac_mobility.py/rd_collision.py all
legitimately produce multiple DETECTED incidents for a single file,
confirmed by reading their detect() loops directly this session, unlike
an assumption that every file has exactly one incident).
"""
import os
import re
import sys
import json
import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "rules"))
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
from topology import load_topology, ground_truth
from vantage_parser import parse_vantages
from fusion import fuse_event_streams
from orchestrator import run_all_rules, annotate_precedence
from scorer_lib import MODULE_FOR_FOLDER
from citations import select_citation
from retrieval import retrieve
from next_steps import select_next_step
from groundedness import evaluate_groundedness

EXPLAIN_DIR = os.path.dirname(os.path.abspath(__file__))
ABLATION_DIR = os.path.join(EXPLAIN_DIR, "rag_kg_ablation")
# 2026-08-18: added after a real parse failure's raw output was
# permanently lost (rt_misconfig_autoderive_export_pe1_notfixed run 3,
# during the NEXT_STEP_TAG_RE two-stage-parser fix's own verification --
# nothing logged the text before the caller moved on, so that specific
# failure could never be inspected). One JSONL line per parser miss,
# append-only, best-effort (see _log_parse_failure).
PARSE_FAILURE_LOG_PATH = os.path.join(EXPLAIN_DIR, "logs", "parse_failures.jsonl")
# 2026-08-08: the .env was placed directly under explanation\ (shared
# modules root), not explanation\rag_kg_ablation\ as originally built --
# pointing here to match reality rather than asking for a move.
_ENV_PATH = os.path.join(EXPLAIN_DIR, ".env")

MODEL = "gpt-5"
# 2026-08-17: checked live against the real API before adding either
# parameter here -- "temperature" is REJECTED by gpt-5 for any value other
# than the default (1): a real call with temperature=0 returned a 400
# BadRequestError, "Unsupported value: 'temperature' does not support 0
# with this model. Only the default (1) value is supported." So
# temperature is deliberately NOT set anywhere in this file; forcing it
# would break every LLM call, not just fail to lower variance. "seed" IS
# accepted (a real call with seed=42 succeeded), though the response's own
# system_fingerprint came back None, so determinism isn't confirmed by the
# API contract itself -- SEED is applied as a best-effort measure, and
# whether it actually reduces output variance for this model has to be
# checked empirically per run, not assumed from the parameter being
# accepted.
SEED = 20260817

DISPLAY_FAULT_TYPE = {"mac_mobility": "MAC Mobility"}

# 2026-08-19: was a bare [:400] literal with no rationale anywhere in the
# codebase. Raised to the corpus's own real p75 chunk length (2,373 chars,
# measured directly off rfc_corpus.json's 404 chunks: min=56, max=35,111,
# median=1,141.5) after confirming 72.3% of chunks exceeded the old 400-char
# cap. p75 was chosen over p90/p95 for diminishing returns: it drops the
# truncated-chunk rate from 72.3% to 25.0% for +900 avg chars/chunk, while
# p90/p95 only buy another 14.9/19.8 points for roughly the same or larger
# marginal cost again, mostly chasing a small number of very long,
# un-subdivided outlier sections (worst case p90/p95 add +8-16K chars to a
# single prompt vs p75's +4-6K worst case).
RFC_EXCERPT_CHAR_LIMIT = 2373

# 2026-08-19: 101/404 corpus chunks still exceed RFC_EXCERPT_CHAR_LIMIT
# after the p75 fix above. 67 of those need exactly 2 segments to be fully
# covered; a flat 2-segment split was considered and rejected in favor of
# dynamic segmenting (as many segments as needed, up to this ceiling) so
# the 34 chunks needing 3+ segments aren't arbitrarily cut at 2 either.
# 5 was chosen as the ceiling: it fully covers every over-cap chunk except
# 3 genuine extreme outliers (measured directly off rfc_corpus.json):
#   - rfc4271_4.3   (RFC 4271 Section 4.3, UPDATE Message Format)      14,479 chars, needs 7 segments
#   - rfc4271_6     (RFC 4271 Section 6, "...Marker field...")         21,440 chars, needs 10 segments
#   - rfc4271_8.2.2 (RFC 4271 Section 8.2.2, Finite State Machine)     35,111 chars, needs 15 segments
# These three are large, sub-heading-free runs of BGP protocol prose that
# this project's leaf-level heading chunker (build_rfc_corpus.py) cannot
# split further without a chunking-strategy change -- out of scope here.
# For these three specifically, content is truncated after the 5th
# segment (5 x RFC_EXCERPT_CHAR_LIMIT = 11,865 chars) -- a documented,
# known exception, not a silent gap: still a large improvement over the
# old flat 400-char cap's ~1% coverage of rfc4271_8.2.2, even though it
# isn't full coverage of any of the three.
RFC_EXCERPT_MAX_SEGMENTS = 5


def _segment_excerpt_lines(entry):
    """Splits entry["text"] into sequential RFC_EXCERPT_CHAR_LIMIT-sized
    segments when it exceeds that cap, up to RFC_EXCERPT_MAX_SEGMENTS
    (see the constants' own comment above for which real chunks hit that
    ceiling and why). Returns a list of prompt lines, one per segment --
    all segments from one chunk are still ONE citation for grounding-slot
    budget purposes (the 2-3-per-incident retrieval count is unaffected
    by how many prompt LINES one retrieved chunk expands into;
    result["citations"] elsewhere is built from the plain, un-suffixed
    entry["citation"] string, one per retrieved chunk, not one per
    segment). Returns a single unlabeled line, unchanged from before,
    when the chunk already fits within the cap.

    2026-08-17 fix: the "(Part N of M)" segment marker used to live
    INSIDE the bracketed [citation] label itself -- since the system
    prompt tells the model to format its own RFC CITATIONS section "in
    the same ... format as any RFC excerpts given to you below," the
    model was faithfully copying the segment marker into its displayed
    citation (confirmed on a real run: "RFC 4271 Section 8.1.4 ... (Part
    2 of 2)" leaked into rr_down_bgpdkill_rr1_recovered's output). The
    marker now sits OUTSIDE the bracket -- the bracketed label is always
    the exact, plain citation string, so there is nothing segment-shaped
    left for the model to mirror into its own citation list. Segment
    tracking itself (which piece of a long chunk this is) is unchanged,
    it's purely a display-position fix."""
    text = entry["text"]
    citation = entry["citation"]
    if len(text) <= RFC_EXCERPT_CHAR_LIMIT:
        return [f"    [{citation}] {text}"]

    segments = [text[i:i + RFC_EXCERPT_CHAR_LIMIT] for i in range(0, len(text), RFC_EXCERPT_CHAR_LIMIT)]
    segments = segments[:RFC_EXCERPT_MAX_SEGMENTS]
    total = len(segments)
    return [f"    [{citation}] (excerpt continues, segment {idx} of {total} -- not part of the citation label) {seg}" for idx, seg in enumerate(segments, 1)]


def _client():
    load_dotenv(_ENV_PATH)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            f"OPENAI_API_KEY is not set in {_ENV_PATH}. Paste the real key "
            f"into that file (OPENAI_API_KEY=sk-...) before running any "
            f"condition that makes an LLM call."
        )
    from openai import OpenAI
    return OpenAI(api_key=api_key)


CONDITIONS = (
    "rule_based_only", "UNGROUNDED", "FLAT_RAG", "KG_RAG",
    "KG_RAG_NO_TOPOLOGY", "FLAT_RAG_NO_TOPOLOGY", "KG_RAG_TEMPLATE",
)

# 6-condition ablation set. Cross-incident context (sibling/causal incident
# gathering) is always included now, so build_context() calls
# _gather_causal_incidents() unconditionally -- it is no longer a spec flag.
# Each condition isolates one axis relative to KG_RAG (the main condition):
#   UNGROUNDED           - no retrieval at all (rag=None)
#   FLAT_RAG              - flat embedding retrieval instead of KG retrieval
#   KG_RAG                 - the main condition: KG retrieval, free-form next step, topology included
#   KG_RAG_NO_TOPOLOGY     - KG retrieval, topology context withheld
#   FLAT_RAG_NO_TOPOLOGY   - flat retrieval, topology context withheld
#   KG_RAG_TEMPLATE         - KG retrieval, templated (not free-form) next step
# rule_based_only is not spec-driven -- see the early return in
# run_one_condition() -- it is a zero-cost deterministic reference point.
CONDITION_SPEC = {
    "UNGROUNDED":           dict(rag=None,   next_step="free",     topology=True),
    "FLAT_RAG":             dict(rag="flat", next_step="free",     topology=True),
    "KG_RAG":               dict(rag="kg",   next_step="free",     topology=True),
    "KG_RAG_NO_TOPOLOGY":   dict(rag="kg",   next_step="free",     topology=False),
    "FLAT_RAG_NO_TOPOLOGY": dict(rag="flat", next_step="free",     topology=False),
    "KG_RAG_TEMPLATE":      dict(rag="kg",   next_step="template", topology=True),
}

# 2026-08-18: two-stage tag parsing, replacing a single whole-text regex
# search. Root cause (confirmed via 15 real re-runs of the 2 files that
# had failed): the mandated section header is "NEXT STEPS:" (plural) and
# the tag-line instruction (FREE_NEXT_STEP_SUFFIX below) asks for a
# second, near-identical "NEXT STEP:" (singular) literal directly under
# it -- the model sometimes (stochastically, not tied to any fault type,
# summary length, or citation set observed across 15 fresh samples)
# treats the header as already satisfying this and never repeats the
# inner "NEXT STEP:" prefix. A naive single-regex broadening to
# "NEXT STEPS?:" would be unsafe: re.search()'s leftmost-match behavior
# would anchor on the SECTION HEADER itself even in compliant responses
# (where the header is immediately followed by a redundant inner
# "NEXT STEP:" line), greedily swallowing that redundant prefix into the
# "recommendation" capture and corrupting output that currently parses
# fine. Splitting into two stages avoids this: first isolate the
# unambiguous NEXT STEPS section body (same boundary this project's
# format always guarantees), then look for the CERTAIN/UNCERTAIN clause
# only within that already-isolated text, treating a leading
# "NEXT STEP(S):" prefix there as optional to strip rather than required
# to search for across the whole response.
NEXT_STEPS_SECTION_RE = re.compile(
    r"NEXT STEPS:\s*(.*?)(?=\n\s*RFC CITATIONS:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
NEXT_STEP_TAG_RE = re.compile(
    r"^\s*(?:NEXT STEPS?:\s*)?(.+?)\.\s*(CERTAIN|UNCERTAIN)\s*--\s*(.+)$",
    re.IGNORECASE | re.DOTALL,
)
RFC_RE = re.compile(r"RFC\s?\d{3,5}")

# 2026-08-16 format change: the prior 4-section shape (SUMMARY/TIMESTAMP/
# NEXT STEP/REASON) is replaced by SUMMARY (timestamp folded into its own
# sentence(s), no standalone TIMESTAMP label anymore) / NEXT STEPS /
# RFC CITATIONS (a short list, its own section instead of scattered
# through free prose) / RFC GROUNDING (the prose explanation connecting
# those citations to the fault -- functionally REASON's old role, renamed
# to match what it actually contains). groundedness.py's categories 1-4
# (fault_type/nodes/mechanism/self-consistency) are unaffected, same as
# before -- they scan the whole explanation text regardless of section
# labels. Categories 5-6 (fabrication's RFC-number check, RFC-grounding
# word-overlap) DO now read from the RFC CITATIONS/RFC GROUNDING sections
# specifically instead of re-parsing RFC mentions out of free prose,
# since those citations now live in a dedicated structured section --
# see format_sections._rfc_relevant_text() usage in groundedness.py.
# NEXT_STEP_TAG_RE's justification group is bounded to stop at
# "RFC CITATIONS:" now (was "REASON:"), same reason as before: it's
# greedy up to the next section label so it doesn't swallow the rest of
# the response.
BASE_SYSTEM_PROMPT = (
    "You are a senior network operations engineer explaining an EVPN/BGP "
    "fault detected from packet capture analysis. Use ONLY the facts "
    "given -- do not invent node names, RFC numbers, or timestamps not "
    "present in the input. If multiple incidents are listed, explicitly "
    "address whether they are related. Describe only the fault(s) "
    "actually present in the facts given -- do not comment on how many "
    "incidents were provided, whether other incidents or pairs exist, or "
    "anything else about how this prompt itself was constructed.\n\n"
    "Structure your entire response as exactly four labeled sections, in "
    "this order, each starting on its own line with the label written "
    "verbatim followed by a colon:\n"
    "SUMMARY: One or two sentences stating the fault type, the affected "
    "node(s), and when it started (and recovered, if applicable) -- fold "
    "the timing into the same sentence(s) using the human-readable "
    "datetime values given in the facts, not raw epoch numbers, rather "
    "than a separate line. Write every timestamp in the exact ISO-8601 "
    "format it is given to you in (e.g. 2026-07-31T16:53:48.949Z) -- do "
    "not reformat it into prose (e.g. 'August 1, 2026 at 17:30:12 UTC') "
    "or drop the date/T-separator on a second mention within the same "
    "response. State the recovery status in plain language "
    "(e.g. 'the fault had not recovered by the end of the capture' or "
    "'the fault recovered at <time>') -- do not copy a raw field value "
    "or status code such as NOT_RECOVERED, RECOVERED, or UNKNOWN "
    "verbatim as a bare token anywhere in your response.\n"
    "NEXT STEPS: The concrete recommended action(s).\n"
    "RFC CITATIONS: A short list of the specific RFC citations that "
    "support this explanation, one per line, in the same "
    "'RFC #### Section #.# (Title)' format as the bracketed [citation] "
    "label on any RFC excerpts given to you below -- use only the exact "
    "text inside those brackets; never include any parenthetical note "
    "that appears outside the brackets (e.g. a segment/continuation "
    "marker), even if one is present next to an excerpt. Only cite RFCs "
    "actually given to you in the facts.\n"
    "RFC GROUNDING: The explanation of why this is a fault, connecting "
    "each citation listed above to the specific rule it establishes and "
    "how that rule applies to this incident.\n"
    "Do not add any text before SUMMARY or after RFC GROUNDING, and do "
    "not add any other section labels."
)
FREE_NEXT_STEP_SUFFIX = (
    "\n\nThe NEXT STEPS section's entire content must be exactly one line "
    "in this format -- yes, it repeats the word 'NEXT STEP' right after "
    "the 'NEXT STEPS:' section label you just wrote; do not treat the "
    "section label as already satisfying this, write the literal prefix "
    "again: "
    "\"NEXT STEP: <your recommendation>. CERTAIN -- <justification>.\" or "
    "\"NEXT STEP: <your recommendation>. UNCERTAIN -- <justification>.\" "
    "Use CERTAIN only if the evidence given fully supports the "
    "recommendation without further data; UNCERTAIN if it doesn't."
)

# 2026-08-18: RECOVERED-job variant of BASE_SYSTEM_PROMPT -- three
# sections instead of four. Used only when build_context() determines
# every incident in the job already recovered on its own (_all_recovered
# below); the model is told explicitly not to write a NEXT STEPS section
# at all, since one is spliced in afterward by _splice_self_resolved_
# next_steps() from recovery_status/recovered_time directly -- a
# deterministic fact, not something that needs a model recommendation or
# a CERTAIN/UNCERTAIN judgment call.
BASE_SYSTEM_PROMPT_NO_NEXT_STEPS = (
    "You are a senior network operations engineer explaining an EVPN/BGP "
    "fault detected from packet capture analysis. Use ONLY the facts "
    "given -- do not invent node names, RFC numbers, or timestamps not "
    "present in the input. If multiple incidents are listed, explicitly "
    "address whether they are related. Every incident given to you here "
    "already recovered on its own before the capture ended -- do not "
    "recommend any corrective action anywhere in your response; a "
    "separate, deterministic self-resolved statement is supplied outside "
    "your response for that. Describe only the fault(s) actually present "
    "in the facts given -- do not comment on how many incidents were "
    "provided, whether other incidents or pairs exist, or anything else "
    "about how this prompt itself was constructed.\n\n"
    "Structure your entire response as exactly three labeled sections, "
    "in this order, each starting on its own line with the label written "
    "verbatim followed by a colon:\n"
    "SUMMARY: One or two sentences stating the fault type, the affected "
    "node(s), and when it started and recovered -- fold the timing into "
    "the same sentence(s) using the human-readable datetime values given "
    "in the facts, not raw epoch numbers. Write every timestamp in the "
    "exact ISO-8601 format it is given to you in (e.g. "
    "2026-07-31T16:53:48.949Z) -- do not reformat it into prose (e.g. "
    "'August 1, 2026 at 17:30:12 UTC') or drop the date/T-separator on a "
    "second mention within the same response. State the recovery status in "
    "plain language (e.g. 'the fault recovered at <time>') -- do not "
    "copy a raw field value or status code such as RECOVERED verbatim as "
    "a bare token anywhere in your response.\n"
    "RFC CITATIONS: A short list of the specific RFC citations that "
    "support this explanation, one per line, in the same "
    "'RFC #### Section #.# (Title)' format as the bracketed [citation] "
    "label on any RFC excerpts given to you below -- use only the exact "
    "text inside those brackets; never include any parenthetical note "
    "that appears outside the brackets (e.g. a segment/continuation "
    "marker), even if one is present next to an excerpt. Only cite RFCs "
    "actually given to you in the facts.\n"
    "RFC GROUNDING: The explanation of why this was a fault, connecting "
    "each citation listed above to the specific rule it establishes and "
    "how that rule applies to this incident.\n"
    "Do not add any text before SUMMARY or after RFC GROUNDING, do not "
    "write a NEXT STEPS section yourself, and do not add any other "
    "section labels."
)


def _all_recovered(incidents):
    """True only when `incidents` is non-empty and every incident in it
    has recovery_status == 'RECOVERED' -- a job with even one
    NOT_RECOVERED (or UNKNOWN, or missing) incident is NOT all-recovered,
    so the normal free-mode NEXT STEP instruction stays in effect for the
    whole job (the non-recovered incident still needs a real
    recommendation)."""
    return bool(incidents) and all(inc.get("recovery_status") == "RECOVERED" for inc in incidents)


def _self_resolved_next_steps_text(incidents):
    """Deterministic (non-model) NEXT STEPS body for an all-recovered job
    -- sourced directly from recovery_status/recovered_time_readable (or
    move_completed_time_readable for MAC Mobility, same field-per-fault-
    type convention _base_facts() already uses), never from a model
    recommendation, since recovery_status is already fully known here
    and there is nothing to recommend or tag. Only called when
    _all_recovered() was True for this same incident list."""
    parts = []
    for inc in incidents:
        fault_type = DISPLAY_FAULT_TYPE.get(inc.get("fault_type"), inc.get("fault_type"))
        completed_time = (inc.get("move_completed_time_readable") if inc.get("fault_type") == "MAC Mobility"
                           else inc.get("recovered_time_readable"))
        if completed_time:
            parts.append(f"The {fault_type} fault self-resolved at {completed_time}; no corrective action is required.")
        else:
            parts.append(f"The {fault_type} fault self-resolved; no corrective action is required.")
    return " ".join(parts)


def _splice_self_resolved_next_steps(explanation, incidents):
    """Inserts the deterministic NEXT STEPS text above into an
    explanation generated under BASE_SYSTEM_PROMPT_NO_NEXT_STEPS (which
    asks for only SUMMARY/RFC CITATIONS/RFC GROUNDING, no NEXT STEPS
    section at all) -- inserted right before "RFC CITATIONS:" so the
    final saved/displayed text still has all four section headers in the
    usual order, matching format_sections.py's SECTION_ORDER, even though
    NEXT STEPS' content here was never model-generated. Falls back to
    appending at the end if the model didn't include an "RFC CITATIONS:"
    header at all, rather than silently dropping the self-resolved
    statement."""
    next_steps_text = _self_resolved_next_steps_text(incidents)
    next_steps_block = f"NEXT STEPS: {next_steps_text}\n\n"
    marker = "RFC CITATIONS:"
    idx = explanation.find(marker)
    if idx == -1:
        return explanation.rstrip() + "\n\n" + next_steps_block.rstrip()
    return explanation[:idx] + next_steps_block + explanation[idx:]


def _pe_nodes(topo):
    return [n["id"] for n in topo["nodes"] if n.get("role") == "PE"]


def _topology_description(topo):
    """Renders a topology's "links" and "ground_truth" sections as prose/a
    compact block instead of a raw JSON dump. Three parts:
      - PE-to-RR attachment, derived from "links" (only PE<->RR pairs;
        RR<->RR mesh links are not PE attachments and are skipped).
      - Expected route target/distinguisher per PE, from "ground_truth".
      - ESI multihoming partnerships, from "ground_truth"'s non-null esi
        values grouped by shared ESI -- explicitly states "none" when
        every esi is null, rather than omitting the line, so the model
        doesn't have to infer absence from silence."""
    pe_ids = _pe_nodes(topo)
    rr_ids = [n["id"] for n in topo["nodes"] if n.get("role") == "RR"]
    rr_id_set = set(rr_ids)

    attachment = {pe: [] for pe in pe_ids}
    for link in topo.get("links", []):
        a, b = link.get("a"), link.get("b")
        if a in attachment and b in rr_id_set:
            attachment[a].append(b)
        elif b in attachment and a in rr_id_set:
            attachment[b].append(a)

    gt = topo.get("ground_truth", {})

    lines = [f"Topology: {len(pe_ids)} PEs, {len(rr_ids)} route reflectors ({', '.join(rr_ids)})."]

    lines.append("PE-to-RR attachment:")
    for pe in pe_ids:
        rrs = attachment.get(pe) or []
        lines.append(f"  {pe} -> {', '.join(rrs) if rrs else '(no direct RR link found)'}")

    lines.append("Expected route target/route distinguisher per PE:")
    for pe in pe_ids:
        entry = gt.get(pe) or {}
        lines.append(f"  {pe}: expected_rt={entry.get('expected_rt')}, expected_rd={entry.get('expected_rd')}")

    esi_groups = {}
    for pe in pe_ids:
        esi = (gt.get(pe) or {}).get("esi")
        if esi:
            esi_groups.setdefault(esi, []).append(pe)
    lines.append("ESI multihoming partnerships:")
    if esi_groups:
        for esi, members in esi_groups.items():
            lines.append(f"  {', '.join(members)} share ESI {esi}")
    else:
        lines.append("  none -- no PE in this topology has a non-null ESI.")

    return "\n".join(lines)


NORMAL_FOLDER_TYPE = "Normal"
# Sentinel module_key for Normal folders -- distinct from every real
# MODULE_FOR_FOLDER value (all of which are display strings like "Link
# Down", "MAC Mobility", etc.), so callers can tell "this is genuinely a
# Normal baseline file" apart from "this is a fault-type file whose
# module found zero incidents" without touching MODULE_FOR_FOLDER itself.
NORMAL_MODULE_KEY = "__NORMAL__"

# multiple/<category>/<scenario>/{metadata.json, *.pcap} -- one nesting
# level deeper than <fault_type>/single/<scenario>/, since the category
# folder (e.g. catB_link_down_x2) sits between "multiple" and the actual
# scenario. MULTIPLE_MODULE_KEY mirrors NORMAL_MODULE_KEY's sentinel
# pattern -- distinct from every real MODULE_FOR_FOLDER value so callers
# can tell "this is genuinely a multi-fault-type scenario" apart from a
# Normal baseline or a single-fault-type file.
MULTIPLE_FOLDER_TYPE = "Multiple"
MULTIPLE_MODULE_KEY = "__MULTIPLE__"


def _folder_type_from_path(folder_dir):
    parent = os.path.basename(os.path.dirname(os.path.normpath(folder_dir)))
    # multiple/ scenarios sit two levels below "multiple" (multiple/
    # <category>/<scenario>/), not one -- checked before the "single"
    # check below since a multiple/ scenario's own immediate parent is
    # the category folder (e.g. "catB_link_down_x2"), never "multiple"
    # itself.
    grandparent_raw = os.path.basename(os.path.dirname(os.path.dirname(os.path.normpath(folder_dir))))
    if grandparent_raw.lower() == "multiple":
        return MULTIPLE_FOLDER_TYPE
    # Normal folders have no "single" nesting level -- the scenario
    # folder's own immediate parent is "normal"/"Normal" (case differs
    # between datasets, normalized to one sentinel value here).
    if parent.lower() == "normal":
        return NORMAL_FOLDER_TYPE
    grandparent = os.path.basename(os.path.dirname(os.path.dirname(os.path.normpath(folder_dir))))
    return grandparent if parent.lower() == "single" else None


def _mechanism_args(folder_type, folder_name):
    rdm = "masking" if "masking" in folder_name else "simple"
    return rdm


def _resolve_topology_and_vmap(folder_dir):
    norm = os.path.normpath(folder_dir).lower()
    parts = norm.split(os.sep)
    if "3rr" in parts and "output_3rr" not in norm:
        topo_path = r"C:\simulation pcap\3rr\config\topology.json"
        vmap = {"RR1": os.path.join(folder_dir, "xrr1.pcap"), "RR2": os.path.join(folder_dir, "xrr2.pcap"), "RR3": os.path.join(folder_dir, "xrr3.pcap")}
    elif "output_3rr" in norm:
        topo_path = os.path.join(os.path.dirname(EXPLAIN_DIR), "config", "topology_3rr.json")
        vmap = {"RR1": os.path.join(folder_dir, "rr1.pcap"), "RR2": os.path.join(folder_dir, "rr2.pcap"), "RR3": os.path.join(folder_dir, "rr3.pcap")}
    elif "synthcap" in norm and "output" in parts:
        topo_path = os.path.join(os.path.dirname(EXPLAIN_DIR), "config", "topology.json")
        vmap = {"RR1": os.path.join(folder_dir, "rr1.pcap"), "RR2": os.path.join(folder_dir, "rr2.pcap")}
    elif "pilot_containerlab" in parts:
        topo_path = os.path.join(os.path.dirname(EXPLAIN_DIR), "config", "topology.json")
        vmap = {"RR1": os.path.join(folder_dir, "rr1.pcap"), "RR2": os.path.join(folder_dir, "rr2.pcap")}
    else:
        raise ValueError(f"Could not resolve dataset/topology for {folder_dir!r}")
    vmap = {k: v for k, v in vmap.items() if os.path.exists(v)}
    return topo_path, vmap


def detect_incidents(folder_dir):
    """Returns (topo, module_key, incidents) -- incidents is every DETECTED
    entry in the primary module's raw output for this file (length 1+),
    not a single primary incident."""
    folder_dir = os.path.normpath(folder_dir)
    folder_type = _folder_type_from_path(folder_dir)

    if folder_type == NORMAL_FOLDER_TYPE:
        # No single fault module to look up -- MODULE_FOR_FOLDER is
        # deliberately never touched or consulted here (it backs already-
        # verified scoring logic in scorer_lib.py, a separate concern).
        # Instead run all 7 rule modules directly, exactly the way
        # scorer_lib.py's own Normal-baseline false-positive check already
        # does (run_scorer's normal_base branch, same mechanism-hint
        # defaults -- no fault was injected in Normal traffic, so these
        # hints are inert), and confirm/collect whatever DETECTED entries
        # exist across ALL of them, not just one module's output.
        topo_path, vmap = _resolve_topology_and_vmap(folder_dir)
        topo = load_topology(topo_path)
        streams = parse_vantages(vmap, topo_path)
        fused = fuse_event_streams(streams, topo_path)
        raw = run_all_rules(fused, topo, "simple")
        # Every entry in each module's list is now, by construction, a
        # genuine finding (2026-08-15: modules return [] for "nothing
        # found" instead of a DETECTED/NOT_DETECTABLE_STRUCTURAL/
        # NO_SIGNAL_FOUND placeholder object).
        incidents = [i for entries in raw.values() for i in entries]
        return topo, folder_dir, NORMAL_MODULE_KEY, incidents, raw

    if folder_type == MULTIPLE_FOLDER_TYPE:
        # 2026-08-19: multiple/<category>/<scenario>/ files genuinely
        # contain 2+ real, distinct fault types by design (confirmed via
        # real metadata.json: "incidents": [...], a list) -- there is no
        # single MODULE_FOR_FOLDER key that applies, so this uses the
        # same "run all 7 modules, collect every real DETECTED entry"
        # pattern as the Normal-folder branch above, not because these
        # are baseline/no-fault files (they aren't), but because the
        # same mechanism -- don't assume a single primary module,
        # collect whatever every module actually found -- is exactly
        # what's needed here too. Confirmed directly (bypassing this
        # gate manually before adding it) that run_all_rules() already
        # detects the real fault types correctly on these files; this
        # branch doesn't change detection logic at all, only makes it
        # reachable through detect_incidents().
        topo_path, vmap = _resolve_topology_and_vmap(folder_dir)
        topo = load_topology(topo_path)
        streams = parse_vantages(vmap, topo_path)
        fused = fuse_event_streams(streams, topo_path)
        raw = run_all_rules(fused, topo, "simple")
        incidents = [i for entries in raw.values() for i in entries]
        return topo, folder_dir, MULTIPLE_MODULE_KEY, incidents, raw

    if folder_type not in MODULE_FOR_FOLDER:
        raise ValueError(f"Unrecognized folder_type {folder_type!r} for {folder_dir!r}")
    module_key = MODULE_FOR_FOLDER[folder_type]
    folder_name = os.path.basename(folder_dir)
    topo_path, vmap = _resolve_topology_and_vmap(folder_dir)
    topo = load_topology(topo_path)
    streams = parse_vantages(vmap, topo_path)
    fused = fuse_event_streams(streams, topo_path)

    rdm = _mechanism_args(folder_type, folder_name)
    raw = run_all_rules(fused, topo, rdm)

    # Normally raw[module_key] (the module matching this folder's own
    # path label) already holds the real finding. But the folder-path
    # label is only a naming convention, not a guarantee -- confirmed via
    # direct investigation (esdf_toggle_link_pe1_notrecovered,
    # mac_mobility_cleanmove_xpe6to7_settled, 2026-08-20) that a folder's
    # own labeled module can come back empty while the real injected
    # fault was actually detected under a DIFFERENT module's key in this
    # same `raw` dict. So: use raw[module_key] only when it's actually
    # non-empty; otherwise fall back to scanning every module in `raw`
    # and collect every non-empty, trigger_mechanism-bearing entry found
    # elsewhere (mirroring how the Normal/Multiple branches above already
    # collect across all modules -- a non-empty entry is, by construction,
    # a genuine finding under the current schema, same convention as
    # those branches use), rather than silently returning an empty
    # incident list for a file that does have a real, detected fault.
    own_entries = raw.get(module_key, [])
    if own_entries:
        incidents = list(own_entries)
    else:
        incidents = [
            e for entries in raw.values() for e in entries
            if e.get("trigger_mechanism")
        ]
        if incidents:
            found_types = sorted({e["fault_type"] for e in incidents})
            module_key = "+".join(found_types)
    return topo, folder_dir, module_key, incidents, raw


def _base_facts(incident):
    fault_type = incident.get("fault_type")
    display_ft = DISPLAY_FAULT_TYPE.get(fault_type, fault_type)
    node = incident.get("root_cause_node")
    if not node:
        pair = incident.get("affected_node_pair")
        nodes = incident.get("affected_nodes")
        if pair:
            node = ",".join(sorted(pair.values()))
        elif nodes:
            node = ",".join(sorted(nodes))
    # mac_mobility.py renamed recovered_time_readable to
    # move_completed_time_readable (2026-08-16, "recovered" never applied
    # to a MAC move) -- read the right field per fault type rather than
    # losing the completion timestamp from every MAC Mobility explanation.
    completed_time = (incident.get("move_completed_time_readable") if fault_type == "MAC Mobility"
                       else incident.get("recovered_time_readable"))
    return {
        "fault_type": display_ft,
        "trigger_mechanism": incident.get("trigger_mechanism"),
        "root_cause_node_or_pair": node,
        "recovery_status": incident.get("recovery_status"),
        # Human-readable, UTC (schema.py's build_result() derives these
        # automatically from time_of_first_fault/recovered_time) --
        # LLM-facing context only shows these now, not the raw epoch
        # floats. The raw fields themselves are untouched everywhere else
        # (scoring/precedence/gap arithmetic all keep reading
        # time_of_first_fault/recovered_time directly, unaffected by this).
        "time_of_first_fault": incident.get("time_of_first_fault_readable"),
        "recovered_time": completed_time,
    }


def _gather_causal_incidents(primary_incidents, raw, topo):
    """This project's one real causal relationship (MAC Mobility<->ESDF
    Toggle co-occurrence, and Link Down<->RR Down/PE Cease co-occurrence)
    is CROSS-MODULE -- run_all_rules() always runs all 7 modules, but
    detect_incidents() only surfaces the PRIMARY module's DETECTED
    entries. A primary incidents list of length 1 would never see its
    real causal partner (which lives under a DIFFERENT module_key in the
    same `raw` dict) without this step. Only expands when exactly 1
    primary incident exists and orchestrator.annotate_precedence() finds
    a genuine CONFIRMED_COOCCURRENCE partner for it -- reuses this
    project's own already-verified precedence logic rather than
    reimplementing causal-chain detection. Returns (incidents, causal_text)."""
    if len(primary_incidents) != 1:
        return primary_incidents, None
    try:
        # fused_events not available in this function's scope (only raw/
        # topo are passed in) -- Rule 6 (DF role vs ESDF Toggle) simply
        # doesn't fire here, same as every caller before Rule 6 existed;
        # Rules 1-5 are unaffected since none of them need raw events.
        precedence = annotate_precedence(raw, topo)
    except Exception:
        return primary_incidents, None

    primary = primary_incidents[0]
    primary_ft = primary.get("fault_type")
    for module_key, entries in precedence.items():
        module_list = raw.get(module_key, [])
        for idx, e in enumerate(entries):
            if e.get("status") != "CONFIRMED_COOCCURRENCE" or "co_occurring_with" not in e:
                continue
            partner = module_list[e["index"]] if e.get("index") is not None and e["index"] < len(module_list) else None
            if partner is None or partner is primary or partner.get("fault_type") == primary_ft:
                continue
            causal_text = (
                f"This incident and its {module_key} counterpart are a confirmed real "
                f"co-occurrence, not two independent faults -- the SAME underlying event "
                f"observed by two detection modules ({e.get('reason', '')})."
            )
            return [primary, partner], causal_text
    return primary_incidents, None


def build_context(folder_dir, incidents, raw, topo, spec):
    """Returns (system_prompt, user_context, causal_text, grounding_by_incident_index,
    incidents, all_recovered) -- incidents is the list actually described
    to the model, which may be LARGER than the caller's input (see
    _gather_causal_incidents: a cross-module causal partner can get
    folded in). Callers must use THIS returned list for anything that
    needs to match what the model was actually shown (e.g. groundedness
    checking), not their original input list. all_recovered (2026-08-18)
    is True only when spec["next_step"] == "free" AND every incident in
    that same returned list has recovery_status == "RECOVERED" -- callers
    use it to skip tag parsing/retry entirely and splice in a
    deterministic self-resolved NEXT STEPS instead of asking the model
    for one (see _splice_self_resolved_next_steps)."""
    incidents, causal_text = _gather_causal_incidents(incidents, raw, topo)

    facts_list = [_base_facts(inc) for inc in incidents]

    # k=2 here is a target, not a hard count -- retrieve()/
    # graph_traverse_retrieve() (2026-08-17) return k+1 entries instead of
    # k whenever the (k+1)th candidate is within SCORE_TIE_TOLERANCE of
    # the kth, rather than silently dropping a near-tied RFC section. So
    # each grounding list below is length 2 OR 3, not always exactly 2 --
    # the prompt-assembly loop right below already iterates `grounding`
    # generically (`for g in grounding`), so no count assumption needed
    # there; this comment just documents why the length can vary.
    grounding_by_incident = []
    if spec["rag"] == "flat":
        for inc in incidents:
            grounding_by_incident.append(select_citation(inc, k=2))
    elif spec["rag"] == "kg":
        from rfc_knowledge_graph.traversal import graph_traverse_retrieve
        from citations import _query_for_incident, _RT_MISCONFIG_ES_IMPORT_TERMS, _RT_MISCONFIG_BASE_TERMS, ES_IMPORT_TRIGGER_MECHANISM
        for inc in incidents:
            q = _query_for_incident(inc)
            if inc.get("fault_type") == "RT Misconfiguration":
                q += _RT_MISCONFIG_ES_IMPORT_TERMS if inc.get("trigger_mechanism") == ES_IMPORT_TRIGGER_MECHANISM else _RT_MISCONFIG_BASE_TERMS
            hits = graph_traverse_retrieve(q, k=2)
            grounding_by_incident.append([{"entry": h["node"], "score": h["score"]} for h in hits])
    else:
        grounding_by_incident = [[] for _ in incidents]

    lines = []
    if spec["topology"]:
        lines.append(_topology_description(topo))
    for i, (inc, facts, grounding) in enumerate(zip(incidents, facts_list, grounding_by_incident), 1):
        lines.append(f"\nIncident {i}:")
        for k, v in facts.items():
            lines.append(f"  {k}: {v}")
        if grounding:
            # Length is 2 or 3 (see comment above grounding_by_incident) --
            # each excerpt is independently segmented at RFC_EXCERPT_CHAR_LIMIT
            # (see _segment_excerpt_lines), so a 3rd near-tied excerpt just
            # adds its own bounded segment line(s), it doesn't change the
            # segmenting behavior for the others. One retrieved chunk can
            # expand into multiple prompt lines (one per segment) but is
            # still one citation against the 2-3 slot budget.
            lines.append("  Grounding RFC excerpts:")
            for g in grounding:
                lines.extend(_segment_excerpt_lines(g["entry"]))
        if spec["next_step"] == "template":
            step = select_next_step(inc, topo)
            if step:
                lines.append(f"  recommended_next_step (deterministic): {step}")
    if len(incidents) > 1:
        lines.append(
            "\nMore than one incident is listed above. Check whether they share a "
            "root cause, an ESI/multihoming partnership, or are otherwise related "
            "before treating them as independent."
        )
    if causal_text:
        lines.append(f"\nCausal note: {causal_text}")

    # 2026-08-18: RECOVERED-job handling. Only applies in "free" next-step
    # mode -- "template"/None modes have their own separate, already-
    # deterministic NEXT STEP mechanics (select_next_step()) untouched by
    # this. all_recovered is True only when EVERY incident in this job
    # (post-causal-expansion, so a 2-incident causal pair is checked as a
    # whole) has recovery_status == "RECOVERED" -- a job with one
    # RECOVERED incident and one NOT_RECOVERED partner keeps the normal
    # free-mode instruction unchanged, since the non-recovered incident
    # still needs a real recommendation.
    all_recovered = spec["next_step"] == "free" and _all_recovered(incidents)
    if all_recovered:
        system_prompt = BASE_SYSTEM_PROMPT_NO_NEXT_STEPS
    else:
        system_prompt = BASE_SYSTEM_PROMPT
        if spec["next_step"] == "free":
            system_prompt += FREE_NEXT_STEP_SUFFIX

    return system_prompt, "\n".join(lines), causal_text, grounding_by_incident, incidents, all_recovered


def _log_parse_failure(field, explanation, folder_dir=None, condition=None):
    """Append-only, best-effort side-effect log of a parser miss --
    2026-08-18. Does NOT change any caller's return value or control
    flow: callers still return None (or whatever they already return)
    exactly as before; this is purely a write, called right before that
    return. Never raises -- a logging failure must not break real
    explanation generation, so any exception here is swallowed rather
    than propagated. One JSON object per line (JSONL), so a partially
    written file from a crash mid-write only corrupts its own last line,
    not entries already flushed."""
    try:
        os.makedirs(os.path.dirname(PARSE_FAILURE_LOG_PATH), exist_ok=True)
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "file": folder_dir,
            "incident_name": os.path.basename(os.path.normpath(folder_dir)) if folder_dir else None,
            "condition": condition,
            "field": field,
            "raw_output": explanation,
        }
        with open(PARSE_FAILURE_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def parse_next_step_tag(explanation, folder_dir=None, condition=None):
    """Two-stage parse (2026-08-18, replacing a single whole-text regex
    search -- see NEXT_STEPS_SECTION_RE's comment above for why). Stage 1
    isolates the NEXT STEPS section body via its unambiguous boundary
    (from the "NEXT STEPS:" header to the "RFC CITATIONS:" header, or end
    of string). Stage 2 looks for the CERTAIN/UNCERTAIN clause only
    within that already-isolated text, tolerating a redundant leading
    "NEXT STEP(S):" prefix if the model wrote one (the instructed,
    compliant shape) but not requiring it (the observed non-compliant
    shape, where the section header alone was treated as satisfying the
    instruction) -- either way the result is the same three fields.

    folder_dir/condition are optional, logging-only context (which file
    and which ablation condition this parse attempt came from) -- passing
    them doesn't change parsing behavior at all, they're only used if a
    failure needs to be logged via _log_parse_failure."""
    section_match = NEXT_STEPS_SECTION_RE.search(explanation)
    if not section_match:
        _log_parse_failure("NEXT_STEPS_SECTION_RE (NEXT STEPS section not found at all)", explanation, folder_dir, condition)
        return None
    section_body = section_match.group(1).strip()
    tag_match = NEXT_STEP_TAG_RE.match(section_body)
    if not tag_match:
        _log_parse_failure("NEXT_STEP_TAG_RE (tag/recommendation/justification not found within NEXT STEPS section)", explanation, folder_dir, condition)
        return None
    return {"recommendation": tag_match.group(1).strip(), "tag": tag_match.group(2).upper(), "justification": tag_match.group(3).strip()}


def _strip_next_step_tag_prefix(explanation, tag):
    """2026-08-17 display cleanup, updated 2026-08-18 for the two-stage
    parser above -- the system prompt instruction that produces
    "NEXT STEP: <rec>. CERTAIN/UNCERTAIN -- <justification>." is left
    untouched; this does not re-parse anything, it just replaces the
    already-located NEXT STEPS section body (re-locating the same span
    parse_next_step_tag() used, via NEXT_STEPS_SECTION_RE, rather than
    re-running NEXT_STEP_TAG_RE against the whole explanation -- that
    regex is now anchored to match only a standalone isolated section
    body, not a mid-string span, so it can't be used as a whole-text
    substitution pattern anymore) down to just "<recommendation>." in the
    text that gets saved/displayed. The CERTAIN/UNCERTAIN tag and
    justification aren't dropped -- they're already the single source of
    truth in the separate `tag` dict (result["tag"]), so this only
    removes their duplicate appearance inside the free-text explanation.
    No-op when tag is None (template conditions, or "free" conditions
    where the model's output didn't match at all -- nothing to clean up,
    and nothing to silently invent)."""
    if not tag:
        return explanation
    section_match = NEXT_STEPS_SECTION_RE.search(explanation)
    if not section_match:
        # Shouldn't happen if tag is non-None (parse_next_step_tag found
        # this same section to produce it), but never corrupt text we
        # can't re-locate.
        return explanation
    start, end = section_match.span(1)
    return explanation[:start] + f"{tag['recommendation']}." + explanation[end:]


def _append_confidence_line(explanation, tag):
    """2026-08-19: appends a real, visible trailing "CONFIDENCE: CERTAIN/
    UNCERTAIN -- <justification>" line after RFC GROUNDING, code-appended
    (never model-written) using the same tag dict _strip_next_step_tag_
    prefix() already draws from -- CERTAIN/UNCERTAIN and its justification
    were always computed, they just weren't visible anywhere in the
    displayed/saved explanation text itself before this. No-op when tag
    is None (recovered jobs, non-"free" conditions, or a persistent parse
    failure after retry) -- same "no tag, no line" rule those cases
    already followed for result["tag"] itself, now extended to this
    trailing line so the two stay consistent."""
    if not tag:
        return explanation
    return explanation.rstrip() + f"\n\nCONFIDENCE: {tag['tag']} -- {tag['justification']}"


def _generate_explanation(client, system_prompt, context, spec, all_recovered, described_incidents, folder_dir, condition):
    """Shared LLM-call + tag-parse + retry-once + recovered-splice logic
    for both of run_one_condition()'s branches (per-incident and main) --
    factored out 2026-08-18 so both branches behave identically instead
    of duplicating this. Returns (text, tag, n_calls).

    tag is None in exactly three cases: this job isn't in "free"
    next-step mode; it's an all-recovered job (no tag concept at all --
    see _all_recovered/BASE_SYSTEM_PROMPT_NO_NEXT_STEPS); or a genuine
    parse failure persisted after one retry (both attempts already
    individually logged via parse_next_step_tag -> _log_parse_failure,
    nothing extra needed here).

    n_calls is 1 normally, 2 only if a retry was actually made -- a
    missing tag on a NOT_RECOVERED free-mode incident is worth one retry
    given the model's confirmed stochastic (not structurally reproducible)
    non-compliance with the tag-line format."""
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": context}],
        seed=SEED,
    )
    text = response.choices[0].message.content
    n_calls = 1
    tag = None

    if spec["next_step"] == "free" and not all_recovered:
        tag = parse_next_step_tag(text, folder_dir=folder_dir, condition=condition)
        if tag is None:
            retry_response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": context}],
                seed=SEED,
            )
            retry_text = retry_response.choices[0].message.content
            n_calls = 2
            retry_tag = parse_next_step_tag(retry_text, folder_dir=folder_dir, condition=condition)
            if retry_tag is not None:
                text, tag = retry_text, retry_tag
            # else: both attempts failed to produce a parseable tag --
            # tag stays None, a genuine persistent failure. Both attempts
            # were already logged individually by parse_next_step_tag().
    elif spec["next_step"] == "free" and all_recovered:
        text = _splice_self_resolved_next_steps(text, described_incidents)

    return text, tag, n_calls


def _load_meta(folder_dir):
    meta_path = os.path.join(folder_dir, "metadata.json")
    if not os.path.exists(meta_path):
        return {}
    return json.load(open(meta_path))


def rule_based_only_dump(incidents):
    lines = []
    for i, inc in enumerate(incidents, 1):
        facts = _base_facts(inc)
        lines.append(f"Incident {i}: " + ", ".join(f"{k}={v}" for k, v in facts.items()))
    return "\n".join(lines)


def _zero_incident_text(module_key, raw):
    """Two distinct, deterministic narratives -- no LLM call either way --
    since a Normal file and a fault file with zero detections mean
    different things and must not be worded the same way. module_key ==
    NORMAL_MODULE_KEY means every one of the 7 rule modules was checked
    and none fired; any other module_key means a specific fault-type
    module was checked and found nothing (or found the fault
    structurally undetectable by design)."""
    if module_key == NORMAL_MODULE_KEY:
        return (
            "No incidents were detected in this capture. All seven fault "
            "detection modules were checked against this capture's fused "
            "event timeline, and none found a matching fault pattern, "
            "consistent with this being a normal traffic baseline."
        )
    if module_key == MULTIPLE_MODULE_KEY:
        return (
            "No incidents were detected in this capture. All seven fault "
            "detection modules were checked against this capture's fused "
            "event timeline, and none found a matching fault pattern -- "
            "unexpected for a file in the multiple/ corpus, which is "
            "designed to contain two or more real, distinct faults."
        )
    # detectability_status removed from the incident schema (2026-08-15) --
    # "nothing found" is now always a bare [] regardless of the reason
    # (genuinely searched and found nothing, or an out-of-scope mechanism),
    # so there is no longer a status to distinguish those cases here.
    return f"No incidents were detected for {module_key} in this capture."


def run_one_condition(folder_dir, condition, client=None):
    topo, folder_dir, module_key, incidents, raw = detect_incidents(folder_dir)
    if not incidents:
        text = _zero_incident_text(module_key, raw)
        return {
            "condition": condition, "llm_called": False,
            "explanation": text, "note": text,
            "citations": [], "groundedness": None,
            "causal_text": None, "n_incidents": 0,
        }

    if condition == "rule_based_only":
        return {"condition": condition, "llm_called": False,
                "explanation": rule_based_only_dump(incidents), "citations": []}

    spec = CONDITION_SPEC[condition]
    client = client or _client()
    meta = _load_meta(folder_dir)

    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = build_context(folder_dir, incidents, raw, topo, spec)
    text, tag, n_calls = _generate_explanation(client, system_prompt, context, spec, all_recovered, described_incidents, folder_dir, condition)
    grounded = evaluate_groundedness(text, described_incidents, grounding, folder_dir, meta, topo, topology_shown=spec["topology"])
    display_text = _strip_next_step_tag_prefix(text, tag)
    display_text = _append_confidence_line(display_text, tag)
    result = {
        "condition": condition, "llm_called": True, "n_calls": n_calls,
        "explanation": display_text,
        "citations": [g["entry"]["citation"] for grp in grounding for g in grp],
        "causal_text": causal_text,
        "groundedness": grounded,
        "n_incidents": len(described_incidents),
    }
    if tag is not None:
        result["tag"] = tag
    return result
