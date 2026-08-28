"""Display-only formatting helper for pipeline.py's structured explanation
text (SUMMARY:/NEXT STEPS:/RFC CITATIONS:/RFC GROUNDING: labeled sections,
introduced 2026-08-10, reshaped 2026-08-16 -- the prior 4-section format
was SUMMARY/TIMESTAMP/NEXT STEP/REASON; TIMESTAMP was folded into SUMMARY's
own sentence(s) rather than kept as a separate label, NEXT STEP became
NEXT STEPS (plural), and REASON's old free-prose RFC citations were split
into a dedicated RFC CITATIONS list plus an RFC GROUNDING explanation).
Does NOT touch generation -- pipeline.py's system prompt, build_context(),
or run_one_condition() are untouched by this module; it only reformats an
already-generated `explanation` string for human reading, console or file.
Splits on the four section labels (verbatim, start-of-line, case-sensitive
to match what BASE_SYSTEM_PROMPT actually requires) rather than assuming
fixed line positions, since a section's own content can itself span
multiple lines (confirmed in the 5-file regen: esdf_toggle_repeated_pe1's
NEXT STEPS section is 3 lines, one per incident).
"""
import re

SECTION_ORDER = ("SUMMARY", "NEXT STEPS", "RFC CITATIONS", "RFC GROUNDING")

# Matches a section label at the start of a line (allowing leading
# whitespace), capturing which label it is. Used to split the explanation
# text into {label: content} without assuming labels appear in order or
# that every explanation has all four (rule_based_only/note-only results
# never go through this format at all -- callers should only invoke this
# on real LLM explanation text).
_SECTION_RE = re.compile(
    r"^\s*(SUMMARY|NEXT STEPS|RFC CITATIONS|RFC GROUNDING):\s*",
    re.MULTILINE,
)


def parse_sections(explanation):
    """Returns an ordered dict-like list of (label, content) pairs found in
    `explanation`, content trimmed of leading/trailing blank lines. Any
    text before the first recognized label (there shouldn't be any, per
    BASE_SYSTEM_PROMPT) is dropped silently -- this is a display
    formatter, not a validator; callers who need to verify structure
    should check parse_sections(text) covers all of SECTION_ORDER
    themselves."""
    matches = list(_SECTION_RE.finditer(explanation))
    sections = []
    for i, m in enumerate(matches):
        label = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(explanation)
        content = explanation[start:end].strip()
        sections.append((label, content))
    return sections


def rfc_relevant_text(explanation):
    """Returns just the RFC CITATIONS + RFC GROUNDING section content
    (joined), the part of the response that actually carries RFC
    citations/mentions under the 2026-08-16 format -- used by
    groundedness.py's fabrication and RFC-grounding-content checks so
    they scan the structured citation section instead of re-parsing RFC
    mentions out of the whole free-text response. Falls back to the
    entire explanation when no recognized section labels are found (e.g.
    older cached explanations generated under the prior REASON-only
    format), same fallback spirit as parse_sections()."""
    sections = dict(parse_sections(explanation))
    if not sections:
        return explanation
    return "\n".join(filter(None, [sections.get("RFC CITATIONS", ""), sections.get("RFC GROUNDING", "")]))


def format_explanation_console(explanation, indent=""):
    """Plain-text console rendering: one UPPERCASE heading line per
    section, underlined, blank line between sections. Falls back to the
    raw text unchanged if no recognized section labels are found (e.g.
    older cached explanations generated before this structure existed)."""
    sections = parse_sections(explanation)
    if not sections:
        return explanation
    blocks = []
    for label, content in sections:
        heading = f"{indent}{label}"
        blocks.append(f"{heading}\n{indent}{'-' * len(label)}\n{indent}{content}")
    return ("\n\n".join(blocks)) + "\n"


def format_explanation_markdown(explanation):
    """Markdown rendering: '### LABEL' heading per section, blank line
    between sections. Falls back to the raw text unchanged if no
    recognized section labels are found."""
    sections = parse_sections(explanation)
    if not sections:
        return explanation
    blocks = [f"### {label}\n\n{content}" for label, content in sections]
    return "\n\n".join(blocks) + "\n"


RESULT_VIEW_FIELDS = ("Summary", "Recommendation", "Citations matched", "Justification", "RFC explanation")


def format_result_view(result):
    """Trimmed 5-field key-value view of a run_one_condition()-shaped
    result dict (the {"explanation": ..., "tag": {...}, "citations": [...]}
    shape pipeline.py's non-per-incident branch returns) -- NOT a
    reformatting of the 4-section explanation text alone, since two of the
    5 requested fields (Recommendation, Justification) live in `result["tag"]`
    and one (Citations matched) lives in `result["citations"]`, outside the
    explanation string entirely.

    Deliberately drops the NEXT STEPS section's raw text (already surfaced
    via Recommendation/Justification from `result["tag"]`) and the full
    groundedness/fabrications block -- those aren't part of this view, but
    nothing is deleted from the underlying result dict itself; this
    function only reads it and returns a new formatted string. There is no
    longer a standalone TIMESTAMP section to drop (folded into SUMMARY as
    of the 2026-08-16 format change).

    Each field is its own labeled block ("Label:\\n<value>") separated by a
    blank line, real visual separation rather than one paragraph with
    embedded newlines. Falls back to an empty string for any field that's
    genuinely absent (e.g. `tag` is None for non-"free"-next-step
    conditions, or `citations` is empty for `rag=None` conditions) rather
    than raising -- this is a display formatter, not a validator."""
    explanation = result.get("explanation") or ""
    sections = dict(parse_sections(explanation))
    tag = result.get("tag") or {}
    citations = result.get("citations") or []

    citations_block = "\n".join(citations) if citations else "(none)"

    fields = [
        ("Summary", sections.get("SUMMARY", "")),
        ("Recommendation", tag.get("recommendation", "")),
        ("Citations matched", citations_block),
        ("Justification", tag.get("justification", "")),
        ("RFC explanation", sections.get("RFC GROUNDING", "")),
    ]
    blocks = [f"{label}:\n{value}" for label, value in fields]
    return "\n\n".join(blocks) + "\n"
