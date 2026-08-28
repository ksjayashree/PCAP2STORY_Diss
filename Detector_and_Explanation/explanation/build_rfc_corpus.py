"""RFC corpus builder for this project's explanation layer.

Fresh implementation, not copied from pcap2story (C:\\PCAP2STORY\\rule_based\\
explain\\build_rfc_corpus.py) -- referenced there for design only (leaf-level
numbered-heading chunking, boilerplate-section exclusion). The RFC .txt
source files themselves (rfc_texts/) are public IETF standards text, copied
as-is from pcap2story's rfc_texts/ folder since they're identical public
documents, not project-specific code or config.

Originally the same 13-RFC scope as pcap2story: RFC 8365 is deliberately
excluded. Per pcap2story's own build_rfc_corpus.py comment (2026-07-22):
"grepped for it in both repos -- the only reference found is inside a
commented-out block in synthcap's eval_scenarios.py (never executed), and
it does not appear anywhere in rule_based/src at all." That investigation
wasn't independently re-run here -- stated as precedent inherited from
pcap2story, not rediscovered. Re-check directly if RFC 8365 relevance is
ever questioned.

2026-08-17: added RFC 4364 (BGP/MPLS IP VPNs) and RFC 5880 (BFD) as a 14th
and 15th entry -- unlike the original 13 (inherited wholesale from
pcap2story with no per-RFC selection rationale on record), these two were
added because this project's own detector code cites them directly and
they were previously absent from the retrieval corpus entirely: RFC 4364
is cited in src/evpn_wire_verify.py (RD structure) and RFC 5880 in
src/rules/link_down.py (BFD mechanics), confirmed by grepping src/ for
"RFC \\d" this session before adding either. Source text fetched fresh
from https://www.rfc-editor.org/rfc/rfc4364.txt and .../rfc5880.txt (no
copy of either existed in this project or in pcap2story's rfc_texts/
folder) -- same plain-text IETF format as the other 13, confirmed by
inspection (numbered section headings, form-feed [Page N] footers, dotted
ToC lines) before wiring them in here.
"""
import os
import re
import json

EXPLAIN_DIR = os.path.dirname(os.path.abspath(__file__))
RFC_TEXTS_DIR = os.path.join(EXPLAIN_DIR, "rfc_texts")
CORPUS_PATH = os.path.join(EXPLAIN_DIR, "rfc_corpus.json")

RFCS = {
    "2918": "rfc2918.txt",
    "4271": "rfc4271.txt",
    "4360": "rfc4360.txt",
    "4364": "rfc4364.txt",
    "4456": "rfc4456.txt",
    "4486": "rfc4486.txt",
    "4724": "rfc4724.txt",
    "4760": "rfc4760.txt",
    "5880": "rfc5880.txt",
    "6608": "rfc6608.txt",
    "6793": "rfc6793.txt",
    "7432": "rfc7432.txt",
    "8538": "rfc8538.txt",
    "8584": "rfc8584.txt",
    "9136": "rfc9136.txt",
}

# Leaf-level numbered headings: "7.7.  MAC Mobility Extended Community" or
# "15.  MAC Mobility" or "5.1.1 ORIGIN" (1-2 spaces, both seen across files).
HEADER_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?\s{1,2}([A-Z][^\n]*)$")
TOC_DOTS_RE = re.compile(r"\.{3,}\s*\d+\s*$")  # ToC lines end in "...... 18"
PAGE_BREAK_RE = re.compile(r"^\x0c|^\s*\[Page \d+\]\s*$", re.MULTILINE)

BOILERPLATE_TITLES = {
    "iana considerations", "security considerations", "references",
    "normative references", "informative references", "acknowledgements",
    "acknowledgments", "author's address", "authors' addresses",
    "full copyright statement", "intellectual property",
    "copyright notice", "table of contents",
}

MIN_SECTION_CHARS = 40


def _strip_page_furniture(text):
    text = PAGE_BREAK_RE.sub("", text)
    lines = [ln for ln in text.split("\n") if not TOC_DOTS_RE.search(ln)]
    return "\n".join(lines)


def _split_sections(text, rfc_number):
    """Returns [{"section": "7.7", "title": "...", "text": "..."}], leaf
    sections only (every numbered heading is its own chunk, not just
    top-level) -- a heading's content runs until the next heading at any
    depth, matching pcap2story's own leaf-level design."""
    lines = text.split("\n")
    headers = []  # (line_idx, section_num, title)
    for i, ln in enumerate(lines):
        # 2026-08-17 fix: real section headings in these RFC .txt files are
        # flush-left (0 indentation); in-body numbered list items (FSM event
        # definitions, algorithm steps, etc.) use the same "N.  Text" shape
        # but are always indented -- matching against ln.strip() erased that
        # distinction, causing indented list items to be misdetected as
        # section boundaries and collide with (or shadow) the real section's
        # id/citation. Confirmed directly against rfc8584.txt: real Section 3
        # heading is flush-left ("3.  The Highest Random Weight DF Election
        # Algorithm"), while three unrelated indented list items ("   3.
        # Disruption is another problem...", "   3.  VLAN_CHANGE: ...",
        # "   3. When the timer expires...") were previously colliding on
        # the same rfc8584_3 id. Requiring flush-left origin excludes all
        # indented list items project-wide (spot-checked: RFC 7432 alone had
        # 83 such indented false-positive matches vs 79 real flush-left
        # headers under the old regex).
        m = HEADER_RE.match(ln.rstrip()) if not ln[:1].isspace() else None
        if m:
            headers.append((i, m.group(1), m.group(2).strip()))

    sections = []
    for idx, (line_idx, num, title) in enumerate(headers):
        end = headers[idx + 1][0] if idx + 1 < len(headers) else len(lines)
        body = "\n".join(lines[line_idx + 1:end]).strip()
        if title.lower().rstrip(".") in BOILERPLATE_TITLES:
            continue
        if len(body) < MIN_SECTION_CHARS:
            continue
        sections.append({
            "id": f"rfc{rfc_number}_{num}",
            "rfc": rfc_number,
            "section": num,
            "title": title,
            "citation": f"RFC {rfc_number} Section {num} ({title})",
            "text": body,
        })
    return sections


def build_corpus():
    corpus = []
    for rfc_number, fname in RFCS.items():
        path = os.path.join(RFC_TEXTS_DIR, fname)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing RFC source text: {path}")
        raw = open(path, encoding="utf-8", errors="replace").read()
        clean = _strip_page_furniture(raw)
        sections = _split_sections(clean, rfc_number)
        corpus.extend(sections)
    return corpus


if __name__ == "__main__":
    corpus = build_corpus()
    with open(CORPUS_PATH, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=1)
    print(f"Built {len(corpus)} chunks from {len(RFCS)} RFCs -> {CORPUS_PATH}")
    by_rfc = {}
    for c in corpus:
        by_rfc[c["rfc"]] = by_rfc.get(c["rfc"], 0) + 1
    for rfc, n in sorted(by_rfc.items()):
        print(f"  RFC {rfc}: {n} chunks")
