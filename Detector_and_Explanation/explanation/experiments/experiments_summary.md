# Experiments Summary — Explanation-Generation Pipeline (5 experiments)

All five experiments used the same 5 fixed test files (rd_collision_pe3_pe4_fixed,
mac_mobility_cleanmove_xpe3to0_settled, esdf_toggle_repeated_pe1,
mac_mobility_repeated_pe1_pe2, esdf_toggle_full_failure_no_recovery_pe6pe7),
looked up only via the cached detection results (no raw pcap re-parsing), and the
"richest" explanation setting (llm_rag_kg_free: topology + sibling/causal context +
knowledge-graph RFC retrieval + free-form next-step).

## Experiment 1 — Multi-agent draft + critique
- A first AI call writes a normal explanation ("the draft"). A second, separate AI
  call — given the draft, the real detector facts, and the RFC text the drafter
  saw — checks it for mistakes and either approves it or rewrites it.
- The critique step changed the draft in **2 of 5** files.
- Manual read (my own judgment, not a formal score): the 2 corrected versions
  tightened wording around root-cause node naming and RFC section precision; they
  did not introduce new errors. The 3 approved-as-is drafts looked accurate on
  read-through too, so the critique step wasn't rubber-stamping — it genuinely had
  nothing worth changing on those.

## Experiment 2 — Retrieval tuning (asking for more RFC context)
- Compared the normal amount of retrieved RFC material (2 passages per source) against
  double that amount (4 passages per source) for the same 5 files.
- Wider retrieval consistently pulled in 2 extra RFC citations per file. Reading the
  extra passages: they were on-topic (same protocol area, e.g. more DF-election or
  MAC-learning detail), not noise — but for the esdf_toggle_repeated_pe1 file the
  extra passages were largely repeats of the same citation shown for multiple
  incidents rather than new distinct grounding, so "more" didn't always mean "more
  varied" content.
- Explanation text length grew modestly (a few hundred extra characters) with more
  retrieval; the core facts/summary did not change, only supporting detail.

## Experiment 3 — Teaching the model from a past mistake (few-shot correction)
- Two real examples of a documented mistake pattern (citing an RFC section slightly
  wrong — "ES-Import Route" instead of "ES-Import Route Target", and overstating a
  conditional BGP requirement as absolute) were shown to the model before it wrote
  its explanation, compared against explanations written without that reminder.
- None of the 5 test files' outputs, with or without the reminder, actually
  reproduced the exact flagged phrases — so this specific known error pattern
  simply wasn't present as a baseline problem in these 5 files to begin with. Stated
  plainly rather than forcing a result: no visible reduction to measure, because the
  error wasn't happening in the "without" version either.
- The few-shot-primed versions were, if anything, slightly more precise/verbose in
  their RFC citation language generally (consistent with "being told to be careful"),
  but this is a soft read, not a scored comparison.

## Experiment 4 — Comparing three model sizes and merging them
- gpt-5, gpt-5-mini, and gpt-5-nano versions of the same explanation were compared,
  then one more AI call combined all three into a single best version and flagged any
  place they disagreed on a fact.
- **Important caveat:** all three models come from the same company/family (OpenAI)
  — this is not a comparison across genuinely different AI systems, so agreement
  between them proves less than it would with independent providers.
- The three versions disagreed on a factual point in **1 of 5** files. The combined
  ("reconciled") version in that case picked the more specific/consistent claim and
  flagged the disagreement explicitly, which read as a sensible resolution on manual
  check.

## Experiment 5 — Automatic fact-check-and-retry loop
- For each file: write an explanation, automatically fact-check every claim in it
  against the real detector data (and RFC text for protocol claims), and if any claim
  failed the check, rewrite the explanation with the specific failure fed back as a
  correction instruction — up to 3 tries total.
- **1 of 5** files needed a second attempt (mac_mobility_cleanmove_xpe3to0_settled);
  after that one retry its explanation passed with no more flagged claims. The other
  4 files passed on the very first attempt.
- **0 of 5** files hit the 3-try cap while still failing — every file that needed a
  retry succeeded well within the limit.
- Extra time cost of the fact-check-and-fix loop, file by file (added seconds beyond
  a single plain generation call): rd_collision_pe3_pe4_fixed +66s,
  mac_mobility_cleanmove_xpe3to0_settled +430s (the one that needed a retry — this
  cost roughly 7x more because of the second full generation + a second full fact-check
  pass), esdf_toggle_repeated_pe1 +188s, mac_mobility_repeated_pe1_pe2 +190s,
  esdf_toggle_full_failure_no_recovery_pe6pe7 +93s. Fact-checking itself is the
  dominant cost even on a single pass (one check call per claim extracted).

## Totals across all 5 experiments
- **Total LLM API calls:** approximately 152
  (Experiment 1: 10 — 5 draft + 5 critique calls.
  Experiment 2: 10 — 5 files × 2 retrieval-width conditions.
  Experiment 3: 10 — 5 files × 2 few-shot conditions.
  Experiment 4: 5 — 1 reconciliation call per file; the 15 individual gpt-5/mini/nano
  explanations were all reused from an earlier same-night test run, not
  regenerated, so no additional calls were needed there.
  Experiment 5: approximately 117 — 6 explanation-generation calls (5 files, 1 of
  which needed a 2nd attempt) plus roughly 111 fact-check calls (1 claim-extraction
  call + 1 verification call per individual claim, across all files/attempts).)
- **Total wall-clock time:** roughly 45–50 minutes for the 5 experiment scripts
  themselves (script output timestamps ran from about 14:10 to 14:56), the large
  majority of it inside Experiment 5's fact-checking loop, plus separate setup/design
  time earlier in the session building the shared helper scripts.

## Ambiguous decisions made (judgment calls), and why
1. **Retrieval widening amount (Experiment 2):** doubled both flat-RAG and
   knowledge-graph-RAG retrieval width from 2 to 4 passages per source — a simple,
   symmetric increase, not further tuned, because the task asked for "a reasonable
   increase" without specifying a target number.
2. **Few-shot examples used (Experiment 3):** used both of the two real flagged-claim
   examples found (the RFC-7432-8.1.1 "ES-Import Route" vs "ES-Import Route Target"
   slip, plus a second real one found by scanning the same source file — an RFC-8538
   claim that overstated a conditional requirement as absolute), since a second
   genuine example existed, rather than stopping at one.
3. **Baseline used for "without few-shot" (Experiment 3):** generated a fresh plain
   explanation in Experiment 3 itself rather than reusing Experiment 1's draft,
   because Experiment 1's draft already went through a critique/correction pass and
   would not have been a clean, unmodified baseline to compare against.
4. **Critique prompt design (Experiment 1):** designed the critique agent's required
   output format as `VERDICT: APPROVED` / `VERDICT: CORRECTED` plus an `ISSUES:` line
   and, only when corrected, a full replacement 4-section explanation — chosen so the
   verdict and any corrected text could be parsed reliably without guessing at prose.
5. **Ensemble reuse vs regeneration (Experiment 4):** reused already-generated
   gpt-5/gpt-5-mini/gpt-5-nano explanations for all 5 files from an earlier same-night
   model-comparison test file rather than regenerating them, since they matched the
   same file set and same generation condition — this avoided 15 redundant API calls.
6. **QAG protocol-claim context in Experiment 5's retry loop:** the bounded-retry
   script judges "protocol" claims (RFC-semantics claims) without a full per-file RFC
   corpus lookup wired in — a smaller-scope reuse of the QAG functions than
   Experiment where full RFC text resolution was available — noted here as a real
   limitation of Experiment 5 specifically (its protocol-claim verification is weaker
   than its factual-claim verification, which is checked directly against full
   ground-truth incident data).
7. **Detection lookup source (all experiments):** followed the task instruction to
   use only the pre-built `cached_detection_results.json` cache via
   `cached_lookup.load_cached_detection()` for all 5 files in all 5 experiments —
   no raw pcap re-parsing was performed anywhere in this session's 5 experiments.

## Failures / errors encountered
None. All 5 experiment scripts completed all 5 files with zero errors
(`failures: 0`/`errors: []` in every results JSON). No file needed to be skipped.
