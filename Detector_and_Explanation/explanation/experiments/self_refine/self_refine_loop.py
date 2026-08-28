"""Shared Self-Refine loop logic for Approach B -- used by both the
offline dry-run harness (Part 1) and the real 20-file run (Part 2), so
the exact same stopping-condition code is what gets validated and then
run for real.
"""
import re

MAX_CRITIQUE_ITERATIONS = 3

CRITIQUE_SYSTEM_PROMPT = (
    "You are a senior network operations reviewer performing a factual audit "
    "of an EVPN/BGP fault explanation before it is sent to an on-call "
    "engineer. You will be given: (1) the CURRENT explanation, (2) the "
    "DETECTOR FACTS, the actual structured incident data the explanation "
    "should be consistent with, and (3) the RFC GROUNDING excerpts that were "
    "shown to the drafting model.\n\n"
    "Check the explanation for: factual errors (wrong node names, wrong "
    "fault type, wrong trigger mechanism, wrong recovery status, wrong "
    "timestamps) relative to DETECTOR FACTS; unsupported claims not present "
    "in DETECTOR FACTS or RFC GROUNDING; and RFC citation errors, meaning "
    "the explanation either cites a section that does not say what the "
    "explanation claims it says, or asserts something as an RFC requirement "
    "when the cited text states it only as a recommendation or one example "
    "among several.\n\n"
    "If this is a revision of an earlier draft, also check whether the "
    "previous correction actually fixed what it was supposed to fix, and "
    "whether it introduced any new error while doing so.\n\n"
    "Respond in exactly this structure:\n"
    "VERDICT: APPROVED or VERDICT: CORRECTED\n"
    "ISSUES: A short bullet list of every issue found (write \"None\" if "
    "APPROVED).\n"
    "If and only if VERDICT is CORRECTED, follow with a corrected "
    "explanation using the exact same four-section structure as the input "
    "(SUMMARY:/NEXT STEPS:/RFC CITATIONS:/RFC GROUNDING:), fixing only the "
    "issues found and leaving everything else as close to the current "
    "wording as possible."
)


def build_critique_user_prompt(current_explanation, generation_context, is_revision):
    """generation_context is build_context()'s actual returned context
    string -- the exact same text the generating model was shown (topology
    description when spec["topology"] is True, full per-incident facts +
    RFC excerpts, the multi-incident relatedness instruction when
    len(incidents) > 1, and the causal note when one was resolved) --
    reused verbatim here rather than reconstructed, so the critic can never
    see a narrower context than the generator did."""
    prefix = (
        "This is a revision of an earlier draft; the CURRENT explanation "
        "below already reflects at least one prior correction.\n\n"
        if is_revision else ""
    )
    return (
        f"{prefix}CURRENT explanation:\n{current_explanation}\n\n"
        f"DETECTOR FACTS AND RFC GROUNDING (the exact context shown to the "
        f"model that drafted this explanation, including topology, "
        f"per-incident facts, RFC excerpts, and any relatedness/causal "
        f"notes):\n{generation_context}"
    )


def parse_critique(text):
    verdict = None
    if "VERDICT: APPROVED" in text.upper():
        verdict = "APPROVED"
    elif "VERDICT: CORRECTED" in text.upper():
        verdict = "CORRECTED"
    corrected_explanation = None
    if verdict == "CORRECTED":
        idx = text.upper().find("SUMMARY:")
        if idx != -1:
            corrected_explanation = text[idx:].strip()
    return verdict, corrected_explanation


def run_self_refine(initial_explanation, generation_context, critique_fn,
                     max_iterations=MAX_CRITIQUE_ITERATIONS):
    """critique_fn(user_prompt) -> raw critique response text (real or mocked).

    generation_context: build_context()'s actual returned context string
    (see build_critique_user_prompt) -- passed straight through unchanged
    on every iteration, so the critic's view of the facts/topology/RFC
    excerpts never drifts from what the generator was shown.

    Returns dict: final_explanation, n_generate_calls (always 1, caller
    already generated initial_explanation), n_critique_calls, iterations
    (list of {iteration, verdict, issues_raw, changed}), stop_reason
    ("approved" or "cap_reached_not_approved")."""
    explanation = initial_explanation
    iterations = []
    stop_reason = "cap_reached_not_approved"
    n_critique_calls = 0

    for i in range(1, max_iterations + 1):
        is_revision = i > 1
        user_prompt = build_critique_user_prompt(explanation, generation_context, is_revision)
        critique_text = critique_fn(user_prompt, i)
        n_critique_calls += 1
        verdict, corrected = parse_critique(critique_text)

        iter_record = {
            "iteration": i,
            "verdict": verdict,
            "raw_critique": critique_text,
            "changed": False,
        }

        if verdict == "APPROVED":
            iterations.append(iter_record)
            stop_reason = "approved"
            break
        elif verdict == "CORRECTED" and corrected:
            explanation = corrected
            iter_record["changed"] = True
            iterations.append(iter_record)
            # loop continues to re-critique the corrected version, unless
            # this was already the last allowed iteration
        else:
            # verdict == "CORRECTED" but no parseable corrected body, or
            # verdict is None (malformed response) -- explanation unchanged,
            # still counts as a used iteration/call, still re-critiqued next
            # round if iterations remain.
            iterations.append(iter_record)

    return {
        "final_explanation": explanation,
        "n_critique_calls": n_critique_calls,
        "iterations": iterations,
        "stop_reason": stop_reason,
    }
