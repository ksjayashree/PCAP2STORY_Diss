"""Usage: python end_to_end.py <fault_folder_name> <topology_file_path>"""
import sys
import os
import json

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src", "rules"))
sys.path.insert(0, os.path.join(REPO_ROOT, "explanation"))
sys.path.insert(0, os.path.join(REPO_ROOT, "explanation", "correctors"))

from topology import load_topology
from vantage_parser import parse_vantages
from fusion import fuse_event_streams
from orchestrator import run_all_rules, annotate_precedence

import pipeline
from pipeline import (
    CONDITION_SPEC, build_context, _generate_explanation, evaluate_groundedness,
    _load_meta, _strip_next_step_tag_prefix, _client,
)
from format_sections import parse_sections

import io
import contextlib
with open(os.devnull, "w") as _devnull, contextlib.redirect_stdout(_devnull):
    from disc import (
        call_model, parse_questions, parse_answer, parse_judge,
        strip_spliced_next_steps, MAX_CYCLES,
        PROMPT_A_SYSTEM, PROMPT_B_SYSTEM, PROMPT_C_SYSTEM, PROMPT_D_SUFFIX,
        MODEL_VERIFIER_JUDGE, MODEL_GEN_CORRECTOR,
    )

CONDITION = "KG_RAG"

FAULT_TYPE_FOR_FOLDER = {
    "link_down_bfd_recovered": "Link Down",
    "pe_cease_recovered": "PE Cease",
    "rr_down_graceful_notrecovered": "RR Down",
    "rd_collision_shared_notrecovered": "RD Collision",
    "rt_misconfig_autoderive_notrecovered": "RT Misconfiguration",
}


def resolve_fault_type(raw, fault_folder_name):
    fault_type = FAULT_TYPE_FOR_FOLDER.get(fault_folder_name)
    if fault_type is None:
        raise RuntimeError(
            f"{fault_folder_name!r} is not in FAULT_TYPE_FOR_FOLDER."
        )
    if not raw.get(fault_type):
        raise RuntimeError(
            f"Expected non-empty {fault_type!r} in raw output for "
            f"{fault_folder_name!r}, got {raw.get(fault_type)!r}. "
            f"Non-empty modules found: {[k for k, v in raw.items() if v]!r}"
        )
    return fault_type


def run_disc_loop(client, system_prompt, context, spec, all_recovered, described_incidents, draft):
    call_log = []

    a_user = f"{context}\n\nDRAFT explanation:\n{draft}"
    a_text = call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_A_SYSTEM, a_user, "A_questions", call_log)
    questions = parse_questions(a_text)

    qa_pairs = []
    for q in questions:
        b_user = f"{context}\n\nQUESTION: {q}"
        b_text = call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_B_SYSTEM, b_user, "B_answer", call_log)
        parsed = parse_answer(b_text)
        qa_pairs.append({"question": q, "raw_answer": b_text, "answer": parsed["answer"], "support": parsed["support"]})
    qa_block = "\n".join(f"Q{i}: {p['question']}\nA{i}: {p['raw_answer']}" for i, p in enumerate(qa_pairs, 1))

    current_draft = draft
    stop_reason = None
    for cycle in range(1, MAX_CYCLES + 1):
        judge_view_draft = strip_spliced_next_steps(current_draft) if all_recovered else current_draft
        c_user = f"{context}\n\nDRAFT explanation:\n{judge_view_draft}\n\nVERIFICATION Q&A PAIRS:\n{qa_block}"
        c_text = call_model(client, MODEL_VERIFIER_JUDGE, PROMPT_C_SYSTEM, c_user, f"C_judge_cycle{cycle}", call_log)
        judge = parse_judge(c_text)

        if judge["verdict"] == "No_Mistake":
            stop_reason = "no_mistake"
            break
        elif judge["verdict"] == "Mistake":
            if all_recovered:
                corrector_system = pipeline.BASE_SYSTEM_PROMPT_NO_NEXT_STEPS + PROMPT_D_SUFFIX
            else:
                corrector_system = system_prompt + PROMPT_D_SUFFIX
            d_user = (
                f"{context}\n\nPREVIOUS explanation:\n{current_draft}\n\n"
                f"JUDGE'S FINDING:\nDRAFT CLAIM: {judge['draft_claim']}\n"
                f"CONTRADICTING ANSWER: {judge['contradicting_answer']}\n"
                f"EXPLANATION: {judge['explanation']}"
            )
            d_text = call_model(client, MODEL_GEN_CORRECTOR, corrector_system, d_user, f"D_correct_cycle{cycle}", call_log)
            if spec["next_step"] == "free" and all_recovered:
                d_text = pipeline._splice_self_resolved_next_steps(d_text, described_incidents)
            current_draft = d_text
            if cycle == MAX_CYCLES:
                stop_reason = "cap_reached_not_resolved"
        else:
            stop_reason = "judge_parse_failure"
            break

    return current_draft, stop_reason, len(call_log)


def print_final_sections(text, all_recovered, tag):
    sections = dict(parse_sections(text))

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(sections.get("SUMMARY", "").strip() or "(none)")
    print()
    print("=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    next_steps = sections.get("NEXT STEPS", "").strip()
    if not next_steps and all_recovered:
        print("(incident already recovered -- no NEXT STEPS content returned)")
    else:
        print(next_steps or "(none)")
    print()
    print("=" * 70)
    print("RFC CITATIONS")
    print("=" * 70)
    print(sections.get("RFC CITATIONS", "").strip() or "(none)")
    print()
    print("=" * 70)
    print("RFC GROUNDING")
    print("=" * 70)
    print(sections.get("RFC GROUNDING", "").strip() or "(none)")
    if tag:
        print(f"\nConfidence: {tag['tag']} -- {tag['justification']}")
    elif all_recovered:
        print("\nConfidence: N/A (incident recovered -- deterministic, not a model judgment)")


def main():
    if len(sys.argv) != 3:
        print("usage: python end_to_end.py <fault_folder_name> <topology_file_path>")
        sys.exit(1)

    fault_folder_name, topology_path = sys.argv[1], sys.argv[2]
    folder_dir = os.path.join(REPO_ROOT, "..", "input", fault_folder_name)
    folder_dir = os.path.normpath(folder_dir)
    if not os.path.isdir(folder_dir):
        print(f"ERROR: {folder_dir!r} does not exist")
        sys.exit(1)

    topo = load_topology(topology_path)

    vmap = {
        "RR1": os.path.join(folder_dir, "rr1.pcap"),
        "RR2": os.path.join(folder_dir, "rr2.pcap"),
    }
    streams = parse_vantages(vmap, topology_path)
    fused = fuse_event_streams(streams, topology_path)

    raw = run_all_rules(fused, topo, "simple")
    precedence = annotate_precedence(raw, topo, fused_events=fused)
    fault_type = resolve_fault_type(raw, fault_folder_name)
    incidents = raw[fault_type]

    spec = CONDITION_SPEC[CONDITION]
    client = _client()
    meta = _load_meta(folder_dir)
    system_prompt, context, causal_text, grounding, described_incidents, all_recovered = \
        build_context(folder_dir, incidents, raw, topo, spec)
    draft_text, tag, n_gen_calls = _generate_explanation(
        client, system_prompt, context, spec, all_recovered, described_incidents, folder_dir, CONDITION
    )
    draft_text = _strip_next_step_tag_prefix(draft_text, tag)

    final_text, stop_reason, n_disc_calls = run_disc_loop(
        client, system_prompt, context, spec, all_recovered, described_incidents, draft_text
    )

    print_final_sections(final_text, all_recovered, tag)


if __name__ == "__main__":
    main()
