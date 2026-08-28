"""Single-file, all-9-conditions runner. Mirrors the readability
convention already established in the detector's own run_single.py
(C:\\simulation pcap\\rule_based detector\\run_single.py) -- one argument
(a scenario folder path), readable per-condition output, no JSON dump.

Usage:
    python run_single.py "C:\\simulation pcap\\pilot_containerlab\\pcaps\\link_down\\single\\link_down_bfd_pe1_notrecovered"
"""
import sys
import os
import io

# GPT-5's output can contain Unicode punctuation (en-dashes, non-breaking
# hyphens) that Windows' default console codepage (cp1252) can't encode,
# crashing print() mid-run after the (already-billed) API call succeeded --
# confirmed via a real run this session. Force UTF-8 stdout/stderr with
# replacement for anything still unencodable, rather than risk losing
# output after real spend.
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from pipeline import CONDITIONS, run_one_condition, _client
from format_sections import format_explanation_console


def print_condition_result(result):
    print("=" * 100)
    print(f"CONDITION: {result['condition']}")
    print(f"LLM called: {result.get('llm_called', False)}" + (f"  (n_calls={result.get('n_calls')})" if result.get("llm_called") else ""))

    if result["condition"] == "rule_based_only":
        print(result["explanation"])
        print()
        return

    if "note" in result:
        print(result["note"])
        print()
        return

    def print_groundedness(g):
        for inc in g["per_incident"]:
            label = f"{inc['fault_type']}/{inc['root_cause_node_or_pair']}"
            checks = [
                ("1.fault_type", inc["fault_type_ok"]),
                ("2.affected_nodes", inc["affected_nodes_ok"]),
                ("3.trigger_mechanism", inc["trigger_mechanism_ok"]),
                ("4.root_cause_self_consistent", inc["root_cause_self_consistent"]),
            ]
            check_str = ", ".join(f"{name}={'n/a' if v is None else v}" for name, v in checks)
            print(f"  groundedness [{label}]: {check_str}")
            if inc["affected_nodes_missing"]:
                print(f"    missing ground-truth nodes not mentioned: {inc['affected_nodes_missing']}")
        if g["fabrications"]:
            print(f"  !!! 5.FABRICATIONS ({len(g['fabrications'])}):")
            for f in g["fabrications"]:
                print(f"      {f}")
        else:
            print("  5.fabrications: none")
        if g["rfc_grounding_checked"]:
            print(f"  6.rfc_grounding_content overlap word count: {g['rfc_grounding_overlap']}")
        elif g["rfc_grounding_note"]:
            print(f"  6.rfc_grounding_content: {g['rfc_grounding_note']}")

    print(f"n_incidents in this job: {result.get('n_incidents')}")
    print(f"citations retrieved: {result.get('citations') or 'none'}")
    if result.get("causal_text"):
        print(f"causal note: {result['causal_text']}")
    if result.get("tag"):
        print(f"NEXT STEP tag: {result['tag']['tag']} -- {result['tag']['recommendation']}")
        print(f"  justification: {result['tag']['justification']}")
    print_groundedness(result["groundedness"])
    print("\nGenerated text:")
    print(format_explanation_console(result["explanation"]))


def main():
    if len(sys.argv) != 2:
        print("Usage: python run_single.py <path-to-scenario-folder>")
        sys.exit(1)
    folder_dir = sys.argv[1]

    client = None
    for condition in CONDITIONS:
        if condition != "rule_based_only" and client is None:
            client = _client()
        result = run_one_condition(folder_dir, condition, client=client)
        print_condition_result(result)


if __name__ == "__main__":
    main()
