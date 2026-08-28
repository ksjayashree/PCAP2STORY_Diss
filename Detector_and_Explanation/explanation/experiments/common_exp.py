"""Shared helpers for experiment_1..5 scripts. Imports pipeline.py's real
BASE_SYSTEM_PROMPT/FREE_NEXT_STEP_SUFFIX/CONDITION_SPEC/_base_facts/
_pe_nodes/parse_next_step_tag/_client/MODEL unmodified -- none of these
experiment scripts edit pipeline.py itself, per the task's global rules.
"""
import os
import sys
import json
import time

EXPLAIN_DIR = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, EXPLAIN_DIR)
sys.path.insert(0, os.path.dirname(__file__))

from pipeline import (  # noqa: E402
    _client, MODEL, CONDITION_SPEC, BASE_SYSTEM_PROMPT, FREE_NEXT_STEP_SUFFIX,
    _base_facts, _pe_nodes, parse_next_step_tag, _gather_causal_incidents,
    RFC_EXCERPT_CHAR_LIMIT,
)
from cached_lookup import load_cached_detection, FILE_KEYS  # noqa: E402

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

SPEC = CONDITION_SPEC["KG_RAG"]

# Global counters, module-level so every experiment script sees the same
# running totals when run in the same process (each experiment script is
# also runnable standalone -- counters just start at 0 in that case).
# UNCHANGED by the per-call logging added below -- both still increment
# exactly as before, on every call through chat() (the only thing that
# incremented them originally); CALL_LOG below is purely additive.
CALL_COUNTER = [0]
WALLCLOCK_TOTAL = [0.0]

# Per-call metrics log, one dict per API call (OpenAI or Gemini), appended
# to by every instrumented call site in this project's experiment scripts
# (chat() below, InstrumentedClient's wrapped create(), and gemini_judge.py's
# own _gemini_call() via log_call_metrics() directly -- Gemini's response
# shape isn't OpenAI-compatible, so it can't go through chat()/
# InstrumentedClient, but logs into this same shared list/schema).
# Never cleared automatically -- call reset_call_log() between separate
# runs if isolation is needed; left to accumulate by default so a single
# process running multiple experiment scripts back-to-back gets one
# combined log covering all of them.
CALL_LOG = []


def log_call_metrics(experiment, file_key, model_requested, model_returned,
                      ts_start, ts_end, input_tokens, output_tokens,
                      success, error=None):
    """Append one call's metrics to CALL_LOG. Called directly by any call
    site that can't go through chat()/InstrumentedClient (e.g. Gemini,
    whose response object has a different shape than OpenAI's)."""
    entry = {
        "experiment": experiment,
        "file": file_key,
        "model_requested": model_requested,
        "model_returned": model_returned,
        "timestamp_start": ts_start,
        "timestamp_end": ts_end,
        "latency_seconds": ts_end - ts_start,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "success": success,
        "error": error,
    }
    CALL_LOG.append(entry)
    return entry


def reset_call_log():
    """Clears CALL_LOG in place (keeps the same list object, since other
    modules may have imported the name directly -- reassigning CALL_LOG =
    [] here would leave those imports pointing at the old, now-orphaned
    list)."""
    CALL_LOG.clear()


class InstrumentedClient:
    """Transparent wrapper around any OpenAI-compatible client -- delegates
    every attribute except .chat.completions.create() unchanged, and logs
    that one call site's metrics into CALL_LOG before returning the real
    response untouched. Lets reliability_experiment.py (and anything else
    that constructs its own client and passes it into pipeline.run_one_
    condition(..., client=...)) get full per-call metrics WITHOUT editing
    pipeline.py at all -- run_one_condition already accepts an injected
    client, so wrapping it here is a clean instrumentation point that
    respects this project's established "never edit pipeline.py" rule
    (see this file's own module docstring).

    experiment/file_key are read from self.current_experiment/
    self.current_file at call time (mutable attributes, set by the caller
    before each call) rather than constructor args, since the same wrapped
    client instance is reused across many files/experiments in a single
    run (e.g. reliability_experiment.py's one `client` object used for
    every file/condition/rerun combination)."""

    def __init__(self, real_client, experiment="unknown", file_key="unknown"):
        self._real_client = real_client
        self.current_experiment = experiment
        self.current_file = file_key
        self.chat = _InstrumentedChat(self)

    def __getattr__(self, name):
        # Anything other than .chat (already overridden above) delegates
        # straight to the real client -- e.g. .models, .embeddings, etc.
        return getattr(self._real_client, name)


class _InstrumentedChat:
    def __init__(self, owner):
        self._owner = owner
        self.completions = _InstrumentedCompletions(owner)


class _InstrumentedCompletions:
    def __init__(self, owner):
        self._owner = owner

    def create(self, **kwargs):
        owner = self._owner
        model_requested = kwargs.get("model")
        t0 = time.time()
        try:
            response = owner._real_client.chat.completions.create(**kwargs)
        except Exception as e:
            t1 = time.time()
            log_call_metrics(
                experiment=owner.current_experiment, file_key=owner.current_file,
                model_requested=model_requested, model_returned=None,
                ts_start=t0, ts_end=t1, input_tokens=None, output_tokens=None,
                success=False, error=f"{type(e).__name__}: {e}",
            )
            raise
        t1 = time.time()
        usage = getattr(response, "usage", None)
        log_call_metrics(
            experiment=owner.current_experiment, file_key=owner.current_file,
            model_requested=model_requested, model_returned=getattr(response, "model", None),
            ts_start=t0, ts_end=t1,
            input_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            output_tokens=getattr(usage, "completion_tokens", None) if usage else None,
            success=True, error=None,
        )
        return response


def chat(client, system_prompt, user_content, model=MODEL, experiment="experiment_1_multiagent", file_key="unknown"):
    t0 = time.time()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
    )
    elapsed = time.time() - t0
    t1 = t0 + elapsed
    CALL_COUNTER[0] += 1
    WALLCLOCK_TOTAL[0] += elapsed
    usage = getattr(response, "usage", None)
    log_call_metrics(
        experiment=experiment, file_key=file_key,
        model_requested=model, model_returned=getattr(response, "model", None),
        ts_start=t0, ts_end=t1,
        input_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
        output_tokens=getattr(usage, "completion_tokens", None) if usage else None,
        success=True, error=None,
    )
    return response.choices[0].message.content, elapsed


def build_context_k(folder_dir, incidents, raw, topo, spec, flat_k=2, kg_k=2):
    """Faithful local copy of pipeline.build_context(), parameterized on
    the flat-RAG / KG-RAG `k` retrieval width (pipeline.py's own
    build_context always calls select_citation(inc, k=2) and
    graph_traverse_retrieve(q, k=2) hardcoded -- this copy exists so
    experiment_2 can widen retrieval without editing pipeline.py, per the
    task's explicit instruction not to touch pipeline.py globally)."""
    from citations import select_citation
    incidents, causal_text = _gather_causal_incidents(incidents, raw, topo)

    facts_list = [_base_facts(inc) for inc in incidents]

    grounding_by_incident = []
    if spec["rag"] == "flat":
        for inc in incidents:
            grounding_by_incident.append(select_citation(inc, k=flat_k))
    elif spec["rag"] == "kg":
        from rfc_knowledge_graph.traversal import graph_traverse_retrieve
        from citations import _query_for_incident, _RT_MISCONFIG_ES_IMPORT_TERMS, _RT_MISCONFIG_BASE_TERMS, ES_IMPORT_TRIGGER_MECHANISM
        for inc in incidents:
            q = _query_for_incident(inc)
            if inc.get("fault_type") == "RT Misconfiguration":
                q += _RT_MISCONFIG_ES_IMPORT_TERMS if inc.get("trigger_mechanism") == ES_IMPORT_TRIGGER_MECHANISM else _RT_MISCONFIG_BASE_TERMS
            hits = graph_traverse_retrieve(q, k=kg_k)
            grounding_by_incident.append([{"entry": h["node"], "score": h["score"]} for h in hits])
    else:
        grounding_by_incident = [[] for _ in incidents]

    lines = []
    if spec["topology"]:
        pe_ids = _pe_nodes(topo)
        lines.append(f"Topology: {len(pe_ids)} PEs ({', '.join(pe_ids)}), route reflectors present.")
    for i, (inc, facts, grounding) in enumerate(zip(incidents, facts_list, grounding_by_incident), 1):
        lines.append(f"\nIncident {i}:")
        for k, v in facts.items():
            lines.append(f"  {k}: {v}")
        if grounding:
            lines.append("  Grounding RFC excerpts:")
            for g in grounding:
                lines.append(f"    [{g['entry']['citation']}] {g['entry']['text'][:RFC_EXCERPT_CHAR_LIMIT]}")
    if len(incidents) > 1:
        lines.append(
            "\nMore than one incident is listed above. Check whether they share a "
            "root cause, an ESI/multihoming partnership, or are otherwise related "
            "before treating them as independent."
        )
    if causal_text:
        lines.append(f"\nCausal note: {causal_text}")

    system_prompt = BASE_SYSTEM_PROMPT
    if spec["next_step"] == "free":
        system_prompt += FREE_NEXT_STEP_SUFFIX

    return system_prompt, "\n".join(lines), causal_text, grounding_by_incident, incidents


def save_json(name, obj):
    path = os.path.join(RESULTS_DIR, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
    return path


def save_md(name, text):
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
