# Detector and Explanation — Evaluator Demo

This folder runs the full EVPN/BGP fault pipeline on one real packet capture: detection -> precedence -> explanation generation -> DISC self-correction -> final human-readable output (SUMMARY, NEXT STEPS, RFC CITATIONS, RFC GROUNDING, Confidence).

## 1. Setup

From this folder:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Open `explanation/.env` and paste in your own API keys:

```
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
```

An `OPENAI_API_KEY` is required (the pipeline uses it for explanation generation and DISC correction). `GEMINI_API_KEY` is only needed by scripts under `explanation/checks/llm_as_judge_gemini.py` and is not required for the demo below.

## 2. Run one file

Five real, pre-captured incidents are provided under `../input/`:

| folder name                            | fault type          | recovered? |
|-----------------------------------------|----------------------|------------|
| `link_down_bfd_recovered`               | Link Down            | yes        |
| `pe_cease_recovered`                    | PE Cease             | yes        |
| `rr_down_graceful_notrecovered`         | RR Down              | no         |
| `rd_collision_shared_notrecovered`      | RD Collision         | no         |
| `rt_misconfig_autoderive_notrecovered`  | RT Misconfiguration  | no         |

Run any one of them with:

```bash
python end_to_end.py <folder_name> config/topology.json
```

For example:

```bash
python end_to_end.py rr_down_graceful_notrecovered config/topology.json
```

or:

```bash
python end_to_end.py pe_cease_recovered config/topology.json
```

## 3. What you'll see

The script prints the final explanation for that capture, split into clearly labeled sections:

```
======================================================================
SUMMARY
======================================================================
...

======================================================================
NEXT STEPS
======================================================================
...

======================================================================
RFC CITATIONS
======================================================================
...

======================================================================
RFC GROUNDING
======================================================================
...

Confidence: CERTAIN -- ...
```

That's the whole pipeline: real packet captures in, a grounded, RFC-cited fault explanation with a confidence verdict out.

## Other scripts

`extra_scripts/` holds batch/scoring scripts (`run_single.py`, `run_multi_incident.py`, `score_detector.py`, `score_detector_3rr.py`, `score_synthcap.py`) used for large-scale detector evaluation across the full corpus. They aren't needed to run the demo above.
