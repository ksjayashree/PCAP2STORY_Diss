"""Shared cached-detection-result lookup helper for the 5 "results"
experiments (experiment_1..5). Reconstructs what pipeline.detect_incidents()
would have returned for one of the 5 fixed test files WITHOUT re-parsing
pcaps, by reading the already-computed cached_detection_results.json cache
(built by cache_full_detection.py against the full 445-file corpus).

Verified against pipeline.py's real detect_incidents() (reads
src/topology.py's load_topology, src/scorer_lib.py's MODULE_FOR_FOLDER,
filters raw[module_key] for detectability_status == "DETECTED" -- same
filter this helper applies) and against src/scorer_lib.py's MODULE_FOR_FOLDER
dict (module_key resolution for folder_type) before trusting the shape
described in the task instructions.
"""
import os
import json
import sys

DETECTOR_DIR = r"C:\simulation pcap\rule_based detector"
EXPLAIN_DIR = os.path.join(DETECTOR_DIR, "explanation")
sys.path.insert(0, os.path.join(DETECTOR_DIR, "src"))
sys.path.insert(0, os.path.join(DETECTOR_DIR, "src", "rules"))
sys.path.insert(0, EXPLAIN_DIR)

from topology import load_topology  # noqa: E402
from scorer_lib import MODULE_FOR_FOLDER  # noqa: E402

CACHE_PATH = os.path.join(EXPLAIN_DIR, "experiments", "results", "cached_detection_results.json")
with open(CACHE_PATH, encoding="utf-8") as f:
    CACHE = json.load(f)

TOPO_PATH_FOR_CORPUS = {
    "sim_pilot_fault": os.path.join(DETECTOR_DIR, "config", "topology.json"),
    "sim_pilot_normal": os.path.join(DETECTOR_DIR, "config", "topology.json"),
    "sim_3rr_fault": r"C:\simulation pcap\3rr\config\topology.json",
    "sim_3rr_normal": r"C:\simulation pcap\3rr\config\topology.json",
    "synthcap_output": os.path.join(DETECTOR_DIR, "config", "topology.json"),
    "synthcap_output_3rr": os.path.join(DETECTOR_DIR, "config", "topology_3rr.json"),
}
_topo_cache = {}

# The 5 fixed cache keys used by all 5 experiments in this task.
FILE_KEYS = [
    "sim_pilot_fault/rd_collision/single/rd_collision_pe3_pe4_fixed",
    "sim_3rr_fault/mac_mobility/single/mac_mobility_cleanmove_xpe3to0_settled",
    "synthcap_output/esdf_toggle/single/esdf_toggle_repeated_pe1",
    "synthcap_output_3rr/mac_mobility/single/mac_mobility_repeated_pe1_pe2",
    "synthcap_output_3rr/esdf_toggle/single/esdf_toggle_full_failure_no_recovery_pe6pe7",
]


def load_cached_detection(cache_key):
    """Returns (topo, folder_dir, module_key, incidents, raw, precedence)."""
    entry = CACHE[cache_key]
    folder_dir = entry["path"]
    raw = entry["raw"]
    precedence = entry["precedence"]
    corpus = entry["corpus"]
    folder_type = cache_key.split("/")[1]
    module_key = MODULE_FOR_FOLDER[folder_type]
    incidents = [i for i in raw[module_key] if i.get("detectability_status") == "DETECTED"]
    topo_path = TOPO_PATH_FOR_CORPUS[corpus]
    if topo_path not in _topo_cache:
        _topo_cache[topo_path] = load_topology(topo_path)
    return _topo_cache[topo_path], folder_dir, module_key, incidents, raw, precedence


if __name__ == "__main__":
    for k in FILE_KEYS:
        topo, folder_dir, module_key, incidents, raw, precedence = load_cached_detection(k)
        print(k, "->", module_key, "n_incidents=", len(incidents), "folder_dir=", folder_dir)
