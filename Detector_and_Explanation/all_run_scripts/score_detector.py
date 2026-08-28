import sys, os

# Moved here from C:\synthcap\ (2026-08-03) -- scorer_lib.py now lives in
# src/ alongside orchestrator.py/fusion.py/vantage_parser.py it imports,
# matching run_multi_incident.py's own relative sys.path convention
# (project root -> src/, src/rules/), rather than the hardcoded absolute
# paths this file used when it lived in a different project.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "rules"))

from topology import load_topology
from scorer_lib import run_scorer

TOPO_PATH = os.path.join(os.path.dirname(__file__), "config", "topology.json")
topo = load_topology(TOPO_PATH)
PCAPS = r"C:\simulation pcap\pilot_containerlab\pcaps"


def vmap_builder(folder_dir):
    rr1 = os.path.join(folder_dir, "rr1.pcap")
    rr2 = os.path.join(folder_dir, "rr2.pcap")
    vmap = {"RR1": rr1}
    if os.path.exists(rr2):
        vmap["RR2"] = rr2
    return vmap


run_scorer(
    pcaps_base=PCAPS,
    topo=topo,
    topo_path=TOPO_PATH,
    vmap_builder=vmap_builder,
    normal_base=PCAPS,
)
