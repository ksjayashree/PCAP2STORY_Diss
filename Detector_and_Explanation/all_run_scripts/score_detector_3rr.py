import sys, os

# Moved here from C:\synthcap\ (2026-08-03) -- see score_detector.py's
# comment for why the src/ paths are now relative.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "rules"))

from topology import load_topology
from scorer_lib import run_scorer

TOPO_PATH = r"C:\simulation pcap\3rr\config\topology.json"
topo = load_topology(TOPO_PATH)
PCAPS = r"C:\simulation pcap\3rr\pcaps"

# Confirmed pre-existing 3RR dataset issues (investigation, prior turn) --
# excluded here explicitly rather than silently omitted:
#   - rd_collision_xpe9_xpe10_fixed/_notfixed: regenerated 2026-08-06 with
#     metadata.json now present (PE_MAC formula bug fixed at the source in
#     rd_collision_run.py, pair added to the __main__ list) -- no longer
#     excluded.
#   - mac_mobility_cleanmove_xpe6to7_settled: root-caused and regenerated
#     2026-08-06. XPE6/XPE7 are members of the SAME Ethernet Segment
#     (es-id 67, topology.json ground_truth) -- FRR's EVPN ES-Sync
#     mechanism synchronizes local MAC ownership across every ES member
#     regardless of which member's FDB is edited, so a "clean move"
#     between two members of the same ES is structurally undefined under
#     this injection method, not a fixable timing/race bug. Confirmed via
#     a 65s live poll (both PEs hold the MAC "peer-active" the entire
#     window, never converging) and independently on the regenerated
#     wire capture (every advertisement from both xpe6 and xpe7 carries
#     the identical ESI 02:00:00:00:67:67:00:00:43; xpe6 re-announces at
#     t=13.335s even after its own earlier withdrawal at t=11.521s).
#     metadata.json's known_limitation documents this specific root cause.
#     Still excluded -- correctly so, this is not a detectable event.
#   - rr_down_containerkill_*: now archived to
#     3rr/_archived_rr_down_containerkill/ (2026-08-02, matching
#     pilot_containerlab's own archival of this mechanism) -- no longer
#     appears in the directory listing at all, so no exclude entry is
#     needed here anymore (was excluded in a prior pass, before archival).
EXCLUDE = {
    ("mac_mobility", "mac_mobility_cleanmove_xpe6to7_settled"): (
        "XPE6/XPE7 share Ethernet Segment es-id 67 -- a move between two members "
        "of the same ES is structurally undefined under FDB-injection (EVPN "
        "ES-Sync keeps both PEs co-advertising the MAC under the shared ESI "
        "regardless of which one's FDB is edited), confirmed via 65s live poll "
        "and independently on the wire; not a generation failure to be retried"
    ),
}


def vmap_builder(folder_dir):
    return {
        "XRR1": os.path.join(folder_dir, "xrr1.pcap"),
        "XRR2": os.path.join(folder_dir, "xrr2.pcap"),
        "XRR3": os.path.join(folder_dir, "xrr3.pcap"),
    }


run_scorer(
    pcaps_base=PCAPS,
    topo=topo,
    topo_path=TOPO_PATH,
    vmap_builder=vmap_builder,
    exclude=EXCLUDE,
    normal_base=PCAPS,
)
