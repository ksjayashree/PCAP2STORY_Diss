"""
Category B generator: link_down x2 -- two genuinely independent link-down
occurrences (different PEs, different mechanisms) in one capture window.
Reuses the exact inject/recover primitives and capture harness from
All_Scenarios.py. Run from Windows (matches project convention).
"""
import sys
import os
import json
import datetime

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures
import All_Scenarios as AS

PCAPS = os.path.join(AS.BASE, "pcaps", "multiple")


def now_iso():
    return AS.now_iso()


def run():
    AS.discover_pe_interfaces()
    if not AS.ensure_healthy("multi_link_down_x2"):
        print("[FATAL] fabric unhealthy, aborting")
        return
    AS.ensure_tcpdump()

    name = "link_down_x2_bfd_pe1_holdtimer_pe3"
    target_dir = os.path.join(PCAPS, "catB_link_down_x2", name)
    os.makedirs(target_dir, exist_ok=True)

    proc_rr1, proc_rr2 = start_concurrent_captures()
    import time
    time.sleep(8)

    # Event 1: BFD-triggered link down on PE1, recovered
    t_fault_1 = now_iso()
    AS.link_down_bfd_inject("pe1")
    time.sleep(10)
    AS.link_down_bfd_recover("pe1")
    t_recovery_1 = now_iso()

    time.sleep(10)

    # Event 2: Hold-timer-triggered link down on PE3 (independent PE, independent mechanism), not recovered within window
    t_fault_2 = now_iso()
    AS.link_down_holdtimer_inject("pe3")
    time.sleep(30)

    stop_and_collect_captures(name, target_dir)

    # restore fabric baseline (outside capture window)
    AS.link_down_holdtimer_recover("pe3")

    meta = {
        "fault_type": "Link Down",
        "multi_incident": True,
        "category": "B",
        "incidents": [
            {
                "event_affected_node": "PE1",
                "fault_type": "Link Down",
                "trigger_mechanism": "BFD Down",
                "time_of_first_fault": t_fault_1,
                "recovered": True,
                "time_of_recovery": t_recovery_1,
            },
            {
                "event_affected_node": "PE3",
                "fault_type": "Link Down",
                "trigger_mechanism": "Hold Timer Expired",
                "time_of_first_fault": t_fault_2,
                "recovered": False,
                "time_of_recovery": None,
            },
        ],
    }
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[DONE] wrote {target_dir}")


if __name__ == "__main__":
    run()
