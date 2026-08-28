"""
Category C generator: link_down (PE A) + rt_misconfig (PE B), different fault
types, co-occurring, no causal link. Reuses primitives from All_Scenarios.py.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures
import All_Scenarios as AS

PCAPS = os.path.join(AS.BASE, "pcaps", "multiple")


def run():
    AS.discover_pe_interfaces()
    if not AS.ensure_healthy("multi_catC_linkdown_rtmisconfig"):
        print("[FATAL] fabric unhealthy, aborting")
        return
    AS.ensure_tcpdump()

    name = "catC_linkdown_pe2_rtmisconfig_pe4"
    target_dir = os.path.join(PCAPS, "catC_link_down_rt_misconfig", name)
    os.makedirs(target_dir, exist_ok=True)

    proc_rr1, proc_rr2 = start_concurrent_captures()
    time.sleep(8)

    # Independent fault 1: BFD link down on PE2 (homed to RR1), recovered
    t_fault_1 = AS.now_iso()
    AS.link_down_bfd_inject("pe2")
    time.sleep(10)
    AS.link_down_bfd_recover("pe2")
    t_recovery_1 = AS.now_iso()

    time.sleep(5)

    # Independent fault 2: RT misconfig on PE4 (homed to RR2, different node/mechanism), left unfixed
    t_fault_2 = AS.now_iso()
    AS.rt_import_only_inject("pe4")
    time.sleep(25)

    stop_and_collect_captures(name, target_dir)

    # restore fabric baseline outside capture
    AS.rt_import_only_recover("pe4")

    meta = {
        "multi_incident": True,
        "category": "C",
        "incidents": [
            {
                "event_affected_node": "PE2",
                "fault_type": "Link Down",
                "trigger_mechanism": "BFD Down",
                "time_of_first_fault": t_fault_1,
                "recovered": True,
                "time_of_recovery": t_recovery_1,
            },
            {
                "event_affected_node": "PE4",
                "fault_type": "RT Misconfiguration",
                "trigger_mechanism": "Plain Import/Export Mismatch",
                "time_of_first_fault": t_fault_2,
                "recovered": False,
                "time_of_recovery": None,
                "configured_export_rt": "100:1 (export)",
                "configured_import_rt": "200:1 (mismatched import)",
            },
        ],
        "causal_relationship": "none -- independent nodes (PE2 homed to RR1, PE4 homed to RR2), independent mechanisms",
    }
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[DONE] wrote {target_dir}")


if __name__ == "__main__":
    run()
