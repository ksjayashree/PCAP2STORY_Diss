"""
Category E: recovery window variation, link_down BFD single PE, 2rr.
Scoped to 60s and 120s only.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures
import All_Scenarios as AS

PCAPS = os.path.join(AS.BASE, "pcaps", "multiple")
RESULTS = []


def gen(delay, pe="pe2"):
    name = f"catE_link_down_bfd_{pe}_recoverdelay{delay}s"
    target_dir = os.path.join(PCAPS, "catE_link_down", name)
    if not AS.ensure_healthy(name):
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(8)
    t_fault = AS.now_iso()
    AS.link_down_bfd_inject(pe)
    time.sleep(delay)
    AS.link_down_bfd_recover(pe)
    t_recovery = AS.now_iso()
    time.sleep(15)  # tail margin to observe reconnection
    stop_and_collect_captures(name, target_dir)
    meta = {
        "fault_type": "Link Down", "event_affected_node": pe.upper(), "trigger_mechanism": "BFD Down",
        "time_of_first_fault": t_fault, "recovered": True, "time_of_recovery": t_recovery,
        "recover_delay_seconds": delay,
        "category": "E",
    }
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


if __name__ == "__main__":
    AS.discover_pe_interfaces()
    for attempt, delay in enumerate([60, 120]):
        ok_before = 0
        try:
            gen(delay)
        except Exception as e:
            print(f"[ERROR] delay={delay}s failed: {e}")
            RESULTS.append({"name": f"catE_delay{delay}", "status": "EXCEPTION", "error": str(e)})
    print("\n=== RESULTS ===")
    print(json.dumps(RESULTS, indent=2))
    print("HEALTHY" if AS.health_ok() else "UNHEALTHY")
