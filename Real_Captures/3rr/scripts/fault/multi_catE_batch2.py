"""
Category E, 3rr: recovery window variation for rr_down (bgpdkill), pe_cease,
rt_misconfig, and rd_collision (fixed variant, parameterized recover_delay),
each at 60/120/300s, plus a 300s link_down BFD attempt.
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures
import All_Scenarios as AS
import rd_collision_run as RD

PCAPS = os.path.join(AS.BASE, "pcaps", "multiple")
CATE = os.path.join(PCAPS, "catE_link_down")
RESULTS = []


def veth_ok(pe="xpe2"):
    r = AS.dexec(pe, "ip", "-brief", "link", "show")
    return "eth1" in r.stdout


def gen_link_down_300(pe="xpe2"):
    name = f"catE_link_down_bfd_{pe}_recoverdelay300s"
    target_dir = os.path.join(CATE, name)
    if not AS.ensure_healthy(name):
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(8)
    t_fault = AS.now_iso()
    AS.link_down_bfd_inject(pe)
    for i in range(6):
        time.sleep(50)
        if not veth_ok(pe):
            print(f"[VETH-LOSS] detected during {name} at ~{(i+1)*50}s, aborting this file")
            RESULTS.append({"name": name, "status": "VETH_LOSS_ABORTED", "at_seconds": (i + 1) * 50})
            return
    AS.link_down_bfd_recover(pe)
    t_recovery = AS.now_iso()
    time.sleep(15)
    stop_and_collect_captures(name, target_dir)
    meta = {"fault_type": "Link Down", "event_affected_node": pe.upper(), "trigger_mechanism": "BFD Down",
            "time_of_first_fault": t_fault, "recovered": True, "time_of_recovery": t_recovery,
            "recover_delay_seconds": 300, "category": "E"}
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_rr_down(delay, rr="xrr1"):
    name = f"catE_rr_down_bgpdkill_{rr}_recoverdelay{delay}s"
    target_dir = os.path.join(CATE, name)
    if not AS.ensure_healthy(name):
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(8)
    t_fault = AS.now_iso()
    AS.rr_down_bgpdkill_inject(rr)
    if delay >= 300:
        for i in range(6):
            time.sleep(50)
            if not veth_ok("xpe2"):
                print(f"[VETH-LOSS] detected during {name}, aborting this file")
                RESULTS.append({"name": name, "status": "VETH_LOSS_ABORTED"}); return
    else:
        time.sleep(delay)
    AS.rr_down_bgpdkill_recover(rr)
    t_recovery = AS.now_iso()
    time.sleep(15)
    stop_and_collect_captures(name, target_dir)
    meta = {"fault_type": "RR Down", "event_affected_node": rr.upper(), "trigger_mechanism": "TCP_connection_closed",
            "time_of_first_fault": t_fault, "recovered": True, "time_of_recovery": t_recovery,
            "recover_delay_seconds": delay, "category": "E"}
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_pe_cease(delay, pe="xpe2"):
    name = f"catE_pe_cease_{pe}_recoverdelay{delay}s"
    target_dir = os.path.join(CATE, name)
    if not AS.ensure_healthy(name):
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(8)
    t_fault = AS.now_iso()
    AS.pe_cease_inject(pe)
    if delay >= 300:
        for i in range(6):
            time.sleep(50)
            if not veth_ok(pe):
                print(f"[VETH-LOSS] detected during {name}, aborting this file")
                RESULTS.append({"name": name, "status": "VETH_LOSS_ABORTED"}); return
    else:
        time.sleep(delay)
    AS.pe_cease_recover(pe)
    t_recovery = AS.now_iso()
    time.sleep(15)
    stop_and_collect_captures(name, target_dir)
    meta = {"fault_type": "PE Cease", "event_affected_node": pe.upper(), "trigger_mechanism": "Cease/Administrative Shutdown",
            "time_of_first_fault": t_fault, "recovered": True, "time_of_recovery": t_recovery,
            "recover_delay_seconds": delay, "category": "E"}
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_rt_misconfig(delay, pe="xpe1"):
    name = f"catE_rt_misconfig_{pe}_recoverdelay{delay}s"
    target_dir = os.path.join(CATE, name)
    if not AS.ensure_healthy(name):
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(8)
    t_fault = AS.now_iso()
    AS.rt_import_only_inject(pe)
    if delay >= 300:
        for i in range(6):
            time.sleep(50)
            if not veth_ok(pe):
                print(f"[VETH-LOSS] detected during {name}, aborting this file")
                RESULTS.append({"name": name, "status": "VETH_LOSS_ABORTED"}); return
    else:
        time.sleep(delay)
    AS.rt_import_only_recover(pe)
    t_recovery = AS.now_iso()
    time.sleep(15)
    stop_and_collect_captures(name, target_dir)
    meta = {"fault_type": "RT Misconfiguration", "event_affected_node": pe.upper(), "trigger_mechanism": "Plain Import/Export Mismatch",
            "time_of_first_fault": t_fault, "recovered": True, "time_of_recovery": t_recovery,
            "recover_delay_seconds": delay, "category": "E"}
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_rd_collision(delay, pe_a="xpe4", pe_b="xpe5"):
    name = f"catE_rd_collision_{pe_a}_{pe_b}_recoverdelay{delay}s"
    target_dir = os.path.join(CATE, name)
    ok = RD.run_scenario(pe_a, pe_b, fixed=True, recover_delay=delay)
    src = os.path.join(RD.PCAPS, "rd_collision", "single", f"rd_collision_{pe_a}_{pe_b}_fixed")
    if ok and os.path.isdir(src):
        os.makedirs(os.path.dirname(target_dir), exist_ok=True)
        if os.path.isdir(target_dir):
            import shutil; shutil.rmtree(target_dir)
        os.rename(src, target_dir)
        try:
            with open(os.path.join(target_dir, "metadata.json")) as f:
                meta = json.load(f)
        except Exception:
            meta = {}
        meta["category"] = "E"
        meta["recover_delay_seconds"] = delay
        with open(os.path.join(target_dir, "metadata.json"), "w") as f:
            json.dump(meta, f, indent=2)
        RESULTS.append({"name": name, "status": "OK"})
        print(f"[DONE] {name}")
    else:
        RESULTS.append({"name": name, "status": "FAILED"})


if __name__ == "__main__":
    AS.discover_pe_interfaces()
    for delay in [60, 120, 300]:
        try:
            gen_rr_down(delay)
        except Exception as e:
            RESULTS.append({"name": f"catE_rr_down_{delay}", "status": "EXCEPTION", "error": str(e)})
    for delay in [60, 120, 300]:
        try:
            gen_pe_cease(delay)
        except Exception as e:
            RESULTS.append({"name": f"catE_pe_cease_{delay}", "status": "EXCEPTION", "error": str(e)})
    for delay in [60, 120, 300]:
        try:
            gen_rt_misconfig(delay)
        except Exception as e:
            RESULTS.append({"name": f"catE_rt_misconfig_{delay}", "status": "EXCEPTION", "error": str(e)})
    for delay in [60, 120, 300]:
        try:
            gen_rd_collision(delay)
        except Exception as e:
            RESULTS.append({"name": f"catE_rd_collision_{delay}", "status": "EXCEPTION", "error": str(e)})
    try:
        gen_link_down_300()
    except Exception as e:
        RESULTS.append({"name": "catE_link_down_300", "status": "EXCEPTION", "error": str(e)})
    print("\n=== RESULTS ===")
    print(json.dumps(RESULTS, indent=2))
    print("HEALTHY" if AS.health_ok() else "UNHEALTHY")
