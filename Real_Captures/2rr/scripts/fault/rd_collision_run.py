"""
RD Collision scenario generation: 3 non-ES PE pairs x fixed/notfixed = 6
pairwise scenarios, plus a 3-way PE3/PE4/PE5 x fixed/notfixed extension.
Does not touch pe1/pe2 ES/vhost100 config. Verifies each group independently.

run_scenario/all_macs_visible are N-ary.
"""
import sys
import os
import subprocess
import datetime
import time
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures

BASE = str(Path(__file__).resolve().parents[2])
PCAPS = os.path.join(BASE, "pcaps")
CHECK_HEALTH = os.path.join(BASE, "scripts", "test_scripts", "check_health.py")

PE_RD = {"pe3": "10.0.0.13:2", "pe4": "10.0.0.14:2", "pe5": "10.0.0.15:2"}
PE_MAC = {"pe3": "52:54:00:00:00:03", "pe4": "52:54:00:00:00:04", "pe5": "52:54:00:00:00:05"}
COLLIDE_RD = "65000:999"

results = []


def now_iso():
    n = datetime.datetime.now(datetime.timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond:06d}Z"


def dexec(container, *args):
    cmd = ["wsl", "docker", "exec", f"clab-pcap2story-{container}"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def vtysh_cmds(container, cmds):
    args = ["vtysh"]
    for c in cmds:
        args += ["-c", c]
    return dexec(container, *args)


def health_ok():
    r = subprocess.run(["python", CHECK_HEALTH], capture_output=True, text=True)
    return r.returncode == 0


def route_count(container):
    r = vtysh_cmds(container, ["show bgp l2vpn evpn"])
    for line in r.stdout.splitlines():
        if "Displayed" in line and "total prefixes" in line:
            return int(line.split()[1])
    return -1


def apply_rd(pe, rd):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])


def revert_rd(pe, original_rd):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {COLLIDE_RD}"])


def all_macs_visible(rr, pes):
    r = vtysh_cmds(rr, ["show bgp l2vpn evpn"])
    out = r.stdout
    return all(PE_MAC[p] in out for p in pes) and f"Route Distinguisher: {COLLIDE_RD}" in out


def run_scenario(pes, fixed, recover_delay=8):
    name = f"rd_collision_{'_'.join(pes)}_{'fixed' if fixed else 'notfixed'}"
    target_dir = os.path.join(PCAPS, "rd_collision", "single", name)
    print(f"\n[SCENARIO] === {name} ===")

    if not health_ok():
        print(f"[SCENARIO][ERROR] {name}: fabric unhealthy before scenario. Aborting.")
        results.append({"name": name, "status": "ABORTED_UNHEALTHY"})
        return False

    # BEFORE snapshot
    before = {p: route_count(p) for p in pes}
    before_rr1 = route_count("rr1")
    print(f"[BEFORE] {before} rr1={before_rr1}")

    proc_rr1, proc_rr2 = start_concurrent_captures()
    time.sleep(6)

    t_fault = now_iso()
    for p in pes:
        apply_rd(p, COLLIDE_RD)
    time.sleep(7)

    # Confirm collision applied on every PE
    cfgs = {p: vtysh_cmds(p, ["show running-config"]).stdout for p in pes}
    if not all(f"rd {COLLIDE_RD}" in cfgs[p] for p in pes):
        print(f"[SCENARIO][ERROR] {name}: rd config did not apply on all PEs!")
        results.append({"name": name, "status": "FAILED_RD_NOT_APPLIED"})
        stop_and_collect_captures(name, target_dir)
        for p in pes:
            revert_rd(p, PE_RD[p])
        return False

    # Confirm all routes remain independently visible (the primary hypothesis)
    visible = all_macs_visible("rr1", pes)
    if not visible:
        print(f"[SCENARIO][CRITICAL] {name}: PRIMARY HYPOTHESIS FAILED -- not all routes independently visible!")
        results.append({"name": name, "status": "HYPOTHESIS_FAILED", "critical": True})
        stop_and_collect_captures(name, target_dir)
        for p in pes:
            revert_rd(p, PE_RD[p])
        return False

    print(f"[SCENARIO] {name}: primary hypothesis holds (all routes visible under shared RD)")

    t_recovery = None
    if fixed:
        time.sleep(recover_delay)
        for p in pes:
            revert_rd(p, PE_RD[p])
        t_recovery = now_iso()
        time.sleep(8)
        # confirm reconvergence
        for _ in range(10):
            cfg_a2 = vtysh_cmds(pes[0], ["show running-config"]).stdout
            if f"rd {COLLIDE_RD}" not in cfg_a2:
                break
            time.sleep(2)
    else:
        time.sleep(16)

    stop_and_collect_captures(name, target_dir)

    after_rr1 = route_count("rr1")

    meta = {
        "fault_type": "RD Collision",
        "fault_subtype": "RD Collision",
        "event_affected_nodes": [p.upper() for p in pes],
        "trigger_mechanism": "Shared Route Distinguisher (RD Collision)",
        "colliding_rd": COLLIDE_RD,
        "original_rd": {p: PE_RD[p] for p in pes},
        "time_of_first_fault": t_fault,
        "recovered": fixed,
        "time_of_recovery": t_recovery,
        "recover_delay_seconds": recover_delay if fixed else None,
    }
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)

    if not fixed:
        # notfixed scenarios: revert now so next scenario starts clean
        for p in pes:
            revert_rd(p, PE_RD[p])
        time.sleep(3)

    # regression check: other PEs and both RRs
    other_pes = [p for p in ["pe1", "pe2", "pe3", "pe4", "pe5"] if p not in pes]
    regression = {}
    for p in other_pes:
        regression[p] = route_count(p)
    regression["rr2"] = route_count("rr2")
    print(f"[REGRESSION] {regression}")

    ok = os.path.exists(os.path.join(target_dir, "rr1.pcap")) and os.path.exists(os.path.join(target_dir, "rr2.pcap"))
    results.append({
        "name": name, "status": "OK" if ok else "MISSING_FILES",
        "before": {**before, "rr1": before_rr1},
        "after_rr1": after_rr1,
        "regression": regression,
    })
    print(f"[SCENARIO] {name}: {'OK' if ok else 'MISSING FILES'}")
    return True


if __name__ == "__main__":
    groups = [["pe3", "pe4"], ["pe3", "pe5"], ["pe4", "pe5"], ["pe3", "pe4", "pe5"]]
    for pes in groups:
        for fixed in [False, True]:
            ok = run_scenario(pes, fixed)
            if not ok:
                print(f"[RUN] Stopping due to failure in {'/'.join(pes)} fixed={fixed}")

    print("\n=== FINAL RESULTS ===")
    print(json.dumps(results, indent=2))

    print("\n=== FINAL HEALTH ===")
    print("HEALTHY" if health_ok() else "UNHEALTHY")
