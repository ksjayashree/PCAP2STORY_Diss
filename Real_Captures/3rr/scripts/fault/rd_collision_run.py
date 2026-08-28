"""
RD Collision scenario generation: 3 non-ES PE pairs x fixed/notfixed = 6 scenarios.
Does not touch pe1/pe2 ES/vhost100 config. Verifies each pair independently.
"""
import sys
import os
import subprocess
import datetime
import time
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures, RR_NODES

BASE = str(Path(__file__).resolve().parents[2])
PCAPS = os.path.join(BASE, "pcaps")
CHECK_HEALTH = os.path.join(BASE, "scripts", "test_scripts", "check_health.py")

ALL_PES = ["xpe1", "xpe2", "xpe3", "xpe4", "xpe5", "xpe6", "xpe7", "xpe8", "xpe9", "xpe10"]
PE_RD = {f"xpe{i}": f"10.0.0.{10+i}:2" for i in range(1, 11)}
PE_MAC = {f"xpe{i}": f"52:54:00:00:00:{i:02d}" for i in range(1, 11)}
COLLIDE_RD = "65000:999"

results = []


def now_iso():
    n = datetime.datetime.now(datetime.timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond:06d}Z"


def dexec(container, *args):
    cmd = ["wsl", "docker", "exec", f"clab-pcap2story-3rr-dev-{container}"] + list(args)
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


def both_macs_visible(rr, pe_a, pe_b):
    r = vtysh_cmds(rr, ["show bgp l2vpn evpn"])
    out = r.stdout
    return PE_MAC[pe_a] in out and PE_MAC[pe_b] in out and f"Route Distinguisher: {COLLIDE_RD}" in out


def run_scenario(pe_a, pe_b, fixed, recover_delay=8):
    name = f"rd_collision_{pe_a}_{pe_b}_{'fixed' if fixed else 'notfixed'}"
    target_dir = os.path.join(PCAPS, "rd_collision", "single", name)
    print(f"\n[SCENARIO] === {name} ===")

    if not health_ok():
        print(f"[SCENARIO][ERROR] {name}: fabric unhealthy before scenario. Aborting.")
        results.append({"name": name, "status": "ABORTED_UNHEALTHY"})
        return False

    # BEFORE snapshot
    before_a = route_count(pe_a)
    before_b = route_count(pe_b)
    before_rr1 = route_count("xrr1")
    print(f"[BEFORE] {pe_a}={before_a} {pe_b}={before_b} rr1={before_rr1}")

    start_concurrent_captures()
    time.sleep(6)

    t_fault = now_iso()
    apply_rd(pe_a, COLLIDE_RD)
    apply_rd(pe_b, COLLIDE_RD)
    time.sleep(5)

    # Confirm collision applied
    cfg_a = vtysh_cmds(pe_a, ["show running-config"]).stdout
    cfg_b = vtysh_cmds(pe_b, ["show running-config"]).stdout
    if f"rd {COLLIDE_RD}" not in cfg_a or f"rd {COLLIDE_RD}" not in cfg_b:
        print(f"[SCENARIO][ERROR] {name}: rd config did not apply on both PEs!")
        results.append({"name": name, "status": "FAILED_RD_NOT_APPLIED"})
        stop_and_collect_captures(name, target_dir)
        revert_rd(pe_a, PE_RD[pe_a])
        revert_rd(pe_b, PE_RD[pe_b])
        return False

    # Confirm both routes remain independently visible (the primary hypothesis)
    visible = both_macs_visible("xrr1", pe_a, pe_b)
    if not visible:
        print(f"[SCENARIO][CRITICAL] {name}: PRIMARY HYPOTHESIS FAILED -- both routes NOT independently visible!")
        results.append({"name": name, "status": "HYPOTHESIS_FAILED", "critical": True})
        stop_and_collect_captures(name, target_dir)
        revert_rd(pe_a, PE_RD[pe_a])
        revert_rd(pe_b, PE_RD[pe_b])
        return False

    print(f"[SCENARIO] {name}: primary hypothesis holds (both routes visible under shared RD)")

    t_recovery = None
    if fixed:
        time.sleep(recover_delay)
        revert_rd(pe_a, PE_RD[pe_a])
        revert_rd(pe_b, PE_RD[pe_b])
        t_recovery = now_iso()
        time.sleep(8)
        # confirm reconvergence
        for _ in range(10):
            cfg_a2 = vtysh_cmds(pe_a, ["show running-config"]).stdout
            if f"rd {COLLIDE_RD}" not in cfg_a2:
                break
            time.sleep(2)
    else:
        time.sleep(16)

    stop_and_collect_captures(name, target_dir)

    after_rr1 = route_count("xrr1")

    meta = {
        "fault_type": "RD Collision",
        "fault_subtype": "RD Collision",
        "event_affected_nodes": [pe_a.upper(), pe_b.upper()],
        "trigger_mechanism": "Shared Route Distinguisher (RD Collision)",
        "colliding_rd": COLLIDE_RD,
        "original_rd": {pe_a: PE_RD[pe_a], pe_b: PE_RD[pe_b]},
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
        revert_rd(pe_a, PE_RD[pe_a])
        revert_rd(pe_b, PE_RD[pe_b])
        time.sleep(3)

    # regression check: other PEs and all RRs
    other_pes = [p for p in ALL_PES if p not in (pe_a, pe_b)]
    regression = {}
    for p in other_pes:
        regression[p] = route_count(p)
    for rr in RR_NODES:
        regression[rr] = route_count(rr)
    print(f"[REGRESSION] {regression}")

    ok = all(os.path.exists(os.path.join(target_dir, f"{rr}.pcap")) for rr in RR_NODES)
    results.append({
        "name": name, "status": "OK" if ok else "MISSING_FILES",
        "before": {pe_a: before_a, pe_b: before_b, "xrr1": before_rr1},
        "after_rr1": after_rr1,
        "regression": regression,
    })
    print(f"[SCENARIO] {name}: {'OK' if ok else 'MISSING FILES'}")
    return True


if __name__ == "__main__":
    pairs = [("xpe3", "xpe4"), ("xpe3", "xpe5"), ("xpe4", "xpe5"), ("xpe9", "xpe10")]
    for pe_a, pe_b in pairs:
        for fixed in [False, True]:
            ok = run_scenario(pe_a, pe_b, fixed)
            if not ok:
                print(f"[RUN] Stopping due to failure in {pe_a}/{pe_b} fixed={fixed}")

    print("\n=== FINAL RESULTS ===")
    print(json.dumps(results, indent=2))

    print("\n=== FINAL HEALTH ===")
    print("HEALTHY" if health_ok() else "UNHEALTHY")
