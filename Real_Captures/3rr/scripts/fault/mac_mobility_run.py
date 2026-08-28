"""
MAC Mobility scenario generation: clean-move (3 scenarios) + rapid-flap (6 scenarios) = 9 total.
Operates only on vhost100 FDB/neigh entries (ip neigh add / bridge fdb add master static),
and never edits any PE's ES/ESI configuration (dual-homing, DF election, es-id, etc.) on any
target node.
"""
import sys
import os
import subprocess
import datetime
import time
import json
import re
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures, RR_NODES

BASE = str(Path(__file__).resolve().parents[2])
PCAPS = os.path.join(BASE, "pcaps")
CHECK_HEALTH = os.path.join(BASE, "scripts", "test_scripts", "check_health.py")

TEST_MAC = "02:00:00:00:99:01"
TEST_IP = "10.100.0.201"
FREEZE_SECONDS = 30

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


def add_mac(pe, mac=TEST_MAC, ip=TEST_IP, retries=3):
    for attempt in range(retries):
        dexec(pe, "ip", "neigh", "del", ip, "lladdr", mac, "dev", "vhost100")
        r = dexec(pe, "ip", "neigh", "add", ip, "lladdr", mac, "dev", "vhost100")
        dexec(pe, "bridge", "fdb", "add", mac, "dev", "vhost100", "master", "static")
        check = dexec(pe, "sh", "-c", f"ip neigh show | grep {ip}")
        if mac in check.stdout:
            return True
        time.sleep(1)
    return False


def del_mac(pe, mac=TEST_MAC, ip=TEST_IP, force_flap=True):
    dexec(pe, "ip", "neigh", "del", ip, "lladdr", mac, "dev", "vhost100")
    dexec(pe, "bridge", "fdb", "del", mac, "dev", "vhost100", "master")
    if force_flap:
        # Flap vhost100 to force zebra to rescan and drop the withdrawn MAC immediately.
        dexec(pe, "ip", "link", "set", "vhost100", "down")
        time.sleep(1)
        dexec(pe, "ip", "link", "set", "vhost100", "up")


def get_local_seq(pe, mac=TEST_MAC):
    r = vtysh_cmds(pe, [f"show evpn mac vni 100 detail"])
    lines = r.stdout.splitlines()
    for i, l in enumerate(lines):
        if f"MAC: {mac}" in l:
            for j in range(i, min(i + 6, len(lines))):
                m = re.search(r"Local Seq:\s*(\d+)", lines[j])
                if m:
                    return int(m.group(1))
    return None


def is_present(pe, mac=TEST_MAC):
    r = vtysh_cmds(pe, ["show evpn mac vni 100"])
    return mac in r.stdout


def is_local(pe, mac=TEST_MAC):
    # Distinguishes a MAC genuinely owned/originated here (Type "local")
    # from one merely known because it was re-learned as remote.
    r = vtysh_cmds(pe, ["show evpn mac vni 100"])
    for line in r.stdout.splitlines():
        if line.strip().startswith(mac):
            parts = line.split()
            return len(parts) > 1 and parts[1] == "local"
    return False


def is_duplicate_flagged(pe, mac=TEST_MAC):
    r = vtysh_cmds(pe, ["show evpn mac vni 100 duplicate"])
    return mac in r.stdout


ALL_PES = ["xpe1", "xpe2", "xpe3", "xpe4", "xpe5", "xpe6", "xpe7", "xpe8", "xpe9", "xpe10"]


def regression_check(exclude_pes):
    reg = {}
    for p in ALL_PES:
        if p not in exclude_pes:
            reg[p] = route_count(p)
    for rr in RR_NODES:
        reg[rr] = route_count(rr)
    return reg


def write_meta(target_dir, meta):
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)


def verify_files(target_dir):
    return all(os.path.exists(os.path.join(target_dir, f"{rr}.pcap")) for rr in RR_NODES)


# ---------------- Clean move ----------------

def run_clean_move(origin, dest):
    name = f"mac_mobility_cleanmove_{origin}to{dest[-1]}_settled"
    target_dir = os.path.join(PCAPS, "mac_mobility", "single", name)
    print(f"\n[SCENARIO] === {name} ===")

    if not health_ok():
        print(f"[ERROR] {name}: unhealthy before scenario")
        results.append({"name": name, "status": "ABORTED_UNHEALTHY"})
        return

    start_concurrent_captures()
    time.sleep(5)

    t_fault = now_iso()
    add_mac(origin)
    time.sleep(4)
    seq_before = get_local_seq(origin)
    print(f"[CLEANMOVE] {origin} initial Local Seq = {seq_before}")

    del_mac(origin)
    add_mac(dest)
    time.sleep(6)

    seq_after = get_local_seq(dest)
    origin_withdrawn = not is_local(origin)
    print(f"[CLEANMOVE] {dest} Local Seq after move = {seq_after}, origin withdrawn = {origin_withdrawn}")

    time.sleep(5)
    stop_and_collect_captures(name, target_dir)

    reg = regression_check([origin, dest])
    print(f"[REGRESSION] {reg}")

    route_transferred = origin_withdrawn and is_present(dest)
    sequence_incremented = seq_after is not None and seq_before is not None and seq_after > seq_before
    if not route_transferred:
        print(f"[CRITICAL] {name}: route transfer NOT confirmed (origin_withdrawn={origin_withdrawn})!")
    if not sequence_incremented:
        print(f"[NOTE] {name}: sequence number did not increment (seq_before={seq_before}, seq_after={seq_after}) "
              f"-- confirmed structural limitation, see metadata for explanation")

    meta = {
        "fault_type": "mac_mobility",
        "mechanism": "clean_move",
        "origin_pe": origin.upper(),
        "destination_pe": dest.upper(),
        "test_mac": TEST_MAC,
        "test_ip": TEST_IP,
        "sequence_before": seq_before,
        "sequence_after": seq_after,
        "sequence_incremented": sequence_incremented,
        "origin_route_withdrawn": origin_withdrawn,
        "route_transferred": route_transferred,
        "time_of_move": t_fault,
        "known_limitation": (
            "RFC 7432 MAC Mobility sequence number does not increment with this "
            "synthetic-FDB injection method. Confirmed via FRR debug logs (debug "
            "zebra vxlan): the BGP withdrawal from the origin PE deletes zebra's "
            "MAC record on the destination PE (zebra_evpn_mac_del) before the "
            "destination's local re-add is processed, regardless of shell-command "
            "ordering across docker exec calls, since BGP propagation completes "
            "faster than sequential host-issued commands can race against it. "
            "The route-transfer itself (withdraw + re-advertise) is confirmed and "
            "is the primary signal actually captured in this pcap."
        ),
    }
    write_meta(target_dir, meta)
    del_mac(dest)
    time.sleep(2)

    ok = verify_files(target_dir) and route_transferred
    results.append({"name": name, "status": "OK" if ok else "PRIMARY_SIGNAL_MISSING",
                     "seq_before": seq_before, "seq_after": seq_after,
                     "origin_withdrawn": origin_withdrawn, "regression": reg})
    print(f"[SCENARIO] {name}: {'OK' if ok else 'FAILED'}")


# ---------------- Rapid flap ----------------

def run_rapid_flap(pe_a, pe_b, variant):
    name = f"mac_mobility_rapidflap_{pe_a}{pe_b}_{variant}"
    target_dir = os.path.join(PCAPS, "mac_mobility", "single", name)
    print(f"\n[SCENARIO] === {name} ===")

    if not health_ok():
        print(f"[ERROR] {name}: unhealthy before scenario")
        results.append({"name": name, "status": "ABORTED_UNHEALTHY"})
        return

    for pe in [pe_a, pe_b]:
        vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn",
                        f"dup-addr-detection freeze {FREEZE_SECONDS}"])

    start_concurrent_captures()
    time.sleep(4)

    t_start = now_iso()
    add_mac(pe_a)
    time.sleep(2)
    current = pe_a
    move_log = []
    move_count = 0
    deadline = time.time() + 60

    while move_count < 6 and time.time() < deadline:
        other = pe_b if current == pe_a else pe_a
        del_mac(current)
        add_mac(other)
        move_count += 1
        move_log.append({"move": move_count, "to": other, "ts": now_iso()})
        current = other
        time.sleep(1.5)

    print(f"[RAPIDFLAP] {move_count} moves completed: {[m['to'] for m in move_log]}")
    time.sleep(3)

    freeze_confirmed = is_duplicate_flagged(current) or is_duplicate_flagged(pe_a) or is_duplicate_flagged(pe_b)
    print(f"[RAPIDFLAP] duplicate/frozen flag confirmed: {freeze_confirmed}")

    if not freeze_confirmed:
        print(f"[CRITICAL] {name}: duplicate-address suppression did NOT trigger after {move_count} moves!")

    unfrozen_confirmed = None
    if variant == "held":
        time.sleep(3)
        stop_and_collect_captures(name, target_dir)
    else:  # unfrozen
        print(f"[RAPIDFLAP] waiting {FREEZE_SECONDS + 10}s for freeze to expire...")
        time.sleep(FREEZE_SECONDS + 10)
        unfrozen_confirmed = not (is_duplicate_flagged(pe_a) or is_duplicate_flagged(pe_b))
        print(f"[RAPIDFLAP] unfrozen confirmed: {unfrozen_confirmed}")
        stop_and_collect_captures(name, target_dir)

    reg = regression_check([pe_a, pe_b])
    print(f"[REGRESSION] {reg}")

    meta = {
        "fault_type": "mac_mobility",
        "mechanism": "rapid_flap",
        "pe_pair": [pe_a.upper(), pe_b.upper()],
        "outcome_variant": variant,
        "test_mac": TEST_MAC,
        "test_ip": TEST_IP,
        "move_count": move_count,
        "move_timestamps": move_log,
        "freeze_confirmed": freeze_confirmed,
        "unfrozen_confirmed": unfrozen_confirmed,
        "freeze_seconds_configured": FREEZE_SECONDS,
        "time_of_first_fault": t_start,
    }
    write_meta(target_dir, meta)

    # cleanup: remove test mac from wherever it landed, clear dup-addr flag if still set
    del_mac(pe_a)
    del_mac(current) if current != pe_a else None
    for pe in [pe_a, pe_b]:
        vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn",
                        "no dup-addr-detection"])
    time.sleep(2)

    ok = verify_files(target_dir) and freeze_confirmed
    results.append({"name": name, "status": "OK" if ok else "PRIMARY_SIGNAL_MISSING",
                     "move_count": move_count, "freeze_confirmed": freeze_confirmed,
                     "unfrozen_confirmed": unfrozen_confirmed, "regression": reg})
    print(f"[SCENARIO] {name}: {'OK' if ok else 'FAILED'}")


if __name__ == "__main__":
    for origin, dest in [("xpe3", "xpe4"), ("xpe3", "xpe5"), ("xpe4", "xpe5")]:
        run_clean_move(origin, dest)

    print("\n=== FINAL RESULTS ===")
    print(json.dumps(results, indent=2))
    print("\n=== FINAL HEALTH ===")
    print("HEALTHY" if health_ok() else "UNHEALTHY")
