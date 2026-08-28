"""
Batch 2 of multi-incident generation for 2rr: pe_cease x2,
rt_misconfig x2, mac_mobility x2, rd_collision second group, and the 2
remaining Category C pairs (rr_down+pe_cease non-homed, mac_mobility+rd_collision).
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures
import All_Scenarios as AS

PCAPS = os.path.join(AS.BASE, "pcaps", "multiple")
RESULTS = []


def dexec(c, *a):
    import subprocess
    return subprocess.run(["wsl", "docker", "exec", f"clab-pcap2story-{c}"] + list(a), capture_output=True, text=True)


def vtysh(c, cmds):
    args = ["vtysh"]
    for x in cmds:
        args += ["-c", x]
    return dexec(c, *args)


def add_mac(pe, mac, ip):
    for _ in range(3):
        dexec(pe, "ip", "neigh", "del", ip, "lladdr", mac, "dev", "vhost100")
        dexec(pe, "ip", "neigh", "add", ip, "lladdr", mac, "dev", "vhost100")
        dexec(pe, "bridge", "fdb", "add", mac, "dev", "vhost100", "master", "static")
        check = dexec(pe, "sh", "-c", f"ip neigh show | grep {ip}")
        if mac in check.stdout:
            return True
        time.sleep(1)
    return False


def del_mac(pe, mac, ip):
    dexec(pe, "ip", "neigh", "del", ip, "lladdr", mac, "dev", "vhost100")
    dexec(pe, "bridge", "fdb", "del", mac, "dev", "vhost100", "master")
    dexec(pe, "ip", "link", "set", "vhost100", "down")
    time.sleep(1)
    dexec(pe, "ip", "link", "set", "vhost100", "up")


def is_present(pe, mac):
    r = vtysh(pe, ["show evpn mac vni 100"])
    return mac in r.stdout


def is_local(pe, mac):
    r = vtysh(pe, ["show evpn mac vni 100"])
    for line in r.stdout.splitlines():
        if line.strip().startswith(mac):
            parts = line.split()
            return len(parts) > 1 and parts[1] == "local"
    return False


def write_meta(target_dir, meta):
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)


def ensure_healthy():
    return AS.ensure_healthy("multi_batch2")


# ---------------- pe_cease x2 ----------------

def gen_pe_cease_x2():
    name = "pe_cease_x2_pe2_pe5"
    target_dir = os.path.join(PCAPS, "catB_pe_cease_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    proc = start_concurrent_captures()
    time.sleep(8)

    t1 = AS.now_iso()
    AS.pe_cease_inject("pe2")
    time.sleep(10)
    AS.pe_cease_recover("pe2")
    tr1 = AS.now_iso()

    time.sleep(6)

    t2 = AS.now_iso()
    AS.pe_cease_inject("pe5")
    time.sleep(30)  # not recovered within window

    stop_and_collect_captures(name, target_dir)
    AS.pe_cease_recover("pe5")  # restore baseline outside capture

    meta = {
        "multi_incident": True, "category": "B", "fault_type": "PE Cease",
        "incidents": [
            {"event_affected_node": "PE2", "fault_type": "PE Cease", "trigger_mechanism": "Cease/Administrative Shutdown",
             "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
            {"event_affected_node": "PE5", "fault_type": "PE Cease", "trigger_mechanism": "Cease/Administrative Shutdown",
             "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
        ],
    }
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


# ---------------- rt_misconfig x2 ----------------

def gen_rt_misconfig_x2():
    name = "rt_misconfig_x2_pe1_pe5"
    target_dir = os.path.join(PCAPS, "catB_rt_misconfig_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    proc = start_concurrent_captures()
    time.sleep(5)

    t1 = AS.now_iso()
    AS.rt_import_only_inject("pe1")
    time.sleep(12)

    t2 = AS.now_iso()
    AS.rt_autoderive_inject("pe5")
    time.sleep(20)

    stop_and_collect_captures(name, target_dir)
    AS.rt_import_only_recover("pe1")
    AS.rt_autoderive_recover("pe5")

    meta = {
        "multi_incident": True, "category": "B", "fault_type": "RT Misconfiguration",
        "incidents": [
            {"event_affected_node": "PE1", "fault_type": "RT Misconfiguration", "trigger_mechanism": "Plain Import/Export Mismatch",
             "time_of_first_fault": t1, "recovered": False, "time_of_recovery": None,
             "configured_export_rt": "100:1 (export)", "configured_import_rt": "200:1 (mismatched import)"},
            {"event_affected_node": "PE5", "fault_type": "RT Misconfiguration", "trigger_mechanism": "Auto-Derived Mismatch",
             "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None,
             "configured_export_rt": "65000:100 (auto)", "configured_import_rt": "100:1 (peer explicit import)"},
        ],
    }
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


# ---------------- mac_mobility x2 (two distinct identities, pe3/pe4/pe5 only) ----------------

def gen_mac_mobility_x2():
    name = "mac_mobility_x2_pe3to4_pe5to3"
    target_dir = os.path.join(PCAPS, "catB_mac_mobility_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    MAC_A, IP_A = "02:00:00:00:99:01", "10.100.0.201"
    MAC_B, IP_B = "02:00:00:00:99:02", "10.100.0.202"

    proc = start_concurrent_captures()
    time.sleep(6)

    t1 = AS.now_iso()
    add_mac("pe3", MAC_A, IP_A)
    time.sleep(4)
    del_mac("pe3", MAC_A, IP_A)
    add_mac("pe4", MAC_A, IP_A)
    time.sleep(6)
    move1_origin_withdrawn = not is_local("pe3", MAC_A)
    move1_dest_present = is_present("pe4", MAC_A)

    time.sleep(5)

    t2 = AS.now_iso()
    add_mac("pe5", MAC_B, IP_B)
    time.sleep(4)
    del_mac("pe5", MAC_B, IP_B)
    add_mac("pe3", MAC_B, IP_B)
    time.sleep(6)
    move2_origin_withdrawn = not is_local("pe5", MAC_B)
    move2_dest_present = is_present("pe3", MAC_B)

    time.sleep(5)
    stop_and_collect_captures(name, target_dir)

    del_mac("pe4", MAC_A, IP_A)
    del_mac("pe3", MAC_B, IP_B)

    meta = {
        "multi_incident": True, "category": "B", "fault_type": "mac_mobility",
        "incidents": [
            {"event_affected_node": "PE3", "fault_type": "mac_mobility", "mechanism": "clean_move",
             "origin_pe": "PE3", "destination_pe": "PE4", "test_mac": MAC_A, "test_ip": IP_A,
             "time_of_move": t1, "origin_route_withdrawn": move1_origin_withdrawn, "route_transferred": move1_origin_withdrawn and move1_dest_present},
            {"event_affected_node": "PE5", "fault_type": "mac_mobility", "mechanism": "clean_move",
             "origin_pe": "PE5", "destination_pe": "PE3", "test_mac": MAC_B, "test_ip": IP_B,
             "time_of_move": t2, "origin_route_withdrawn": move2_origin_withdrawn, "route_transferred": move2_origin_withdrawn and move2_dest_present},
        ],
        "independence_note": "Two distinct MAC/IP identities used (MAC_A on PE3->PE4, MAC_B on PE5->PE3) so the two moves are wire-distinguishable events, not the same object moved twice. PE3 appears in both incidents (as origin in incident 1, destination in incident 2) because only pe3/pe4/pe5 are eligible per project convention (pe1/pe2 vhost100 untouched) -- disclosed here rather than hidden.",
    }
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK", "move1_transferred": move1_origin_withdrawn and move1_dest_present, "move2_transferred": move2_origin_withdrawn and move2_dest_present})
    print(f"[DONE] {name}")


# ---------------- rd_collision second group ----------------

def gen_rd_collision_second_group():
    name = "rd_collision_x2_pe3pe4_pe4pe5"
    target_dir = os.path.join(PCAPS, "catB_rd_collision_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    COLLIDE_RD_1 = "65000:999"
    COLLIDE_RD_2 = "65000:888"
    ORIG_RD = {"pe3": "10.0.0.13:2", "pe4": "10.0.0.14:2", "pe5": "10.0.0.15:2"}

    def apply_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])

    def revert_rd(pe, rd, orig):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {rd}"])

    proc = start_concurrent_captures()
    time.sleep(6)

    t1 = AS.now_iso()
    apply_rd("pe3", COLLIDE_RD_1)
    apply_rd("pe4", COLLIDE_RD_1)
    time.sleep(8)
    revert_rd("pe3", COLLIDE_RD_1, ORIG_RD["pe3"])
    revert_rd("pe4", COLLIDE_RD_1, ORIG_RD["pe4"])
    tr1 = AS.now_iso()

    time.sleep(6)

    t2 = AS.now_iso()
    apply_rd("pe4", COLLIDE_RD_2)
    apply_rd("pe5", COLLIDE_RD_2)
    time.sleep(16)  # left unfixed within window

    stop_and_collect_captures(name, target_dir)
    revert_rd("pe4", COLLIDE_RD_2, ORIG_RD["pe4"])
    revert_rd("pe5", COLLIDE_RD_2, ORIG_RD["pe5"])

    meta = {
        "multi_incident": True, "category": "B", "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
        "incidents": [
            {"event_affected_nodes": ["PE3", "PE4"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
             "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": COLLIDE_RD_1,
             "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
            {"event_affected_nodes": ["PE4", "PE5"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
             "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": COLLIDE_RD_2,
             "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
        ],
        "independence_note": "PE4 participates in both groups (only pe3/pe4/pe5 eligible per project convention -- 3 PEs cannot form 2 fully disjoint RD-collision pairs). Colliding RD values differ (65000:999 vs 65000:888) and events are temporally separated with the first fully reverted before the second begins, so they are still two distinct, independently-triggered fault instances rather than one continuous fault -- but full node-disjointness was not achievable and is disclosed here.",
    }
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


# ---------------- Category C pair 2: rr_down + pe_cease (non-homed) ----------------

def gen_catC_rrdown_pecease():
    name = "catC_rrdown_rr2_pecease_pe1"
    target_dir = os.path.join(PCAPS, "catC_rr_down_pe_cease", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    proc = start_concurrent_captures()
    time.sleep(8)

    # RR2 down (graceful)
    t1 = AS.now_iso()
    AS.rr_down_graceful_inject("rr2")
    time.sleep(10)
    AS.rr_down_graceful_recover("rr2")
    tr1 = AS.now_iso()

    time.sleep(5)

    # PE1 cease
    t2 = AS.now_iso()
    AS.pe_cease_inject("pe1")
    time.sleep(20)

    stop_and_collect_captures(name, target_dir)
    AS.pe_cease_recover("pe1")

    meta = {
        "multi_incident": True, "category": "C",
        "incidents": [
            {"event_affected_node": "RR2", "fault_type": "RR Down", "trigger_mechanism": "Cease/Administrative Shutdown",
             "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
            {"event_affected_node": "PE1", "fault_type": "PE Cease", "trigger_mechanism": "Cease/Administrative Shutdown",
             "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
        ],
        "causal_relationship": "none -- PE1 is homed to RR1, not RR2, so RR2's outage cannot have caused PE1's cease",
    }
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


# ---------------- Category C pair 3: mac_mobility + rd_collision (different node sets) ----------------

def gen_catC_macmobility_rdcollision():
    name = "catC_macmobility_pe4to5_rdcollision_pe3pe4"
    target_dir = os.path.join(PCAPS, "catC_mac_mobility_rd_collision", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    MAC_C, IP_C = "02:00:00:00:99:03", "10.100.0.203"
    COLLIDE_RD = "65000:777"
    ORIG_RD = {"pe3": "10.0.0.13:2", "pe4": "10.0.0.14:2"}

    def apply_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])

    def revert_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {rd}"])

    proc = start_concurrent_captures()
    time.sleep(6)

    t1 = AS.now_iso()
    add_mac("pe4", MAC_C, IP_C)
    time.sleep(4)
    del_mac("pe4", MAC_C, IP_C)
    add_mac("pe5", MAC_C, IP_C)
    time.sleep(6)
    origin_withdrawn = not is_local("pe4", MAC_C)
    dest_present = is_present("pe5", MAC_C)

    time.sleep(5)

    t2 = AS.now_iso()
    apply_rd("pe3", COLLIDE_RD)
    apply_rd("pe4", COLLIDE_RD)
    time.sleep(16)

    stop_and_collect_captures(name, target_dir)
    del_mac("pe5", MAC_C, IP_C)
    revert_rd("pe3", COLLIDE_RD)
    revert_rd("pe4", COLLIDE_RD)

    meta = {
        "multi_incident": True, "category": "C",
        "incidents": [
            {"event_affected_node": "PE4", "fault_type": "mac_mobility", "mechanism": "clean_move",
             "origin_pe": "PE4", "destination_pe": "PE5", "test_mac": MAC_C, "test_ip": IP_C,
             "time_of_move": t1, "origin_route_withdrawn": origin_withdrawn, "route_transferred": origin_withdrawn and dest_present},
            {"event_affected_nodes": ["PE3", "PE4"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
             "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": COLLIDE_RD,
             "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
        ],
        "causal_relationship": "none -- MAC move targets PE4/PE5 identity churn; RD collision targets PE3/PE4 route-distinguisher config; different mechanisms, independently triggered, node overlap only at PE4 which is incidental (not causal)",
    }
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


if __name__ == "__main__":
    AS.discover_pe_interfaces()
    gen_pe_cease_x2()
    gen_rt_misconfig_x2()
    gen_mac_mobility_x2()
    gen_rd_collision_second_group()
    gen_catC_rrdown_pecease()
    gen_catC_macmobility_rdcollision()
    print("\n=== RESULTS ===")
    print(json.dumps(RESULTS, indent=2))
    print("HEALTHY" if AS.health_ok() else "UNHEALTHY")
