"""
Batch 2 of multi-incident generation for 3rr (10PE/3RR): pe_cease x2,
rt_misconfig x2, mac_mobility x2 (two distinct identities, xpe3/4/5 only),
rd_collision second group, and 2 Category C pairs (mac_mobility+rd_collision,
link_down+rt_misconfig).
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
    return subprocess.run(["wsl", "docker", "exec", f"clab-pcap2story-3rr-dev-{c}"] + list(a), capture_output=True, text=True)


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
    return AS.ensure_healthy("multi_batch2_3rr")


def gen_pe_cease_x2():
    name = "pe_cease_x2_xpe2_xpe9"
    target_dir = os.path.join(PCAPS, "catB_pe_cease_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(8)
    t1 = AS.now_iso()
    AS.pe_cease_inject("xpe2")
    time.sleep(10)
    AS.pe_cease_recover("xpe2")
    tr1 = AS.now_iso()
    time.sleep(6)
    t2 = AS.now_iso()
    AS.pe_cease_inject("xpe9")
    time.sleep(30)
    stop_and_collect_captures(name, target_dir)
    AS.pe_cease_recover("xpe9")
    meta = {"multi_incident": True, "category": "B", "fault_type": "PE Cease", "incidents": [
        {"event_affected_node": "XPE2", "fault_type": "PE Cease", "trigger_mechanism": "Cease/Administrative Shutdown",
         "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
        {"event_affected_node": "XPE9", "fault_type": "PE Cease", "trigger_mechanism": "Cease/Administrative Shutdown",
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
    ]}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_rt_misconfig_x2():
    name = "rt_misconfig_x2_xpe1_xpe10"
    target_dir = os.path.join(PCAPS, "catB_rt_misconfig_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    start_concurrent_captures()
    time.sleep(5)
    t1 = AS.now_iso()
    AS.rt_import_only_inject("xpe1")
    time.sleep(12)
    t2 = AS.now_iso()
    AS.rt_autoderive_inject("xpe10")
    time.sleep(20)
    stop_and_collect_captures(name, target_dir)
    AS.rt_import_only_recover("xpe1")
    AS.rt_autoderive_recover("xpe10")
    meta = {"multi_incident": True, "category": "B", "fault_type": "RT Misconfiguration", "incidents": [
        {"event_affected_node": "XPE1", "fault_type": "RT Misconfiguration", "trigger_mechanism": "Plain Import/Export Mismatch",
         "time_of_first_fault": t1, "recovered": False, "time_of_recovery": None,
         "configured_export_rt": "100:1 (export)", "configured_import_rt": "200:1 (mismatched import)"},
        {"event_affected_node": "XPE10", "fault_type": "RT Misconfiguration", "trigger_mechanism": "Auto-Derived Mismatch",
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None,
         "configured_export_rt": "65000:100 (auto)", "configured_import_rt": "100:1 (peer explicit import)"},
    ]}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_mac_mobility_x2():
    name = "mac_mobility_x2_xpe3to4_xpe5to3"
    target_dir = os.path.join(PCAPS, "catB_mac_mobility_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    MAC_A, IP_A = "02:00:00:00:99:01", "10.100.0.201"
    MAC_B, IP_B = "02:00:00:00:99:02", "10.100.0.202"
    start_concurrent_captures()
    time.sleep(6)
    t1 = AS.now_iso()
    add_mac("xpe3", MAC_A, IP_A); time.sleep(4)
    del_mac("xpe3", MAC_A, IP_A); add_mac("xpe4", MAC_A, IP_A); time.sleep(6)
    m1_w = not is_local("xpe3", MAC_A); m1_p = is_present("xpe4", MAC_A)
    time.sleep(5)
    t2 = AS.now_iso()
    add_mac("xpe5", MAC_B, IP_B); time.sleep(4)
    del_mac("xpe5", MAC_B, IP_B); add_mac("xpe3", MAC_B, IP_B); time.sleep(6)
    m2_w = not is_local("xpe5", MAC_B); m2_p = is_present("xpe3", MAC_B)
    time.sleep(5)
    stop_and_collect_captures(name, target_dir)
    del_mac("xpe4", MAC_A, IP_A); del_mac("xpe3", MAC_B, IP_B)
    meta = {"multi_incident": True, "category": "B", "fault_type": "mac_mobility", "incidents": [
        {"event_affected_node": "XPE3", "fault_type": "mac_mobility", "mechanism": "clean_move",
         "origin_pe": "XPE3", "destination_pe": "XPE4", "test_mac": MAC_A, "test_ip": IP_A,
         "time_of_move": t1, "origin_route_withdrawn": m1_w, "route_transferred": m1_w and m1_p},
        {"event_affected_node": "XPE5", "fault_type": "mac_mobility", "mechanism": "clean_move",
         "origin_pe": "XPE5", "destination_pe": "XPE3", "test_mac": MAC_B, "test_ip": IP_B,
         "time_of_move": t2, "origin_route_withdrawn": m2_w, "route_transferred": m2_w and m2_p},
    ], "independence_note": "Two distinct MAC/IP identities; XPE3 appears as origin then destination (only xpe3/4/5 eligible per project convention)."}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK", "move1": m1_w and m1_p, "move2": m2_w and m2_p})
    print(f"[DONE] {name}")


def gen_rd_collision_x2():
    name = "rd_collision_x2_xpe1xpe2_xpe8xpe9"
    target_dir = os.path.join(PCAPS, "catB_rd_collision_x2", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    RD1, RD2 = "65000:999", "65000:888"
    ORIG = {"xpe1": "10.0.0.11:2", "xpe2": "10.0.0.12:2", "xpe8": "10.0.0.18:2", "xpe9": "10.0.0.19:2"}

    def apply_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])

    def revert_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {rd}"])

    start_concurrent_captures()
    time.sleep(6)
    t1 = AS.now_iso()
    apply_rd("xpe1", RD1); apply_rd("xpe2", RD1)
    time.sleep(8)
    revert_rd("xpe1", RD1); revert_rd("xpe2", RD1)
    tr1 = AS.now_iso()
    time.sleep(6)
    t2 = AS.now_iso()
    apply_rd("xpe8", RD2); apply_rd("xpe9", RD2)
    time.sleep(16)
    stop_and_collect_captures(name, target_dir)
    revert_rd("xpe8", RD2); revert_rd("xpe9", RD2)
    meta = {"multi_incident": True, "category": "B", "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision", "incidents": [
        {"event_affected_nodes": ["XPE1", "XPE2"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
         "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": RD1,
         "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
        {"event_affected_nodes": ["XPE8", "XPE9"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
         "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": RD2,
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
    ], "independence_note": "Fully disjoint PE groups (xpe1/xpe2 vs xpe8/xpe9, different RRs entirely) -- feasible here unlike 2rr's 3-PE constraint."}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_catC_macmobility_rdcollision():
    name = "catC_macmobility_xpe4to5_rdcollision_xpe8xpe9"
    target_dir = os.path.join(PCAPS, "catC_mac_mobility_rd_collision", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    MAC_C, IP_C = "02:00:00:00:99:03", "10.100.0.203"
    RD = "65000:777"

    def apply_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])

    def revert_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {rd}"])

    start_concurrent_captures()
    time.sleep(6)
    t1 = AS.now_iso()
    add_mac("xpe4", MAC_C, IP_C); time.sleep(4)
    del_mac("xpe4", MAC_C, IP_C); add_mac("xpe5", MAC_C, IP_C); time.sleep(6)
    origin_w = not is_local("xpe4", MAC_C); dest_p = is_present("xpe5", MAC_C)
    time.sleep(5)
    t2 = AS.now_iso()
    apply_rd("xpe8", RD); apply_rd("xpe9", RD)
    time.sleep(16)
    stop_and_collect_captures(name, target_dir)
    del_mac("xpe5", MAC_C, IP_C)
    revert_rd("xpe8", RD); revert_rd("xpe9", RD)
    meta = {"multi_incident": True, "category": "C", "incidents": [
        {"event_affected_node": "XPE4", "fault_type": "mac_mobility", "mechanism": "clean_move",
         "origin_pe": "XPE4", "destination_pe": "XPE5", "test_mac": MAC_C, "test_ip": IP_C,
         "time_of_move": t1, "origin_route_withdrawn": origin_w, "route_transferred": origin_w and dest_p},
        {"event_affected_nodes": ["XPE8", "XPE9"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
         "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": RD,
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
    ], "causal_relationship": "none -- MAC move on xpe4/xpe5 (xrr1/xrr2 domains) fully independent from RD collision on xpe8/xpe9 (xrr3 domain)"}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_catC_linkdown_rtmisconfig():
    name = "catC_linkdown_xpe2_rtmisconfig_xpe7"
    target_dir = os.path.join(PCAPS, "catC_link_down_rt_misconfig", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    AS.discover_pe_interfaces()
    start_concurrent_captures()
    time.sleep(8)
    t1 = AS.now_iso()
    AS.link_down_bfd_inject("xpe2")
    time.sleep(10)
    AS.link_down_bfd_recover("xpe2")
    tr1 = AS.now_iso()
    time.sleep(5)
    t2 = AS.now_iso()
    AS.rt_import_only_inject("xpe7")
    time.sleep(25)
    stop_and_collect_captures(name, target_dir)
    AS.rt_import_only_recover("xpe7")
    meta = {"multi_incident": True, "category": "C", "incidents": [
        {"event_affected_node": "XPE2", "fault_type": "Link Down", "trigger_mechanism": "BFD Down",
         "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
        {"event_affected_node": "XPE7", "fault_type": "RT Misconfiguration", "trigger_mechanism": "Plain Import/Export Mismatch",
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None,
         "configured_export_rt": "100:1 (export)", "configured_import_rt": "200:1 (mismatched import)"},
    ], "causal_relationship": "none -- XPE2 (xrr1 domain) vs XPE7 (xrr2 domain), independent mechanisms"}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


if __name__ == "__main__":
    AS.discover_pe_interfaces()
    gen_pe_cease_x2()
    gen_rt_misconfig_x2()
    gen_mac_mobility_x2()
    gen_rd_collision_x2()
    gen_catC_macmobility_rdcollision()
    gen_catC_linkdown_rtmisconfig()
    print("\n=== RESULTS ===")
    print(json.dumps(RESULTS, indent=2))
    print("HEALTHY" if AS.health_ok() else "UNHEALTHY")
