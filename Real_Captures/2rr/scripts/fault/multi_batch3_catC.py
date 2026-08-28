"""
Batch 3, 2rr: the 3 remaining Category C pairs: link_down +
mac_mobility, rt_misconfig + rd_collision, pe_cease + rd_collision.
mac_mobility/rd_collision restricted to pe3/pe4/pe5.
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


def is_local(pe, mac):
    r = vtysh(pe, ["show evpn mac vni 100"])
    for line in r.stdout.splitlines():
        if line.strip().startswith(mac):
            parts = line.split()
            return len(parts) > 1 and parts[1] == "local"
    return False


def is_present(pe, mac):
    r = vtysh(pe, ["show evpn mac vni 100"])
    return mac in r.stdout


def write_meta(target_dir, meta):
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)


def ensure_healthy():
    return AS.ensure_healthy("multi_batch3_catC_pilot")


def gen_catC_linkdown_macmobility():
    name = "catC_linkdown_pe1_macmobility_pe4to5"
    target_dir = os.path.join(PCAPS, "catC_link_down_mac_mobility", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    AS.discover_pe_interfaces()
    MAC, IP = "02:00:00:00:99:10", "10.100.0.210"
    start_concurrent_captures()
    time.sleep(8)
    t1 = AS.now_iso()
    AS.link_down_bfd_inject("pe1")
    time.sleep(10)
    AS.link_down_bfd_recover("pe1")
    tr1 = AS.now_iso()
    time.sleep(5)
    t2 = AS.now_iso()
    add_mac("pe4", MAC, IP); time.sleep(4)
    del_mac("pe4", MAC, IP); add_mac("pe5", MAC, IP); time.sleep(6)
    origin_w = not is_local("pe4", MAC); dest_p = is_present("pe5", MAC)
    time.sleep(5)
    stop_and_collect_captures(name, target_dir)
    del_mac("pe5", MAC, IP)
    meta = {"multi_incident": True, "category": "C", "incidents": [
        {"event_affected_node": "PE1", "fault_type": "Link Down", "trigger_mechanism": "BFD Down",
         "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
        {"event_affected_node": "PE4", "fault_type": "mac_mobility", "mechanism": "clean_move",
         "origin_pe": "PE4", "destination_pe": "PE5", "test_mac": MAC, "test_ip": IP,
         "time_of_move": t2, "origin_route_withdrawn": origin_w, "route_transferred": origin_w and dest_p},
    ], "causal_relationship": "none -- PE1 is the ES pair member (rr1 domain) vs mac move on pe4/pe5 (non-ES, rr2 domain), independent"}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_catC_rtmisconfig_rdcollision():
    name = "catC_rtmisconfig_pe1_rdcollision_pe3pe4"
    target_dir = os.path.join(PCAPS, "catC_rt_misconfig_rd_collision", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    RD = "65000:555"

    def apply_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])

    def revert_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {rd}"])

    start_concurrent_captures()
    time.sleep(8)
    t1 = AS.now_iso()
    AS.rt_import_only_inject("pe1")
    time.sleep(10)
    t2 = AS.now_iso()
    apply_rd("pe3", RD); apply_rd("pe4", RD)
    time.sleep(16)
    stop_and_collect_captures(name, target_dir)
    AS.rt_import_only_recover("pe1")
    revert_rd("pe3", RD); revert_rd("pe4", RD)
    meta = {"multi_incident": True, "category": "C", "incidents": [
        {"event_affected_node": "PE1", "fault_type": "RT Misconfiguration", "trigger_mechanism": "Plain Import/Export Mismatch",
         "time_of_first_fault": t1, "recovered": False, "time_of_recovery": None,
         "configured_export_rt": "100:1 (export)", "configured_import_rt": "200:1 (mismatched import)"},
        {"event_affected_nodes": ["PE3", "PE4"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
         "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": RD,
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
    ], "causal_relationship": "none -- PE1 (ES pair member, rr1 domain) vs RD collision on pe3/pe4 (non-ES, rr1/rr2 domains), independent mechanisms"}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


def gen_catC_pecease_rdcollision():
    name = "catC_pecease_pe2_rdcollision_pe4pe5"
    target_dir = os.path.join(PCAPS, "catC_pe_cease_rd_collision", name)
    if not ensure_healthy():
        RESULTS.append({"name": name, "status": "ABORTED_UNHEALTHY"}); return
    RD = "65000:333"

    def apply_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"rd {rd}"])

    def revert_rd(pe, rd):
        vtysh(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100", f"no rd {rd}"])

    start_concurrent_captures()
    time.sleep(8)
    t1 = AS.now_iso()
    AS.pe_cease_inject("pe2")
    time.sleep(10)
    AS.pe_cease_recover("pe2")
    tr1 = AS.now_iso()
    time.sleep(5)
    t2 = AS.now_iso()
    apply_rd("pe4", RD); apply_rd("pe5", RD)
    time.sleep(16)
    stop_and_collect_captures(name, target_dir)
    revert_rd("pe4", RD); revert_rd("pe5", RD)
    meta = {"multi_incident": True, "category": "C", "incidents": [
        {"event_affected_node": "PE2", "fault_type": "PE Cease", "trigger_mechanism": "Cease/Administrative Shutdown",
         "time_of_first_fault": t1, "recovered": True, "time_of_recovery": tr1},
        {"event_affected_nodes": ["PE4", "PE5"], "fault_type": "RT Misconfiguration", "fault_subtype": "RD Collision",
         "trigger_mechanism": "Shared Route Distinguisher (RD Collision)", "colliding_rd": RD,
         "time_of_first_fault": t2, "recovered": False, "time_of_recovery": None},
    ], "causal_relationship": "none -- PE2 (ES pair member, rr1 domain) vs RD collision on pe4/pe5 (non-ES, rr2 domain), independent mechanisms"}
    write_meta(target_dir, meta)
    RESULTS.append({"name": name, "status": "OK"})
    print(f"[DONE] {name}")


if __name__ == "__main__":
    AS.discover_pe_interfaces()
    gen_catC_linkdown_macmobility()
    gen_catC_rtmisconfig_rdcollision()
    gen_catC_pecease_rdcollision()
    print("\n=== RESULTS ===")
    print(json.dumps(RESULTS, indent=2))
    print("HEALTHY" if AS.health_ok() else "UNHEALTHY")
