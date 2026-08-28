"""
Overnight full generation run: 86 scenarios across 5 categories (Link Down 30,
RR Down 8, PE Cease 10, RT Misconfig 20, Normal 18). Sequential, one scenario
at a time. Health-checked before every scenario; redeploys on failure, retries
the same scenario from scratch.

Run from Windows (not inside WSL), matching project convention.
"""
import sys
import os
import subprocess
import datetime
import time
import json
import shutil
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures

_BASE_PATH = Path(__file__).resolve().parents[2]
BASE = str(_BASE_PATH)
PCAPS = os.path.join(BASE, "pcaps")
_topo_win = _BASE_PATH / "topology" / "5pe_2rr_topology.yml"
TOPO = "/mnt/" + _topo_win.drive[0].lower() + str(_topo_win)[2:].replace("\\", "/")
CHECK_HEALTH = os.path.join(BASE, "scripts", "test_scripts", "check_health.py")
REPORT_PATH = os.path.join(BASE, "logs", "all_scenarios_report.json")

PE_TARGET_IP = {"pe1": "10.0.0.1", "pe2": "10.0.0.1", "pe3": "10.0.0.1", "pe4": "10.0.0.2", "pe5": "10.0.0.2"}
PE_IFACE = {}  # filled at startup by querying running-config
RR_NEIGHBORS = {
    "rr1": ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.2"],
    "rr2": ["10.0.0.14", "10.0.0.15", "10.0.0.1"],
}

redeploy_log = []
scenario_results = []


def now_iso():
    n = datetime.datetime.now(datetime.timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond:06d}Z"


def dexec(container, *args, check=False):
    cmd = ["wsl", "docker", "exec", f"clab-pcap2story-{container}"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def vtysh_cmds(container, cmds):
    args = ["vtysh"]
    for c in cmds:
        args += ["-c", c]
    return dexec(container, *args)


def health_ok():
    r = subprocess.run(["python", CHECK_HEALTH], capture_output=True, text=True)
    return r.returncode == 0


def ensure_tcpdump():
    """(Re)install tcpdump on rr1/rr2."""
    for rr in ["rr1", "rr2"]:
        r = dexec(rr, "sh", "-c", "which tcpdump")
        if r.returncode != 0:
            print(f"[SETUP] Installing tcpdump on {rr}...")
            dexec(rr, "sh", "-c", "apk add tcpdump 2>&1 | tail -3")
        r2 = dexec(rr, "sh", "-c", "which tcpdump")
        if r2.returncode != 0:
            print(f"[SETUP][ERROR] tcpdump still missing on {rr} after install attempt!")


def redeploy(reason):
    ts = now_iso()
    print(f"[REDEPLOY] {ts} reason={reason}")
    redeploy_log.append({"timestamp": ts, "reason": reason})
    subprocess.run(f'wsl containerlab destroy -t "{TOPO}"', shell=True)
    subprocess.run(f'wsl containerlab deploy -t "{TOPO}"', shell=True)
    # wait for health, polling up to 3 min
    deadline = time.time() + 180
    while time.time() < deadline:
        if health_ok():
            print("[REDEPLOY] Fabric healthy after redeploy.")
            ensure_tcpdump()
            return True
        time.sleep(5)
    print("[REDEPLOY][ERROR] Fabric did not become healthy within 180s after redeploy.")
    return False


def ensure_healthy(scenario_name):
    if health_ok():
        return True
    print(f"[HEALTH] Unhealthy before scenario {scenario_name}, redeploying...")
    return redeploy(f"unhealthy before {scenario_name}")


def discover_pe_interfaces():
    for pe, rr_desc in [("pe1", "to-rr1"), ("pe2", "to-rr1"), ("pe3", "to-rr1"),
                         ("pe4", "to-rr2"), ("pe5", "to-rr2")]:
        r = vtysh_cmds(pe, ["show running-config"])
        lines = r.stdout.splitlines()
        iface = None
        for i, l in enumerate(lines):
            if l.strip() == f"interface eth{1}" or l.strip().startswith("interface eth"):
                pass
        # simple parse: find "description to-rrX" then walk back to nearest "interface ethN"
        for i, l in enumerate(lines):
            if rr_desc in l:
                for j in range(i, -1, -1):
                    if lines[j].strip().startswith("interface eth"):
                        iface = lines[j].strip().split()[1]
                        break
                break
        PE_IFACE[pe] = iface or ("eth1" if pe in ("pe1", "pe2", "pe3") else "eth2")
        print(f"[DISCOVER] {pe} -> {PE_IFACE[pe]} (toward {rr_desc})")


def write_metadata(target_dir, meta):
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)


def verify_scenario_files(target_dir, need_metadata=True):
    ok = True
    for fn in ["rr1.pcap", "rr2.pcap"] + (["metadata.json"] if need_metadata else []):
        p = os.path.join(target_dir, fn)
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            ok = False
    return ok


def run_scenario(name, target_dir, fault_type, affected_node, trigger_mechanism,
                  inject_fn, recover_fn, recovered, capture_pre=8, capture_post=60,
                  recover_delay=None, extra_meta=None, collect_before_recover=False):
    """Generic scenario runner: health check -> capture -> inject -> (recover) -> collect -> metadata.

    collect_before_recover=True is required whenever recover_fn() destroys the
    container the capture is running inside (e.g. full-container-kill recovery
    via redeploy) -- the pcap file lives on that container's ephemeral
    filesystem, so it must be collected before the container is torn down.
    """
    for attempt in range(2):
        if not ensure_healthy(name):
            print(f"[SCENARIO][ERROR] {name}: fabric unhealthy even after redeploy, retrying scenario.")
            continue
        try:
            proc_rr1, proc_rr2 = start_concurrent_captures()
            time.sleep(capture_pre)

            t_fault = now_iso()
            inject_fn()

            t_recovery = None
            if collect_before_recover:
                time.sleep(capture_post)
                stop_and_collect_captures(name, target_dir)
                if recovered:
                    recover_fn()
                    t_recovery = now_iso()
                else:
                    recover_fn()  # still restore fabric baseline after capture ends
            else:
                if recovered:
                    delay = recover_delay if recover_delay is not None else capture_post * 0.6
                    time.sleep(delay)
                    recover_fn()
                    t_recovery = now_iso()
                    time.sleep(max(0, capture_post - delay))
                    stop_and_collect_captures(name, target_dir)
                else:
                    # Capture stops before recover_fn() runs so a recovered=False
                    # scenario has no wire-visible recovery activity in its own
                    # capture window. recover_fn() still runs afterward, outside
                    # the capture, to restore the fabric to a clean baseline.
                    time.sleep(capture_post)
                    stop_and_collect_captures(name, target_dir)
                    recover_fn()

            meta = {
                "fault_type": fault_type,
                "event_affected_node": affected_node,
                "trigger_mechanism": trigger_mechanism,
                "time_of_first_fault": t_fault,
                "recovered": recovered,
                "time_of_recovery": t_recovery,
            }
            if extra_meta:
                meta.update(extra_meta)
            write_metadata(target_dir, meta)

            ok = verify_scenario_files(target_dir)
            scenario_results.append({"name": name, "status": "OK" if ok else "MISSING_FILES", "dir": target_dir})
            print(f"[SCENARIO] {name}: {'OK' if ok else 'MISSING FILES'}")
            return
        except Exception as e:
            print(f"[SCENARIO][EXCEPTION] {name}: {e}")
            try:
                recover_fn()
            except Exception:
                pass
            continue
    scenario_results.append({"name": name, "status": "FAILED_AFTER_RETRY", "dir": target_dir})
    print(f"[SCENARIO][FAILED] {name} failed even after redeploy retry.")


# ---------------- Link Down mechanisms ----------------

def link_down_bfd_inject(pe):
    dexec(pe, "ip", "link", "set", PE_IFACE[pe], "down")


def link_down_bfd_recover(pe):
    dexec(pe, "ip", "link", "set", PE_IFACE[pe], "up")


def link_down_holdtimer_inject(pe):
    rr_ip = PE_TARGET_IP[pe]
    vtysh_cmds(pe, ["conf t", "router bgp 65000", f"no neighbor {rr_ip} bfd"])
    dexec(pe, "ip", "link", "set", PE_IFACE[pe], "down")


def link_down_holdtimer_recover(pe):
    rr_ip = PE_TARGET_IP[pe]
    dexec(pe, "ip", "link", "set", PE_IFACE[pe], "up")
    vtysh_cmds(pe, ["conf t", "router bgp 65000", f"neighbor {rr_ip} bfd"])


def ensure_iptables(pe):
    r = dexec(pe, "sh", "-c", "which iptables")
    if r.returncode != 0:
        dexec(pe, "sh", "-c", "apk add iptables 2>&1 | tail -2")


def ensure_conntrack(pe):
    r = dexec(pe, "sh", "-c", "which conntrack")
    if r.returncode != 0:
        dexec(pe, "sh", "-c", "apk add conntrack-tools 2>&1 | tail -2")


def link_down_tcpfail_inject(pe):
    rr_ip = PE_TARGET_IP[pe]
    ensure_iptables(pe)
    ensure_conntrack(pe)
    dexec(pe, "iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "179", "-d", rr_ip, "-j", "REJECT", "--reject-with", "tcp-reset")
    dexec(pe, "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "179", "-d", rr_ip, "-j", "REJECT", "--reject-with", "tcp-reset")
    # Flush the conntrack entry in both directions so the existing BGP TCP
    # session can't bypass the REJECT rules just inserted.
    dexec(pe, "conntrack", "-D", "-p", "tcp", "-d", rr_ip)
    dexec(pe, "conntrack", "-D", "-p", "tcp", "-s", rr_ip)


def link_down_tcpfail_recover(pe):
    dexec(pe, "iptables", "-F", "OUTPUT")


LINK_DOWN_MECH = {
    # (inject, recover, trigger, capture_pre, capture_post, recover_delay)
    "bfd": (link_down_bfd_inject, link_down_bfd_recover, "BFD Down", 8, 45, 10),
    "holdtimer": (link_down_holdtimer_inject, link_down_holdtimer_recover, "Hold Timer Expired", 8, 65, 15),
    "tcpfail": (link_down_tcpfail_inject, link_down_tcpfail_recover, "TcpConnectionFails", 8, 60, 35),
}


def run_link_down():
    for mech, (inj, rec, trigger, pre, post, recover_delay) in LINK_DOWN_MECH.items():
        for pe in ["pe1", "pe2", "pe3", "pe4", "pe5"]:
            for recovered in [True, False]:
                rec_tag = "recovered" if recovered else "notrecovered"
                name = f"link_down_{mech}_{pe}_{rec_tag}"
                target_dir = os.path.join(PCAPS, "link_down", "single", name)
                run_scenario(
                    name, target_dir, "Link Down", pe.upper(), trigger,
                    lambda pe=pe, inj=inj: inj(pe),
                    lambda pe=pe, rec=rec: rec(pe),
                    recovered, capture_pre=pre, capture_post=post,
                    recover_delay=recover_delay,
                )


# ---------------- RR Down mechanisms ----------------

def rr_bgpd_pid(rr):
    r = dexec(rr, "sh", "-c", "pidof bgpd")
    return r.stdout.strip().split()[0] if r.stdout.strip() else None


def rr_down_bgpdkill_inject(rr):
    pid = rr_bgpd_pid(rr)
    if pid:
        dexec(rr, "kill", "-9", pid)


def rr_down_bgpdkill_recover(rr):
    dexec(rr, "sh", "-c", "source /usr/lib/frr/frrcommon.sh; daemon_start bgpd")
    dexec(rr, "sh", "-c", "vtysh -b")
    deadline = time.time() + 60
    while time.time() < deadline:
        r = vtysh_cmds(rr, ["show bgp summary"])
        if "never" not in r.stdout:
            break
        time.sleep(3)


def rr_down_containerkill_inject(rr):
    subprocess.run(f"wsl docker kill clab-pcap2story-{rr}", shell=True)


def rr_down_containerkill_recover(rr):
    redeploy(f"container-kill recovery for {rr}")


def rr_down_graceful_inject(rr):
    for peer in RR_NEIGHBORS[rr]:
        vtysh_cmds(rr, ["conf t", "router bgp 65000", f"neighbor {peer} shutdown"])


def rr_down_graceful_recover(rr):
    for peer in RR_NEIGHBORS[rr]:
        vtysh_cmds(rr, ["conf t", "router bgp 65000", f"no neighbor {peer} shutdown"])


RR_DOWN_MECH = {
    "bgpdkill": (rr_down_bgpdkill_inject, rr_down_bgpdkill_recover, "TCP_connection_closed", 8, 30, None),
    "graceful": (rr_down_graceful_inject, rr_down_graceful_recover, "Cease/Administrative Shutdown", 8, 30, 10),
}


def run_rr_down():
    for mech, (inj, rec, trigger, pre, post, recover_delay) in RR_DOWN_MECH.items():
        for rr in ["rr1", "rr2"]:
            for recovered in [True, False]:
                rec_tag = "recovered" if recovered else "notrecovered"
                name = f"rr_down_{mech}_{rr}_{rec_tag}"
                target_dir = os.path.join(PCAPS, "rr_down", "single", name)
                extra_meta = None
                if mech == "containerkill" and recovered:
                    extra_meta = {
                        "recovered": "NOT_CAPTURED",
                        "recovery_note": (
                            "containerkill's recovery (fabric redeploy) runs after "
                            "capture collection by necessity -- the container being "
                            "recovered is destroyed and rebuilt, so its pcap must be "
                            "collected before that happens. Recovery is confirmed via "
                            "post-redeploy health checks but is not wire-observable "
                            "within this scenario's capture, regardless of capture_post."
                        ),
                    }
                run_scenario(
                    name, target_dir, "RR Down", rr.upper(), trigger,
                    lambda rr=rr, inj=inj: inj(rr),
                    lambda rr=rr, rec=rec: rec(rr),
                    recovered, capture_pre=pre, capture_post=post,
                    recover_delay=recover_delay,
                    collect_before_recover=(mech == "containerkill"),
                    extra_meta=extra_meta,
                )


# ---------------- PE Cease ----------------

def pe_cease_inject(pe):
    rr_ip = PE_TARGET_IP[pe]
    vtysh_cmds(pe, ["conf t", "router bgp 65000", f"neighbor {rr_ip} shutdown"])


def pe_cease_recover(pe):
    rr_ip = PE_TARGET_IP[pe]
    vtysh_cmds(pe, ["conf t", "router bgp 65000", f"no neighbor {rr_ip} shutdown"])


def run_pe_cease():
    for pe in ["pe1", "pe2", "pe3", "pe4", "pe5"]:
        for recovered in [True, False]:
            rec_tag = "recovered" if recovered else "notrecovered"
            name = f"pe_cease_{pe}_{rec_tag}"
            target_dir = os.path.join(PCAPS, "pe_cease", "single", name)
            # capture_post and recover_delay tuned to give margin over observed recovery timing
            run_scenario(
                name, target_dir, "PE Cease", pe.upper(), "Cease/Administrative Shutdown",
                lambda pe=pe: pe_cease_inject(pe),
                lambda pe=pe: pe_cease_recover(pe),
                recovered, capture_pre=8, capture_post=30, recover_delay=10,
            )


# ---------------- RT Misconfig ----------------

def rt_import_only_inject(pe):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100",
                     "no route-target both 100:1", "route-target export 100:1", "route-target import 200:1"])


def rt_import_only_recover(pe):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100",
                     "no route-target import 200:1", "no route-target export 100:1", "route-target both 100:1"])


def rt_autoderive_inject(pe):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100",
                     "no route-target both 100:1"])


def rt_autoderive_recover(pe):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100",
                     "route-target both 100:1"])


RT_MECH = {
    "import_only": (rt_import_only_inject, rt_import_only_recover, "Plain Import/Export Mismatch", "100:1 (export)", "200:1 (mismatched import)"),
    "autoderive_export": (rt_autoderive_inject, rt_autoderive_recover, "Auto-Derived Mismatch", "65000:100 (auto)", "100:1 (peer explicit import)"),
}


def run_rt_misconfig():
    for mech, (inj, rec, trigger, export_rt, import_rt) in RT_MECH.items():
        for pe in ["pe1", "pe2", "pe3", "pe4", "pe5"]:
            # notfixed: mismatch present throughout
            name = f"rt_misconfig_{mech}_{pe}_notfixed"
            target_dir = os.path.join(PCAPS, "rt_misconfig", "single", name)
            run_scenario(
                name, target_dir, "RT Misconfiguration", pe.upper(), trigger,
                lambda pe=pe, inj=inj: inj(pe),
                lambda pe=pe, rec=rec: rec(pe),
                False, capture_pre=5, capture_post=40,
                extra_meta={"configured_export_rt": export_rt, "configured_import_rt": import_rt},
            )
            # fixed: mismatch injected, then reverted mid-capture
            name = f"rt_misconfig_{mech}_{pe}_fixed"
            target_dir = os.path.join(PCAPS, "rt_misconfig", "single", name)
            run_scenario(
                name, target_dir, "RT Misconfiguration", pe.upper(), trigger,
                lambda pe=pe, inj=inj: inj(pe),
                lambda pe=pe, rec=rec: rec(pe),
                True, capture_pre=5, capture_post=40,
                extra_meta={"configured_export_rt": export_rt, "configured_import_rt": import_rt},
            )


# ---------------- Normal captures (Step 1) ----------------

def run_normal_captures():
    cmds = []
    cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_baseline.py"), "--duration", "2", "--load", "light"])
    cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_baseline.py"), "--duration", "2", "--load", "moderate"])
    cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_baseline.py"), "--duration", "2", "--load", "heavy"])
    for pe in ["1", "2", "3", "4", "5"]:
        cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_silent_pe.py"), "--silent-pes", pe, "--load", "moderate", "--duration", "2"])
    pairs = ["1,2", "1,3", "1,4", "1,5", "2,3", "2,4", "2,5", "3,4", "3,5", "4,5"]
    for pair in pairs:
        cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_silent_pe.py"), "--silent-pes", pair, "--load", "moderate", "--duration", "2"])

    for cmd in cmds:
        name = " ".join(cmd[2:])
        if not ensure_healthy(f"normal:{name}"):
            print(f"[NORMAL][ERROR] Could not achieve health before {name}")
        print(f"[NORMAL] Running: {name}")
        r = subprocess.run(cmd, cwd=BASE)
        scenario_results.append({"name": f"normal:{name}", "status": "OK" if r.returncode == 0 else "FAILED", "dir": None})


def delete_stale_normal():
    normal_dir = os.path.join(PCAPS, "Normal")
    if os.path.isdir(normal_dir):
        for entry in os.listdir(normal_dir):
            if entry.startswith("normal_"):
                p = os.path.join(normal_dir, entry)
                if os.path.isdir(p):
                    shutil.rmtree(p)
                    print(f"[CLEANUP] Deleted {p}")


def final_report():
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    report = {
        "completed_at": now_iso(),
        "redeploys": redeploy_log,
        "redeploy_count": len(redeploy_log),
        "scenarios": scenario_results,
        "failed_scenarios": [s for s in scenario_results if s["status"] not in ("OK",)],
        "final_health": health_ok(),
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[REPORT] Written to {REPORT_PATH}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    print(f"[RUN] Overnight run starting at {now_iso()}")
    delete_stale_normal()
    discover_pe_interfaces()

    if not ensure_healthy("startup"):
        print("[RUN][FATAL] Could not achieve health at startup even after redeploy.")
    ensure_tcpdump()

    run_normal_captures()
    run_link_down()
    run_rr_down()
    run_pe_cease()
    run_rt_misconfig()

    final_report()
    print(f"[RUN] Overnight run finished at {now_iso()}")
