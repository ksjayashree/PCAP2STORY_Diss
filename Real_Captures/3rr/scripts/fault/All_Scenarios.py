"""
Overnight full generation run: 190 scenarios across 5 categories (Link Down 60,
RR Down 12, PE Cease 20, RT Misconfig 40, Normal 58). Sequential, one scenario
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
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures, RR_NODES

_base_path = Path(__file__).resolve().parents[2]
BASE = str(_base_path)
PCAPS = os.path.join(BASE, "pcaps")
_topo_win = _base_path / "topology" / "3rr_10pe_topology.yml"
TOPO = "/mnt/" + _topo_win.drive[0].lower() + str(_topo_win)[2:].replace("\\", "/")
CHECK_HEALTH = os.path.join(BASE, "scripts", "test_scripts", "check_health.py")
REPORT_PATH = os.path.join(BASE, "logs", "all_scenarios_report.json")

PE_TARGET_IP = {
    "xpe1": "10.0.0.1", "xpe2": "10.0.0.1", "xpe3": "10.0.0.1", "xpe4": "10.0.0.1",
    "xpe5": "10.0.0.2", "xpe6": "10.0.0.2", "xpe7": "10.0.0.2",
    "xpe8": "10.0.0.3", "xpe9": "10.0.0.3", "xpe10": "10.0.0.3",
}
PE_IFACE = {}  # filled at startup by querying running-config
RR_NEIGHBORS = {
    "xrr1": ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.2", "10.0.0.3"],
    "xrr2": ["10.0.0.15", "10.0.0.16", "10.0.0.17", "10.0.0.1", "10.0.0.3"],
    "xrr3": ["10.0.0.18", "10.0.0.19", "10.0.0.20", "10.0.0.1", "10.0.0.2"],
}

# Canonical PE/RR lists, driven by the dicts above rather than re-listed as
# separate literals -- every scenario-generation loop should iterate these,
# not its own hardcoded subset.
PE_LIST = list(PE_TARGET_IP.keys())
RR_LIST = list(RR_NEIGHBORS.keys())
# Which RR each PE is single-homed to (derived from the topology's own link
# list, since PE_TARGET_IP only stores the RR's loopback IP, not its name).
PE_RR = {
    "xpe1": "xrr1", "xpe2": "xrr1", "xpe3": "xrr1", "xpe4": "xrr1",
    "xpe5": "xrr2", "xpe6": "xrr2", "xpe7": "xrr2",
    "xpe8": "xrr3", "xpe9": "xrr3", "xpe10": "xrr3",
}

redeploy_log = []
scenario_results = []


def now_iso():
    n = datetime.datetime.now(datetime.timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond:06d}Z"


def dexec(container, *args, check=False):
    cmd = ["wsl", "docker", "exec", f"clab-pcap2story-3rr-dev-{container}"] + list(args)
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
    """tcpdump does not persist across redeploys (README known limitation).
    Must be (re)installed on all RRs after every fresh deploy."""
    for rr in ["xrr1", "xrr2", "xrr3"]:
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
    for pe in PE_LIST:
        rr_desc = f"to-{PE_RR[pe]}"
        r = vtysh_cmds(pe, ["show running-config"])
        lines = r.stdout.splitlines()
        iface = None
        # find "description to-xrrX" then walk back to nearest "interface ethN"
        for i, l in enumerate(lines):
            if rr_desc in l:
                for j in range(i, -1, -1):
                    if lines[j].strip().startswith("interface eth"):
                        iface = lines[j].strip().split()[1]
                        break
                break
        if iface is None:
            # No safe numeric fallback exists across this topology (xpe5's
            # real uplink is eth2 while every other PE's is eth1 -- a wrong
            # guess would silently target the wrong interface). Fail loud.
            raise RuntimeError(f"[DISCOVER] Could not determine uplink interface for {pe} (looked for '{rr_desc}' in running-config)")
        PE_IFACE[pe] = iface
        print(f"[DISCOVER] {pe} -> {PE_IFACE[pe]} (toward {rr_desc})")


def write_metadata(target_dir, meta):
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)


def verify_scenario_files(target_dir, need_metadata=True):
    ok = True
    for fn in [f"{rr}.pcap" for rr in RR_NODES] + (["metadata.json"] if need_metadata else []):
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
    filesystem, so it must be collected BEFORE the container is torn down,
    not after.
    """
    for attempt in range(2):
        if not ensure_healthy(name):
            print(f"[SCENARIO][ERROR] {name}: fabric unhealthy even after redeploy, retrying scenario.")
            continue
        try:
            capture_procs = start_concurrent_captures()
            time.sleep(capture_pre)

            t_fault = now_iso()
            inject_fn()

            t_recovery = None
            if collect_before_recover:
                # Capture window ends at fault; collect now, then recover (which may destroy containers).
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
                    # Capture stops BEFORE recover_fn() runs -- a recovered=False
                    # scenario must not have any wire-visible correction/recovery
                    # activity inside its own capture window. recover_fn() still
                    # runs afterward, entirely outside the capture, purely to
                    # restore the fabric to a clean baseline for the next scenario.
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
    # The pre-existing BGP TCP session's conntrack entry (ESTABLISHED,
    # [ASSURED]) lets subsequent packets on that flow bypass the
    # just-inserted REJECT rules entirely, so it must be deleted for the
    # session to actually break. BGP sessions can be established with
    # either side as the TCP initiator, so delete both directions.
    dexec(pe, "conntrack", "-D", "-p", "tcp", "-d", rr_ip)
    dexec(pe, "conntrack", "-D", "-p", "tcp", "-s", rr_ip)


def link_down_tcpfail_recover(pe):
    dexec(pe, "iptables", "-F", "OUTPUT")


LINK_DOWN_MECH = {
    # (inject, recover, trigger, capture_pre, capture_post, recover_delay)
    "bfd": (link_down_bfd_inject, link_down_bfd_recover, "BFD Down", 8, 45, 10),
    "holdtimer": (link_down_holdtimer_inject, link_down_holdtimer_recover, "Hold Timer Expired", 8, 65, 15),
    # tcpfail: the real fault signature is the RR's own side of the session
    # timing out and sending FIN after ~30s of unacked keepalives (pe1's
    # configured hold time is 30s, keepalive interval 10s), not a PE-side
    # RST from the injected iptables REJECT rule. recover_delay=35s ensures
    # the fault reliably manifests before recover_fn() runs.
    "tcpfail": (link_down_tcpfail_inject, link_down_tcpfail_recover, "TcpConnectionFails", 8, 60, 35),
}


def run_link_down():
    for mech, (inj, rec, trigger, pre, post, recover_delay) in LINK_DOWN_MECH.items():
        for pe in PE_LIST:
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
    subprocess.run(f"wsl docker kill clab-pcap2story-3rr-dev-{rr}", shell=True)


def rr_down_containerkill_recover(rr):
    redeploy(f"container-kill recovery for {rr}")


def rr_down_graceful_inject(rr):
    for peer in RR_NEIGHBORS[rr]:
        vtysh_cmds(rr, ["conf t", "router bgp 65000", f"neighbor {peer} shutdown"])


def rr_down_graceful_recover(rr):
    for peer in RR_NEIGHBORS[rr]:
        vtysh_cmds(rr, ["conf t", "router bgp 65000", f"no neighbor {peer} shutdown"])


RR_DOWN_MECH = {
    # bgpdkill: recover_fn polls "show bgp summary" until real convergence
    # before t_recovery is stamped.
    "bgpdkill": (rr_down_bgpdkill_inject, rr_down_bgpdkill_recover, "TCP_connection_closed", 8, 30, None),
    # containerkill: recovery mechanism is a full fabric destroy+redeploy,
    # not a valid isolated single-RR-down scenario; see
    # _archived_rr_down_containerkill/README.
    # "containerkill": (rr_down_containerkill_inject, rr_down_containerkill_recover, "TCP_connection_closed+BFD_control_expired", 8, 20, None),
    "graceful": (rr_down_graceful_inject, rr_down_graceful_recover, "Cease/Administrative Shutdown", 8, 30, 10),
}


def run_rr_down():
    for mech, (inj, rec, trigger, pre, post, recover_delay) in RR_DOWN_MECH.items():
        for rr in RR_LIST:
            for recovered in [True, False]:
                rec_tag = "recovered" if recovered else "notrecovered"
                name = f"rr_down_{mech}_{rr}_{rec_tag}"
                target_dir = os.path.join(PCAPS, "rr_down", "single", name)
                extra_meta = None
                if mech == "containerkill" and recovered:
                    # containerkill's recover_fn() is a full fabric redeploy,
                    # which necessarily runs AFTER stop_and_collect_captures()
                    # (the container being recovered is destroyed and rebuilt,
                    # so the capture must be collected first). This means
                    # there is no wire evidence of recovery in this
                    # scenario's capture, so a distinct sentinel value is
                    # used instead of true/false, which would either
                    # overclaim or misreport recovery.
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
    for pe in PE_LIST:
        for recovered in [True, False]:
            rec_tag = "recovered" if recovered else "notrecovered"
            name = f"pe_cease_{pe}_{rec_tag}"
            target_dir = os.path.join(PCAPS, "pe_cease", "single", name)
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
    # capture_post=40 covers autoderive_export's wire-visible RT correction.
    # import_only's mismatch is a receiver-side import-policy filter (RFC
    # 4360), which produces no outbound wire artifact regardless of window
    # length -- its notfixed/fixed scenarios remain NOT_WIRE_OBSERVABLE by
    # design; the same capture_post is used for both mechanisms only
    # because they share this one call.
    for mech, (inj, rec, trigger, export_rt, import_rt) in RT_MECH.items():
        for pe in PE_LIST:
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
            # fixed: mismatch injected, then reverted mid-capture (mirrors
            # notfixed's real injection, but with recovered=True so
            # run_scenario's own recover step actually fires and the
            # correction is wire-visible within the capture window)
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
    # Derived from PE_LIST (all 10 PEs): 10 single-silent-PE scenarios and
    # C(10,2)=45 pairs (55 total).
    pe_nums = [pe[len("xpe"):] for pe in PE_LIST]

    cmds = []
    cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_baseline.py"), "--duration", "2", "--load", "light"])
    cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_baseline.py"), "--duration", "2", "--load", "moderate"])
    cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_baseline.py"), "--duration", "2", "--load", "heavy"])
    for pe in pe_nums:
        cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_silent_pe.py"), "--silent-pes", pe, "--load", "moderate", "--duration", "2"])
    import itertools
    for a, b in itertools.combinations(pe_nums, 2):
        cmds.append(["python", os.path.join(BASE, "scripts", "normal", "capture_normal_silent_pe.py"), "--silent-pes", f"{a},{b}", "--load", "moderate", "--duration", "2"])

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
