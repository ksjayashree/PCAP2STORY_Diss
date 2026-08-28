"""
Multi-incident scenario generator for 2rr (5PE/2RR).
Reuses the exact inject_fn/recover_fn building blocks and capture harness
from All_Scenarios.py -- no new fault mechanisms invented here.

Category B: same fault type, 2 independent instances in one capture window.
Category C: two different fault types, non-causally co-occurring.

Output: pcaps/multiple/<category_dir>/<name>/{rr1.pcap, rr2.pcap, metadata.json}
"""
import sys, os, subprocess, datetime, time, json
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__) + os.sep + "link_down")
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures

BASE = str(Path(__file__).resolve().parents[2])
PCAPS = os.path.join(BASE, "pcaps", "multiple")
CHECK_HEALTH = os.path.join(BASE, "scripts", "test_scripts", "check_health.py")

PE_TARGET_IP = {"pe1": "10.0.0.1", "pe2": "10.0.0.1", "pe3": "10.0.0.1", "pe4": "10.0.0.2", "pe5": "10.0.0.2"}
PE_IFACE = {}
RR_NEIGHBORS = {
    "rr1": ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.2"],
    "rr2": ["10.0.0.14", "10.0.0.15", "10.0.0.1"],
}

RESULTS = []


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


def discover_pe_interfaces():
    for pe, rr_desc in [("pe1", "to-rr1"), ("pe2", "to-rr1"), ("pe3", "to-rr1"),
                         ("pe4", "to-rr2"), ("pe5", "to-rr2")]:
        r = vtysh_cmds(pe, ["show running-config"])
        lines = r.stdout.splitlines()
        iface = None
        for i, l in enumerate(lines):
            if rr_desc in l:
                for j in range(i, -1, -1):
                    if lines[j].strip().startswith("interface eth"):
                        iface = lines[j].strip().split()[1]
                        break
                break
        PE_IFACE[pe] = iface or ("eth1" if pe in ("pe1", "pe2", "pe3") else "eth2")
        print(f"[DISCOVER] {pe} -> {PE_IFACE[pe]}")


# ---- fault primitives (copied verbatim from All_Scenarios.py) ----

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


def pe_cease_inject(pe):
    rr_ip = PE_TARGET_IP[pe]
    vtysh_cmds(pe, ["conf t", "router bgp 65000", f"neighbor {rr_ip} shutdown"])


def pe_cease_recover(pe):
    rr_ip = PE_TARGET_IP[pe]
    vtysh_cmds(pe, ["conf t", "router bgp 65000", f"no neighbor {rr_ip} shutdown"])


def rt_import_only_inject(pe):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100",
                     "no route-target both 100:1", "route-target export 100:1", "route-target import 200:1"])


def rt_import_only_recover(pe):
    vtysh_cmds(pe, ["conf t", "router bgp 65000", "address-family l2vpn evpn", "vni 100",
                     "no route-target import 200:1", "no route-target export 100:1", "route-target both 100:1"])


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


def write_metadata(target_dir, meta):
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)


def verify_scenario_files(target_dir):
    for fn in ["rr1.pcap", "rr2.pcap", "metadata.json"]:
        p = os.path.join(target_dir, fn)
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            return False
    return True


def run_multi(name, target_dir, events_meta, steps, capture_pre=8, capture_post_total=90):
    """steps: list of (delay_from_start, fn) executed in order after capture_pre."""
    for attempt in range(2):
        if not health_ok():
            print(f"[HEALTH][WARN] {name}: not healthy before scenario (continuing per no-redeploy-helper-here policy)")
        try:
            start_concurrent_captures()
            time.sleep(capture_pre)
            t0 = time.time()
            for delay, fn, label in steps:
                wait = max(0, delay - (time.time() - t0))
                time.sleep(wait)
                ts = now_iso()
                print(f"[STEP] {name}: {label} at {ts}")
                fn()
                for e in events_meta:
                    if e.get("_label") == label:
                        e["_ts"] = ts
            elapsed = time.time() - t0
            remaining = max(0, capture_post_total - elapsed)
            time.sleep(remaining)
            stop_and_collect_captures(name, target_dir)

            for e in events_meta:
                e.pop("_label", None)
            meta = {"incidents": events_meta, "multi_incident": True}
            write_metadata(target_dir, meta)
            ok = verify_scenario_files(target_dir)
            RESULTS.append({"name": name, "status": "OK" if ok else "MISSING_FILES", "dir": target_dir})
            print(f"[SCENARIO] {name}: {'OK' if ok else 'MISSING FILES'}")
            return
        except Exception as e:
            print(f"[SCENARIO][EXCEPTION] {name}: {e}")
            continue
    RESULTS.append({"name": name, "status": "FAILED_AFTER_RETRY", "dir": target_dir})


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "all"
    discover_pe_interfaces()

    if scenario in ("linkdown_x2", "all"):
        name = "link_down_x2_pe1bfd_pe4holdtimer"
        target_dir = os.path.join(PCAPS, "catB_link_down_x2", name)
        events = [
            {"_label": "fault1", "fault_type": "Link Down", "event_affected_node": "PE1",
             "trigger_mechanism": "BFD Down", "recovered": True},
            {"_label": "fault2", "fault_type": "Link Down", "event_affected_node": "PE4",
             "trigger_mechanism": "Hold Timer Expired", "recovered": True},
        ]
        steps = [
            (0, lambda: link_down_bfd_inject("pe1"), "fault1"),
            (12, lambda: link_down_bfd_recover("pe1"), "fault1_recover"),
            (35, lambda: link_down_holdtimer_inject("pe4"), "fault2"),
            (60, lambda: link_down_holdtimer_recover("pe4"), "fault2_recover"),
        ]
        # capture events' recover timestamps too by adding extra label entries
        events.append({"_label": "fault1_recover"})
        events.append({"_label": "fault2_recover"})
        run_multi(name, target_dir, events, steps, capture_pre=8, capture_post_total=100)

    if scenario in ("catB_pe_cease_x2", "all"):
        name = "pe_cease_x2_pe2_pe5"
        target_dir = os.path.join(PCAPS, "catB_pe_cease_x2", name)
        events = [
            {"_label": "fault1", "fault_type": "PE Cease", "event_affected_node": "PE2",
             "trigger_mechanism": "Cease/Administrative Shutdown", "recovered": True},
            {"_label": "fault2", "fault_type": "PE Cease", "event_affected_node": "PE5",
             "trigger_mechanism": "Cease/Administrative Shutdown", "recovered": True},
        ]
        steps = [
            (0, lambda: pe_cease_inject("pe2"), "fault1"),
            (10, lambda: pe_cease_recover("pe2"), "fault1_recover"),
            (25, lambda: pe_cease_inject("pe5"), "fault2"),
            (35, lambda: pe_cease_recover("pe5"), "fault2_recover"),
        ]
        events.append({"_label": "fault1_recover"})
        events.append({"_label": "fault2_recover"})
        run_multi(name, target_dir, events, steps, capture_pre=8, capture_post_total=55)

    if scenario in ("mixed_c1", "all"):
        # Category C pair 1: link_down(PE3) + rt_misconfig(PE5), independent, non-causal
        name = "mixed_linkdown_pe3_rtmisconfig_pe5"
        target_dir = os.path.join(PCAPS, "catC_link_down_rt_misconfig", name)
        events = [
            {"_label": "fault1", "fault_type": "Link Down", "event_affected_node": "PE3",
             "trigger_mechanism": "BFD Down", "recovered": False},
            {"_label": "fault2", "fault_type": "RT Misconfiguration", "event_affected_node": "PE5",
             "trigger_mechanism": "Plain Import/Export Mismatch", "recovered": False,
             "configured_export_rt": "100:1 (export)", "configured_import_rt": "200:1 (mismatched import)"},
        ]
        steps = [
            (0, lambda: link_down_bfd_inject("pe3"), "fault1"),
            (20, lambda: rt_import_only_inject("pe5"), "fault2"),
        ]
        run_multi(name, target_dir, events, steps, capture_pre=8, capture_post_total=55)

    print(json.dumps(RESULTS, indent=2))
    os.makedirs(os.path.join(BASE, "logs"), exist_ok=True)
    with open(os.path.join(BASE, "logs", "multi_incident_report.json"), "w") as f:
        json.dump(RESULTS, f, indent=2)
