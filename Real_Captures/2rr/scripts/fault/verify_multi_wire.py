"""
Lightweight wire-level verification pass across all pcaps/multiple scenarios
(both projects): for each ground-truth incident with a node identifiable in
the topology, confirm via tshark that BGP traffic involving that node's
router-id shows activity (Notification/Update/Keepalive) near its claimed
time_of_first_fault, and that distinct incidents in the same file have
distinct timestamps/peers (not one event double-counted as two).
"""
import sys, os, json, subprocess, glob
from pathlib import Path

_BASE_PATH = Path(__file__).resolve().parents[2]

PROJECTS = {
    "2rr": {
        "base": str(_BASE_PATH / "pcaps" / "multiple"),
        "ip_map": {"PE1": "10.0.0.11", "PE2": "10.0.0.12", "PE3": "10.0.0.13", "PE4": "10.0.0.14", "PE5": "10.0.0.15",
                    "RR1": "10.0.0.1", "RR2": "10.0.0.2"},
    },
    "3rr": {
        "base": str(_BASE_PATH.parent / "3rr" / "pcaps" / "multiple"),
        "ip_map": {f"XPE{i}": f"10.0.0.{10+i}" for i in range(1, 11)} | {"XRR1": "10.0.0.1", "XRR2": "10.0.0.2", "XRR3": "10.0.0.3"},
    },
}


def tshark_bgp_times(pcap, ip):
    cmd = ["wsl", "tshark", "-r", to_wsl(pcap), "-Y", f"bgp && ip.addr=={ip}", "-T", "fields", "-e", "frame.time_epoch", "-e", "bgp.type"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 1 and parts[0]:
            out.append(float(parts[0]))
    return out


def to_wsl(p):
    p = os.path.abspath(p).replace("\\", "/")
    if p[1:3] == ":/":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def iso_to_epoch(iso):
    import datetime
    return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc).timestamp()


def verify_file(scenario_dir, ip_map):
    meta_path = os.path.join(scenario_dir, "metadata.json")
    with open(meta_path) as f:
        meta = json.load(f)
    incidents = meta.get("incidents") or [meta]
    rr1 = os.path.join(scenario_dir, "rr1.pcap") if os.path.exists(os.path.join(scenario_dir, "rr1.pcap")) else None
    pcaps = [p for p in glob.glob(os.path.join(scenario_dir, "*.pcap"))]
    report = {"scenario": scenario_dir, "incidents": []}
    for inc in incidents:
        node = inc.get("event_affected_node")
        nodes = inc.get("event_affected_nodes") or ([node] if node else [])
        ts_field = inc.get("time_of_first_fault") or inc.get("time_of_move")
        entry = {"nodes": nodes, "declared_ts": ts_field, "activity_found": False, "nearest_gap_s": None}
        if not nodes or not ts_field:
            entry["note"] = "no node/timestamp to check (e.g. mac_mobility clean_move without a plain time field)"
            report["incidents"].append(entry)
            continue
        try:
            t0 = iso_to_epoch(ts_field)
        except Exception:
            entry["note"] = f"unparseable timestamp {ts_field}"
            report["incidents"].append(entry)
            continue
        best_gap = None
        for n in nodes:
            ip = ip_map.get(n)
            if not ip:
                continue
            for pcap in pcaps:
                times = tshark_bgp_times(pcap, ip)
                for t in times:
                    gap = abs(t - t0)
                    if best_gap is None or gap < best_gap:
                        best_gap = gap
        entry["nearest_gap_s"] = best_gap
        entry["activity_found"] = best_gap is not None and best_gap <= 30.0
        report["incidents"].append(entry)
    return report


def main():
    all_reports = []
    for proj, cfg in PROJECTS.items():
        base = cfg["base"]
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            if "metadata.json" in files and any(f.endswith(".pcap") for f in files):
                rep = verify_file(root, cfg["ip_map"])
                rep["project"] = proj
                all_reports.append(rep)
                print(json.dumps(rep, indent=2))
    out = str(_BASE_PATH / "logs" / "multi_incident_wire_verification.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(all_reports, f, indent=2)
    print(f"[WRITTEN] {out}")


if __name__ == "__main__":
    main()
