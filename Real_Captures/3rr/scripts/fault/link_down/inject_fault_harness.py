import subprocess
import datetime
import json
import time
import os
import argparse
import logging
from pathlib import Path

BASE = str(Path(__file__).resolve().parents[3])
LOG_DIR = os.path.join(BASE, "logs")
_logger = None

# Explicit RR list for this topology's capture vantage points. No
# topology.json exists in this project's fault-injection side (that's a
# separate, detector-side artifact, not built here) -- an explicit list
# is the simplest signal already available. Update this list, not the
# function bodies below, if the RR set changes again.
RR_NODES = ["xrr1", "xrr2", "xrr3"]

def _init_run_logger():
    """
    Creates one timestamped log file per harness run (module import) and returns
    a logger that writes to that file. Safe to call multiple times; only the
    first call in a process creates the file/handler.
    """
    global _logger
    if _logger is not None:
        return _logger

    os.makedirs(LOG_DIR, exist_ok=True)
    run_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log_path = os.path.join(LOG_DIR, f"harness_run_{run_ts}.log")

    logger = logging.getLogger(f"harness.{run_ts}")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(message)s"))
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream_handler)

    logger.info(f"[HARNESS] Log file for this run: {log_path}")
    _logger = logger
    return _logger

def start_concurrent_captures():
    """
    Launches tcpdump captures on every RR in RR_NODES concurrently in
    background subprocesses. Waits and confirms all tcpdump processes are
    up before returning.

    Returns a dict {rr_name: Popen} instead of a fixed-arity tuple, so
    the RR count is driven by RR_NODES, not by how many return values a
    caller happens to unpack.
    """
    log = _init_run_logger()
    capture_start_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log.info(f"[HARNESS] Capture start requested at {capture_start_ts}")
    log.info(f"[HARNESS] Starting concurrent captures on {', '.join(RR_NODES)}...")

    procs = {}
    for rr in RR_NODES:
        cmd = f"wsl docker exec clab-pcap2story-3rr-dev-{rr} bash -c 'tcpdump -i any -w /tmp/{rr}.pcap'"
        log.info(f"[HARNESS] Popen: {cmd}")
        proc = subprocess.Popen(cmd, shell=True)
        log.info(f"[HARNESS] Popen launched {rr} tcpdump (pid of wrapper shell: {proc.pid})")
        procs[rr] = proc

    # Confirm every tcpdump process is running inside its container
    for attempt in range(1, 11):
        time.sleep(1)
        statuses = {}
        for rr in RR_NODES:
            check = subprocess.run(f"wsl docker exec clab-pcap2story-3rr-dev-{rr} pidof tcpdump", shell=True, capture_output=True, text=True)
            statuses[rr] = check.stdout.strip()

        status_line = ", ".join(
            f"{rr}={'PASS pid=' + pid if pid else 'FAIL (no pid)'}" for rr, pid in statuses.items()
        )
        log.info(f"[HARNESS] pidof check attempt {attempt}/10: {status_line}")

        if all(statuses.values()):
            log.info(f"[HARNESS] Confirmed tcpdump running on {', '.join(RR_NODES)} after {attempt} attempt(s).")
            return procs

    log.error(f"[HARNESS] Failed to verify concurrent tcpdump processes on {', '.join(RR_NODES)} after 10 attempts.")
    raise RuntimeError(f"[HARNESS] Failed to verify concurrent tcpdump processes on {', '.join(RR_NODES)}.")

def stop_and_collect_captures(scenario_name, target_dir=None):
    """
    Stops tcpdump processes on every RR in RR_NODES, copies PCAP files out
    to the target scenario directory, and explicitly verifies each file
    exists and is non-zero before returning.
    """
    log = _init_run_logger()
    capture_stop_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log.info(f"[HARNESS] Capture stop requested at {capture_stop_ts}")

    if target_dir is None:
        target_dir = os.path.join(BASE, "pcaps", scenario_name)
    os.makedirs(target_dir, exist_ok=True)

    log.info(f"[HARNESS] Stopping tcpdump on {', '.join(RR_NODES)}...")
    for rr in RR_NODES:
        subprocess.run(f"wsl docker exec clab-pcap2story-3rr-dev-{rr} killall -2 tcpdump", shell=True)
    time.sleep(2)

    def to_wsl_path(win_path):
        # Convert a Windows path (C:\foo\bar) to its WSL mount equivalent (/mnt/c/foo/bar)
        path = os.path.abspath(win_path).replace("\\", "/")
        if path[1:3] == ":/":
            drive = path[0].lower()
            path = f"/mnt/{drive}{path[2:]}"
        return path

    dests = {rr: os.path.join(target_dir, f"{rr}.pcap") for rr in RR_NODES}

    log.info(f"[HARNESS] Copying captures to {target_dir}...")
    for rr in RR_NODES:
        wsl_dest = to_wsl_path(dests[rr])
        subprocess.run(f"wsl docker cp clab-pcap2story-3rr-dev-{rr}:/tmp/{rr}.pcap \"{wsl_dest}\"", shell=True, check=True)

    # Explicit non-zero size collection verification
    for rr, pcap_file in dests.items():
        if not os.path.exists(pcap_file):
            log.error(f"[HARNESS] Collection error: Destination PCAP missing: {pcap_file}")
            raise FileNotFoundError(f"[HARNESS] Collection error: Destination PCAP missing: {pcap_file}")
        size = os.path.getsize(pcap_file)
        if size == 0:
            log.error(f"[HARNESS] Collection error: Destination PCAP is 0 bytes: {pcap_file}")
            raise ValueError(f"[HARNESS] Collection error: Destination PCAP is 0 bytes: {pcap_file}")
        log.info(f"[HARNESS] Verified collection: {pcap_file} ({size} bytes)")

def inject_fault(node="xpe1", fault_type="isolate", scenario_name="pe1_isolation", capture_duration=15):
    """
    Explicitly injects fault intent atomically:
    1. Starts concurrent captures on RR1 and RR2.
    2. Brings down all topology-facing interfaces for specified node.
    3. Writes scenario metadata ground truth JSON.
    4. Waits for capture duration and collects PCAP artifacts.
    """
    log = _init_run_logger()
    capture_procs = start_concurrent_captures()

    gt_dir = os.path.join(BASE, "metadata")
    os.makedirs(gt_dir, exist_ok=True)
    gt_file = os.path.join(gt_dir, f"{scenario_name}.json")

    if node.lower() == "xpe1" and fault_type == "isolate":
        log.info("[HARNESS] Injecting atomic PE1 isolation fault (eth1 down + eth2 down)...")
        cmd = "wsl docker exec clab-pcap2story-3rr-dev-xpe1 bash -c 'ip link set eth1 down; ip link set eth2 down'"

        subprocess.run(cmd, shell=True, check=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        t_fault = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"
        
        gt = {
            "event_affected_node": "PE1",
            "fault_type": "Link Down",
            "time_of_first_fault": t_fault,
            "trigger_mechanism": "Interfaces eth1 and eth2 (PE1 dual point-to-point links) forced down via ip link set down, resulting in complete PE isolation",
            "recovered": False
        }
        
        with open(gt_file, "w") as f:
            json.dump(gt, f, indent=2)
            
        log.info(f"[HARNESS] Fault injected successfully at {t_fault}")
        log.info(f"[HARNESS] Auto-generated metadata at {gt_file}")

        log.info(f"[HARNESS] Capturing post-fault window for {capture_duration} seconds...")
        time.sleep(capture_duration)
        
        stop_and_collect_captures(scenario_name)
        return gt

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fault Injection Harness with Concurrent Dual RR Captures")
    parser.add_argument("--node", default="xpe1", help="Target node for fault injection")
    parser.add_argument("--fault", default="isolate", help="Fault type (e.g. isolate)")
    parser.add_argument("--scenario", default="pe1_isolation", help="Scenario output name")
    parser.add_argument("--duration", type=int, default=15, help="Capture window duration after fault (seconds)")
    args = parser.parse_args()
    
    inject_fault(node=args.node, fault_type=args.fault, scenario_name=args.scenario, capture_duration=args.duration)
