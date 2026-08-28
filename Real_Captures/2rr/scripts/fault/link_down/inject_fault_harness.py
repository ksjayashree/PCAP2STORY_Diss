import subprocess
import datetime
import json
import time
import os
import argparse
import logging
from pathlib import Path

_BASE_PATH = Path(__file__).resolve().parents[3]
LOG_DIR = str(_BASE_PATH / "logs")
_logger = None

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
    Launches tcpdump captures on RR1 and RR2 concurrently in background subprocesses.
    Waits and confirms both tcpdump processes are up before returning.
    """
    log = _init_run_logger()
    capture_start_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log.info(f"[HARNESS] Capture start requested at {capture_start_ts}")
    log.info("[HARNESS] Starting concurrent captures on RR1 and RR2...")
    cmd_rr1 = "wsl docker exec clab-pcap2story-rr1 bash -c 'tcpdump -i any -w /tmp/rr1.pcap'"
    cmd_rr2 = "wsl docker exec clab-pcap2story-rr2 bash -c 'tcpdump -i any -w /tmp/rr2.pcap'"

    log.info(f"[HARNESS] Popen: {cmd_rr1}")
    proc_rr1 = subprocess.Popen(cmd_rr1, shell=True)
    log.info(f"[HARNESS] Popen launched rr1 tcpdump (pid of wrapper shell: {proc_rr1.pid})")

    log.info(f"[HARNESS] Popen: {cmd_rr2}")
    proc_rr2 = subprocess.Popen(cmd_rr2, shell=True)
    log.info(f"[HARNESS] Popen launched rr2 tcpdump (pid of wrapper shell: {proc_rr2.pid})")

    # Confirm both tcpdump processes are running inside containers
    for attempt in range(1, 11):
        time.sleep(1)
        check_rr1 = subprocess.run("wsl docker exec clab-pcap2story-rr1 pidof tcpdump", shell=True, capture_output=True, text=True)
        check_rr2 = subprocess.run("wsl docker exec clab-pcap2story-rr2 pidof tcpdump", shell=True, capture_output=True, text=True)

        pid1 = check_rr1.stdout.strip()
        pid2 = check_rr2.stdout.strip()

        log.info(
            f"[HARNESS] pidof check attempt {attempt}/10: rr1={'PASS pid=' + pid1 if pid1 else 'FAIL (no pid)'}, "
            f"rr2={'PASS pid=' + pid2 if pid2 else 'FAIL (no pid)'}"
        )

        if pid1 and pid2:
            log.info(f"[HARNESS] Confirmed tcpdump running on RR1 (PID {pid1}) and RR2 (PID {pid2}) after {attempt} attempt(s).")
            return proc_rr1, proc_rr2

    log.error("[HARNESS] Failed to verify concurrent tcpdump processes on RR1 and RR2 after 10 attempts.")
    raise RuntimeError("[HARNESS] Failed to verify concurrent tcpdump processes on RR1 and RR2.")

def stop_and_collect_captures(scenario_name, target_dir=None):
    """
    Stops tcpdump processes on RR1 and RR2, copies PCAP files out to target scenario directory,
    and explicitly verifies both files exist and are non-zero before returning.
    """
    log = _init_run_logger()
    capture_stop_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log.info(f"[HARNESS] Capture stop requested at {capture_stop_ts}")

    if target_dir is None:
        target_dir = os.path.join(str(_BASE_PATH / "pcaps"), scenario_name)
    os.makedirs(target_dir, exist_ok=True)

    log.info("[HARNESS] Stopping tcpdump on RR1 and RR2...")
    subprocess.run("wsl docker exec clab-pcap2story-rr1 killall -2 tcpdump", shell=True)
    subprocess.run("wsl docker exec clab-pcap2story-rr2 killall -2 tcpdump", shell=True)
    time.sleep(2)
    
    rr1_dest = os.path.join(target_dir, "rr1.pcap")
    rr2_dest = os.path.join(target_dir, "rr2.pcap")
    
    def to_wsl_path(win_path):
        # Convert a Windows path (C:\foo\bar) to its WSL mount equivalent (/mnt/c/foo/bar)
        path = os.path.abspath(win_path).replace("\\", "/")
        if path[1:3] == ":/":
            drive = path[0].lower()
            path = f"/mnt/{drive}{path[2:]}"
        return path

    wsl_rr1_dest = to_wsl_path(rr1_dest)
    wsl_rr2_dest = to_wsl_path(rr2_dest)
    
    log.info(f"[HARNESS] Copying captures to {target_dir}...")
    subprocess.run(f"wsl docker cp clab-pcap2story-rr1:/tmp/rr1.pcap \"{wsl_rr1_dest}\"", shell=True, check=True)
    subprocess.run(f"wsl docker cp clab-pcap2story-rr2:/tmp/rr2.pcap \"{wsl_rr2_dest}\"", shell=True, check=True)

    # Explicit non-zero size collection verification
    for pcap_file in [rr1_dest, rr2_dest]:
        if not os.path.exists(pcap_file):
            log.error(f"[HARNESS] Collection error: Destination PCAP missing: {pcap_file}")
            raise FileNotFoundError(f"[HARNESS] Collection error: Destination PCAP missing: {pcap_file}")
        size = os.path.getsize(pcap_file)
        if size == 0:
            log.error(f"[HARNESS] Collection error: Destination PCAP is 0 bytes: {pcap_file}")
            raise ValueError(f"[HARNESS] Collection error: Destination PCAP is 0 bytes: {pcap_file}")

    log.info(f"[HARNESS] Verified collection: {rr1_dest} ({os.path.getsize(rr1_dest)} bytes)")
    log.info(f"[HARNESS] Verified collection: {rr2_dest} ({os.path.getsize(rr2_dest)} bytes)")

def inject_fault(node="pe1", fault_type="isolate", scenario_name="pe1_isolation", capture_duration=15):
    """
    Explicitly injects fault intent atomically:
    1. Starts concurrent captures on RR1 and RR2.
    2. Brings down all topology-facing interfaces for specified node.
    3. Writes scenario metadata ground truth JSON.
    4. Waits for capture duration and collects PCAP artifacts.
    """
    log = _init_run_logger()
    proc_rr1, proc_rr2 = start_concurrent_captures()

    gt_dir = str(_BASE_PATH / "metadata")
    os.makedirs(gt_dir, exist_ok=True)
    gt_file = os.path.join(gt_dir, f"{scenario_name}.json")

    if node.lower() == "pe1" and fault_type == "isolate":
        log.info("[HARNESS] Injecting atomic PE1 isolation fault (eth1 down + eth2 down)...")
        cmd = "wsl docker exec clab-pcap2story-pe1 bash -c 'ip link set eth1 down; ip link set eth2 down'"

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
    parser.add_argument("--node", default="pe1", help="Target node for fault injection")
    parser.add_argument("--fault", default="isolate", help="Fault type (e.g. isolate)")
    parser.add_argument("--scenario", default="pe1_isolation", help="Scenario output name")
    parser.add_argument("--duration", type=int, default=15, help="Capture window duration after fault (seconds)")
    args = parser.parse_args()
    
    inject_fault(node=args.node, fault_type=args.fault, scenario_name=args.scenario, capture_duration=args.duration)
