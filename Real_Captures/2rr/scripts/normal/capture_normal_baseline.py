import sys
import os
import subprocess
import datetime
import time
import random
import threading
import argparse
from pathlib import Path

# Add path to import shared capture functions from inject_fault_harness
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fault", "link_down")))

from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures

COUNTER_FILE = str(Path(__file__).resolve().parents[2] / "pcaps" / ".n_id_counter")

def get_next_n_id():
    """
    Reads the persistent global n_id counter file. Returns starting integer in valid octet range [100..255].
    """
    if os.path.exists(COUNTER_FILE):
        try:
            with open(COUNTER_FILE, "r") as f:
                val = int(f.read().strip())
                if 100 <= val <= 255:
                    return val
        except Exception:
            pass
    return 100

def save_next_n_id(val):
    """
    Saves the next starting n_id back to the persistent counter file.
    Ensures val stays within [100..255] range before saving.
    """
    if val > 255 or val < 100:
        val = 100
    os.makedirs(os.path.dirname(COUNTER_FILE), exist_ok=True)
    with open(COUNTER_FILE, "w") as f:
        f.write(str(val))

def get_incremented_n_id(current_n_id, active_timers):
    """
    Increments n_id safely within the range [100..255].
    If n_id exceeds 255, wraps back to 100.
    Checks active_timers to ensure the candidate n_id is not currently pending withdrawal.
    """
    next_id = current_n_id + 1
    if next_id > 255:
        next_id = 100
        
    # Extract set of n_ids currently pending withdrawal in active_timers (stored in tuple item 2)
    pending_ids = {t[2] for t in active_timers if t[0].is_alive()}
    
    # If candidate next_id collides with a pending withdrawal timer, advance past it
    while next_id in pending_ids:
        next_id += 1
        if next_id > 255:
            next_id = 100
            
    return next_id

def cleanup_synthetic_entries():
    """
    Cleans up any leftover synthetic ARP/FDB entries (IP 10.100.0.100+ or MAC 52:54:00:00:00:64+)
    across all PE nodes (pe1-5) prior to starting capture.
    """
    print("[CLEANUP] Inspecting PE nodes for leftover synthetic MAC/IP entries...")
    for pe_idx in range(1, 6):
        container = f"clab-pcap2story-pe{pe_idx}"
        
        # Check kernel ARP neighbor table
        res_neigh = subprocess.run(f"wsl docker exec {container} ip neigh show dev vhost100", shell=True, capture_output=True, text=True)
        if res_neigh.stdout:
            for line in res_neigh.stdout.splitlines():
                parts = line.split()
                if parts:
                    ip = parts[0]
                    if ip.startswith("10.100.0."):
                        try:
                            last_octet = int(ip.split(".")[-1])
                            if last_octet >= 100:
                                print(f"[CLEANUP] Removing leftover ARP entry {ip} on pe{pe_idx}...")
                                subprocess.run(f"wsl docker exec {container} ip neigh del {ip} dev vhost100", shell=True)
                        except ValueError:
                            pass
                            
        # Check bridge FDB table
        res_fdb = subprocess.run(f"wsl docker exec {container} bridge fdb show dev vhost100", shell=True, capture_output=True, text=True)
        if res_fdb.stdout:
            for line in res_fdb.stdout.splitlines():
                parts = line.split()
                if parts:
                    mac = parts[0]
                    if mac.startswith("52:54:00:00:00:"):
                        try:
                            last_hex = int(mac.split(":")[-1], 16)
                            if last_hex >= 100:
                                print(f"[CLEANUP] Removing leftover FDB entry {mac} on pe{pe_idx}...")
                                subprocess.run(f"wsl docker exec {container} bridge fdb del {mac} dev vhost100 master", shell=True)
                        except ValueError:
                            pass

def withdraw_churn_event(container, pe_name, ip_addr, mac_addr, hold_time):
    """
    Executes the withdrawal portion of a churn event after hold_time seconds.
    """
    print(f"[CHURN] Withdrawing {ip_addr} / {mac_addr} from {pe_name} after {hold_time}s hold...")
    subprocess.run(["wsl", "docker", "exec", container, "ip", "neigh", "del", ip_addr, "dev", "vhost100"], check=True)
    subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "del", mac_addr, "dev", "vhost100", "master"], check=True)

def run_churn_event(pe_index, n_id, active_timers):
    """
    Injects a single MAC/IP churn event on a specific PE node, schedules its withdrawal
    asynchronously via threading.Timer, appends the timer object to active_timers list, and returns immediately.
    """
    pe_name = f"pe{pe_index}"
    container = f"clab-pcap2story-{pe_name}"
    
    ip_addr = f"10.100.0.{n_id}"
    mac_addr = f"52:54:00:00:00:{n_id:02x}"
    
    print(f"[CHURN] Adding {ip_addr} / {mac_addr} on {pe_name}...")
    subprocess.run(["wsl", "docker", "exec", container, "ip", "neigh", "add", ip_addr, "lladdr", mac_addr, "dev", "vhost100"], check=True)
    subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "add", mac_addr, "dev", "vhost100", "master", "static"], check=True)
    
    hold_time = random.randint(3, 8)
    
    # Schedule withdrawal asynchronously so main loop returns immediately
    timer = threading.Timer(hold_time, withdraw_churn_event, args=(container, pe_name, ip_addr, mac_addr, hold_time))
    timer.daemon = True
    active_timers.append((timer, hold_time, n_id))
    timer.start()

def capture_normal_baseline(duration_minutes, load):
    """
    Runs normal baseline traffic capture while background MAC/IP churn events are injected.
    Persistent global n_id counter is read at start, bounded within [100..255], and saved in try/finally block.
    """
    cleanup_synthetic_entries()
    
    load_mapping = {
        "light": 30,
        "moderate": 15,
        "heavy": 5
    }
    
    churn_interval = load_mapping[load]
    total_seconds = duration_minutes * 60
    scenario_name = f"normal_{load}_{duration_minutes}min"
    target_dir = os.path.join(str(Path(__file__).resolve().parents[2] / "pcaps"), scenario_name)
    
    proc_rr1, proc_rr2 = start_concurrent_captures()
    
    start_time = time.time()
    end_time = start_time + total_seconds
    
    pe_counter = 1
    n_id = get_next_n_id()
    churn_events_count = 0
    active_timers = []
    
    print(f"[BASELINE] Starting normal baseline '{scenario_name}' for {duration_minutes} min ({total_seconds}s) with interval {churn_interval}s starting n_id={n_id}...")
    
    try:
        while time.time() < end_time:
            loop_start = time.time()
            
            if loop_start + churn_interval > end_time:
                remaining = max(0, end_time - time.time())
                time.sleep(remaining)
                break
                
            run_churn_event(pe_counter, n_id, active_timers)
            churn_events_count += 1
            
            pe_counter = (pe_counter % 5) + 1
            n_id = get_incremented_n_id(n_id, active_timers)
            
            elapsed_in_loop = time.time() - loop_start
            sleep_needed = max(0, churn_interval - elapsed_in_loop)
            
            if time.time() + sleep_needed > end_time:
                sleep_needed = max(0, end_time - time.time())
                time.sleep(sleep_needed)
                break
                
            time.sleep(sleep_needed)
            
        print(f"[BASELINE] Main loop finished. Joining {len(active_timers)} active withdrawal timers...")
        for timer, hold_time, _ in active_timers:
            timer.join(timeout=hold_time + 5.0)
            
        stop_and_collect_captures(scenario_name, target_dir)
        print(f"[BASELINE] Completed baseline capture '{scenario_name}'. Total churn events injected: {churn_events_count}")
    finally:
        save_next_n_id(n_id)
        print(f"[BASELINE] Persisted next n_id={n_id} to {COUNTER_FILE}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normal Baseline Traffic Generator and Dual RR Capture")
    parser.add_argument("--duration", type=int, choices=[1, 2, 5, 10], required=True, help="Capture duration in minutes (1, 2, 5, 10)")
    parser.add_argument("--load", choices=["light", "moderate", "heavy"], required=True, help="Background churn load level (light, moderate, heavy)")
    args = parser.parse_args()
    
    capture_normal_baseline(args.duration, args.load)
