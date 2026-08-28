import sys
import os
import subprocess
import time
import random
import threading
import argparse
from pathlib import Path

# Add path to import shared capture functions and cleanup helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "fault", "link_down")))
from inject_fault_harness import start_concurrent_captures, stop_and_collect_captures

from capture_normal_baseline import cleanup_synthetic_entries, withdraw_churn_event, get_next_n_id, save_next_n_id, get_incremented_n_id, COUNTER_FILE

def configure_pe_silence_state(silent_pes):
    """
    Configures base static MAC/IP entries across PE1-5:
    - Active PEs (not in silent_pes): Ensures base static entry (10.100.0.X / 52:54:00:00:00:0X) is present.
    - Silent PEs (in silent_pes): Explicitly removes base static entry so node remains EVPN silent.
    """
    print(f"[SILENT-PE] Applying topology configuration (Silent PEs: {silent_pes})...")
    for pe_idx in range(1, 6):
        container = f"clab-pcap2story-pe{pe_idx}"
        ip_addr = f"10.100.0.{pe_idx}"
        mac_addr = f"52:54:00:00:00:0{pe_idx}"
        
        if pe_idx in silent_pes:
            print(f"[SILENT-PE] Silencing pe{pe_idx}: Removing base static MAC/IP entry...")
            subprocess.run(["wsl", "docker", "exec", container, "ip", "neigh", "del", ip_addr, "dev", "vhost100"], check=False)
            subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "del", mac_addr, "dev", "vhost100", "master"], check=False)
            subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "del", mac_addr, "dev", "vhost100", "vlan", "1", "master"], check=False)
        else:
            print(f"[SILENT-PE] Active pe{pe_idx}: Ensuring base static MAC/IP entry present...")
            subprocess.run(["wsl", "docker", "exec", container, "ip", "neigh", "add", ip_addr, "lladdr", mac_addr, "dev", "vhost100"], check=False)
            subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "add", mac_addr, "dev", "vhost100", "master", "static"], check=False)

def verify_pe_silence_state(silent_pes):
    """
    Verifies via ip neigh show / bridge fdb show that silenced PEs have zero synthetic/base entries while active PEs do.
    """
    print("[SILENT-PE] Verifying PE silence state across topology...")
    all_ok = True
    for pe_idx in range(1, 6):
        container = f"clab-pcap2story-pe{pe_idx}"
        res_neigh = subprocess.run(["wsl", "docker", "exec", container, "ip", "neigh", "show", "dev", "vhost100"], capture_output=True, text=True, check=True)
        res_fdb = subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "show", "dev", "vhost100"], capture_output=True, text=True, check=True)
        
        has_neigh = any(line.split()[0].startswith("10.100.0.") for line in res_neigh.stdout.strip().splitlines() if line.strip())
        has_fdb = any(line.split()[0].startswith("52:54:00:00:00:") for line in res_fdb.stdout.strip().splitlines() if line.strip())
        
        if pe_idx in silent_pes:
            if has_neigh or has_fdb:
                print(f"[SILENT-PE] ERROR: pe{pe_idx} is marked SILENT but has active entries!")
                all_ok = False
            else:
                print(f"[SILENT-PE] CONFIRMED: pe{pe_idx} is completely silent.")
        else:
            if not has_neigh or not has_fdb:
                print(f"[SILENT-PE] WARNING: pe{pe_idx} is marked ACTIVE but missing static entry.")
            else:
                print(f"[SILENT-PE] CONFIRMED: pe{pe_idx} is active.")
                
    if not all_ok:
        raise RuntimeError("[SILENT-PE] Silence state verification failed!")

def run_churn_event_active_pes(active_pes, pe_rotation_idx, n_id, active_timers):
    """
    Injects a MAC/IP churn event rotating ONLY through active_pes (never touching silent PEs).
    Returns the updated rotation index.
    """
    pe_idx = active_pes[pe_rotation_idx % len(active_pes)]
    pe_name = f"pe{pe_idx}"
    container = f"clab-pcap2story-{pe_name}"
    
    ip_addr = f"10.100.0.{n_id}"
    mac_addr = f"52:54:00:00:00:{n_id:02x}"
    
    print(f"[CHURN] Adding {ip_addr} / {mac_addr} on active {pe_name}...")
    subprocess.run(["wsl", "docker", "exec", container, "ip", "neigh", "add", ip_addr, "lladdr", mac_addr, "dev", "vhost100"], check=True)
    subprocess.run(["wsl", "docker", "exec", container, "bridge", "fdb", "add", mac_addr, "dev", "vhost100", "master", "static"], check=True)
    
    hold_time = random.randint(3, 8)
    
    timer = threading.Timer(hold_time, withdraw_churn_event, args=(container, pe_name, ip_addr, mac_addr, hold_time))
    timer.daemon = True
    active_timers.append((timer, hold_time, n_id))
    timer.start()
    
    return pe_rotation_idx + 1

def capture_normal_silent_pe(silent_pes, load="moderate", duration_minutes=2):
    """
    Runs a normal baseline capture with specific PE nodes kept completely silent.
    Persistent global n_id counter is read at start, bounded within [100..255], and saved in try/finally block.
    """
    active_pes = [p for p in range(1, 6) if p not in silent_pes]
    if not active_pes:
        raise ValueError("At least one PE must remain active!")
        
    cleanup_synthetic_entries()
    configure_pe_silence_state(silent_pes)
    verify_pe_silence_state(silent_pes)
    
    load_mapping = {"light": 30, "moderate": 15, "heavy": 5}
    churn_interval = load_mapping[load]
    total_seconds = duration_minutes * 60
    
    pe_str = "".join(str(p) for p in sorted(silent_pes))
    scenario_name = f"normal_silent_pe{pe_str}_{duration_minutes}min"
    target_dir = os.path.join(str(Path(__file__).resolve().parents[2] / "pcaps"), scenario_name)
    
    proc_rr1, proc_rr2 = start_concurrent_captures()
    
    start_time = time.time()
    end_time = start_time + total_seconds
    
    pe_rotation_idx = 0
    n_id = get_next_n_id()
    churn_events_count = 0
    active_timers = []
    
    print(f"[BASELINE] Starting silent-PE capture '{scenario_name}' for {duration_minutes} min ({total_seconds}s) starting n_id={n_id}...")
    print(f"[BASELINE] Active PEs: {active_pes} | Silent PEs: {silent_pes}")
    
    try:
        while time.time() < end_time:
            loop_start = time.time()
            
            if loop_start + churn_interval > end_time:
                remaining = max(0, end_time - time.time())
                time.sleep(remaining)
                break
                
            pe_rotation_idx = run_churn_event_active_pes(active_pes, pe_rotation_idx, n_id, active_timers)
            churn_events_count += 1
            n_id = get_incremented_n_id(n_id, active_timers)
            
            elapsed_in_loop = time.time() - loop_start
            sleep_needed = max(0, churn_interval - elapsed_in_loop)
            
            if time.time() + sleep_needed > end_time:
                sleep_needed = max(0, end_time - time.time())
                time.sleep(sleep_needed)
                break
                
            time.sleep(sleep_needed)
            
        print(f"[BASELINE] Joining {len(active_timers)} active withdrawal timers...")
        for timer, hold_time, _ in active_timers:
            timer.join(timeout=hold_time + 5.0)
            
        stop_and_collect_captures(scenario_name, target_dir)
    finally:
        save_next_n_id(n_id)
        print(f"[BASELINE] Persisted next n_id={n_id} to {COUNTER_FILE}")
        
    print("[SILENT-PE] Restoring default static MAC/IP entries on silenced PEs...")
    configure_pe_silence_state(silent_pes=[])
    
    print(f"[BASELINE] Completed silent-PE capture '{scenario_name}'. Total churn events: {churn_events_count}")

def parse_pe_list(pe_str):
    """Converts CLI string like '4', '4,5', '2,3' into list of ints [4, 5]."""
    try:
        return [int(p.strip()) for p in pe_str.split(",") if p.strip()]
    except Exception:
        raise argparse.ArgumentTypeError("PE list must be comma-separated integers, e.g. '4' or '4,5'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Silent-PE Normal Baseline Capture Generator")
    parser.add_argument("--silent-pes", type=parse_pe_list, required=True, help="Comma-separated PE numbers to keep silent (e.g. '4', '4,5', '2,3')")
    parser.add_argument("--load", choices=["light", "moderate", "heavy"], default="moderate", help="Background churn load level (default: moderate)")
    parser.add_argument("--duration", type=int, choices=[1, 2, 5, 10], default=2, help="Capture duration in minutes (default: 2)")
    args = parser.parse_args()
    
    capture_normal_silent_pe(silent_pes=args.silent_pes, load=args.load, duration_minutes=args.duration)
