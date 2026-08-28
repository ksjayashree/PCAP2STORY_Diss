import sys
import os
import time
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "normal"))
from capture_normal_baseline import run_churn_event

active_timers = []
print("Testing fixed run_churn_event() directly on PE2...")
run_churn_event(pe_index=2, n_id=223, active_timers=active_timers)

print("Checking rr1 BGP EVPN route table immediately for 10.100.0.223 / 52:54:00:00:00:df...")
res = subprocess.run(["wsl", "docker", "exec", "clab-pcap2story-3rr-dev-xrr1", "vtysh", "-c", "show bgp l2vpn evpn route"], capture_output=True, text=True)
print(res.stdout)

print(f"Waiting for timer withdrawal ({len(active_timers)} active timer)...")
for t, hold, _ in active_timers:
    t.join()

print("Re-checking rr1 BGP EVPN route table after withdrawal...")
res2 = subprocess.run(["wsl", "docker", "exec", "clab-pcap2story-3rr-dev-xrr1", "vtysh", "-c", "show bgp l2vpn evpn route"], capture_output=True, text=True)
print(res2.stdout)
