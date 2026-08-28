import json
import os
from pathlib import Path

BASE = str(Path(__file__).resolve().parents[3])

def derive_ground_truth(affected_pe, fault_type, t_fault, trigger_mechanism, recovered=False):
    ground_truth = {
        "event_affected_node": affected_pe,
        "fault_type": fault_type,
        "time_of_first_fault": t_fault,
        "trigger_mechanism": trigger_mechanism,
        "recovered": recovered
    }
    return ground_truth

if __name__ == "__main__":
    # Timestamp of PE1 complete isolation (eth1 down + eth2 down)
    t_fault = "2026-07-27T13:18:21.270122Z"
    gt = derive_ground_truth(
        affected_pe="PE1",
        fault_type="Link Down",
        t_fault=t_fault,
        trigger_mechanism="Interfaces eth1 and eth2 (PE1 dual point-to-point links) forced down via ip link set down, resulting in complete PE isolation",
        recovered=False
    )
    with open(os.path.join(BASE, "metadata", "ground_truth.json"), "w") as f:
        json.dump(gt, f, indent=2)
    print(json.dumps(gt, indent=2))
