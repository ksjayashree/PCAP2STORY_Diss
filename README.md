# pcap2story

Four folders, covering the full pipeline: generating/capturing EVPN/BGP packet captures, then detecting and explaining the faults inside them.

## Folders

### `Synthetic_Captures/`
Software toolkit that synthesizes production-realistic EVPN/BGP PCAP files (plus per-scenario JSON ground truth) without a live network. See its own [README](Synthetic_Captures/README.md) to generate captures.

### `Real_Captures/`
Two real containerlab/FRR testbeds (`2rr/` = 5 PE/2 RR, `3rr/` = 10 PE/3 RR) that produce genuine EVPN/BGP packet captures by running an actual network under WSL2 + Docker + containerlab, injecting real faults, and capturing the resulting BGP traffic with `tcpdump`. See its own [README](Real_Captures/README.md) to run a testbed.

### `input/`
Five real, pre-captured fault scenarios (one folder each, containing `rr1.pcap`, `rr2.pcap`, `metadata.json`) taken from `Real_Captures`, used as the demo input for `Detector_and_Explanation/end_to_end.py`.

### `Detector_and_Explanation/`
Takes a capture (from `input/`) and runs it through the full pipeline: fault detection -> explanation generation -> RFC-grounded self-correction -> final human-readable output. See its own [README](Detector_and_Explanation/README.md) to set up and run a demo.

## Where to start

To just see the end result — a real fault explained end-to-end — go to [`Detector_and_Explanation/README.md`](Detector_and_Explanation/README.md) and run `end_to_end.py` against one of the five folders in `input/`.

To see where the packet captures themselves come from, look at `Synthetic_Captures/` (software-generated) or `Real_Captures/` (real network testbed).
