# synthcap

> **Copyright (c) 2026 Ciena Corporation. All Rights Reserved.**
> Proprietary and confidential.

Synthetic packet capture toolkit for EVPN/BGP control-plane traffic.

Generates production-realistic synthetic PCAP files (plus per-scenario JSON ground truth) for fault-detection research on EVPN fabrics.

---

## Table of Contents

- [Quick Start](#quick-start)
- [What Gets Generated](#what-gets-generated)
- [Generation Scripts](#generation-scripts)
- [Output Structure](#output-structure)
- [CLI Reference](#cli-reference)
- [Checker](#checker--checkersevpn_bgp)
- [Other Utility Scripts](#other-utility-scripts)
- [Adding a New Scenario](#adding-a-new-scenario)
- [Topology Configuration](#topology-configuration)
- [Requirements](#requirements)

---

> **Platform note:** All commands are shown for both platforms.
> macOS / Linux uses `python` and `\` for line continuation.
> Windows PowerShell uses `py` and a backtick for line continuation.

---

## Quick Start

**macOS / Linux**

```bash
cd synthcap
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
cd synthcap
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

> **tshark required for the checker.**
> - macOS: `brew install --cask wireshark` or download from https://www.wireshark.org
> - Windows: Wireshark installer includes tshark — tick "Add to PATH" during setup

Generate everything with one command:

```bash
python scripts/generate_dual_vantage.py --config configs/default_topology.yaml --output output
python scripts/generate_multi_incident.py --config configs/default_topology.yaml --output output
```

---

## What Gets Generated

The active scenario set (`SCENARIO_REGISTRY` in [`generators/evpn_bgp/cli.py`](generators/evpn_bgp/cli.py)) covers three in-scope fault types, plus their paired/combo variants. A large amount of older scenario code (Link Down, RR Down, Normal baselines, AS Misconfig, FSM Error, and other Section 1/3/4 content) still exists in the codebase but is commented out of the registry — it's covered by the separate pilot_containerlab testbed, or paused pending a scope decision. It is not part of the current dataset.

| Fault type | Single-fault variants | Notes |
|---|---|---|
| **ESDF Toggle** | single, repeated, no-recovery, slow, single-midchurn, type1-EVI, AC-state, full-failure (recovery / no-recovery) | Per PE1/PE2 (5PE/2RR topology) and PE3/PE4/PE6/PE7 (3RR topology) |
| **RT Misconfig (ES-Import only)** | es-import, es-import-recovery | Per PE1/PE2 (5PE/2RR) and PE3/PE4/PE6/PE7 (3RR). Plain import/export RT misconfig is out of scope — already covered on the real testbed |
| **MAC Mobility** | rapid-flap, repeated-flap | PE1↔PE2 and PE4↔PE5 pairs (5PE/2RR topology only) |

Plus multi-incident (two faults in one capture) combinations: ESDF×2, RT-Misconfig×2, MAC-Mobility×2, and ESDF+RT-Misconfig / ESDF+MAC-Mobility crosses — see [`generate_multi_incident.py`](scripts/generate_multi_incident.py).

Every scenario is generated once per route reflector vantage point in the topology (RR1+RR2 for the default 5PE/2RR config, RR1+RR2+RR3 for the 3RR config) by `generate_dual_vantage.py`.

---

## Generation Scripts

Two scripts cover the full current dataset. Both are single commands — each generates every registered scenario for the given topology in one run.

### `scripts/generate_dual_vantage.py` — single-fault scenarios

Generates every registered scenario once per RR vantage, into a folder-per-scenario layout:

```bash
python scripts/generate_dual_vantage.py --config configs/default_topology.yaml --output output
python scripts/generate_dual_vantage.py --config configs/default_topology.yaml --output output --workers 8
```

Produces `output/<category>/single/<scenario>/rr1.pcap`, `rr2.pcap` (and `rr3.pcap` for the 3RR topology), plus one `metadata.json` per scenario holding ground truth, expected BGP events, topology, and per-vantage fault timing/frame counts.

### `scripts/generate_multi_incident.py` — multi-fault scenarios

Generates the scenarios with two overlapping faults in one capture (e.g. ESDF Toggle + RT Misconfig together):

```bash
python scripts/generate_multi_incident.py --config configs/default_topology.yaml --output output
python scripts/generate_multi_incident.py --config configs/3rr_topology.yaml --output output_3rr
```

Produces `output/multiple/<category>/<scenario>/rr1.pcap`, `rr2.pcap` (and `rr3.pcap` for 3RR), plus `metadata.json`. Runs sequentially, one scenario at a time — no `--workers` flag (there are only a handful of multi-incident scenarios, so this is fast enough as-is).

`generate_dual_vantage.py` takes `--workers N` to control parallelism (default: 8, via `ProcessPoolExecutor`, one process per scenario×vantage job). Both scripts share the same deterministic per-scenario seeding, so re-running either with the same `--config` reproduces byte-identical output.

### 3RR Topology

`configs/3rr_topology.yaml` (3 route reflectors, 10 PEs) is a second topology usable as `--config`/`--topology` on any script here, alongside the default `configs/default_topology.yaml` (2 route reflectors, 5 PEs).

---

## Output Structure

```
output/
├── esdf_toggle/single/esdf_toggle_single_pe1/
│   ├── rr1.pcap
│   ├── rr2.pcap
│   └── metadata.json
├── rt_misconfig/single/rt_misconfig_es_import_pe1/
│   └── ...
├── mac_mobility/single/mac_mobility_rapid_pe1_pe2/
│   └── ...
└── multiple/
    ├── esdf_toggle_x2/esdf_toggle_x2_pe1_pe2/
    ├── rt_misconfig_x2/rt_misconfig_x2_pe1_pe2/
    ├── mac_mobility_x2/catB_mac_mobility_x2/
    ├── catC_esdf_toggle_rt_misconfig/...
    └── catC_esdf_toggle_mac_mobility/...
```

Each `metadata.json` looks like:

```json
{
  "scenario_stem": "esdf_toggle_single_pe1",
  "fault_type": "ES/DF Toggle",
  "ground_truth_label": "ES/DF Toggle",
  "affected_device": "PE1",
  "description": "...",
  "expected_bgp_events": ["..."],
  "topology": { "..." },
  "fault_window": {
    "rr1": { "fault_start_t": "...", "fault_end_t": "..." },
    "rr2": { "fault_start_t": "...", "fault_end_t": "..." }
  },
  "frame_counts": {
    "rr1": { "total_frames": 8000, "bgp_update": 42 },
    "rr2": { "total_frames": 8000, "bgp_update": 42 }
  }
}
```

`fault_window` and `frame_counts` are nested per vantage (RR1/RR2/RR3) because propagation delay makes fault timing genuinely differ between reflectors even though the underlying fault is the same.

---

## CLI Reference

`generate_dual_vantage.py` and `generate_multi_incident.py` are the recommended entry points (above). The lower-level per-scenario CLI they call into is also usable directly:

```
python -m generators.evpn_bgp [OPTIONS]       # macOS / Linux
py -m generators.evpn_bgp [OPTIONS]           # Windows
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--config` | PATH | required | Path to topology YAML file |
| `--output` | PATH | `./output` | Output directory |
| `--capture-vantage` | TEXT | config's own value | Override the topology's `capture_vantage` (e.g. RR1, RR2) for this run |
| `--all` | FLAG | — | Generate all registered scenarios |
| `--section` | INT | — | Generate scenarios for a specific registry section (currently only `2` has active entries) |
| `--fault-type` | TEXT | — | Filter by fault type (`esdf-toggle`, `rt-misconfig`, `mac-mobility`) |
| `--variant` | TEXT | — | Generate a specific variant of a fault type |
| `--frames-per-file` | INT | varies | Total frames per PCAP (defaults differ per scenario) |
| `--copies` | INT | 1 | Number of copies per scenario |
| `--seed` | INT | 42 | Seed the RNG for reproducible generation (same seed + same selection yields byte-identical pcaps) |
| `--metadata` / `--no-metadata` | FLAG | on | Generate Excel spreadsheet + per-pcap JSON alongside pcaps |
| `--list-scenarios` | FLAG | — | List all available scenarios and exit |

### Examples

```bash
# List all available scenarios
python -m generators.evpn_bgp --list-scenarios

# All ESDF Toggle variants
python -m generators.evpn_bgp --config configs/default_topology.yaml \
    --output output/ --fault-type esdf-toggle --metadata

# Single specific variant
python -m generators.evpn_bgp --config configs/default_topology.yaml \
    --output output/ --fault-type rt-misconfig --variant es-import-pe1
```

---

## Checker — `checkers/evpn_bgp`

Decodes PCAP files with `tshark`, extracts BGP sessions and EVPN routes, and runs a suite of validation rules.

> Replace `python` with `py` on Windows for all commands below.

```bash
# Full consistency check
python -m checkers.evpn_bgp verify capture.pcap

# With topology awareness
python -m checkers.evpn_bgp verify capture.pcap \
    --topology configs/default_topology.yaml

# Mid-session capture (relaxed checks)
python -m checkers.evpn_bgp verify capture.pcap --partial-capture

# Summary counts only
python -m checkers.evpn_bgp verify capture.pcap --summary-only

# Sequence (ladder) diagram
python -m checkers.evpn_bgp ladder capture.pcap --mac 00:2f:01:00:00:01

# Route timeline
python -m checkers.evpn_bgp timeline capture.pcap

# Reconstructed MAC table
python -m checkers.evpn_bgp mac-table capture.pcap --evi 100

# Sensitivity scan
python -m checkers.evpn_bgp inspect capture.pcap
```

### Validation Rules

| Code | Severity | Description |
|------|----------|-------------|
| BGP-001 | FAIL | UPDATE or KEEPALIVE received before OPEN |
| BGP-002 | FAIL | Traffic after NOTIFICATION |
| BGP-003 | WARN | Route Refresh without negotiated capability |
| BGP-004 | WARN | Hold Time advertised as 1 or 2 seconds (must be 0 or >= 3, RFC 4271 §4.2) |
| EVPN-001 | FAIL | EVPN UPDATE without L2VPN/EVPN capability |
| EVPN-002 | WARN | Type 2 MAC without corresponding Type 3 IMET |
| EVPN-003 | WARN | Type 2 MAC precedes Type 3 IMET |
| EVPN-004 | WARN | MAC withdrawal without prior advertisement |
| EVPN-005 | WARN/FAIL | MAC move detected |
| EVPN-006 | WARN | Route Target to EVI mapping mismatch |
| EVPN-007 | WARN | MAC with only one advertising PE |
| EVPN-008 | WARN | Type 2 MAC advertisement carries broadcast, multicast, or all-zero MAC |
| MH-001 | FAIL | Type 2 with non-zero ESI but no Type 1 A-D |
| TOPO-001 | WARN | Declared PE with no BGP session |
| TOPO-002 | WARN | Declared PE with no EVPN routes |
| TOPO-003 | FAIL | Route next-hop unknown |
| TOPO-004 | WARN | ESI-sharing PE missing Type 1/4 routes |
| TOPO-005 | INFO | MAC single-homed on a multi-homed PE |
| SCEN-001 | WARN | Expected BGP peer not found |
| SCEN-002 | WARN | Expected IMET not found |

TOPO-* rules only run when `--topology` is provided.

---

## Other Utility Scripts

> Replace `python` with `py` on Windows for all commands below.

### `scripts/validate.py` — Structural Validator

```bash
python scripts/validate.py output/ --verbose
python scripts/validate.py output/ --json
```

Structural checks on every PCAP: frame count, BGP message types, EVPN routes, timestamp monotonicity, and link-layer type.

### `scripts/generate_report.py` — HTML Report

```bash
python scripts/generate_report.py \
    --output report.html \
    --topology configs/default_topology.yaml \
    --pcap-dir output/
```

### `scripts/analyse_section.py` — BGP Message Breakdown

Analyses a generated directory and prints a per-file table of frame counts and BGP message type totals. Useful for verifying generated captures match expected distributions.

```bash
python scripts/analyse_section.py output/esdf_toggle
```

### `scripts/generate_json.py` — CATALOGUE / JSON Ground Truth

**Required by `generate_dual_vantage.py`**, which imports `CATALOGUE` and several helpers (`count_pcap_stats`, `_affected_link_ids`, ...) directly from this file to build each scenario's `metadata.json` — it is not optional for the main workflow. (`generate_multi_incident.py` does not use it; it builds `metadata.json` from its own `self.incidents` data instead.)

It can also be run standalone to regenerate per-pcap JSON from the static `CATALOGUE` dict without regenerating PCAPs — used by the older single-vantage CLI path (`--metadata` flag on `python -m generators.evpn_bgp`):

```bash
python scripts/generate_json.py --output-dir output/
python scripts/generate_json.py --output-dir output/ --dry-run
```

---

## Adding a New Scenario

Three touch points are required.

### 1. Create the scenario class

Add a class under `generators/evpn_bgp/scenarios/` inheriting from `BaseScenario`:

```python
from .base import BaseScenario

class MyNewScenario(BaseScenario):
    def generate(self) -> list:
        packets = []
        t = self.start_time

        setup_pkts, t = self.establish_all_sessions(t)
        packets.extend(setup_pkts)

        init_pkts, t = self.generate_initial_routes(t)
        packets.extend(init_pkts)

        # inject fault here

        return packets
```

`BaseScenario` helpers:

| Helper | Description |
|--------|-------------|
| `establish_all_sessions(t)` | TCP handshake and BGP OPEN for all sessions at vantage |
| `generate_initial_routes(t)` | Full EVPN route table (Types 1 to 5) across all sessions |
| `generate_keepalives_for_duration(t, duration)` | Fill a time window with keepalives |
| `self.tcp_sessions` | Dict of session_id to TCPSession for all established sessions |
| `self.topology.get_sessions_at_vantage()` | List of BGPSession objects visible from capture point |

### 2. Register in the CLI

Add an entry to `SCENARIO_REGISTRY` in `generators/evpn_bgp/cli.py`, under section `2` alongside `esdf-toggle` / `rt-misconfig` / `mac-mobility`:

```python
2: {
    "my-fault": {
        "my-variant-pe1": "generators.evpn_bgp.scenarios.my_scenario.MyNewScenarioPE1",
        "my-variant-pe2": "generators.evpn_bgp.scenarios.my_scenario.MyNewScenarioPE2",
    },
},
```

### 3. Add a JSON catalogue entry (only if using the legacy single-vantage `--metadata` path)

If the scenario should also work through `python -m generators.evpn_bgp --metadata` (rather than only `generate_dual_vantage.py`), add an entry to `CATALOGUE` in `scripts/generate_json.py`:

```python
("section2_labelled", "my_fault_my_variant_pe1"): _make(
    section=2,
    fault_type="My Fault",
    ground_truth="My Fault",
    affected_device="PE1",
    recovery=True,
    recovery_time_seconds=FAULT_INJECT_TIME + 30,
    description="Short description of what PE1 does in this scenario.",
    event_key="my_fault",   # add a matching entry to EVENTS dict above
),
```

Then generate and validate:

```bash
python scripts/generate_dual_vantage.py --config configs/default_topology.yaml \
    --output output --workers 1

python scripts/validate.py output/my_fault/single/my_fault_my_variant_pe1 --verbose
```

---

## Topology Configuration

```yaml
as_number: 65001

timing:
  hold_timer: 30
  keepalive_timer: 10
  connect_retry: 30
  min_route_adv_interval: 0

evpn:
  vni: 100
  route_target: "65001:100"
  mac_pool_size: 50
  ip_prefix_pool: "192.168.0.0/16"
  srv6_locator_prefix: "2001:db8:ffff::/48"

capture_vantage: RR1

route_reflectors:
  - id: RR1
    loopback: "2001:db8::1:1"
    bgp_id: "10.0.0.1"
  - id: RR2
    loopback: "2001:db8::1:2"
    bgp_id: "10.0.0.2"

pe_nodes:
  - id: PE1
    loopback: "2001:db8::2:1"
    bgp_id: "10.0.0.11"
    esi: "00:11:22:33:44:55:66:77:88:01"
  - id: PE2
    loopback: "2001:db8::2:2"
    bgp_id: "10.0.0.12"
    esi: "00:11:22:33:44:55:66:77:88:01"   # same ESI as PE1 — multi-homed pair
  - id: PE3
    loopback: "2001:db8::2:3"
    bgp_id: "10.0.0.13"
  - id: PE4
    loopback: "2001:db8::2:4"
    bgp_id: "10.0.0.14"
  - id: PE5
    loopback: "2001:db8::2:5"
    bgp_id: "10.0.0.15"
```

Two topologies ship in `configs/`:

| File | Route reflectors | PEs | Notes |
|------|-------------------|-----|-------|
| `configs/default_topology.yaml` | RR1, RR2 | PE1–PE5 | Default. PE1/PE2 is the ESI-multihomed pair |
| `configs/3rr_topology.yaml` | RR1, RR2, RR3 | PE1–PE10 | PE3/PE4 and PE6/PE7 are the ESI-multihomed pairs |

---

## Repository Layout

```
synthcap/
├── generators/
│   ├── common/              # Protocol-agnostic utilities (pcap writer, timing)
│   └── evpn_bgp/            # EVPN/BGP synthetic PCAP generator
│       ├── scenarios/       # One class per scenario (esdf_toggle.py, rt_misconfig.py,
│       │                    # mac_mobility.py, mixed.py, plus paused Section 1/3/4 files)
│       ├── bgp/             # BGP message builders
│       ├── tcp/             # TCP session simulator
│       ├── cli.py           # Click CLI + SCENARIO_REGISTRY (source of truth for what's active)
│       ├── config.py        # Topology config loader
│       ├── metadata.py      # Excel metadata writer
│       └── topology.py      # Graph topology model
├── checkers/
│   ├── common/              # Protocol-agnostic utilities (tshark wrapper)
│   └── evpn_bgp/            # EVPN/BGP consistency checker and sensitivity inspector
├── configs/
│   ├── default_topology.yaml    # 5PE / 2RR
│   └── 3rr_topology.yaml        # 10PE / 3RR
├── scripts/
│   ├── generate_dual_vantage.py     # Recommended — all single-fault scenarios, all vantages
│   ├── generate_multi_incident.py   # Recommended — all multi-fault (combo) scenarios
│   ├── generate_parallel.py         # Legacy single-vantage parallel generator
│   ├── validate.py                  # Structural PCAP validator
│   ├── generate_report.py           # HTML report generator
│   ├── generate_json.py             # CATALOGUE + JSON helpers — required by generate_dual_vantage.py
│   └── analyse_section.py           # BGP message breakdown table for a directory
├── requirements.txt
└── README.md
```

---

## Requirements

- **Python** 3.10+ (verified working on 3.14)
- **tshark** (Wireshark CLI) on `PATH` — required by the checker
  - macOS: `brew install --cask wireshark`
  - Windows: Wireshark installer at https://www.wireshark.org — tick "Add to PATH"

```bash
pip install -r requirements.txt
```

| Package | Version | Used by |
|---------|---------|---------|
| `scapy` | >= 2.5.0 | generator, validator, inspector |
| `click` | >= 8.0 | generator CLI |
| `pyyaml` | >= 6.0 | generator, checker |
| `openpyxl` | >= 3.1.0 | metadata spreadsheet |
| `colorama` | >= 0.4 | inspector (coloured output) |
| `manuf` | >= 1.1 | inspector (MAC OUI lookup) |

---

## License

Part of an MSc dissertation. Not published under an open-source licence.
