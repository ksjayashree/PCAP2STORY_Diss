# simulation pcap — real EVPN/BGP testbed captures

Two real containerlab/FRR testbeds that produce genuine EVPN/BGP packet captures (as opposed to `synthcap`, which synthesizes traffic in software). Both deploy FRR route-reflector/PE topologies under WSL2 + Docker + [containerlab](https://containerlab.dev/), inject faults or run normal traffic, and capture the resulting BGP control-plane traffic with `tcpdump` on every route reflector.

| | `2rr/` | `3rr/` |
|---|---|---|
| Topology | 5 PE, 2 RR | 10 PE, 3 RR |
| Lab name | `pcap2story` | `pcap2story-3rr-dev` |
| Capture files per scenario | `rr1.pcap`, `rr2.pcap` | `xrr1.pcap`, `xrr2.pcap`, `xrr3.pcap` |
| Topology file | `topology/5pe_2rr_topology.yml` | `topology/3rr_10pe_topology.yml` |

`3rr` is the larger sibling of `2rr` — same fault types and scripting pattern, scaled up to a bigger topology. They are separate codebases (not shared code), so scripts are duplicated between the two with topology-specific constants changed.

> All commands below assume you're running them from inside this folder (the one containing this README) — no absolute path to it is assumed anywhere; the orchestration scripts locate themselves via their own file location at runtime.

---

## Requirements

- **Windows 10/11** with **WSL2** enabled, running an **Ubuntu** distro
- Inside that Ubuntu distro: **Docker CE** (native, `apt`-installed) and **[containerlab](https://containerlab.dev/)**
- **Python 3** on the Windows side (the orchestration scripts run natively on Windows and shell out to `wsl docker exec ...` / `wsl bash ...` for everything that touches the containers)
- No `requirements.txt` — orchestration scripts use only the Python standard library (`subprocess`, `json`, `datetime`, `argparse`)

> **Docker Desktop must NOT be the active Docker engine.** Use native **Docker CE** installed directly inside the Ubuntu WSL2 distro (a systemd-managed `dockerd`), not Docker Desktop's WSL2 integration/backend. If Docker Desktop is installed on this machine at all, its **"Use the WSL 2 based engine"** / **WSL integration for this distro** setting must be switched **off**, so it doesn't proxy `docker` commands away from the native engine. Mixing the two causes exactly the kind of container/network confusion this project's scripts assume never happens (they assume one real dockerd inside the same distro they deploy into).

---

## Setup from scratch (new machine / new person)

### 1. Enable WSL2 and install Ubuntu

From an elevated PowerShell:

```powershell
wsl --install -d Ubuntu
```

This enables the WSL2 feature, installs the Ubuntu distro, and reboots if needed. On first launch, Ubuntu asks you to create a Linux username/password — any values are fine, they're local to WSL only.

Confirm it's on WSL **version 2** (not 1):

```powershell
wsl -l -v
```

If Ubuntu shows `VERSION 1`, convert it: `wsl --set-version Ubuntu 2`.

### 2. Install Docker CE inside Ubuntu (not Docker Desktop)

Open a WSL Ubuntu shell (`wsl` from PowerShell, or the Ubuntu app) and install Docker's own `apt` repo, per [Docker's official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

WSL2 distros generally don't run a full init system by default — enable `systemd` so `docker.service` can start automatically. Add this to `/etc/wsl.conf` (create it if it doesn't exist):

```ini
[boot]
systemd=true
```

Then, from PowerShell, restart WSL for that to take effect:

```powershell
wsl --shutdown
wsl
```

Enable and start Docker inside Ubuntu:

```bash
sudo systemctl enable --now docker
```

Let your Linux user run `docker` without `sudo` (optional but convenient):

```bash
sudo usermod -aG docker $USER
```
(log out of the WSL shell and back in for the group change to apply)

### 3. Verify Docker CE is the one actually running

```bash
docker --version
docker context ls
systemctl status docker
ls -la /var/run/docker.sock
which dockerd    # should print /usr/bin/dockerd
```

`docker context ls` should point at `unix:///var/run/docker.sock` with no `docker-desktop` context selected. If a `docker-desktop` WSL distro exists on this machine (`wsl -l -v` lists it), it must show **Stopped** — if it's Running, Docker Desktop's backend may be intercepting `docker` commands.

**Recommended: uninstall Docker Desktop entirely** rather than just disabling its WSL integration — having both installed is a real, observed source of confusion (competing `docker` contexts, `docker-desktop` and `docker-desktop-data` WSL distros left registered even after uninstall).

1. Windows Settings → Apps → Installed apps → "Docker Desktop" → Uninstall (or `winget uninstall Docker.DockerDesktop` from an admin PowerShell)
2. Clean up its leftover WSL distros, from PowerShell:
   ```powershell
   wsl -l -v
   wsl --unregister docker-desktop
   wsl --unregister docker-desktop-data
   ```
3. Confirm only your Ubuntu distro remains: `wsl -l -v`

### 4. Install containerlab

Inside the Ubuntu WSL shell ([official install docs](https://containerlab.dev/install/)):

```bash
curl -sL https://containerlab.dev/setup | sudo -E bash -s "all"
```

Verify:

```bash
containerlab version
```

The installer creates a `clab_admins` group. Add your user to it (same reason as the `docker` group above — lets you run `containerlab` without `sudo`):

```bash
sudo usermod -aG clab_admins $USER
```
(log out of the WSL shell and back in for this to apply — you can combine it with the `docker` group login-refresh from step 2 into a single exit/reopen)

Confirm both group memberships took effect:

```bash
groups
```
should list both `docker` and `clab_admins`.

### 5. Pull the FRR container image (first deploy will do this automatically, but you can prefetch)

```bash
docker pull quay.io/frrouting/frr:10.6.1
```

### 6. Python on the Windows side

The orchestration scripts (`scripts/fault/*.py`, `scripts/normal/*.py`, `scripts/test_scripts/*.py`) run from **Windows PowerShell**, not from inside WSL. Install Python 3 on Windows normally (python.org installer or `winget install Python.Python.3`) and confirm:

```powershell
python --version
```

No virtualenv or `pip install` step is needed — these scripts only use the Python standard library.

### 7. Confirm everything is reachable end-to-end

```powershell
wsl --status
wsl bash -c "which containerlab; which docker; docker ps"
```

You're ready to deploy — see **Deploying a topology** below.

---

## Deploying a topology

**`2rr`** — deployed via `containerlab deploy` directly (see `logs/control_deploy_5pe2rr_*.log` for a real deploy's node table). No retry wrapper script; deploy from WSL, from inside this folder's `2rr/topology` directory (adjust the `cd` target to wherever this folder actually lives on your machine — e.g. if this repo is at `C:\PCAP2STORY\Real_Captures`, that's `cd "/mnt/c/PCAP2STORY/Real_Captures/2rr/topology"`):

```bash
wsl
cd "/mnt/c/PCAP2STORY/Real_Captures/2rr/topology"
containerlab deploy -t 5pe_2rr_topology.yml
```

**`3rr`** — has a retry wrapper that detects a stalled deploy, cleans up, and retries once before giving up:

```bash
wsl
cd "/mnt/c/PCAP2STORY/Real_Captures/3rr/topology"
bash deploy_with_retry.sh
```

Both labs may already be deployed and running — check before redeploying:

```powershell
wsl bash -c "docker ps --format '{{.Names}}'"
```

Containers are named `clab-pcap2story-<node>` (2rr) or `clab-pcap2story-3rr-dev-<node>` (3rr), e.g. `clab-pcap2story-rr1`, `clab-pcap2story-3rr-dev-xpe4`.

---

## Capturing scenarios

All capture scripts run **from Windows** (not inside WSL) and shell out to `wsl docker exec clab-pcap2story-...` for anything that touches a container — this is the project convention in both folders.

### Normal baseline traffic

```powershell
python scripts/normal/capture_normal_baseline.py --duration 2 --load moderate
python scripts/normal/capture_normal_silent_pe.py --silent-pes 4 --load moderate --duration 2
```

`--duration` is capture length in minutes (1/2/5/10). `--load` is background churn intensity (light/moderate/heavy).

### Single-fault scenarios

Fault injection lives under `scripts/fault/`. The main driver, `All_Scenarios.py`, runs a full batch across every category in one pass (health-checks before each scenario, redeploys and retries on failure):

```powershell
python scripts/fault/All_Scenarios.py
```

`3rr` additionally has `scripts/fault/run_full_batch.py`, which deploys via `deploy_with_retry.sh` first, then drives the full ~223-scenario plan the same way (bounded 2-attempt-per-scenario retry, logs and continues on unexpected failures rather than stopping).

Individual fault families also have their own standalone drivers you can run in isolation (`mac_mobility_run.py`, `rd_collision_run.py`, `multi_incident_run.py`, `multi_batch2.py`, etc. — see `scripts/fault/`).

### Health check

Before capturing, confirm the lab has converged (OSPF/BGP up on every node):

```powershell
python scripts/test_scripts/check_health.py
```

---

## Output

Captures land under `pcaps/<scenario-family>/single/<scenario>/`, one pcap per capturing route reflector:

```
pcaps/
├── Normal/normal_light_2min/{rr1,rr2}.pcap          (2rr)
├── link_down/single/link_down_bfd_pe1_notrecovered/{rr1,rr2}.pcap
├── rt_misconfig/single/.../{rr1,rr2}.pcap
├── mac_mobility/single/.../{rr1,rr2}.pcap
├── rd_collision/single/.../{rr1,rr2}.pcap
├── pe_cease/single/.../{rr1,rr2}.pcap
├── rr_down/single/.../{rr1,rr2}.pcap
├── esdf_toggle/single/.../{rr1,rr2}.pcap
└── multiple/<category>/<scenario>/{rr1,rr2}.pcap    (multi-fault combos)
```

(`3rr` uses `{xrr1,xrr2,xrr3}.pcap` in place of `{rr1,rr2}.pcap`, and its `Normal` family is lowercase `normal/`.)

Currently on disk:

| Family | `2rr` | `3rr` |
|---|---|---|
| Normal | 36 files | 174 files |
| link_down | 60 files | 180 files |
| rr_down | 16 files | 36 files |
| pe_cease | 20 files | 60 files |
| rt_misconfig | 40 files | 120 files |
| mac_mobility | 6 files | 60 files |
| rd_collision | 14 files | 30 files |
| esdf_toggle | 2 files | — |
| multiple (combos) | 54 files | 81 files |

### Verify captures

```powershell
python scripts/test_scripts/verify_pcaps.py
```

---

## Ground truth

Fault-injection timing (when a fault was triggered / recovered) is derived per-scenario in `scripts/fault/link_down/derive_ground_truth.py` and logged alongside each run — check `logs/` for the corresponding `harness_run_<timestamp>.log` / `*_report.json` for a given capture.

---

## Notes

- These are **real** captures from live FRR containers — not reproducible byte-for-byte like `synthcap`'s deterministic-seed synthetic output. Re-running a scenario produces a new capture with the same fault *mechanism* but different real timing/jitter.
- `logs/` and `diagnostics/` hold the operational history of every deploy and capture run (timestamped, one file per run) — check there first if a specific capture's provenance is in question.
- Folders prefixed `_archived_` hold superseded scenario runs, kept for reference but not part of the current dataset.

---

## Troubleshooting: OSPF/BGP won't converge after deploy

If `check_health.py` reports every node stuck with "OSPF: No neighbors listed" and BGP in `Connect` state, and this follows a Windows sleep/resume, a `wsl --shutdown`, or the host machine restarting — the WSL2 VM's network namespace state can come back stale even though the containers themselves restart fine. Symptoms: a fresh `containerlab deploy` briefly shows OSPF converging in the deploy log, but the data-plane interfaces (`eth1`, `eth2`, ...) are gone from `docker exec <node> ip -brief link` within a minute or two of deploy finishing, and `check_health.py` fails.

Fix, in order of increasing effort:

1. **Destroy and redeploy** the affected lab (`containerlab destroy -t <topology.yml> --cleanup`, then `containerlab deploy -t <topology.yml>` — or `deploy_with_retry.sh` for `3rr`).
2. If that recurs, **fully restart WSL2** (not just Docker):
   ```powershell
   wsl --shutdown
   ```
   then reopen a WSL shell (this restarts the VM), and destroy+redeploy again.
3. If deploy itself now fails with `Failed to lookup link "br-...": Link not found` (Docker says a network was created but the kernel bridge device never appears — reproducible even for a plain `docker network create --driver bridge test`), Docker's internal network database is corrupted, usually from many prior deploy/destroy cycles across multiple labs. Fix (inside WSL):
   ```bash
   sudo systemctl stop docker docker.socket
   sudo rm -f /var/lib/docker/network/files/local-kv.db
   sudo systemctl start docker
   docker network ls   # should list only bridge/host/none
   ```
   This drops the network attachment of every container on the machine (all labs, not just the one you're working on) — they'll show as `Exited` afterward; destroy+redeploy each lab you need.
4. If it *still* recurs after both of the above, check whether the WSL2 VM itself is silently crashing and restarting (not just Docker/networking inside it) — this is a Windows host-level Hyper-V issue, not fixable from inside WSL/Docker/containerlab. Confirm with:
   ```bash
   uptime
   dmesg | tail -5   # if the first kernel-log timestamp is only seconds/
                      # minutes old relative to `uptime`, the VM rebooted
   ```
   If `uptime` shows only a few minutes even though you deployed longer ago than that, the VM crashed. Check Windows Event Viewer for what happened around that time, from PowerShell:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Hyper-V-Worker-Admin" -MaxEvents 20 |
     Format-Table TimeCreated, Id, Message -AutoSize
   Get-WinEvent -LogName System -MaxEvents 50 |
     Where-Object {$_.TimeCreated -gt (Get-Date).AddMinutes(-15)} |
     Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize
   ```
   Common causes: third-party antivirus/VPN interfering with the `vEthernet (WSL)` adapter, insufficient host resources for the `.wslconfig` memory/CPU limits, a pending Windows update needing a real (not just WSL) reboot, or a Hyper-V/driver bug. This needs Windows-level diagnosis — redeploying inside WSL will not fix a VM that keeps crashing.

Always verify with the actual health check, not just the deploy log — `node_setup.sh`'s "OSPF converged" message reflects the state at that instant during deploy and does not guarantee the links stay up afterward:

```powershell
python scripts/test_scripts/check_health.py
```

### Full reset (nuclear option)

If nothing above resolves it, wipe everything and start over:

**Docker only** (keeps Ubuntu/containerlab installed):
```bash
sudo systemctl stop docker docker.socket
sudo rm -rf /var/lib/docker
sudo systemctl start docker
```
Removes every container, image, network, and volume — re-pull the FRR image (`docker pull quay.io/frrouting/frr:10.6.1`) before the next deploy.

**Entire Ubuntu WSL distro** (most reliable if Docker-only reset doesn't help — full clean OS, most setup work afterward). From PowerShell, **not** WSL:
```powershell
wsl --shutdown
wsl --unregister Ubuntu
wsl --install -d Ubuntu
```
`--unregister` deletes everything inside the distro (Docker, containerlab, all packages) but does **not** touch this folder or anything else on the Windows filesystem. Redo **Setup from scratch** above afterward.
