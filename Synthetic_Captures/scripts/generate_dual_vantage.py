"""Generate all registered scenarios once per RR vantage in the topology
(RR1+RR2 for the 5PE/2RR config, RR1+RR2+RR3 for the 3RR config -- the
vantage list is derived from the topology YAML's route_reflectors), in
parallel, into a folder-per-scenario layout:

    output/{category}/single/{scenario_stem}/rr1.pcap
    output/{category}/single/{scenario_stem}/rr2.pcap
    output/{category}/single/{scenario_stem}/rr3.pcap   (3RR topologies only)
    output/{category}/single/{scenario_stem}/metadata.json

{category} is the fault_type slug (e.g. "esdf_toggle", "rt_misconfig").
metadata.json holds the static, vantage-independent fields once (fault
type, ground truth label, affected device, description, expected BGP
events, topology, ...) plus a "fault_window" key nested per vantage, since
fault_start_datetime_utc/fault_end_datetime_utc genuinely differ between
RR1 and RR2 (reflection delay) even though the underlying fault is the same.
It is omitted entirely for Normal/baseline fault types.

Both vantages are generated from the same topology YAML using
--capture-vantage to switch RR1/RR2 at runtime. Uses the same per-scenario
deterministic seeding as cli.py/generate_parallel.py, so start_time and all
vantage-invariant params are identical between vantage runs; only the
actual fault propagation delay differs.

Generation is parallelised across worker processes (one job per scenario x
vantage), same model as scripts/generate_parallel.py. The metadata.json
merge step runs afterward, in the main process.

Usage:
    python scripts/generate_dual_vantage.py --config configs/default_topology.yaml --output output
    python scripts/generate_dual_vantage.py --config configs/default_topology.yaml --output output --workers 8
"""

import argparse
import hashlib
import json
import os
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

def _scenario_seed(global_seed: int, cls_path: str, copy_idx: int) -> int:
    key = f"{global_seed}:{cls_path}:{copy_idx}"
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % (2**31)


# ---------------------------------------------------------------------------
# Worker -- runs in a separate process, no shared state
# ---------------------------------------------------------------------------

def _generate_one(job_args):
    """Generate a single (scenario, vantage) pcap+csv. Runs in a worker process."""
    cls_path, out_path_str, config_path_str, frames, sec, seed, global_seed, vantage = job_args
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from generators.evpn_bgp.config import load_config
        from generators.evpn_bgp.cli import _import_class
        import random

        warnings.filterwarnings(
            'ignore', message=r'.*did not set _fault_start_t.*', category=UserWarning,
        )

        random.seed(seed)

        cfg = load_config(Path(config_path_str))
        cfg.capture_vantage = vantage

        out_path = Path(out_path_str)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        Cls = _import_class(cls_path)
        scenario = Cls(config=cfg, target_frames=frames)
        n = scenario.write(out_path, section=sec, seed=global_seed, copy_idx=1,
                          write_csv_sidecar=False)
        return out_path_str, scenario.start_time, n, None
    except Exception as e:
        return out_path_str, None, 0, str(e)


# ---------------------------------------------------------------------------
# Job list
# ---------------------------------------------------------------------------

def _build_jobs(config_path, output_dir, global_seed, vantages, section_filter=None):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from generators.evpn_bgp.cli import (
        SECTION_DIR_MAP, DEFAULT_FRAMES,
        _import_class, _class_default_frames, _filename_for_scenario, _iter_scenarios,
    )
    from generators.evpn_bgp.config import load_config

    probe_cfg = load_config(config_path)

    jobs = []
    stems = {}  # stem -> (cls_path, sec, section_dir, category)  (for the merge step)
    skipped = []

    for sec, ft, var, cls_path in _iter_scenarios(section=section_filter):
        try:
            Cls = _import_class(cls_path)
            frames = _class_default_frames(Cls, DEFAULT_FRAMES[sec])
        except Exception:
            frames = DEFAULT_FRAMES[sec]

        stem = _filename_for_scenario(ft, var, copy_idx=1)[:-len(".pcap")]

        # Compatibility probe: some scenario classes (e.g. ESDFSingleTogglePE3,
        # RTMisconfigESImportPE6) target a specific PE by id and raise
        # ValueError in __init__ if that PE doesn't exist or isn't multihomed
        # in the given topology -- expected when running the 5PE/2RR config
        # against the full registry (which also has 3RR-only PE3/4/6/7
        # variants) or vice versa. Skip these rather than treating them as
        # generation failures.
        try:
            Cls(config=probe_cfg, target_frames=frames)
        except ValueError as e:
            skipped.append((stem, str(e)))
            continue

        category = ft.replace("-", "_")
        scenario_dir = Path(output_dir) / category / "single" / stem
        stems[stem] = (cls_path, sec, SECTION_DIR_MAP[sec], category)

        for vantage in vantages:
            out_path = scenario_dir / f"{vantage.lower()}.pcap"
            seed = _scenario_seed(global_seed, cls_path, copy_idx=1)
            jobs.append((cls_path, str(out_path), str(config_path), frames, sec, seed,
                         global_seed, vantage))

    return jobs, stems, skipped


def _format_time(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    return f"{seconds/60:.1f}m"


# ---------------------------------------------------------------------------
# Merge step -- one metadata.json per scenario, run after all pcaps exist
# ---------------------------------------------------------------------------

def _parse_pe_set(device_str):
    """'PE3, PE4' / 'PE3,PE4' / 'PE3' -> {'PE3','PE4'}, order/spacing-independent."""
    if not device_str:
        return set()
    return {p.strip().upper() for p in device_str.split(",") if p.strip()}


def _merge_ground_truth(output_dir, stems, vantages, topology_id):
    from scripts.generate_json import (CATALOGUE, count_pcap_stats, _affected_link_ids,
                                        TOPOLOGY_ID_2RR, TOPOLOGY_ID_3RR)

    def _resolve_by_topology(value):
        """CATALOGUE fields can be a plain value (shared across both
        topologies) or a {topology_id: value} dict built by
        generate_json.py's _by_topology(), for entries whose real value
        differs per topology. Resolved using the real topology_id this
        run was invoked with."""
        if isinstance(value, dict) and (TOPOLOGY_ID_2RR in value or TOPOLOGY_ID_3RR in value):
            if topology_id not in value:
                raise KeyError(
                    f"CATALOGUE field is topology-branched ({sorted(value.keys())}) "
                    f"but has no entry for topology_id={topology_id!r} -- add one, "
                    f"don't guess a fallback."
                )
            return value[topology_id]
        return value

    mismatches = []
    missing_catalogue = []
    # Cross-check: CATALOGUE's affected_device / topology.esi are static
    # guesses written by hand; BaseScenario.write() serializes the
    # generator's own real PE/ESI identity per instance (see base.py's
    # generator_identity comment). Compares every stem's real identity
    # against its catalogue guess and fails loudly on any mismatch.
    identity_mismatches = []

    for stem, (cls_path, sec, section_dir, category) in sorted(stems.items()):
        scenario_dir = Path(output_dir) / category / "single" / stem
        per_vantage = {}
        start_times = {}
        generator_identity = None

        for vantage in vantages:
            pcap_path = scenario_dir / f"{vantage.lower()}.pcap"
            sidecar = pcap_path.with_suffix(".json")
            fault_window = None
            if sidecar.exists():
                with open(sidecar, encoding="utf-8") as f:
                    payload = json.load(f)
                fault_window = payload.get("fault_window")
                start_times[vantage] = payload.get("_start_time")
                if generator_identity is None:
                    generator_identity = payload.get("generator_identity")
                sidecar.unlink()

            per_vantage[vantage.lower()] = {
                "fault_window": fault_window,
                "frame_counts": count_pcap_stats(pcap_path) if pcap_path.exists() else None,
            }

        vantage_start_times = [start_times[v] for v in vantages if start_times.get(v) is not None]
        if len(vantage_start_times) == len(vantages) and len(set(vantage_start_times)) > 1:
            mismatches.append((stem, dict(start_times)))

        meta = CATALOGUE.get((section_dir, stem))
        if meta is None:
            missing_catalogue.append(f"{section_dir}/{stem}")
            static_fields = {}
        else:
            affected_dev = _resolve_by_topology(meta.get("affected_device", ""))
            resolved_topology = _resolve_by_topology(meta.get("topology"))
            static_fields = {
                "section": meta.get("section"),
                "fault_type": meta.get("fault_type"),
                "ground_truth_label": meta.get("ground_truth_label"),
                "fault_description": meta.get("fault_description"),
                "affected_device": affected_dev,
                "affected_link_ids": _affected_link_ids(affected_dev) if affected_dev else [],
                "recovery": meta.get("recovery"),
                "recovery_time_seconds": meta.get("recovery_time_seconds"),
                "description": meta.get("description"),
                "base_variant": meta.get("base_variant"),
                "expected_bgp_events": meta.get("expected_bgp_events", []),
                "topology": resolved_topology,
                "notes": meta.get("notes"),
            }
            static_fields = {k: v for k, v in static_fields.items() if v is not None}

            # Cross-check: real generator identity vs catalogue's static guess.
            if generator_identity:
                real_pe_set = set()
                if generator_identity.get("pe_pair"):
                    real_pe_set = {p.upper() for p in generator_identity["pe_pair"]}
                elif generator_identity.get("affected_pe_id"):
                    real_pe_set = {generator_identity["affected_pe_id"].upper()}

                catalogue_pe_set = _parse_pe_set(affected_dev)
                if real_pe_set and catalogue_pe_set and real_pe_set != catalogue_pe_set:
                    line = (f"MISMATCH: {stem} catalogue says affected_device={sorted(catalogue_pe_set)} "
                            f"but generator targeted {sorted(real_pe_set)}")
                    print(line)
                    identity_mismatches.append(line)

                real_esi = generator_identity.get("esi")
                catalogue_esi = (resolved_topology or {}).get("esi")
                if real_esi and catalogue_esi and real_esi.lower() != catalogue_esi.lower():
                    line = (f"MISMATCH: {stem} catalogue says topology.esi={catalogue_esi!r} "
                            f"but generator targeted esi={real_esi!r}")
                    print(line)
                    identity_mismatches.append(line)

        ground_truth = {
            "scenario_stem": stem,
            **static_fields,
            "fault_window": {v.lower(): per_vantage[v.lower()]["fault_window"] for v in vantages},
            "frame_counts": {v.lower(): per_vantage[v.lower()]["frame_counts"] for v in vantages},
        }

        # Omit metadata.json entirely for Normal/baseline captures.
        if meta is not None and meta.get("fault_type") == "Normal":
            continue

        with open(scenario_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(ground_truth, f, indent=2)

    if identity_mismatches:
        summary = "\n".join(identity_mismatches)
        raise RuntimeError(
            f"generator-identity cross-check found {len(identity_mismatches)} "
            f"mismatch(es) between CATALOGUE's static guess and the real "
            f"generator output -- metadata.json was still written for every "
            f"stem using CATALOGUE's (unverified) values, same as before this "
            f"check existed, so nothing was silently dropped, but this run "
            f"must not be treated as clean:\n{summary}"
        )

    return mismatches, missing_catalogue


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", "-c", required=True, help="Path to topology YAML config.")
    parser.add_argument("--output", "-o", required=True, help="Output directory (folder-per-scenario).")
    parser.add_argument("--workers", "-w", type=int, default=os.cpu_count(),
                        help=f"Parallel worker processes (default: {os.cpu_count()}).")
    parser.add_argument("--section", "-s", type=int, default=None, help="Only generate one section.")
    parser.add_argument("--seed", type=int, default=42, help="Global RNG seed (default: 42).")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        print(f"ERROR: Config not found: {config_path}")
        sys.exit(1)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from generators.evpn_bgp.config import load_config
    vantages = tuple(rr.id for rr in load_config(config_path).route_reflectors)
    if not vantages:
        print(f"ERROR: no RR nodes found in {config_path}")
        sys.exit(1)

    print("Building job list...", flush=True)
    jobs, stems, skipped = _build_jobs(config_path, output_dir, global_seed=args.seed,
                                       vantages=vantages, section_filter=args.section)

    total = len(jobs)
    print(f"  Scenarios : {len(stems)}  ({len(skipped)} skipped as N/A for this topology)")
    print(f"  Vantages  : {', '.join(vantages)}")
    print(f"  Jobs      : {total} ({len(vantages)} vantage(s) each)")
    print(f"  Workers   : {args.workers}")
    print(f"  Seed      : {args.seed}\n")
    if skipped:
        for stem, reason in skipped:
            print(f"  [SKIP] {stem}: {reason}")
        print()

    t_start = time.time()
    done = 0
    errors = []

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_generate_one, job): job for job in jobs}
        for future in as_completed(futures):
            out_path_str, start_time_val, n_frames, err = future.result()
            done += 1
            rel = Path(out_path_str).relative_to(output_dir)
            if err:
                errors.append((out_path_str, err))
                print(f"  [FAIL {done:>3}/{total}] {rel}\n    ERROR: {err}", flush=True)
            else:
                # Stash start_time into the .json sidecar base.py already wrote, so the
                # merge step (a separate process invocation) can compare RR1 vs RR2.
                sidecar = Path(out_path_str).with_suffix(".json")
                payload = {}
                if sidecar.exists():
                    with open(sidecar, encoding="utf-8") as f:
                        payload = json.load(f)
                payload["_start_time"] = start_time_val
                with open(sidecar, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                print(f"  [OK   {done:>3}/{total}] {rel}  ({n_frames:,} frames)", flush=True)

    elapsed = time.time() - t_start
    print(f"\nGenerated {done - len(errors)}/{total} pcap(s) in {_format_time(elapsed)}")
    if errors:
        print(f"\n{len(errors)} FAILED:")
        for path, err in errors:
            print(f"  {path}: {err}")
        print("\nSkipping metadata.json merge due to errors.")
        return 1

    print("\nMerging per-vantage metadata.json files...")
    # topology_id matches generate_json.py's TOPOLOGY_ID_2RR/TOPOLOGY_ID_3RR
    # constants exactly (both derived the same way: Path(config).stem) --
    # this is how _resolve_by_topology() picks the right branch for any
    # CATALOGUE field built with _by_topology().
    topology_id = config_path.stem
    mismatches, missing_catalogue = _merge_ground_truth(output_dir, stems, vantages, topology_id)

    if mismatches:
        print(f"\n[FAIL] {len(mismatches)} scenario(s) had a start_time mismatch between vantages:")
        for stem, times in mismatches:
            print(f"  {stem}: {times}")
    else:
        print(f"[OK] start_time identical across all {len(vantages)} vantage(s) for all {len(stems)} scenarios.")

    if missing_catalogue:
        print(f"\n[WARN] {len(missing_catalogue)} scenario(s) not in generate_json.CATALOGUE "
              f"(metadata.json will lack static fields):")
        for m in missing_catalogue:
            print(f"  {m}")

    total_elapsed = time.time() - t_start
    print(f"\nAll done in {_format_time(total_elapsed)}.")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
