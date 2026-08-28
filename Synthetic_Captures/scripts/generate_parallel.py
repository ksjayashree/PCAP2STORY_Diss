"""Parallel pcap generator — runs all 165 scenarios concurrently.

Uses one worker process per scenario variant. Default workers = CPU count.
Each worker is isolated (separate Python process), so no memory conflicts.

Seeding matches the CLI exactly: each scenario uses
    MD5(f"{global_seed}:{cls_path}:1") % 2^31
so --seed 42 here produces byte-identical output to `cli.py --seed 42 --all`.

Usage:
    python scripts/generate_parallel.py --config configs/default_topology.yaml --output output/
    python scripts/generate_parallel.py --config configs/default_topology.yaml --output output/ --workers 4
    python scripts/generate_parallel.py --config configs/default_topology.yaml --output output/ --section 2
    python scripts/generate_parallel.py --config configs/default_topology.yaml --output output/ --no-metadata
    python scripts/generate_parallel.py --config configs/default_topology.yaml --output output/ --seed 42

Estimated times (8 CPU cores, measured on this machine):
    Sequential:            ~68 min
    --workers 4 (by sec):  ~23 min
    --workers 8 (default): ~10 min
    --workers 16:          ~6 min
"""

import argparse
import hashlib
import os
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# ---------------------------------------------------------------------------
# Worker — runs in a separate process, no shared state
# ---------------------------------------------------------------------------

def _scenario_seed(global_seed: int, cls_path: str, copy_idx: int) -> int:
    """MD5-based per-scenario seed — identical to cli.py's implementation."""
    key = f"{global_seed}:{cls_path}:{copy_idx}"
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % (2**31)


def _generate_one(args):
    """Generate a single pcap. Runs inside a worker process."""
    (cls_path, output_path_str, config_path_str, target_frames, section_num, seed, global_seed,
     copy_idx, capture_vantage) = args
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from generators.evpn_bgp.config import load_config
        from generators.evpn_bgp.cli import _import_class

        import random
        import warnings
        random.seed(seed)

        # Suppress the expected "did not set _fault_start_t" notice for scenarios
        # that intentionally have no fault window (normal traffic, rt_misconfig,
        # planned maintenance, eval scenarios). Real bugs (start set but end missing)
        # still surface via the separate _fault_end_t warning, which is NOT suppressed.
        warnings.filterwarnings(
            'ignore',
            message=r'.*did not set _fault_start_t.*',
            category=UserWarning,
        )

        config_path = Path(config_path_str)
        output_path = Path(output_path_str)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cfg = load_config(config_path)
        if capture_vantage:
            cfg.capture_vantage = capture_vantage
        Cls = _import_class(cls_path)
        scenario = Cls(config=cfg, target_frames=target_frames)
        n = scenario.write(output_path, section=section_num, seed=global_seed, copy_idx=copy_idx)
        return output_path_str, n, None  # path, frames_written, error
    except Exception as e:
        return output_path_str, 0, str(e)


# ---------------------------------------------------------------------------
# Build job list from SCENARIO_REGISTRY
# ---------------------------------------------------------------------------

def _build_jobs(config_path, output_dir, global_seed, section_filter=None, capture_vantage=None):
    """Return list of (cls_path, output_path, config_path, target_frames, section, seed,
    global_seed, copy_idx, capture_vantage) tuples."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from generators.evpn_bgp.cli import (
        SCENARIO_REGISTRY, SECTION_DIR_MAP,
        _import_class, _class_default_frames,
        DEFAULT_FRAMES, _filename_for_scenario,
    )

    jobs = []
    for sec, faults in sorted(SCENARIO_REGISTRY.items()):
        if section_filter and sec != section_filter:
            continue
        section_dir = Path(output_dir) / SECTION_DIR_MAP[sec]
        for ft, variants in sorted(faults.items()):
            for var, cls_path in sorted(variants.items(), key=lambda x: x[0] or ""):
                try:
                    Cls = _import_class(cls_path)
                    frames = _class_default_frames(Cls, DEFAULT_FRAMES[sec])
                except Exception:
                    frames = DEFAULT_FRAMES[sec]

                filename = _filename_for_scenario(ft, var, copy_idx=1)
                output_path = section_dir / filename
                seed = _scenario_seed(global_seed, cls_path, copy_idx=1)
                jobs.append((cls_path, str(output_path), str(config_path), frames, sec, seed,
                             global_seed, 1, capture_vantage))

    return jobs


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------

def _format_time(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    return f"{seconds/60:.1f}m"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate all synthcap pcap files in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", "-c", required=True,
                        help="Path to topology YAML config.")
    parser.add_argument("--output", "-o", required=True,
                        help="Output directory for pcap files.")
    parser.add_argument("--workers", "-w", type=int, default=os.cpu_count(),
                        help=f"Parallel worker processes (default: {os.cpu_count()} = CPU count).")
    parser.add_argument("--section", "-s", type=int, default=None,
                        help="Only generate one section (1, 2, 3, or 4).")
    parser.add_argument("--no-metadata", action="store_true",
                        help="Skip metadata xlsx and JSON sidecar generation.")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip pcap files that already exist on disk.")
    parser.add_argument("--seed", type=int, default=42,
                        help="Global RNG seed (default: 42). Matches cli.py --seed.")
    parser.add_argument("--capture-vantage", type=str, default=None,
                        help="Override the config file's capture_vantage (e.g. RR1, RR2) "
                             "for this run, without needing a separate topology YAML.")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    output_dir = Path(args.output).resolve()

    if not config_path.exists():
        print(f"ERROR: Config not found: {config_path}")
        sys.exit(1)

    # Build job list
    print("Building job list...", flush=True)
    jobs = _build_jobs(config_path, output_dir, global_seed=args.seed,
                       section_filter=args.section, capture_vantage=args.capture_vantage)

    if args.skip_existing:
        before = len(jobs)
        jobs = [j for j in jobs if not Path(j[1]).exists()]
        skipped = before - len(jobs)
        if skipped:
            print(f"  Skipping {skipped} already-existing file(s).")

    total = len(jobs)
    if total == 0:
        print("Nothing to generate.")
        sys.exit(0)

    # Estimate time
    total_frames = sum(j[3] for j in jobs)
    avg_rate = 1000  # frames/sec conservative estimate
    est_seq = total_frames / avg_rate
    est_par = est_seq / min(args.workers, total)
    print(f"\n  Jobs     : {total}")
    print(f"  Frames   : {total_frames:,}")
    print(f"  Workers  : {args.workers}")
    print(f"  Seed     : {args.seed}")
    print(f"  Est. time: ~{_format_time(est_par)} (parallel)  "
          f"vs ~{_format_time(est_seq)} (sequential)")
    print()

    # Run parallel generation
    t_start = time.time()
    done = 0
    errors = []

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_generate_one, job): job for job in jobs}

        for future in as_completed(futures):
            output_path_str, n_frames, err = future.result()
            done += 1
            rel = Path(output_path_str).relative_to(output_dir)
            if err:
                errors.append((output_path_str, err))
                status = f"  [FAIL {done:>3}/{total}] {rel}"
                print(f"{status}\n    ERROR: {err}", flush=True)
            else:
                status = f"  [OK   {done:>3}/{total}] {rel}  ({n_frames:,} frames)"
                print(status, flush=True)

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"Generated {done - len(errors)}/{total} files in {_format_time(elapsed)}")
    if errors:
        print(f"\n{len(errors)} FAILED:")
        for path, err in errors:
            print(f"  {path}: {err}")

    if args.no_metadata or errors:
        if errors:
            print("\nSkipping metadata due to errors.")
        return

    # Metadata: xlsx
    print(f"\nGenerating dataset_metadata.xlsx...")
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from generators.evpn_bgp.metadata import generate_default_metadata
        from generators.evpn_bgp.config import load_config
        cfg = load_config(config_path)
        if args.capture_vantage:
            cfg.capture_vantage = args.capture_vantage
        writer = generate_default_metadata(cfg, output_dir)
        meta_path = writer.write()
        print(f"  Written: {meta_path}")
    except Exception as e:
        print(f"  WARN: xlsx failed: {e}")

    # Metadata: JSON sidecars (reads actual frame counts from each pcap)
    print(f"\nGenerating JSON sidecar files...")
    try:
        from scripts.generate_json import write_json
        write_json(output_dir)
    except ImportError:
        # Try direct path import
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "generate_json",
            Path(__file__).parent / "generate_json.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.write_json(output_dir)

    total_elapsed = time.time() - t_start
    print(f"\nAll done in {_format_time(total_elapsed)}.")


if __name__ == "__main__":
    main()
