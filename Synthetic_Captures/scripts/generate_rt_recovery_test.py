#!/usr/bin/env python3
"""Generate the RT-misconfig-with-recovery TEST instances.

Generates a fresh instance of each RTMisconfigWithRecovery* class using a
TEST seed distinct from the TRAIN seed used in Section 2, and writes it
into ``section3_mixed/``. This gives the RT-misconfig-with-recovery fault
a standalone test-set capture that differs byte-for-byte from its
Section-2 train instance, without duplicating the scenario class itself
across the train/test boundary.

Usage
-----
    # 1. Train instances (Section 2) -- generated with TRAIN_SEED:
    python -m generators.evpn_bgp.cli -c configs/default_topology.yaml \
        -o output -f rt-misconfig -v recovery-pe1 --seed 1001
    #    (repeat for recovery-pe2, recovery-pe4)

    # 2. Test instances (Section 3) -- generated here with TEST_SEED:
    python scripts/generate_rt_recovery_test.py \
        -c configs/default_topology.yaml -o output

The script asserts that each test pcap differs byte-for-byte from the
train pcap produced with TRAIN_SEED, guaranteeing the boundary holds at
the instance level.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

# Fixed seeds so both sides are reproducible. Keep these distinct.
TRAIN_SEED = 1001
TEST_SEED = 2002

# RTMisconfigWithRecovery classes and their PE label (the recovery fault).
RECOVERY_CLASSES = {
    "pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE1",
    "pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE2",
    "pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE4",
}

TARGET_FRAMES = 8000  # Section 3 default; recovery scenarios use 8000.
TEST_DIR = "section3_mixed"
TRAIN_DIR = "section2_labelled"


def _import_class(path: str):
    module_path, _, cls_name = path.rpartition(".")
    import importlib
    module = importlib.import_module(module_path)
    return getattr(module, cls_name)


def _generate(cls_path: str, config, out_path: Path, seed: int) -> int:
    """Seed the RNG and write a single scenario pcap. Returns packet count."""
    random.seed(seed)
    ScenarioClass = _import_class(cls_path)
    scenario = ScenarioClass(config=config, target_frames=TARGET_FRAMES)
    return scenario.write(out_path, seed=seed, copy_idx=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-c", "--config", required=True, help="Topology YAML config.")
    parser.add_argument("-o", "--output", required=True, help="Dataset root output dir.")
    args = parser.parse_args()

    # Allow running as a module or a script.
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from generators.evpn_bgp.config import load_config

    config = load_config(args.config)
    output_dir = Path(args.output)
    test_dir = output_dir / TEST_DIR
    test_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating RT-misconfig-recovery TEST instances "
          f"(seed {TEST_SEED}) into {test_dir}/")

    import tempfile
    failures = 0
    for pe, cls_path in RECOVERY_CLASSES.items():
        test_path = test_dir / f"rt_misconfig_recovery_{pe}_test.pcap"
        n = _generate(cls_path, config, test_path, TEST_SEED)
        print(f"  -> {test_path.relative_to(output_dir)} ({n} packets)")

        # Verify the test instance differs from the TRAIN instance.
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=True) as tf:
            train_path = Path(tf.name)
            _generate(cls_path, config, train_path, TRAIN_SEED)
            if train_path.read_bytes() == test_path.read_bytes():
                print(f"     [FAIL] test instance is identical to the train "
                      f"instance for {pe}!", file=sys.stderr)
                failures += 1
            else:
                print(f"     [OK] differs from train instance (seed {TRAIN_SEED}).")

    if failures:
        print(f"\n{failures} instance(s) did not differ from train -- "
              f"boundary NOT satisfied.", file=sys.stderr)
        return 1
    print(f"\nDone. Train instances belong in {TRAIN_DIR}/ (seed {TRAIN_SEED}); "
          f"test instances written to {TEST_DIR}/ (seed {TEST_SEED}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
