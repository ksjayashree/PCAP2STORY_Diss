"""Generate the Category B/C multi-incident scenarios into a separate
output/multiple/ (or output_3rr/multiple/) tree:

    output/multiple/<category_dir>/<scenario_stem>/rr1.pcap
    output/multiple/<category_dir>/<scenario_stem>/rr2.pcap
    output/multiple/<category_dir>/<scenario_stem>/rr3.pcap  (3RR only)
    output/multiple/<category_dir>/<scenario_stem>/metadata.json

Not built on scripts/generate_dual_vantage.py's CATALOGUE/fault_window
machinery, since that path is single-incident-shaped (one fault_start_t/
fault_end_t pair). These scenario classes instead build a self.incidents
list directly (each dict already in the metadata.json schema), which this
driver writes out unmodified alongside multi_incident/category/
causal_relationship.

Usage:
    python scripts/generate_multi_incident.py --config configs/default_topology.yaml --output output
    python scripts/generate_multi_incident.py --config configs/3rr_topology.yaml --output output_3rr
"""
import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from generators.evpn_bgp.config import load_config
from generators.evpn_bgp.scenarios.esdf_toggle import ESDFToggleX2PE1PE2, ESDFToggleX2PE3PE4
from generators.evpn_bgp.scenarios.rt_misconfig import RTMisconfigESImportX2PE1PE2
from generators.evpn_bgp.scenarios.mac_mobility import MACMobilityX2
from generators.evpn_bgp.scenarios.mixed import (
    CatCESDFToggleRTMisconfig, CatCESDFToggleRTMisconfigPE3PE6,
    CatCESDFToggleMACMobility, CatCRTMisconfigMACMobility,
)

# (scenario_stem, category_dir, ScenarioClass, applicable_topology)
# applicable_topology: "5pe2rr", "3rr", or "both"
SCENARIOS = [
    ("esdf_toggle_x2_pe1_pe2", "esdf_toggle_x2", ESDFToggleX2PE1PE2, "5pe2rr"),
    ("esdf_toggle_x2_pe3_pe4", "esdf_toggle_x2", ESDFToggleX2PE3PE4, "3rr"),
    ("rt_misconfig_x2_pe1_pe2", "rt_misconfig_x2", RTMisconfigESImportX2PE1PE2, "5pe2rr"),
    ("catB_mac_mobility_x2", "mac_mobility_x2", MACMobilityX2, "5pe2rr"),
    ("catC_esdf_toggle_rt_misconfig_pe1_pe2", "catC_esdf_toggle_rt_misconfig", CatCESDFToggleRTMisconfig, "5pe2rr"),
    ("catC_esdf_toggle_rt_misconfig_pe3_pe6", "catC_esdf_toggle_rt_misconfig", CatCESDFToggleRTMisconfigPE3PE6, "3rr"),
    ("catC_esdf_toggle_mac_mobility_pe1", "catC_esdf_toggle_mac_mobility", CatCESDFToggleMACMobility, "5pe2rr"),
    ("catC_rt_misconfig_mac_mobility_pe3", "catC_rt_misconfig_mac_mobility", CatCRTMisconfigMACMobility, "3rr"),
]

DEFAULT_FRAMES = {
    ESDFToggleX2PE1PE2: 30000, ESDFToggleX2PE3PE4: 30000,
    RTMisconfigESImportX2PE1PE2: 20000, MACMobilityX2: 8000,
    CatCESDFToggleRTMisconfig: 20000, CatCESDFToggleRTMisconfigPE3PE6: 20000,
    CatCESDFToggleMACMobility: 20000, CatCRTMisconfigMACMobility: 20000,
}


def _scenario_seed(global_seed: int, cls_path: str) -> int:
    key = f"{global_seed}:{cls_path}:multi"
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % (2**31)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", required=True)
    parser.add_argument("--output", "-o", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    output_dir = Path(args.output).resolve()
    is_3rr = "3rr" in config_path.stem

    base_cfg = load_config(config_path)
    vantages = tuple(rr.id for rr in base_cfg.route_reflectors)
    topo_kind = "3rr" if is_3rr else "5pe2rr"

    applicable = [s for s in SCENARIOS if s[3] in (topo_kind, "both")]
    print(f"Topology: {config_path.name} ({topo_kind}, vantages={vantages})")
    print(f"Applicable scenarios: {len(applicable)}\n")

    generated = 0
    failed = []

    for stem, category_dir, Cls, _ in applicable:
        cls_path = f"{Cls.__module__}.{Cls.__qualname__}"
        frames = DEFAULT_FRAMES.get(Cls, 20000)
        scenario_dir = output_dir / "multiple" / category_dir / stem
        scenario_dir.mkdir(parents=True, exist_ok=True)

        incidents_by_vantage = {}
        category = "C" if Cls.__name__.startswith("CatC") else "B"
        ok = True

        for vantage in vantages:
            try:
                cfg = load_config(config_path)
                cfg.capture_vantage = vantage
                seed = _scenario_seed(args.seed, cls_path)
                random.seed(seed)

                scenario = Cls(config=cfg, target_frames=frames)
                out_path = scenario_dir / f"{vantage.lower()}.pcap"
                scenario.write(out_path, seed=args.seed, copy_idx=1, write_csv_sidecar=False)
                incidents_by_vantage[vantage] = getattr(scenario, "incidents", [])
                print(f"  [OK] {stem}/{vantage.lower()}.pcap ({len(scenario.packets)} frames, "
                      f"{len(incidents_by_vantage[vantage])} incidents)")
            except Exception as e:
                print(f"  [FAIL] {stem}/{vantage.lower()}.pcap: {e}")
                ok = False
                failed.append((stem, vantage, str(e)))

        if not ok:
            continue

        # metadata.json should describe what genuinely happened in the
        # capture, not what one particular vantage happened to see -- a
        # vantage that isn't every involved PE's home RR can miss an
        # incident entirely. Use the vantage with the most incidents
        # recorded (the most complete view) as ground truth.
        vantage_list = list(incidents_by_vantage.keys())
        primary_vantage = max(vantage_list, key=lambda v: len(incidents_by_vantage[v]))
        primary_incidents = incidents_by_vantage[primary_vantage]
        mismatch = any(incidents_by_vantage[v] != primary_incidents for v in vantage_list)
        if mismatch:
            print(f"  [WARN] {stem}: incidents differ across vantages (expected for mac_mobility's "
                  f"known cross-RR reflection gap, or normal per-vantage reflection-delay timestamp "
                  f"drift) -- using {primary_vantage}'s view ({len(primary_incidents)} incidents) as ground truth")

        causal = None
        for s_stem, s_cat, s_cls, _ in applicable:
            if s_stem == stem:
                causal = getattr(s_cls, "CAUSAL_RELATIONSHIP", None)
                break

        meta = {
            "multi_incident": True,
            "category": category,
            "incidents": primary_incidents,
        }
        if category == "B":
            meta["fault_type"] = primary_incidents[0]["fault_type"] if primary_incidents else None
        if causal:
            meta["causal_relationship"] = causal

        with open(scenario_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        generated += 1
        print(f"  -> {scenario_dir.relative_to(output_dir)}/metadata.json ({len(primary_incidents)} incidents)\n")

    print(f"\nGenerated {generated}/{len(applicable)} scenario(s).")
    if failed:
        print(f"{len(failed)} FAILED:")
        for stem, vantage, err in failed:
            print(f"  {stem}/{vantage}: {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
