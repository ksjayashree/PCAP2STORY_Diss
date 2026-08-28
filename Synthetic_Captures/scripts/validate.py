#!/usr/bin/env python3
"""Validate generated EVPN/BGP pcap files.

Usage:
    python scripts/validate.py output/
    python scripts/validate.py output/section2_labelled/link_down_fast_recovery_001.pcap
    python scripts/validate.py output/ --verbose
    python scripts/validate.py output/ --tshark-path /usr/bin/tshark
"""

import argparse
import subprocess
import sys
import json
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ValidationResult:
    file: str
    passed: bool
    checks: dict[str, bool]
    errors: list[str]
    warnings: list[str]
    stats: dict[str, any]


def find_tshark() -> str:
    """Find tshark binary."""
    # Try common locations
    for path in ['/usr/bin/tshark', '/usr/local/bin/tshark']:
        if Path(path).exists():
            return path
    # Try PATH
    result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def validate_pcap(pcap_path: Path, tshark_path: str = None,
                  target_frames: int = 8000, verbose: bool = False) -> ValidationResult:
    """Validate a single pcap file."""
    errors = []
    warnings = []
    checks = {}
    stats = {}

    # Check 1: File exists and is non-empty
    checks['file_exists'] = pcap_path.exists() and pcap_path.stat().st_size > 0
    if not checks['file_exists']:
        return ValidationResult(str(pcap_path), False, checks,
                               ["File does not exist or is empty"], [], {})

    stats['file_size_kb'] = pcap_path.stat().st_size / 1024

    # Check 2: tshark can decode it (if available)
    tshark = tshark_path or find_tshark()
    msg_types = set()
    if tshark:
        # Count total frames
        result = subprocess.run(
            [tshark, '-r', str(pcap_path), '-T', 'fields', '-e', 'frame.number'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            checks['tshark_decode'] = False
            errors.append(f"tshark decode failed: {result.stderr[:200]}")
        else:
            checks['tshark_decode'] = True
            total_frames = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            stats['total_frames'] = total_frames

        # Count BGP frames
        result = subprocess.run(
            [tshark, '-r', str(pcap_path), '-Y', 'bgp', '-T', 'fields', '-e', 'frame.number'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            bgp_frames = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            stats['bgp_frames'] = bgp_frames

            # Check total frame count is reasonable (includes TCP ACKs).
            # A low ratio is expected for no-recovery scenarios where the
            # session terminates early; warn but do not fail.
            ratio = total_frames / target_frames if target_frames > 0 else 0
            checks['frame_count_reasonable'] = ratio <= 2.0
            if ratio < 0.5:
                warnings.append(f"Total frame count {total_frames} vs target {target_frames} (ratio={ratio:.2f}) — possible early termination")
            elif not checks['frame_count_reasonable']:
                warnings.append(f"Total frame count {total_frames} vs target {target_frames} (ratio={ratio:.2f})")

        # Check BGP message types present
        result = subprocess.run(
            [tshark, '-r', str(pcap_path), '-Y', 'bgp', '-T', 'fields', '-e', 'bgp.type'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            msg_types = set(result.stdout.strip().split('\n'))
            stats['bgp_msg_types'] = list(msg_types)
            # At minimum we expect OPEN (1) and KEEPALIVE (4)
            checks['has_open'] = '1' in msg_types
            checks['has_keepalive'] = '4' in msg_types
            if not checks['has_open']:
                errors.append("No BGP OPEN messages found")
            if not checks['has_keepalive']:
                errors.append("No BGP KEEPALIVE messages found")

        # Check for EVPN routes (if UPDATE messages present)
        if '2' in msg_types:  # UPDATE present
            result = subprocess.run(
                [tshark, '-r', str(pcap_path),
                 '-Y', 'bgp.update.path_attribute.mp_reach_nlri',
                 '-T', 'fields', '-e', 'bgp.evpn.nlri.rt'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                evpn_types = set(result.stdout.strip().replace(',', '\n').split('\n'))
                stats['evpn_route_types'] = list(evpn_types)
                checks['has_evpn_routes'] = len(evpn_types) > 0
            else:
                checks['has_evpn_routes'] = False
                warnings.append("No EVPN routes found in UPDATE messages")

        # Check timestamps are monotonic
        result = subprocess.run(
            [tshark, '-r', str(pcap_path), '-T', 'fields', '-e', 'frame.time_epoch'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            timestamps = [float(t) for t in result.stdout.strip().split('\n') if t]
            checks['timestamps_monotonic'] = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
            if timestamps:
                stats['duration_seconds'] = timestamps[-1] - timestamps[0]
                stats['first_timestamp'] = timestamps[0]
                stats['last_timestamp'] = timestamps[-1]
            if not checks['timestamps_monotonic']:
                errors.append("Timestamps are not monotonically increasing")
    else:
        warnings.append("tshark not found — skipping decode validation")
        checks['tshark_decode'] = None

    # Check 3: File is proper pcap (try reading with scapy)
    try:
        from scapy.all import rdpcap, CookedLinuxV2
        # Just read first few packets
        pkts = rdpcap(str(pcap_path), count=10)
        checks['scapy_readable'] = len(pkts) > 0
        # Check link layer
        if pkts:
            first_pkt = pkts[0]
            checks['correct_link_type'] = first_pkt.haslayer(CookedLinuxV2)
            if not checks['correct_link_type']:
                errors.append("Wrong link type: expected CookedLinuxV2")
    except Exception as e:
        checks['scapy_readable'] = False
        errors.append(f"Scapy read failed: {e}")

    passed = all(v for v in checks.values() if v is not None) and len(errors) == 0
    return ValidationResult(str(pcap_path), passed, checks, errors, warnings, stats)


def validate_directory(dir_path: Path, tshark_path: str = None,
                      verbose: bool = False) -> list[ValidationResult]:
    """Validate all pcap files in a directory (recursive)."""
    results = []
    pcaps = sorted(dir_path.rglob("*.pcap"))

    if not pcaps:
        print(f"No .pcap files found in {dir_path}")
        return results

    print(f"Validating {len(pcaps)} pcap files...")

    for pcap in pcaps:
        # Determine target frames based on section
        if 'section3' in str(pcap):
            target = 5000
        else:
            target = 8000

        result = validate_pcap(pcap, tshark_path, target_frames=target, verbose=verbose)
        results.append(result)

        status = "✓" if result.passed else "✗"
        print(f"  {status} {pcap.name}", end="")
        if verbose and result.stats:
            bgp = result.stats.get('bgp_frames', '?')
            dur = result.stats.get('duration_seconds', '?')
            if isinstance(dur, float):
                dur = f"{dur:.1f}s"
            print(f"  [BGP frames: {bgp}, duration: {dur}]", end="")
        if result.errors:
            print(f"  ERRORS: {'; '.join(result.errors)}", end="")
        if result.warnings and verbose:
            print(f"  WARN: {'; '.join(result.warnings)}", end="")
        print()

    # Summary
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed out of {len(results)} files")
    if failed:
        print(f"\nFailed files:")
        for r in results:
            if not r.passed:
                print(f"  {r.file}: {'; '.join(r.errors)}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Validate synthetic EVPN/BGP pcap files")
    parser.add_argument("path", help="Path to pcap file or directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--tshark-path", help="Path to tshark binary")
    parser.add_argument("--target-frames", type=int, default=8000, help="Target BGP frame count")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()
    path = Path(args.path)

    if path.is_dir():
        results = validate_directory(path, args.tshark_path, args.verbose)
    elif path.is_file():
        result = validate_pcap(path, args.tshark_path, args.target_frames, args.verbose)
        results = [result]
        if not args.json:
            status = "PASSED" if result.passed else "FAILED"
            print(f"{status}: {path}")
            if result.errors:
                for e in result.errors:
                    print(f"  ERROR: {e}")
            if result.warnings:
                for w in result.warnings:
                    print(f"  WARN: {w}")
            if result.stats:
                print(f"  Stats: {result.stats}")
    else:
        print(f"Error: {path} not found")
        sys.exit(1)

    if args.json:
        output = []
        for r in results:
            output.append({
                'file': r.file,
                'passed': r.passed,
                'checks': r.checks,
                'errors': r.errors,
                'warnings': r.warnings,
                'stats': r.stats,
            })
        print(json.dumps(output, indent=2, default=str))

    # Exit with error code if any failed
    if any(not r.passed for r in results):
        sys.exit(1)


if __name__ == '__main__':
    main()
