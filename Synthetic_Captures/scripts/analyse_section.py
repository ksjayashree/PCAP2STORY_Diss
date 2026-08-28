"""Analyse generated pcap files and print a PPT-style breakdown table.

Usage:
    python scripts/analyse_section.py output/section1_normal
    python scripts/analyse_section.py output/section2_labelled
"""
import sys
import struct
from pathlib import Path
from collections import defaultdict

from scapy.all import rdpcap, TCP, Raw


BGP_MARKER = b'\xff' * 16

def count_bgp_in_payload(payload: bytes) -> dict:
    """Walk a TCP payload and count BGP message types."""
    counts = defaultdict(int)
    i = 0
    while i <= len(payload) - 19:
        if payload[i:i+16] == BGP_MARKER:
            if i + 19 <= len(payload):
                msg_len = struct.unpack('!H', payload[i+16:i+18])[0]
                msg_type = payload[i+18]
                if 1 <= msg_type <= 5 and msg_len >= 19:
                    counts[msg_type] += 1
                    i += msg_len
                    continue
        i += 1
    return counts


def count_bgp_messages(pcap_path: Path) -> dict:
    """Return per-type BGP message counts for all packets in a pcap."""
    totals = defaultdict(int)
    pkts = rdpcap(str(pcap_path))
    for pkt in pkts:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            for t, n in count_bgp_in_payload(bytes(pkt[Raw])).items():
                totals[t] += n
    return {'total_frames': len(pkts), 'bgp': dict(totals)}


def analyse_directory(section_dir: Path):
    pcap_files = sorted(section_dir.glob('*.pcap'))
    if not pcap_files:
        print(f"No .pcap files found in {section_dir}")
        return

    rows = []
    for pcap in pcap_files:
        print(f"  analysing {pcap.name}...", flush=True)
        result = count_bgp_messages(pcap)
        bgp = result['bgp']
        rows.append({
            'file': pcap.stem,
            'frames': result['total_frames'],
            'OPEN':         bgp.get(1, 0),
            'UPDATE':       bgp.get(2, 0),
            'NOTIFICATION': bgp.get(3, 0),
            'KEEPALIVE':    bgp.get(4, 0),
            'REFRESH':      bgp.get(5, 0),
        })

    col_w = max(len(r['file']) for r in rows) + 2
    hdr = f"\n{'File':<{col_w}} {'Frames':>10}  {'OPEN':>6}  {'KEEPALIVE':>10}  {'UPDATE':>8}  {'NOTIF':>7}  {'REFRESH':>8}"
    sep = '-' * len(hdr)
    print(hdr)
    print(sep)
    for r in rows:
        print(
            f"{r['file']:<{col_w}} {r['frames']:>10}  {r['OPEN']:>6}  "
            f"{r['KEEPALIVE']:>10}  {r['UPDATE']:>8}  {r['NOTIFICATION']:>7}  {r['REFRESH']:>8}"
        )
    print(sep)
    frames_list = [r['frames'] for r in rows]
    ka_list     = [r['KEEPALIVE'] for r in rows]
    open_list   = [r['OPEN'] for r in rows]
    upd_list    = [r['UPDATE'] for r in rows]
    notif_list  = [r['NOTIFICATION'] for r in rows]
    ref_list    = [r['REFRESH'] for r in rows]

    def rng(lst):
        lo, hi = min(lst), max(lst)
        return f"{lo:,}" if lo == hi else f"{lo:,}–{hi:,}"

    print(f"\n{'Summary (range across files)':<{col_w}}")
    print(f"  Files       : {len(rows)}")
    print(f"  Frames      : {rng(frames_list)}")
    print(f"  OPEN        : {rng(open_list)}")
    print(f"  KEEPALIVE   : {rng(ka_list)}")
    print(f"  UPDATE      : {rng(upd_list)}")
    print(f"  NOTIFICATION: {rng(notif_list)}")
    print(f"  REFRESH     : {rng(ref_list)}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scripts/analyse_section.py <section_dir>")
        sys.exit(1)
    analyse_directory(Path(sys.argv[1]))
