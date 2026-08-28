#!/usr/bin/env python3
"""
===============================================================================
EVPN Wire Verification Tool (`evpn_wire_verify.py`)
===============================================================================
A reusable, standalone CLI and Python module for parsing, filtering, and
decoding BGP EVPN control-plane packet captures via `tshark`.

Parses via `tshark -T pdml` and walks the packet-detail XML tree directly,
rather than `-T fields` with comma-joined multi-value columns -- a single
captured frame can bundle multiple independent BGP UPDATE messages (each its
own sibling `<proto name="bgp">` element in the pdml tree when several PDUs
ride one TCP segment), and each message can itself carry both an
MP_REACH_NLRI (advertisement) and an MP_UNREACH_NLRI (withdrawal/End-of-RIB)
path attribute. Emitting one row per BGP MESSAGE (not one row per captured
frame) is required to classify and decode each route correctly instead of
collapsing several distinct routes into one garbled, mislabeled row.

ORIGIN RESOLUTION:
-------------------
Each event reports two distinct node fields, never collapsed into one:
  - `relaying_node`: the node that put THIS specific copy of the packet on
    the wire, resolved from the frame's own ip.src (an RR when this copy is
    a reflected one, the owning PE itself when not).
  - `origin_pe`: the PE that actually owns/originated the route, resolved
    from the EVPN NLRI's own Route Distinguisher (RD) when the RD encodes an
    IP-address-type administrator matching a known PE's router-id (this
    project's confirmed RD convention: RD = <PE router-id>:<instance>), with
    BGP's own ORIGINATOR_ID path attribute (present only on RR-reflected
    copies) as a second, independent check. A colliding/synthetic RD (e.g.
    RD Collision's AS-type "65000:999") does not encode a PE at all --
    origin_pe is reported as null in that case (never guessed), with
    `origin_note` explaining why, and `relaying_node` still tells you which
    node actually sent this specific copy.

USAGE EXAMPLES:
---------------
1. Single pcap file inspection:
   python3 evpn_wire_verify.py /path/to/rr1.pcap

2. Directory inspection (all pcaps in folder, multi-vantage):
   python3 evpn_wire_verify.py /path/to/scenario_dir/

3. Filtering by specific MAC address and/or Route Distinguisher (RD):
   python3 evpn_wire_verify.py /path/to/scenario_dir/ --mac 02:00:00:00:99:01 --rd 65000:999

4. Formatting output as JSON:
   python3 evpn_wire_verify.py /path/to/scenario_dir/ --format json

5. Explicit topology (auto-detected from the target path by default --
   "pilot_containerlab" or "3rr" substring -- override if needed):
   python3 evpn_wire_verify.py /path/to/scenario_dir/ --topology /path/to/topology.json

REPLACES:
---------
Ad-hoc inline `tshark` one-liners across project investigations. Future
verification steps in both `pilot_containerlab` and `3rr` should invoke this
tool directly.
===============================================================================
"""

import os
import sys
import json
import argparse
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

ROUTE_TYPE_NAMES = {
    "1": "Type-1 (EAD)",
    "2": "Type-2 (MAC/IP)",
    "3": "Type-3 (IMET)",
    "4": "Type-4 (ES)",
    "5": "Type-5 (IP Prefix)",
}

# Default topology.json locations this project actually uses -- matched by
# a substring of the target path, since both datasets share the same 10.0.0.x
# addressing scheme and cannot be told apart from IPs alone.
DEFAULT_TOPOLOGIES = {
    "pilot_containerlab": r"C:\simulation pcap\rule_based detector\config\topology.json",
    "3rr": r"C:\simulation pcap\3rr\config\topology.json",
}


def decode_rd_hex(rd_raw):
    """Decodes a raw hex RD string (tshark's bgp.evpn.nlri.rd `value`
    attribute, no separators) into human-readable form, e.g. 10.0.0.19:2 or
    65000:999. Returns (decoded_str, rd_type) where rd_type is 0 (AS:val,
    2-octet), 1 (IPv4:val), or 2 (AS:val, 4-octet) per RFC 4364."""
    if not rd_raw or len(rd_raw) < 16:
        return rd_raw, None
    try:
        clean = rd_raw.replace(":", "").replace("0x", "")
        type_val = int(clean[0:4], 16)
        if type_val == 0:
            asn = int(clean[4:8], 16)
            val = int(clean[8:16], 16)
            return f"{asn}:{val}", 0
        elif type_val == 1:
            ip_parts = [str(int(clean[i:i + 2], 16)) for i in range(4, 12, 2)]
            val = int(clean[12:16], 16)
            return f"{'.'.join(ip_parts)}:{val}", 1
        elif type_val == 2:
            asn = int(clean[4:12], 16)
            val = int(clean[12:16], 16)
            return f"{asn}:{val}", 2
    except Exception:
        pass
    return rd_raw, None


def load_topology_maps(topo_path):
    """Returns (ip_to_node: {router_id_ip: node_name}, pe_names: set) built
    from topology.json's own nodes list -- both PE and RR entries, since
    `relaying_node` needs to resolve RR loopback IPs too, not just PEs."""
    ip_to_node = {}
    pe_names = set()
    if not topo_path or not os.path.isfile(topo_path):
        return ip_to_node, pe_names
    with open(topo_path) as f:
        topo = json.load(f)
    for node in topo.get("nodes", []):
        rid = node.get("router_id")
        name = node.get("id")
        if rid and name:
            ip_to_node[rid] = name
            if node.get("role") == "PE":
                pe_names.add(name)
    return ip_to_node, pe_names


def autodetect_topology(target_path, explicit_topo):
    if explicit_topo:
        return explicit_topo
    norm = target_path.replace("\\", "/").lower()
    for key, path in DEFAULT_TOPOLOGIES.items():
        if key in norm:
            return path
    return None


def _find(el, name):
    """First direct-or-nested field descendant named `name` under `el`."""
    for f in el.iter("field"):
        if f.get("name") == name:
            return f
    return None


def _findall_direct_path_attrs(bgp_msg_el):
    """All bgp.update.path_attribute children directly under this one BGP
    message's proto element (siblings of each other -- MP_REACH_NLRI,
    MP_UNREACH_NLRI, ORIGINATOR_ID, EXTENDED_COMMUNITIES, etc. are each
    their own top-level path attribute of the SAME message, not nested
    inside one another)."""
    out = []
    for child in bgp_msg_el.iter("field"):
        if child.get("name") == "bgp.update.path_attribute":
            out.append(child)
    return out


def _decode_evpn_nlri_block(nlri_el):
    """Decodes one bgp.evpn.nlri block (found under either MP_REACH_NLRI or
    MP_UNREACH_NLRI) into route_type/rd/mac/esi/etag fields."""
    rt_field = _find(nlri_el, "bgp.evpn.nlri.rt")
    rd_field = _find(nlri_el, "bgp.evpn.nlri.rd")
    mac_field = _find(nlri_el, "bgp.evpn.nlri.mac_addr")
    esi_field = _find(nlri_el, "bgp.evpn.nlri.esi.value")
    etag_field = _find(nlri_el, "bgp.evpn.nlri.etag")

    rt_val = rt_field.get("show") if rt_field is not None else None
    rd_raw = rd_field.get("value") if rd_field is not None else None
    rd_decoded, rd_type = decode_rd_hex(rd_raw) if rd_raw else (None, None)
    mac_val = mac_field.get("show") if mac_field is not None else None
    esi_val = esi_field.get("show") if esi_field is not None else None
    etag_val = etag_field.get("show") if etag_field is not None else None

    return {
        "route_type": ROUTE_TYPE_NAMES.get(rt_val, f"Type-{rt_val}") if rt_val else None,
        "rd_raw": rd_raw,
        "rd_decoded": rd_decoded,
        "rd_type": rd_type,
        "mac": mac_val,
        "esi": esi_val,
        "ethernet_tag": etag_val,
    }


def _has_df_election_community(path_attrs):
    """DF Election Extended Community (RFC 8584): type Transitive EVPN
    (0x06), subtype DF Election (0x06). Extended communities live under
    their own EXTENDED_COMMUNITIES path attribute, a sibling of
    MP_REACH_NLRI within the same message -- searched across ALL of this
    message's path attributes, not just the one carrying the NLRI."""
    for pa in path_attrs:
        for stype in pa.iter("field"):
            if stype.get("name") == "bgp.ext_com.stype_tr_evpn" and "DF Election" in (stype.get("showname") or ""):
                return True
    return False


def resolve_origin(rd_decoded, rd_type, originator_id_ip, ip_to_node, pe_names):
    """Returns (origin_pe, origin_note). Primary signal: RD's own embedded
    IP-address administrator (rd_type==1, this project's confirmed
    RD=<router-id>:<instance> convention) matched against a known PE's
    router-id. Independent cross-check: BGP's own ORIGINATOR_ID attribute,
    present only on RR-reflected copies -- reported when it disagrees with
    the RD-derived answer, since that would itself be worth flagging, not
    silently discarded."""
    origin_from_rd = None
    if rd_type == 1 and rd_decoded:
        ip_part = rd_decoded.rsplit(":", 1)[0]
        node = ip_to_node.get(ip_part)
        if node in pe_names:
            origin_from_rd = node

    origin_from_originator_id = None
    if originator_id_ip:
        node = ip_to_node.get(originator_id_ip)
        if node in pe_names:
            origin_from_originator_id = node

    if origin_from_rd and origin_from_originator_id and origin_from_rd != origin_from_originator_id:
        return origin_from_rd, (
            f"RD-derived origin ({origin_from_rd}) disagrees with ORIGINATOR_ID-derived "
            f"origin ({origin_from_originator_id}) -- reporting RD-derived, flagged for review"
        )
    if origin_from_rd:
        return origin_from_rd, "resolved from RD's IP-address administrator"
    if origin_from_originator_id:
        return origin_from_originator_id, "resolved from BGP ORIGINATOR_ID (RD did not encode a PE)"
    if rd_type == 0 or rd_type == 2:
        return None, "RD is AS-type (not IP-address-type) -- does not encode a PE, no origin resolvable from RD"
    return None, "no PE-identifying RD or ORIGINATOR_ID found on this message"


def run_tshark_pdml(pcap_path, ip_to_node, pe_names):
    """Executes tshark with -T pdml against a single pcap and returns one
    event dict per BGP MESSAGE (not per captured frame) with independently
    resolved origin_pe / relaying_node fields."""
    cmd = ["tshark", "-r", pcap_path, "-Y", "bgp.evpn.nlri.rt or bgp.type==2", "-T", "pdml"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark on {pcap_path}: {e.stderr}", file=sys.stderr)
        return []

    try:
        root = ET.fromstring(res.stdout)
    except ET.ParseError as e:
        print(f"Error parsing tshark pdml output for {pcap_path}: {e}", file=sys.stderr)
        return []

    vantage_name = os.path.basename(pcap_path).replace(".pcap", "")
    events = []

    for pkt in root.findall("packet"):
        frame_proto = next((p for p in pkt.findall("proto") if p.get("name") == "frame"), None)
        ip_proto = next((p for p in pkt.findall("proto") if p.get("name") == "ip"), None)
        if frame_proto is None:
            continue
        ts_field = _find(frame_proto, "frame.time_epoch")
        if ts_field is None:
            continue
        ts_epoch = float(ts_field.get("show"))
        ts_iso = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).isoformat()

        ip_src = _find(ip_proto, "ip.src").get("show") if ip_proto is not None and _find(ip_proto, "ip.src") is not None else None
        ip_dst = _find(ip_proto, "ip.dst").get("show") if ip_proto is not None and _find(ip_proto, "ip.dst") is not None else None
        relaying_node = ip_to_node.get(ip_src, ip_src)
        relaying_dst_node = ip_to_node.get(ip_dst, ip_dst)

        bgp_msgs = [p for p in pkt.findall("proto") if p.get("name") == "bgp"]
        for bgp_msg in bgp_msgs:
            type_field = _find(bgp_msg, "bgp.type")
            if type_field is None or type_field.get("show") != "2":
                continue  # only UPDATE messages carry EVPN NLRI content

            path_attrs = _findall_direct_path_attrs(bgp_msg)

            originator_id_ip = None
            for pa in path_attrs:
                showname = pa.get("showname") or ""
                if "ORIGINATOR_ID" in showname:
                    oid_field = _find(pa, "bgp.update.path_attribute.originator_id")
                    if oid_field is not None:
                        originator_id_ip = oid_field.get("show")

            df_election_present = _has_df_election_community(path_attrs)

            for pa in path_attrs:
                showname = pa.get("showname") or ""
                if "MP_REACH_NLRI" in showname:
                    nlri = _find(pa, "bgp.evpn.nlri")
                    if nlri is None:
                        continue
                    decoded = _decode_evpn_nlri_block(nlri)
                    origin_pe, origin_note = resolve_origin(
                        decoded["rd_decoded"], decoded["rd_type"], originator_id_ip, ip_to_node, pe_names
                    )
                    events.append({
                        "timestamp": ts_iso, "epoch": ts_epoch, "vantage": vantage_name,
                        "classification": "ADVERTISEMENT",
                        "relaying_node": relaying_node, "relaying_dst_node": relaying_dst_node,
                        "ip_src": ip_src, "ip_dst": ip_dst,
                        "origin_pe": origin_pe, "origin_note": origin_note,
                        "originator_id_ip": originator_id_ip,
                        **decoded,
                        "df_election_community": df_election_present,
                    })
                elif "MP_UNREACH_NLRI" in showname:
                    nlri = _find(pa, "bgp.evpn.nlri")
                    if nlri is None:
                        # Empty MP_UNREACH_NLRI (AFI/SAFI only, no NLRI body)
                        # is the standard RFC 4724 End-of-RIB marker for
                        # that AFI/SAFI -- NOT a route withdrawal. Reported
                        # as its own distinct classification, never folded
                        # into WITHDRAWAL.
                        events.append({
                            "timestamp": ts_iso, "epoch": ts_epoch, "vantage": vantage_name,
                            "classification": "END_OF_RIB",
                            "relaying_node": relaying_node, "relaying_dst_node": relaying_dst_node,
                            "ip_src": ip_src, "ip_dst": ip_dst,
                            "origin_pe": None, "origin_note": "End-of-RIB marker carries no NLRI -- no route, no origin",
                            "originator_id_ip": originator_id_ip,
                            "route_type": None, "rd_raw": None, "rd_decoded": None, "rd_type": None,
                            "mac": None, "esi": None, "ethernet_tag": None,
                            "df_election_community": df_election_present,
                        })
                        continue
                    decoded = _decode_evpn_nlri_block(nlri)
                    origin_pe, origin_note = resolve_origin(
                        decoded["rd_decoded"], decoded["rd_type"], originator_id_ip, ip_to_node, pe_names
                    )
                    events.append({
                        "timestamp": ts_iso, "epoch": ts_epoch, "vantage": vantage_name,
                        "classification": "WITHDRAWAL",
                        "relaying_node": relaying_node, "relaying_dst_node": relaying_dst_node,
                        "ip_src": ip_src, "ip_dst": ip_dst,
                        "origin_pe": origin_pe, "origin_note": origin_note,
                        "originator_id_ip": originator_id_ip,
                        **decoded,
                        "df_election_community": df_election_present,
                    })

    return events


def parse_target(target_path, target_mac=None, target_rd=None, topo_path=None):
    """Parses a file or directory of pcaps and applies optional MAC/RD filters."""
    resolved_topo = autodetect_topology(target_path, topo_path)
    ip_to_node, pe_names = load_topology_maps(resolved_topo)
    if not ip_to_node:
        print(f"WARNING: no topology.json resolved/loaded for {target_path} "
              f"-- origin_pe/relaying_node will not resolve to node names, only raw IPs.", file=sys.stderr)

    pcap_files = []
    if os.path.isfile(target_path):
        if target_path.endswith(".pcap"):
            pcap_files.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in sorted(files):
                if f.endswith(".pcap"):
                    pcap_files.append(os.path.join(root, f))

    all_events = []
    for pf in pcap_files:
        all_events.extend(run_tshark_pdml(pf, ip_to_node, pe_names))

    filtered = []
    for ev in all_events:
        if target_mac:
            if not (ev.get("mac") and target_mac.lower() in ev["mac"].lower()):
                continue
        if target_rd:
            rd_hits = [ev.get("rd_decoded") or "", ev.get("rd_raw") or ""]
            if not any(target_rd.lower() in r.lower() for r in rd_hits):
                continue
        filtered.append(ev)

    filtered.sort(key=lambda x: x["epoch"])
    return filtered


def main():
    parser = argparse.ArgumentParser(description="EVPN Wire Verification Tool")
    parser.add_argument("target", help="Path to a .pcap file or directory containing .pcap files")
    parser.add_argument("--mac", help="Filter events by MAC address (e.g. 02:00:00:00:99:01)", default=None)
    parser.add_argument("--rd", help="Filter events by Route Distinguisher (e.g. 65000:999 or 10.0.0.19:2)", default=None)
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--topology", help="Explicit topology.json path (default: auto-detected from target path)", default=None)

    args = parser.parse_args()

    events = parse_target(args.target, target_mac=args.mac, target_rd=args.rd, topo_path=args.topology)

    if args.format == "json":
        print(json.dumps(events, indent=2))
    else:
        print(f"=== EVPN WIRE VERIFICATION REPORT ({len(events)} events matching filter) ===")
        for ev in events:
            origin_str = ev["origin_pe"] or "UNRESOLVED"
            mac_str = ev.get("mac") or "N/A"
            rd_str = ev.get("rd_decoded") or "N/A"
            rt_str = ev.get("route_type") or "N/A"
            df_str = " | DF_COMM: True" if ev.get("df_election_community") else ""
            print(
                f"[{ev['timestamp']}] [{ev['vantage']}] "
                f"relay={ev['relaying_node']}->{ev['relaying_dst_node']} "
                f"origin={origin_str} | {ev['classification']} | RT: {rt_str} | RD: {rd_str} | MAC: {mac_str}{df_str}"
            )


if __name__ == "__main__":
    main()
