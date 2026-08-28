"""tshark integration — decode PCAPs to JSON and field discovery."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Duplicate-key-aware JSON parser
# ---------------------------------------------------------------------------

def _dup_hook(pairs: list[tuple[str, Any]]) -> dict:
    """``object_pairs_hook`` that collects duplicate JSON keys into lists."""
    d: dict = {}
    for key, value in pairs:
        if key in d:
            if not isinstance(d[key], list):
                d[key] = [d[key]]
            d[key].append(value)
        else:
            d[key] = value
    return d


def _json_loads_dup(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_dup_hook)


# ---------------------------------------------------------------------------
# Recursive field finder — works on any nesting depth
# ---------------------------------------------------------------------------

def find_all_by_key(obj: Any, target_key: str) -> list[Any]:
    """Return every value whose *immediate* dict key is *target_key*."""
    results: list[Any] = []
    _walk_find(obj, target_key, results)
    return results


def _walk_find(obj: Any, target: str, acc: list) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == target:
                acc.append(v)
            _walk_find(v, target, acc)
    elif isinstance(obj, list):
        for item in obj:
            _walk_find(item, target, acc)


def _scalar(obj: Any, key: str, default: str = "") -> str:
    """Return the first scalar value for *key* found anywhere in *obj*."""
    vals = find_all_by_key(obj, key)
    for v in vals:
        if isinstance(v, str):
            return v
        if isinstance(v, list) and v:
            return str(v[0])
    return default


# ---------------------------------------------------------------------------
# Packet normalisation
# ---------------------------------------------------------------------------

def normalize_packets(raw_packets: list[dict]) -> list[dict]:
    """Turn raw tshark ``-T json`` output into a flat list suitable for
    the extraction layer.

    Each returned dict has the ``_source.layers`` structure that the rest of
    the code expects, but the ``layers`` dict contains *flat* keys
    (e.g. ``"bgp.type"``, ``"bgp.evpn.nlri.rt"``) so the extraction code
    doesn't need to know about tshark nesting.

    A single input frame may produce *multiple* output dicts when the TCP
    segment carries several BGP messages or when a single UPDATE carries
    multiple EVPN NLRIs.
    """
    out: list[dict] = []
    for pkt in raw_packets:
        layers = pkt.get("_source", {}).get("layers", {})

        # ---- frame-level metadata (always nested under "frame", "ip", "tcp")
        frame_meta = _extract_frame_meta(layers)

        # ---- BGP messages
        bgp_raw = layers.get("bgp")
        if bgp_raw is None:
            # Non-BGP packet — emit one record with frame metadata only
            out.append({"_source": {"layers": dict(frame_meta)}})
            continue

        bgp_msgs = bgp_raw if isinstance(bgp_raw, list) else [bgp_raw]
        for bgp_msg in bgp_msgs:
            flats = _flatten_bgp_multi(bgp_msg, frame_meta)
            for flat in flats:
                out.append({"_source": {"layers": flat}})

    return out


def _extract_frame_meta(layers: dict) -> dict[str, str]:
    """Pull frame / IP / TCP metadata from the nested layers."""
    meta: dict[str, str] = {}
    frame = layers.get("frame", {})
    if isinstance(frame, dict):
        meta["frame.number"] = frame.get("frame.number", "")
        meta["frame.time_epoch"] = frame.get("frame.time_epoch", "")

    # IP layer — may be a dict (single) or list (GRE / tunnelled: outer + inner).
    # When there are two, the *last* dict typically carries the inner (BGP peer) IPs.
    ip_raw = layers.get("ip")
    if isinstance(ip_raw, list):
        # Take the last IP layer (inner / closest to BGP)
        for ip_item in reversed(ip_raw):
            if isinstance(ip_item, dict) and ip_item.get("ip.src"):
                meta["ip.src"] = ip_item.get("ip.src", "")
                meta["ip.dst"] = ip_item.get("ip.dst", "")
                break
    elif isinstance(ip_raw, dict):
        meta["ip.src"] = ip_raw.get("ip.src", "")
        meta["ip.dst"] = ip_raw.get("ip.dst", "")

    # Fall back to IPv6 if IPv4 addresses are absent
    if not meta.get("ip.src"):
        ipv6 = layers.get("ipv6", {})
        if isinstance(ipv6, dict):
            meta["ip.src"] = ipv6.get("ipv6.src", "")
            meta["ip.dst"] = ipv6.get("ipv6.dst", "")

    tcp = layers.get("tcp", {})
    if isinstance(tcp, dict):
        meta["tcp.stream"] = tcp.get("tcp.stream", "")
    return meta


def _flatten_bgp_multi(bgp_msg: dict, frame_meta: dict) -> list[dict]:
    """Walk a single BGP message dict and return one flat dict per EVPN NLRI.

    Non-UPDATE messages (OPEN, KEEPALIVE, NOTIFICATION) or UPDATEs without
    EVPN NLRIs produce exactly one flat dict.
    """
    base: dict[str, Any] = dict(frame_meta)
    base["bgp.type"] = bgp_msg.get("bgp.type", "")

    # Also capture OPEN fields for capability extraction
    for field in (
        "bgp.open.my_as", "bgp.open.holdtime",
        "bgp.notification.major_error",
    ):
        v = bgp_msg.get(field, "")
        if v:
            base[field] = v

    # Preserve capability tree so parse_capabilities() can find it
    opt_tree = bgp_msg.get("bgp.open.opt")
    if opt_tree is not None:
        base["bgp.open.opt"] = opt_tree

    # Path attributes
    pa_container = bgp_msg.get("bgp.update.path_attributes", {})
    if not isinstance(pa_container, dict):
        return [base]
    path_attrs_raw = pa_container.get("bgp.update.path_attribute")
    if path_attrs_raw is None:
        return [base]

    path_attrs = (
        path_attrs_raw if isinstance(path_attrs_raw, list) else [path_attrs_raw]
    )

    # First pass: collect route targets and next-hop (shared across NLRIs)
    rt_list: list[str] = []
    next_hop: str = ""

    for attr in path_attrs:
        if not isinstance(attr, dict):
            continue
        type_code = attr.get("bgp.update.path_attribute.type_code", "")

        if type_code == "16":
            _collect_route_targets(attr, rt_list)
        elif type_code == "14":
            nh = _get_next_hop(attr)
            if nh:
                next_hop = nh

    # Second pass: collect all EVPN NLRIs
    nlri_dicts: list[dict] = []
    is_withdrawal = False

    for attr in path_attrs:
        if not isinstance(attr, dict):
            continue
        type_code = attr.get("bgp.update.path_attribute.type_code", "")

        if type_code in ("14", "15"):
            if type_code == "15":
                is_withdrawal = True
            raw_nlris = find_all_by_key(attr, "bgp.evpn.nlri")
            for item in raw_nlris:
                if isinstance(item, list):
                    nlri_dicts.extend(
                        d for d in item if isinstance(d, dict)
                    )
                elif isinstance(item, dict):
                    nlri_dicts.append(item)

    if not nlri_dicts:
        # No EVPN NLRIs — emit one record for the BGP message
        if rt_list:
            base["bgp.ext_com.value_rt"] = rt_list
        if next_hop:
            base["bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv4"] = (
                next_hop
            )
        return [base]

    # Emit one flat dict per NLRI
    results: list[dict] = []
    for nlri in nlri_dicts:
        flat = dict(base)
        rt = nlri.get("bgp.evpn.nlri.rt", "")
        if rt:
            flat["bgp.evpn.nlri.rt"] = rt
        flat["bgp.evpn.nlri.rd"] = nlri.get("bgp.evpn.nlri.rd", "")
        flat["bgp.evpn.nlri.esi"] = nlri.get("bgp.evpn.nlri.esi", "")
        flat["bgp.evpn.nlri.etag"] = nlri.get("bgp.evpn.nlri.etag", "")
        flat["bgp.evpn.nlri.mac_addr"] = nlri.get(
            "bgp.evpn.nlri.mac_addr", ""
        )
        ip_addr = nlri.get("bgp.evpn.nlri.ip.addr", "")
        if ip_addr:
            flat["bgp.evpn.nlri.ip.addr"] = ip_addr
        flat["bgp.evpn.nlri.iplen"] = nlri.get("bgp.evpn.nlri.iplen", "")
        flat["bgp.evpn.nlri.mpls_ls1"] = nlri.get(
            "bgp.evpn.nlri.mpls_ls1", ""
        )
        if rt_list:
            flat["bgp.ext_com.value_rt"] = rt_list
        if next_hop:
            flat["bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv4"] = (
                next_hop
            )
        if is_withdrawal:
            flat["bgp.update.withdrawn_routes"] = "1"
        results.append(flat)

    return results


def _collect_route_targets(attr: dict, rt_list: list[str]) -> None:
    """Pull route target values from an extended-community path attribute."""
    communities = find_all_by_key(attr, "bgp.ext_community")
    for comm_item in communities:
        items = comm_item if isinstance(comm_item, list) else [comm_item]
        for comm in items:
            if not isinstance(comm, dict):
                continue
            # Route target (stype 0x02)
            stype = comm.get("bgp.ext_com.stype_tr_as2", "")
            if stype == "0x02":
                asn = comm.get("bgp.ext_com.value_as2", "")
                an4 = comm.get("bgp.ext_com.value_an4", "")
                if asn and an4:
                    rt_list.append(f"target:{asn}:{an4}")


def _get_next_hop(attr: dict) -> str:
    """Extract the next-hop address from an MP_REACH_NLRI attribute (IPv4 or IPv6)."""
    nh_tree = attr.get("bgp.update.path_attribute.mp_reach_nlri.next_hop_tree")
    if isinstance(nh_tree, dict):
        # Try IPv4 first
        nh = nh_tree.get(
            "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv4", ""
        )
        if nh:
            return nh
        # Fall back to IPv6
        nh = nh_tree.get(
            "bgp.update.path_attribute.mp_reach_nlri.next_hop.ipv6", ""
        )
        if nh:
            return nh
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decode_pcap(pcap_path: str | Path, tshark_bin: str = "tshark") -> list[dict]:
    """Run tshark on *pcap_path* and return normalised packet dicts."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    cmd = [tshark_bin, "-r", str(pcap_path), "-T", "json", "-l"]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed: {result.stderr.strip()}")

    raw = _json_loads_dup(result.stdout)
    return normalize_packets(raw)


def load_json(json_path: str | Path) -> list[dict]:
    """Load a previously exported tshark JSON file.

    Accepts both full tshark ``-T json`` output (nested) and the flat format
    produced by ``-T json -e`` or by unit-test fixtures.
    """
    json_path = Path(json_path)
    if not json_path.exists():
        raise FileNotFoundError(f"JSON not found: {json_path}")

    with open(json_path) as f:
        text = f.read()

    data = _json_loads_dup(text)

    # Detect format: if the first packet has a nested "frame" dict inside
    # layers, it's full tshark output and needs normalisation.
    if data and _is_nested_format(data[0]):
        return normalize_packets(data)
    return data


def _is_nested_format(pkt: dict) -> bool:
    layers = pkt.get("_source", {}).get("layers", {})
    return isinstance(layers.get("frame"), dict)


def dump_fields(packets: list[dict], contains: str = "") -> dict[str, list[Any]]:
    """Walk all decoded packets and collect unique field names (and sample values).

    If *contains* is non-empty, only fields whose name contains the substring
    are returned.
    """
    fields: dict[str, list[Any]] = {}

    def _walk(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                if not contains or contains.lower() in path.lower():
                    if path not in fields:
                        fields[path] = []
                    if not isinstance(val, (dict, list)) and len(fields[path]) < 3:
                        fields[path].append(val)
                _walk(val, path)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, prefix)

    for pkt in packets:
        _walk(pkt)
    return dict(sorted(fields.items()))
