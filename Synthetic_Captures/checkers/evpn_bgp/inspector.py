"""
BGP/EVPN PCAP Inspector
========================
Inspects a PCAP file for potentially sensitive data in BGP/EVPN traffic.
Generates a detailed report to help decide what (if anything) to obfuscate.

Requirements:
    pip install scapy manuf colorama

Usage:
    python bgp_evpn_pcap_inspector.py <path_to_pcap>
    python bgp_evpn_pcap_inspector.py <path_to_pcap> --output report.txt
"""

import sys
import json
import struct
import socket
import argparse
import ipaddress
from collections import defaultdict
from datetime import datetime

# Optional: coloured terminal output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOUR = True
except ImportError:
    COLOUR = False

# Optional: MAC OUI vendor lookup
try:
    from manuf import manuf
    MAC_PARSER = manuf.MacParser()
except ImportError:
    MAC_PARSER = None

from scapy.all import rdpcap, wrpcap, IP, IPv6, Ether, TCP, Raw, conf
from scapy.contrib.bgp import (
    BGPHeader, BGPOpen, BGPUpdate, BGPNotification,
    BGPKeepAlive, BGPRouteRefresh,
    BGPPathAttr,
)

conf.verb = 0  # Suppress Scapy warnings

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def red(s):    return f"{Fore.RED}{s}{Style.RESET_ALL}"    if COLOUR else s
def yellow(s): return f"{Fore.YELLOW}{s}{Style.RESET_ALL}" if COLOUR else s
def green(s):  return f"{Fore.GREEN}{s}{Style.RESET_ALL}"  if COLOUR else s
def cyan(s):   return f"{Fore.CYAN}{s}{Style.RESET_ALL}"   if COLOUR else s
def bold(s):   return f"{Style.BRIGHT}{s}{Style.RESET_ALL}" if COLOUR else s

# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

IANA_SPECIAL_RANGES = [
    ("0.0.0.0/8",       "This network"),
    ("10.0.0.0/8",      "Private (RFC 1918)"),
    ("100.64.0.0/10",   "Shared Address Space (RFC 6598)"),
    ("127.0.0.0/8",     "Loopback"),
    ("169.254.0.0/16",  "Link-local"),
    ("172.16.0.0/12",   "Private (RFC 1918)"),
    ("192.0.0.0/24",    "IETF Protocol Assignments"),
    ("192.0.2.0/24",    "TEST-NET-1 (RFC 5737) — safe for docs"),
    ("192.168.0.0/16",  "Private (RFC 1918)"),
    ("198.18.0.0/15",   "Benchmarking (RFC 2544)"),
    ("198.51.100.0/24", "TEST-NET-2 (RFC 5737) — safe for docs"),
    ("203.0.113.0/24",  "TEST-NET-3 (RFC 5737) — safe for docs"),
    ("224.0.0.0/4",     "Multicast"),
    ("240.0.0.0/4",     "Reserved"),
    ("255.255.255.255/32", "Broadcast"),
]

RFC5737_SAFE = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

RFC3849_SAFE_V6 = ipaddress.ip_network("2001:db8::/32")  # IPv6 documentation range


def classify_ip(ip_str):
    """Return (category, flag_level) where flag_level: 0=ok, 1=warn, 2=sensitive."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid", 2

    if isinstance(addr, ipaddress.IPv6Address):
        if addr in RFC3849_SAFE_V6:
            return "IPv6 documentation (safe)", 0
        if addr.is_loopback:
            return "IPv6 loopback", 0
        if addr.is_link_local:
            return "IPv6 link-local", 1
        if addr.is_private:
            return "IPv6 private/ULA", 1
        return "IPv6 public/routable", 2

    for net_str, label in IANA_SPECIAL_RANGES:
        if addr in ipaddress.ip_network(net_str):
            if any(addr in safe for safe in RFC5737_SAFE):
                return f"{label}", 0
            if addr.is_loopback:
                return label, 0
            return label, 1

    return "Public/routable", 2


def classify_asn(asn):
    """Return (label, flag_level)."""
    if asn == 0:
        return "Reserved (0)", 1
    if asn == 23456:
        return "AS_TRANS (RFC 6793)", 0
    if 1 <= asn <= 64495:
        return "Public ASN", 0
    if 64496 <= asn <= 64511:
        return "Documentation ASN (RFC 5398) — safe", 0
    if 64512 <= asn <= 65534:
        return "Private ASN (RFC 6996)", 1
    if asn == 65535:
        return "Reserved", 1
    if 65536 <= asn <= 65551:
        return "Documentation ASN (RFC 5398) — safe", 0
    if 4200000000 <= asn <= 4294967294:
        return "Private 4-byte ASN (RFC 6996)", 1
    if asn == 4294967295:
        return "Reserved", 1
    return "Public 4-byte ASN", 0


def oui_vendor(mac):
    if MAC_PARSER:
        try:
            result = MAC_PARSER.get_manuf(mac)
            return result if result else "Unknown"
        except Exception:
            return "Unknown"
    return "Unknown (manuf package not installed)"


# ---------------------------------------------------------------------------
# BGP TCP stream reassembly
# ---------------------------------------------------------------------------

BGP_PORT   = 179
BGP_MARKER = b"\xff" * 16


def extract_bgp_messages(tcp_payload: bytes):
    """Yield raw BGP messages from a TCP payload buffer."""
    buf = tcp_payload
    while len(buf) >= 19:
        if buf[:16] != BGP_MARKER:
            break
        msg_len = struct.unpack("!H", buf[16:18])[0]
        if msg_len < 19 or len(buf) < msg_len:
            break
        yield buf[:msg_len]
        buf = buf[msg_len:]


# BGP message type constants
BGP_TYPE_OPEN         = 1
BGP_TYPE_UPDATE       = 2
BGP_TYPE_NOTIFICATION = 3
BGP_TYPE_KEEPALIVE    = 4
BGP_TYPE_ROUTE_REFRESH = 5

# BGP path attribute type codes
PA_ORIGIN           = 1
PA_AS_PATH          = 2
PA_NEXT_HOP         = 3
PA_MED              = 4
PA_LOCAL_PREF       = 5
PA_ATOMIC_AGGREGATE = 6
PA_AGGREGATOR       = 7
PA_COMMUNITY        = 8
PA_ORIGINATOR_ID    = 9
PA_CLUSTER_LIST     = 10
PA_MP_REACH         = 14
PA_MP_UNREACH       = 15
PA_EXT_COMMUNITY    = 16
PA_AS4_PATH         = 17
PA_AS4_AGGREGATOR   = 18
PA_LARGE_COMMUNITY  = 32
PA_TUNNEL_ENCAP     = 23

# AFI/SAFI
AFI_IPV4  = 1
AFI_IPV6  = 2
AFI_L2VPN = 25
SAFI_UNICAST    = 1
SAFI_MULTICAST  = 2
SAFI_LABELED    = 4
SAFI_EVPN       = 70
SAFI_MPLS_VPN   = 128

# EVPN route types
EVPN_TYPE_NAMES = {
    1: "Ethernet Auto-Discovery",
    2: "MAC/IP Advertisement",
    3: "Inclusive Multicast Ethernet Tag (IMET)",
    4: "Ethernet Segment",
    5: "IP Prefix Route",
    6: "Selective Multicast Ethernet Tag",
}

# BGP NOTIFICATION error codes
NOTIF_ERROR_CODES = {
    1: "Message Header Error",
    2: "OPEN Message Error",
    3: "UPDATE Message Error",
    4: "Hold Timer Expired",
    5: "Finite State Machine Error",
    6: "Cease",
}

NOTIF_SUBCODES = {
    1: {1: "Connection Not Synchronized", 2: "Bad Message Length", 3: "Bad Message Type"},
    2: {1: "Unsupported Version", 2: "Bad Peer AS", 3: "Bad BGP Identifier",
        4: "Unsupported Optional Parameter", 6: "Unacceptable Hold Time",
        7: "Unsupported Capability"},
    3: {1: "Malformed Attribute List", 2: "Unrecognized Well-known Attribute",
        3: "Missing Well-known Attribute", 4: "Attribute Flags Error",
        5: "Attribute Length Error", 6: "Invalid ORIGIN Attribute",
        8: "Invalid NEXT_HOP Attribute", 9: "Optional Attribute Error",
        10: "Invalid Network Field", 11: "Malformed AS_PATH"},
    6: {1: "Maximum Number of Prefixes Reached", 2: "Administrative Shutdown",
        3: "Peer De-configured", 4: "Administrative Reset",
        5: "Connection Rejected", 6: "Other Configuration Change",
        7: "Connection Collision Resolution", 8: "Out of Resources"},
}

# BGP capabilities
BGP_CAP_NAMES = {
    1:   "Multiprotocol Extensions (RFC 4760)",
    2:   "Route Refresh (RFC 2918)",
    5:   "Extended Next Hop Encoding",
    6:   "Extended Message (RFC 8654)",
    7:   "BGPsec",
    8:   "Multiple Labels",
    9:   "BGP Role (RFC 9234)",
    64:  "Graceful Restart (RFC 4724)",
    65:  "4-octet AS Number (RFC 6793)",
    69:  "ADD-PATH (RFC 7911)",
    70:  "Enhanced Route Refresh",
    71:  "Long-lived Graceful Restart",
    73:  "FQDN",
    128: "Route Refresh (Cisco)",
}

# TCP option numbers (for MD5/TCP-AO detection)
TCP_OPT_MD5   = 19
TCP_OPT_TCP_AO = 29


# ---------------------------------------------------------------------------
# Low-level BGP parsing helpers
# ---------------------------------------------------------------------------

def parse_as_path(data):
    """Return list of ASNs from AS_PATH attribute (both 2- and 4-byte)."""
    asns, i = [], 0
    while i < len(data):
        if i + 2 > len(data):
            break
        seg_type = data[i]
        seg_len  = data[i + 1]
        i += 2
        for _ in range(seg_len):
            if i + 2 <= len(data):
                asn = struct.unpack("!H", data[i:i+2])[0]
                asns.append(asn)
                i += 2
    return asns


def parse_as4_path(data):
    """Return list of ASNs from AS4_PATH attribute (4-byte ASNs)."""
    asns, i = [], 0
    while i < len(data):
        if i + 2 > len(data):
            break
        seg_type = data[i]
        seg_len  = data[i + 1]
        i += 2
        for _ in range(seg_len):
            if i + 4 <= len(data):
                asn = struct.unpack("!I", data[i:i+4])[0]
                asns.append(asn)
                i += 4
    return asns


def parse_communities(data):
    """Return list of (asn, value) from COMMUNITY attribute."""
    communities = []
    for i in range(0, len(data) - 3, 4):
        asn = struct.unpack("!H", data[i:i+2])[0]
        val = struct.unpack("!H", data[i+2:i+4])[0]
        communities.append((asn, val))
    return communities


def parse_ext_communities(data):
    """Return list of hex strings from EXTENDED COMMUNITIES attribute."""
    ext_comms = []
    for i in range(0, len(data) - 7, 8):
        ec = data[i:i+8]
        ext_comms.append(ec.hex())
    return ext_comms


def parse_large_communities(data):
    """Return list of (global_admin, local_data1, local_data2)."""
    large_comms = []
    for i in range(0, len(data) - 11, 12):
        ga  = struct.unpack("!I", data[i:i+4])[0]
        ld1 = struct.unpack("!I", data[i+4:i+8])[0]
        ld2 = struct.unpack("!I", data[i+8:i+12])[0]
        large_comms.append((ga, ld1, ld2))
    return large_comms


def parse_nlri_prefixes(data, is_v6=False):
    """Parse packed NLRI prefix list, return list of prefix strings."""
    prefixes, i = [], 0
    addr_len = 16 if is_v6 else 4
    while i < len(data):
        if i >= len(data):
            break
        plen = data[i]; i += 1
        nbytes = (plen + 7) // 8
        if i + nbytes > len(data):
            break
        raw = data[i:i+nbytes] + b"\x00" * (addr_len - nbytes)
        i += nbytes
        try:
            if is_v6:
                addr = str(ipaddress.IPv6Address(raw))
            else:
                addr = str(ipaddress.IPv4Address(raw[:4]))
            prefixes.append(f"{addr}/{plen}")
        except Exception:
            pass
    return prefixes


def parse_mp_reach(data):
    """
    Parse MP_REACH_NLRI (type 14).
    Returns dict with afi, safi, next_hops, prefixes, evpn_routes.
    """
    result = {"afi": None, "safi": None, "next_hops": [], "prefixes": [], "evpn_routes": []}
    if len(data) < 4:
        return result
    afi  = struct.unpack("!H", data[0:2])[0]
    safi = data[2]
    nh_len = data[3]
    result["afi"]  = afi
    result["safi"] = safi
    i = 4

    # Next hop(s)
    nh_data = data[i:i+nh_len]
    i += nh_len

    if afi == AFI_IPV4 and nh_len >= 4:
        result["next_hops"].append(str(ipaddress.IPv4Address(nh_data[:4])))
        if nh_len >= 8:  # RD + NH (VPN)
            result["next_hops"].append(str(ipaddress.IPv4Address(nh_data[4:8])))
    elif afi == AFI_IPV6 and nh_len >= 16:
        result["next_hops"].append(str(ipaddress.IPv6Address(nh_data[:16])))
        if nh_len >= 32:
            result["next_hops"].append(str(ipaddress.IPv6Address(nh_data[16:32])))
    elif afi == AFI_L2VPN:
        # EVPN next-hop: 16 bytes = IPv6, 4 bytes = IPv4
        if nh_len >= 16:
            result["next_hops"].append(str(ipaddress.IPv6Address(nh_data[:16])))
            if nh_len >= 32:
                result["next_hops"].append(str(ipaddress.IPv6Address(nh_data[16:32])))
        elif nh_len >= 4:
            result["next_hops"].append(str(ipaddress.IPv4Address(nh_data[:4])))

    if i >= len(data):
        return result

    snpa_count = data[i]; i += 1
    for _ in range(snpa_count):
        if i >= len(data): break
        snpa_len = data[i]; i += 1
        i += (snpa_len + 1) // 2

    nlri_data = data[i:]

    if safi == SAFI_EVPN:
        result["evpn_routes"] = parse_evpn_nlri(nlri_data)
    elif afi == AFI_IPV4:
        result["prefixes"] = parse_nlri_prefixes(nlri_data, is_v6=False)
    elif afi == AFI_IPV6:
        result["prefixes"] = parse_nlri_prefixes(nlri_data, is_v6=True)

    return result


def parse_mp_unreach(data):
    """Parse MP_UNREACH_NLRI (type 15). Returns dict."""
    result = {"afi": None, "safi": None, "prefixes": [], "evpn_routes": []}
    if len(data) < 3:
        return result
    afi  = struct.unpack("!H", data[0:2])[0]
    safi = data[2]
    result["afi"]  = afi
    result["safi"] = safi
    nlri_data = data[3:]
    if safi == SAFI_EVPN:
        result["evpn_routes"] = parse_evpn_nlri(nlri_data)
    elif afi == AFI_IPV4:
        result["prefixes"] = parse_nlri_prefixes(nlri_data, is_v6=False)
    elif afi == AFI_IPV6:
        result["prefixes"] = parse_nlri_prefixes(nlri_data, is_v6=True)
    return result


def parse_evpn_nlri(data):
    """Parse EVPN NLRI, return list of dicts describing each route."""
    routes = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            break
        route_type = data[i]
        route_len  = data[i + 1]
        i += 2
        route_data = data[i:i + route_len]
        i += route_len

        route = {
            "type":      route_type,
            "type_name": EVPN_TYPE_NAMES.get(route_type, f"Unknown ({route_type})"),
            "rd":        None,
            "esi":       None,
            "eth_tag":   None,
            "mac":       None,
            "mac_len":   None,
            "ip":        None,
            "ip_len":    None,
            "mpls1":     None,
            "mpls2":     None,
            "vni":       None,
            "prefix":    None,
            "gw_ip":     None,
        }

        j = 0
        try:
            if route_type == 1:  # Ethernet Auto-Discovery
                route["rd"]      = route_data[j:j+8].hex(); j += 8
                route["esi"]     = route_data[j:j+10].hex(); j += 10
                route["eth_tag"] = struct.unpack("!I", route_data[j:j+4])[0]; j += 4
                if j + 3 <= len(route_data):
                    route["mpls1"] = route_data[j:j+3].hex()

            elif route_type == 2:  # MAC/IP Advertisement
                route["rd"]      = route_data[j:j+8].hex(); j += 8
                route["esi"]     = route_data[j:j+10].hex(); j += 10
                route["eth_tag"] = struct.unpack("!I", route_data[j:j+4])[0]; j += 4
                route["mac_len"] = route_data[j]; j += 1
                mac_bytes        = route_data[j:j+6]; j += 6
                route["mac"]     = ":".join(f"{b:02x}" for b in mac_bytes)
                route["ip_len"]  = route_data[j]; j += 1
                if route["ip_len"] > 0:
                    ip_bytes = route_data[j:j + route["ip_len"] // 8]; j += route["ip_len"] // 8
                    if route["ip_len"] == 32:
                        route["ip"] = str(ipaddress.IPv4Address(ip_bytes))
                    elif route["ip_len"] == 128:
                        route["ip"] = str(ipaddress.IPv6Address(ip_bytes))
                if j + 3 <= len(route_data):
                    route["mpls1"] = route_data[j:j+3].hex(); j += 3
                if j + 3 <= len(route_data):
                    route["mpls2"] = route_data[j:j+3].hex()

            elif route_type == 3:  # IMET
                route["rd"]      = route_data[j:j+8].hex(); j += 8
                route["eth_tag"] = struct.unpack("!I", route_data[j:j+4])[0]; j += 4
                ip_len           = route_data[j]; j += 1
                if ip_len == 32:
                    route["ip"] = str(ipaddress.IPv4Address(route_data[j:j+4]))
                elif ip_len == 128:
                    route["ip"] = str(ipaddress.IPv6Address(route_data[j:j+16]))

            elif route_type == 4:  # Ethernet Segment
                route["rd"]  = route_data[j:j+8].hex(); j += 8
                route["esi"] = route_data[j:j+10].hex(); j += 10
                ip_len       = route_data[j]; j += 1
                if ip_len == 32:
                    route["ip"] = str(ipaddress.IPv4Address(route_data[j:j+4]))
                elif ip_len == 128:
                    route["ip"] = str(ipaddress.IPv6Address(route_data[j:j+16]))

            elif route_type == 5:  # IP Prefix
                route["rd"]      = route_data[j:j+8].hex(); j += 8
                route["esi"]     = route_data[j:j+10].hex(); j += 10
                route["eth_tag"] = struct.unpack("!I", route_data[j:j+4])[0]; j += 4
                pfx_len          = route_data[j]; j += 1
                # Determine address sizes from route_len:
                # Fixed overhead: RD(8)+ESI(10)+EthTag(4)+PfxLen(1)+Label(3) = 26
                # Remaining = prefix_bytes + gw_bytes
                ip_data_len = route_len - 26
                if pfx_len <= 32:
                    pfx_byte_len = 4
                else:
                    pfx_byte_len = 16
                gw_byte_len = ip_data_len - pfx_byte_len
                ip_bytes = route_data[j:j + pfx_byte_len]; j += pfx_byte_len
                if pfx_byte_len == 4:
                    route["prefix"] = f"{ipaddress.IPv4Address(ip_bytes)}/{pfx_len}"
                else:
                    route["prefix"] = f"{ipaddress.IPv6Address(ip_bytes)}/{pfx_len}"
                gw_bytes = route_data[j:j + gw_byte_len]; j += gw_byte_len
                if gw_byte_len == 16:
                    route["gw_ip"] = str(ipaddress.IPv6Address(gw_bytes))
                elif gw_byte_len == 4:
                    route["gw_ip"] = str(ipaddress.IPv4Address(gw_bytes))
                if j + 3 <= len(route_data):
                    route["mpls1"] = route_data[j:j+3].hex()
        except Exception:
            pass

        # Extract VNI from MPLS label field (top 20 bits of 3-byte label)
        if route.get("mpls1"):
            try:
                label_bytes = bytes.fromhex(route["mpls1"])
                vni = (label_bytes[0] << 12) | (label_bytes[1] << 4) | (label_bytes[2] >> 4)
                if vni > 0:
                    route["vni"] = vni
            except (ValueError, IndexError):
                pass

        routes.append(route)
    return routes


def parse_bgp_open_caps(data):
    """Parse BGP OPEN optional parameters, return list of capability dicts."""
    caps = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            break
        param_type = data[i]
        param_len  = data[i + 1]
        i += 2
        param_data = data[i:i + param_len]
        i += param_len
        if param_type != 2:  # Only process Capability params
            continue
        j = 0
        while j < len(param_data):
            if j + 2 > len(param_data):
                break
            cap_code = param_data[j]
            cap_len  = param_data[j + 1]
            j += 2
            cap_data = param_data[j:j + cap_len]
            j += cap_len
            cap = {
                "code": cap_code,
                "name": BGP_CAP_NAMES.get(cap_code, f"Unknown ({cap_code})"),
                "afi":  None,
                "safi": None,
                "asn":  None,
                "fqdn": None,
            }
            if cap_code == 1 and cap_len >= 4:  # Multiprotocol
                cap["afi"]  = struct.unpack("!H", cap_data[0:2])[0]
                cap["safi"] = cap_data[3]
            elif cap_code == 65 and cap_len == 4:  # 4-octet ASN
                cap["asn"]  = struct.unpack("!I", cap_data)[0]
            elif cap_code == 73:  # FQDN
                # Format: 1B hostname len, hostname, 1B domain len, domain
                try:
                    hlen = cap_data[0]
                    hostname = cap_data[1:1+hlen].decode("utf-8", errors="replace")
                    dlen = cap_data[1+hlen]
                    domain = cap_data[2+hlen:2+hlen+dlen].decode("utf-8", errors="replace")
                    cap["fqdn"] = f"{hostname}.{domain}" if domain else hostname
                except Exception:
                    pass
            caps.append(cap)
    return caps


def decode_rd(rd_bytes):
    """Decode an 8-byte Route Distinguisher into human-readable form."""
    if len(rd_bytes) < 8:
        return rd_bytes.hex()
    rd_type = struct.unpack("!H", rd_bytes[0:2])[0]
    if rd_type == 0:
        asn = struct.unpack("!H", rd_bytes[2:4])[0]
        val = struct.unpack("!I", rd_bytes[4:8])[0]
        return f"0:{asn}:{val}"
    elif rd_type == 1:
        ip  = str(ipaddress.IPv4Address(rd_bytes[2:6]))
        val = struct.unpack("!H", rd_bytes[6:8])[0]
        return f"1:{ip}:{val}"
    elif rd_type == 2:
        asn = struct.unpack("!I", rd_bytes[2:6])[0]
        val = struct.unpack("!H", rd_bytes[6:8])[0]
        return f"2:{asn}:{val}"
    return rd_bytes.hex()


def decode_ext_community(ec_hex):
    """Decode an extended community hex string into human-readable form."""
    try:
        ec = bytes.fromhex(ec_hex)
        ec_type    = ec[0]
        ec_subtype = ec[1]
        if ec_type in (0x00, 0x40):  # 2-octet AS specific
            asn = struct.unpack("!H", ec[2:4])[0]
            val = struct.unpack("!I", ec[4:8])[0]
            return f"AS:{asn}:{val} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
        elif ec_type in (0x01, 0x41):  # IPv4 specific
            ip  = str(ipaddress.IPv4Address(ec[2:6]))
            val = struct.unpack("!H", ec[6:8])[0]
            return f"IP:{ip}:{val} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
        elif ec_type in (0x02, 0x42):  # 4-octet AS specific
            asn = struct.unpack("!I", ec[2:6])[0]
            val = struct.unpack("!H", ec[6:8])[0]
            return f"AS4:{asn}:{val} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
        elif ec_type == 0x03 and ec_subtype == 0x0c:  # Encapsulation (RFC 5512)
            tunnel_type = struct.unpack("!H", ec[6:8])[0]
            tunnel_names = {8: "VXLAN", 15: "SRv6", 13: "NVGRE", 2: "GRE"}
            tname = tunnel_names.get(tunnel_type, f"type={tunnel_type}")
            return f"Encapsulation: {tname} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
        elif ec_type == 0x06 and ec_subtype == 0x00:  # EVPN MAC Mobility (RFC 7432)
            seq = struct.unpack("!I", ec[4:8])[0]
            return f"EVPN MAC Mobility seq={seq}"
        elif ec_type == 0x06 and ec_subtype == 0x01:  # EVPN ESI MPLS Label
            return f"EVPN ESI MPLS Label"
        elif ec_type == 0x80 and ec_subtype == 0x0a:  # L2 VNI
            vni = struct.unpack("!I", b"\x00" + ec[5:8])[0]
            return f"L2 VNI={vni} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
        elif ec_type == 0x80 and ec_subtype == 0x09:  # L3 VNI
            vni = struct.unpack("!I", b"\x00" + ec[5:8])[0]
            return f"L3 VNI={vni} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
        return f"raw={ec_hex} (type=0x{ec_type:02x}/0x{ec_subtype:02x})"
    except Exception:
        return ec_hex


def check_tcp_auth(pkt):
    """Return list of detected TCP authentication options (MD5/TCP-AO)."""
    found = []
    if TCP in pkt:
        for opt in pkt[TCP].options:
            if isinstance(opt, tuple):
                if opt[0] == "MD5header" or (isinstance(opt[0], int) and opt[0] == TCP_OPT_MD5):
                    found.append("TCP MD5 (RFC 2385)")
                elif isinstance(opt[0], int) and opt[0] == TCP_OPT_TCP_AO:
                    found.append("TCP-AO (RFC 5925)")
    return found


# ---------------------------------------------------------------------------
# Main inspector
# ---------------------------------------------------------------------------

class Finding:
    """Represents a single sensitivity finding."""
    LEVELS = {0: "INFO", 1: "WARN", 2: "HIGH"}

    def __init__(self, level, category, field, value, detail=""):
        self.level    = level
        self.category = category
        self.field    = field
        self.value    = value
        self.detail   = detail

    def __str__(self):
        label = self.LEVELS[self.level]
        base  = f"[{label}] {self.category} | {self.field}: {self.value}"
        return f"{base}  → {self.detail}" if self.detail else base


class PcapInspector:
    def __init__(self, pcap_path):
        self.pcap_path   = pcap_path
        self.findings    = []
        self.stats       = defaultdict(int)

        # Dedup sets
        self._seen_ips   = {}
        self._seen_macs  = {}
        self._seen_asns  = {}
        self._seen_rds   = set()
        self._seen_rts   = set()
        self._seen_comms = set()
        self._seen_fqdns = set()
        self._seen_vnis  = set()
        self._seen_esis  = set()
        self._seen_pfxs  = set()

        # BGP session tracking
        self.bgp_sessions        = defaultdict(lambda: {"open_sent": False, "open_recv": False})
        self.bgp_notifications   = []
        self.bgp_capabilities    = defaultdict(set)
        self.tcp_auth_detected   = []
        self.bgp_errors          = []

        # Timestamps
        self.first_ts = None
        self.last_ts  = None

        # TCP stream reassembly buffer
        self._tcp_buffers = defaultdict(bytes)

    def _add(self, level, category, field, value, detail=""):
        self.findings.append(Finding(level, category, field, value, detail))

    # ------------------------------------------------------------------
    # IP inspection
    # ------------------------------------------------------------------
    def _inspect_ip(self, ip_str, context=""):
        if ip_str in self._seen_ips:
            return
        cat, flag = classify_ip(ip_str)
        self._seen_ips[ip_str] = (cat, flag)
        if flag == 2:
            self._add(2, "IP Address", f"IP ({context})", ip_str,
                      f"{cat} — consider obfuscating before public distribution")
        elif flag == 1:
            self._add(1, "IP Address", f"IP ({context})", ip_str,
                      f"{cat} — review before distribution")
        else:
            self._add(0, "IP Address", f"IP ({context})", ip_str, f"{cat} — generally safe")

    # ------------------------------------------------------------------
    # MAC inspection
    # ------------------------------------------------------------------
    def _inspect_mac(self, mac_str, context=""):
        mac_norm = mac_str.lower()
        if mac_norm in self._seen_macs:
            return
        vendor = oui_vendor(mac_str)
        self._seen_macs[mac_norm] = vendor
        # Broadcast/multicast are fine
        first_byte = int(mac_str.split(":")[0], 16) if ":" in mac_str else 0
        if mac_norm in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            self._add(0, "MAC Address", f"MAC ({context})", mac_str, "Broadcast/null — safe")
        elif first_byte & 0x01:
            self._add(0, "MAC Address", f"MAC ({context})", mac_str,
                      f"Multicast — safe | vendor hint: {vendor}")
        else:
            self._add(1, "MAC Address", f"MAC ({context})", mac_str,
                      f"Unicast — OUI reveals vendor: {vendor}. Device-specific portion "
                      f"may fingerprint hardware. Low risk at interop events.")

    # ------------------------------------------------------------------
    # ASN inspection
    # ------------------------------------------------------------------
    def _inspect_asn(self, asn, context=""):
        if asn in self._seen_asns:
            return
        label, flag = classify_asn(asn)
        self._seen_asns[asn] = (label, flag)
        self._add(flag, "AS Number", f"ASN ({context})", asn,
                  f"{label}")

    # ------------------------------------------------------------------
    # RD / RT / Community inspection
    # ------------------------------------------------------------------
    def _inspect_rd(self, rd_hex, context=""):
        if rd_hex in self._seen_rds:
            return
        self._seen_rds.add(rd_hex)
        decoded = decode_rd(bytes.fromhex(rd_hex)) if len(rd_hex) == 16 else rd_hex
        # Extract embedded IP/ASN
        parts = decoded.split(":")
        if len(parts) == 3:
            if parts[0] == "1":  # IP-based RD
                self._inspect_ip(parts[1], context=f"RD embedded IP ({context})")
            elif parts[0] in ("0", "2"):
                try:
                    self._inspect_asn(int(parts[1]), context=f"RD embedded ASN ({context})")
                except ValueError:
                    pass
        self._add(1, "Route Distinguisher", context, decoded,
                  "May reveal VPN topology / tenant info")

    def _inspect_rt(self, ec_hex, context="EVPN RT"):
        if ec_hex in self._seen_rts:
            return
        self._seen_rts.add(ec_hex)
        decoded = decode_ext_community(ec_hex)
        # Extract embedded IP/ASN from RT
        try:
            ec = bytes.fromhex(ec_hex)
            ec_type = ec[0]
            if ec_type in (0x00, 0x40):
                self._inspect_asn(struct.unpack("!H", ec[2:4])[0], context="RT embedded ASN")
            elif ec_type in (0x01, 0x41):
                self._inspect_ip(str(ipaddress.IPv4Address(ec[2:6])), context="RT embedded IP")
            elif ec_type in (0x02, 0x42):
                self._inspect_asn(struct.unpack("!I", ec[2:6])[0], context="RT embedded ASN")
        except Exception:
            pass
        # Detect VNI
        try:
            ec_b    = bytes.fromhex(ec_hex)
            subtype = ec_b[1]
            if subtype in (0x09, 0x0a):
                vni = struct.unpack("!I", b"\x00" + ec_b[5:8])[0]
                self._seen_vnis.add(vni)
                self._add(0, "VNI/VXLAN", context, vni, "VNI from extended community — low risk")
        except Exception:
            pass
        self._add(1, "Extended Community / Route Target", context, decoded,
                  "May reveal routing policy or segmentation scheme")

    def _inspect_community(self, asn, val, context=""):
        key = (asn, val)
        if key in self._seen_comms:
            return
        self._seen_comms.add(key)
        well_known = {
            (0xFFFF, 0xFF01): "NO_EXPORT",
            (0xFFFF, 0xFF02): "NO_ADVERTISE",
            (0xFFFF, 0xFF03): "NO_EXPORT_SUBCONFED",
            (0xFFFF, 0x0000): "GRACEFUL_SHUTDOWN",
            (0xFFFF, 0x0001): "ACCEPT_OWN",
        }
        label = well_known.get(key)
        if label:
            self._add(0, "BGP Community", context, f"{asn}:{val} ({label})", "Well-known — safe")
        else:
            self._inspect_asn(asn, context="Community ASN")
            self._add(1, "BGP Community", context, f"{asn}:{val}",
                      "Private community — may reveal internal routing policy")

    # ------------------------------------------------------------------
    # BGP path attribute parsing
    # ------------------------------------------------------------------
    def _parse_path_attributes(self, data, session_key):
        i = 0
        while i < len(data):
            if i + 2 > len(data):
                break
            flags   = data[i]
            pa_type = data[i + 1]
            extended = (flags & 0x10) != 0
            i += 2
            if extended:
                if i + 2 > len(data): break
                pa_len = struct.unpack("!H", data[i:i+2])[0]; i += 2
            else:
                if i + 1 > len(data): break
                pa_len = data[i]; i += 1
            pa_data = data[i:i + pa_len]; i += pa_len

            if pa_type == PA_AS_PATH:
                for asn in parse_as_path(pa_data):
                    self._inspect_asn(asn, context="AS_PATH")

            elif pa_type == PA_AS4_PATH:
                for asn in parse_as4_path(pa_data):
                    self._inspect_asn(asn, context="AS4_PATH")

            elif pa_type == PA_NEXT_HOP:
                if len(pa_data) >= 4:
                    self._inspect_ip(str(ipaddress.IPv4Address(pa_data[:4])),
                                     context="NEXT_HOP")

            elif pa_type == PA_AGGREGATOR:
                if len(pa_data) >= 6:
                    asn = struct.unpack("!H", pa_data[:2])[0]
                    ip  = str(ipaddress.IPv4Address(pa_data[2:6]))
                    self._inspect_asn(asn, context="AGGREGATOR ASN")
                    self._inspect_ip(ip,  context="AGGREGATOR IP")

            elif pa_type == PA_AS4_AGGREGATOR:
                if len(pa_data) >= 8:
                    asn = struct.unpack("!I", pa_data[:4])[0]
                    ip  = str(ipaddress.IPv4Address(pa_data[4:8]))
                    self._inspect_asn(asn, context="AS4_AGGREGATOR ASN")
                    self._inspect_ip(ip,  context="AS4_AGGREGATOR IP")

            elif pa_type == PA_ORIGINATOR_ID:
                if len(pa_data) >= 4:
                    self._inspect_ip(str(ipaddress.IPv4Address(pa_data[:4])),
                                     context="ORIGINATOR_ID")

            elif pa_type == PA_CLUSTER_LIST:
                for j in range(0, len(pa_data) - 3, 4):
                    self._inspect_ip(str(ipaddress.IPv4Address(pa_data[j:j+4])),
                                     context="CLUSTER_LIST")

            elif pa_type == PA_COMMUNITY:
                for asn, val in parse_communities(pa_data):
                    self._inspect_community(asn, val, context="COMMUNITY")

            elif pa_type == PA_EXT_COMMUNITY:
                for ec_hex in parse_ext_communities(pa_data):
                    self._inspect_rt(ec_hex, context="EXT_COMMUNITY")

            elif pa_type == PA_LARGE_COMMUNITY:
                for ga, ld1, ld2 in parse_large_communities(pa_data):
                    key = f"{ga}:{ld1}:{ld2}"
                    if key not in self._seen_comms:
                        self._seen_comms.add(key)
                        self._inspect_asn(ga, context="LARGE_COMMUNITY global admin")
                        self._add(1, "Large Community", "LARGE_COMMUNITY", key,
                                  "May reveal internal routing policy")

            elif pa_type == PA_MP_REACH:
                mp = parse_mp_reach(pa_data)
                afi_safi = f"AFI={mp['afi']} SAFI={mp['safi']}"
                for nh in mp["next_hops"]:
                    self._inspect_ip(nh, context=f"MP_REACH next-hop ({afi_safi})")
                for pfx in mp["prefixes"]:
                    if pfx not in self._seen_pfxs:
                        self._seen_pfxs.add(pfx)
                        ip_part = pfx.split("/")[0]
                        self._inspect_ip(ip_part, context=f"MP_REACH prefix ({afi_safi})")
                for route in mp["evpn_routes"]:
                    self._inspect_evpn_route(route)

            elif pa_type == PA_MP_UNREACH:
                mp = parse_mp_unreach(pa_data)
                for pfx in mp["prefixes"]:
                    if pfx not in self._seen_pfxs:
                        self._seen_pfxs.add(pfx)
                        ip_part = pfx.split("/")[0]
                        self._inspect_ip(ip_part, context=f"MP_UNREACH prefix")
                for route in mp["evpn_routes"]:
                    self._inspect_evpn_route(route)

    def _inspect_evpn_route(self, route):
        rtype = route["type"]
        rname = route["type_name"]

        if route["rd"]:
            try:
                self._inspect_rd(route["rd"], context=f"EVPN {rname} RD")
            except Exception:
                pass

        if route["esi"] and route["esi"] != "00" * 10:
            if route["esi"] not in self._seen_esis:
                self._seen_esis.add(route["esi"])
                self._add(1, "EVPN ESI", f"EVPN {rname}", route["esi"],
                          "Ethernet Segment ID — may fingerprint multi-homed topology")

        if route["mac"]:
            self._inspect_mac(route["mac"], context=f"EVPN {rname}")

        if route["ip"]:
            self._inspect_ip(route["ip"], context=f"EVPN {rname} IP")

        if route["prefix"]:
            ip_part = route["prefix"].split("/")[0]
            self._inspect_ip(ip_part, context=f"EVPN {rname} prefix")

        if route["gw_ip"]:
            self._inspect_ip(route["gw_ip"], context=f"EVPN {rname} GW")

        if route["vni"] is not None:
            if route["vni"] not in self._seen_vnis:
                self._seen_vnis.add(route["vni"])
                self._add(0, "VNI/VXLAN", f"EVPN {rname}", route["vni"],
                          "VNI — low risk at interop events")

    # ------------------------------------------------------------------
    # BGP message dispatch
    # ------------------------------------------------------------------
    def _process_bgp_message(self, raw_msg, session_key):
        if len(raw_msg) < 19:
            return
        msg_type = raw_msg[18]
        msg_body = raw_msg[19:]
        self.stats[f"bgp_type_{msg_type}"] += 1

        if msg_type == BGP_TYPE_OPEN:
            self._process_open(msg_body, session_key)
        elif msg_type == BGP_TYPE_UPDATE:
            self._process_update(msg_body, session_key)
        elif msg_type == BGP_TYPE_NOTIFICATION:
            self._process_notification(msg_body, session_key)
        elif msg_type == BGP_TYPE_KEEPALIVE:
            pass  # nothing sensitive
        elif msg_type == BGP_TYPE_ROUTE_REFRESH:
            pass  # AFI/SAFI only, not sensitive

    def _process_open(self, body, session_key):
        if len(body) < 10:
            return
        version  = body[0]
        my_asn   = struct.unpack("!H", body[1:3])[0]
        hold_time = struct.unpack("!H", body[3:5])[0]
        router_id = str(ipaddress.IPv4Address(body[5:9]))
        opt_len  = body[9]
        opt_data = body[10:10 + opt_len]

        self._inspect_asn(my_asn, context="BGP OPEN My AS")
        self._inspect_ip(router_id, context="BGP OPEN Router ID")

        caps = parse_bgp_open_caps(opt_data)
        for cap in caps:
            cap_key = f"{cap['code']}-{cap.get('afi')}-{cap.get('safi')}"
            self.bgp_capabilities[session_key].add(cap_key)
            if cap["asn"] is not None:
                self._inspect_asn(cap["asn"], context="BGP OPEN 4-octet ASN capability")
            if cap["fqdn"]:
                if cap["fqdn"] not in self._seen_fqdns:
                    self._seen_fqdns.add(cap["fqdn"])
                    self._add(2, "FQDN / Hostname", "BGP OPEN FQDN capability",
                              cap["fqdn"],
                              "Hostname reveals device identity — consider obfuscating")

    def _process_update(self, body, session_key):
        if len(body) < 4:
            return
        withdrawn_len = struct.unpack("!H", body[0:2])[0]
        i = 2
        # Withdrawn routes
        withdrawn_data = body[i:i + withdrawn_len]
        for pfx in parse_nlri_prefixes(withdrawn_data):
            if pfx not in self._seen_pfxs:
                self._seen_pfxs.add(pfx)
                self._inspect_ip(pfx.split("/")[0], context="UPDATE withdrawn prefix")
        i += withdrawn_len

        if i + 2 > len(body):
            return
        pa_len = struct.unpack("!H", body[i:i+2])[0]
        i += 2
        pa_data = body[i:i + pa_len]
        i += pa_len

        self._parse_path_attributes(pa_data, session_key)

        # Reachable NLRI (IPv4 unicast)
        nlri_data = body[i:]
        for pfx in parse_nlri_prefixes(nlri_data):
            if pfx not in self._seen_pfxs:
                self._seen_pfxs.add(pfx)
                self._inspect_ip(pfx.split("/")[0], context="UPDATE NLRI prefix")

    def _process_notification(self, body, session_key):
        if len(body) < 2:
            return
        err_code    = body[0]
        err_subcode = body[1]
        err_data    = body[2:]
        err_name    = NOTIF_ERROR_CODES.get(err_code, f"Unknown ({err_code})")
        sub_name    = NOTIF_SUBCODES.get(err_code, {}).get(err_subcode,
                                                            f"subcode {err_subcode}")
        rec = {
            "session": session_key,
            "error_code":    err_code,
            "error_subcode": err_subcode,
            "error_name":    err_name,
            "subcode_name":  sub_name,
            "data_hex":      err_data.hex() if err_data else "",
        }
        self.bgp_notifications.append(rec)
        self._add(1, "BGP NOTIFICATION", f"Session {session_key}",
                  f"{err_name} / {sub_name}",
                  "BGP errors/failures may embarrass vendors — confirm before publishing")

    # ------------------------------------------------------------------
    # Main scan loop
    # ------------------------------------------------------------------
    def scan(self):
        print(bold(f"\n{'='*70}"))
        print(bold(f"  BGP/EVPN PCAP Inspector"))
        print(bold(f"  File: {self.pcap_path}"))
        print(bold(f"{'='*70}\n"))

        print("Loading PCAP…", end=" ", flush=True)
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            print(red(f"FAILED: {e}"))
            sys.exit(1)
        print(green(f"{len(packets)} packets loaded."))

        self.stats["total_packets"] = len(packets)
        bgp_tcp_pkts = 0

        for pkt in packets:
            # Timestamps
            ts = float(pkt.time)
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

            # Layer-2 MACs
            if Ether in pkt:
                self._inspect_mac(pkt[Ether].src, context="Ethernet src")
                self._inspect_mac(pkt[Ether].dst, context="Ethernet dst")

            # Layer-3 IPs
            if IP in pkt:
                self.stats["ipv4_packets"] += 1
                self._inspect_ip(pkt[IP].src, context="IP src")
                self._inspect_ip(pkt[IP].dst, context="IP dst")

            if IPv6 in pkt:
                self.stats["ipv6_packets"] += 1
                self._inspect_ip(str(pkt[IPv6].src), context="IPv6 src")
                self._inspect_ip(str(pkt[IPv6].dst), context="IPv6 dst")

            # TCP auth options
            if TCP in pkt:
                auth = check_tcp_auth(pkt)
                for a in auth:
                    if a not in self.tcp_auth_detected:
                        self.tcp_auth_detected.append(a)
                        self._add(2, "TCP Authentication", "TCP option", a,
                                  "⚠️  Authentication credential present — MUST obfuscate/remove")

            # BGP over TCP
            # Note: importing scapy.contrib.bgp causes scapy to auto-dissect
            # TCP port 179 payloads into BGPHeader/BGPKeepAlive/etc layers.
            # We need the raw bytes for our own reassembly, so we extract from
            # whatever layer sits above TCP (could be Raw, BGPHeader, or
            # BGPKeepAlive depending on what scapy's dissector handled).
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                if BGP_PORT in (src_port, dst_port):
                    tcp_payload = pkt[TCP].payload
                    if tcp_payload and not isinstance(tcp_payload, type(None)):
                        payload_bytes = bytes(tcp_payload)
                        if not payload_bytes:
                            continue
                        bgp_tcp_pkts += 1
                        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                        session_key = tuple(sorted([
                            f"{ip_layer.src}:{src_port}",
                            f"{ip_layer.dst}:{dst_port}",
                        ]))
                        self._tcp_buffers[session_key] += payload_bytes
                        for raw_msg in extract_bgp_messages(self._tcp_buffers[session_key]):
                            self._process_bgp_message(raw_msg, session_key)
                        # Keep only leftover (incomplete message) in buffer
                        buf = self._tcp_buffers[session_key]
                        consumed = 0
                        while len(buf[consumed:]) >= 19:
                            if buf[consumed:consumed+16] != BGP_MARKER:
                                break
                            msg_len = struct.unpack("!H", buf[consumed+16:consumed+18])[0]
                            if len(buf[consumed:]) < msg_len:
                                break
                            consumed += msg_len
                        self._tcp_buffers[session_key] = buf[consumed:]

        self.stats["bgp_tcp_packets"] = bgp_tcp_pkts
        self._print_report()

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def _print_report(self):
        sep = "-" * 70

        # ── Summary ────────────────────────────────────────────────────
        print(bold("\n📊 CAPTURE SUMMARY"))
        print(sep)
        if self.first_ts and self.last_ts:
            print(f"  Capture start : {datetime.utcfromtimestamp(self.first_ts)} UTC")
            print(f"  Capture end   : {datetime.utcfromtimestamp(self.last_ts)} UTC")
            print(f"  Duration      : {self.last_ts - self.first_ts:.1f}s")
        print(f"  Total packets : {self.stats['total_packets']}")
        print(f"  IPv4 packets  : {self.stats['ipv4_packets']}")
        print(f"  IPv6 packets  : {self.stats['ipv6_packets']}")
        print(f"  BGP TCP pkts  : {self.stats['bgp_tcp_packets']}")
        print(f"  Unique IPs    : {len(self._seen_ips)}")
        print(f"  Unique MACs   : {len(self._seen_macs)}")
        print(f"  Unique ASNs   : {len(self._seen_asns)}")
        print(f"  Unique RDs    : {len(self._seen_rds)}")
        print(f"  Unique RTs/ECs: {len(self._seen_rts)}")
        print(f"  Unique VNIs   : {len(self._seen_vnis)}")
        print(f"  Unique ESIs   : {len(self._seen_esis)}")
        print(f"  Unique FQDNs  : {len(self._seen_fqdns)}")
        bgp_open  = self.stats.get("bgp_type_1", 0)
        bgp_upd   = self.stats.get("bgp_type_2", 0)
        bgp_notif = self.stats.get("bgp_type_3", 0)
        bgp_ka    = self.stats.get("bgp_type_4", 0)
        print(f"  BGP OPEN      : {bgp_open}")
        print(f"  BGP UPDATE    : {bgp_upd}")
        print(f"  BGP NOTIFY    : {bgp_notif}")
        print(f"  BGP KEEPALIVE : {bgp_ka}")

        # ── TCP Auth ────────────────────────────────────────────────────
        if self.tcp_auth_detected:
            print(bold(f"\n🔴 TCP AUTHENTICATION CREDENTIALS DETECTED"))
            print(sep)
            for a in self.tcp_auth_detected:
                print(f"  {red('⚠️  ' + a)} — MUST be removed before any distribution")

        # ── FQDNs ───────────────────────────────────────────────────────
        if self._seen_fqdns:
            print(bold(f"\n🔴 HOSTNAMES / FQDNs FOUND (via BGP FQDN capability)"))
            print(sep)
            for fqdn in sorted(self._seen_fqdns):
                print(f"  {red(fqdn)} — reveals device identity")

        # ── BGP Notifications ───────────────────────────────────────────
        if self.bgp_notifications:
            print(bold(f"\n⚠️  BGP NOTIFICATIONS (errors/failures) — {len(self.bgp_notifications)} found"))
            print(sep)
            for n in self.bgp_notifications:
                print(f"  Session : {n['session']}")
                print(f"  Error   : {yellow(n['error_name'])} / {n['subcode_name']}")
                if n["data_hex"]:
                    print(f"  Data    : {n['data_hex']}")
                print()

        # ── IP Addresses ────────────────────────────────────────────────
        print(bold(f"\n🌐 IP ADDRESSES"))
        print(sep)

        ipv4_addrs = sorted([ip for ip in self._seen_ips.keys() if ':' not in ip])
        ipv6_addrs = sorted([ip for ip in self._seen_ips.keys() if ':' in ip])

        if ipv4_addrs:
            print(f"  IPv4 ({len(ipv4_addrs)}):")
            for ip in ipv4_addrs:
                print(f"     {ip}")
        if ipv6_addrs:
            print(f"\n  IPv6 ({len(ipv6_addrs)}):")
            for ip in ipv6_addrs:
                print(f"     {ip}")

        # ── MAC Addresses ───────────────────────────────────────────────
        print(bold(f"\n📡 MAC ADDRESSES"))
        print(sep)
        for mac, vendor in sorted(self._seen_macs.items()):
            print(f"  {mac:20s}  vendor: {vendor}")

        # ── AS Numbers ──────────────────────────────────────────────────
        print(bold(f"\n🔢 AS NUMBERS"))
        print(sep)
        for asn, (label, flag) in sorted(self._seen_asns.items()):
            print(f"  ASN {asn:<12} {label}")

        # ── Route Distinguishers ────────────────────────────────────────
        if self._seen_rds:
            print(bold(f"\n🗂️  ROUTE DISTINGUISHERS"))
            print(sep)
            for rd_hex in sorted(self._seen_rds):
                try:
                    decoded = decode_rd(bytes.fromhex(rd_hex))
                except Exception:
                    decoded = rd_hex
                print(f"  {decoded}")

        # ── Extended Communities / Route Targets ────────────────────────
        if self._seen_rts:
            print(bold(f"\n🏷️  EXTENDED COMMUNITIES / ROUTE TARGETS"))
            print(sep)
            for ec_hex in sorted(self._seen_rts):
                decoded = decode_ext_community(ec_hex)
                print(f"  {decoded}")

        # ── BGP Communities ─────────────────────────────────────────────
        std_comms = [c for c in self._seen_comms if isinstance(c, tuple)]
        lrg_comms = [c for c in self._seen_comms if isinstance(c, str) and c.count(":") == 2]
        if std_comms or lrg_comms:
            print(bold(f"\n💬 BGP COMMUNITIES"))
            print(sep)
            for asn, val in sorted(std_comms):
                print(f"  {asn}:{val}")
            for lc in sorted(lrg_comms):
                print(f"  {lc}  (large community)")

        # ── VNIs ────────────────────────────────────────────────────────
        if self._seen_vnis:
            print(bold(f"\n🔖 VNIs (VXLAN Network Identifiers)"))
            print(sep)
            for vni in sorted(self._seen_vnis):
                print(f"  VNI {vni}")

        # ── ESIs ────────────────────────────────────────────────────────
        if self._seen_esis:
            print(bold(f"\n🔗 ETHERNET SEGMENT IDs (ESI)"))
            print(sep)
            for esi in sorted(self._seen_esis):
                print(f"  {esi}")

        # ── BGP Capabilities ────────────────────────────────────────────
        if self.bgp_capabilities:
            print(bold(f"\n⚙️  BGP CAPABILITIES ADVERTISED (per session)"))
            print(sep)
            for session, caps in self.bgp_capabilities.items():
                print(f"  Session: {session}")
                for cap_key in sorted(caps):
                    code = int(cap_key.split("-")[0])
                    name = BGP_CAP_NAMES.get(code, f"code {code}")
                    print(f"    • {name}")

        print(bold(f"\n{'='*70}\n"))

    def save_report(self, path):
        """Save findings to a text file."""
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._print_report()
        with open(path, "w", encoding="utf-8") as f:
            f.write(buf.getvalue())
        print(f"Report saved to: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="BGP/EVPN PCAP Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("pcap", help="Path to the PCAP file to inspect")
    parser.add_argument("--output", "-o", help="Save report to file", default=None)
    args = parser.parse_args()

    inspector = PcapInspector(args.pcap)
    inspector.scan()
    if args.output:
        inspector.save_report(args.output)


if __name__ == "__main__":
    main()