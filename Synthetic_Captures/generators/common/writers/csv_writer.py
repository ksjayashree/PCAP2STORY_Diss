"""Write per-pcap BGP feature CSVs alongside pcap files.

Called by BaseScenario.write() immediately after write_pcap().
Parses BGP payloads from TCPPacket objects and emits one CSV row per BGP
message, including the event_label ground-truth column set by each scenario.
"""

import csv
from datetime import datetime, timezone
from pathlib import Path

from .bgp_evpn_wire_parser import parse_bgp_payload


# ── IP → Node ID, Node-pair → Link ID (topology-derived) ───────────────────


def build_ip_to_node(config) -> dict:
    """Derive {bgp_id: node_id} from a TopologyConfig.

    Node ids are assigned by config-list order, PEs first then RRs,
    starting at 1.
    """
    ip_to_node = {}
    node_id = 1
    for pe in config.pe_nodes:
        ip_to_node[pe.bgp_id] = node_id
        node_id += 1
    for rr in config.route_reflectors:
        ip_to_node[rr.bgp_id] = node_id
        node_id += 1
    return ip_to_node


def build_link_identity(config, ip_to_node: dict) -> dict:
    """Derive {(node_id, node_id): link_id} (both directions) from a
    TopologyConfig, covering every PE-RR pair and every RR-RR pair.

    Assignment order:
      1. Each PE's home link (its declared peers[0] RR), in pe_nodes
         config-list order.
      2. Each RR-RR pair, in route_reflectors config-list order.
      3. Each remaining PE-to-non-home-RR ("away") pair, grouped by RR
         (route_reflectors order), then by PE (pe_nodes order) within
         each RR.
    """
    link_identity = {}
    next_id = 1

    def _assign(id_a: int, id_b: int):
        nonlocal next_id
        if (id_a, id_b) in link_identity:
            return
        link_identity[(id_a, id_b)] = next_id
        link_identity[(id_b, id_a)] = next_id
        next_id += 1

    home_rr_of = {}
    for pe in config.pe_nodes:
        home_rr_id = pe.peers[0] if pe.peers else None
        home_rr_of[pe.id] = home_rr_id
        if home_rr_id is not None:
            rr = config.get_router(home_rr_id)
            if rr is not None:
                _assign(ip_to_node[pe.bgp_id], ip_to_node[rr.bgp_id])

    rrs = config.route_reflectors
    for i in range(len(rrs)):
        for j in range(i + 1, len(rrs)):
            _assign(ip_to_node[rrs[i].bgp_id], ip_to_node[rrs[j].bgp_id])

    for rr in rrs:
        for pe in config.pe_nodes:
            if home_rr_of.get(pe.id) == rr.id:
                continue
            _assign(ip_to_node[pe.bgp_id], ip_to_node[rr.bgp_id])

    return link_identity

# TCP control flags that qualify a payload-less packet as its own CSV row
# (packet_type='tcp_control'). Plain ACKs (no SYN/FIN/RST bit) are excluded.
TCP_SYN = 0x02
TCP_FIN = 0x01
TCP_RST = 0x04
_TCP_LIFECYCLE_FLAGS = TCP_SYN | TCP_FIN | TCP_RST

# Every distinct TCP flags byte value the generator produces.
TCP_MSG_TYPE = {
    0x02: 'SYN',
    0x12: 'SYN-ACK',
    0x10: 'ACK',
    0x18: 'PSH-ACK',
    0x11: 'FIN-ACK',
    0x14: 'RST-ACK',
}

CSV_FIELDNAMES = [
    'pcap_file', 'fault_type', 'section',
    'relative_timestamp', 'inter_event_delta', 'absolute_timestamp',
    'source', 'destination', 'link_identity', 'tcp_seq_no',
    'bgp_msg_type', 'bgp_msg_significance', 'packet_type', 'route_action',
    'error_code', 'error_code_severity',
    'error_subcode', 'error_subcode_severity',
    'evpn_route_type', 'next_hop', 'route_target',
    'mac_address', 'ip_prefix', 'esi', 'originator_id',
    'event_label', 'event_fault_type', 'event_affected_node', 'event_trigger_mechanism',
    'event_phase',
    'tcp_msg_type',
]


# ── Public writer ─────────────────────────────────────────────────────────────

def write_csv(packets: list, output_path: 'str | Path',
              pcap_file: str, fault_type: str = 'Normal', section: int = 1,
              config=None) -> int:
    """Parse BGP from packets and write one CSV row per BGP message.

    The event_label is read directly from each TCPPacket's boolean flag,
    which scenarios set before calling write().

    config: TopologyConfig used to derive IP_TO_NODE/LINK_IDENTITY for this
    run's actual topology (see build_ip_to_node/build_link_identity above).
    Required.

    Returns the number of BGP event rows written.
    """
    if not packets:
        return 0
    if config is None:
        raise ValueError("write_csv() requires config= to derive IP_TO_NODE/LINK_IDENTITY")

    ip_to_node = build_ip_to_node(config)
    link_identity = build_link_identity(config, ip_to_node)

    start_time = packets[0].timestamp
    rows = []
    last_ts_per_link = {}  # link_id -> relative_timestamp of last BGP event on that link

    for pkt in packets:
        is_tcp_lifecycle = bool(pkt.flags & _TCP_LIFECYCLE_FLAGS)
        if not pkt.payload and not pkt.event_label and not is_tcp_lifecycle:
            continue
        if pkt.dport != 179 and pkt.sport != 179:
            continue

        src_node = ip_to_node.get(pkt.src_ip, 0)
        dst_node = ip_to_node.get(pkt.dst_ip, 0)
        link_id  = link_identity.get((src_node, dst_node), 0)
        relative_ts = round(pkt.timestamp - start_time, 4)
        inter_event_delta = round(relative_ts - last_ts_per_link.get(link_id, relative_ts), 4)
        last_ts_per_link[link_id] = relative_ts
        dt = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc)
        abs_ts = dt.strftime('%d_%m_%Y_%H_%M_%S_') + f"{dt.microsecond // 1000:03d}"

        if not pkt.payload:
            # TCP-layer lifecycle event (SYN/SYN-ACK/FIN/RST, or a labeled
            # event with no BGP message); every BGP-specific field is None/'n/a'.
            messages = [{
                'bgp_msg_type': None, 'bgp_msg_significance': None,
                'packet_type': 'tcp_control', 'route_action': 'n/a',
                'error_code': None, 'error_code_severity': None,
                'error_subcode': None, 'error_subcode_severity': None,
                'evpn_route_type': None, 'next_hop': None,
                'route_target': None,
                'mac_address': None, 'ip_prefix': None, 'esi': None,
                'originator_id': None,
            }]
        else:
            messages = parse_bgp_payload(pkt.payload)

        for msg in messages:
            rows.append({
                'pcap_file':              pcap_file,
                'fault_type':             fault_type,
                'section':                section,
                'relative_timestamp':     relative_ts,
                'inter_event_delta':      inter_event_delta,
                'absolute_timestamp':     abs_ts,
                'source':                 src_node,
                'destination':            dst_node,
                'link_identity':          link_id,
                'tcp_seq_no':             pkt.seq,
                'bgp_msg_type':           msg['bgp_msg_type'],
                'bgp_msg_significance':   msg['bgp_msg_significance'],
                'packet_type':            msg['packet_type'],
                'route_action':           msg['route_action'],
                'error_code':             msg['error_code'],
                'error_code_severity':    msg['error_code_severity'],
                'error_subcode':          msg['error_subcode'],
                'error_subcode_severity': msg['error_subcode_severity'],
                'evpn_route_type':        msg['evpn_route_type'],
                'next_hop':               msg['next_hop'],
                'route_target':           msg['route_target'],
                'mac_address':            msg['mac_address'],
                'ip_prefix':              msg['ip_prefix'],
                'esi':                    msg['esi'],
                'originator_id':          msg['originator_id'],
                'event_label':            int(pkt.event_label),
                'event_fault_type':       pkt.event_fault_type if pkt.event_label else None,
                'event_affected_node':    pkt.event_affected_node if pkt.event_label else None,
                'event_trigger_mechanism': pkt.event_trigger_mechanism if pkt.event_label else None,
                'event_phase':            pkt.event_phase if pkt.event_label else None,
                'tcp_msg_type':           TCP_MSG_TYPE.get(pkt.flags, f'UNKNOWN(0x{pkt.flags:02x})'),
            })

    # Combo fault_type strings use '+' at the class-attribute level;
    # rejoin with ';' for CSV output.
    if '+' in fault_type:
        normalized_fault_type = ';'.join(p.strip() for p in fault_type.split('+'))
    else:
        normalized_fault_type = fault_type
    for row in rows:
        row['fault_type'] = normalized_fault_type

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)
