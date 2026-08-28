"""Pcap file writer for synthetic BGP/EVPN captures.

Assembles CookedLinuxV2 + IP + TCP packets from TCPPacket objects
and writes them to pcap files using scapy.
"""

from pathlib import Path
from typing import Optional
from scapy.all import (
    CookedLinuxV2, IP, TCP, Raw,
    wrpcap, Packet, conf
)
import struct
import ipaddress

# Import the TCPPacket dataclass
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from generators.evpn_bgp.tcp.session import TCPPacket


class PcapWriter:
    """Assembles and writes pcap files from TCPPacket objects.
    
    Usage:
        writer = PcapWriter()
        
        # Add packets from TCP sessions
        for tcp_pkt in session_packets:
            writer.add_packet(tcp_pkt)
        
        # Write to file
        writer.write("output.pcap")
    """
    
    def __init__(self, vantage_ip: str = None):
        """Initialize writer.
        
        Args:
            vantage_ip: IP of the capture vantage point. Used to set
                       pkttype (outgoing vs incoming). If None, all
                       packets use pkttype=0 (incoming).
        """
        self.packets: list[Packet] = []
        self.vantage_ip = vantage_ip
    
    def add_packet(self, tcp_pkt: TCPPacket) -> None:
        """Convert a TCPPacket to a scapy packet and add to the capture.
        
        Assembles: CookedLinuxV2 / IPv6 / TCP / [Raw payload]
        """
        # Determine packet direction relative to vantage
        if self.vantage_ip and tcp_pkt.src_ip == self.vantage_ip:
            pkttype = 4  # Outgoing from vantage
        else:
            pkttype = 0  # Incoming to vantage (or unknown)
        
        # Build CookedLinuxV2 header
        sll2 = CookedLinuxV2(
            proto=0x0800,    # IPv4
            ifindex=0,
            lladdrtype=1,    # Ethernet
            pkttype=pkttype,
        )

        # Build IP header
        ip_hdr = IP(
            src=tcp_pkt.src_ip,
            dst=tcp_pkt.dst_ip,
            proto=6,         # TCP
            ttl=64,
        )
        
        # Build TCP header
        tcp = TCP(
            sport=tcp_pkt.sport,
            dport=tcp_pkt.dport,
            seq=tcp_pkt.seq & 0xFFFFFFFF,  # Ensure 32-bit
            ack=tcp_pkt.ack & 0xFFFFFFFF,
            flags=tcp_pkt.flags,
            window=tcp_pkt.window,
        )
        
        # Assemble packet
        if tcp_pkt.payload:
            pkt = sll2 / ip_hdr / tcp / Raw(load=tcp_pkt.payload)
        else:
            pkt = sll2 / ip_hdr / tcp
        
        # Set timestamp
        pkt.time = tcp_pkt.timestamp
        
        self.packets.append(pkt)
    
    def add_packets(self, tcp_pkts: list[TCPPacket]) -> None:
        """Add multiple packets at once."""
        for pkt in tcp_pkts:
            self.add_packet(pkt)
    
    def write(self, output_path: str | Path) -> None:
        """Write all packets to a pcap file.
        
        Args:
            output_path: Path to output .pcap file
        
        Creates parent directories if they don't exist.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Sort packets by timestamp before writing
        self.packets.sort(key=lambda p: float(p.time))
        
        # Write using scapy (linktype for CookedLinuxV2 = 276)
        wrpcap(str(path), self.packets, linktype=276)
    
    def clear(self) -> None:
        """Clear all stored packets."""
        self.packets = []
    
    @property
    def packet_count(self) -> int:
        """Number of packets currently stored."""
        return len(self.packets)


def write_pcap(tcp_packets: list[TCPPacket], output_path: str | Path, 
               vantage_ip: str = None) -> int:
    """Convenience function to write packets directly to pcap.
    
    Args:
        tcp_packets: List of TCPPacket objects
        output_path: Path to output .pcap file
        vantage_ip: Optional vantage IP for direction marking
    
    Returns:
        Number of packets written
    """
    writer = PcapWriter(vantage_ip=vantage_ip)
    writer.add_packets(tcp_packets)
    writer.write(output_path)
    return writer.packet_count
