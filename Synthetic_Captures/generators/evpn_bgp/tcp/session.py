"""TCP session state machine for synthetic BGP pcap generation.

Manages TCP connection lifecycle including:
- 3-way handshake (SYN → SYN-ACK → ACK)
- Data transfer with proper seq/ack tracking
- Graceful shutdown (FIN → FIN-ACK → ACK)
- Abrupt disconnect (RST)
- Window size simulation
"""

import random
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class TCPState(Enum):
    """TCP connection states."""
    CLOSED = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()


@dataclass
class TCPPacket:
    """Represents a TCP packet with all necessary fields for pcap assembly."""
    src_ip: str          # IPv4 source address
    dst_ip: str          # IPv4 destination address
    sport: int           # Source port
    dport: int           # Destination port
    seq: int             # Sequence number
    ack: int             # Acknowledgment number
    flags: int           # TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08)
    window: int          # Window size
    payload: bytes       # TCP payload (BGP messages)
    timestamp: float     # Packet timestamp (seconds since epoch)
    event_label: bool = False   # True if this packet is a direct fault-injection event
    event_fault_type: str = None   # Single-mechanism fault name active when this packet was marked
    event_affected_node: str = None   # Root-cause node id active when this packet was marked
    event_trigger_mechanism: str = None   # Wire-level trigger (TCP RST / Graceful FIN Close / BGP NOTIFICATION: <code> / Route UPDATE)
    event_phase: str = None   # 'trigger' | 'propagation' | 'recovery' -- which phase of the fault lifecycle produced this event

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def is_psh(self) -> bool:
        return bool(self.flags & 0x08)


# TCP Flag constants
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

# 32-bit sequence number mask
_SEQ_MASK = 0xFFFFFFFF


def _wrap_seq(seq: int) -> int:
    """Wrap sequence number to 32-bit unsigned range."""
    return seq & _SEQ_MASK


class TCPSession:
    """Manages a single TCP session between two endpoints.

    Tracks state, sequence numbers, and generates packets for:
    - Connection establishment (3-way handshake)
    - Data transfer (with ACKs)
    - Connection teardown (FIN or RST)

    Usage:
        session = TCPSession(
            client_ip="2001:db8::2:1",
            server_ip="2001:db8::1:1",
            server_port=179,  # BGP
        )

        # Generate handshake packets
        packets = session.connect(timestamp=1000.0)

        # Send BGP data (client → server)
        packets += session.send_data(bgp_message_bytes, timestamp=1000.5, direction='client_to_server')

        # Generate ACK (server → client)
        packets += session.generate_ack(timestamp=1000.501, direction='server_to_client')

        # Teardown
        packets += session.close_graceful(timestamp=2000.0, initiator='client')
        # OR
        packets += session.close_reset(timestamp=2000.0, initiator='server')
    """

    def __init__(self, client_ip: str, server_ip: str, server_port: int = 179,
                 client_port: int = None, window_size: int = 65535,
                 mss: int = 1460):
        """Initialize TCP session.

        Args:
            client_ip: IPv4 address of the client (initiator)
            server_ip: IPv4 address of the server (BGP listener on port 179)
            server_port: Server port (default 179 for BGP)
            client_port: Client ephemeral port (random if not specified)
            window_size: TCP window size
            mss: Maximum Segment Size
        """
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port or random.randint(32768, 60999)
        self.window_size = window_size
        self.mss = mss

        # Sequence numbers (initialized on connect)
        self.client_seq = 0  # ISN for client
        self.server_seq = 0  # ISN for server
        self.client_ack = 0  # What client has ACK'd
        self.server_ack = 0  # What server has ACK'd

        self.state = TCPState.CLOSED

    def connect(self, timestamp: float) -> list[TCPPacket]:
        """Generate 3-way handshake packets.

        Returns 3 packets: SYN, SYN-ACK, ACK
        Advances time by small increments for realism.
        """
        packets = []

        # Initialize ISNs
        self.client_seq = random.randint(100000, 4000000000)
        self.server_seq = random.randint(100000, 4000000000)

        # SYN (client → server)
        packets.append(TCPPacket(
            src_ip=self.client_ip,
            dst_ip=self.server_ip,
            sport=self.client_port,
            dport=self.server_port,
            seq=self.client_seq,
            ack=0,
            flags=TCP_SYN,
            window=self.window_size,
            payload=b'',
            timestamp=timestamp,
        ))
        self.client_seq = _wrap_seq(self.client_seq + 1)  # SYN consumes 1 seq
        self.state = TCPState.SYN_SENT

        # SYN-ACK (server → client)
        t_synack = timestamp + random.uniform(0.0005, 0.003)
        packets.append(TCPPacket(
            src_ip=self.server_ip,
            dst_ip=self.client_ip,
            sport=self.server_port,
            dport=self.client_port,
            seq=self.server_seq,
            ack=self.client_seq,
            flags=TCP_SYN | TCP_ACK,
            window=self.window_size,
            payload=b'',
            timestamp=t_synack,
        ))
        self.server_seq = _wrap_seq(self.server_seq + 1)  # SYN-ACK consumes 1 seq
        self.server_ack = self.client_seq
        self.state = TCPState.SYN_RECEIVED

        # ACK (client → server)
        t_ack = t_synack + random.uniform(0.0002, 0.001)
        self.client_ack = self.server_seq
        packets.append(TCPPacket(
            src_ip=self.client_ip,
            dst_ip=self.server_ip,
            sport=self.client_port,
            dport=self.server_port,
            seq=self.client_seq,
            ack=self.client_ack,
            flags=TCP_ACK,
            window=self.window_size,
            payload=b'',
            timestamp=t_ack,
        ))
        self.state = TCPState.ESTABLISHED

        return packets

    def send_data(self, data: bytes, timestamp: float,
                  direction: str = 'client_to_server') -> list[TCPPacket]:
        """Send data and return the data packet(s).

        For large payloads, segments into multiple packets based on MSS.
        Does NOT generate the ACK — call generate_ack() separately for realism.

        Args:
            data: Payload bytes (e.g., BGP message)
            timestamp: Packet timestamp
            direction: 'client_to_server' or 'server_to_client'

        Returns:
            List of TCPPacket(s) carrying the data.
        """
        if self.state != TCPState.ESTABLISHED:
            raise RuntimeError(f"Cannot send data in state {self.state}")

        packets = []
        offset = 0
        t = timestamp

        while offset < len(data):
            segment = data[offset:offset + self.mss]

            if direction == 'client_to_server':
                pkt = TCPPacket(
                    src_ip=self.client_ip,
                    dst_ip=self.server_ip,
                    sport=self.client_port,
                    dport=self.server_port,
                    seq=self.client_seq,
                    ack=self.client_ack,
                    flags=TCP_PSH | TCP_ACK,
                    window=self.window_size,
                    payload=segment,
                    timestamp=t,
                )
                self.client_seq = _wrap_seq(self.client_seq + len(segment))
            else:
                pkt = TCPPacket(
                    src_ip=self.server_ip,
                    dst_ip=self.client_ip,
                    sport=self.server_port,
                    dport=self.client_port,
                    seq=self.server_seq,
                    ack=self.server_ack,
                    flags=TCP_PSH | TCP_ACK,
                    window=self.window_size,
                    payload=segment,
                    timestamp=t,
                )
                self.server_seq = _wrap_seq(self.server_seq + len(segment))

            packets.append(pkt)
            offset += len(segment)
            t += random.uniform(0.00001, 0.0001)  # Tiny gap between segments

        return packets

    def generate_ack(self, timestamp: float, direction: str = 'server_to_client') -> list[TCPPacket]:
        """Generate a pure ACK for the last received data.

        Args:
            timestamp: Packet timestamp
            direction: Direction of the ACK ('server_to_client' means server ACKs client's data)
        """
        if direction == 'server_to_client':
            # Server acknowledges client's data
            self.server_ack = self.client_seq
            return [TCPPacket(
                src_ip=self.server_ip,
                dst_ip=self.client_ip,
                sport=self.server_port,
                dport=self.client_port,
                seq=self.server_seq,
                ack=self.server_ack,
                flags=TCP_ACK,
                window=self.window_size,
                payload=b'',
                timestamp=timestamp,
            )]
        else:
            # Client acknowledges server's data
            self.client_ack = self.server_seq
            return [TCPPacket(
                src_ip=self.client_ip,
                dst_ip=self.server_ip,
                sport=self.client_port,
                dport=self.server_port,
                seq=self.client_seq,
                ack=self.client_ack,
                flags=TCP_ACK,
                window=self.window_size,
                payload=b'',
                timestamp=timestamp,
            )]

    def close_graceful(self, timestamp: float, initiator: str = 'client') -> list[TCPPacket]:
        """Generate graceful TCP close (FIN exchange).

        Returns 4 packets: FIN, ACK, FIN, ACK

        Args:
            timestamp: Start time of close sequence
            initiator: Who initiates ('client' or 'server')
        """
        packets = []
        t = timestamp

        if initiator == 'client':
            # FIN from client
            packets.append(TCPPacket(
                src_ip=self.client_ip, dst_ip=self.server_ip,
                sport=self.client_port, dport=self.server_port,
                seq=self.client_seq, ack=self.client_ack,
                flags=TCP_FIN | TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))
            self.client_seq = _wrap_seq(self.client_seq + 1)

            # ACK from server
            t += random.uniform(0.0005, 0.002)
            self.server_ack = self.client_seq
            packets.append(TCPPacket(
                src_ip=self.server_ip, dst_ip=self.client_ip,
                sport=self.server_port, dport=self.client_port,
                seq=self.server_seq, ack=self.server_ack,
                flags=TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))

            # FIN from server
            t += random.uniform(0.0001, 0.001)
            packets.append(TCPPacket(
                src_ip=self.server_ip, dst_ip=self.client_ip,
                sport=self.server_port, dport=self.client_port,
                seq=self.server_seq, ack=self.server_ack,
                flags=TCP_FIN | TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))
            self.server_seq = _wrap_seq(self.server_seq + 1)

            # ACK from client
            t += random.uniform(0.0002, 0.001)
            self.client_ack = self.server_seq
            packets.append(TCPPacket(
                src_ip=self.client_ip, dst_ip=self.server_ip,
                sport=self.client_port, dport=self.server_port,
                seq=self.client_seq, ack=self.client_ack,
                flags=TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))
        else:
            # FIN from server
            packets.append(TCPPacket(
                src_ip=self.server_ip, dst_ip=self.client_ip,
                sport=self.server_port, dport=self.client_port,
                seq=self.server_seq, ack=self.server_ack,
                flags=TCP_FIN | TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))
            self.server_seq = _wrap_seq(self.server_seq + 1)

            # ACK from client
            t += random.uniform(0.0005, 0.002)
            self.client_ack = self.server_seq
            packets.append(TCPPacket(
                src_ip=self.client_ip, dst_ip=self.server_ip,
                sport=self.client_port, dport=self.server_port,
                seq=self.client_seq, ack=self.client_ack,
                flags=TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))

            # FIN from client
            t += random.uniform(0.0001, 0.001)
            packets.append(TCPPacket(
                src_ip=self.client_ip, dst_ip=self.server_ip,
                sport=self.client_port, dport=self.server_port,
                seq=self.client_seq, ack=self.client_ack,
                flags=TCP_FIN | TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))
            self.client_seq = _wrap_seq(self.client_seq + 1)

            # ACK from server
            t += random.uniform(0.0002, 0.001)
            self.server_ack = self.client_seq
            packets.append(TCPPacket(
                src_ip=self.server_ip, dst_ip=self.client_ip,
                sport=self.server_port, dport=self.client_port,
                seq=self.server_seq, ack=self.server_ack,
                flags=TCP_ACK, window=self.window_size,
                payload=b'', timestamp=t,
            ))

        self.state = TCPState.CLOSED
        return packets

    def close_reset(self, timestamp: float, initiator: str = 'server') -> list[TCPPacket]:
        """Generate abrupt TCP reset (RST).

        Used when a link/device goes down unexpectedly.
        Returns a single RST packet.

        Args:
            timestamp: Time of reset
            initiator: Who sends RST ('client' or 'server')
        """
        if initiator == 'server':
            pkt = TCPPacket(
                src_ip=self.server_ip, dst_ip=self.client_ip,
                sport=self.server_port, dport=self.client_port,
                seq=self.server_seq, ack=self.server_ack,
                flags=TCP_RST | TCP_ACK, window=0,
                payload=b'', timestamp=timestamp,
            )
        else:
            pkt = TCPPacket(
                src_ip=self.client_ip, dst_ip=self.server_ip,
                sport=self.client_port, dport=self.server_port,
                seq=self.client_seq, ack=self.client_ack,
                flags=TCP_RST | TCP_ACK, window=0,
                payload=b'', timestamp=timestamp,
            )

        self.state = TCPState.CLOSED
        return [pkt]

    def is_established(self) -> bool:
        """Check if session is established."""
        return self.state == TCPState.ESTABLISHED

    def is_closed(self) -> bool:
        """Check if session is closed."""
        return self.state == TCPState.CLOSED
