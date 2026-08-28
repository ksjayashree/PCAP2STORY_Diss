"""Core data models for BGP/EVPN PCAP analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class BgpMsgType(IntEnum):
    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4
    ROUTE_REFRESH = 5


class EvpnRouteType(IntEnum):
    ETHERNET_AD = 1
    MAC_IP_ADV = 2
    IMET = 3
    ETHERNET_SEGMENT = 4
    IP_PREFIX = 5


class Severity:
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"


@dataclass
class BgpMessage:
    frame_number: int
    timestamp: float
    msg_type: int
    tcp_stream: int
    src_ip: str
    dst_ip: str
    raw: dict = field(repr=False, default_factory=dict)


@dataclass
class BgpCapabilities:
    """Capabilities advertised in a BGP OPEN message."""
    four_octet_as: bool = False
    multiprotocol: list[tuple[int, int]] = field(default_factory=list)
    route_refresh: bool = False
    graceful_restart: bool = False
    evpn: bool = False
    asn: int = 0
    hold_time: int = 0


@dataclass
class EvpnRoute:
    frame_number: int
    timestamp: float
    route_type: int
    rd: str = ""
    route_targets: list[str] = field(default_factory=list)
    esi: str = ""
    ethernet_tag: int = 0
    mac: str = ""
    ip: str = ""
    next_hop: str = ""
    label: int = 0
    is_withdrawal: bool = False
    src_ip: str = ""
    dst_ip: str = ""
    tcp_stream: int = 0
    raw: dict = field(repr=False, default_factory=dict)


@dataclass
class BgpSession:
    """Tracks the state of a BGP session on a single TCP stream."""
    tcp_stream: int
    src_ip: str = ""
    dst_ip: str = ""
    open_received: bool = False
    open_sent: bool = False
    keepalive_received: bool = False
    established: bool = False
    terminated: bool = False
    capabilities: BgpCapabilities = field(default_factory=BgpCapabilities)
    remote_capabilities: BgpCapabilities = field(default_factory=BgpCapabilities)
    messages: list[BgpMessage] = field(default_factory=list)


@dataclass
class MacEntry:
    """A MAC table entry tracking advertise/withdraw state."""
    mac: str
    ip: str = ""
    evi: int = 0
    esi: str = ""
    next_hop: str = ""
    frame_advertised: int = 0
    frame_withdrawn: int = 0
    is_active: bool = True
    move_count: int = 0


@dataclass
class Finding:
    severity: str
    code: str
    frame: int
    message: str
    impact: str = ""
    evidence: dict = field(default_factory=dict)
    confidence: str = "high"

    def __str__(self) -> str:
        return f"{self.severity} {self.code} frame {self.frame}: {self.message}"


@dataclass
class Scenario:
    """Parsed scenario definition for expected behaviour."""
    peers: dict[str, dict[str, Any]] = field(default_factory=dict)
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    checks: dict[str, bool] = field(default_factory=dict)

    @property
    def require_imet_before_mac(self) -> bool:
        return self.checks.get("require_imet_before_mac", True)

    @property
    def require_evpn_capability(self) -> bool:
        return self.checks.get("require_evpn_capability", True)

    @property
    def allow_partial_capture(self) -> bool:
        return self.checks.get("allow_partial_capture", False)
