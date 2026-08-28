"""Configuration loading and validation for pcap generator.

Loads topology from YAML files and provides structured access to
network elements, BGP parameters, and EVPN settings.
"""

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RouterConfig:
    """Configuration for a single router (PE or RR)."""
    id: str                    # Human-readable ID (e.g., "PE1", "RR1")
    loopback: str              # IPv6 loopback address (used for BGP peering)
    bgp_id: str                # BGP Router ID (IPv4 dotted-quad)
    role: str                  # "pe" or "rr"
    peers: list[str] = field(default_factory=list)  # List of peer IDs this router connects to
    esi: Optional[str] = None  # Ethernet Segment ID (for multi-homing PEs)
    route_distinguisher: Optional[str] = None  # RD override (default: <loopback>:vni)


@dataclass
class EVPNConfig:
    """EVPN-specific configuration."""
    vni: int = 100
    route_target: str = "65001:100"  # Import/export RT
    mac_pool_size: int = 50          # Number of simulated MAC addresses per PE
    ip_prefix_pool: str = "192.168.0.0/16"  # Pool for IP prefix routes
    srv6_locator_prefix: str = "2001:db8:ffff::/48"  # SRv6 locator


@dataclass
class TimingConfig:
    """BGP timing parameters."""
    hold_timer: int = 30          # Hold timer in seconds
    keepalive_timer: int = 10     # Keepalive interval (typically hold_timer / 3)
    connect_retry: int = 30       # Connect retry timer
    min_route_adv_interval: int = 0  # MRAI for iBGP (usually 0)


@dataclass
class TopologyConfig:
    """Complete topology configuration."""
    as_number: int
    timing: TimingConfig
    evpn: EVPNConfig
    routers: list[RouterConfig]
    capture_vantage: str = "RR1"  # Default capture point

    @property
    def route_reflectors(self) -> list[RouterConfig]:
        return [r for r in self.routers if r.role == 'rr']

    @property
    def pe_nodes(self) -> list[RouterConfig]:
        return [r for r in self.routers if r.role == 'pe']

    def get_router(self, router_id: str) -> Optional[RouterConfig]:
        """Get router by ID."""
        for r in self.routers:
            if r.id == router_id:
                return r
        return None

    def get_peers_of(self, router_id: str) -> list[RouterConfig]:
        """Get all peer routers for a given router."""
        router = self.get_router(router_id)
        if not router:
            return []
        return [self.get_router(pid) for pid in router.peers if self.get_router(pid)]

    def get_sessions_at_vantage(self, vantage_id: str = None) -> list[tuple[RouterConfig, RouterConfig]]:
        """Get all BGP sessions visible from a capture vantage point.

        Returns list of (local_router, remote_router) tuples where
        the vantage router is one endpoint.
        """
        vantage = vantage_id or self.capture_vantage
        vantage_router = self.get_router(vantage)
        if not vantage_router:
            return []

        sessions = []
        for peer_id in vantage_router.peers:
            peer = self.get_router(peer_id)
            if peer:
                sessions.append((vantage_router, peer))

        # Also include sessions where other routers peer TO the vantage
        for router in self.routers:
            if router.id != vantage and vantage in router.peers:
                if (vantage_router, router) not in sessions:
                    sessions.append((vantage_router, router))

        return sessions

    def get_multihomed_peers(self) -> list[tuple[RouterConfig, RouterConfig]]:
        """Get pairs of PEs that share the same ESI (multi-homed)."""
        esi_map: dict[str, list[RouterConfig]] = {}
        for pe in self.pe_nodes:
            if pe.esi:
                esi_map.setdefault(pe.esi, []).append(pe)

        pairs = []
        for esi, pes in esi_map.items():
            if len(pes) >= 2:
                for i in range(len(pes)):
                    for j in range(i + 1, len(pes)):
                        pairs.append((pes[i], pes[j]))
        return pairs


def load_config(config_path: str | Path) -> TopologyConfig:
    """Load topology configuration from a YAML file.

    Args:
        config_path: Path to YAML config file

    Returns:
        TopologyConfig object

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, 'r') as f:
        raw = yaml.safe_load(f)

    return parse_config(raw)


def parse_config(raw: dict) -> TopologyConfig:
    """Parse raw YAML dict into TopologyConfig."""
    # Timing
    timing_raw = raw.get('timing', {})
    timing = TimingConfig(
        hold_timer=timing_raw.get('hold_timer', 30),
        keepalive_timer=timing_raw.get('keepalive_timer', 10),
        connect_retry=timing_raw.get('connect_retry', 30),
        min_route_adv_interval=timing_raw.get('min_route_adv_interval', 0),
    )

    # EVPN
    evpn_raw = raw.get('evpn', {})
    evpn = EVPNConfig(
        vni=evpn_raw.get('vni', 100),
        route_target=evpn_raw.get('route_target', f"{raw.get('as_number', 65001)}:100"),
        mac_pool_size=evpn_raw.get('mac_pool_size', 50),
        ip_prefix_pool=evpn_raw.get('ip_prefix_pool', '192.168.0.0/16'),
        srv6_locator_prefix=evpn_raw.get('srv6_locator_prefix', '2001:db8:ffff::/48'),
    )

    # Routers
    routers = []
    for rr_raw in raw.get('route_reflectors', []):
        # RRs peer with all PEs by default
        pe_ids = [pe.get('id') for pe in raw.get('pe_nodes', [])]
        # Also peer with other RRs
        other_rr_ids = [r.get('id') for r in raw.get('route_reflectors', []) if r.get('id') != rr_raw.get('id')]
        peers = rr_raw.get('peers', pe_ids + other_rr_ids)

        routers.append(RouterConfig(
            id=rr_raw['id'],
            loopback=rr_raw['loopback'],
            bgp_id=rr_raw['bgp_id'],
            role='rr',
            peers=peers,
        ))

    for pe_raw in raw.get('pe_nodes', []):
        # PEs peer with all RRs by default
        rr_ids = [rr.get('id') for rr in raw.get('route_reflectors', [])]
        peers = pe_raw.get('peers', rr_ids)

        routers.append(RouterConfig(
            id=pe_raw['id'],
            loopback=pe_raw['loopback'],
            bgp_id=pe_raw['bgp_id'],
            role='pe',
            peers=peers,
            esi=pe_raw.get('esi'),
            route_distinguisher=pe_raw.get('route_distinguisher'),
        ))

    return TopologyConfig(
        as_number=raw.get('as_number', 65001),
        timing=timing,
        evpn=evpn,
        routers=routers,
        capture_vantage=raw.get('capture_vantage', routers[0].id if routers else 'RR1'),
    )
