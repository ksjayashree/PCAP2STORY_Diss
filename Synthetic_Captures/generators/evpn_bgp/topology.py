"""Network topology model for BGP session management.

Provides a higher-level abstraction over the configuration,
managing active BGP sessions and their state during scenario generation.
"""

import random
import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from .config import TopologyConfig, RouterConfig


@dataclass
class BGPSession:
    """Represents an active BGP session between two routers."""
    local_router: RouterConfig
    remote_router: RouterConfig
    local_port: int = 179      # BGP well-known port for server side
    remote_port: int = 0       # Ephemeral port for client side
    state: str = 'idle'        # idle, connect, active, opensent, openconfirm, established

    def __post_init__(self):
        if self.remote_port == 0:
            self.remote_port = random.randint(32768, 60999)

    @property
    def session_id(self) -> str:
        """Unique identifier for this session."""
        return f"{self.local_router.id}-{self.remote_router.id}"

    @property
    def client_ip(self) -> str:
        """The PE (client/initiator) IP address."""
        # PE initiates connection to RR
        if self.remote_router.role == 'rr':
            return self.local_router.loopback
        return self.remote_router.loopback

    @property
    def server_ip(self) -> str:
        """The RR (server/listener) IP address."""
        if self.remote_router.role == 'rr':
            return self.remote_router.loopback
        return self.local_router.loopback


@dataclass
class MACEntry:
    """Simulated MAC address learned by a PE."""
    mac: str
    ip: Optional[str] = None
    vni: int = 100
    pe_id: str = ""


class NetworkTopology:
    """Manages the active network state for scenario generation.

    This class provides:
    - Active BGP sessions between routers
    - MAC address tables (simulated learned MACs)
    - ESI membership for multi-homing
    - Route state tracking
    """

    def __init__(self, config: TopologyConfig):
        self.config = config
        self.sessions: list[BGPSession] = []
        self.mac_tables: dict[str, list[MACEntry]] = {}  # PE ID → learned MACs
        self._initialize()

    def _initialize(self):
        """Set up initial sessions and MAC tables."""
        self._build_sessions()
        self._generate_mac_tables()

    def _build_sessions(self):
        """Create BGP sessions based on topology config."""
        seen = set()
        for router in self.config.routers:
            for peer_id in router.peers:
                peer = self.config.get_router(peer_id)
                if not peer:
                    continue
                # Avoid duplicates (A→B and B→A are the same session)
                key = tuple(sorted([router.id, peer.id]))
                if key not in seen:
                    seen.add(key)
                    # PE initiates to RR (PE is client)
                    if router.role == 'pe' and peer.role == 'rr':
                        self.sessions.append(BGPSession(
                            local_router=router, remote_router=peer
                        ))
                    elif router.role == 'rr' and peer.role == 'pe':
                        self.sessions.append(BGPSession(
                            local_router=peer, remote_router=router
                        ))
                    elif router.role == 'rr' and peer.role == 'rr':
                        # RR-to-RR peering (first one listed is "client")
                        self.sessions.append(BGPSession(
                            local_router=router, remote_router=peer
                        ))

    def _generate_mac_tables(self):
        """Generate simulated MAC addresses for each PE."""
        for pe in self.config.pe_nodes:
            macs = []
            for i in range(self.config.evpn.mac_pool_size):
                # Generate deterministic but varied MACs per PE
                pe_idx = int(pe.bgp_id.split('.')[-1])
                mac = f"00:aa:bb:{pe_idx:02x}:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}"
                ip = f"192.168.{pe_idx}.{i + 1}" if i < 254 else None
                macs.append(MACEntry(mac=mac, ip=ip, vni=self.config.evpn.vni, pe_id=pe.id))
            self.mac_tables[pe.id] = macs

    def get_sessions_for_router(self, router_id: str) -> list[BGPSession]:
        """Get all BGP sessions involving a specific router."""
        return [s for s in self.sessions
                if s.local_router.id == router_id or s.remote_router.id == router_id]

    def get_sessions_at_vantage(self, vantage_id: str = None) -> list[BGPSession]:
        """Get all sessions visible from the capture vantage point.

        The vantage is typically an RR that can see all PE sessions to it,
        plus RR-RR sessions.
        """
        vantage = vantage_id or self.config.capture_vantage
        return self.get_sessions_for_router(vantage)

    def get_pe_sessions_to_rr(self, rr_id: str) -> list[BGPSession]:
        """Get all PE sessions to a specific RR."""
        return [s for s in self.sessions
                if s.remote_router.id == rr_id and s.local_router.role == 'pe']

    def get_macs_for_pe(self, pe_id: str, count: int = None) -> list[MACEntry]:
        """Get MAC entries for a PE (optionally limited to count)."""
        macs = self.mac_tables.get(pe_id, [])
        if count:
            return macs[:count]
        return macs

    def get_route_distinguisher(self, router: RouterConfig) -> str:
        """Get the Route Distinguisher for a router."""
        if router.route_distinguisher:
            return router.route_distinguisher
        return f"{router.loopback}:{self.config.evpn.vni}"

    def get_multihomed_esi_peers(self, pe_id: str) -> list[RouterConfig]:
        """Get other PEs that share the same ESI (multi-homed segment)."""
        pe = self.config.get_router(pe_id)
        if not pe or not pe.esi:
            return []
        return [r for r in self.config.pe_nodes
                if r.id != pe_id and r.esi == pe.esi]

    def get_srv6_sid(self, router: RouterConfig) -> str:
        """Generate SRv6 SID for a router based on locator prefix.

        Format: <locator_prefix>::<router_index>:<vni>
        """
        prefix = self.config.evpn.srv6_locator_prefix.split('/')[0]
        # Use last octet of BGP ID as router index
        router_idx = int(router.bgp_id.split('.')[-1])
        vni = self.config.evpn.vni
        # Build SRv6 SID: prefix + function (router_idx:vni)
        base = ipaddress.IPv6Address(prefix)
        # Encode router_idx and vni into lower bits
        sid_int = int(base) | (router_idx << 16) | vni
        return str(ipaddress.IPv6Address(sid_int))
