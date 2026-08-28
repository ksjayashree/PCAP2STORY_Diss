"""Topology data model for evpnpcapcheck.

Represents a network topology with PE nodes, route reflectors, loopback
addresses, and ESI (Ethernet Segment Identifier) groups.  Used by
topology-aware rules to distinguish expected behaviour from faults.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Node:
    """A network node (PE or RR)."""

    id: str
    loopback: str
    bgp_id: str
    esi: str = ""


@dataclass
class Topology:
    """Parsed network topology.

    Provides lookup helpers for rules to query:
    - Which PEs share an ESI (multi-homed pair)
    - Loopback → node ID mapping
    - Which nodes are expected in the capture
    """

    as_number: int = 0
    capture_vantage: str = ""
    pe_nodes: list[Node] = field(default_factory=list)
    route_reflectors: list[Node] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build internal lookup indexes."""
        self._loopback_to_node: dict[str, Node] = {}
        self._bgp_id_to_node: dict[str, Node] = {}
        self._esi_groups: dict[str, list[Node]] = {}

        for node in self.pe_nodes + self.route_reflectors:
            if node.loopback:
                self._loopback_to_node[node.loopback] = node
            if node.bgp_id:
                self._bgp_id_to_node[node.bgp_id] = node

        for pe in self.pe_nodes:
            if pe.esi:
                self._esi_groups.setdefault(pe.esi, []).append(pe)

    @property
    def all_pe_loopbacks(self) -> set[str]:
        """Set of all PE loopback addresses."""
        return {pe.loopback for pe in self.pe_nodes if pe.loopback}

    @property
    def all_rr_loopbacks(self) -> set[str]:
        """Set of all RR loopback addresses."""
        return {rr.loopback for rr in self.route_reflectors if rr.loopback}

    @property
    def all_loopbacks(self) -> set[str]:
        """Set of all node loopback addresses (PEs + RRs)."""
        return self.all_pe_loopbacks | self.all_rr_loopbacks

    @property
    def esi_groups(self) -> dict[str, list[Node]]:
        """ESI → list of PEs sharing that ESI."""
        return dict(self._esi_groups)

    def node_by_loopback(self, loopback: str) -> Node | None:
        """Look up a node by its loopback address."""
        return self._loopback_to_node.get(loopback)

    def node_by_bgp_id(self, bgp_id: str) -> Node | None:
        """Look up a node by its BGP router ID."""
        return self._bgp_id_to_node.get(bgp_id)

    def is_multihomed_pe(self, loopback: str) -> bool:
        """Return True if the PE at this loopback shares an ESI with another PE."""
        node = self._loopback_to_node.get(loopback)
        if node is None or not node.esi:
            return False
        return len(self._esi_groups.get(node.esi, [])) > 1

    def esi_peers(self, loopback: str) -> list[Node]:
        """Return the other PEs sharing an ESI with the given PE."""
        node = self._loopback_to_node.get(loopback)
        if node is None or not node.esi:
            return []
        return [n for n in self._esi_groups.get(node.esi, []) if n is not node]

    def expected_pe_sessions(self) -> set[str]:
        """Return loopbacks of PEs expected to have sessions with the vantage."""
        return self.all_pe_loopbacks
