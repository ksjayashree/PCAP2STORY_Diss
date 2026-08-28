"""Load a topology YAML file into a Topology model.

The YAML format is compatible with the pcap_generator's topology YAML
(e.g. ``configs/default_topology.yaml``).  Extra fields such as ``evpn:``,
``timing:``, etc. are silently ignored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .model import Node, Topology


def load_topology(path: str | Path) -> Topology:
    """Parse a topology YAML file and return a Topology instance.

    Raises FileNotFoundError if path does not exist, or ValueError if the
    YAML is missing required fields.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Topology file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Topology YAML must be a mapping, got {type(data).__name__}")

    return _build_topology(data)


def _build_topology(data: dict[str, Any]) -> Topology:
    """Build a Topology from parsed YAML data."""
    pe_nodes: list[Node] = []
    for pe in data.get("pe_nodes", []):
        if not isinstance(pe, dict):
            continue
        pe_nodes.append(Node(
            id=str(pe.get("id", "")),
            loopback=str(pe.get("loopback", "")),
            bgp_id=str(pe.get("bgp_id", "")),
            esi=str(pe.get("esi", "")),
        ))

    rr_nodes: list[Node] = []
    for rr in data.get("route_reflectors", []):
        if not isinstance(rr, dict):
            continue
        rr_nodes.append(Node(
            id=str(rr.get("id", "")),
            loopback=str(rr.get("loopback", "")),
            bgp_id=str(rr.get("bgp_id", "")),
        ))

    return Topology(
        as_number=int(data.get("as_number", 0)),
        capture_vantage=str(data.get("capture_vantage", "")),
        pe_nodes=pe_nodes,
        route_reflectors=rr_nodes,
    )
