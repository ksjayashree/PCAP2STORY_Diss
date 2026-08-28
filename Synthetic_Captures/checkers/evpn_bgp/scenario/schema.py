"""Parse scenario YAML files into a Scenario model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from checkers.evpn_bgp.model import Scenario


def load_scenario(path: str | Path) -> Scenario:
    """Load and validate a scenario YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("Scenario YAML must be a mapping at the top level.")

    return Scenario(
        peers=data.get("peers", {}),
        services=data.get("services", {}),
        checks=data.get("checks", {}),
    )


def scenario_peer_ips(scenario: Scenario) -> set[str]:
    """Return all peer IP addresses defined in the scenario."""
    ips: set[str] = set()
    for peer_name, peer in scenario.peers.items():
        if "ip" in peer:
            ips.add(peer["ip"])
        if "loopback" in peer:
            ips.add(peer["loopback"])
    return ips
