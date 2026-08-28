import json
import os

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "topology.json")


def load_topology(path=DEFAULT_PATH):
    with open(path) as f:
        topo = json.load(f)
    _validate(topo)
    return topo


def _validate(topo):
    for key in ("nodes", "links", "vantages", "visibility", "ground_truth"):
        if key not in topo:
            raise ValueError(f"topology missing required key: {key}")
    node_ids = {n["id"] for n in topo["nodes"]}

    for v in topo["vantages"]:
        if v not in node_ids:
            raise ValueError(f"vantage {v} is not a declared node")
        if v not in topo["visibility"]:
            raise ValueError(f"vantage {v} has no visibility entry")

    for vantage, vis in topo["visibility"].items():
        for peer in vis["direct_peers"]:
            if peer not in node_ids:
                raise ValueError(f"{vantage}.direct_peers references unknown node {peer}")
        for other in vis["reflects_routes_from"]:
            if other not in topo["vantages"]:
                raise ValueError(f"{vantage}.reflects_routes_from references non-vantage {other}")


def direct_peers(topo, vantage):
    return set(topo["visibility"][vantage]["direct_peers"])


def reflected_vantages(topo, vantage):
    return set(topo["visibility"][vantage]["reflects_routes_from"])


def vantage_for_node(topo, node_id):
    """Every vantage that directly observes node_id's local protocol state."""
    return [v for v in topo["vantages"] if node_id in direct_peers(topo, v)]


def authoritative_vantages_for_node(topo, node_id):
    """Vantage(s) whose report about node_id's own local state (session
    up/down, notification sent/received, etc.) should be trusted as ground
    truth -- distinct name from vantage_for_node for caller-facing clarity
    (Layer 3 fusion / Layer 4 rules query this specifically to resolve the
    RR-Down vantage-flip case), though the underlying computation is the
    same: because direct_peers never lists a node as its own peer, a
    vantage is automatically excluded from being its own authority here --
    e.g. authoritative_vantages_for_node(topo, "RR1") == ["RR2"], since
    RR2 is the only vantage with RR1 in its direct_peers. If node_id's own
    vantage capture goes dark (e.g. its container is killed), this is the
    generic way to find who else can still speak for it, with no
    fault-type-specific branch."""
    return vantage_for_node(topo, node_id)


def ground_truth(topo, node_id):
    return topo["ground_truth"].get(node_id)


if __name__ == "__main__":
    topo = load_topology()
    print(f"Loaded topology: {topo['topology_id']}")
    print(f"Nodes: {[n['id'] for n in topo['nodes']]}")
    print(f"Vantages ({len(topo['vantages'])}): {topo['vantages']}")
    for v in topo["vantages"]:
        print(f"  {v}: direct_peers={sorted(direct_peers(topo, v))} "
              f"reflects_routes_from={sorted(reflected_vantages(topo, v))}")
    print("Ground truth per node:")
    for n in topo["nodes"]:
        gt = ground_truth(topo, n["id"])
        if gt:
            print(f"  {n['id']}: {gt}")
    print("\nValidation OK — no code path above assumes len(vantages) == 2; "
          "every loop iterates topo['vantages'] generically.")
