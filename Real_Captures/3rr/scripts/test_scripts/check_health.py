import sys
import time
import subprocess

nodes = ["xpe1", "xpe2", "xpe3", "xpe4", "xpe5", "xpe6", "xpe7", "xpe8", "xpe9", "xpe10", "xrr1", "xrr2", "xrr3"]

def evaluate_node_health(node):
    container = f"clab-pcap2story-3rr-dev-{node}"
    node_ok = True
    issues = []
    
    # OSPF Check
    res_ospf = subprocess.run(["wsl", "docker", "exec", container, "vtysh", "-c", "show ip ospf neighbor"], capture_output=True, text=True)
    ospf_out = res_ospf.stdout.strip()
    
    ospf_lines = [l for l in ospf_out.splitlines() if l.strip() and "Neighbor ID" not in l]
    if not ospf_lines:
        node_ok = False
        issues.append("OSPF: No neighbors listed")
    else:
        for line in ospf_lines:
            if "Full" not in line:
                node_ok = False
                issues.append(f"OSPF not Full: {line.strip()}")
                
    # BGP EVPN Summary Check
    res_bgp = subprocess.run(["wsl", "docker", "exec", container, "vtysh", "-c", "show bgp l2vpn evpn summary"], capture_output=True, text=True)
    bgp_out = res_bgp.stdout.strip()
    
    in_table = False
    bgp_peers_found = False
    for line in bgp_out.splitlines():
        if line.startswith("Neighbor"):
            in_table = True
            continue
        if in_table and line.strip():
            parts = line.split()
            if len(parts) >= 10:
                bgp_peers_found = True
                state_pfx = parts[9]
                if not state_pfx.isdigit():
                    node_ok = False
                    issues.append(f"BGP not Established ({parts[0]} state={state_pfx})")
                    
    if not bgp_peers_found:
        node_ok = False
        issues.append("BGP: No peers listed in summary")
        
    return node_ok, issues, ospf_out, bgp_out

def main():
    max_duration = 60
    poll_interval = 3
    start_time = time.time()
    
    print("=== PASSIVE LAB HEALTH CHECK (OSPF & BGP) ===")
    
    while True:
        elapsed = int(time.time() - start_time)
        print(f"\n--- Health Check Poll at T+{elapsed}s ---")
        
        all_ok = True
        current_issues = {}
        
        for node in nodes:
            node_ok, issues, ospf_out, bgp_out = evaluate_node_health(node)
            if not node_ok:
                all_ok = False
                current_issues[node] = issues
            
            print(f"\n--- Node {node} ---")
            print("OSPF Neighbors:")
            print(ospf_out if ospf_out else "(empty)")
            print("BGP Summary:")
            print(bgp_out if bgp_out else "(empty)")
            if issues:
                for issue in issues:
                    print(f"  [WARN] {issue}")
            else:
                print("  [OK] OSPF Full, BGP Established")
                
        if all_ok:
            total_time = int(time.time() - start_time)
            print(f"\n>>> ALL NODES HEALTHY: OSPF Full, BGP Established in {total_time}s <<<")
            sys.exit(0)
                        
        if elapsed + poll_interval > max_duration:
            break
            
        time.sleep(poll_interval)
        
    total_time = int(time.time() - start_time)
    print(f"\n>>> FAILURE: Health checks failed to converge after {total_time}s <<<")
    print("Unresolved Issues:")
    for node, issues in current_issues.items():
        print(f"  Node {node}:")
        for iss in issues:
            print(f"    - {iss}")
    sys.exit(1)

if __name__ == "__main__":
    main()
