import subprocess

for idx in range(1, 6):
    container = f"clab-pcap2story-pe{idx}"
    lo_ip = f"10.0.0.1{idx}"
    
    cmds = [
        ["wsl", "docker", "exec", container, "ip", "link", "add", "br100", "type", "bridge"],
        ["wsl", "docker", "exec", container, "ip", "link", "add", "vxlan100", "type", "vxlan", "id", "100", "dstport", "4789", "local", lo_ip, "dev", "lo"],
        ["wsl", "docker", "exec", container, "ip", "link", "set", "vxlan100", "master", "br100"],
        ["wsl", "docker", "exec", container, "ip", "link", "set", "br100", "up"],
        ["wsl", "docker", "exec", container, "ip", "link", "set", "vxlan100", "up"],
        ["wsl", "docker", "exec", container, "ip", "link", "add", "vhost100", "type", "dummy"],
        ["wsl", "docker", "exec", container, "ip", "link", "set", "vhost100", "master", "br100"],
        ["wsl", "docker", "exec", container, "ip", "link", "set", "vhost100", "up"],
        ["wsl", "docker", "exec", container, "ip", "neigh", "add", f"10.100.0.{idx}", "lladdr", f"52:54:00:00:00:0{idx}", "dev", "vhost100"],
        ["wsl", "docker", "exec", container, "bridge", "fdb", "add", f"52:54:00:00:00:0{idx}", "dev", "vhost100", "master", "static"],
        ["wsl", "docker", "exec", container, "vtysh", "-b"]
    ]
    
    print(f"Setting up bridge & VXLAN interfaces on {container}...")
    for cmd in cmds:
        subprocess.run(cmd, check=False, stderr=subprocess.DEVNULL)

print("Reapplying vtysh -b on rr1 and rr2...")
subprocess.run(["wsl", "docker", "exec", "clab-pcap2story-rr1", "vtysh", "-b"], check=False)
subprocess.run(["wsl", "docker", "exec", "clab-pcap2story-rr2", "vtysh", "-b"], check=False)
