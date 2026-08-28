import os
import subprocess
from pathlib import Path

scenarios = [
    "normal_light_2min",
    "normal_moderate_2min",
    "normal_heavy_2min",
    "normal_silent_pe4_2min"
]

pcaps_dir = str(Path(__file__).resolve().parents[2] / "pcaps")

print("=== PCAP VERIFICATION SUMMARY ===")

for sc in scenarios:
    sc_path = os.path.join(pcaps_dir, sc)
    print(f"\n==========================================")
    print(f"Scenario: {sc}")
    print(f"Path: {sc_path}")
    print(f"==========================================")
    
    for rr in ["rr1.pcap", "rr2.pcap"]:
        pcap_file = os.path.join(sc_path, rr)
        if not os.path.exists(pcap_file):
            print(f"[-] {rr}: MISSING FILE")
            continue
            
        size = os.path.getsize(pcap_file)
        wsl_file = pcap_file.replace("C:\\", "/mnt/c/").replace("\\", "/")
        
        # tshark BGP Keepalive count
        res_ka = subprocess.run(
            f'wsl bash -c "tshark -r \'{wsl_file}\' -Y \'bgp.type == 4\' 2>/dev/null | wc -l"',
            shell=True, capture_output=True, text=True
        )
        ka_count = res_ka.stdout.strip() or "0"
        
        # tshark BGP Update count
        res_up = subprocess.run(
            f'wsl bash -c "tshark -r \'{wsl_file}\' -Y \'bgp.type == 2\' 2>/dev/null | wc -l"',
            shell=True, capture_output=True, text=True
        )
        up_count = res_up.stdout.strip() or "0"
        
        # tshark BFD count
        res_bfd = subprocess.run(
            f'wsl bash -c "tshark -r \'{wsl_file}\' -Y \'bfd\' 2>/dev/null | wc -l"',
            shell=True, capture_output=True, text=True
        )
        bfd_count = res_bfd.stdout.strip() or "0"
        
        # Total packet count
        res_total = subprocess.run(
            f'wsl bash -c "tshark -r \'{wsl_file}\' 2>/dev/null | wc -l"',
            shell=True, capture_output=True, text=True
        )
        total_count = res_total.stdout.strip() or "0"
        
        print(f"\n  [{rr}] Size: {size} bytes ({size/1024:.1f} KB)")
        print(f"    - Total Packets: {total_count}")
        print(f"    - BFD Packets: {bfd_count}")
        print(f"    - BGP Keepalives (Type 4): {ka_count}")
        print(f"    - BGP Updates (Type 2): {up_count}")
        
        if int(up_count) > 0:
            print(f"    [!] ALERT: BGP UPDATE messages detected ({up_count}) in normal scenario {sc}!")
        else:
            print(f"    [+] CLEAN: 0 BGP UPDATE messages present.")
