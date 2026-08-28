#!/bin/bash

HOSTNAME=$(hostname)
LOG_FILE="/tmp/node_setup_error.log"

# Ensure tcpdump is installed
if [[ "$HOSTNAME" =~ ^(rr1|rr2)$ ]]; then
  if ! which tcpdump >/dev/null 2>&1; then
    echo "[NODE_SETUP] tcpdump not present, installing..."
    apk add --no-cache tcpdump >/dev/null 2>&1
  fi
  if which tcpdump >/dev/null 2>&1; then
    echo "[NODE_SETUP] tcpdump ready: $(which tcpdump)"
  else
    echo "[NODE_SETUP ERROR] tcpdump still missing after install attempt!" | tee -a "$LOG_FILE"
  fi
fi

# Pre-create the FRR log directory with correct ownership
mkdir -p /var/log/frr 2>/dev/null || true
chown frr:frr /var/log/frr 2>/dev/null || true

# Ensure all physical point-to-point interface links are set UP
ip link set eth1 up 2>/dev/null || true
ip link set eth2 up 2>/dev/null || true
ip link set eth3 up 2>/dev/null || true
ip link set eth4 up 2>/dev/null || true
ip link set eth5 up 2>/dev/null || true
ip link set eth6 up 2>/dev/null || true

# Per-node expected interfaces / OSPF neighbor count, matching the
# asymmetric topology: pe1-3 -> rr1 only, pe4-5 -> rr2 only, rr1/rr2
# peer each other.
case "$HOSTNAME" in
  pe1|pe2|pe3)
    EXPECTED_IFACES="eth1"
    EXPECTED_NEIGHBORS=1
    ;;
  pe4|pe5)
    EXPECTED_IFACES="eth2"
    EXPECTED_NEIGHBORS=1
    ;;
  rr1)
    EXPECTED_IFACES="eth1 eth2 eth3 eth4"
    EXPECTED_NEIGHBORS=4
    ;;
  rr2)
    EXPECTED_IFACES="eth1 eth5 eth6"
    EXPECTED_NEIGHBORS=3
    ;;
  *)
    EXPECTED_IFACES=""
    EXPECTED_NEIGHBORS=0
    ;;
esac

# Setup Linux VXLAN and Bridge for EVPN VNI 100 on PE nodes.
if [[ "$HOSTNAME" =~ pe[1-5] ]]; then
  NODE_NUM=${HOSTNAME#pe}
  LO_IP="10.0.0.1${NODE_NUM}"
  ip addr add ${LO_IP}/32 dev lo 2>/dev/null || true

  if [[ "$HOSTNAME" =~ ^(pe1|pe2)$ ]]; then
    ip link add br100 type bridge vlan_filtering 1 2>/dev/null || true
  else
    ip link add br100 type bridge 2>/dev/null || true
  fi
  ip link set br100 up 2>/dev/null || true

  if [[ "$HOSTNAME" =~ ^(pe1|pe2)$ ]]; then
    bridge vlan add vid 100 dev br100 self 2>/dev/null || true
  fi

  ip link add vxlan100 type vxlan id 100 dstport 4789 local $LO_IP dev lo 2>/dev/null || true
  ip link set vxlan100 master br100 2>/dev/null || true
  if [[ "$HOSTNAME" =~ ^(pe1|pe2)$ ]]; then
    bridge vlan del vid 1 dev vxlan100 2>/dev/null || true
    bridge vlan add vid 100 untagged pvid dev vxlan100 2>/dev/null || true
  fi
  ip link set vxlan100 up 2>/dev/null || true

  if [[ "$HOSTNAME" =~ ^(pe1|pe2)$ ]]; then
    # Bond100: real ES access port replacing the vhost100 dummy for ES purposes.
    ip link add dev bond100 type bond mode active-backup 2>/dev/null || true
    ip link set dev bond100 type bond miimon 100 2>/dev/null || true
    ip link set dev bond100 type bond min_links 1 2>/dev/null || true

    ip link set dev eth2 down 2>/dev/null || true
    ip link set dev eth2 master bond100 2>/dev/null || true
    ip link set dev eth2 up 2>/dev/null || true
    ip link set dev bond100 up 2>/dev/null || true

    ip link set dev bond100 master br100 2>/dev/null || true
    bridge vlan del vid 1 dev bond100 2>/dev/null || true
    bridge vlan del vid 1 untagged pvid dev bond100 2>/dev/null || true
    bridge vlan add vid 100 untagged pvid dev bond100 2>/dev/null || true
    ip link set bond100 up 2>/dev/null || true
  fi

  # vhost100 stays as a plain (non-ES) dummy, still the fake-host ARP/FDB anchor.
  ip link add vhost100 type dummy 2>/dev/null || true
  ip link set vhost100 master br100 2>/dev/null || true
  if [[ "$HOSTNAME" =~ ^(pe1|pe2)$ ]]; then
    bridge vlan del vid 1 dev vhost100 2>/dev/null || true
    bridge vlan del vid 1 untagged pvid dev vhost100 2>/dev/null || true
    bridge vlan add vid 100 untagged pvid dev vhost100 2>/dev/null || true
  fi
  ip link set vhost100 up 2>/dev/null || true
  ip neigh add 10.100.0.${NODE_NUM} lladdr 52:54:00:00:00:0${NODE_NUM} dev vhost100 2>/dev/null || true
  bridge fdb add 52:54:00:00:00:0${NODE_NUM} dev vhost100 master static 2>/dev/null || true
fi

# Wait for ospfd VTY socket readiness before applying integrated configuration
echo "[NODE_SETUP] Polling for ospfd readiness..."
OSPF_READY=false

for i in $(seq 1 15); do
  if vtysh -c "show ip ospf" 2>&1 | grep -q "OSPF Routing Process"; then
    OSPF_READY=true
    echo "[NODE_SETUP] ospfd is ready after ${i}s."
    break
  fi
  sleep 1
done

if [ "$OSPF_READY" != "true" ]; then
  ERR_MSG="[NODE_SETUP ERROR] ospfd failed to become ready within 15s. Skipping vtysh -b."
  echo "$ERR_MSG" | tee -a "$LOG_FILE"
  exit 1
fi

echo "[NODE_SETUP] Applying integrated FRR config via vtysh -b..."
vtysh -b

# Confirm bond100 ES-EVI state
if [[ "$HOSTNAME" =~ ^(pe1|pe2)$ ]]; then
  BOND_STATE=$(ip -br link show bond100 2>/dev/null)
  VNI_COUNT=$(vtysh -c "show evpn es detail" 2>&1 | grep "VNI Count" | awk '{print $NF}')
  echo "[NODE_SETUP] bond100 state: ${BOND_STATE:-<not found>}"
  echo "[NODE_SETUP] ES VNI Count: ${VNI_COUNT:-<not found>}"
  if [[ "$VNI_COUNT" != "1" ]]; then
    echo "[NODE_SETUP ERROR] bond100 ES-EVI VNI Count is '${VNI_COUNT:-<not found>}', expected 1." | tee -a "$LOG_FILE"
  fi
fi

# Confirm expected interfaces are present before triggering an ospfd rescan
echo "[NODE_SETUP] Verifying expected interfaces are present: ${EXPECTED_IFACES:-<none>}"
IFACES_READY=false

for i in $(seq 1 15); do
  missing=0
  for ifc in $EXPECTED_IFACES; do
    if ! ip link show "$ifc" up 2>/dev/null | grep -q "UP"; then
      missing=1
    fi
  done
  if [ -z "$EXPECTED_IFACES" ] || [ "$missing" -eq 0 ]; then
    IFACES_READY=true
    echo "[NODE_SETUP] Expected interfaces present after ${i}s."
    break
  fi
  sleep 1
done

if [ "$IFACES_READY" != "true" ]; then
  ERR_MSG="[NODE_SETUP ERROR] Expected interfaces (${EXPECTED_IFACES}) did not appear UP within 15s."
  echo "$ERR_MSG" | tee -a "$LOG_FILE"
  exit 1
fi

# Force ospfd to rescan for interfaces
echo "[NODE_SETUP] Issuing clear ip ospf process to force interface rescan..."
vtysh -c "clear ip ospf process"

# Verify OSPF reaches the expected Full neighbor count
OSPF_CONVERGED=false
FULL_COUNT=0

for i in $(seq 1 90); do
  FULL_COUNT=$(vtysh -c "show ip ospf neighbor" 2>&1 | grep -c "Full")
  if [ "$FULL_COUNT" -ge "$EXPECTED_NEIGHBORS" ]; then
    OSPF_CONVERGED=true
    echo "[NODE_SETUP] OSPF converged: ${FULL_COUNT}/${EXPECTED_NEIGHBORS} Full neighbor(s) after ${i}s."
    break
  fi
  sleep 1
done

if [ "$OSPF_CONVERGED" != "true" ]; then
  ERR_MSG="[NODE_SETUP ERROR] OSPF failed to reach ${EXPECTED_NEIGHBORS} Full neighbor(s) within 90s after clear ip ospf process. Got ${FULL_COUNT}."
  echo "$ERR_MSG" | tee -a "$LOG_FILE"
  exit 1
fi

echo "[NODE_SETUP] node_setup.sh completed successfully with OSPF converged."
