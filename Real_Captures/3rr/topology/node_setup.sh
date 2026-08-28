#!/bin/bash

HOSTNAME=$(hostname)
LOG_FILE="/tmp/node_setup_error.log"

# Pre-create the FRR log directory with correct ownership so frr.conf's
# "log file /var/log/frr/frr.log debugging" line does not fail to open
# when vtysh -b applies it below.
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
# asymmetric topology: each PE is single-homed to exactly one RR;
# xrr1/xrr2/xrr3 are fully meshed with each other.
# xrr1 domain: xpe1-4 (xpe3/xpe4 share an ESI)
# xrr2 domain: xpe5-7 (xpe6/xpe7 share a separate ESI)
# xrr3 domain: xpe8-10 (no ESI sharing)
case "$HOSTNAME" in
  xpe1|xpe2|xpe3|xpe4|xpe6|xpe7|xpe8|xpe9|xpe10)
    EXPECTED_IFACES="eth1"
    EXPECTED_NEIGHBORS=1
    ;;
  xpe5)
    EXPECTED_IFACES="eth2"
    EXPECTED_NEIGHBORS=1
    ;;
  xrr1)
    EXPECTED_IFACES="eth1 eth2 eth3 eth4 eth5 eth6"
    EXPECTED_NEIGHBORS=6
    ;;
  xrr2)
    EXPECTED_IFACES="eth1 eth2 eth3 eth4 eth6"
    EXPECTED_NEIGHBORS=5
    ;;
  xrr3)
    EXPECTED_IFACES="eth1 eth2 eth3 eth4 eth5"
    EXPECTED_NEIGHBORS=5
    ;;
  *)
    EXPECTED_IFACES=""
    EXPECTED_NEIGHBORS=0
    ;;
esac

# Setup Linux VXLAN and Bridge for EVPN VNI 100 on PE nodes. Runs before
# vtysh -b so that vhost100's VLAN membership is already correct when
# zebra correlates the ES config (applied by vtysh -b, from frr.conf) to
# the real kernel device. The lo IP is assigned directly at the kernel
# level here (rather than deferring to vtysh -b) since vxlan100's
# "local $LO_IP dev lo" binding requires that IP to already exist on lo;
# frr.conf's own "interface lo / ip address" line still applies later via
# vtysh -b as normal (idempotent, same address either way).
# ES-sharing PEs: three independent ES pairs, each pair sharing one
# es-id/es-sys-mac (with differing es-df-pref) in its frr.conf. The
# bridge/VLAN dance below only applies to nodes that actually carry an
# ES (evpn mh es-id) in their config -- membership is a set lookup
# against the known ES groups, so a new ES pair only needs adding to
# ES_PES/case below, not new branches.
ES_PES="xpe3 xpe4 xpe6 xpe7"
IS_ES_PE=false
for es_pe in $ES_PES; do
  if [[ "$HOSTNAME" == "$es_pe" ]]; then
    IS_ES_PE=true
    break
  fi
done

# bond100 migration (Stage 1: xpe3 only) -- real ES access port via a
# dedicated stub-node slave link on eth2, replacing vhost100 for ES
# purposes only. Remaining ES PEs (xpe4, xpe6, xpe7) stay on vhost100
# until their own migration stage.
BOND_PES="xpe3"
IS_BOND_PE=false
for bond_pe in $BOND_PES; do
  if [[ "$HOSTNAME" == "$bond_pe" ]]; then
    IS_BOND_PE=true
    break
  fi
done

if [[ "$HOSTNAME" =~ ^xpe(10|[1-9])$ ]]; then
  NODE_NUM=${HOSTNAME#xpe}
  LO_IP="10.0.0.$((10 + NODE_NUM))"
  ip addr add ${LO_IP}/32 dev lo 2>/dev/null || true

  if $IS_ES_PE; then
    ip link add br100 type bridge vlan_filtering 1 2>/dev/null || true
  else
    ip link add br100 type bridge 2>/dev/null || true
  fi
  ip link set br100 up 2>/dev/null || true

  if $IS_ES_PE; then
    bridge vlan add vid 100 dev br100 self 2>/dev/null || true
  fi

  ip link add vxlan100 type vxlan id 100 dstport 4789 local $LO_IP dev lo 2>/dev/null || true
  ip link set vxlan100 master br100 2>/dev/null || true
  if $IS_ES_PE; then
    bridge vlan del vid 1 dev vxlan100 2>/dev/null || true
    bridge vlan add vid 100 untagged pvid dev vxlan100 2>/dev/null || true
  fi
  ip link set vxlan100 up 2>/dev/null || true

  if $IS_BOND_PE; then
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

  # Add dummy host for MAC/IP route generation in EVPN. For ES PEs not yet
  # migrated to bond100, this is also the ES access port (evpn mh es-id,
  # applied later by vtysh -b), so its VLAN membership must be correct
  # BEFORE that config lands. For migrated bond100 PEs, vhost100 stays as
  # a plain (non-ES) dummy, still the fake-host ARP/FDB anchor.
  ip link add vhost100 type dummy 2>/dev/null || true
  ip link set vhost100 master br100 2>/dev/null || true
  if $IS_ES_PE; then
    bridge vlan del vid 1 dev vhost100 2>/dev/null || true
    bridge vlan del vid 1 untagged pvid dev vhost100 2>/dev/null || true
    bridge vlan add vid 100 untagged pvid dev vhost100 2>/dev/null || true
  fi
  ip link set vhost100 up 2>/dev/null || true
  MAC_SUFFIX=$(printf "%02d" "$NODE_NUM")
  ip neigh add 10.100.0.${NODE_NUM} lladdr 52:54:00:00:00:${MAC_SUFFIX} dev vhost100 2>/dev/null || true
  bridge fdb add 52:54:00:00:00:${MAC_SUFFIX} dev vhost100 master static 2>/dev/null || true
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

# ospfd only registers interfaces present in its own netlink scan at
# daemon startup. Containerlab attaches this node veth links AFTER
# the FRR daemons are already running, so those interfaces exist and
# are UP in the netns but ospfd never learns about them from vtysh -b
# alone. Before asking ospfd to rescan, confirm the links this node
# actually needs are present -- rescanning against a netns still
# missing links would accomplish nothing.
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

# Before starting the OSPF-convergence clock, confirm each expected peer
# is actually reachable at L3 over its point-to-point link, not just that
# our own interface is locally UP. Each P2P link here is a /30 with
# exactly two host addresses (.1 and .2), so the peer's address is
# derivable from our own configured address on the same interface:
# whichever of .1/.2 we are NOT is the peer.
#
# Bounded by its own timeout, separate from and prior to the
# OSPF-convergence timeout below, so a genuinely-failed deploy (peer
# never comes up at all) still fails this script in finite time.
PEER_WAIT_TIMEOUT=900
echo "[NODE_SETUP] Verifying expected peers are L3-reachable (timeout ${PEER_WAIT_TIMEOUT}s)..."
PEERS_READY=false

for i in $(seq 1 "$PEER_WAIT_TIMEOUT"); do
  missing=0
  for ifc in $EXPECTED_IFACES; do
    local_ip=$(ip -4 -o addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    if [ -z "$local_ip" ]; then
      missing=1
      continue
    fi
    net_prefix=${local_ip%.*}
    last_octet=${local_ip##*.}
    peer_octet=$((3 - last_octet))
    peer_ip="${net_prefix}.${peer_octet}"
    if ! ping -c 1 -W 1 "$peer_ip" >/dev/null 2>&1; then
      missing=1
    fi
  done
  if [ -z "$EXPECTED_IFACES" ] || [ "$missing" -eq 0 ]; then
    PEERS_READY=true
    echo "[NODE_SETUP] All expected peers reachable after ${i}s."
    break
  fi
  sleep 1
done

if [ "$PEERS_READY" != "true" ]; then
  ERR_MSG="[NODE_SETUP ERROR] Expected peer(s) on (${EXPECTED_IFACES}) not L3-reachable within ${PEER_WAIT_TIMEOUT}s."
  echo "$ERR_MSG" | tee -a "$LOG_FILE"
  exit 1
fi

# Force ospfd to rescan for interfaces now that the links this node
# needs are confirmed present -- vtysh -b reapplies config text to
# the running daemon but does not itself trigger an interface rescan.
echo "[NODE_SETUP] Issuing clear ip ospf process to force interface rescan..."
vtysh -c "clear ip ospf process"

# Verify OSPF actually reaches the expected Full neighbor count before
# declaring success -- do not assume the clear worked. The wait window
# scales with this node's own EXPECTED_NEIGHBORS on top of a fixed floor,
# since a node's own OSPF-wait clock starts right after its own container
# is created, independent of whether its peer node exists yet.
OSPF_TIMEOUT=$((1200 + EXPECTED_NEIGHBORS * 20))
OSPF_CONVERGED=false
FULL_COUNT=0

for i in $(seq 1 "$OSPF_TIMEOUT"); do
  FULL_COUNT=$(vtysh -c "show ip ospf neighbor" 2>&1 | grep -c "Full")
  if [ "$FULL_COUNT" -ge "$EXPECTED_NEIGHBORS" ]; then
    OSPF_CONVERGED=true
    echo "[NODE_SETUP] OSPF converged: ${FULL_COUNT}/${EXPECTED_NEIGHBORS} Full neighbor(s) after ${i}s (timeout was ${OSPF_TIMEOUT}s)."
    break
  fi
  sleep 1
done

if [ "$OSPF_CONVERGED" != "true" ]; then
  ERR_MSG="[NODE_SETUP ERROR] OSPF failed to reach ${EXPECTED_NEIGHBORS} Full neighbor(s) within ${OSPF_TIMEOUT}s after clear ip ospf process. Got ${FULL_COUNT}."
  echo "$ERR_MSG" | tee -a "$LOG_FILE"
  exit 1
fi

echo "[NODE_SETUP] node_setup.sh completed successfully with OSPF converged."
