#!/bin/bash
date -u +'CHECK_TIME %Y-%m-%dT%H:%M:%SZ'
for n in xrr1 xrr2 xrr3 xpe1 xpe2 xpe3 xpe4 xpe5 xpe6 xpe7 xpe8 xpe9 xpe10; do
  c="clab-pcap2story-3rr-dev-${n}"
  full=$(docker exec "$c" vtysh -c "show ip ospf neighbor" 2>&1 | grep -c "Full")
  down=$(docker exec "$c" vtysh -c "show bgp summary" 2>&1 | grep -Ec "Idle|Active|Connect|Never")
  total=$(docker exec "$c" vtysh -c "show bgp summary" 2>&1 | grep -oE "Total number of neighbors [0-9]+" | grep -oE "[0-9]+")
  echo "${n}: OSPF_Full_count=${full} BGP_total_neighbors=${total} BGP_not_established=${down}"
done
