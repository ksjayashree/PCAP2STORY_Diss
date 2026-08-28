#!/bin/bash
# Start FRR daemons directly, bypassing watchfrr supervision
source /usr/lib/frr/frrcommon.sh
for d in $(daemon_list); do
  daemon_start "$d"
done
vtysh_b || true
exec tail -f /dev/null
