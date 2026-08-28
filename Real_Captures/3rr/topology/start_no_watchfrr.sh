#!/bin/bash
# Replaces the image's default entrypoint (/usr/lib/frr/docker-start, which
# execs watchfrr as the container's main process). watchfrr repeatedly
# misjudges mgmtd as unhealthy (frrouting/frr#20294, open/unfixed) and issues
# "restart all", wiping every daemon's state every 30-90s. This project uses
# no mgmtd-dependent features, so daemons are started directly via
# frrcommon.sh's own daemon_start(), bypassing watchfrr supervision entirely.
source /usr/lib/frr/frrcommon.sh

for d in $(daemon_list); do
  daemon_start "$d"
done

vtysh_b
exec tail -f /dev/null
