#!/bin/bash
# Wrapper around `containerlab deploy` for the 3rr/10pe topology: detects
# stalls or failed deploys, cleans up, retries once, then gives up loudly.
#
# Usage: run from inside topology/ (or pass TOPO_DIR below), inside WSL:
#   bash deploy_with_retry.sh
set -u

TOPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOPO_FILE="3rr_10pe_topology.yml"
LAB_NAME="pcap2story-3rr-dev"
CONTAINER_PREFIX="clab-${LAB_NAME}-"
EXPECTED_NODES=13
# worker count for containerlab deploy
MAX_WORKERS=8
# stall detection threshold for deploy progress
STALL_THRESHOLD_SECONDS=540
POLL_INTERVAL_SECONDS=15
MAX_ATTEMPTS=2
POST_CLEANUP_WAIT_SECONDS=30

LOGDIR="$TOPO_DIR/../logs"
mkdir -p "$LOGDIR"

container_count() {
    docker ps -a --filter "name=${CONTAINER_PREFIX}" --format '{{.Names}}' | wc -l
}

cleanup_stray_processes() {
    # WSL-side: kill any orphaned clab/containerlab deploy or destroy process
    echo "[cleanup] checking for any orphaned clab/containerlab process inside WSL..."
    if pgrep -f "containerlab (deploy|destroy)" >/dev/null 2>&1; then
        echo "[cleanup] found orphaned containerlab process(es), sending SIGTERM:"
        pgrep -af "containerlab (deploy|destroy)" 2>/dev/null
        pkill -TERM -f "containerlab (deploy|destroy)" 2>/dev/null
        sleep 3
        if pgrep -f "containerlab (deploy|destroy)" >/dev/null 2>&1; then
            echo "[cleanup] still alive after SIGTERM, escalating to SIGKILL"
            pkill -KILL -f "containerlab (deploy|destroy)" 2>/dev/null
            sleep 1
        fi
        if pgrep -f "containerlab (deploy|destroy)" >/dev/null 2>&1; then
            echo "[cleanup][WARN] a containerlab process survived SIGKILL -- unexpected, reporting but continuing"
        else
            echo "[cleanup] orphaned containerlab process(es) cleared"
        fi
    else
        echo "[cleanup] no orphaned containerlab process found inside WSL"
    fi

    # Windows-side: detect only, do not blind-kill wsl.exe processes.
    if command -v tasklist.exe >/dev/null 2>&1; then
        local wsl_procs
        wsl_procs=$(tasklist.exe /FI "IMAGENAME eq wsl.exe" 2>/dev/null | grep -c "wsl.exe")
        echo "[cleanup] Windows-side wsl.exe process count: ${wsl_procs:-0} (informational only, not auto-killed -- see script comment)"
    else
        echo "[cleanup] tasklist.exe not reachable from this shell -- skipping Windows-side process check"
    fi
}

full_destroy() {
    echo "[cleanup] running containerlab destroy for a clean slate..."
    (cd "$TOPO_DIR" && containerlab destroy -t "$TOPO_FILE") 2>&1
    local n
    n=$(container_count)
    echo "[cleanup] container count after destroy: $n"
}

# Post-deploy stability check: checks StartedAt on every expected container
# every POLL_INTERVAL_SECONDS for STABILITY_CHECK_SECONDS; any change means
# at least one container restarted during the window -> not stable.
STABILITY_CHECK_SECONDS=90

check_post_deploy_stability() {
    local -A first_seen
    local containers
    containers=$(docker ps -a --filter "name=${CONTAINER_PREFIX}" --format '{{.Names}}')
    for c in $containers; do
        first_seen["$c"]=$(docker inspect "$c" --format '{{.State.StartedAt}}' 2>/dev/null)
    done

    local elapsed=0
    while [ "$elapsed" -lt "$STABILITY_CHECK_SECONDS" ]; do
        sleep "$POLL_INTERVAL_SECONDS"
        elapsed=$((elapsed + POLL_INTERVAL_SECONDS))
        for c in $containers; do
            local now_started
            now_started=$(docker inspect "$c" --format '{{.State.StartedAt}}' 2>/dev/null)
            if [ "$now_started" != "${first_seen[$c]}" ]; then
                echo "[stability][t+${elapsed}s] $c StartedAt changed (${first_seen[$c]} -> $now_started) -- NOT stable, a restart occurred"
                return 1
            fi
        done
        echo "[stability][t+${elapsed}s] all containers stable so far"
    done
    return 0
}

# Runs one deploy attempt. Returns via global ATTEMPT_RESULT:
#   0 = success (13/13, deploy process exited cleanly, AND stable for
#       STABILITY_CHECK_SECONDS afterward)
#   1 = completed but wrong count (partial or rolled-back), or unstable
#       post-deploy (a restart occurred during the stability window)
#   2 = stalled past STALL_THRESHOLD_SECONDS (process force-killed by us)
run_one_attempt() {
    local attempt_num="$1"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local deploy_log="$LOGDIR/deploy_attempt${attempt_num}_${ts}.log"

    echo "[attempt $attempt_num] deploy log: $deploy_log"
    echo "[attempt $attempt_num] max-workers=${MAX_WORKERS}"
    (cd "$TOPO_DIR" && containerlab deploy -t "$TOPO_FILE" --max-workers "$MAX_WORKERS") > "$deploy_log" 2>&1 &
    local deploy_pid=$!
    echo "[attempt $attempt_num] deploy_pid=$deploy_pid"

    local last_count=-1
    local last_change_epoch
    last_change_epoch=$(date +%s)
    local start_epoch=$last_change_epoch

    while kill -0 "$deploy_pid" 2>/dev/null; do
        sleep "$POLL_INTERVAL_SECONDS"
        local now
        now=$(date +%s)
        local count
        count=$(container_count)
        local elapsed=$((now - start_epoch))

        if [ "$count" != "$last_count" ]; then
            echo "[attempt $attempt_num][t+${elapsed}s] container count changed: $last_count -> $count"
            last_count=$count
            last_change_epoch=$now
        fi

        local stall_duration=$((now - last_change_epoch))
        if [ "$stall_duration" -ge "$STALL_THRESHOLD_SECONDS" ]; then
            echo "[attempt $attempt_num][t+${elapsed}s] STALLED: no new containers for ${stall_duration}s (threshold ${STALL_THRESHOLD_SECONDS}s), count stuck at $count -- killing deploy process"
            kill -TERM "$deploy_pid" 2>/dev/null
            sleep 3
            kill -0 "$deploy_pid" 2>/dev/null && kill -KILL "$deploy_pid" 2>/dev/null
            ATTEMPT_RESULT=2
            ATTEMPT_LOG="$deploy_log"
            return
        fi
    done

    wait "$deploy_pid" 2>/dev/null
    local exit_code=$?
    local final_count
    final_count=$(container_count)
    echo "[attempt $attempt_num] deploy process exited (code=$exit_code), final container count: $final_count"

    if [ "$final_count" -ne "$EXPECTED_NODES" ]; then
        ATTEMPT_RESULT=1
        ATTEMPT_LOG="$deploy_log"
        return
    fi

    echo "[attempt $attempt_num] count OK ($final_count/$EXPECTED_NODES) -- running ${STABILITY_CHECK_SECONDS}s post-deploy stability check before declaring success..."
    if check_post_deploy_stability; then
        echo "[attempt $attempt_num] stable for ${STABILITY_CHECK_SECONDS}s -- genuine success"
        ATTEMPT_RESULT=0
    else
        echo "[attempt $attempt_num] restart detected during stability window -- NOT a genuine success"
        ATTEMPT_RESULT=1
    fi
    ATTEMPT_LOG="$deploy_log"
}

ensure_tcpdump_all_rrs() {
    # tcpdump does not persist across redeploys; install on all RR nodes
    # once per fresh deploy, before any scenario generation begins.
    echo "[setup] ensuring tcpdump is installed on all RR nodes..."
    for c in $(docker ps -a --filter "name=${CONTAINER_PREFIX}xrr" --format '{{.Names}}'); do
        local node="${c#$CONTAINER_PREFIX}"
        if docker exec "$c" sh -c "which tcpdump" >/dev/null 2>&1; then
            echo "  $node: tcpdump already present"
        else
            echo "  $node: installing tcpdump..."
            docker exec "$c" sh -c "apk add tcpdump 2>&1 | tail -2"
            if docker exec "$c" sh -c "which tcpdump" >/dev/null 2>&1; then
                echo "  $node: tcpdump installed OK"
            else
                echo "  $node: [ERROR] tcpdump still missing after install attempt!"
            fi
        fi
    done
}

check_node_health() {
    echo "=== running node_setup.sh convergence check on all $EXPECTED_NODES nodes ==="
    local all_ok=1
    for c in $(docker ps -a --filter "name=${CONTAINER_PREFIX}" --format '{{.Names}}'); do
        local node="${c#$CONTAINER_PREFIX}"
        local ospf_full
        ospf_full=$(docker exec "$c" vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -c "Full")
        echo "  $node: OSPF Full neighbor count = $ospf_full"
        if [ "$ospf_full" -lt 1 ] && [[ "$node" == xpe* ]]; then
            echo "  $node: WARNING -- no Full OSPF neighbors"
            all_ok=0
        fi
    done
    if [ "$all_ok" -eq 1 ]; then
        echo "=== health check: all PE nodes show at least one Full OSPF neighbor ==="
    else
        echo "=== health check: one or more PE nodes show NO Full OSPF neighbors -- investigate before treating as fully healthy ==="
    fi
}

echo "########## deploy_with_retry.sh starting, $(date -u +%Y-%m-%dT%H:%M:%SZ) ##########"

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    echo
    echo "========== ATTEMPT $attempt / $MAX_ATTEMPTS =========="
    # Pre-attempt orphan check runs every time, including attempt 1
    cleanup_stray_processes
    run_one_attempt "$attempt"

    case "$ATTEMPT_RESULT" in
        0)
            echo
            echo "########## SUCCESS: attempt $attempt reached ${EXPECTED_NODES}/${EXPECTED_NODES} containers ##########"
            echo "deploy log: $ATTEMPT_LOG"
            ensure_tcpdump_all_rrs
            check_node_health
            exit 0
            ;;
        1|2)
            reason="partial/rolled-back count"
            [ "$ATTEMPT_RESULT" -eq 2 ] && reason="stalled past ${STALL_THRESHOLD_SECONDS}s"
            echo
            echo "[attempt $attempt] FAILED ($reason). Log: $ATTEMPT_LOG"
            full_destroy
            if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
                echo "[attempt $attempt] waiting ${POST_CLEANUP_WAIT_SECONDS}s before retry..."
                sleep "$POST_CLEANUP_WAIT_SECONDS"
            fi
            ;;
    esac
done

echo
echo "########## FAILURE: all $MAX_ATTEMPTS attempts failed. Not retrying further. ##########"
echo "Last attempt's log: $ATTEMPT_LOG"
echo "Partial state already destroyed after the final failed attempt (see above), confirming clean:"
final_count=$(container_count)
echo "Final container count: $final_count / $EXPECTED_NODES"
if [ "$final_count" -ne 0 ]; then
    echo "[FAILURE][WARN] non-zero containers remain after final destroy -- investigate manually before any further use of this environment."
fi
exit 1
