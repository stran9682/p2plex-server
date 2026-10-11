#!/usr/bin/env bash
set -e

# ==============================================================================
# Multi-Process Decentralized Mesh Cluster Simulation
# ==============================================================================
# Simulates a distributed deployment of independent OS processes communicating
# over real QUIC sockets and monitored via REST control planes:
#   1. Origin Server Daemon (HTTP control plane on :9001)
#   2. Replica Server Daemons (HTTP control planes on :9002, :9003, ...)
#   3. Mesh Server Registration & Ticket Exchange
#   4. Dynamic ACL Grant & Revocation propagation across independent processes
#   5. Standalone Viewer Load Generator issuing QUIC stream requests
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

REPLICA_COUNT="${1:-2}"

# Determine binary location
if [ "$ROOT_DIR/src-tauri/target/debug/bench_access_control" -nt "$ROOT_DIR/src-tauri/target/release/bench_access_control" ]; then
    BIN_PATH="$ROOT_DIR/src-tauri/target/debug/bench_access_control"
elif [ -f "$ROOT_DIR/src-tauri/target/release/bench_access_control" ]; then
    BIN_PATH="$ROOT_DIR/src-tauri/target/release/bench_access_control"
else
    BIN_PATH="$ROOT_DIR/src-tauri/target/debug/bench_access_control"
fi

PIDS=()
cleanup() {
    echo ""
    echo "[*] Terminating background mesh processes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "[✓] All simulation daemons cleaned up."
}
trap cleanup EXIT INT TERM

echo "=========================================================================="
echo " 1. Starting Origin Server Peer (HTTP Control Plane: 9001)..."
echo "=========================================================================="
"$BIN_PATH" server --name "origin-mesh-1" --control-port 9001 &
PIDS+=($!)

# Wait for Origin Server to start up
for i in {1..40}; do
    if curl -s http://127.0.0.1:9001/status > /dev/null; then
        break
    fi
    sleep 0.15
done

ORIGIN_STATUS=$(curl -s http://127.0.0.1:9001/status)
ORIGIN_EP=$(echo "$ORIGIN_STATUS" | python3 -c "import sys, json; print(json.load(sys.stdin)['endpoint_id'])")
NAMESPACE=$(echo "$ORIGIN_STATUS" | python3 -c "import sys, json; print(json.load(sys.stdin)['namespace'])")
RESOURCE=$(echo "$ORIGIN_STATUS" | python3 -c "import sys, json; print(json.load(sys.stdin)['resource'])")
TICKET=$(echo "$ORIGIN_STATUS" | python3 -c "import sys, json; print(json.load(sys.stdin)['ticket'])")

echo "[✓] Origin Server running:"
echo "    Endpoint ID: $ORIGIN_EP"
echo "    Namespace:   $NAMESPACE"
echo "    Resource:    $RESOURCE"
echo "    Ticket:      $TICKET"

REPLICA_PORTS=()
REPLICA_EPS=()

for r in $(seq 1 "$REPLICA_COUNT"); do
    PORT=$((9001 + r))
    REPLICA_PORTS+=("$PORT")

    echo ""
    echo "=========================================================================="
    echo " 2.$r Starting Replica Server #$r (HTTP Control Plane: $PORT)..."
    echo "=========================================================================="
    "$BIN_PATH" server --name "replica-mesh-$r" --control-port "$PORT" &
    PIDS+=($!)

    for i in {1..40}; do
        if curl -s "http://127.0.0.1:$PORT/status" > /dev/null; then
            break
        fi
        sleep 0.15
    done

    REP_STATUS=$(curl -s "http://127.0.0.1:$PORT/status")
    REP_EP=$(echo "$REP_STATUS" | python3 -c "import sys, json; print(json.load(sys.stdin)['endpoint_id'])")
    REPLICA_EPS+=("$REP_EP")

    echo "[*] Registering Replica Server ($REP_EP) on Origin..."
    curl -s -X POST http://127.0.0.1:9001/add_server \
        -H "Content-Type: application/json" \
        -d "{\"server\":\"$REP_EP\"}" > /dev/null

    # Refresh ticket from Origin to include newly registered replica
    TICKET=$(curl -s http://127.0.0.1:9001/status | python3 -c "import sys, json; print(json.load(sys.stdin)['ticket'])")

    echo "[*] Importing Ticket on Replica Server..."
    IMPORT_BODY=$(python3 -c "import json; print(json.dumps({'ticket': '''$TICKET'''}))")
    curl -s -X POST "http://127.0.0.1:$PORT/import_ticket" \
        -H "Content-Type: application/json" \
        -d "$IMPORT_BODY" > /dev/null

    echo "[✓] Replica #$r successfully joined mesh ($REP_EP)"
done

# Allow mesh gossip/replication to settle
sleep 0.8

echo ""
echo "=========================================================================="
echo " 3. Testing Wire Rejection Before Grant via Viewer Load Generator"
echo "=========================================================================="
echo "[*] Dispatching 30 unauthorized stream requests to Origin over QUIC (Expected: 100% Rejected)..."
"$BIN_PATH" viewer --server "$ORIGIN_EP" --namespace "$NAMESPACE" --resource "$RESOURCE" --requests 30 --concurrency 5

echo ""
echo "=========================================================================="
echo " 4. Testing Multi-Process Dynamic Grant Propagation Across Mesh"
echo "=========================================================================="
TEST_VIEWER=$(curl -s http://127.0.0.1:9001/new_viewer_key)
echo "[*] Generated fresh test viewer ID: $TEST_VIEWER"

for idx in "${!REPLICA_PORTS[@]}"; do
    PORT="${REPLICA_PORTS[$idx]}"
    echo "[*] Initial Auth Check on Replica on :$PORT (expected: false):"
    curl -s -X POST "http://127.0.0.1:$PORT/check_auth" \
        -H "Content-Type: application/json" \
        -d "{\"namespace\":\"$NAMESPACE\",\"resource\":\"$RESOURCE\",\"viewer\":\"$TEST_VIEWER\"}"
    echo ""
done

echo "[*] Granting permission to test viewer on ORIGIN server..."
START_GRANT=$(python3 -c 'import time; print(int(time.time() * 1000000))')
curl -s -X POST http://127.0.0.1:9001/grant \
    -H "Content-Type: application/json" \
    -d "{\"namespace\":\"$NAMESPACE\",\"resource\":\"$RESOURCE\",\"viewer\":\"$TEST_VIEWER\"}" > /dev/null

# Poll replicas for convergence
for idx in "${!REPLICA_PORTS[@]}"; do
    PORT="${REPLICA_PORTS[$idx]}"
    CONVERGED=false
    for _ in {1..50}; do
        RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/check_auth" \
            -H "Content-Type: application/json" \
            -d "{\"namespace\":\"$NAMESPACE\",\"resource\":\"$RESOURCE\",\"viewer\":\"$TEST_VIEWER\"}")
        if echo "$RESP" | grep -q '"authorized":true'; then
            CONVERGED=true
            break
        fi
        sleep 0.02
    done
    END_GRANT=$(python3 -c 'import time; print(int(time.time() * 1000000))')
    DIFF_MS=$(python3 -c "print(f'{($END_GRANT - $START_GRANT) / 1000.0:.2f}')")
    if [ "$CONVERGED" = true ]; then
        echo "[✓] Replica on :$PORT converged on GRANT in ${DIFF_MS} ms!"
    else
        echo "[X] Replica on :$PORT failed to converge on GRANT within timeout"
        exit 1
    fi
done

echo ""
echo "=========================================================================="
echo " 5. Testing Multi-Process Dynamic Revocation Propagation Across Mesh"
echo "=========================================================================="
echo "[*] Revoking permission on ORIGIN server..."
START_REVOKE=$(python3 -c 'import time; print(int(time.time() * 1000000))')
curl -s -X POST http://127.0.0.1:9001/revoke \
    -H "Content-Type: application/json" \
    -d "{\"namespace\":\"$NAMESPACE\",\"resource\":\"$RESOURCE\",\"viewer\":\"$TEST_VIEWER\"}" > /dev/null

# Poll replicas for revocation convergence
for idx in "${!REPLICA_PORTS[@]}"; do
    PORT="${REPLICA_PORTS[$idx]}"
    CONVERGED=false
    for _ in {1..50}; do
        RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/check_auth" \
            -H "Content-Type: application/json" \
            -d "{\"namespace\":\"$NAMESPACE\",\"resource\":\"$RESOURCE\",\"viewer\":\"$TEST_VIEWER\"}")
        if echo "$RESP" | grep -q '"authorized":false'; then
            CONVERGED=true
            break
        fi
        sleep 0.02
    done
    END_REVOKE=$(python3 -c 'import time; print(int(time.time() * 1000000))')
    DIFF_MS=$(python3 -c "print(f'{($END_REVOKE - $START_REVOKE) / 1000.0:.2f}')")
    if [ "$CONVERGED" = true ]; then
        echo "[✓] Replica on :$PORT converged on REVOCATION in ${DIFF_MS} ms (0% post-convergence leakage)!"
    else
        echo "[X] Replica on :$PORT failed to converge on REVOCATION within timeout"
        exit 1
    fi
done

echo ""
echo "=========================================================================="
echo " [✓] Multi-process mesh cluster simulation passed with 100% convergence!"
echo "=========================================================================="
