#!/usr/bin/env bash
set -e

# ==============================================================================
# Decentralized Access Control Benchmark Runner
# ==============================================================================
# Usage:
#   ./scripts/run_benchmarks.sh peers [--quick] [--json]
#   ./scripts/run_benchmarks.sh mesh [--servers 2,3,5] [--rounds 10] [--viewers 20]
#   ./scripts/run_benchmarks.sh all [--quick]
#   ./scripts/run_benchmarks.sh simulate [--servers 3]
#   ./scripts/run_benchmarks.sh test
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-peers}"

RESULTS_DIR="$ROOT_DIR/bench_results"
mkdir -p "$RESULTS_DIR"

case "$MODE" in
    test)
        echo "[*] Running Access Control Benchmark Integration Tests..."
        cd "$ROOT_DIR/src-tauri"
        cargo test --test access_control_bench -- --nocapture
        ;;
    simulate)
        echo "[*] Running Multi-Process Mesh Cluster Simulation..."
        shift || true
        exec "$SCRIPT_DIR/simulate_mesh_cluster.sh" "$@"
        ;;
    mesh)
        shift || true
        cd "$ROOT_DIR/src-tauri"
        cargo run --release --bin bench_access_control -- mesh --csv-dir "$RESULTS_DIR" "$@"
        ;;
    peers)
        shift || true
        cd "$ROOT_DIR/src-tauri"
        cargo run --release --bin bench_access_control -- peers --csv-dir "$RESULTS_DIR" "$@"
        ;;
    all)
        shift || true
        cd "$ROOT_DIR/src-tauri"
        cargo run --release --bin bench_access_control -- all --csv-dir "$RESULTS_DIR" "$@"
        ;;
    *)
        echo "Usage: $0 {peers|mesh|all|simulate|test} [args...]"
        exit 1
        ;;
esac
