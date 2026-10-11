#!/usr/bin/env bash
set -e

# ==============================================================================
# Helper Script: Run Multi-VM Decentralized Benchmarks via Ansible
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v ansible-playbook >/dev/null 2>&1; then
    echo "[X] Error: ansible-playbook is not installed on this machine."
    echo "    Please install Ansible: brew install ansible (macOS) or pip install ansible"
    exit 1
fi

if [ ! -f "inventory.ini" ]; then
    echo "[!] inventory.ini not found. Creating from inventory.ini.example..."
    cp inventory.ini.example inventory.ini
    echo "[!] Please edit 'ansible/inventory.ini' with your VM IP addresses and re-run."
    exit 1
fi

MODE="${1:-mesh}"

case "$MODE" in
    setup)
        echo "[*] Provisioning remote nodes and building benchmark binaries..."
        ansible-playbook setup_nodes.yml
        ;;
    peers)
        echo "[*] Running peer scalability microbenchmarks across remote VMs..."
        ansible-playbook run_peer_benchmarks.yml
        ;;
    mesh)
        echo "[*] Running distributed multi-VM mesh benchmark..."
        ansible-playbook run_distributed_mesh.yml
        ;;
    teardown)
        echo "[*] Stopping remote benchmark daemons..."
        ansible-playbook teardown.yml
        ;;
    all)
        echo "[*] Setting up nodes..."
        ansible-playbook setup_nodes.yml
        echo "[*] Running peer benchmarks..."
        ansible-playbook run_peer_benchmarks.yml
        echo "[*] Running distributed mesh benchmark..."
        ansible-playbook run_distributed_mesh.yml
        ;;
    *)
        echo "Usage: ./run_all.sh <setup|peers|mesh|teardown|all>"
        exit 1
        ;;
esac
