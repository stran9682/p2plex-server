# Distributed Benchmark Orchestration with Ansible

This directory contains automated Ansible playbooks to provision, coordinate, and execute the decentralized access control benchmarks across **multiple physical or cloud virtual machines (VMs)** (e.g., AWS EC2, GCP Compute Engine, Azure, DigitalOcean, Hetzner, or local Libvirt/Proxmox clusters).

---

## Architecture Overview

```
                      +-----------------------------+
                      |     Ansible Controller      |
                      | (Your Local Machine / CI/CD)|
                      +--------------+--------------+
                                     |
               SSH Automation & Orchestration (Playbooks)
                                     |
         +---------------------------+---------------------------+
         |                                                       |
+--------v--------+             +--------v--------+             +v----------------+
|  Origin Server  |  Iroh QUIC  | Replica Servers |  QUIC Load  | Remote Viewers  |
|      (VM 1)     |<===========>| (VM 2, 3, ...)  |<============|  (VM 4, 5...)   |
|                 | Wire Mesh   |                 | Streams     |                 |
| - REST :9001    | Broadcasts  | - REST :9001    |             | - bench viewer  |
| - bench server  |             | - bench server  |             |                 |
+-----------------+             +-----------------+             +-----------------+
```

1. **Origin Server (`[origin_server]`)**: Initiates the namespace, authors synthetic video content, and distributes cryptographic server tickets.
2. **Replica Servers (`[replica_servers]`)**: Import tickets from Origin, join the Iroh mesh, replicate video Merkle roots and signed ACLs, and enforce the wire ALPN gate.
3. **Remote Viewers (`[viewers]`)**: Act as clients dispatching concurrent QUIC stream authorization requests over the network.

---

## Directory Structure

```
ansible/
├── ansible.cfg                    # Optimized connection & pipelining config
├── inventory.ini.example          # Inventory template for your VM IPs & credentials
├── setup_nodes.yml                # Installs OS packages, Rust, syncs code, builds binary
├── run_distributed_mesh.yml       # Orchestrates full multi-VM mesh benchmark & 0% leakage test
├── run_peer_benchmarks.yml        # Runs isolated peer scaling microbenchmarks on VMs
├── teardown.yml                   # Kills background server daemons and cleans temporary files
├── run_all.sh                     # Convenience wrapper script
└── results/                       # Local directory where fetched reports & JSON are saved
```

---

## Quick Start Guide

### 1. Prerequisites on Controller Machine

Ensure Ansible and `rsync` are installed on your local control machine:
```bash
# macOS
brew install ansible

# Ubuntu / Debian
sudo apt update && sudo apt install -y ansible rsync

# Python virtual environment
pip install ansible
```

### 2. Configure Your Inventory

Copy the example inventory and edit it with your VMs' IP addresses and SSH details:
```bash
cd ansible
cp inventory.ini.example inventory.ini
nano inventory.ini
```

Example `inventory.ini`:
```ini
[origin_server]
origin-1 ansible_host=192.168.1.101 control_port=9001 node_name=origin-1

[replica_servers]
replica-1 ansible_host=192.168.1.102 control_port=9001 node_name=replica-1
replica-2 ansible_host=192.168.1.103 control_port=9001 node_name=replica-2

[mesh_servers:children]
origin_server
replica_servers

[viewers]
viewer-1 ansible_host=192.168.1.104
viewer-2 ansible_host=192.168.1.105

[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_ed25519
remote_project_dir=/home/ubuntu/video-server
```

Verify SSH connectivity:
```bash
ansible all -m ping
```

---

## Running the Playbooks

### Step 1: Provision Nodes & Build Binaries
Installs system dependencies (`build-essential`, `libssl-dev`, `pkg-config`), installs the Rust toolchain via `rustup`, synchronizes the codebase, and compiles `bench_access_control` in `--release` mode on all VMs:
```bash
ansible-playbook setup_nodes.yml
```

### Step 2: Run the Distributed Mesh Benchmark
Orchestrates the entire multi-VM distributed benchmark:
- Starts Origin daemon on VM 1
- Starts Replica daemons on VMs 2 and 3
- Mutual ticket exchange & mesh peering
- Dynamic `GRANT` propagation latency across physical VMs
- Dynamic `REVOCATION` propagation latency across physical VMs
- Verifies 0% post-convergence authorization leakage
- Executes concurrent QUIC load from Viewer VMs
```bash
ansible-playbook run_distributed_mesh.yml
```

### Step 3: Run Peer Microbenchmarks (Optional)
Runs authorization decision latency, mutation rate, and concurrent contention microbenchmarks on remote nodes and collects the JSON results:
```bash
ansible-playbook run_peer_benchmarks.yml
```

### Step 4: Teardown Daemons
Stops all background benchmark daemons on all VMs:
```bash
ansible-playbook teardown.yml
```

---

## Convenience Runner Script

You can also use [`run_all.sh`](run_all.sh) to run specific stages:
```bash
./run_all.sh setup       # Provision & compile
./run_all.sh mesh        # Run distributed mesh benchmark
./run_all.sh peers       # Run peer microbenchmarks
./run_all.sh teardown    # Stop remote daemons
./run_all.sh all         # Run entire pipeline from setup to mesh
```

---

## Output & Reports

After running `run_distributed_mesh.yml`, a Markdown report is generated in `ansible/results/distributed_mesh_report.md`:

```markdown
# Distributed Mesh Access Control Benchmark Report

- **Timestamp**: 2026-10-11T00:24:12Z
- **Mesh Topology**: 1 Origin + 2 Replicas
- **Origin Node**: `0a8c2...` (IP: `192.168.1.101`)
- **Namespace**: `7xKm49zL`
- **Resource Root**: `synthetic_video.mp4`

## Cross-VM Propagation Latencies

| Replica Host | Grant Convergence (ms) | Revocation Convergence (ms) | Post-Revocation Leakage |
|---|---|---|---|
| `192.168.1.102` | **4.12 ms** | **3.88 ms** | **0.00%** |
| `192.168.1.103` | **6.45 ms** | **5.21 ms** | **0.00%** |
```

---

## Firewall / Network Security Groups

Ensure the following ports are open between your VMs:
- **TCP `control_port` (default `9001`)**: REST control plane between the controller and mesh nodes.
- **UDP (All ephemeral ports or Iroh default)**: Iroh uses UDP QUIC for peer-to-peer mesh synchronization and viewer streaming. Iroh automatically falls back to public DERP relays if direct UDP connectivity is blocked by NAT or firewalls.
