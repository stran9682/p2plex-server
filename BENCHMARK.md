# Decentralized Access Control Benchmark Guide

A high-performance benchmark and simulation suite for evaluating decentralized access control in `video-server`, built on top of **Iroh 1.1**, **Appa-style signed LWW-CRDTs**, and wire-level **QUIC ALPN** authentication gates.

---

## 1. Architectural Overview

The access control architecture enforces a strict separation between **Mesh Servers** and **Viewers**:
- **Mesh Servers (Nodes):** Replicate cryptographic access control metadata and video blobs peer-to-peer.
  - Server membership is managed via signed `ServerPermissions` (Writer vs Server permissions).
  - Video ACLs are signed by the content writer using Ed25519 signatures encapsulated in Conflict-Free Replicated Data Types (`LwwEntry<SignedAcl>`).
  - Servers synchronize video records and broadcast state changes over the `b"management"` QUIC ALPN.
- **Viewers (Clients):** Never access the private access control document, keys, or server peer rosters.
  - **Discovery (`DISCOVERY_ALPN = b"discovery"`):** Viewers query servers for only the videos they are authorized to access. Servers filter out any unauthorized resources before replying.
  - **Media Gate (`ALPN = b"gate"`):** Viewers request video chunks over QUIC (`Request`). Servers authenticate the caller's Ed25519 public key (`EndpointId`) against the local signed ACL before serving stream data. Unauthorized callers receive an immediate single-byte rejection (`Status::Denied`), terminating the stream instantly.

---

## 2. Benchmark CLI Subcommands

The benchmark binary is located at [`src-tauri/src/bin/bench_access_control.rs`](file:///Users/sebastiantran/Documents/Research/RTP%20Research/file%20sync/video-server/src-tauri/src/bin/bench_access_control.rs).

### A. Peer Scalability Suite (`peers`)
Evaluates authorization decision speed, ACL mutations, wire-gate QUIC round-trips, discovery filtering, and concurrent contention as the number of peers grows:

```bash
# Quick run with reduced iterations
./scripts/run_benchmarks.sh peers --quick

# Full statistical release benchmark
./scripts/run_benchmarks.sh peers
```

### B. Multi-Server Mesh Scalability Suite (`mesh`)
Benchmarks mesh formation, peer ticket synchronization, broadcast propagation latencies, distributed viewer traffic, and server revocation:

```bash
# Benchmark mesh scaling across 2, 3, and 4 servers
./scripts/run_benchmarks.sh mesh --servers 2,3,4 --rounds 5 --viewers 12
```

### C. Multi-Process Cluster Simulation (`simulate`)
Simulates a real-world multi-host deployment by launching independent background OS daemons on distinct network ports:
- Starts Origin Server daemon with an HTTP REST control plane (`http://127.0.0.1:9001`).
- Starts $N$ Replica Server daemons (`:9002`, `:9003`, ...).
- Origin registers replicas in the mesh and exchanges `ServerTicket`s.
- Dispatches concurrent viewer traffic over QUIC wire gates (asserts 100% rejection pre-grant).
- Grants viewer access dynamically via REST and measures real-time convergence across independent processes.
- Revokes viewer access dynamically via REST and verifies **0% post-convergence leakage**.

```bash
# Simulate a 3-node cluster (1 Origin + 2 Replicas)
./scripts/simulate_mesh_cluster.sh 2

# Simulate a 5-node cluster (1 Origin + 4 Replicas)
./scripts/simulate_mesh_cluster.sh 4
```

### D. Standalone Remote Server Daemon (`server`)
Runs a persistent Iroh server node with an embedded **HTTP REST Control Plane** allowing remote coordinators to dynamically inspect status, generate tickets, issue grants/revocations, and query authorization:

```bash
# Host 1: Start Origin Server
cargo run --release --bin bench_access_control -- server --name origin-east --control-port 9001

# Host 2: Join Replica Server via Ticket
cargo run --release --bin bench_access_control -- server --name replica-west --control-port 9002 --ticket <TICKET>
```

#### HTTP Control Plane API
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/status` | Returns node role, endpoint ID, store namespace, resource hash, and ticket. |
| `GET` | `/new_viewer_key` | Generates a valid test Ed25519 viewer endpoint ID. |
| `POST` | `/add_server` | Authorizes a replica server in the mesh: `{"server": "..."}` |
| `POST` | `/import_ticket` | Imports a ticket and syncs videos/ACLs: `{"ticket": "..."}` |
| `POST` | `/grant` | Grants a viewer access: `{"viewer": "..."}` |
| `POST` | `/revoke` | Revokes a viewer's access: `{"viewer": "..."}` |
| `POST` | `/check_auth` | Evaluates authorization: `{"viewer": "..."}` |

### E. Standalone Remote Viewer Load Generator (`viewer`)
Connects directly to a remote server over wire QUIC (`ALPN = b"gate"`), issuing concurrent stream requests:

```bash
cargo run --release --bin bench_access_control -- viewer \
  --server <SERVER_ENDPOINT_ID> \
  --namespace <NAMESPACE> \
  --resource <RESOURCE> \
  --requests 500 \
  --concurrency 25
```

---

## 3. Quick-Start Scripts Summary

| Command | Purpose |
| :--- | :--- |
| `./scripts/run_benchmarks.sh peers` | Run viewer peer scaling benchmarks (decision latency, mutations, wire gate). |
| `./scripts/run_benchmarks.sh mesh` | Run multi-server mesh scaling benchmarks ($S=2,3,4$ servers). |
| `./scripts/run_benchmarks.sh all` | Run both peer and mesh benchmarks and print a complete report. |
| `./scripts/simulate_mesh_cluster.sh` | Run multi-process OS simulation on localhost with REST control planes. |
| `./scripts/run_benchmarks.sh test` | Run fast automated integration tests (`access_control_bench`). |
| `./test_mp4_access.sh` | Run E2E verification with real uploaded `.mp4` video files. |

---

## 4. Empirical Performance Baseline (Release Mode)

### A. Peer & ACL Scaling
| Category | Scenario | Scale / Peers | Mean Latency | Median (p50) | p95 Latency | Throughput |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Decision Latency** | Authorized Viewer (Hit) | 1 | 38.92 µs | 38.46 µs | 46.58 µs | **25,700 ops/s** |
| **Decision Latency** | Unauthorized Viewer (Miss) | 1 | 41.34 µs | 40.17 µs | 45.62 µs | **24,200 ops/s** |
| **Decision Latency** | Authorized Viewer (Hit) | 10 | 66.85 µs | 64.92 µs | 78.04 µs | **15,000 ops/s** |
| **Decision Latency** | Authorized Viewer (Hit) | 50 | 185.75 µs | 181.67 µs | 223.33 µs | **5,400 ops/s** |
| **Decision Latency** | Authorized Viewer (Hit) | 100 | 395.05 µs | 393.54 µs | 411.88 µs | **2,500 ops/s** |
| **ACL Mutation** | Grant Access (+1 viewer @ base 0) | 0 | 130.14 µs | 129.42 µs | 168.54 µs | **7,700 ops/s** |
| **ACL Mutation** | Revoke Access (-1 viewer @ base 0) | 0 | 129.46 µs | 120.21 µs | 167.50 µs | **7,700 ops/s** |
| **ACL Mutation** | Grant Access (+1 viewer @ base 100) | 100 | 818.91 µs | 817.08 µs | 836.42 µs | **1,200 ops/s** |
| **Discovery Protocol** | Unauthorized Filtered Query RTT | 0 | 1.51 ms | 1.24 ms | 3.16 ms | **664 ops/s** |
| **Concurrent Load** | Concurrent Wire Gate Tasks ($C=50$) | 50 | 5.22 ms | 5.22 ms | 84.03 ms | **190 ops/s** |

### B. Multi-Server Mesh Scaling
| Category | Scenario | Scale ($S$) | Mean Latency | Median (p50) | p95 Latency | Throughput |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Mesh Convergence** | Grant Propagate -> Full Mesh | 2 servers | 1.59 ms | 1.51 ms | 2.00 ms | **630 ops/s** |
| **Mesh Convergence** | Revoke Propagate -> Full Mesh | 2 servers | 1.40 ms | 1.41 ms | 1.44 ms | **713 ops/s** |
| **Mesh Convergence** | Grant Propagate -> Full Mesh | 3 servers | 4.52 ms | 4.87 ms | 5.61 ms | **221 ops/s** |
| **Mesh Convergence** | Revoke Propagate -> Full Mesh | 3 servers | 6.42 ms | 3.41 ms | 12.81 ms | **156 ops/s** |
| **Mesh Convergence** | Grant Propagate -> Full Mesh | 4 servers | 7.64 ms | 4.54 ms | 13.89 ms | **131 ops/s** |
| **Mesh Convergence** | Revoke Propagate -> Full Mesh | 4 servers | 4.77 ms | 4.17 ms | 6.16 ms | **210 ops/s** |
| **Server Revocation** | Revoke Server Node from Mesh | 2 servers | 301.29 µs | 301.29 µs | 301.29 µs | **3,300 ops/s** |
| **Server Revocation** | Revoke Server Node from Mesh | 4 servers | 2.30 ms | 2.30 ms | 2.30 ms | **434 ops/s** |
| **Multi-Process Convergence** | Dynamic Grant over OS Processes | 3 processes | 40.40 ms | 40.40 ms | 70.54 ms | **25 ops/s** |
| **Multi-Process Convergence** | Dynamic Revocation over OS Processes | 3 processes | 35.12 ms | 35.12 ms | 65.64 ms | **28 ops/s** |

---

## 5. Post-Hoc Analysis via CSV Export

All benchmark suites automatically produce RFC-4180 compliant CSV files stored in `bench_results/` (or a custom directory specified via `--csv-dir`):

### Generated CSV Datasets

1. **Summary CSV (`*_summary.csv`)**:
   Contains aggregated statistics per scenario and peer scale:
   `category,scenario,scale,iterations,min_us,max_us,mean_us,median_us,p95_us,p99_us,std_dev_us,ops_per_sec`

2. **Raw Trial Samples CSV (`*_raw_samples.csv`)**:
   Contains every individual trial run sample for granular statistical modeling (CDFs, ANOVA, boxplots, distribution skew):
   `category,scenario,scale,iteration,latency_us`

3. **Cluster Simulation CSV (`cluster_simulation.csv`)**:
   Captures dynamic multi-process mesh convergence metrics per replica node:
   `timestamp,replica_name,port,endpoint_id,phase,latency_ms,authorized,leakage`

### CLI Flags for CSV Output

```bash
# Save both summary and raw samples to a directory
cargo run --release --bin bench_access_control -- peers --csv-dir ./my_results

# Save summary CSV to a specific file
cargo run --release --bin bench_access_control -- peers --csv-file ./summary.csv

# Save raw samples CSV to a specific file
cargo run --release --bin bench_access_control -- peers --csv-raw ./raw_trials.csv

# Print summary CSV to stdout
cargo run --release --bin bench_access_control -- peers --csv
```

### Python Post-Hoc Analysis Snippet (Pandas / Seaborn)

```python
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load raw trial samples
df_raw = pd.read_csv("bench_results/peers_raw_samples.csv")

# 1. Latency Scaling Curve (Mean + 95% Confidence Interval)
plt.figure(figsize=(10, 6))
sns.lineplot(
    data=df_raw[df_raw["category"] == "Decision Latency"],
    x="scale",
    y="latency_us",
    hue="scenario",
    marker="o",
)
plt.title("Authorization Decision Latency vs. Peer Scale")
plt.xlabel("Number of Authorized Viewers (N)")
plt.ylabel("Latency (µs)")
plt.grid(True, linestyle="--", alpha=0.6)
plt.savefig("bench_results/decision_latency_scaling.png")

# 2. Cumulative Distribution Function (CDF) at Scale 100
plt.figure(figsize=(10, 6))
scale_100 = df_raw[df_raw["scale"] == 100]
sns.ecdfplot(data=scale_100, x="latency_us", hue="scenario")
plt.title("Empirical CDF at Scale N=100")
plt.xlabel("Latency (µs)")
plt.ylabel("Cumulative Probability")
plt.grid(True, linestyle="--", alpha=0.6)
plt.savefig("bench_results/cdf_scale_100.png")

# 3. Load Summary Data for Publication Table
df_summary = pd.read_csv("bench_results/peers_summary.csv")
print(df_summary[["scenario", "scale", "mean_us", "p95_us", "ops_per_sec"]])
```

