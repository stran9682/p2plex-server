use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use iroh::{endpoint::presets, Endpoint};

use crate::{
    benchmark::{
        node::{generate_random_endpoint, upload_synthetic_video},
        stats::BenchmarkResult,
    },
    iroh_runtime::IrohRuntime,
    protocol::{viewer::Viewer, Request},
    store::PermissionLevel,
};

pub struct ServerMesh {
    pub origin: Arc<IrohRuntime>,
    pub replicas: Vec<Arc<IrohRuntime>>,
    pub namespace: String,
    pub resource: String,
}

impl ServerMesh {
    pub async fn create(replica_count: usize) -> anyhow::Result<Self> {
        let origin = Arc::new(IrohRuntime::create_in_memory().await?);
        let (namespace, resource) = upload_synthetic_video(&origin, None).await?;

        let mut replicas = Vec::with_capacity(replica_count);
        for _ in 0..replica_count {
            let replica = Arc::new(IrohRuntime::create_in_memory().await?);
            origin
                .add_server(namespace.clone(), replica.endpoint_id().to_string())
                .await?;
            replicas.push(replica);
        }

        let ticket = origin.generate_ticket(&namespace).await?;

        for replica in &replicas {
            replica.import_ticket(ticket.clone()).await?;
        }

        // Allow initial replication streams to settle
        let settle_ms = 100 + (replica_count as u64 * 25);
        tokio::time::sleep(std::time::Duration::from_millis(settle_ms)).await;

        Ok(Self {
            origin,
            replicas,
            namespace,
            resource,
        })
    }

    pub fn total_servers(&self) -> usize {
        1 + self.replicas.len()
    }

    pub fn get_server(&self, index: usize) -> Arc<IrohRuntime> {
        if index == 0 {
            self.origin.clone()
        } else {
            self.replicas[index - 1].clone()
        }
    }
}

/// Benchmarks grant and revocation propagation latencies across a multi-server mesh
pub async fn run_mesh_convergence_benchmark(
    mesh: &ServerMesh,
    rounds: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    let total_servers = mesh.total_servers();
    let replica_count = mesh.replicas.len();

    println!(
        "\n--- Benchmarking Mesh Convergence: {} servers (1 Origin + {} Replicas) over {} rounds ---",
        total_servers, replica_count, rounds
    );

    let mut grant_samples_us = Vec::with_capacity(rounds);
    let mut revoke_samples_us = Vec::with_capacity(rounds);

    for round in 1..=rounds {
        let viewer_id = generate_random_endpoint();

        // 1. Grant Access on Origin and measure time until ALL replicas converge
        let grant_start = Instant::now();
        mesh.origin
            .add_viewer(
                mesh.namespace.clone(),
                mesh.resource.clone(),
                viewer_id.to_string(),
            )
            .await?;

        let mut all_granted = false;
        let grant_timeout = Instant::now() + std::time::Duration::from_secs(5);
        while Instant::now() < grant_timeout {
            let mut ready = true;
            for replica in &mesh.replicas {
                let status = replica
                    .access_control()
                    .list_manager()
                    .check_authorization(&mesh.namespace, Some(&mesh.resource), &viewer_id)
                    .await?;
                if status != PermissionLevel::Viewer {
                    ready = false;
                    break;
                }
            }
            if ready {
                all_granted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }

        assert!(
            all_granted,
            "Mesh failed to converge on Grant within timeout"
        );
        grant_samples_us.push(grant_start.elapsed().as_secs_f64() * 1_000_000.0);

        // 2. Revoke Access on Origin and measure time until ALL replicas converge to Unauthorized
        let revoke_start = Instant::now();
        mesh.origin
            .remove_viewer(
                mesh.namespace.clone(),
                mesh.resource.clone(),
                viewer_id.to_string(),
            )
            .await?;

        let mut all_revoked = false;
        let revoke_timeout = Instant::now() + std::time::Duration::from_secs(5);
        while Instant::now() < revoke_timeout {
            let mut ready = true;
            for replica in &mesh.replicas {
                let status = replica
                    .access_control()
                    .list_manager()
                    .check_authorization(&mesh.namespace, Some(&mesh.resource), &viewer_id)
                    .await?;
                if status != PermissionLevel::Unauthorized {
                    ready = false;
                    break;
                }
            }
            if ready {
                all_revoked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }

        assert!(
            all_revoked,
            "Mesh failed to converge on Revocation within timeout"
        );
        revoke_samples_us.push(revoke_start.elapsed().as_secs_f64() * 1_000_000.0);

        if round % 5 == 0 || round == rounds {
            print!(".");
        }
    }
    println!();

    results.push(BenchmarkResult::compute(
        "Mesh Convergence",
        &format!("Grant Propagate -> Full Mesh (S={})", total_servers),
        total_servers,
        grant_samples_us,
    ));

    results.push(BenchmarkResult::compute(
        "Mesh Convergence",
        &format!("Revoke Propagate -> Full Mesh (S={})", total_servers),
        total_servers,
        revoke_samples_us,
    ));

    Ok(())
}

/// Benchmarks concurrent wire load distributed across a multi-server mesh
pub async fn run_distributed_viewer_mesh_load(
    mesh: &ServerMesh,
    num_viewers: usize,
    requests_per_viewer: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    let total_servers = mesh.total_servers();
    println!(
        "\n--- Benchmarking Distributed Wire Load: {} viewers across {} servers ({} req/viewer) ---",
        num_viewers, total_servers, requests_per_viewer
    );

    // Prepare half authorized, half unauthorized viewers
    let mut auth_keys = Vec::with_capacity(num_viewers / 2);
    for _ in 0..(num_viewers / 2) {
        let key = crate::benchmark::node::generate_random_secret_key();
        let ep = key.public();
        mesh.origin
            .add_viewer(
                mesh.namespace.clone(),
                mesh.resource.clone(),
                ep.to_string(),
            )
            .await?;
        auth_keys.push(key);
    }

    // Wait for all replicas to receive the grants
    tokio::time::sleep(std::time::Duration::from_millis(150 + total_servers as u64 * 20)).await;

    let total_reqs = num_viewers * requests_per_viewer;
    let auth_success_count = Arc::new(AtomicUsize::new(0));
    let unauth_rejected_count = Arc::new(AtomicUsize::new(0));

    let auth_samples = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_reqs / 2)));
    let unauth_samples = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_reqs / 2)));

    let mut handles = Vec::with_capacity(num_viewers);

    for i in 0..num_viewers {
        let is_auth = i < num_viewers / 2;
        let target_server_idx = i % total_servers;
        let target_server_id = mesh.get_server(target_server_idx).endpoint_id();
        let namespace = mesh.namespace.clone();
        let resource = mesh.resource.clone();

        let auth_success = auth_success_count.clone();
        let unauth_rejected = unauth_rejected_count.clone();
        let auth_vec = auth_samples.clone();
        let unauth_vec = unauth_samples.clone();

        let secret_key = if is_auth {
            auth_keys[i].clone()
        } else {
            crate::benchmark::node::generate_random_secret_key()
        };

        handles.push(tokio::spawn(async move {
            let client_ep = Endpoint::builder(presets::N0)
                .secret_key(secret_key)
                .bind()
                .await
                .unwrap();
            let viewer = Viewer::new(client_ep);

            let req = Request::new(namespace, resource, "playlist.m3u8".to_string());

            for _ in 0..requests_per_viewer {
                let start = Instant::now();
                let res = viewer.retreive_remote(target_server_id, &req).await;
                let elapsed_us = start.elapsed().as_secs_f64() * 1_000_000.0;

                match res {
                    Ok(Some(_)) => {
                        auth_success.fetch_add(1, Ordering::Relaxed);
                        let mut v = auth_vec.lock().await;
                        v.push(elapsed_us);
                    }
                    Ok(None) => {
                        unauth_rejected.fetch_add(1, Ordering::Relaxed);
                        let mut v = unauth_vec.lock().await;
                        v.push(elapsed_us);
                    }
                    Err(_) => {
                        // Connection or stream error
                        unauth_rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let auth_count = auth_success_count.load(Ordering::Relaxed);
    let unauth_count = unauth_rejected_count.load(Ordering::Relaxed);

    println!(
        "Completed distributed load: {} authorized hits, {} unauthorized rejections",
        auth_count, unauth_count
    );

    let auth_latencies = auth_samples.lock().await.clone();
    let unauth_latencies = unauth_samples.lock().await.clone();

    results.push(BenchmarkResult::compute(
        "Distributed Mesh Load",
        &format!("Authorized Stream Acceptance (S={}, V={})", total_servers, num_viewers),
        num_viewers,
        auth_latencies,
    ));

    results.push(BenchmarkResult::compute(
        "Distributed Mesh Load",
        &format!("Unauthorized ALPN Rejection (S={}, V={})", total_servers, num_viewers),
        num_viewers,
        unauth_latencies,
    ));

    Ok(())
}
