use std::collections::HashSet;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use iroh::{endpoint::presets, Endpoint, EndpointId};

use video_server_lib::{
    benchmark::{
        cluster::{
            run_distributed_viewer_mesh_load, run_mesh_convergence_benchmark, ServerMesh,
        },
        node::{generate_random_endpoint, upload_synthetic_video},
        remote::{run_server_daemon, run_standalone_viewer},
        stats::{print_result_row, print_summary_table_markdown, BenchmarkResult},
    },
    iroh_runtime::IrohRuntime,
    protocol::{viewer::Viewer, Request},
};

fn get_arg_val(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if args[i].starts_with(&format!("{flag}=")) {
            return Some(args[i][flag.len() + 1..].to_string());
        }
    }
    None
}

// ===========================================================================
// Benchmark Suite: Peer Scalability
// ===========================================================================
async fn bench_peer_scalability(
    quick: bool,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    println!("\n==========================================================================");
    println!(" [1/5] BENCHMARK: Authorization Decision Latency vs. ACL Peer Scale");
    println!("==========================================================================");

    let runtime = IrohRuntime::create_in_memory().await?;
    let (namespace, resource) = upload_synthetic_video(&runtime, None).await?;

    let acl_scales = if quick {
        vec![1, 10, 50, 100]
    } else {
        vec![1, 10, 50, 100, 500, 1000]
    };

    let (warmup_iters, bench_iters) = if quick { (10, 50) } else { (30, 200) };

    for &scale in &acl_scales {
        let mut viewers: HashSet<EndpointId> = HashSet::with_capacity(scale);
        for _ in 0..scale {
            let ep = generate_random_endpoint();
            runtime
                .add_viewer(namespace.clone(), resource.clone(), ep.to_string())
                .await?;
            viewers.insert(ep);
        }

        let test_viewer = *viewers.iter().next().unwrap();
        let unauth_viewer = generate_random_endpoint();

        // 1. Authorized Viewer decision latency
        for _ in 0..warmup_iters {
            let _ = runtime
                .access_control()
                .list_manager()
                .check_authorization(&namespace, Some(&resource), &test_viewer)
                .await?;
        }

        let mut hit_samples = Vec::with_capacity(bench_iters);
        for _ in 0..bench_iters {
            let start = Instant::now();
            let _ = runtime
                .access_control()
                .list_manager()
                .check_authorization(&namespace, Some(&resource), &test_viewer)
                .await?;
            hit_samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        }

        let hit_res = BenchmarkResult::compute(
            "Decision Latency",
            "Authorized Viewer (Hit)",
            scale,
            hit_samples,
        );
        print_result_row(&hit_res);
        results.push(hit_res);

        // 2. Unauthorized Viewer decision latency
        let mut miss_samples = Vec::with_capacity(bench_iters);
        for _ in 0..bench_iters {
            let start = Instant::now();
            let _ = runtime
                .access_control()
                .list_manager()
                .check_authorization(&namespace, Some(&resource), &unauth_viewer)
                .await?;
            miss_samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        }

        let miss_res = BenchmarkResult::compute(
            "Decision Latency",
            "Unauthorized Viewer (Miss)",
            scale,
            miss_samples,
        );
        print_result_row(&miss_res);
        results.push(miss_res);
    }

    println!("\n==========================================================================");
    println!(" [2/5] BENCHMARK: ACL Mutation Latency (Grant & Revoke) vs. Scale");
    println!("==========================================================================");

    let mutation_scales = if quick { vec![0, 50, 100] } else { vec![0, 100, 500] };
    let mutation_iters = if quick { 15 } else { 40 };

    for &base_scale in &mutation_scales {
        let (ns, res) = upload_synthetic_video(&runtime, None).await?;
        for _ in 0..base_scale {
            runtime
                .add_viewer(
                    ns.clone(),
                    res.clone(),
                    generate_random_endpoint().to_string(),
                )
                .await?;
        }

        let mut grant_samples = Vec::with_capacity(mutation_iters);
        let mut revoke_samples = Vec::with_capacity(mutation_iters);

        for _ in 0..mutation_iters {
            let ep = generate_random_endpoint();

            let g_start = Instant::now();
            runtime
                .add_viewer(ns.clone(), res.clone(), ep.to_string())
                .await?;
            grant_samples.push(g_start.elapsed().as_secs_f64() * 1_000_000.0);

            let r_start = Instant::now();
            runtime
                .remove_viewer(ns.clone(), res.clone(), ep.to_string())
                .await?;
            revoke_samples.push(r_start.elapsed().as_secs_f64() * 1_000_000.0);
        }

        let g_res = BenchmarkResult::compute(
            "ACL Mutation",
            "Grant Access (+1 viewer)",
            base_scale,
            grant_samples,
        );
        print_result_row(&g_res);
        results.push(g_res);

        let r_res = BenchmarkResult::compute(
            "ACL Mutation",
            "Revoke Access (-1 viewer)",
            base_scale,
            revoke_samples,
        );
        print_result_row(&r_res);
        results.push(r_res);
    }

    println!("\n==========================================================================");
    println!(" [3/5] BENCHMARK: Wire Protocol ALPN Gate RTT Latency");
    println!("==========================================================================");

    let (wire_ns, wire_res) = upload_synthetic_video(&runtime, None).await?;
    let auth_key = video_server_lib::benchmark::node::generate_random_secret_key();
    let auth_id = auth_key.public();
    runtime
        .add_viewer(wire_ns.clone(), wire_res.clone(), auth_id.to_string())
        .await?;

    let origin_id = runtime.endpoint_id();

    let auth_ep = Endpoint::builder(presets::N0)
        .secret_key(auth_key)
        .bind()
        .await?;
    let auth_viewer = Viewer::new(auth_ep);

    let unauth_ep = Endpoint::bind(presets::N0).await?;
    let unauth_viewer = Viewer::new(unauth_ep);

    let req = Request::new(wire_ns, wire_res, "playlist.m3u8".to_string());

    let wire_iters = if quick { 20 } else { 100 };

    // Unauthorized wire gate rejection
    let mut unauth_samples = Vec::with_capacity(wire_iters);
    for _ in 0..wire_iters {
        let start = Instant::now();
        let res = unauth_viewer.retreive_remote(origin_id, &req).await?;
        assert!(res.is_none());
        unauth_samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    let unauth_wire_res = BenchmarkResult::compute(
        "Wire Gate Protocol",
        "Unauthorized ALPN Rejection RTT",
        0,
        unauth_samples,
    );
    print_result_row(&unauth_wire_res);
    results.push(unauth_wire_res);

    // Authorized wire gate acceptance
    let mut auth_samples = Vec::with_capacity(wire_iters);
    for _ in 0..wire_iters {
        let start = Instant::now();
        let res = auth_viewer.retreive_remote(origin_id, &req).await?;
        assert!(res.is_some());
        auth_samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    let auth_wire_res = BenchmarkResult::compute(
        "Wire Gate Protocol",
        "Authorized Stream Acceptance RTT",
        1,
        auth_samples,
    );
    print_result_row(&auth_wire_res);
    results.push(auth_wire_res);

    println!("\n==========================================================================");
    println!(" [4/5] BENCHMARK: Discovery Filtering Latency vs. Unauthorized Viewers");
    println!("==========================================================================");

    let disc_iters = if quick { 15 } else { 50 };
    let mut disc_samples = Vec::with_capacity(disc_iters);

    for _ in 0..disc_iters {
        let start = Instant::now();
        let disc = unauth_viewer
            .request_authorized_videos(&req.namespace, &origin_id)
            .await?;
        assert!(disc.unwrap_or_default().is_empty());
        disc_samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }

    let disc_res = BenchmarkResult::compute(
        "Discovery Protocol",
        "Unauthorized Filtered Query RTT",
        0,
        disc_samples,
    );
    print_result_row(&disc_res);
    results.push(disc_res);

    println!("\n==========================================================================");
    println!(" [5/5] BENCHMARK: High-Concurrency Gate Contention Throughput");
    println!("==========================================================================");

    let concurrencies = if quick { vec![10, 50] } else { vec![10, 50, 100] };
    let reqs_per_task = if quick { 10 } else { 20 };

    for &concurrency in &concurrencies {
        let start_all = Instant::now();
        let samples = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(
            concurrency * reqs_per_task,
        )));
        let mut handles = Vec::with_capacity(concurrency);

        for _ in 0..concurrency {
            let unauth_client = Viewer::new(Endpoint::bind(presets::N0).await?);
            let s_id = origin_id;
            let r = Request::new(
                req.namespace.clone(),
                req.resource.clone(),
                "playlist.m3u8".to_string(),
            );
            let smp = samples.clone();

            handles.push(tokio::spawn(async move {
                for _ in 0..reqs_per_task {
                    let s = Instant::now();
                    let _ = unauth_client.retreive_remote(s_id, &r).await;
                    let el = s.elapsed().as_secs_f64() * 1_000_000.0;
                    let mut vec = smp.lock().await;
                    vec.push(el);
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let _ = start_all.elapsed();
        let smp_vec = samples.lock().await.clone();
        let conc_res = BenchmarkResult::compute(
            "Concurrent Contention",
            &format!("Concurrent Wire Gate Tasks (C={})", concurrency),
            concurrency,
            smp_vec,
        );
        print_result_row(&conc_res);
        results.push(conc_res);
    }

    Ok(())
}

// ===========================================================================
// Benchmark Suite: Mesh Scalability
// ===========================================================================
async fn bench_mesh_scalability(
    mesh_sizes: Vec<usize>,
    rounds: usize,
    viewers: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    println!("\n==========================================================================");
    println!(" BENCHMARK: Multi-Server Decentralized Mesh Scalability");
    println!("==========================================================================");

    for &size in &mesh_sizes {
        let replica_count = size.saturating_sub(1);
        println!(
            "\n[+] Setting up Mesh of {} servers (1 Origin + {} Replicas)...",
            size, replica_count
        );

        let setup_start = Instant::now();
        let mesh = ServerMesh::create(replica_count).await?;
        let setup_elapsed_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
        println!(
            "[✓] Mesh of {} servers established in {:.2} ms",
            size, setup_elapsed_ms
        );

        // 1. Mesh Convergence (Grant & Revocation)
        run_mesh_convergence_benchmark(&mesh, rounds, results).await?;

        // 2. Distributed Load
        run_distributed_viewer_mesh_load(&mesh, viewers, 4, results).await?;

        // 3. Server Revocation Test
        if replica_count > 0 {
            let target_replica = mesh.replicas[0].endpoint_id();
            let revoke_start = Instant::now();
            let revoked = mesh
                .origin
                .remove_server(mesh.namespace.clone(), target_replica.to_string())
                .await?;
            let revoke_elapsed_us = revoke_start.elapsed().as_secs_f64() * 1_000_000.0;
            assert!(revoked);

            results.push(BenchmarkResult::compute(
                "Mesh Revocation",
                &format!("Revoke Server Node from Mesh (S={})", size),
                size,
                vec![revoke_elapsed_us],
            ));
            println!(
                "[✓] Server {} revoked from mesh (S={}) in {:.2} µs",
                target_replica, size, revoke_elapsed_us
            );
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("peers");

    let quick = args.iter().any(|a| a == "--quick");
    let json_output = args.iter().any(|a| a == "--json");

    let mut results = Vec::new();

    match mode {
        "peers" => {
            println!("==========================================================================");
            println!(" Decentralized Access Control Benchmark: Peer Scalability Suite");
            println!(" Mode: {}", if quick { "Quick (Reduced iterations)" } else { "Full" });
            println!("==========================================================================");

            bench_peer_scalability(quick, &mut results).await?;
            print_summary_table_markdown("Peer Scalability Benchmark Results", &results);
        }
        "mesh" => {
            let servers_str = get_arg_val(&args, "--servers").unwrap_or_else(|| "2,3,5".to_string());
            let servers: Vec<usize> = servers_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            let rounds: usize = get_arg_val(&args, "--rounds")
                .and_then(|s| s.parse().ok())
                .unwrap_or(if quick { 4 } else { 10 });

            let viewers: usize = get_arg_val(&args, "--viewers")
                .and_then(|s| s.parse().ok())
                .unwrap_or(if quick { 10 } else { 20 });

            println!("==========================================================================");
            println!(" Decentralized Access Control Benchmark: Multi-Server Mesh Suite");
            println!(" Mesh Sizes: {:?}, Rounds: {}, Concurrent Viewers: {}", servers, rounds, viewers);
            println!("==========================================================================");

            bench_mesh_scalability(servers, rounds, viewers, &mut results).await?;
            print_summary_table_markdown("Multi-Server Mesh Benchmark Results", &results);
        }
        "all" => {
            println!("==========================================================================");
            println!(" Decentralized Access Control: Comprehensive Benchmark Suite");
            println!("==========================================================================");

            bench_peer_scalability(quick, &mut results).await?;

            let mesh_sizes = if quick { vec![2, 3] } else { vec![2, 3, 5] };
            bench_mesh_scalability(mesh_sizes, 5, 16, &mut results).await?;

            print_summary_table_markdown("Complete Benchmark Suite Summary", &results);
        }
        "server" => {
            let name = get_arg_val(&args, "--name").unwrap_or_else(|| "node-1".to_string());
            let port: u16 = get_arg_val(&args, "--control-port")
                .and_then(|s| s.parse().ok())
                .unwrap_or(9001);
            let ticket = get_arg_val(&args, "--ticket");

            run_server_daemon(name, port, ticket).await?;
        }
        "viewer" => {
            let server_ep_str = get_arg_val(&args, "--server")
                .expect("Missing --server <EndpointId> argument");
            let server_ep = EndpointId::from_str(&server_ep_str)
                .expect("Invalid server EndpointId");
            let namespace = get_arg_val(&args, "--namespace")
                .expect("Missing --namespace argument");
            let resource = get_arg_val(&args, "--resource")
                .unwrap_or_else(|| "synthetic_video.mp4".to_string());
            let requests: usize = get_arg_val(&args, "--requests")
                .and_then(|s| s.parse().ok())
                .unwrap_or(100);
            let concurrency: usize = get_arg_val(&args, "--concurrency")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);

            run_standalone_viewer(server_ep, namespace, resource, requests, concurrency).await?;
        }
        _ => {
            println!("Usage: bench_access_control <peers|mesh|all|server|viewer> [options]");
            println!("  peers   [--quick] [--json]");
            println!("  mesh    [--servers 2,3,5] [--rounds 10] [--viewers 20]");
            println!("  all     [--quick] [--json]");
            println!("  server  --name <NAME> --control-port <PORT> [--ticket <TICKET>]");
            println!("  viewer  --server <ENDPOINT_ID> --namespace <NS> [--resource <RES>] [--requests 100] [--concurrency 10]");
        }
    }

    if json_output {
        println!("\n```json");
        println!("{}", serde_json::to_string_pretty(&results)?);
        println!("```");
    }

    Ok(())
}
