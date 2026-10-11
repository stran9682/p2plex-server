use video_server_lib::benchmark::{
    cluster::{run_distributed_viewer_mesh_load, run_mesh_convergence_benchmark, ServerMesh},
    node::{generate_random_endpoint, upload_synthetic_video},
};
use video_server_lib::iroh_runtime::IrohRuntime;
use video_server_lib::store::PermissionLevel;

#[tokio::test]
async fn test_bench_peer_scalability_quick() -> anyhow::Result<()> {
    println!("\n[Test] Running quick peer scalability verification...");
    let runtime = IrohRuntime::create_in_memory().await?;
    let (namespace, resource) = upload_synthetic_video(&runtime, None).await?;

    let test_ep = generate_random_endpoint();
    let unauth_ep = generate_random_endpoint();

    // 1. Grant viewer
    let grant_ok = runtime
        .add_viewer(namespace.clone(), resource.clone(), test_ep.to_string())
        .await?;
    assert!(grant_ok);

    // 2. Check authorization hit
    let status_auth = runtime
        .access_control()
        .list_manager()
        .check_authorization(&namespace, Some(&resource), &test_ep)
        .await?;
    assert_eq!(status_auth, PermissionLevel::Viewer);

    // 3. Check authorization miss
    let status_unauth = runtime
        .access_control()
        .list_manager()
        .check_authorization(&namespace, Some(&resource), &unauth_ep)
        .await?;
    assert_eq!(status_unauth, PermissionLevel::Unauthorized);

    // 4. Revoke viewer
    let revoke_ok = runtime
        .remove_viewer(namespace.clone(), resource.clone(), test_ep.to_string())
        .await?;
    assert!(revoke_ok);

    let status_revoked = runtime
        .access_control()
        .list_manager()
        .check_authorization(&namespace, Some(&resource), &test_ep)
        .await?;
    assert_eq!(status_revoked, PermissionLevel::Unauthorized);

    println!("[✓] Peer scalability verification passed.");
    Ok(())
}

#[tokio::test]
async fn test_bench_mesh_scalability_quick() -> anyhow::Result<()> {
    println!("\n[Test] Running quick mesh scalability verification (3-server mesh)...");
    let mesh = ServerMesh::create(2).await?;
    assert_eq!(mesh.total_servers(), 3);

    let mut results = Vec::new();
    run_mesh_convergence_benchmark(&mesh, 3, &mut results).await?;
    assert_eq!(results.len(), 2);

    run_distributed_viewer_mesh_load(&mesh, 6, 2, &mut results).await?;
    assert_eq!(results.len(), 4);

    println!("[✓] 3-server mesh convergence & distributed load benchmark passed.");
    Ok(())
}
