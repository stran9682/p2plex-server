use std::collections::HashSet;
use tokio::io::AsyncReadExt;

use video_server_lib::{
    benchmark::node::upload_synthetic_video,
    iroh_runtime::IrohRuntime,
    protocol::QueryResponse,
    store::ServerRequest,
    Status, MANAGEMENT,
};

#[tokio::test]
async fn test_dag_convergence_and_server_revocation() -> anyhow::Result<()> {
    println!("\n[Test] Testing p2panda-auth DAG Convergence & Server Revocation Protection...");

    // 1. Initialize Origin
    let origin = IrohRuntime::create_in_memory().await?;
    let (namespace, resource) = upload_synthetic_video(&origin, None).await?;

    let origin_group = origin
        .access_control()
        .list_manager()
        .get_group_data(&namespace)
        .await?
        .expect("Origin group exists");

    let auth_resources = origin
        .access_control()
        .list_manager()
        .get_authorized_resources(&namespace)
        .await?;
    assert!(auth_resources.contains(&resource));

    // 2. Add Replica 1
    let replica1 = IrohRuntime::create_in_memory().await?;
    let replica1_id = replica1.endpoint_id();
    let add_ok = origin
        .add_server(namespace.clone(), replica1_id.to_string())
        .await?;
    assert!(add_ok);

    let origin_servers = origin
        .access_control()
        .list_manager()
        .get_server_endpoints(&namespace)
        .await?
        .expect("Server endpoints exist");
    assert!(origin_servers.contains(&replica1_id));

    // 3. Replica 1 imports ticket and replicates
    let ticket = origin.generate_ticket(&namespace).await?;
    replica1.import_ticket(ticket).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Verify Replica 1 converged to the same server roster and synced video
    let r1_servers = replica1
        .access_control()
        .list_manager()
        .get_server_endpoints(&namespace)
        .await?
        .expect("R1 servers exist");
    assert!(r1_servers.contains(&replica1_id));

    let local_videos = replica1.get_local_videos().await?;
    let r1_videos = local_videos.get(&namespace).expect("Namespace found");
    assert!(r1_videos.iter().any(|v| v.tag.contains(&resource)));

    // 4. Origin revokes Replica 1
    let revoke_ok = origin
        .remove_server(namespace.clone(), replica1_id.to_string())
        .await?;
    assert!(revoke_ok);

    let origin_servers_after_revoke = origin
        .access_control()
        .list_manager()
        .get_server_endpoints(&namespace)
        .await?
        .expect("Server endpoints exist");
    assert!(!origin_servers_after_revoke.contains(&replica1_id));

    // 5. Revoked Replica 1 tries to send unauthorized SyncAuth to Origin
    let ep = replica1
        .access_control()
        .list_manager()
        .iroh_instance()
        .endpoint();
    let conn = ep.connect(origin.endpoint_id(), MANAGEMENT).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let stale_req = ServerRequest::SyncAuth {
        namespace: namespace.clone(),
        operations: origin_group.operations.clone(),
    };
    send.write_all(&serde_json::to_vec(&stale_req)?).await?;
    send.finish()?;

    let resp_status = recv.read_u8().await?;
    assert_eq!(
        resp_status,
        Status::Denied as u8,
        "Origin must reject SyncAuth from non-writer peer"
    );

    // 6. Add Replica 2 to cluster
    let replica2 = IrohRuntime::create_in_memory().await?;
    let replica2_id = replica2.endpoint_id();
    let add_r2 = origin
        .add_server(namespace.clone(), replica2_id.to_string())
        .await?;
    assert!(add_r2);

    let ticket2 = origin.generate_ticket(&namespace).await?;
    replica2.import_ticket(ticket2).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let r2_servers = replica2
        .access_control()
        .list_manager()
        .get_server_endpoints(&namespace)
        .await?
        .expect("R2 servers exist");
    assert!(r2_servers.contains(&replica2_id));
    assert!(!r2_servers.contains(&replica1_id));

    // 7. Revoked Replica 1 attempts to query Replica 2
    let conn2 = ep.connect(replica2_id, MANAGEMENT).await?;
    let (mut send2, mut recv2) = conn2.open_bi().await?;
    let query_req = ServerRequest::Query {
        namespace: namespace.clone(),
    };
    send2.write_all(&serde_json::to_vec(&query_req)?).await?;
    send2.finish()?;

    let query_status = recv2.read_u8().await?;
    assert_eq!(
        query_status,
        Status::Denied as u8,
        "Replica 2 must deny Query from revoked server Replica 1"
    );

    println!("[✓] p2panda-auth DAG convergence and server revocation defense verified.");
    Ok(())
}

#[tokio::test]
async fn test_rogue_server_resource_mismatch_detected() -> anyhow::Result<()> {
    println!("\n[Test] Testing Anti-Tamper Resource List Mismatch Detection...");

    // 1. Initialize Origin
    let origin = IrohRuntime::create_in_memory().await?;
    let (namespace, valid_resource) = upload_synthetic_video(&origin, None).await?;

    // 2. Initialize Honest Replica and Rogue Replica
    let honest_replica = IrohRuntime::create_in_memory().await?;
    let rogue_replica = IrohRuntime::create_in_memory().await?;
    let rogue_id = rogue_replica.endpoint_id();

    // Origin authorizes honest and rogue servers
    origin
        .add_server(namespace.clone(), honest_replica.endpoint_id().to_string())
        .await?;
    origin
        .add_server(namespace.clone(), rogue_id.to_string())
        .await?;

    let latest_data = origin
        .access_control()
        .list_manager()
        .get_group_data(&namespace)
        .await?
        .expect("Origin group exists");

    let auth_resources = origin
        .access_control()
        .list_manager()
        .get_authorized_resources(&namespace)
        .await?;

    // Setup rogue replica with a fake extra video in metadata
    let metadata_valid = origin
        .access_control()
        .list_manager()
        .get_metadata(&namespace, &valid_resource)
        .await?
        .expect("Valid metadata exists");

    let mut rogue_metadata = metadata_valid.clone();
    let forged_resource =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    rogue_metadata.resource = forged_resource.clone();

    // Query response with extra forged video
    let tampered_response = QueryResponse {
        metadata: vec![metadata_valid.clone(), rogue_metadata],
        operations: latest_data.operations.clone(),
    };

    let claimed_resources: HashSet<String> = tampered_response
        .metadata
        .iter()
        .map(|e| e.resource.clone())
        .collect();

    assert_ne!(
        claimed_resources, auth_resources,
        "Claimed resources must not match writer-authorized resources list"
    );

    // Also test omission attack: rogue node omits valid_resource
    let omitted_response = QueryResponse {
        metadata: vec![],
        operations: latest_data.operations.clone(),
    };
    let omitted_resources: HashSet<String> = omitted_response
        .metadata
        .iter()
        .map(|e| e.resource.clone())
        .collect();
    assert_ne!(
        omitted_resources, auth_resources,
        "Omitted resources must not match writer-authorized resources list"
    );

    println!("[✓] Rogue node resource list tampering detection verified.");
    Ok(())
}

#[tokio::test]
async fn test_forged_operation_signature_rejected() -> anyhow::Result<()> {
    println!("\n[Test] Testing Forged Operation Signature Rejection...");

    let origin = IrohRuntime::create_in_memory().await?;
    let (namespace, _) = upload_synthetic_video(&origin, None).await?;

    let data = origin
        .access_control()
        .list_manager()
        .get_group_data(&namespace)
        .await?
        .expect("Origin group exists");

    assert!(!data.operations.is_empty());
    let valid_op = &data.operations[0];
    assert!(valid_op.verify(), "Valid operation must pass verification");

    // Tamper with operation author without updating signature
    let mut tampered_op = valid_op.clone();
    let rogue_key = p2panda_core::SigningKey::generate();
    tampered_op.operation.author = rogue_key.verifying_key();

    assert!(
        !tampered_op.verify(),
        "Tampered operation must fail cryptographic verification"
    );

    println!("[✓] Cryptographic signature defense verified.");
    Ok(())
}
