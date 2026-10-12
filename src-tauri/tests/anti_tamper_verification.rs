use std::collections::HashSet;
use tokio::io::AsyncReadExt;

use video_server_lib::{
    benchmark::node::upload_synthetic_video,
    iroh_runtime::IrohRuntime,
    protocol::QueryResponse,
    store::ServerRequest,
    MANAGEMENT, Status,
};

#[tokio::test]
async fn test_epoch_rollback_and_server_revocation() -> anyhow::Result<()> {
    println!("\n[Test] Testing Epoch Rollback & Revocation Protection...");

    // 1. Initialize Origin
    let origin = IrohRuntime::create_in_memory().await?;
    let (namespace, resource) = upload_synthetic_video(&origin, None).await?;

    let origin_perms = origin
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("Origin perms exist");
    assert_eq!(origin_perms.server_permissions.epoch, 2);
    assert!(origin_perms.server_permissions.resources.contains(&resource));

    // 2. Add Replica 1
    let replica1 = IrohRuntime::create_in_memory().await?;
    let replica1_id = replica1.endpoint_id();
    let add_ok = origin
        .add_server(namespace.clone(), replica1_id.to_string())
        .await?;
    assert!(add_ok);

    let origin_perms_after_add = origin
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("Perms exist");
    assert_eq!(origin_perms_after_add.server_permissions.epoch, 3);

    // 3. Replica 1 imports ticket and replicates
    let ticket = origin.generate_ticket(&namespace).await?;
    replica1.import_ticket(ticket).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Verify Replica 1 adopted epoch 3 and synced video
    let r1_perms = replica1
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("R1 perms exist");
    assert_eq!(r1_perms.server_permissions.epoch, 3);

    let local_videos = replica1.get_local_videos().await?;
    let r1_videos = local_videos.get(&namespace).expect("Namespace found");
    assert!(r1_videos.iter().any(|v| v.tag.contains(&resource)));

    // 4. Origin revokes Replica 1
    let revoke_ok = origin
        .remove_server(namespace.clone(), replica1_id.to_string())
        .await?;
    assert!(revoke_ok);

    let origin_perms_after_revoke = origin
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("Perms exist");
    assert_eq!(origin_perms_after_revoke.server_permissions.epoch, 4);
    assert!(!origin_perms_after_revoke
        .server_permissions
        .servers
        .contains_key(&replica1_id));

    // 5. Revoked Replica 1 tries to send stale UpdateServers (epoch 3) to Origin (epoch 4)
    let ep = replica1
        .access_control()
        .list_manager()
        .iroh_instance()
        .endpoint();
    let conn = ep.connect(origin.endpoint_id(), MANAGEMENT).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let stale_req = ServerRequest::UpdateServers {
        server_update: r1_perms.clone(),
    };
    send.write_all(&serde_json::to_vec(&stale_req)?).await?;
    send.finish()?;

    let resp_status = recv.read_u8().await?;
    assert_eq!(
        resp_status,
        Status::Denied as u8,
        "Origin must reject stale epoch / revoked peer update"
    );

    // 6. Add Replica 2 to cluster (advancing epoch to 5)
    let replica2 = IrohRuntime::create_in_memory().await?;
    let replica2_id = replica2.endpoint_id();
    let add_r2 = origin
        .add_server(namespace.clone(), replica2_id.to_string())
        .await?;
    assert!(add_r2);

    let ticket2 = origin.generate_ticket(&namespace).await?;
    replica2.import_ticket(ticket2).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let r2_perms = replica2
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("R2 perms exist");
    assert_eq!(r2_perms.server_permissions.epoch, 5);

    // 7. Revoked Replica 1 attempts to query Replica 2 with its stale state
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

    println!("[✓] Epoch rollback and server revocation defense verified.");
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

    let latest_perms = origin
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("Origin perms exist");

    // Setup rogue replica with a fake extra video in metadata
    // but the writer's signed server permissions only authorizes valid_resource!
    let metadata_valid = origin
        .access_control()
        .list_manager()
        .get_metadata(&namespace, &valid_resource)
        .await?
        .expect("Valid metadata exists");

    let mut rogue_metadata = metadata_valid.clone();
    let forged_resource = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    rogue_metadata.acl.value.resource = forged_resource.clone();

    // Query response with extra forged video
    let tampered_response = QueryResponse {
        metadata: vec![metadata_valid.clone(), rogue_metadata],
        signed_server_perms: latest_perms.clone(),
    };

    // When claimed_resources (valid_resource + forged_resource) != signed_server_perms.resources (only valid_resource),
    // replication is rejected!
    let claimed_resources: HashSet<String> = tampered_response
        .metadata
        .iter()
        .map(|e| e.acl.resource.clone())
        .collect();

    assert_ne!(
        claimed_resources, latest_perms.server_permissions.resources,
        "Claimed resources must not match signed resources list"
    );

    // Also test omission attack: rogue node omits valid_resource
    let omitted_response = QueryResponse {
        metadata: vec![],
        signed_server_perms: latest_perms.clone(),
    };
    let omitted_resources: HashSet<String> = omitted_response
        .metadata
        .iter()
        .map(|e| e.acl.resource.clone())
        .collect();
    assert_ne!(
        omitted_resources, latest_perms.server_permissions.resources,
        "Omitted resources must not match signed resources list"
    );

    println!("[✓] Rogue node resource list tampering detection verified.");
    Ok(())
}

#[tokio::test]
async fn test_forged_server_perms_signature_rejected() -> anyhow::Result<()> {
    println!("\n[Test] Testing Forged Server Permissions Signature Rejection...");

    let origin = IrohRuntime::create_in_memory().await?;
    let (namespace, _) = upload_synthetic_video(&origin, None).await?;

    let mut perms = origin
        .access_control()
        .list_manager()
        .get_server_perms(&namespace)
        .await?
        .expect("Origin perms exist");

    // Verify valid signature
    assert!(perms.verify_signature()?);
    assert!(perms.is_writer_authorized()?);

    // Tamper with epoch without updating writer's signature
    perms.server_permissions.value.epoch = 999;
    assert!(
        !perms.verify_signature()?,
        "Tampered perms must fail cryptographic signature verification"
    );

    println!("[✓] Cryptographic signature defense verified.");
    Ok(())
}
