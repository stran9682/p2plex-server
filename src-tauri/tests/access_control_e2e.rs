use std::path::PathBuf;

use iroh::{endpoint::presets, Endpoint};
use tokio::io::AsyncReadExt;
use video_server_lib::{
    iroh_runtime::IrohRuntime,
    protocol::{viewer::Viewer, Request},
    store::VideoInfo,
};

async fn run_full_access_control_lifecycle(mp4_name: &str) -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mp4_path = manifest_dir.join(mp4_name);
    assert!(
        mp4_path.exists(),
        "Test MP4 file not found at {:?}",
        mp4_path
    );

    println!("\n========================================================");
    println!(" [E2E Test] Access Control Lifecycle for: {}", mp4_name);
    println!("========================================================");
    println!("[1/6] Using test MP4: {:?}", mp4_path);

    // 1. Initialize Origin Server
    let origin_server = IrohRuntime::create_in_memory().await?;
    let origin_id = origin_server.endpoint_id();
    println!("[1/6] Origin Server started with EndpointId: {}", origin_id);

    // 2. Ingest real MP4 via add_dir
    println!("[2/6] Transcoding MP4 to HLS & ingesting into Iroh blobs...");
    let namespace = origin_server.add_dir(mp4_path.clone(), None).await?;
    println!("[2/6] Video ingested into namespace: {}", namespace);

    // Query local videos to retrieve resource root hash
    let local_videos = origin_server.get_local_videos().await?;
    let videos = local_videos.get(&namespace).expect("Namespace videos found");
    assert!(!videos.is_empty(), "At least one video must be present");
    let video_info: &VideoInfo = &videos[0];
    let resource = video_info
        .tag
        .split('/')
        .nth(1)
        .expect("Tag has namespace/resource format")
        .to_string();
    println!(
        "[2/6] Video Info: name = '{}', tag = '{}', resource = '{}'",
        video_info.video_name, video_info.tag, resource
    );

    // 3. Initialize Viewers: Unauthorized vs Authorized
    let unauth_ep = Endpoint::bind(presets::N0).await?;
    let unauth_viewer = Viewer::new(unauth_ep.clone());
    let unauth_id = unauth_ep.id();

    let auth_ep = Endpoint::bind(presets::N0).await?;
    let auth_viewer = Viewer::new(auth_ep.clone());
    let auth_id = auth_ep.id();

    println!("[3/6] Viewer Peers initialized:");
    println!("      Unauthorized Viewer ID: {}", unauth_id);
    println!("      Authorized Viewer ID:   {}", auth_id);

    // --- TEST 1: Unauthorized viewer is filtered out from Discovery ---
    println!("[3/6] Testing Discovery Protocol for Unauthorized Viewer...");
    let disc_res = unauth_viewer
        .request_authorized_videos(&namespace, &origin_id)
        .await?;
    let unauth_files = disc_res.unwrap_or_default();
    assert!(
        unauth_files.is_empty(),
        "Unauthorized viewer must receive 0 videos in discovery"
    );
    println!("[✓] Unauthorized viewer discovery correctly returned empty video list.");

    // --- TEST 2: Unauthorized viewer is denied access at wire ALPN gate ---
    println!("[3/6] Testing Wire Protocol ALPN gate for Unauthorized Viewer...");
    let req = Request::new(
        namespace.clone(),
        resource.clone(),
        "playlist.m3u8".into(),
    );
    let stream_res = unauth_viewer.retreive_remote(origin_id, &req).await?;
    assert!(
        stream_res.is_none(),
        "Unauthorized viewer must be rejected by wire gate"
    );
    println!("[✓] Unauthorized viewer request was rejected with Status::Denied.");

    // --- TEST 3: Grant access to Authorized Viewer ---
    println!("[4/6] Granting access to Viewer: {}...", auth_id);
    let grant_ok = origin_server
        .add_viewer(namespace.clone(), resource.clone(), auth_id.to_string())
        .await?;
    assert!(grant_ok, "Viewer should be added to ACL");
    println!("[✓] Viewer successfully added to ACL.");

    // Verify authorized viewer now discovers the video
    let auth_disc = auth_viewer
        .request_authorized_videos(&namespace, &origin_id)
        .await?;
    let auth_files = auth_disc.expect("Authorized viewer receives video list");
    assert!(
        auth_files.iter().any(|v| v.tag == video_info.tag),
        "Authorized viewer must discover the video"
    );
    println!(
        "[✓] Authorized viewer discovery succeeded, found: {:?}",
        auth_files
    );

    // Verify authorized viewer downloads and verifies playlist.m3u8 with Merkle proof
    let auth_playlist_res = auth_viewer.retreive_remote(origin_id, &req).await?;
    assert!(
        auth_playlist_res.is_some(),
        "Authorized viewer must receive playlist.m3u8"
    );
    let mut playlist_file = auth_playlist_res.unwrap();
    let mut playlist_content = String::new();
    playlist_file.read_to_string(&mut playlist_content).await?;
    assert!(
        playlist_content.contains("#EXTM3U"),
        "Playlist must contain valid HLS header"
    );
    println!("[✓] Authorized viewer downloaded and Merkle-verified playlist.m3u8:\n{}", playlist_content);

    // Also download a .ts chunk from the playlist
    let first_chunk = playlist_content
        .lines()
        .find(|line| line.ends_with(".ts"))
        .expect("At least one .ts chunk in HLS playlist");
    let chunk_req = Request::new(
        namespace.clone(),
        resource.clone(),
        first_chunk.to_string(),
    );
    let chunk_res = auth_viewer.retreive_remote(origin_id, &chunk_req).await?;
    assert!(
        chunk_res.is_some(),
        "Authorized viewer must receive video chunk"
    );
    println!("[✓] Authorized viewer downloaded and verified chunk: {}", first_chunk);

    // --- TEST 4: Multi-Server Mesh Sync & Replication ---
    println!("[5/6] Testing Multi-Server Mesh Replication & Ticket Exchange...");
    let replica_server = IrohRuntime::create_in_memory().await?;
    let replica_id = replica_server.endpoint_id();
    println!("[5/6] Replica Server started with EndpointId: {}", replica_id);

    // Origin authorizes Replica Server into the namespace server roster
    let add_srv_ok = origin_server
        .add_server(namespace.clone(), replica_id.to_string())
        .await?;
    assert!(add_srv_ok, "Origin should authorize replica server");
    println!("[✓] Origin added Replica Server to server roster.");

    // Origin generates ticket for the namespace
    let ticket = origin_server.generate_ticket(&namespace).await?;
    println!("[5/6] Generated ServerTicket: {}", ticket);

    // Replica imports the ticket and syncs
    replica_server.import_ticket(ticket).await?;
    println!("[✓] Replica imported ticket and initiated replication.");

    // Allow sync/replication stream to settle
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Authorized viewer queries replica server
    let replica_auth_disc = auth_viewer
        .request_authorized_videos(&namespace, &replica_id)
        .await?;
    let replica_vids = replica_auth_disc.expect("Authorized viewer receives videos from replica");
    assert!(
        replica_vids.iter().any(|v| v.tag == video_info.tag),
        "Replica server must authorize Viewer A after sync"
    );
    println!("[✓] Replica server successfully recognized Authorized Viewer from synced ACL.");

    // Unauthorized viewer queries replica server
    let replica_unauth_stream = unauth_viewer.retreive_remote(replica_id, &req).await?;
    assert!(
        replica_unauth_stream.is_none(),
        "Replica server must reject Unauthorized Viewer"
    );
    println!("[✓] Replica server successfully denied Unauthorized Viewer.");

    // --- TEST 5: Revocation Propagation ---
    println!("[6/6] Testing Access Revocation on Origin & Replica...");
    let revoke_ok = origin_server
        .remove_viewer(namespace.clone(), resource.clone(), auth_id.to_string())
        .await?;
    assert!(revoke_ok, "Viewer should be removed from ACL");

    // Allow broadcast to settle
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Origin server now rejects the revoked viewer
    let post_revoke_origin = auth_viewer.retreive_remote(origin_id, &req).await?;
    assert!(
        post_revoke_origin.is_none(),
        "Origin server must reject revoked viewer"
    );
    println!("[✓] Origin server rejected revoked viewer.");

    // Replica server also rejects the revoked viewer
    let post_revoke_replica = auth_viewer.retreive_remote(replica_id, &req).await?;
    assert!(
        post_revoke_replica.is_none(),
        "Replica server must reject revoked viewer post-revocation"
    );
    println!("[✓] Replica server rejected revoked viewer post-revocation.");

    // --- TEST 6: Server Revocation ---
    println!("[6/6] Testing Server Revocation (removing Replica Server from Server roster)...");
    let remove_server_ok = origin_server
        .remove_server(namespace.clone(), replica_id.to_string())
        .await?;
    assert!(remove_server_ok, "Replica server should be removed from server roster");
    println!("[✓] Server {} revoked from namespace {}.", replica_id, namespace);

    println!("\n========================================================");
    println!(" [✓] TEST FOR {} PASSED SUCCESSFULLY!", mp4_name);
    println!("========================================================\n");
    Ok(())
}

#[tokio::test]
async fn test_access_control_input_mp4() -> anyhow::Result<()> {
    run_full_access_control_lifecycle("input.mp4").await
}

#[tokio::test]
async fn test_access_control_video_mp4() -> anyhow::Result<()> {
    run_full_access_control_lifecycle("video.mp4").await
}

#[tokio::test]
async fn test_access_control_uuid_mp4() -> anyhow::Result<()> {
    run_full_access_control_lifecycle("5B17432F-D2BD-4327-B0EE-054E9CCD8444.mp4").await
}
