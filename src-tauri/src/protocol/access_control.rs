use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    vec,
};

use anyhow::bail;
use ed25519_dalek::{SigningKey, Verifier};
use iroh::{
    endpoint::{RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointId,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{
    protocol::{viewer::Viewer, Request},
    store::{
        AccessListManager, DiscoveryResponse, LwwEntry, PermissionLevel, ServerPermissions,
        ServerRequest, StorageManager, VideoInfo, VideoMetadata,
    },
    Status::{self, Allowed, Denied, ResourceNotFound},
    ALPN, DISCOVERY_ALPN, MANAGEMENT,
};

/// Manages the storage and access control of videos
#[derive(Debug, Clone)]
pub struct AccessControl {
    list_manager: AccessListManager,
    storage_manager: StorageManager,
    endpoint_id: EndpointId,
    viewer: Viewer,
}

impl ProtocolHandler for AccessControl {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let peer: EndpointId = connection.remote_id();
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let access_control = self.clone();

            match connection.alpn() {
                ALPN => {
                    tokio::spawn(async move {
                        match access_control
                            .handle_request(peer, &mut send, &mut recv)
                            .await
                        {
                            Err(e) => eprintln!("Error handling request: {e}"),
                            Ok(false) => eprintln!("Invalid data"),
                            _ => (),
                        }

                        if let Err(e) = send.finish() {
                            eprintln!("Stream was closed already: {e}")
                        }
                    });
                }
                DISCOVERY_ALPN => {
                    tokio::spawn(async move {
                        if let Err(e) = access_control
                            .handle_discovery_request(peer, &mut send, &mut recv)
                            .await
                        {
                            eprintln!("Error occured handling discovery request, {}", e);
                        }

                        if let Err(e) = send.finish() {
                            eprintln!("Stream was closed already: {e}")
                        }
                    });
                }
                MANAGEMENT => {
                    tokio::spawn(async move {
                        if let Err(e) = access_control
                            .handle_server_request(peer, &mut send, &mut recv)
                            .await
                        {
                            eprintln!("Error occured handling discovery request, {}", e);
                        }

                        let _ = send.finish();
                    });
                }
                _ => {
                    return Err(AcceptError::from_err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "ALPN doesn't exist",
                    )));
                }
            }
        }

        Ok(())
    }
}

impl AccessControl {
    pub fn new(
        list_manager: AccessListManager,
        storage_manager: StorageManager,
        endpoint: Endpoint,
    ) -> Self {
        Self {
            list_manager,
            storage_manager,
            endpoint_id: endpoint.id(),
            viewer: Viewer::new(endpoint),
        }
    }

    /// Make a request to retrieve a video, either locally or from a server.
    pub async fn make_request(
        &self,
        endpoint_id: Option<EndpointId>,
        request: &Request,
    ) -> anyhow::Result<Option<File>> {
        if let Some(endpoint_id) = endpoint_id {
            println!("Making request to: {}", endpoint_id);

            self.viewer.retreive_remote(endpoint_id, request).await
        } else {
            self.storage_manager
                .retrieve_local(&request)
                .await
                .map(Some)
        }
    }

    async fn handle_request(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> anyhow::Result<bool> {
        let mut len_buf = [0u8; size_of::<u32>()];
        recv.read_exact(&mut len_buf).await?;
        let req_len = u32::from_be_bytes(len_buf);

        let mut request_bytes = vec![0u8; req_len as usize];
        recv.read_exact(&mut request_bytes).await?;
        let request: Request = serde_json::from_slice(&request_bytes)?;

        let status = self
            .list_manager
            .check_authorization(&request.namespace, Some(&request.resource), &endpoint_id)
            .await?;

        if status == PermissionLevel::Unauthorized {
            eprintln!("Access check failed for {}: {:?}", endpoint_id, status);
            send.write_all(&[status as u8]).await?;
            return Ok(false);
        }

        self.storage_manager
            .send(
                &request.namespace,
                &request.resource,
                &request.filename,
                send,
            )
            .await?;

        Ok(true)
    }

    async fn handle_discovery_request(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> anyhow::Result<()> {
        let len = recv.read_u32().await?;

        let mut request_bytes: Vec<u8> = vec![0u8; len as usize];
        recv.read_exact(&mut request_bytes).await?;

        let namespace = String::from_utf8(request_bytes)?;

        let Some(list) = self
            .list_manager
            .get_authorized_videos(&namespace, Some(&endpoint_id), true)
            .await?
        else {
            send.write_all(&[Status::FileNotFound as u8]).await?;
            bail!("Couldn't find namespace");
        };

        let files = self.storage_manager.get_filenames(&list).await?;

        let servers: Vec<EndpointId> = self
            .list_manager
            .get_server_endpoints(&namespace)
            .await?
            .unwrap_or_default();

        let response = DiscoveryResponse { files, servers };

        send.write_all(&[Status::Allowed as u8]).await?;

        let response_bytes = serde_json::to_vec(&response)?;
        send.write_all(&response_bytes).await?;

        Ok(())
    }

    async fn handle_server_request(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> anyhow::Result<()> {
        let payload = recv.read_to_end(usize::MAX).await?;
        let request: ServerRequest = serde_json::from_slice(&payload)?;

        match request {
            ServerRequest::UpdateACL { acl_update } => {
                let perm_level = self
                    .list_manager
                    .check_authorization(&acl_update.namespace, None, &endpoint_id)
                    .await?;

                if perm_level != PermissionLevel::Server && perm_level != PermissionLevel::Writer {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                }

                // Verify cryptographic signature on the ACL
                let Ok(endpoint_bytes) = serde_json::to_vec(&acl_update.authorized_endpoints)
                else {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                };
                if acl_update
                    .from
                    .verify(&endpoint_bytes, &acl_update.authorized_endpoints_signature)
                    .is_err()
                {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                }

                // Update local metadata ACL using LWW merge
                if let Ok(Some(mut metadata)) = self
                    .list_manager
                    .get_metadata(&acl_update.namespace, &acl_update.resource)
                    .await
                {
                    metadata.acl.merge(acl_update.clone());
                    let tag = format!("{}/{}", acl_update.namespace, acl_update.resource);
                    let _ = self
                        .list_manager
                        .update_bytes(&tag, &serde_json::to_vec(&metadata)?)
                        .await;
                } else {
                    let metadata = VideoMetadata {
                        clip_hashes: std::collections::HashMap::new(),
                        video_name: format!("Video-{}", acl_update.resource),
                        acl: acl_update.clone(),
                    };
                    let tag = format!("{}/{}", acl_update.namespace, acl_update.resource);
                    let _ = self
                        .list_manager
                        .update_bytes(&tag, &serde_json::to_vec(&metadata)?)
                        .await;
                }

                send.write_u8(Allowed as u8).await?;
                send.finish()?;
            }
            ServerRequest::UpdateServers { server_update } => {
                let perm_level = self
                    .list_manager
                    .check_authorization(&server_update.namespace, None, &endpoint_id)
                    .await?;

                // Only a Writer can modify the server list
                if perm_level != PermissionLevel::Writer {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                }

                let Ok(server_bytes) = serde_json::to_vec(&server_update.servers) else {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                };
                if server_update
                    .from
                    .verify(&server_bytes, &server_update.signed_servers)
                    .is_err()
                {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                }

                if let Ok(Some(mut current)) = self
                    .list_manager
                    .get_server_perms(&server_update.namespace)
                    .await
                {
                    current.merge(server_update);
                    let _ = self
                        .list_manager
                        .update_bytes(&current.namespace, &serde_json::to_vec(&current)?)
                        .await;
                } else {
                    let _ = self
                        .list_manager
                        .update_bytes(
                            &server_update.namespace,
                            &serde_json::to_vec(&server_update)?,
                        )
                        .await;
                }

                send.write_u8(Allowed as u8).await?;
                send.finish()?;
            }
            ServerRequest::AddEntry { entry } => {
                let perm_level = self
                    .list_manager
                    .check_authorization(&entry.acl.namespace, None, &endpoint_id)
                    .await?;

                if perm_level != PermissionLevel::Server && perm_level != PermissionLevel::Writer {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                }

                send.write_u8(Allowed as u8).await?;
                send.finish()?;

                let namespace = entry.acl.namespace.clone();
                let resource = entry.acl.resource.clone();
                let video_name = entry.video_name.clone();

                if !self.storage_manager.has_video(&namespace, &resource).await {
                    let _ = self
                        .viewer
                        .replicate(
                            &self.storage_manager,
                            &namespace,
                            &resource,
                            &video_name,
                            endpoint_id,
                        )
                        .await;
                }

                let tag = format!("{}/{}", namespace, resource);
                let _ = self
                    .list_manager
                    .update_bytes(&tag, &serde_json::to_vec(&entry)?)
                    .await;
            }
            ServerRequest::Query { namespace } => {
                let perm_level = self
                    .list_manager
                    .check_authorization(&namespace, None, &endpoint_id)
                    .await?;

                if perm_level != PermissionLevel::Server && perm_level != PermissionLevel::Writer {
                    send.write_u8(Denied as u8).await?;
                    send.finish()?;
                    return Ok(());
                }

                let Some(tags) = self
                    .list_manager
                    .get_authorized_videos(&namespace, Some(&endpoint_id), false)
                    .await?
                else {
                    send.write_u8(ResourceNotFound as u8).await?;
                    send.finish()?;
                    return Ok(());
                };

                let mut entries = Vec::new();
                for tag in tags {
                    let parts: Vec<&str> = tag.split('/').collect();
                    if parts.len() == 2 {
                        if let Ok(Some(metadata)) = self.list_manager.get_metadata(parts[0], parts[1]).await {
                            entries.push(metadata);
                        }
                    }
                }

                send.write_u8(Allowed as u8).await?;
                let entries_bytes = serde_json::to_vec(&entries)?;
                send.write_all(&entries_bytes).await?;
                send.finish()?;
            }
        }

        Ok(())
    }

    /// Upload a new video to an existing namespace or creates a new one.
    pub async fn upload_new(
        &self,
        path: &str,
        video_name: &str,
        namespace: Option<&str>,
    ) -> anyhow::Result<String> {
        let namespace = match namespace {
            Some(ns) => ns.to_string(),
            None => self.list_manager.create_namespace().await?,
        };

        let my_perm = self
            .list_manager
            .check_authorization(&namespace, None, &self.endpoint_id)
            .await?;
        if my_perm != PermissionLevel::Writer {
            bail!("Only a Writer can upload new videos to namespace {namespace}");
        }

        let resource = self
            .storage_manager
            .upload_dir(path, video_name, &namespace)
            .await?;

        println!("Uploaded resource: {}/{}", namespace, resource);

        // Broadcast to all other mesh servers in the namespace
        if let Ok(Some(metadata)) = self.list_manager.get_metadata(&namespace, &resource).await {
            let _ = self.broadcast_add_entry(&namespace, metadata).await;
        }

        Ok(namespace)
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn list_manager(&self) -> &AccessListManager {
        &self.list_manager
    }

    /// Import a ticket and begin syncing stores
    pub async fn import(&self, ticket_str: &str) -> anyhow::Result<String> {
        let ticket = crate::store::ServerTicket::parse(ticket_str)?;
        let namespace = ticket.namespace.clone();

        if self
            .list_manager
            .get_server_perms(&namespace)
            .await?
            .is_none()
        {
            let secret_key_bytes = self
                .list_manager
                .iroh_instance()
                .endpoint()
                .secret_key()
                .to_bytes();
            let signing_key = SigningKey::from_bytes(&secret_key_bytes);

            let mut init_servers = HashMap::new();
            for server in &ticket.servers {
                init_servers.insert(*server, PermissionLevel::Server);
            }
            init_servers.insert(self.endpoint_id, PermissionLevel::Server);

            let server_perms = ServerPermissions::new(&signing_key, &namespace, init_servers)?;
            let lww = LwwEntry::new(server_perms);
            self.list_manager
                .update_bytes(&namespace, &serde_json::to_vec(&lww)?)
                .await?;
        }

        self.replicate_handler(&namespace).await?;

        Ok(namespace)
    }

    pub async fn get_local_videos(&self) -> anyhow::Result<HashMap<String, Vec<VideoInfo>>> {
        let namespaces = self.list_manager.get_all_namespaces().await?;
        let mut namespace_videos: HashMap<String, Vec<VideoInfo>> = HashMap::new();

        for namespace in namespaces {
            if let Some(tags) = self
                .list_manager
                .get_authorized_videos(&namespace, None, true)
                .await?
            {
                let videos = self.storage_manager.get_filenames(&tags).await?;
                namespace_videos.insert(namespace, videos);
            } else {
                namespace_videos.insert(namespace, Vec::new());
            };
        }

        Ok(namespace_videos)
    }

    /// Determines what videos in a namespace this peer has access to
    /// by querying a server in the namespace
    pub async fn request_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Vec<VideoInfo>>> {
        self.viewer
            .request_authorized_videos(namespace, endpoint_id)
            .await
    }

    /// Determines which videos this server lacks, then downloads them locally to iroh-blobs
    pub async fn replicate_handler(&self, namespace: &str) -> anyhow::Result<()> {
        let Ok(Some(mut candidate_peers)) = self.list_manager.get_server_endpoints(namespace).await
        else {
            bail!("Namespace not found")
        };
        candidate_peers.retain(|x| *x != self.endpoint_id());

        if candidate_peers.is_empty() {
            println!("No remote server peers found yet for namespace {namespace}");
            return Ok(());
        }

        for endpoint_id in candidate_peers {
            let conn = match self
                .viewer
                .endpoint()
                .connect(endpoint_id, MANAGEMENT)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "Heartbeat failed for server peer {endpoint_id}: {e}. Removing from active peers list."
                    );
                    let _ = self
                        .list_manager
                        .modify_server_list(namespace, &endpoint_id, PermissionLevel::Server, true)
                        .await;
                    continue;
                }
            };

            let (mut send, mut recv) = match conn.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    eprintln!("Failed to open bidirectional stream with {endpoint_id}: {e}");
                    continue;
                }
            };

            let req = ServerRequest::Query {
                namespace: namespace.to_string(),
            };
            let Ok(req_bytes) = serde_json::to_vec(&req) else {
                continue;
            };
            if send.write_all(&req_bytes).await.is_err() || send.finish().is_err() {
                continue;
            }

            let Ok(status) = recv.read_u8().await else {
                continue;
            };
            if status != Status::Allowed as u8 {
                eprintln!("Query denied by {endpoint_id} for namespace {namespace}");
                continue;
            }

            let Ok(entries_bytes) = recv.read_to_end(usize::MAX).await else {
                continue;
            };
            let Ok(entries) = serde_json::from_slice::<Vec<VideoMetadata>>(&entries_bytes) else {
                continue;
            };

            for entry in entries {
                let resource = entry.acl.value.resource.clone();
                let video_name = entry.video_name.clone();
                if !self.storage_manager.has_video(namespace, &resource).await {
                    if let Err(e) = self
                        .viewer
                        .replicate(
                            &self.storage_manager,
                            namespace,
                            &resource,
                            &video_name,
                            endpoint_id,
                        )
                        .await
                    {
                        eprintln!(
                            "Failed to replicate video {resource} from {endpoint_id}: {e}"
                        );
                    }
                }

                let tag = format!("{namespace}/{resource}");
                let _ = self
                    .list_manager
                    .update_bytes(&tag, &serde_json::to_vec(&entry)?)
                    .await;
            }
        }

        Ok(())
    }

    pub async fn broadcast_add_entry(
        &self,
        namespace: &str,
        entry: VideoMetadata,
    ) -> anyhow::Result<()> {
        if let Ok(Some(mut peers)) = self.list_manager.get_server_endpoints(namespace).await {
            peers.retain(|p| *p != self.endpoint_id);
            for peer in peers {
                if let Ok(conn) = self.viewer.endpoint().connect(peer, MANAGEMENT).await {
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        let req = ServerRequest::AddEntry {
                            entry: entry.clone(),
                        };
                        if let Ok(bytes) = serde_json::to_vec(&req) {
                            if send.write_all(&bytes).await.is_ok() && send.finish().is_ok() {
                                let _ = recv.read_u8().await;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn broadcast_update_acl(
        &self,
        namespace: &str,
        acl_update: LwwEntry<crate::store::SignedAcl>,
    ) -> anyhow::Result<()> {
        if let Ok(Some(mut peers)) = self.list_manager.get_server_endpoints(namespace).await {
            peers.retain(|p| *p != self.endpoint_id);
            for peer in peers {
                if let Ok(conn) = self.viewer.endpoint().connect(peer, MANAGEMENT).await {
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        let req = ServerRequest::UpdateACL {
                            acl_update: acl_update.clone(),
                        };
                        if let Ok(bytes) = serde_json::to_vec(&req) {
                            if send.write_all(&bytes).await.is_ok() && send.finish().is_ok() {
                                let _ = recv.read_u8().await;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn broadcast_update_servers(
        &self,
        namespace: &str,
        server_update: LwwEntry<ServerPermissions>,
    ) -> anyhow::Result<()> {
        if let Ok(Some(mut peers)) = self.list_manager.get_server_endpoints(namespace).await {
            peers.retain(|p| *p != self.endpoint_id);
            for peer in peers {
                if let Ok(conn) = self.viewer.endpoint().connect(peer, MANAGEMENT).await {
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        let req = ServerRequest::UpdateServers {
                            server_update: server_update.clone(),
                        };
                        if let Ok(bytes) = serde_json::to_vec(&req) {
                            if send.write_all(&bytes).await.is_ok() && send.finish().is_ok() {
                                let _ = recv.read_u8().await;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
