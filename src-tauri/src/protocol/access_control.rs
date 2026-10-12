use std::{
    collections::{HashMap, HashSet},
    io::{self, ErrorKind},
    vec,
};

use anyhow::{bail, Context};
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
    protocol::{viewer::Viewer, QueryResponse, Request},
    store::{
        AccessListManager, DiscoveryResponse, LwwEntry, PermissionLevel, ServerPermissions,
        ServerRequest, SignedServerPerms, StorageManager, VideoInfo, VideoMetadata,
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
                self.handle_update_acl(endpoint_id, send, acl_update).await
            }
            ServerRequest::UpdateServers { server_update } => {
                self.handle_update_servers(endpoint_id, send, server_update).await
            }
            ServerRequest::AddEntry {
                entry,
                server_update,
            } => {
                self.handle_add_entry(endpoint_id, send, entry, server_update).await
            }
            ServerRequest::Query { namespace } => {
                self.handle_query(endpoint_id, send, namespace).await
            }
        }
    }

    fn validate_server_update(
        &self,
        current_perms: Option<&SignedServerPerms>,
        server_update: &SignedServerPerms,
    ) -> bool {
        if !server_update.verify_signature().unwrap_or(false) {
            return false;
        }

        if !server_update.is_writer_authorized().unwrap_or(false) {
            return false;
        }

        if let Some(current) = current_perms {
            if current.server_permissions.epoch > 0 {
                if server_update.from_writer != current.from_writer {
                    return false;
                }
                if server_update.server_permissions.epoch <= current.server_permissions.epoch {
                    return false;
                }
            }
        }

        true
    }

    async fn handle_update_acl(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        acl_update: LwwEntry<crate::store::SignedAcl>,
    ) -> anyhow::Result<()> {
        if !self
            .verify_perms(
                send,
                PermissionLevel::Server,
                &acl_update.namespace,
                &endpoint_id,
            )
            .await?
        {
            return Ok(());
        }

        // Verify cryptographic signature on the ACL
        let Ok(endpoint_bytes) = serde_json::to_vec(&acl_update.authorized_endpoints) else {
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
        let tag = format!("{}/{}", acl_update.namespace, acl_update.resource);
        if let Ok(Some(mut metadata)) = self
            .list_manager
            .get_metadata(&acl_update.namespace, &acl_update.resource)
            .await
        {
            metadata.acl.merge(acl_update.clone());
            let _ = self
                .list_manager
                .update_bytes(&tag, &serde_json::to_vec(&metadata)?)
                .await;
        } else {
            let metadata = VideoMetadata {
                clip_hashes: HashMap::new(),
                video_name: format!("Video-{}", acl_update.resource),
                acl: acl_update.clone(),
            };
            let _ = self
                .list_manager
                .update_bytes(&tag, &serde_json::to_vec(&metadata)?)
                .await;
        }

        send.write_u8(Allowed as u8).await?;
        send.finish()?;
        Ok(())
    }

    async fn handle_update_servers(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        server_update: SignedServerPerms,
    ) -> anyhow::Result<()> {
        let namespace = &server_update.server_permissions.namespace;
        if !self
            .verify_perms(send, PermissionLevel::Writer, namespace, &endpoint_id)
            .await?
        {
            return Ok(());
        }

        let current = self.list_manager.get_server_perms(namespace).await?;
        if !self.validate_server_update(current.as_ref(), &server_update) {
            send.write_u8(Denied as u8).await?;
            send.finish()?;
            return Ok(());
        }

        self.list_manager
            .update_bytes(namespace, &serde_json::to_vec(&server_update)?)
            .await?;

        send.write_u8(Allowed as u8).await?;
        send.finish()?;
        Ok(())
    }

    async fn handle_add_entry(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        entry: VideoMetadata,
        server_update: SignedServerPerms,
    ) -> anyhow::Result<()> {
        let namespace = server_update.server_permissions.namespace.clone();
        if !self
            .verify_perms(send, PermissionLevel::Writer, &namespace, &endpoint_id)
            .await?
        {
            return Ok(());
        }

        let resource = entry.acl.resource.clone();
        let video_name = entry.video_name.clone();

        let current = self.list_manager.get_server_perms(&namespace).await?;
        if !self.validate_server_update(current.as_ref(), &server_update) {
            send.write_u8(Denied as u8).await?;
            send.finish()?;
            return Ok(());
        }

        // Verify the new set of resources contains the resource from entry
        if !server_update.server_permissions.resources.contains(&resource) {
            send.write_u8(Denied as u8).await?;
            send.finish()?;
            return Ok(());
        }

        self.list_manager
            .update_bytes(&namespace, &serde_json::to_vec(&server_update)?)
            .await?;

        send.write_u8(Allowed as u8).await?;
        send.finish()?;

        // Replicate video if local node doesn't have it
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

        // Save metadata
        let tag = format!("{}/{}", namespace, resource);
        let _ = self
            .list_manager
            .update_bytes(&tag, &serde_json::to_vec(&entry)?)
            .await;

        Ok(())
    }

    async fn handle_query(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        namespace: String,
    ) -> anyhow::Result<()> {
        if !self
            .verify_perms(send, PermissionLevel::Server, &namespace, &endpoint_id)
            .await?
        {
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
                if let Ok(Some(metadata)) =
                    self.list_manager.get_metadata(parts[0], parts[1]).await
                {
                    entries.push(metadata);
                }
            }
        }

        let query_response = QueryResponse {
            metadata: entries,
            signed_server_perms: self
                .list_manager
                .get_server_perms(&namespace)
                .await?
                .context("Not found")?,
        };

        send.write_u8(Allowed as u8).await?;
        let response_bytes = serde_json::to_vec(&query_response)?;
        send.write_all(&response_bytes).await?;
        send.finish()?;
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

        // Update writer-signed resource list and increment epoch
        self.list_manager
            .insert_to_server_resource_list(&namespace, &resource)
            .await?;

        // Broadcast to all other mesh servers in the namespace
        if let Ok(Some(metadata)) = self.list_manager.get_metadata(&namespace, &resource).await {
            if let Ok(Some(server_perms)) = self.list_manager.get_server_perms(&namespace).await {
                let _ = self
                    .broadcast_add_entry(&namespace, metadata, server_perms)
                    .await;
            }
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

            let server_perms = ServerPermissions {
                servers: init_servers,
                resources: HashSet::new(),
                namespace: namespace.clone(),
                epoch: 0,
            };
            let lww = LwwEntry::new(server_perms);
            let signed_server_perms = SignedServerPerms::new(&signing_key, lww)?;
            self.list_manager
                .update_bytes(&namespace, &serde_json::to_vec(&signed_server_perms)?)
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
                    // Disabled to keep epoch consistent for everyone
                    // let _ = self
                    //     .list_manager
                    //     .modify_server_list(namespace, &endpoint_id, PermissionLevel::Server, true)
                    //     .await;
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

            let Ok(query_response) = serde_json::from_slice::<QueryResponse>(&entries_bytes) else {
                eprintln!("Failed to deserialize QueryResponse from {endpoint_id}");
                continue;
            };

            let remote_perms = query_response.signed_server_perms;
            let entries = query_response.metadata;

            // 1. Verify Writer's cryptographic signature on server_perms
            if !remote_perms.verify_signature().unwrap_or(false) {
                eprintln!("Rejected replication from {endpoint_id}: invalid writer signature on server perms");
                continue;
            }

            // 2. Verify Writer is an authorized Writer in the signed perms
            if !remote_perms.is_writer_authorized().unwrap_or(false) {
                eprintln!("Rejected replication from {endpoint_id}: signer is not an authorized Writer");
                continue;
            }

            // 3. Verify that the remote peer is an authorized Server or Writer in remote_perms
            let peer_perm = remote_perms.server_permissions.servers.get(&endpoint_id);
            if peer_perm != Some(&PermissionLevel::Server) && peer_perm != Some(&PermissionLevel::Writer) {
                eprintln!("Rejected replication from {endpoint_id}: peer is not an authorized server in signed perms");
                continue;
            }

            // 4. Verify that local node (self) is an authorized Server or Writer in remote_perms
            let my_perm = remote_perms.server_permissions.servers.get(&self.endpoint_id);
            if my_perm != Some(&PermissionLevel::Server) && my_perm != Some(&PermissionLevel::Writer) {
                eprintln!("Rejected replication from {endpoint_id}: local node has been revoked or is not in server roster");
                continue;
            }

            // 5. Epoch check against local server perms (prevent rollback attacks and revoked servers rejoining with older state)
            let local_perms_opt = self.list_manager.get_server_perms(namespace).await?;
            if let Some(ref local_perms) = local_perms_opt {
                if local_perms.server_permissions.epoch > 0 {
                    if remote_perms.from_writer != local_perms.from_writer {
                        eprintln!("Rejected replication from {endpoint_id}: writer key mismatch");
                        continue;
                    }
                    if remote_perms.server_permissions.epoch < local_perms.server_permissions.epoch {
                        eprintln!(
                            "Rejected replication from {endpoint_id}: stale epoch (remote: {}, local: {})",
                            remote_perms.server_permissions.epoch,
                            local_perms.server_permissions.epoch,
                        );
                        continue;
                    }
                }
            }

            // 6. Anti-tamper verification: Confirm claimed resources match the Writer-signed resource set!
            let claimed_resources: HashSet<String> = entries.iter().map(|e| e.acl.resource.clone()).collect();
            if claimed_resources != remote_perms.server_permissions.resources
                || entries.len() != remote_perms.server_permissions.resources.len()
            {
                eprintln!(
                    "Rejected replication from rogue node {endpoint_id}: claimed resources do not match writer-signed resource list (claimed: {:?}, signed: {:?})",
                    claimed_resources,
                    remote_perms.server_permissions.resources,
                );
                continue;
            }

            // 7. Adopt the verified server perms if newer or initial bootstrap
            if local_perms_opt.is_none()
                || remote_perms.server_permissions.epoch >= local_perms_opt.as_ref().unwrap().server_permissions.epoch
            {
                let _ = self
                    .list_manager
                    .update_bytes(namespace, &serde_json::to_vec(&remote_perms)?)
                    .await;
            }

            // 8. Replicate and store videos
            for entry in entries {
                let resource = entry.acl.resource.clone();
                let video_name = entry.video_name.clone();

                // security risk, how to determine the difference between sync issue and an unauthorized video?
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
                        eprintln!("Failed to replicate video {resource} from {endpoint_id}: {e}");
                    }
                }

                // save the access list
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
        server_update: SignedServerPerms,
    ) -> anyhow::Result<()> {
        if let Ok(Some(mut peers)) = self.list_manager.get_server_endpoints(namespace).await {
            peers.retain(|p| *p != self.endpoint_id);
            for peer in peers {
                if let Ok(conn) = self.viewer.endpoint().connect(peer, MANAGEMENT).await {
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        let req = ServerRequest::AddEntry {
                            entry: entry.clone(),
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
        server_update: SignedServerPerms,
    ) -> anyhow::Result<()> {
        let peers = match self.list_manager.get_server_endpoints(namespace).await {
            Ok(Some(mut pks)) => {
                pks.retain(|p| *p != self.endpoint_id);
                pks
            }
            Ok(None) => return Ok(()),
            Err(e) => bail!("No peers associated with namespace {e}"),
        };

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
        Ok(())
    }

    async fn verify_perms(
        &self,
        send: &mut SendStream,
        permited_access_level: PermissionLevel,
        namespace: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<bool> {
        let perm_level = self
            .list_manager
            .check_authorization(&namespace, None, &endpoint_id)
            .await?;

        if perm_level as u8 > permited_access_level as u8 {
            send.write_u8(Denied as u8).await?;
            send.finish()?;
            return Ok(false);
        }

        Ok(true)
    }
}
