use std::{
    collections::{HashMap, HashSet},
    io::{self, ErrorKind},
    vec,
};

use anyhow::bail;
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
        endpoint_to_verifying_key, merge_operations, namespace_to_group_id,
        namespace_to_resource_authority, AccessLevel, AccessListManager, DiscoveryResponse,
        PermissionLevel, ServerRequest, SignedAuthOperation, StorageManager, StoredGroupData,
        VideoGroupCrdt, VideoInfo, VideoMetadata,
    },
    Status::{self, Allowed, Denied, ResourceNotFound},
    ALPN, DISCOVERY_ALPN, MANAGEMENT,
};

/// Manages the storage and access control of videos using p2panda-auth CRDTs.
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
                            eprintln!("Error occured handling management request, {}", e);
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
            ServerRequest::SyncAuth {
                namespace,
                operations,
            } => {
                self.handle_sync_auth(endpoint_id, send, namespace, operations)
                    .await
            }
            ServerRequest::AddEntry {
                namespace,
                entry,
                operations,
            } => {
                self.handle_add_entry(endpoint_id, send, namespace, entry, operations)
                    .await
            }
            ServerRequest::Query { namespace } => {
                self.handle_query(endpoint_id, send, namespace).await
            }
        }
    }

    async fn handle_sync_auth(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        namespace: String,
        operations: Vec<SignedAuthOperation>,
    ) -> anyhow::Result<()> {
        if !self
            .verify_perms(send, PermissionLevel::Writer, &namespace, &endpoint_id)
            .await?
        {
            return Ok(());
        }

        for op in &operations {
            if !op.verify() {
                send.write_u8(Denied as u8).await?;
                send.finish()?;
                return Ok(());
            }
        }

        let mut data = self
            .list_manager
            .get_group_data(&namespace)
            .await?
            .unwrap_or_else(|| StoredGroupData {
                state: VideoGroupCrdt::init(),
                operations: Vec::new(),
            });

        let raw_ops = operations.iter().map(|s| s.operation.clone()).collect();
        data.state = match merge_operations(data.state, raw_ops) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to merge CRDT operations: {e}");
                send.write_u8(Denied as u8).await?;
                send.finish()?;
                return Ok(());
            }
        };

        for op in operations {
            if !data
                .operations
                .iter()
                .any(|existing| existing.operation.id == op.operation.id)
            {
                data.operations.push(op);
            }
        }

        self.list_manager.save_group_data(&namespace, &data).await?;

        send.write_u8(Allowed as u8).await?;
        send.finish()?;
        Ok(())
    }

    async fn handle_add_entry(
        &self,
        endpoint_id: EndpointId,
        send: &mut SendStream,
        namespace: String,
        entry: VideoMetadata,
        operations: Vec<SignedAuthOperation>,
    ) -> anyhow::Result<()> {
        if !self
            .verify_perms(send, PermissionLevel::Writer, &namespace, &endpoint_id)
            .await?
        {
            return Ok(());
        }

        for op in &operations {
            if !op.verify() {
                send.write_u8(Denied as u8).await?;
                send.finish()?;
                return Ok(());
            }
        }

        let mut data = self
            .list_manager
            .get_group_data(&namespace)
            .await?
            .unwrap_or_else(|| StoredGroupData {
                state: VideoGroupCrdt::init(),
                operations: Vec::new(),
            });

        let raw_ops = operations.iter().map(|s| s.operation.clone()).collect();
        data.state = match merge_operations(data.state, raw_ops) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to merge CRDT operations in handle_add_entry: {e}");
                send.write_u8(Denied as u8).await?;
                send.finish()?;
                return Ok(());
            }
        };

        for op in operations {
            if !data
                .operations
                .iter()
                .any(|existing| existing.operation.id == op.operation.id)
            {
                data.operations.push(op);
            }
        }

        self.list_manager.save_group_data(&namespace, &data).await?;

        let auth_resources = self
            .list_manager
            .get_authorized_resources(&namespace)
            .await?;
        if !auth_resources.contains(&entry.resource) {
            send.write_u8(Denied as u8).await?;
            send.finish()?;
            return Ok(());
        }

        send.write_u8(Allowed as u8).await?;
        send.finish()?;

        let resource = entry.resource.clone();
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
                if let Ok(Some(metadata)) = self.list_manager.get_metadata(parts[0], parts[1]).await
                {
                    entries.push(metadata);
                }
            }
        }

        let Some(data) = self.list_manager.get_group_data(&namespace).await? else {
            send.write_u8(ResourceNotFound as u8).await?;
            send.finish()?;
            return Ok(());
        };

        let query_response = QueryResponse {
            metadata: entries,
            operations: data.operations,
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

        self.list_manager
            .insert_to_server_resource_list(&namespace, &resource)
            .await?;

        if let Ok(Some(metadata)) = self.list_manager.get_metadata(&namespace, &resource).await {
            if let Ok(Some(data)) = self.list_manager.get_group_data(&namespace).await {
                let _ = self
                    .broadcast_add_entry(&namespace, metadata, data.operations)
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

        self.replicate_from_peers(&namespace, ticket.servers)
            .await?;

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
        let candidate_peers = self
            .list_manager
            .get_server_endpoints(namespace)
            .await?
            .unwrap_or_default();
        self.replicate_from_peers(namespace, candidate_peers).await
    }

    pub async fn replicate_from_peers(
        &self,
        namespace: &str,
        mut candidate_peers: Vec<EndpointId>,
    ) -> anyhow::Result<()> {
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
                    eprintln!("Heartbeat failed for server peer {endpoint_id}: {e}.");
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

            let remote_ops = query_response.operations;
            let entries = query_response.metadata;

            // 1. Verify signatures on all operations
            let mut all_valid = true;
            for op in &remote_ops {
                if !op.verify() {
                    eprintln!(
                        "Rejected replication from {endpoint_id}: invalid signature on operation"
                    );
                    all_valid = false;
                    break;
                }
            }
            if !all_valid {
                continue;
            }

            // 2. Merge operations into local CRDT state
            let mut local_data = self
                .list_manager
                .get_group_data(namespace)
                .await?
                .unwrap_or_else(|| StoredGroupData {
                    state: VideoGroupCrdt::init(),
                    operations: Vec::new(),
                });

            let raw_ops = remote_ops.iter().map(|s| s.operation.clone()).collect();
            let merged_state = match merge_operations(local_data.state.clone(), raw_ops) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to merge CRDT operations from {endpoint_id}: {e}");
                    continue;
                }
            };

            let group_id = namespace_to_group_id(namespace);
            let res_auth_vk = namespace_to_resource_authority(namespace);
            let members = merged_state.members(group_id);

            // 3. Verify that the remote peer is an authorized Server or Writer in CRDT
            let Ok(peer_vk) = endpoint_to_verifying_key(&endpoint_id) else {
                continue;
            };
            let peer_mem = members.iter().find(|m| m.0 == peer_vk);
            let peer_is_auth = peer_mem
                .map(|m| m.1.level == AccessLevel::Write || m.1.level == AccessLevel::Manage)
                .unwrap_or(false);
            if !peer_is_auth {
                eprintln!("Rejected replication from {endpoint_id}: peer is not an authorized server in CRDT");
                continue;
            }

            // 4. Verify that local node (self) is an authorized Server or Writer in CRDT
            let Ok(my_vk) = endpoint_to_verifying_key(&self.endpoint_id) else {
                continue;
            };
            let my_mem = members.iter().find(|m| m.0 == my_vk);
            let my_is_auth = my_mem
                .map(|m| m.1.level == AccessLevel::Write || m.1.level == AccessLevel::Manage)
                .unwrap_or(false);
            if !my_is_auth {
                eprintln!("Rejected replication from {endpoint_id}: local node has been revoked or is not in server roster");
                continue;
            }

            // 5. Anti-tamper verification: Confirm claimed resources match Writer-signed resource set!
            let auth_resources: HashSet<String> = members
                .iter()
                .find(|m| m.0 == res_auth_vk)
                .and_then(|m| {
                    m.1.conditions
                        .as_ref()
                        .map(|c| c.resources.iter().cloned().collect())
                })
                .unwrap_or_default();

            let claimed_resources: HashSet<String> =
                entries.iter().map(|e| e.resource.clone()).collect();
            if claimed_resources != auth_resources || entries.len() != auth_resources.len() {
                eprintln!(
                    "Rejected replication from rogue node {endpoint_id}: claimed resources do not match writer-signed resource list (claimed: {:?}, signed: {:?})",
                    claimed_resources, auth_resources,
                );
                continue;
            }

            // 6. Adopt the verified CRDT state
            local_data.state = merged_state;
            for op in remote_ops {
                if !local_data
                    .operations
                    .iter()
                    .any(|existing| existing.operation.id == op.operation.id)
                {
                    local_data.operations.push(op);
                }
            }
            let _ = self
                .list_manager
                .save_group_data(namespace, &local_data)
                .await;

            // 7. Replicate and store videos
            for entry in entries {
                let resource = &entry.resource;
                let video_name = &entry.video_name;

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
        operations: Vec<SignedAuthOperation>,
    ) -> anyhow::Result<()> {
        if let Ok(Some(mut peers)) = self.list_manager.get_server_endpoints(namespace).await {
            peers.retain(|p| *p != self.endpoint_id);
            for peer in peers {
                if let Ok(conn) = self.viewer.endpoint().connect(peer, MANAGEMENT).await {
                    if let Ok((mut send, mut recv)) = conn.open_bi().await {
                        let req = ServerRequest::AddEntry {
                            namespace: namespace.to_string(),
                            entry: entry.clone(),
                            operations: operations.clone(),
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

    pub async fn broadcast_operations(
        &self,
        namespace: &str,
        operations: Vec<SignedAuthOperation>,
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
                    let req = ServerRequest::SyncAuth {
                        namespace: namespace.to_string(),
                        operations: operations.clone(),
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
