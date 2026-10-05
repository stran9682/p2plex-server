use std::{
    collections::{HashMap, HashSet},
    io::{self, ErrorKind},
    vec,
};

use anyhow::bail;
use iroh::{
    endpoint::{RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
    EndpointId,
};
use iroh_docs::{api::Doc, DocTicket};
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncReadExt};

use crate::{
    access_list::list_manager::AccessListManager, store::storage_manager::StorageManager, Status,
    VideoInfo, ALPN, DISCOVERY_ALPN,
};

#[derive(Debug, Clone)]
pub struct AccessControl {
    list_manager: AccessListManager,
    storage_manager: StorageManager,
    endpoint_id: EndpointId,
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
        endpoint_id: EndpointId,
    ) -> Self {
        Self {
            list_manager,
            storage_manager,
            endpoint_id,
        }
    }

    pub async fn make_request(
        &self,
        endpoint_id: Option<EndpointId>,
        request: &Request,
    ) -> anyhow::Result<Option<File>> {
        if let Some(endpoint_id) = endpoint_id {
            println!("Making request to: {}", endpoint_id);

            self.storage_manager
                .retreive_remote(endpoint_id, request)
                .await
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
            .check_authorization(&request.namespace, &request.resource, &endpoint_id)
            .await?;

        if status != Status::Allowed {
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
            .get_authorized_videos(&namespace, Some(&endpoint_id))
            .await?
        else {
            send.write_all(&[Status::FileNotFound as u8]).await?;
            bail!("Couldn't find namespace");
        };

        let files = self.storage_manager.get_filenames(&list).await?;

        send.write_all(&[Status::Allowed as u8]).await?;

        let list_bytes = serde_json::to_vec(&files)?;
        send.write_all(&list_bytes).await?;

        Ok(())
    }

    pub async fn upload_new(
        &self,
        path: &str,
        video_name: &str,
        namespace: Option<&str>,
    ) -> anyhow::Result<Doc> {
        let (namespace, doc) = if let Some(namespace) = namespace {
            if let Some(doc) = self.list_manager.get_doc(namespace).await? {
                (namespace.to_string(), doc)
            } else {
                bail!("Document not found")
            }
        } else {
            let doc = self.list_manager.new_doc(None).await?;
            (doc.id().into_public_key()?.to_string(), doc)
        };

        let resource = self
            .storage_manager
            .upload_dir(path, video_name, &namespace)
            .await?;

        self.list_manager
            .append_access_list(&doc, None, &self.endpoint_id)
            .await?;

        // this is so the file shows up in docs,
        self.list_manager
            .append_access_list(&doc, Some(&resource), &self.endpoint_id)
            .await?;

        let ticket = doc
            .share(
                iroh_docs::api::protocol::ShareMode::Write,
                Default::default(),
            )
            .await?;

        println!("Resource: {}/{}", namespace, resource);
        println!("Ticket: {}", ticket);

        Ok(doc)
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn list_manager(&self) -> &AccessListManager {
        &self.list_manager
    }

    pub async fn import(&self, ticket: DocTicket) -> anyhow::Result<Doc> {
        println!("Importing ticket: {}", ticket);
        let doc = self.list_manager.new_doc(Some(ticket.to_string())).await?;

        // Add this server to the store's servers list
        self.list_manager
            .append_access_list(&doc, None, &self.endpoint_id)
            .await?;

        // Also add the ticket's bootstrap nodes as authorized servers
        for node in &ticket.nodes {
            let _ = self
                .list_manager
                .append_access_list(&doc, None, &node.id)
                .await;
        }

        self.replicate_handler(&doc).await?;

        Ok(doc)
    }

    pub async fn get_local_videos(&self) -> anyhow::Result<HashMap<String, Vec<VideoInfo>>> {
        let namespaces = self.list_manager.get_all_namespaces().await?;
        let mut namespace_videos: HashMap<String, Vec<VideoInfo>> = HashMap::new();

        for namespace in namespaces {
            if let Some(tags) = self
                .list_manager
                .get_authorized_videos(&namespace, None)
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

    pub async fn request_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Vec<VideoInfo>>> {
        self.list_manager
            .request_authorized_videos(namespace, endpoint_id)
            .await
    }

    pub async fn replicate_handler(&self, doc: &Doc) -> anyhow::Result<()> {
        println!("Replicating handler for namespace {}", doc.id());
        let namespace = doc.id().to_string();

        let mut candidate_peers = HashSet::new();

        // 1. Known servers from doc root tag
        if let Ok(servers) = self.list_manager.get_servers(&namespace).await {
            candidate_peers.extend(servers);
        }

        // 2. Doc sync peers
        if let Ok(Some(peers)) = doc.get_sync_peers().await {
            for peer_bytes in peers {
                if let Ok(endpoint_id) = EndpointId::from_bytes(&peer_bytes) {
                    candidate_peers.insert(endpoint_id);
                }
            }
        }

        candidate_peers.remove(&self.endpoint_id);

        if candidate_peers.is_empty() {
            println!("No remote server peers found yet for namespace {namespace}");
            return Ok(());
        }

        for endpoint_id in candidate_peers {
            let Ok(Some(videos)) = self
                .request_authorized_videos(&namespace, &endpoint_id)
                .await
            else {
                println!("Peer {endpoint_id} was unavailable");
                continue;
            };

            for video_info in videos {
                let args: Vec<&str> = video_info.tag.split('/').collect();
                if args.len() < 2 {
                    continue;
                }
                let resource = args[1].to_owned();

                // Skip if this video is already stored locally
                if self.storage_manager.has_video(&namespace, &resource).await {
                    continue;
                }

                println!(
                    "Replicating video {} ({}) from server {}",
                    video_info.video_name, resource, endpoint_id
                );
                match self
                    .storage_manager
                    .replicate(&namespace, &resource, &video_info.video_name, endpoint_id)
                    .await
                {
                    Ok(true) => {
                        println!("Successfully replicated video: {}", video_info.video_name)
                    }
                    Ok(false) => {
                        eprintln!("Failed to replicate video: {}", video_info.video_name)
                    }
                    Err(e) => {
                        eprintln!("Error replicating video {}: {}", video_info.video_name, e)
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub namespace: String,
    pub resource: String,
    pub filename: String,
}

impl Request {
    pub fn new(namespace: String, resource: String, filename: String) -> Self {
        Request {
            namespace,
            resource,
            filename,
        }
    }
}
