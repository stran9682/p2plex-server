use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    vec,
};

use anyhow::bail;
use iroh::{
    endpoint::{RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointId,
};
use iroh_docs::{api::Doc, DocTicket};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{
    protocol::{viewer::Viewer, Request},
    store::{AccessListManager, PermissionLevel, ServerRequest, StorageManager, VideoInfo},
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

        send.write_all(&[Status::Allowed as u8]).await?;

        let list_bytes = serde_json::to_vec(&files)?;
        send.write_all(&list_bytes).await?;

        todo!("Also send back a list of active servers in the namespace");

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
                todo!("Verify if the request comes from a server or writer, then update the ACL locally")
            }
            ServerRequest::UpdateServers { server_update } => {
                todo!("Verify the request comes from a writer, update the server list")
            }
            ServerRequest::AddEntry { entry } => {
                todo!("Verify the request comes from a writer, update our stores if so, then download from them (the endpoint)")
            }
            ServerRequest::Query { namespace } => {
                let perm_level = self
                    .list_manager
                    .check_authorization(&namespace, None, &endpoint_id)
                    .await?;

                if perm_level != PermissionLevel::Server || perm_level != PermissionLevel::Writer {
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

                send.write_u8(Allowed as u8).await?;
                let tags_bytes = serde_json::to_vec(&tags)?;
                send.write_all(&tags_bytes).await?;
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
    ) -> anyhow::Result<Doc> {
        let namespace = match namespace {
            Some(ns) => ns.to_string(),
            None => self.list_manager.create_namespace().await?,
        };

        todo!(
            "
                For now, if your permission is writer,
                - upload the file locally to blobs,
                - make a broadcast for everyone to update their store
            "
        );

        let resource = self
            .storage_manager
            .upload_dir(path, video_name, &namespace)
            .await?;

        println!("Resource: {}/{}", namespace, resource);
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    pub fn list_manager(&self) -> &AccessListManager {
        &self.list_manager
    }

    /// Import a doc ticket and begin syncing stores
    pub async fn import(&self, ticket: DocTicket) -> anyhow::Result<Doc> {
        todo!("Add to blobs the namespace, and server to contact, then begin syncing");
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
        let Ok(Some(mut candidate_peers)) =
            self.list_manager.get_server_endpoints(&namespace).await
        else {
            bail!("Namespace not found")
        };
        candidate_peers.retain(|x| *x != self.endpoint_id());

        if candidate_peers.is_empty() {
            println!("No remote server peers found yet for namespace {namespace}");
            return Ok(());
        }

        for endpoint_id in candidate_peers {
            todo!(
                "
                    Finish replication, make a server-query request for items in namespace
                    Query will return tags, so need to request those items
                    - for files, check if we have them locally then download if not,
                    - for metadata, update if permissions are valid

                    Also serves as heartbeat check, if the peer fails to answer, 
                    remove them from active peers list so we don't refer viewers to them
                "
            )
        }

        Ok(())
    }
}
