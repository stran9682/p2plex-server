use std::collections::HashMap;
use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};

use ffmpeg_sidecar::command::{ffmpeg_is_installed, FfmpegCommand};
use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointId};
use iroh_blobs::{store::mem::MemStore, BlobsProtocol, ALPN as BLOBS_ALPN};
use iroh_docs::api::Doc;
use iroh_docs::{protocol::Docs, DocTicket, ALPN as DOCS_ALPN};
use iroh_gossip::{Gossip, ALPN as GOSSIP_ALPN};
use sea_orm::{ActiveHasMany, ActiveValue::Set, DatabaseConnection};
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel};
use serde::Deserialize;
use tempfile::TempDir;
use tokio::fs::File;

use crate::Error::IrohErr;
use crate::VideoInfo;
use crate::{
    access_list::list_manager::AccessListManager,
    discovery::discovery_service::DiscoveryService,
    entities::{address, topic},
    iroh::iroh_mem_instance::IrohMemInstance,
    protocol::access_control::{AccessControl, Request},
    store::storage_manager::StorageManager,
    Error, ALPN, DISCOVERY_ALPN,
};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use tokio_util::io::ReaderStream;

/// Manages discovery, storage, and access control for videos
pub struct IrohRuntime {
    _router: Router,
    access_control: AccessControl,
    db: DatabaseConnection,
    discovery: DiscoveryService,
}

impl IrohRuntime {
    pub async fn new(db: DatabaseConnection) -> anyhow::Result<Self> {
        let endpoint = Endpoint::bind(presets::N0).await?;
        let shared_blobs = MemStore::new();
        let gossip = Gossip::builder().spawn(endpoint.clone());

        let docs = Docs::memory()
            .spawn(endpoint.clone(), (*shared_blobs).clone(), gossip.clone())
            .await?;

        let acl_iroh_instance =
            IrohMemInstance::new(shared_blobs.clone(), docs.clone(), endpoint.clone());

        let list_manager = AccessListManager::new(acl_iroh_instance);

        let storage_iroh_instance =
            IrohMemInstance::new(shared_blobs.clone(), docs.clone(), endpoint.clone());
        let storage_manager = StorageManager::new(storage_iroh_instance);

        let access_control =
            AccessControl::new(list_manager.clone(), storage_manager, endpoint.id());

        println!("Endpoint: {}", endpoint.id());

        let discovery_service = DiscoveryService::new(endpoint.clone(), gossip.clone());

        let _router = Router::builder(endpoint)
            .accept(DOCS_ALPN, docs)
            .accept(GOSSIP_ALPN, gossip)
            .accept(BLOBS_ALPN, BlobsProtocol::new(&shared_blobs, None))
            .accept(ALPN, access_control.clone())
            .accept(DISCOVERY_ALPN, access_control.clone())
            .spawn();

        // Background periodic replication loop for eventual consistency
        let acl_for_sync = access_control.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                interval.tick().await;
                if let Ok(namespaces) = acl_for_sync.list_manager().get_all_namespaces().await {
                    for ns in namespaces {
                        if let Ok(Some(doc)) = acl_for_sync.list_manager().get_doc(&ns).await {
                            if let Err(e) = acl_for_sync.replicate_handler(&doc).await {
                                eprintln!("Periodic sync error for namespace {ns}: {e}");
                            }
                        }
                    }
                }
            }
        });

        if let Ok(namespaces) = access_control.list_manager().get_all_namespaces().await {
            for ns in namespaces {
                if let Err(e) = discovery_service.emit_topic(&ns, &db, true).await {
                    eprintln!("Error occured! {}", e);
                }
            }
        }

        Ok(Self {
            _router,
            access_control,
            db,
            discovery: discovery_service,
        })
    }

    /// Import a ticket to begin syncing videos inside the namespace with other servers.
    /// Will download videos locally to iroh-blobs,
    /// then begin announcing availability over iroh-gossip.
    pub async fn import_ticket(&self, ticket: String) -> Result<(), Error> {
        let doc_ticket =
            DocTicket::from_str(&ticket).map_err(|e| Error::InputErr(e.to_string()))?;
        let doc = self
            .access_control
            .import(doc_ticket.clone())
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        let doc_id = doc.id().to_string();
        let mut topic = match topic::Entity::find_by_topic(&doc_id).one(&self.db).await? {
            Some(topic) => {
                let topic = topic.into_active_model();
                topic.into_ex()
            }
            None => topic::ActiveModelEx {
                topic: Set(doc_id),
                ..Default::default()
            },
        };

        // Add addresses associated with the topic to the database.
        for endpoint in doc_ticket.nodes {
            let endpoint_id = endpoint.id.to_string();
            let address_model_ex = match address::Entity::find_by_endpoint(&endpoint_id)
                .one(&self.db)
                .await?
            {
                Some(endpoint) => {
                    let endpoint = endpoint.into_active_model();
                    endpoint.into_ex()
                }
                None => address::ActiveModelEx {
                    endpoint: Set(endpoint_id),
                    ..Default::default()
                },
            };

            topic = topic.add_address(address_model_ex);
        }

        topic.save(&self.db).await?;

        self.notify_availability(doc).await?;

        Ok(())
    }

    /// Adds a local video and creates a syncable namespace that other peers can sync with.
    pub async fn add_dir(
        &self,
        file_path: PathBuf,
        namespace: Option<String>,
    ) -> Result<(), Error> {
        if !ffmpeg_is_installed() {
            return Err(Error::InputErr("ffmpeg was not installed".to_string()));
        }

        let Some(filename) = file_path.file_name() else {
            return Err(Error::InputErr("Filename was invalid".to_owned()));
        };

        let temp_dir = TempDir::new()
            .map_err(|e| Error::InputErr(format!("Failed to create temp dir {e}")))?;

        let args = format!(
            "-codec: copy -start_number 1 -hls_time 10 -hls_list_size 0 -f hls {}/playlist.m3u8",
            temp_dir.path().to_string_lossy()
        );
        let mut command = FfmpegCommand::new()
            .input(&file_path.to_string_lossy())
            .args(args.split(' '))
            .spawn()
            .map_err(|e| Error::InputErr(format!("Failed to spawn ffmpeg: {e}")))?;

        command
            .iter()
            .map_err(|e| Error::InputErr(format!("ffmpeg failed during processing: {e}")))?;

        let doc = self
            .access_control
            .upload_new(
                &temp_dir.path().to_string_lossy(),
                &filename.to_string_lossy(),
                namespace.as_deref(),
            )
            .await
            .map_err(|e| IrohErr(e.to_string()))?;

        if namespace.is_none() {
            let topic = topic::ActiveModel {
                topic: Set(doc.id().to_string()),
                ..Default::default()
            };

            topic.save(&self.db).await?;
        }

        self.notify_availability(doc).await
    }

    /// Adds a server's EndpointId and their topic to the database.
    /// This will only serve as a lookup to find the video during streaming
    /// Syncing requires importing the ticket
    pub async fn add_remote_store(&self, endpoint: String, topic: String) -> Result<(), Error> {
        topic::ActiveModelEx {
            topic: Set(topic),
            addresses: ActiveHasMany::Append(vec![address::ActiveModelEx {
                endpoint: Set(endpoint),
                ..Default::default()
            }]),
            ..Default::default()
        }
        .save(&self.db)
        .await?;

        Ok(())
    }

    /// Download a specific file from the namespace.
    /// Will search locally first, before searching database for
    /// a server who has it, then downloading from them
    pub async fn download_file(
        &self,
        namespace: &str,
        resource: &str,
        filename: &str,
    ) -> anyhow::Result<Option<File>> {
        let request = Request::new(
            String::from(namespace),
            String::from(resource),
            String::from(filename),
        );

        // 1. Check local storage first
        if let Ok(Some(file)) = self.access_control.make_request(None, &request).await {
            return Ok(Some(file));
        }

        // 2. Fall back to streaming on-demand from remote server peers
        let bootstraps = self.get_remotes(namespace).await?;

        for endpoint_id in bootstraps {
            if let Ok(Some(file)) = self
                .access_control
                .make_request(Some(endpoint_id), &request)
                .await
            {
                println!("Got file from remote server: {}", endpoint_id);
                return Ok(Some(file));
            }
        }

        Ok(None)
    }

    /// Listen over iroh-gossip for new servers on this namespace to add to the database
    pub async fn start_adding_namespace_servers(&self, topic: String) -> Result<bool, Error> {
        if self.get_local_videos().await?.contains_key(&topic) {
            return Ok(false);
        }
        self.discovery.cancel_topic(&topic);
        self.discovery.emit_topic(&topic, &self.db, false).await?;

        Ok(true)
    }

    /// Stop listening for new servers on this namespace.
    pub async fn stop_adding_namespace_servers(&self, topic: String) -> Result<bool, Error> {
        if self.get_local_videos().await?.contains_key(&topic) {
            return Ok(false);
        }

        Ok(self.discovery.cancel_topic(&topic))
    }

    /// Find all videos that this peer can view.
    /// First, Queries the local database for all inserted topics and associated servers,
    /// then contacts a server for authorized videos.
    pub async fn request_authorized_videos(
        &self,
    ) -> Result<HashMap<String, Vec<VideoInfo>>, Error> {
        let topic: Vec<(topic::Model, Vec<address::Model>)> = topic::Entity::find()
            .find_with_related(address::Entity)
            .all(&self.db)
            .await?;

        let mut namespace_videos: HashMap<String, Vec<VideoInfo>> = HashMap::new();
        for (namespace, addresses) in topic {
            for address in addresses {
                let endpoint = EndpointId::from_str(&address.endpoint)
                    .map_err(|e| Error::InputErr(e.to_string()))?;

                if let Ok(Some(videos)) = self
                    .access_control
                    .request_authorized_videos(&namespace.topic, &endpoint)
                    .await
                {
                    namespace_videos.insert(namespace.topic, videos);
                    break;
                } else {
                    continue;
                }
            }
        }

        let local_videos = self
            .access_control
            .get_local_videos()
            .await
            .map_err(|e| IrohErr(e.to_string()))?;

        namespace_videos.extend(local_videos);

        Ok(namespace_videos)
    }

    /// Queries the local database for servers in the namespace
    async fn get_remotes(&self, topic: &str) -> Result<Vec<EndpointId>, Error> {
        let topic: Vec<(topic::Model, Vec<address::Model>)> = topic::Entity::find_by_topic(topic)
            .find_with_related(address::Entity)
            .all(&self.db)
            .await?;

        if topic.is_empty() {
            return Ok(Vec::new());
        }

        let (_, addresses) = &topic[0];

        let bootstrap: Vec<EndpointId> = addresses
            .iter()
            .filter_map(|i| EndpointId::from_str(&i.endpoint).ok())
            .collect();

        Ok(bootstrap)
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.access_control.endpoint_id()
    }

    /// Adds an EndpointId to the access control list associated with a video
    pub async fn add_viewer(
        &self,
        namespace: String,
        resource: String,
        viewer: String,
    ) -> Result<bool, Error> {
        let viewer_id =
            EndpointId::from_str(&viewer).map_err(|e| Error::InputErr(e.to_string()))?;
        self.access_control
            .list_manager()
            .add_viewer_to_video(&namespace, &resource, &viewer_id)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
    }

    /// Removes an EndpointId to the access control list associated with a video
    pub async fn remove_viewer(
        &self,
        namespace: String,
        resource: String,
        viewer: String,
    ) -> Result<bool, Error> {
        let viewer_id =
            EndpointId::from_str(&viewer).map_err(|e| Error::InputErr(e.to_string()))?;
        self.access_control
            .list_manager()
            .remove_viewer_from_video(&namespace, &resource, &viewer_id)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
    }

    /// Creates a ticket that grants permission to sync videos in this namespace.
    pub async fn generate_ticket(&self, namespace: &str) -> Result<String, Error> {
        self.access_control
            .list_manager()
            .generate_ticket(namespace)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
    }

    /// Returns a list of EndpointIds of the nodes
    /// who are allowed to access this video.
    pub async fn get_viewers(&self, namespace: &str, resource: &str) -> Result<Vec<String>, Error> {
        self.access_control
            .list_manager()
            .get_viewers(namespace, resource)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
    }

    /// Returns a list of EndpointIds of the nodes from Iroh-Docs
    /// who are currently syncing videos in this namespace.
    ///
    /// Intended for servers to determine who they are syncing with.
    pub async fn get_server_peers(&self, namespace: &str) -> Result<Vec<String>, Error> {
        self.access_control
            .list_manager()
            .get_server_endpoints(namespace)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
    }

    /// Returns all locally available videos,
    /// grouped by their namespace.
    pub async fn get_local_videos(&self) -> Result<HashMap<String, Vec<VideoInfo>>, Error> {
        self.access_control
            .get_local_videos()
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
    }

    /// Announces over iroh-gossip that this node is available to serve files.
    async fn notify_availability(&self, doc: Doc) -> Result<(), Error> {
        self.discovery
            .emit_topic(&doc.id().to_string(), &self.db, true)
            .await?;

        Ok(())
    }
}

#[derive(Deserialize)]
pub struct RequestArgs {
    namespace: String,
    resource: String,
    filename: String,
}

pub async fn download_handler(
    Path(request_args): Path<RequestArgs>,
    State(iroh_runtime): State<Arc<IrohRuntime>>,
) -> impl IntoResponse {
    println!("Got a request!");

    let file = match iroh_runtime
        .download_file(
            &request_args.namespace,
            &request_args.resource,
            &request_args.filename,
        )
        .await
    {
        Ok(Some(file)) => file,
        Ok(None) => {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    "Permission error or file hash didn't match resource",
                ))
                .unwrap();
        }
        Err(e) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(format!("Network error occured, {e}")))
                .unwrap();
        }
    };

    let content_type = mime_guess::from_path(&request_args.filename).first_or_octet_stream();

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type.as_ref())
        .body(body)
        .unwrap()
}
