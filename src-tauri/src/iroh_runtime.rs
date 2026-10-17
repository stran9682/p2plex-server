use std::collections::HashMap;
use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};

use ffmpeg_sidecar::command::ffmpeg_is_installed;
use ffmpeg_sidecar::paths::ffmpeg_path;
use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointId};
use iroh_blobs::store::mem::MemStore;
use sea_orm::{ActiveHasMany, ActiveValue::Set, DatabaseConnection};
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel};
use serde::Deserialize;
use tempfile::TempDir;
use tokio::fs::File;

use crate::protocol::{AccessControl, Request};
use crate::store::AccessListManager;
use crate::store::VideoInfo;
use crate::Error::IrohErr;
use crate::MANAGEMENT;
use crate::{
    entities::{address, topic},
    iroh::iroh_mem_instance::IrohMemInstance,
    store::StorageManager,
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
}

impl IrohRuntime {
    pub async fn new(db: DatabaseConnection) -> anyhow::Result<Self> {
        let endpoint = Endpoint::bind(presets::N0).await?;
        let shared_blobs = MemStore::new();

        let acl_iroh_instance = IrohMemInstance::new(shared_blobs.clone(), endpoint.clone());

        let list_manager = AccessListManager::new(acl_iroh_instance);

        let storage_iroh_instance = IrohMemInstance::new(shared_blobs.clone(), endpoint.clone());
        let storage_manager = StorageManager::new(storage_iroh_instance);

        let access_control =
            AccessControl::new(list_manager.clone(), storage_manager, endpoint.clone());

        println!("Endpoint: {}", endpoint.id());

        let _router = Router::builder(endpoint)
            .accept(ALPN, access_control.clone())
            .accept(DISCOVERY_ALPN, access_control.clone())
            .accept(MANAGEMENT, access_control.clone())
            .spawn();

        // Background periodic replication loop for eventual consistency
        let acl_for_sync = access_control.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                interval.tick().await;
                if let Ok(namespaces) = acl_for_sync.list_manager().get_all_namespaces().await {
                    for ns in namespaces {
                        if let Err(e) = acl_for_sync.replicate_handler(&ns).await {
                            eprintln!("Periodic replication error for {ns}: {e}");
                        }
                    }
                }
            }
        });

        Ok(Self {
            _router,
            access_control,
            db,
        })
    }

    /// Creates an in-memory IrohRuntime instance for testing or standalone execution
    pub async fn create_in_memory() -> anyhow::Result<Self> {
        let db = sea_orm::Database::connect("sqlite::memory:").await?;
        db.get_schema_registry("video_server_lib").sync(&db).await?;
        Self::new(db).await
    }

    pub fn access_control(&self) -> &AccessControl {
        &self.access_control
    }

    /// Import a ticket to begin syncing videos inside the namespace with other servers.
    /// Will download videos locally to iroh-blobs,
    pub async fn import_ticket(&self, ticket: String) -> Result<(), Error> {
        let namespace = self
            .access_control
            .import(&ticket)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        let parsed_ticket = crate::store::ServerTicket::parse(&ticket)
            .map_err(|e| Error::InputErr(e.to_string()))?;

        let mut topic = match topic::Entity::find_by_topic(&namespace)
            .one(&self.db)
            .await?
        {
            Some(topic) => {
                let topic = topic.into_active_model();
                topic.into_ex()
            }
            None => topic::ActiveModelEx {
                topic: Set(namespace.clone()),
                ..Default::default()
            },
        };

        // Add addresses associated with the topic to the database.
        for endpoint in parsed_ticket.servers {
            let endpoint_id = endpoint.to_string();
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

        Ok(())
    }

    /// Adds a local video and creates a syncable namespace that other peers can sync with.
    pub async fn add_dir(
        &self,
        file_path: PathBuf,
        namespace: Option<String>,
    ) -> Result<String, Error> {
        if !ffmpeg_is_installed() {
            return Err(Error::InputErr("ffmpeg was not installed".to_string()));
        }

        let Some(filename) = file_path.file_name() else {
            return Err(Error::InputErr("Filename was invalid".to_owned()));
        };

        let temp_dir = TempDir::new()
            .map_err(|e| Error::InputErr(format!("Failed to create temp dir {e}")))?;

        let playlist_path = temp_dir.path().join("playlist.m3u8");

        let ffmpeg_bin = ffmpeg_path();
        let output = tokio::process::Command::new(ffmpeg_bin)
            .arg("-i")
            .arg(&file_path)
            .args([
                "-c",
                "copy",
                "-start_number",
                "1",
                "-hls_time",
                "10",
                "-hls_list_size",
                "0",
                "-f",
                "hls",
            ])
            .arg(&playlist_path)
            .output()
            .await
            .map_err(|e| Error::InputErr(format!("Failed to execute ffmpeg: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("ffmpeg error: {stderr}");
            return Err(Error::InputErr(format!(
                "ffmpeg failed during processing: {stderr}"
            )));
        }

        let ns = self
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
                topic: Set(ns.clone()),
                ..Default::default()
            };

            topic.save(&self.db).await?;
        }

        Ok(ns)
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

        for (ns, vids) in &local_videos {
            println!("Local store {ns}: {} video(s): {:?}", vids.len(), vids);
        }

        // Merge local videos into namespace_videos without overwriting remote results with empty lists
        for (namespace, videos) in local_videos {
            let entry = namespace_videos.entry(namespace).or_default();
            for vid in videos {
                if !entry.iter().any(|v| v.tag == vid.tag) {
                    entry.push(vid);
                }
            }
        }

        for (ns, vids) in &namespace_videos {
            println!("Total authorized store {ns}: {} video(s)", vids.len());
        }

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
        let ok = self
            .access_control
            .list_manager()
            .modify_access_list(&namespace, &resource, &viewer_id, false)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        if ok {
            if let Ok(Some(data)) = self
                .access_control
                .list_manager()
                .get_group_data(&namespace)
                .await
            {
                let _ = self
                    .access_control
                    .broadcast_operations(&namespace, data.operations)
                    .await;
            }
        }

        Ok(ok)
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
        let ok = self
            .access_control
            .list_manager()
            .modify_access_list(&namespace, &resource, &viewer_id, true)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        if ok {
            if let Ok(Some(data)) = self
                .access_control
                .list_manager()
                .get_group_data(&namespace)
                .await
            {
                let _ = self
                    .access_control
                    .broadcast_operations(&namespace, data.operations)
                    .await;
            }
        }

        Ok(ok)
    }

    /// Adds a server peer to the server list for a namespace
    pub async fn add_server(&self, namespace: String, server: String) -> Result<bool, Error> {
        let server_id =
            EndpointId::from_str(&server).map_err(|e| Error::InputErr(e.to_string()))?;
        let ok = self
            .access_control
            .list_manager()
            .modify_server_list(
                &namespace,
                &server_id,
                Some(crate::store::PermissionLevel::Server),
            )
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        if ok {
            if let Ok(Some(data)) = self
                .access_control
                .list_manager()
                .get_group_data(&namespace)
                .await
            {
                let _ = self
                    .access_control
                    .broadcast_operations(&namespace, data.operations)
                    .await;
            }
        }

        Ok(ok)
    }

    /// Removes a server peer from the server list for a namespace (revoking server sync access)
    pub async fn remove_server(&self, namespace: String, server: String) -> Result<bool, Error> {
        let server_id =
            EndpointId::from_str(&server).map_err(|e| Error::InputErr(e.to_string()))?;
        let ok = self
            .access_control
            .list_manager()
            .modify_server_list(
                &namespace,
                &server_id,
                None,
            )
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        if ok {
            if let Ok(Some(data)) = self
                .access_control
                .list_manager()
                .get_group_data(&namespace)
                .await
            {
                let _ = self
                    .access_control
                    .broadcast_operations(&namespace, data.operations)
                    .await;
            }
        }

        Ok(ok)
    }

    /// Creates a ticket that grants permission to sync videos in this namespace.
    pub async fn generate_ticket(&self, namespace: &str) -> Result<String, Error> {
        let mut servers = vec![self.endpoint_id()];
        if let Ok(Some(peers)) = self
            .access_control
            .list_manager()
            .get_server_endpoints(namespace)
            .await
        {
            for p in peers {
                if !servers.contains(&p) {
                    servers.push(p);
                }
            }
        }
        let ticket = crate::store::ServerTicket::new(namespace.to_string(), servers);
        Ok(ticket.format())
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
        let res = self
            .access_control
            .list_manager()
            .get_server_endpoints(namespace)
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?;

        match res {
            Some(res) => {
                let res: Vec<String> = res.iter().map(|e| e.to_string()).collect();
                Ok(res)
            }
            None => Err(Error::IrohErr("Server list not found in blobs".to_string())),
        }
    }

    /// Returns all locally available videos,
    /// grouped by their namespace.
    pub async fn get_local_videos(&self) -> Result<HashMap<String, Vec<VideoInfo>>, Error> {
        self.access_control
            .get_local_videos()
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))
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
