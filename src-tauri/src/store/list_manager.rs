use std::collections::{HashMap, HashSet};

use iroh::{EndpointId, PublicKey};
use rand::distr::{Alphanumeric, SampleString};
use tokio_stream::StreamExt;

use crate::iroh::iroh_mem_instance::IrohMemInstance;
use crate::store::PermissionLevel::{Unauthorized, Viewer};
use crate::store::{LwwEntry, PermissionLevel, ServerPermissions, VideoMetadata};

/// Manages the Access control lists associated with a video using Iroh-Docs
/// As a server, verifies Endpoints are inside access lists.
/// For viewers, retrieves metadata about what videos are accessible in a namespace
#[derive(Debug, Clone)]
pub struct AccessListManager {
    iroh_instance: IrohMemInstance,
}

impl AccessListManager {
    pub fn new(iroh_instance: IrohMemInstance) -> Self {
        Self { iroh_instance }
    }

    /// Adds a peer to an access control list
    pub async fn modify_access_list(
        &self,
        namespace: &str,
        resource: &str,
        endpoint_id: &EndpointId,
        remove: bool,
    ) -> anyhow::Result<bool> {
        let Some(mut acl) = self.get_acl(namespace, resource).await? else {
            return Ok(false);
        };

        let outcome = if remove {
            acl.remove(endpoint_id)
        } else {
            acl.insert(*endpoint_id)
        };

        if outcome {
            let Some(mut metadata) = self.get_metadata(namespace, resource).await? else {
                return Ok(false);
            };

            metadata.update_acl(self.iroh_instance.endpoint().secret_key(), acl);
            let tag = format!("{}/{}", namespace, resource);

            self.update_bytes(&tag, &serde_json::to_vec(&metadata)?)
                .await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn modify_server_list(
        &self,
        namespace: &str,
        endpoint_id: &EndpointId,
        permission_level: PermissionLevel,
        remove: bool,
    ) -> anyhow::Result<bool> {
        let Some(mut servers_list) = self.get_server_perms(namespace).await? else {
            return Ok(false);
        };

        let mut servers = servers_list.value.clone();
        let outcome = if remove {
            servers.remove(endpoint_id)
        } else {
            servers.insert(*endpoint_id, permission_level)
        };

        if let Some(_) = outcome {
            let new_list = LwwEntry::new(servers);
            servers_list.merge(new_list);

            self.update_bytes(&namespace, &serde_json::to_vec(&servers_list)?)
                .await?;

            return Ok(true);
        }

        Ok(false)
    }

    pub async fn create_namespace(&self) {
        let namespace = Alphanumeric.sample_string(&mut rand::rng(), 10);
    }

    /// Determines if a peer can access a video.
    pub async fn check_authorization(
        &self,
        namespace: &str,
        resource: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<PermissionLevel> {
        // 1. Is this peer a registered server for this store?
        if let Some(servers) = self.get_server_perms(namespace).await? {
            let servers = servers.value;
            if servers.contains_key(endpoint_id) {
                return Ok(*servers.get(endpoint_id).unwrap());
            }
        }

        // 2. Is this peer an authorized viewer for this video?
        if let Some(viewer_acl) = self.get_acl(namespace, resource).await? {
            if viewer_acl.contains(endpoint_id) {
                return Ok(Viewer);
            }
        }

        Ok(Unauthorized)
    }

    pub async fn get_viewers(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<Vec<String>> {
        if let Some(viewers) = self.get_acl(namespace, resource).await? {
            Ok(viewers.into_iter().map(|id| id.to_string()).collect())
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn get_server_endpoints(
        &self,
        namespace: &str,
    ) -> anyhow::Result<Option<Vec<String>>> {
        if let Some(servers) = self.get_server_perms(namespace).await? {
            let servers = servers.value;
            let endpoints: Vec<&PublicKey> = servers.keys().collect();
            return Ok(Some(endpoints.iter().map(|e| e.to_string()).collect()));
        }
        return Ok(None);
    }

    /// Check locally the videos a peer has access to inside a namespace
    /// Intended for servers.
    pub async fn get_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: Option<&EndpointId>,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let endpoint_id = match endpoint_id {
            Some(endpoint_id) => endpoint_id,
            None => &self.iroh_instance.endpoint().id(),
        };

        // Check if requester is a server for this namespace
        let servers = match self.get_server_perms(namespace).await? {
            Some(i) => i.value,
            None => HashMap::new(),
        };
        let is_server = servers.contains_key(endpoint_id);

        let entries = self
            .iroh_instance
            .blobs()
            .tags()
            .list_prefix(namespace)
            .await?;

        let entries: Vec<_> = entries.collect().await;
        let mut authorized_videos: Vec<String> = Vec::new();

        for entry_res in entries {
            let Ok(entry) = entry_res else {
                continue;
            };

            let tag = entry.name.to_string();

            let parts: Vec<&str> = tag.split('/').collect();

            // this will exclude the servers list and the files
            if parts.len() != 2 {
                continue;
            }

            if is_server {
                // Servers are authorized to see/sync all videos in the namespace
                authorized_videos.push(tag);
            } else {
                // Viewers: check private viewer ACL
                if let Ok(bytes) = self.iroh_instance.blobs().get_bytes(entry.hash).await {
                    if let Ok(metadata) = serde_json::from_slice::<VideoMetadata>(&bytes) {
                        if metadata
                            .acl
                            .value
                            .authorized_endpoints
                            .contains(endpoint_id)
                        {
                            authorized_videos.push(tag);
                        }
                    }
                }
            }
        }

        Ok(Some(authorized_videos))
    }

    pub async fn get_all_namespaces(&self) -> anyhow::Result<Vec<String>> {
        todo!("Working on it");
    }

    /// Returns the access control list for a resource in a namespace.
    pub async fn get_acl(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<Option<HashSet<EndpointId>>> {
        if let Some(metadata) = self.get_metadata(namespace, resource).await? {
            return Ok(Some(metadata.acl.value.authorized_endpoints));
        }

        return Ok(None);
    }

    async fn get_server_perms(&self, namespace: &str) -> anyhow::Result<Option<ServerPermissions>> {
        let Some(entry) = self.iroh_instance.blobs().tags().get(namespace).await? else {
            return Ok(None);
        };

        let bytes = self.iroh_instance.blobs().get_bytes(entry.hash).await?;
        let server_permissions: ServerPermissions = serde_json::from_slice(&bytes)?;

        Ok(Some(server_permissions))
    }

    async fn get_metadata(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<Option<VideoMetadata>> {
        let tag = format!("{}/{}", namespace, resource);
        let Some(entry) = self.iroh_instance.blobs().tags().get(tag).await? else {
            return Ok(None);
        };

        let bytes = self.iroh_instance.blobs().get_bytes(entry.hash).await?;
        let metadata: VideoMetadata = serde_json::from_slice(&bytes)?;

        Ok(Some(metadata))
    }

    async fn update_bytes(&self, tag: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let temp_tag = self.iroh_instance.blobs().add_slice(bytes).await?;
        self.iroh_instance
            .blobs()
            .tags()
            .set(tag, temp_tag.hash_and_format())
            .await?;

        Ok(())
    }
}
