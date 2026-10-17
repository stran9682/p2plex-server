use std::collections::{BTreeSet, HashSet};

use iroh::{EndpointId, PublicKey};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

use crate::iroh::iroh_mem_instance::IrohMemInstance;
use crate::store::{
    endpoint_to_verifying_key, namespace_to_group_id, namespace_to_resource_authority,
    verifying_key_to_endpoint, Access, AccessLevel, GroupAction, GroupMember, PermissionLevel,
    ResourceCondition, SignedAuthOperation, VideoGroupCrdt, VideoGroupState, VideoMetadata,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredGroupData {
    pub state: VideoGroupState,
    pub operations: Vec<SignedAuthOperation>,
}

/// Manages access control lists using p2panda-auth DAG CRDTs.
/// As a server, verifies endpoints are inside group states.
/// For viewers, retrieves metadata about accessible videos in a namespace.
#[derive(Debug, Clone)]
pub struct AccessListManager {
    iroh_instance: IrohMemInstance,
}

impl AccessListManager {
    pub fn new(iroh_instance: IrohMemInstance) -> Self {
        Self { iroh_instance }
    }

    pub async fn get_group_data(&self, namespace: &str) -> anyhow::Result<Option<StoredGroupData>> {
        let Some(entry) = self.iroh_instance.blobs().tags().get(namespace).await? else {
            return Ok(None);
        };

        let bytes = self.iroh_instance.blobs().get_bytes(entry.hash).await?;
        let data: StoredGroupData = postcard::from_bytes(&bytes)?;
        Ok(Some(data))
    }

    pub async fn save_group_data(
        &self,
        namespace: &str,
        data: &StoredGroupData,
    ) -> anyhow::Result<()> {
        let bytes = postcard::to_stdvec(data)?;
        self.update_bytes(namespace, &bytes).await?;
        Ok(())
    }

    /// Add or remove a viewer to an access control list for a resource.
    pub async fn modify_access_list(
        &self,
        namespace: &str,
        resource: &str,
        endpoint_id: &EndpointId,
        remove: bool,
    ) -> anyhow::Result<bool> {
        let Some(mut data) = self.get_group_data(namespace).await? else {
            return Ok(false);
        };

        let group_id = namespace_to_group_id(namespace);
        let viewer_vk = endpoint_to_verifying_key(endpoint_id)?;
        let signing_key = p2panda_core::SigningKey::from_bytes(
            &self.iroh_instance.endpoint().secret_key().to_bytes(),
        );

        let members = data.state.members(group_id);
        let current_mem = members.iter().find(|m| m.0 == viewer_vk);

        let action = if remove {
            let Some(mem) = current_mem else {
                return Ok(false);
            };
            let mut resources = mem
                .1
                .conditions
                .as_ref()
                .map(|c| c.resources.clone())
                .unwrap_or_default();
            if !resources.remove(resource) {
                return Ok(false);
            }
            if resources.is_empty() {
                GroupAction::Remove {
                    member: GroupMember::Individual(viewer_vk),
                }
            } else {
                GroupAction::Promote {
                    member: GroupMember::Individual(viewer_vk),
                    access: Access::read().with_conditions(ResourceCondition { resources }),
                }
            }
        } else {
            if let Some(mem) = current_mem {
                let mut resources = mem
                    .1
                    .conditions
                    .as_ref()
                    .map(|c| c.resources.clone())
                    .unwrap_or_default();
                if !resources.insert(resource.to_string()) {
                    return Ok(false);
                }
                GroupAction::Promote {
                    member: GroupMember::Individual(viewer_vk),
                    access: Access::read().with_conditions(ResourceCondition { resources }),
                }
            } else {
                let mut resources = BTreeSet::new();
                resources.insert(resource.to_string());
                GroupAction::Add {
                    member: GroupMember::Individual(viewer_vk),
                    access: Access::read().with_conditions(ResourceCondition { resources }),
                }
            }
        };

        let deps = data.state.heads();
        let signed_op = SignedAuthOperation::new(&signing_key, group_id, deps, action)?;
        data.state = VideoGroupCrdt::process(data.state, &signed_op.operation)
            .map_err(|e| anyhow::anyhow!("CRDT process error: {e}"))?;
        data.operations.push(signed_op);

        self.save_group_data(namespace, &data).await?;
        Ok(true)
    }

    /// Adds or removes a server in the namespace, then saves locally to blobs.
    /// `permission_level == None` indicates a removal.
    pub async fn modify_server_list(
        &self,
        namespace: &str,
        endpoint_id: &EndpointId,
        permission_level: Option<PermissionLevel>,
    ) -> anyhow::Result<bool> {
        let Some(mut data) = self.get_group_data(namespace).await? else {
            return Ok(false);
        };

        let group_id = namespace_to_group_id(namespace);
        let server_vk = endpoint_to_verifying_key(endpoint_id)?;
        let signing_key = p2panda_core::SigningKey::from_bytes(
            &self.iroh_instance.endpoint().secret_key().to_bytes(),
        );

        let members = data.state.members(group_id);
        let current_mem = members.iter().find(|m| m.0 == server_vk);

        let action = if permission_level.is_some() {
            if current_mem.is_some() && current_mem.unwrap().1.level == AccessLevel::Write {
                return Ok(false);
            }
            GroupAction::Add {
                member: GroupMember::Individual(server_vk),
                access: Access::write(),
            }
        } else {
            if current_mem.is_none() {
                return Ok(false);
            }
            GroupAction::Remove {
                member: GroupMember::Individual(server_vk),
            }
        };

        let deps = data.state.heads();
        let signed_op = SignedAuthOperation::new(&signing_key, group_id, deps, action)?;
        data.state = VideoGroupCrdt::process(data.state, &signed_op.operation)
            .map_err(|e| anyhow::anyhow!("CRDT process error: {e}"))?;
        data.operations.push(signed_op);

        self.save_group_data(namespace, &data).await?;
        Ok(true)
    }

    pub async fn insert_to_server_resource_list(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<bool> {
        let Some(mut data) = self.get_group_data(namespace).await? else {
            return Ok(false);
        };

        let group_id = namespace_to_group_id(namespace);
        let res_auth_vk = namespace_to_resource_authority(namespace);
        let signing_key = p2panda_core::SigningKey::from_bytes(
            &self.iroh_instance.endpoint().secret_key().to_bytes(),
        );

        let members = data.state.members(group_id);
        let current_mem = members.iter().find(|m| m.0 == res_auth_vk);

        let mut resources = current_mem
            .and_then(|m| m.1.conditions.as_ref().map(|c| c.resources.clone()))
            .unwrap_or_default();

        if !resources.insert(resource.to_string()) {
            return Ok(false);
        }

        let action = GroupAction::Promote {
            member: GroupMember::Individual(res_auth_vk),
            access: Access::read().with_conditions(ResourceCondition { resources }),
        };

        let deps = data.state.heads();
        let signed_op = SignedAuthOperation::new(&signing_key, group_id, deps, action)?;
        data.state = VideoGroupCrdt::process(data.state, &signed_op.operation)
            .map_err(|e| anyhow::anyhow!("CRDT process error: {e}"))?;
        data.operations.push(signed_op);

        self.save_group_data(namespace, &data).await?;
        Ok(true)
    }

    pub async fn create_namespace(&self) -> anyhow::Result<String> {
        let namespace = Alphanumeric.sample_string(&mut rand::rng(), 10);
        let group_id = namespace_to_group_id(&namespace);
        let res_auth_vk = namespace_to_resource_authority(&namespace);

        let signing_key = p2panda_core::SigningKey::from_bytes(
            &self.iroh_instance.endpoint().secret_key().to_bytes(),
        );
        let writer_vk = signing_key.verifying_key();

        let mut state = VideoGroupCrdt::init();
        let create_action = GroupAction::Create {
            initial_members: vec![
                (GroupMember::Individual(writer_vk), Access::manage()),
                (
                    GroupMember::Individual(res_auth_vk),
                    Access::read().with_conditions(ResourceCondition::default()),
                ),
            ],
        };

        let signed_op = SignedAuthOperation::new(&signing_key, group_id, vec![], create_action)?;
        state = VideoGroupCrdt::process(state, &signed_op.operation)
            .map_err(|e| anyhow::anyhow!("CRDT process error: {e}"))?;

        let data = StoredGroupData {
            state,
            operations: vec![signed_op],
        };

        self.save_group_data(&namespace, &data).await?;
        Ok(namespace)
    }

    /// Determines if a peer can access a video.
    pub async fn check_authorization(
        &self,
        namespace: &str,
        resource: Option<&str>,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<PermissionLevel> {
        let Some(data) = self.get_group_data(namespace).await? else {
            return Ok(PermissionLevel::Unauthorized);
        };

        let group_id = namespace_to_group_id(namespace);
        let res_auth_vk = namespace_to_resource_authority(namespace);
        let Ok(target_vk) = endpoint_to_verifying_key(endpoint_id) else {
            return Ok(PermissionLevel::Unauthorized);
        };

        if target_vk == res_auth_vk {
            return Ok(PermissionLevel::Unauthorized);
        }

        let members = data.state.members(group_id);
        for (vk, access) in members {
            if vk == target_vk {
                match access.level {
                    AccessLevel::Manage => return Ok(PermissionLevel::Writer),
                    AccessLevel::Write => return Ok(PermissionLevel::Server),
                    AccessLevel::Read | AccessLevel::Pull => {
                        if let Some(res) = resource {
                            if access
                                .conditions
                                .as_ref()
                                .map(|c| c.resources.contains(res))
                                .unwrap_or(false)
                            {
                                return Ok(PermissionLevel::Viewer);
                            } else {
                                return Ok(PermissionLevel::Unauthorized);
                            }
                        } else {
                            return Ok(PermissionLevel::Viewer);
                        }
                    }
                }
            }
        }

        Ok(PermissionLevel::Unauthorized)
    }

    pub async fn get_authorized_resources(
        &self,
        namespace: &str,
    ) -> anyhow::Result<HashSet<String>> {
        let Some(data) = self.get_group_data(namespace).await? else {
            return Ok(HashSet::new());
        };

        let group_id = namespace_to_group_id(namespace);
        let res_auth_vk = namespace_to_resource_authority(namespace);
        let members = data.state.members(group_id);

        if let Some(r_mem) = members.iter().find(|m| m.0 == res_auth_vk) {
            if let Some(ref c) = r_mem.1.conditions {
                return Ok(c.resources.iter().cloned().collect());
            }
        }

        Ok(HashSet::new())
    }

    pub async fn get_viewers(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<Vec<String>> {
        let Some(data) = self.get_group_data(namespace).await? else {
            return Ok(Vec::new());
        };

        let group_id = namespace_to_group_id(namespace);
        let res_auth_vk = namespace_to_resource_authority(namespace);
        let mut viewers = Vec::new();

        for (vk, access) in data.state.members(group_id) {
            if vk == res_auth_vk {
                continue;
            }
            if access.level == AccessLevel::Read {
                if access
                    .conditions
                    .as_ref()
                    .map(|c| c.resources.contains(resource))
                    .unwrap_or(false)
                {
                    if let Ok(ep) = verifying_key_to_endpoint(&vk) {
                        viewers.push(ep.to_string());
                    }
                }
            }
        }

        Ok(viewers)
    }

    pub async fn get_server_endpoints(
        &self,
        namespace: &str,
    ) -> anyhow::Result<Option<Vec<PublicKey>>> {
        let Some(data) = self.get_group_data(namespace).await? else {
            return Ok(None);
        };

        let group_id = namespace_to_group_id(namespace);
        let res_auth_vk = namespace_to_resource_authority(namespace);
        let mut endpoints = Vec::new();

        for (vk, access) in data.state.members(group_id) {
            if vk == res_auth_vk {
                continue;
            }
            if access.level == AccessLevel::Write || access.level == AccessLevel::Manage {
                if let Ok(ep) = verifying_key_to_endpoint(&vk) {
                    endpoints.push(ep);
                }
            }
        }

        Ok(Some(endpoints))
    }

    /// Check locally the videos a peer has access to inside a namespace.
    pub async fn get_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: Option<&EndpointId>,
        filter_metadata: bool,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let endpoint_id = match endpoint_id {
            Some(endpoint_id) => endpoint_id,
            None => &self.iroh_instance.endpoint().id(),
        };

        let status = self
            .check_authorization(namespace, None, endpoint_id)
            .await?;
        let is_server = status == PermissionLevel::Writer || status == PermissionLevel::Server;
        let is_viewer = status == PermissionLevel::Viewer;

        if status == PermissionLevel::Unauthorized {
            return Ok(Some(Vec::new()));
        }

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

            let tag = String::from_utf8_lossy(entry.name.as_ref()).to_string();
            let parts: Vec<&str> = tag.split('/').collect();

            if filter_metadata && parts.len() != 2 {
                continue;
            }

            if is_server {
                authorized_videos.push(tag);
            } else if is_viewer && parts.len() == 2 {
                let resource = parts[1];
                let perm = self
                    .check_authorization(namespace, Some(resource), endpoint_id)
                    .await?;
                if perm == PermissionLevel::Viewer {
                    authorized_videos.push(tag);
                }
            }
        }

        Ok(Some(authorized_videos))
    }

    pub fn iroh_instance(&self) -> &IrohMemInstance {
        &self.iroh_instance
    }

    pub async fn get_all_namespaces(&self) -> anyhow::Result<Vec<String>> {
        let tags = self.iroh_instance.blobs().tags().list().await?;
        let mut tags_stream = tags;
        let mut namespaces = HashSet::new();

        while let Some(tag_res) = tags_stream.next().await {
            if let Ok(entry) = tag_res {
                let tag_str = String::from_utf8_lossy(entry.name.as_ref()).to_string();
                let parts: Vec<&str> = tag_str.split('/').collect();
                if parts.len() == 1 {
                    if let Ok(Some(_)) = self.get_group_data(parts[0]).await {
                        namespaces.insert(parts[0].to_string());
                    }
                } else if !parts.is_empty() {
                    if let Ok(Some(_)) = self.get_group_data(parts[0]).await {
                        namespaces.insert(parts[0].to_string());
                    }
                }
            }
        }

        Ok(namespaces.into_iter().collect())
    }

    /// Returns the access control list for a resource in a namespace (viewer endpoints).
    pub async fn get_acl(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<Option<HashSet<EndpointId>>> {
        let viewers = self.get_viewers(namespace, resource).await?;
        let endpoints: HashSet<EndpointId> =
            viewers.into_iter().filter_map(|s| s.parse().ok()).collect();
        Ok(Some(endpoints))
    }

    pub async fn get_metadata(
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

    pub async fn update_bytes(&self, tag: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let temp_tag = self.iroh_instance.blobs().add_slice(bytes).await?;
        self.iroh_instance
            .blobs()
            .tags()
            .set(tag, temp_tag.hash_and_format())
            .await?;

        Ok(())
    }
}
