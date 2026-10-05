use std::collections::HashSet;
use std::str::FromStr;

use iroh::EndpointId;
use iroh_docs::Entry;
use iroh_docs::{api::Doc, engine::LiveEvent, store::Query, DocTicket, NamespaceId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::iroh::iroh_mem_instance::IrohMemInstance;
use crate::{Status, VideoInfo, DISCOVERY_ALPN};

#[derive(Debug, Clone)]
pub struct AccessListManager {
    iroh_instance: IrohMemInstance,
}

impl AccessListManager {
    pub fn new(iroh_instance: IrohMemInstance) -> Self {
        Self { iroh_instance }
    }

    pub async fn new_doc(&self, ticket: Option<String>) -> anyhow::Result<Doc> {
        let doc = match ticket {
            Some(ticket) => {
                let ticket = DocTicket::from_str(&ticket)?;
                let (doc, mut events) = self
                    .iroh_instance
                    .docs()
                    .import_and_subscribe(ticket)
                    .await?;

                while let Some(event) = events.next().await {
                    if let Ok(LiveEvent::ContentReady { .. }) = event {
                        println!("Finished syncing");
                        break;
                    }
                }

                doc
            }
            None => self.iroh_instance.docs().create().await?,
        };

        Ok(doc)
    }

    pub async fn append_access_list(
        &self,
        doc: &Doc,
        resource: Option<&str>,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<bool> {
        let namespace = doc.id().to_string();

        let mut acl = self
            .query_for_tag(doc, &namespace, resource)
            .await?
            .unwrap_or_else(HashSet::new);

        if acl.insert(*endpoint_id) {
            self.insert_bytes(doc, &namespace, resource, &acl).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn remove_access_list(
        &self,
        doc: &Doc,
        resource: Option<&str>,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<bool> {
        let namespace = doc.id().to_string();

        let mut acl = self
            .query_for_tag(doc, &namespace, resource)
            .await?
            .unwrap_or_else(HashSet::new);

        if acl.remove(endpoint_id) {
            self.insert_bytes(doc, &namespace, resource, &acl).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_servers(&self, namespace: &str) -> anyhow::Result<HashSet<EndpointId>> {
        let Some(doc) = self.get_doc(namespace).await? else {
            return Ok(HashSet::new());
        };
        Ok(self.query_for_tag(&doc, namespace, None).await?.unwrap_or_default())
    }

    pub async fn add_viewer_to_video(
        &self,
        namespace: &str,
        resource: &str,
        viewer: &EndpointId,
    ) -> anyhow::Result<bool> {
        let Some(doc) = self.get_doc(namespace).await? else {
            anyhow::bail!("Namespace document not found");
        };
        self.append_access_list(&doc, Some(resource), viewer).await
    }

    pub async fn remove_viewer_from_video(
        &self,
        namespace: &str,
        resource: &str,
        viewer: &EndpointId,
    ) -> anyhow::Result<bool> {
        let Some(doc) = self.get_doc(namespace).await? else {
            anyhow::bail!("Namespace document not found");
        };
        self.remove_access_list(&doc, Some(resource), viewer).await
    }

    pub async fn check_authorization(
        &self,
        namespace: &str,
        resource: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Status> {
        let Some(doc) = self.get_doc(namespace).await? else {
            return Ok(Status::ResourceNotFound);
        };

        if endpoint_id == &self.iroh_instance.endpoint().id() {
            return Ok(Status::Allowed);
        }

        // 1. Is this peer a registered server for this store?
        if let Some(servers) = self.query_for_tag(&doc, namespace, None).await? {
            if servers.contains(endpoint_id) {
                return Ok(Status::Allowed);
            }
        }

        // 2. Is this peer an authorized viewer for this video?
        if let Some(viewer_acl) = self.query_for_tag(&doc, namespace, Some(resource)).await? {
            if viewer_acl.contains(endpoint_id) {
                return Ok(Status::Allowed);
            }
        }

        Ok(Status::Denied)
    }

    pub async fn get_doc(&self, namespace: &str) -> anyhow::Result<Option<Doc>> {
        let namespace = NamespaceId::from_str(namespace)?;

        let doc = self.iroh_instance.docs().open(namespace).await?;

        Ok(doc)
    }

    pub async fn generate_ticket(&self, namespace: &str) -> anyhow::Result<String> {
        use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
        let Some(doc) = self.get_doc(namespace).await? else {
            anyhow::bail!("Namespace document not found");
        };
        let ticket = doc.share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses).await?;
        Ok(ticket.to_string())
    }

    pub async fn get_viewers(&self, namespace: &str, resource: &str) -> anyhow::Result<Vec<String>> {
        let Some(doc) = self.get_doc(namespace).await? else {
            return Ok(Vec::new());
        };
        if let Some(viewers) = self.query_for_tag(&doc, namespace, Some(resource)).await? {
            Ok(viewers.into_iter().map(|id| id.to_string()).collect())
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn get_server_endpoints(&self, namespace: &str) -> anyhow::Result<Vec<String>> {
        let servers = self.get_servers(namespace).await?;
        Ok(servers.into_iter().map(|id| id.to_string()).collect())
    }

    #[allow(dead_code)]
    pub async fn get_access_list(
        &self,
        namespace: &str,
        resource: &str,
    ) -> anyhow::Result<Option<(Doc, HashSet<EndpointId>)>> {
        let Some(doc) = self.get_doc(namespace).await? else {
            return Ok(None);
        };

        if let Some(access_list) = self.query_for_tag(&doc, namespace, Some(resource)).await? {
            return Ok(Some((doc, access_list)));
        }

        if let Some(access_list) = self.query_for_tag(&doc, namespace, None).await? {
            return Ok(Some((doc, access_list)));
        }

        Ok(None)
    }

    pub async fn request_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Vec<VideoInfo>>> {
        let endpoint = self.iroh_instance.endpoint();

        let conn = endpoint.connect(*endpoint_id, DISCOVERY_ALPN).await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        send.write_u32(namespace.len() as u32).await?;
        send.write_all(namespace.as_bytes()).await?;

        let status = recv.read_u8().await?;
        if status != (Status::Allowed as u8) {
            eprintln!(
                "Failed to retrieve file: {:?}",
                Status::try_from(status).unwrap_or(Status::UnknownError)
            );

            return Ok(None);
        }

        let bytes = recv.read_to_end(usize::MAX).await?;
        let authorized_videos: Vec<VideoInfo> = serde_json::from_slice(&bytes)?;

        Ok(Some(authorized_videos))
    }

    pub async fn get_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: Option<&EndpointId>,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let Some(doc) = self
            .iroh_instance
            .docs()
            .open(NamespaceId::from_str(namespace)?)
            .await?
        else {
            return Ok(None);
        };

        let endpoint_id = match endpoint_id {
            Some(endpoint_id) => endpoint_id,
            None => &self.iroh_instance.endpoint().id(),
        };

        // Check if requester is a server for this namespace
        let servers = self.query_for_tag(&doc, namespace, None).await?.unwrap_or_default();
        let is_server = servers.contains(endpoint_id) || endpoint_id == &self.iroh_instance.endpoint().id();

        let entries = doc.get_many(Query::single_latest_per_key().build()).await?;
        let entries: Vec<Result<Entry, anyhow::Error>> = entries.collect().await;

        let mut authorized_videos: Vec<String> = Vec::new();

        for entry_res in entries {
            let Ok(entry) = entry_res else { continue; };
            let Ok(tag) = String::from_utf8(entry.key().to_vec()) else { continue; };

            let parts: Vec<&str> = tag.split('/').collect();
            if parts.len() < 2 || parts[0] != namespace {
                continue;
            }

            if is_server {
                // Servers are authorized to see/sync all videos in the namespace
                authorized_videos.push(tag);
            } else {
                // Viewers: check private viewer ACL
                if let Ok(bytes) = self.iroh_instance.blobs().get_bytes(entry.content_hash()).await {
                    if let Ok(acl) = serde_json::from_slice::<HashSet<EndpointId>>(&bytes) {
                        if acl.contains(endpoint_id) {
                            authorized_videos.push(tag);
                        }
                    }
                }
            }
        }

        Ok(Some(authorized_videos))
    }

    pub async fn get_all_namespaces(&self) -> anyhow::Result<Vec<String>> {
        let mut stream = self.iroh_instance.docs().list().await?;

        let mut namespaces: Vec<String> = Vec::new();
        while let Some(Ok((namespace, _))) = stream.next().await {
            namespaces.push(namespace.to_string());
        }

        Ok(namespaces)
    }

    async fn query_for_tag(
        &self,
        doc: &Doc,
        namespace: &str,
        resource: Option<&str>,
    ) -> anyhow::Result<Option<HashSet<EndpointId>>> {
        let mut tag = namespace.to_string();
        if let Some(resource) = resource {
            tag.push_str(&format!("/{resource}"));
        };

        let Some(entry) = doc
            .get_one(Query::single_latest_per_key().key_exact(tag).build())
            .await?
        else {
            return Ok(None);
        };

        match self
            .iroh_instance
            .blobs()
            .get_bytes(entry.content_hash())
            .await
        {
            Ok(bytes) => {
                let list_members: HashSet<EndpointId> = serde_json::from_slice(&bytes)?;
                Ok(Some(list_members))
            }
            Err(e) => {
                eprintln!("Error reading entry: {e}");
                Ok(None)
            }
        }
    }

    async fn insert_bytes(
        &self,
        doc: &Doc,
        namespace: &str,
        resource: Option<&str>,
        access_list: &HashSet<EndpointId>,
    ) -> anyhow::Result<()> {
        let mut tag = namespace.to_string();
        if let Some(resource) = resource {
            tag.push_str(&format!("/{resource}"));
        };

        let content = serde_json::to_vec(access_list)?;

        doc.set_bytes(
            self.iroh_instance.docs().author_default().await?,
            tag,
            content,
        )
        .await?;

        println!("Updated list");
        Ok(())
    }
}
