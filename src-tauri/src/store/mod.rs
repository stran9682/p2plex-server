mod list_manager;
mod storage_manager;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use list_manager::AccessListManager;
pub use storage_manager::StorageManager;

use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    str::FromStr,
};

use iroh::{EndpointId, SecretKey};
use rs_merkle::{algorithms::Sha256, MerkleTree};
use serde::{Deserialize, Serialize};
use uhlc::{Timestamp, HLC};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ServerRequest {
    UpdateACL {
        acl_update: LwwEntry<SignedAcl>,
    },
    UpdateServers {
        server_update: SignedServerPerms,
    },
    AddEntry {
        entry: VideoMetadata,
        server_update: SignedServerPerms,
    },
    Query {
        namespace: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
/// Permission levels determine the capabilties a peer has in the namespace.
/// A higher level permission has all the access a lower level one has.
/// Since a decentralized environment assumes no trust,
/// actions associated with a permission level must be signed and verfied before
/// acted upon locally.
pub enum PermissionLevel {
    /// A writer can add a video to the namespace, which all other servers will download.
    /// A writer can also add or remove servers from the namespace,
    /// allowing or preventing them from syncing in the future
    Writer,
    /// A server is permitted to replicate a video and share with viewers.
    /// A server is also allowed to update access control lists associated with a video
    Server,
    /// A viewer can only make discovery requests
    /// for what videos they have access to in the namespace
    Viewer,
    /// This peer isn't part of the namespace.
    Unauthorized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoInfo {
    pub tag: String,
    pub video_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiscoveryResponse {
    pub files: Vec<VideoInfo>,
    pub servers: Vec<EndpointId>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerTicket {
    pub namespace: String,
    pub servers: Vec<EndpointId>,
}

impl ServerTicket {
    pub fn new(namespace: String, servers: Vec<EndpointId>) -> Self {
        Self { namespace, servers }
    }

    pub fn format(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Ok(ticket) = serde_json::from_str::<ServerTicket>(s) {
            return Ok(ticket);
        }
        if let Ok(doc_ticket) = iroh_docs::DocTicket::from_str(s) {
            let servers = doc_ticket.nodes.iter().map(|n| n.id).collect();
            return Ok(ServerTicket {
                namespace: doc_ticket.capability.id().to_string(),
                servers,
            });
        }
        anyhow::bail!("Invalid ticket format: {s}")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedAcl {
    pub authorized_endpoints: HashSet<EndpointId>,
    pub authorized_endpoints_signature: Signature,
    pub from: VerifyingKey,
    pub namespace: String,
    pub resource: String,
}

impl SignedAcl {
    pub fn new(
        secret_key: &SigningKey,
        namespace: &str,
        resource: &str,
        authorized_endpoints: HashSet<EndpointId>,
    ) -> anyhow::Result<Self> {
        let endpoint_bytes = serde_json::to_vec(&authorized_endpoints)?;
        let authorized_endpoints_signature = secret_key.sign(&endpoint_bytes);
        let from = secret_key.verifying_key();

        Ok(Self {
            authorized_endpoints,
            from,
            authorized_endpoints_signature,
            resource: resource.to_string(),
            namespace: namespace.to_string(),
        })
    }

    #[allow(dead_code)]
    pub fn verify_and_decode(
        bytes: &[u8],
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Self>> {
        let acl: Self = serde_json::from_slice(bytes)?;
        let key = acl.from;

        if let Err(_) = key.verify(
            &serde_json::to_vec(&acl.authorized_endpoints)?,
            &acl.authorized_endpoints_signature,
        ) {
            return Ok(None);
        }

        let bytes: &[u8; 32] = acl.from.as_bytes()[..].try_into()?;
        let expected_node_id = EndpointId::from_bytes(bytes)?;

        if expected_node_id != *endpoint_id {
            return Ok(None);
        }

        Ok(Some(acl))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VideoMetadata {
    // filename -> (index in tree, hash)
    pub clip_hashes: HashMap<String, (usize, [u8; 32])>,
    pub video_name: String,
    pub acl: LwwEntry<SignedAcl>,
}

impl VideoMetadata {
    pub fn new(
        leaves: Vec<(String, [u8; 32])>,
        video_name: &str,
        namespace: &str,
        resource: &str,
        secret_key: &SecretKey,
    ) -> Self {
        let mut clip_hashes: HashMap<String, (usize, [u8; 32])> = HashMap::new();

        for (index, (filename, leaf)) in leaves.into_iter().enumerate() {
            clip_hashes.insert(filename, (index, leaf));
        }

        let signing_key = SigningKey::from_bytes(&secret_key.to_bytes());

        Self {
            clip_hashes,
            video_name: video_name.to_string(),
            acl: LwwEntry::new(
                SignedAcl::new(&signing_key, namespace, resource, HashSet::new()).unwrap(),
            ),
        }
    }

    pub fn update_acl(
        &mut self,
        secret_key: &SecretKey,
        endpoints: HashSet<EndpointId>,
    ) -> anyhow::Result<()> {
        let prev_acl = &self.acl.value;
        let signing_key = SigningKey::from_bytes(&secret_key.to_bytes());

        let signed_acl = SignedAcl::new(
            &signing_key,
            &prev_acl.namespace,
            &prev_acl.resource,
            endpoints,
        )?;

        let new_acl = LwwEntry::new(signed_acl);
        self.acl.merge(new_acl);

        Ok(())
    }

    pub fn generate_proof(&self, filename: &str) -> Option<MerkleVerification> {
        let index = self.clip_hashes.get(filename).map(|x| x.0)?;

        let mut leaves = vec![[0u8; 32]; self.clip_hashes.len()];
        for (index, leaf) in self.clip_hashes.values() {
            leaves[*index] = *leaf;
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

        let merkle_proof = merkle_tree.proof(&[index]).to_bytes();

        Some(MerkleVerification {
            merkle_proof,
            index,
            count: leaves.len(),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedServerPerms {
    pub server_permissions: LwwEntry<ServerPermissions>,
    pub signed_server_perms: Signature,
    pub from_writer: VerifyingKey,
}

impl SignedServerPerms {
    pub fn canonical_payload(perms: &LwwEntry<ServerPermissions>) -> anyhow::Result<Vec<u8>> {
        let mut sorted_servers: Vec<(&EndpointId, &PermissionLevel)> = perms.servers.iter().collect();
        sorted_servers.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

        let mut sorted_resources: Vec<&String> = perms.resources.iter().collect();
        sorted_resources.sort();

        let payload = (
            sorted_servers,
            sorted_resources,
            &perms.namespace,
            perms.epoch,
            &perms.timestamp,
        );
        Ok(serde_json::to_vec(&payload)?)
    }

    pub fn new(
        secret_key: &SigningKey,
        server_permissions: LwwEntry<ServerPermissions>,
    ) -> anyhow::Result<Self> {
        let server_bytes = Self::canonical_payload(&server_permissions)?;

        let signed_server_perms = secret_key.sign(&server_bytes);
        let from_writer = secret_key.verifying_key();

        Ok(Self {
            from_writer,
            server_permissions,
            signed_server_perms,
        })
    }

    pub fn verify_signature(&self) -> anyhow::Result<bool> {
        let bytes = Self::canonical_payload(&self.server_permissions)?;
        Ok(self.from_writer.verify(&bytes, &self.signed_server_perms).is_ok())
    }

    pub fn writer_endpoint(&self) -> anyhow::Result<EndpointId> {
        let bytes: &[u8; 32] = self.from_writer.as_bytes()[..].try_into()?;
        let endpoint = EndpointId::from_bytes(bytes)?;
        Ok(endpoint)
    }

    pub fn is_writer_authorized(&self) -> anyhow::Result<bool> {
        let writer_endpoint = self.writer_endpoint()?;
        Ok(self.server_permissions.servers.get(&writer_endpoint) == Some(&PermissionLevel::Writer))
    }

    pub fn update(
        &mut self,
        updated_resources: Option<HashSet<String>>,
        updated_servers: Option<HashMap<EndpointId, PermissionLevel>>,
        secret_key: &SigningKey,
    ) -> anyhow::Result<bool> {
        let server_perms = &*self.server_permissions;

        // create the new server perms.
        let updated_server_perms = ServerPermissions {
            servers: updated_servers.unwrap_or_else(|| server_perms.servers.clone()),
            resources: updated_resources.unwrap_or_else(|| server_perms.resources.clone()),
            namespace: server_perms.namespace.clone(),
            epoch: server_perms.epoch + 1,
        };

        let mut new_server_perms = LwwEntry::new(updated_server_perms.clone());
        while new_server_perms.timestamp <= self.server_permissions.timestamp {
            std::thread::sleep(std::time::Duration::from_millis(1));
            new_server_perms = LwwEntry::new(updated_server_perms.clone());
        }
        let signature = secret_key.sign(&Self::canonical_payload(&new_server_perms)?);

        if self.server_permissions.merge(new_server_perms) {
            // if the update was valid, update the signature
            self.from_writer = secret_key.verifying_key();
            self.signed_server_perms = signature;

            return Ok(true);
        }
        return Ok(false);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerPermissions {
    pub servers: HashMap<EndpointId, PermissionLevel>,
    pub resources: HashSet<String>,
    pub namespace: String,
    pub epoch: u32, // So you can't roll back on permissions to an earlier state
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleVerification {
    pub merkle_proof: Vec<u8>,
    pub index: usize,
    pub count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LwwEntry<T> {
    pub value: T,
    pub timestamp: Timestamp,
}

impl<T> Deref for LwwEntry<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> LwwEntry<T> {
    pub fn new(value: T) -> Self {
        return Self {
            value,
            timestamp: HLC::default().new_timestamp(),
        };
    }

    pub fn merge(&mut self, incoming: Self) -> bool {
        if incoming.timestamp > self.timestamp {
            *self = incoming;
            return true;
        }
        false
    }
}
