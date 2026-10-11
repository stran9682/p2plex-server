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
        server_update: LwwEntry<ServerPermissions>,
    },
    AddEntry {
        entry: VideoMetadata,
    },
    Query {
        namespace: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PermissionLevel {
    Writer,
    Server,
    Viewer,
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
pub struct ServerPermissions {
    pub servers: HashMap<EndpointId, PermissionLevel>,
    pub signed_servers: Signature,
    pub from: VerifyingKey,
    pub namespace: String,
}

impl ServerPermissions {
    pub fn new(
        secret_key: &SigningKey,
        namespace: &str,
        servers: HashMap<EndpointId, PermissionLevel>,
    ) -> anyhow::Result<Self> {
        let server_bytes = serde_json::to_vec(&servers)?;

        let signed_servers = secret_key.sign(&server_bytes);
        let from = secret_key.verifying_key();

        Ok(Self {
            servers,
            signed_servers,
            from,
            namespace: namespace.to_string(),
        })
    }

    #[allow(dead_code)]
    pub fn verify_and_decode(
        bytes: &[u8],
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Self>> {
        let server_perms: Self = serde_json::from_slice(bytes)?;
        let key = server_perms.from;

        if let Err(_) = key.verify(
            &serde_json::to_vec(&server_perms.servers)?,
            &server_perms.signed_servers,
        ) {
            return Ok(None);
        }

        let bytes: &[u8; 32] = key.as_bytes()[..].try_into()?;
        let expected_node_id = EndpointId::from_bytes(bytes)?;

        if expected_node_id != *endpoint_id {
            return Ok(None);
        }

        Ok(Some(server_perms))
    }
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

    pub fn merge(&mut self, incoming: Self) {
        if incoming.timestamp > self.timestamp {
            *self = incoming;
        }
    }
}
