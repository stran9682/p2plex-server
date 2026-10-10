mod list_manager;
mod storage_manager;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use list_manager::AccessListManager;
pub use storage_manager::StorageManager;

use std::collections::{HashMap, HashSet};

use iroh::{EndpointId, SecretKey};
use rs_merkle::{algorithms::Sha256, MerkleTree};
use serde::{Deserialize, Serialize};
use uhlc::{Timestamp, HLC};

#[derive(Serialize, Deserialize, Clone, Copy)]
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

#[derive(Serialize, Deserialize)]
pub struct SignedAcl {
    pub authorized_endpoints: HashSet<EndpointId>,
    pub from: VerifyingKey,
    pub resource_signature: Signature,
    pub namespace: String,
    pub resource: String,
}

impl SignedAcl {
    pub fn new(
        secret_key: &SigningKey,
        namespace: &str,
        resource: &str,
        authorized_endpoints: HashSet<EndpointId>,
    ) -> Self {
        let tag = format!("{}/{}", namespace, resource).into_bytes();
        let resource_signature = secret_key.sign(&tag);
        let from = secret_key.verifying_key();

        Self {
            authorized_endpoints,
            from,
            resource_signature,
            resource: String::from_utf8(tag).unwrap(),
            namespace: namespace.to_string(),
        }
    }

    pub fn verify_and_decode(
        bytes: &[u8],
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Self>> {
        let acl: Self = serde_json::from_slice(bytes)?;
        let key = acl.from;

        if let Err(_) = key.verify(&acl.resource.as_bytes(), &acl.resource_signature) {
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

#[derive(Serialize, Deserialize)]
struct VideoMetadata {
    clip_hashes: HashMap<String, (usize, [u8; 32])>,
    video_name: String,
    acl: LwwEntry<SignedAcl>,
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
            acl: LwwEntry::new(SignedAcl::new(
                &signing_key,
                namespace,
                resource,
                HashSet::new(),
            )),
        }
    }

    pub fn update_acl(&mut self, secret_key: &SecretKey, endpoints: HashSet<EndpointId>) {
        let prev_acl = &self.acl.value;
        let signing_key = SigningKey::from_bytes(&secret_key.to_bytes());

        let signed_acl = SignedAcl::new(
            &signing_key,
            &prev_acl.namespace,
            &prev_acl.resource,
            endpoints,
        );

        self.acl.merge(LwwEntry::new(signed_acl));
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
    ) -> Self {
        let namespace_signature = secret_key.sign(&tag);
        let from = secret_key.verifying_key();

        Self {
            authorized_endpoints,
            from,
            resource_signature,
            resource: String::from_utf8(tag).unwrap(),
            namespace: namespace.to_string(),
        }
    }

    pub fn verify_and_decode(
        bytes: &[u8],
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Self>> {
        let acl: Self = serde_json::from_slice(bytes)?;
        let key = acl.from;

        if let Err(_) = key.verify(&acl.resource.as_bytes(), &acl.resource_signature) {
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

#[derive(Serialize, Deserialize)]
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
