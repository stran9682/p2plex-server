mod list_manager;
mod storage_manager;

pub use list_manager::{AccessListManager, StoredGroupData};
pub use storage_manager::StorageManager;

use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};

use iroh::{EndpointId, SecretKey};
pub use p2panda_auth::{
    Access, AccessLevel, GroupsOperation,
    group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember, resolver::StrongRemove},
    traits::Conditions,
};
pub use p2panda_core::{Hash, SigningKey, VerifyingKey};
use rs_merkle::{algorithms::Sha256, MerkleTree};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct ResourceCondition {
    pub resources: BTreeSet<String>,
}

impl Conditions for ResourceCondition {}

pub type VideoGroupCrdt = GroupCrdt<
    VerifyingKey,
    Hash,
    GroupsOperation<ResourceCondition>,
    ResourceCondition,
    StrongRemove<VerifyingKey, Hash, GroupsOperation<ResourceCondition>, ResourceCondition>,
>;

pub type VideoGroupState = GroupCrdtState<
    VerifyingKey,
    Hash,
    GroupsOperation<ResourceCondition>,
    ResourceCondition,
>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuthOperation {
    pub operation: GroupsOperation<ResourceCondition>,
    pub signature: p2panda_core::Signature,
}

impl SignedAuthOperation {
    pub fn new(
        signing_key: &SigningKey,
        group_id: VerifyingKey,
        dependencies: Vec<Hash>,
        action: GroupAction<VerifyingKey, ResourceCondition>,
    ) -> anyhow::Result<Self> {
        let author = signing_key.verifying_key();
        let payload = postcard::to_stdvec(&(author, &dependencies, group_id, &action))?;
        let id = Hash::digest(&payload);
        let signature = signing_key.sign(id.as_bytes());
        let operation = GroupsOperation {
            id,
            author,
            dependencies,
            group_id,
            action,
        };
        Ok(Self { operation, signature })
    }

    pub fn verify(&self) -> bool {
        let op = &self.operation;
        if let Ok(payload) =
            postcard::to_stdvec(&(op.author, &op.dependencies, op.group_id, &op.action))
        {
            let expected_id = Hash::digest(&payload);
            if op.id != expected_id {
                return false;
            }
            return op.author.verify(op.id.as_bytes(), &self.signature);
        }
        false
    }
}

pub fn namespace_to_group_id(namespace: &str) -> VerifyingKey {
    let digest = Hash::digest(format!("group:{}", namespace).as_bytes());
    SigningKey::from_bytes(digest.as_bytes()).verifying_key()
}

pub fn namespace_to_resource_authority(namespace: &str) -> VerifyingKey {
    let digest = Hash::digest(format!("resources:{}", namespace).as_bytes());
    SigningKey::from_bytes(digest.as_bytes()).verifying_key()
}

pub fn endpoint_to_verifying_key(endpoint: &EndpointId) -> anyhow::Result<VerifyingKey> {
    VerifyingKey::from_bytes(endpoint.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid endpoint key: {e}"))
}

pub fn verifying_key_to_endpoint(vk: &VerifyingKey) -> anyhow::Result<EndpointId> {
    let bytes: &[u8; 32] = vk.as_bytes();
    EndpointId::from_bytes(bytes).map_err(|e| anyhow::anyhow!("Invalid endpoint id: {e}"))
}

pub fn merge_operations(
    mut state: VideoGroupState,
    mut operations: Vec<GroupsOperation<ResourceCondition>>,
) -> anyhow::Result<VideoGroupState> {
    let mut progressed = true;
    while !operations.is_empty() && progressed {
        progressed = false;
        let mut remaining = Vec::new();
        for op in operations {
            if state.inner.operations.contains_key(&op.id) {
                continue;
            }
            let all_deps_present = op
                .dependencies
                .iter()
                .all(|dep| state.inner.operations.contains_key(dep));
            if all_deps_present {
                state = VideoGroupCrdt::process(state, &op)
                    .map_err(|e| anyhow::anyhow!("CRDT process error: {e}"))?;
                progressed = true;
            } else {
                remaining.push(op);
            }
        }
        operations = remaining;
    }
    if !operations.is_empty() {
        anyhow::bail!("Unsatisfied dependencies for {} operations", operations.len());
    }
    Ok(state)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ServerRequest {
    SyncAuth {
        namespace: String,
        operations: Vec<SignedAuthOperation>,
    },
    AddEntry {
        namespace: String,
        entry: VideoMetadata,
        operations: Vec<SignedAuthOperation>,
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

impl From<AccessLevel> for PermissionLevel {
    fn from(level: AccessLevel) -> Self {
        match level {
            AccessLevel::Manage => PermissionLevel::Writer,
            AccessLevel::Write => PermissionLevel::Server,
            AccessLevel::Read | AccessLevel::Pull => PermissionLevel::Viewer,
        }
    }
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
pub struct VideoMetadata {
    // filename -> (index in tree, hash)
    pub clip_hashes: HashMap<String, (usize, [u8; 32])>,
    pub video_name: String,
    pub resource: String,
}

impl VideoMetadata {
    pub fn new(
        leaves: Vec<(String, [u8; 32])>,
        video_name: &str,
        _namespace: &str,
        resource: &str,
        _secret_key: &SecretKey,
    ) -> Self {
        let mut clip_hashes: HashMap<String, (usize, [u8; 32])> = HashMap::new();

        for (index, (filename, leaf)) in leaves.into_iter().enumerate() {
            clip_hashes.insert(filename, (index, leaf));
        }

        Self {
            clip_hashes,
            video_name: video_name.to_string(),
            resource: resource.to_string(),
        }
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
pub struct MerkleVerification {
    pub merkle_proof: Vec<u8>,
    pub index: usize,
    pub count: usize,
}
