use std::collections::BTreeSet;
use p2panda_auth::{
    Access, AccessLevel, GroupsOperation,
    group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember, resolver::StrongRemove},
    traits::Conditions,
};
use p2panda_core::{Hash, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct ResourceCondition {
    pub resources: BTreeSet<String>,
}

impl Conditions for ResourceCondition {}

type VideoGroupCrdt = GroupCrdt<
    VerifyingKey,
    Hash,
    GroupsOperation<ResourceCondition>,
    ResourceCondition,
    StrongRemove<VerifyingKey, Hash, GroupsOperation<ResourceCondition>, ResourceCondition>,
>;

type VideoGroupState = GroupCrdtState<
    VerifyingKey,
    Hash,
    GroupsOperation<ResourceCondition>,
    ResourceCondition,
>;

#[test]
fn test_p2panda_auth_lifecycle() -> anyhow::Result<()> {
    let writer_key = SigningKey::generate();
    let writer_vk = writer_key.verifying_key();
    let group_id = writer_vk;

    let server_key = SigningKey::generate();
    let server_vk = server_key.verifying_key();

    let viewer_key = SigningKey::generate();
    let viewer_vk = viewer_key.verifying_key();

    // 1. Initialize CRDT state and create group with Writer
    let mut state = VideoGroupCrdt::init();

    let create_action = GroupAction::Create {
        initial_members: vec![(GroupMember::Individual(writer_vk), Access::manage())],
    };
    let op0_bytes = serde_json::to_vec(&(writer_vk, Vec::<Hash>::new(), group_id, &create_action))?;
    let op0 = GroupsOperation {
        id: Hash::digest(&op0_bytes),
        author: writer_vk,
        dependencies: vec![],
        group_id,
        action: create_action,
    };
    state = VideoGroupCrdt::process(state, &op0).unwrap();

    // Check members: writer has manage access
    let members = state.members(group_id);
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, writer_vk);
    assert_eq!(members[0].1.level, AccessLevel::Manage);

    // 2. Add Server
    let add_server_action = GroupAction::Add {
        member: GroupMember::Individual(server_vk),
        access: Access::write(),
    };
    let deps1 = state.heads();
    let op1_bytes = serde_json::to_vec(&(writer_vk, &deps1, group_id, &add_server_action))?;
    let op1 = GroupsOperation {
        id: Hash::digest(&op1_bytes),
        author: writer_vk,
        dependencies: deps1,
        group_id,
        action: add_server_action,
    };
    state = VideoGroupCrdt::process(state, &op1).unwrap();

    let members = state.members(group_id);
    assert_eq!(members.len(), 2);
    let s_mem = members.iter().find(|m| m.0 == server_vk).unwrap();
    assert_eq!(s_mem.1.level, AccessLevel::Write);

    // 3. Add Viewer with condition for "video123"
    let mut resources = BTreeSet::new();
    resources.insert("video123".to_string());
    let add_viewer_action = GroupAction::Add {
        member: GroupMember::Individual(viewer_vk),
        access: Access::read().with_conditions(ResourceCondition { resources }),
    };
    let deps2 = state.heads();
    let op2_bytes = serde_json::to_vec(&(writer_vk, &deps2, group_id, &add_viewer_action))?;
    let op2 = GroupsOperation {
        id: Hash::digest(&op2_bytes),
        author: writer_vk,
        dependencies: deps2,
        group_id,
        action: add_viewer_action,
    };
    state = VideoGroupCrdt::process(state, &op2).unwrap();

    let members = state.members(group_id);
    assert_eq!(members.len(), 3);
    let v_mem = members.iter().find(|m| m.0 == viewer_vk).unwrap();
    assert_eq!(v_mem.1.level, AccessLevel::Read);
    assert!(v_mem.1.conditions.as_ref().unwrap().resources.contains("video123"));

    // 4. Test Serialization and Deserialization of GroupCrdtState
    let serialized = postcard::to_stdvec(&state)?;
    let deserialized: VideoGroupState = postcard::from_bytes(&serialized)?;
    let des_members = deserialized.members(group_id);
    assert_eq!(des_members.len(), 3);

    // 5. Remove Server
    let remove_server_action = GroupAction::Remove {
        member: GroupMember::Individual(server_vk),
    };
    let deps3 = state.heads();
    let op3_bytes = serde_json::to_vec(&(writer_vk, &deps3, group_id, &remove_server_action))?;
    let op3 = GroupsOperation {
        id: Hash::digest(&op3_bytes),
        author: writer_vk,
        dependencies: deps3,
        group_id,
        action: remove_server_action,
    };
    state = VideoGroupCrdt::process(state, &op3).unwrap();

    let members = state.members(group_id);
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|m| m.0 != server_vk));

    println!("All p2panda-auth operations completed successfully!");
    Ok(())
}

fn merge_operations(
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

#[test]
fn test_sync_between_replicas() -> anyhow::Result<()> {
    let writer_key = SigningKey::generate();
    let writer_vk = writer_key.verifying_key();
    let group_id = writer_vk;

    let server1_key = SigningKey::generate();
    let server1_vk = server1_key.verifying_key();

    let server2_key = SigningKey::generate();
    let server2_vk = server2_key.verifying_key();

    // 1. Origin creates group
    let mut origin_state = VideoGroupCrdt::init();
    let create_action = GroupAction::Create {
        initial_members: vec![(GroupMember::Individual(writer_vk), Access::manage())],
    };
    let op0_bytes = serde_json::to_vec(&(writer_vk, Vec::<Hash>::new(), group_id, &create_action))?;
    let op0 = GroupsOperation {
        id: Hash::digest(&op0_bytes),
        author: writer_vk,
        dependencies: vec![],
        group_id,
        action: create_action,
    };
    origin_state = VideoGroupCrdt::process(origin_state, &op0).unwrap();

    // 2. Add server 1
    let add_s1_action = GroupAction::Add {
        member: GroupMember::Individual(server1_vk),
        access: Access::write(),
    };
    let deps1 = origin_state.heads();
    let op1_bytes = serde_json::to_vec(&(writer_vk, &deps1, group_id, &add_s1_action))?;
    let op1 = GroupsOperation {
        id: Hash::digest(&op1_bytes),
        author: writer_vk,
        dependencies: deps1,
        group_id,
        action: add_s1_action,
    };
    origin_state = VideoGroupCrdt::process(origin_state, &op1).unwrap();

    // 3. Add server 2
    let add_s2_action = GroupAction::Add {
        member: GroupMember::Individual(server2_vk),
        access: Access::write(),
    };
    let deps2 = origin_state.heads();
    let op2_bytes = serde_json::to_vec(&(writer_vk, &deps2, group_id, &add_s2_action))?;
    let op2 = GroupsOperation {
        id: Hash::digest(&op2_bytes),
        author: writer_vk,
        dependencies: deps2,
        group_id,
        action: add_s2_action,
    };
    origin_state = VideoGroupCrdt::process(origin_state, &op2).unwrap();

    // 4. Replica starts with blank state and merges all operations from origin
    let replica_state = VideoGroupCrdt::init();
    let all_ops: Vec<GroupsOperation<ResourceCondition>> =
        origin_state.inner.operations.values().cloned().collect();

    let merged_replica = merge_operations(replica_state, all_ops)?;
    let replica_members = merged_replica.members(group_id);
    assert_eq!(replica_members.len(), 3);
    assert!(replica_members.iter().any(|m| m.0 == server1_vk));
    assert!(replica_members.iter().any(|m| m.0 == server2_vk));

    println!("Replica synchronization verified successfully!");
    Ok(())
}

#[test]
fn test_member_condition_updates() -> anyhow::Result<()> {
    let writer_key = SigningKey::generate();
    let writer_vk = writer_key.verifying_key();
    let group_id = writer_vk;

    let res_key = SigningKey::generate();
    let res_vk = res_key.verifying_key();

    let mut state = VideoGroupCrdt::init();
    let create_action = GroupAction::Create {
        initial_members: vec![
            (GroupMember::Individual(writer_vk), Access::manage()),
            (GroupMember::Individual(res_vk), Access::read().with_conditions(ResourceCondition::default())),
        ],
    };
    let op0_bytes = serde_json::to_vec(&(writer_vk, Vec::<Hash>::new(), group_id, &create_action))?;
    let op0 = GroupsOperation {
        id: Hash::digest(&op0_bytes),
        author: writer_vk,
        dependencies: vec![],
        group_id,
        action: create_action,
    };
    state = VideoGroupCrdt::process(state, &op0).unwrap();

    // Now update res_vk with condition containing "res1"
    let mut res_set = BTreeSet::new();
    res_set.insert("res1".to_string());
    let promote_action = GroupAction::Promote {
        member: GroupMember::Individual(res_vk),
        access: Access::read().with_conditions(ResourceCondition { resources: res_set.clone() }),
    };
    let deps1 = state.heads();
    let op1_bytes = serde_json::to_vec(&(writer_vk, &deps1, group_id, &promote_action))?;
    let op1 = GroupsOperation {
        id: Hash::digest(&op1_bytes),
        author: writer_vk,
        dependencies: deps1,
        group_id,
        action: promote_action,
    };
    state = VideoGroupCrdt::process(state, &op1).unwrap();

    let m = state.members(group_id);
    let r = m.iter().find(|m| m.0 == res_vk).unwrap();
    assert_eq!(r.1.level, AccessLevel::Read);
    assert!(r.1.conditions.as_ref().unwrap().resources.contains("res1"));
    println!("Resource authority promote with condition succeeded!");

    Ok(())
}
