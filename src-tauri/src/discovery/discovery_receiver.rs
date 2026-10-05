use std::collections::HashSet;

use iroh::EndpointId;
use iroh_gossip::api::{Event, GossipReceiver};
use sea_orm::{ActiveValue::Set, DbConn, IntoActiveModel};
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::StreamExt;

use crate::{
    discovery::SignedMessage,
    entities::{address, topic},
};

pub async fn update_list(
    receiver: &mut GossipReceiver,
    peer_tx: Option<UnboundedSender<EndpointId>>,
    mut bootstrap: HashSet<EndpointId>,
    db: &DbConn,
) -> anyhow::Result<()> {
    while let Some(res) = receiver.next().await {
        match res {
            Ok(Event::Received(msg)) => {
                // Verify and decode the signed message
                let (verifying_key, address_info) =
                    match SignedMessage::verify_and_decode(&msg.content) {
                        Ok(result) => result,
                        Err(e) => {
                            eprintln!("Failed to verify message signature, ignoring {}", e);
                            continue;
                        }
                    };

                // Verify that the claimed node_id matches the public key
                let bytes: &[u8; 32] = verifying_key.as_bytes()[..].try_into()?;

                let expected_node_id = EndpointId::from_bytes(bytes)?;
                if address_info.node_id != expected_node_id {
                    println!("EndpointId spoofing attempt detected, ignoring message");
                    continue;
                }

                let is_new_peer = !bootstrap.contains(&expected_node_id);

                if is_new_peer {
                    // Send new peer to sender for joining
                    if let Some(ref tx) = peer_tx {
                        tx.send(address_info.node_id)?;
                    }
                    println!(
                        "Discovered new peer: {} (role: {:?}) for topic {}",
                        address_info.node_id, address_info.role, address_info.topic_id
                    );

                    bootstrap.insert(expected_node_id);

                    let endpoint =
                        match address::Entity::find_by_endpoint(expected_node_id.to_string())
                            .one(db)
                            .await?
                        {
                            Some(endpoint) => {
                                let endpoint = endpoint.into_active_model();
                                endpoint.into_ex()
                            }
                            None => address::ActiveModelEx {
                                endpoint: Set(expected_node_id.to_string()),
                                ..Default::default()
                            },
                        };

                    let topic = match topic::Entity::find_by_topic(&address_info.topic_id)
                        .one(db)
                        .await?
                    {
                        Some(topic) => {
                            let topic = topic.into_active_model();
                            topic.into_ex()
                        }
                        None => topic::ActiveModelEx {
                            topic: Set(address_info.topic_id),
                            ..Default::default()
                        },
                    };

                    topic.add_address(endpoint).save(db).await?;
                }
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error receiving gossip {}", e);
            }
        }
    }
    Ok(())
}
