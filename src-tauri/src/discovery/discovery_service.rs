use std::{collections::HashSet, str::FromStr, time::Duration};

use crate::{
    entities::{address, topic},
    Error,
};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointId, PublicKey};
use iroh_gossip::{api::GossipSender, Gossip, TopicId};
use sea_orm::DbConn;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::discovery::{discovery_receiver, discovery_sender::GossipDiscoverySender, AddressInfo};

/// Uses Iroh-gossip to find other servers then add them to a local database.
/// Viewers will only listen for server announcments that they are available,
/// while servers will actively announce themselves.
/// Both will write to the database on new server announcment.
#[derive(Debug)]
pub struct DiscoveryService {
    endpoint: Endpoint,
    gossip: Gossip,
    task_tracker: DashMap<String, CancellationToken>,
}

impl DiscoveryService {
    pub fn new(endpoint: Endpoint, gossip: Gossip) -> Self {
        Self {
            endpoint,
            gossip,
            task_tracker: DashMap::new(),
        }
    }

    pub fn cancel_topic(&self, topic_id: &str) -> bool {
        if let Some(token) = self.task_tracker.get(topic_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    pub async fn emit_topic(&self, topic_id: &str, db: &DbConn, emit: bool) -> Result<(), Error> {
        let entry = topic::Entity::find_by_topic(topic_id)
            .find_with_related(address::Entity)
            .all(db)
            .await?;

        let bootstraps: Vec<EndpointId> = entry
            .first()
            .map(|(_, addresses)| {
                addresses
                    .iter()
                    .filter_map(|i| EndpointId::from_str(&i.endpoint).ok())
                    .collect()
            })
            .unwrap_or_default();

        let topic = TopicId::from_str(topic_id).map_err(|e| Error::InputErr(e.to_string()))?;

        // Setting up subscribing to the gossip topic.
        let (sender, mut receiver) = self
            .gossip
            .subscribe(topic, bootstraps.clone())
            .await
            .map_err(|e| Error::IrohErr(e.to_string()))?
            .split();

        let token = CancellationToken::new();
        self.task_tracker
            .insert(topic_id.to_string(), token.clone());
        let send_token = token.clone();

        let peer_rx = if emit {
            let peer_tx = self.emit(topic_id, sender, send_token);

            Some(peer_tx)
        } else {
            None
        };

        let conn = db.clone();
        tokio::spawn(async move {
            tokio::select! {
                res = discovery_receiver::update_list(
                    &mut receiver,
                    peer_rx,
                    bootstraps.iter().cloned().collect::<HashSet<EndpointId>>(),
                    &conn
                ) => {
                    match res {
                        Ok(_) => { println!("The gossip receiver is no longer receiving messages"); },
                        Err(e) => { eprintln!("An error occured during peer discovery: {}", e)}
                    };
                },
                _ = token.cancelled() => {
                    println!("Task cancelled")
                }
            }
        });

        Ok(())
    }

    fn emit(
        &self,
        topic_id: &str,
        sender: GossipSender,
        token: CancellationToken,
    ) -> UnboundedSender<PublicKey> {
        let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<EndpointId>();
        let node_secret = self.endpoint.secret_key();
        let secret_key_bytes = node_secret.to_bytes();
        let secret_key = SigningKey::from_bytes(&secret_key_bytes);

        let address_info = AddressInfo {
            node_id: self.endpoint.id(),
            topic_id: topic_id.to_string(),
            role: crate::discovery::PeerRole::Server,
        };

        let mut discovery_sender = GossipDiscoverySender {
            peer_rx,
            sender,
            secret_key,
            address_info,
        };

        tokio::spawn(async move {
            tokio::select! {
                Err(e) = discovery_sender.gossip(Duration::from_secs(2)) => {
                    eprintln!("The signed message was invalid and couldn't be sent: {}", e)
                },
                _ = token.cancelled() => ()
            }
        });

        peer_tx
    }
}
