pub mod discovery_receiver;
pub mod discovery_sender;
pub mod discovery_service;

use bytes::Bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub enum PeerRole {
    #[default]
    Server,
    Viewer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressInfo {
    pub node_id: EndpointId,
    pub topic_id: String,
    #[serde(default)]
    pub role: PeerRole,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SignedMessage {
    from: VerifyingKey,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn sign_and_encode(
        secret_key: &SigningKey,
        address_info: &AddressInfo,
    ) -> anyhow::Result<Bytes> {
        let data: Bytes = Bytes::from(serde_json::to_vec(address_info)?);
        let signature = secret_key.sign(&data);
        let from: VerifyingKey = secret_key.verifying_key();

        let signed_message = Self {
            from,
            data,
            signature,
        };

        let encoded = serde_json::to_vec(&signed_message)?;
        Ok(encoded.into())
    }

    pub fn verify_and_decode(bytes: &[u8]) -> anyhow::Result<(VerifyingKey, AddressInfo)> {
        let signed_message: Self = serde_json::from_slice(bytes)?;
        let key: VerifyingKey = signed_message.from;

        key.verify(&signed_message.data, &signed_message.signature)?;

        let address_info: AddressInfo = serde_json::from_slice(&signed_message.data)?;
        Ok((signed_message.from, address_info))
    }
}
