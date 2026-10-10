use std::io::SeekFrom;

use iroh::{Endpoint, EndpointId};
use rs_merkle::{algorithms::Sha256, MerkleProof};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

use crate::{
    protocol::Request,
    store::{MerkleVerification, VideoInfo},
    Status, ALPN, DISCOVERY_ALPN,
};

pub struct Viewer {
    endpoint: Endpoint,
}

impl Viewer {
    /// Check with a server, the videos a peer has access to.
    pub async fn request_authorized_videos(
        &self,
        namespace: &str,
        endpoint_id: &EndpointId,
    ) -> anyhow::Result<Option<Vec<VideoInfo>>> {
        let endpoint = &self.endpoint;

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

    /// Retrieve a file from a server, and verifies it hasn't been tampered with.
    pub async fn retreive_remote(
        &self,
        endpoint_id: EndpointId,
        request: &Request,
    ) -> anyhow::Result<Option<File>> {
        let mut file_writer = tokio::fs::File::from_std(tempfile::tempfile()?);

        let endpoint = &self.endpoint;

        let conn = endpoint.connect(endpoint_id, ALPN).await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        let request_bytes = serde_json::to_vec(request)?;
        let request_len = request_bytes.len() as u32;

        send.write_u32(request_len).await?;
        send.write_all(&request_bytes).await?;

        let status = recv.read_u8().await?;

        if status != (Status::Allowed as u8) {
            eprintln!(
                "Failed to retrieve file: {:?}",
                Status::try_from(status).unwrap_or(Status::UnknownError)
            );

            return Ok(None);
        }

        let proof_len = recv.read_u32().await?;
        let mut proof_buf = vec![0u8; proof_len as usize];
        recv.read_exact(&mut proof_buf).await?;

        let proof: MerkleVerification = serde_json::from_slice(&proof_buf)?;
        let merkle_proof = MerkleProof::<Sha256>::from_bytes(&proof.merkle_proof)?;

        let merkle_root: [u8; 32] = hex::decode(&request.resource)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Merkle root length"))?;

        // this is being loaded all into memory
        let file_bytes = recv.read_to_end(usize::MAX).await?;
        file_writer.write_all(&file_bytes).await?;
        file_writer.seek(SeekFrom::Start(0)).await?;

        let hash = sha256::digest(&file_bytes);
        let hash_bytes: [u8; 32] = hex::decode(&hash)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid hash length"))?;

        if !merkle_proof.verify(merkle_root, &[proof.index], &[hash_bytes], proof.count) {
            return Ok(None);
        }

        conn.close(0u32.into(), b"Successfully retrieved file.");

        Ok(Some(file_writer))
    }
}
