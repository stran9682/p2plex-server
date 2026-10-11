use std::io::SeekFrom;

use iroh::{Endpoint, EndpointId};
use rs_merkle::{algorithms::Sha256, MerkleProof};
use tempfile::TempDir;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
};

use crate::{
    protocol::Request,
    store::{MerkleVerification, VideoInfo},
    Status, ALPN, DISCOVERY_ALPN,
};

#[derive(Debug, Clone)]
pub struct Viewer {
    endpoint: Endpoint,
}

impl Viewer {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

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
        if let Ok(resp) = serde_json::from_slice::<crate::store::DiscoveryResponse>(&bytes) {
            return Ok(Some(resp.files));
        }
        if let Ok(files) = serde_json::from_slice::<Vec<VideoInfo>>(&bytes) {
            return Ok(Some(files));
        }

        anyhow::bail!("Failed to deserialize discovery response");
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

    /// Replicates a remote namespace locally.
    /// Requests from another peer the .m3u8 file, which contains a list of all files, then downloads them.
    /// After all files have been downloaded, reconstructs the metadata at `namespace/resource`
    pub async fn replicate(
        &self,
        storage_manager: &crate::store::StorageManager,
        namespace: &str,
        resource: &str,
        video_name: &str,
        endpoint_id: EndpointId,
    ) -> anyhow::Result<bool> {
        if storage_manager.has_video(namespace, resource).await {
            println!("Video {resource} already exists locally in {namespace}, skipping download.");
            return Ok(true);
        }

        println!("Replicating video {resource} from {endpoint_id}!");

        let Some(mut file) = self
            .retreive_remote(
                endpoint_id,
                &Request::new(
                    namespace.to_string(),
                    resource.to_string(),
                    "playlist.m3u8".into(),
                ),
            )
            .await?
        else {
            return Ok(false);
        };

        let temp_dir = TempDir::new()?;

        let playlist = temp_dir.path().join("playlist.m3u8");
        let mut playlist_file = File::create(&playlist).await?;
        tokio::io::copy(&mut file, &mut playlist_file).await?;

        let mut lines = BufReader::new(File::open(playlist).await?).lines();
        while let Some(filename) = lines.next_line().await? {
            let filename = filename.trim().to_string();
            if filename.starts_with('#') || filename.is_empty() {
                continue;
            }

            let Some(mut file) = self
                .retreive_remote(
                    endpoint_id,
                    &Request::new(
                        namespace.to_string(),
                        resource.to_string(),
                        filename.clone(),
                    ),
                )
                .await?
            else {
                return Ok(false);
            };

            println!("Replicating chunk: {}", filename);
            let mut output = File::create(temp_dir.path().join(&filename)).await?;
            tokio::io::copy(&mut file, &mut output).await?;
        }

        storage_manager
            .upload_dir(&temp_dir.path().to_string_lossy(), video_name, namespace)
            .await?;

        Ok(true)
    }
}
