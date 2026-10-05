use std::{
    collections::HashMap,
    fs::{self, DirEntry},
};

use anyhow::{bail, Context};
use iroh::{endpoint::SendStream, EndpointId};
use iroh_blobs::HashAndFormat;
use rs_merkle::{algorithms::Sha256, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};
use tempfile::{tempfile, TempDir};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom},
};
use tokio_util::io::ReaderStream;

use crate::{
    iroh::iroh_mem_instance::IrohMemInstance, protocol::access_control::Request, Status, VideoInfo,
    ALPN,
};

#[derive(Debug, Clone)]
pub struct StorageManager {
    iroh_instance: IrohMemInstance,
}

impl StorageManager {
    pub fn new(iroh_instance: IrohMemInstance) -> Self {
        Self { iroh_instance }
    }

    #[allow(dead_code)]
    pub async fn has_local_file(&self, request: &Request) -> bool {
        let tag = format!(
            "{}/{}/{}",
            request.namespace, request.resource, request.filename
        );
        self.iroh_instance
            .blobs()
            .tags()
            .get(tag)
            .await
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    pub async fn has_video(&self, namespace: &str, resource: &str) -> bool {
        let tag = format!("{namespace}/{resource}");
        self.iroh_instance
            .blobs()
            .tags()
            .get(tag)
            .await
            .map(|opt| opt.is_some())
            .unwrap_or(false)
    }

    pub async fn retrieve_local(&self, request: &Request) -> anyhow::Result<File> {
        let mut file_writer = tokio::fs::File::from_std(tempfile()?);

        let tag = format!(
            "{}/{}/{}",
            request.namespace, request.resource, request.filename
        );

        let tag_info = self
            .iroh_instance
            .blobs()
            .tags()
            .get(tag)
            .await?
            .context("Tag not found locally")?;
        let mut reader = self.iroh_instance.blobs().reader(tag_info.hash);
        tokio::io::copy(&mut reader, &mut file_writer).await?;
        file_writer.seek(SeekFrom::Start(0)).await?;

        Ok(file_writer)
    }

    pub async fn retreive_remote(
        &self,
        endpoint_id: EndpointId,
        request: &Request,
    ) -> anyhow::Result<Option<File>> {
        let mut file_writer = tokio::fs::File::from_std(tempfile()?);

        let endpoint = self.iroh_instance.endpoint();

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

    pub async fn send(
        &self,
        namespace: &str,
        resource: &str,
        filename: &str,
        send: &mut SendStream,
    ) -> anyhow::Result<bool> {
        let mut tag = format!("{namespace}/{resource}");

        let Some(metadata_tag) = self.iroh_instance.blobs().tags().get(&tag).await? else {
            eprintln!("metadata tag not found");
            send.write_all(&[Status::ResourceNotFound as u8]).await?;
            bail!("Metadata tag not found")
        };

        tag.push_str(&format!("/{filename}"));
        let Some(file_tag) = self.iroh_instance.blobs().tags().get(&tag).await? else {
            eprintln!("File not found");
            send.write_all(&[Status::FileNotFound as u8]).await?;
            return Ok(false);
        };

        send.write_all(&[Status::Allowed as u8]).await?;
        println!("Accepted");

        let metadata_bytes = self
            .iroh_instance
            .blobs()
            .get_bytes(metadata_tag.hash)
            .await?;
        let metadata: VideoMetadata = serde_json::from_slice(&metadata_bytes)?;

        let proof = metadata
            .generate_proof(filename)
            .context("Couldn't generate proof")?;

        let proof_bytes = serde_json::to_vec(&proof)?;

        send.write_u32(proof_bytes.len() as u32).await?;
        send.write_all(&proof_bytes).await?;

        println!("Sending file");
        let mut reader = self.iroh_instance.blobs().reader(file_tag.hash);
        tokio::io::copy(&mut reader, send).await?;

        Ok(true)
    }

    pub async fn upload_dir(
        &self,
        path: &str,
        video_name: &str,
        namespace: &str,
    ) -> anyhow::Result<String> {
        let mut entries: Vec<DirEntry> = fs::read_dir(path)?
            .map(|file| file.map_err(anyhow::Error::from))
            .collect::<anyhow::Result<_>>()?;
        entries.sort_by_key(|a| a.file_name());

        let mut hash_formats: Vec<(HashAndFormat, String, [u8; 32])> = Vec::new();
        let blobs = self.iroh_instance.blobs();

        for entry in entries {
            let file = File::open(entry.path()).await?;

            let hash = sha256::async_digest::try_async_digest(entry.path()).await?;
            let hash_bytes: [u8; 32] = hex::decode(&hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid hash length"))?;

            let stream = ReaderStream::new(file);

            let res = blobs.add_stream(stream).await.temp_tag().await?;

            hash_formats.push((
                res.hash_and_format(),
                entry.file_name().to_string_lossy().into_owned(),
                hash_bytes,
            ));
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(
            &hash_formats.iter().map(|x| x.2).collect::<Vec<_>>(),
        );
        let merkle_root = merkle_tree
            .root_hex()
            .context("Failed to retreive root hash")?;

        for (hash_format, filename, _) in hash_formats.iter() {
            self.set_tag(namespace, Some(&merkle_root), Some(filename), *hash_format)
                .await?;
        }

        let metadata = VideoMetadata::new(
            hash_formats.into_iter().map(|h| (h.1, h.2)).collect(),
            video_name,
        );

        let leaves_hash = blobs
            .add_slice(&serde_json::to_vec(&metadata)?)
            .temp_tag()
            .await?
            .hash_and_format();

        self.set_tag(namespace, Some(&merkle_root), None, leaves_hash)
            .await?;

        Ok(merkle_root)
    }

    async fn set_tag(
        &self,
        namespace: &str,
        resource: Option<&str>,
        filename: Option<&str>,
        value: impl Into<HashAndFormat>,
    ) -> anyhow::Result<()> {
        let tags_api = self.iroh_instance.blobs().tags();

        let mut tag = namespace.to_string();

        if let Some(resource) = resource {
            tag.push_str(&format!("/{resource}"));
        }

        if let Some(filename) = filename {
            tag.push_str(&format!("/{filename}"));
        }

        if let Err(e) = tags_api.set(tag, value).await {
            match tags_api.delete_prefix(namespace).await {
                Ok(num_removed) => {
                    bail!("Failed to set tag, removed {num_removed} in clean up. err: {e}")
                }
                Err(delete_err) => {
                    bail!("Failed to clean up tags: {delete_err} after failing to set tag: {e}")
                }
            }
        }

        Ok(())
    }

    pub async fn get_filenames(&self, tags: &Vec<String>) -> anyhow::Result<Vec<VideoInfo>> {
        let mut files: Vec<VideoInfo> = Vec::new();
        for tag in tags {
            let Some(entry) = self.iroh_instance.blobs().tags().get(tag).await? else {
                continue;
            };

            let Ok(bytes) = self.iroh_instance.blobs().get_bytes(entry.hash).await else {
                continue;
            };

            if let Ok(video_metadata) = serde_json::from_slice::<VideoMetadata>(&bytes) {
                files.push(VideoInfo {
                    tag: tag.clone(),
                    video_name: video_metadata.video_name,
                });
            }
        }

        Ok(files)
    }

    pub async fn replicate(
        &self,
        namespace: &str,
        resource: &str,
        video_name: &str,
        endpoint_id: EndpointId,
    ) -> anyhow::Result<bool> {
        if self.has_video(namespace, resource).await {
            println!("Video {resource} already exists locally in {namespace}, skipping download.");
            return Ok(true);
        }

        println!("replicating video {resource} from {endpoint_id}!");

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

            println!("Replicating: {}", filename);
            let mut output = File::create(temp_dir.path().join(filename)).await?;
            tokio::io::copy(&mut file, &mut output).await?;
        }

        self.upload_dir(&temp_dir.path().to_string_lossy(), video_name, namespace)
            .await?;

        Ok(true)
    }
}

#[derive(Serialize, Deserialize)]
struct VideoMetadata {
    clip_hashes: HashMap<String, (usize, [u8; 32])>,
    video_name: String,
}

impl VideoMetadata {
    pub fn new(leaves: Vec<(String, [u8; 32])>, video_name: &str) -> Self {
        let mut clip_hashes: HashMap<String, (usize, [u8; 32])> = HashMap::new();

        for (index, (filename, leaf)) in leaves.into_iter().enumerate() {
            clip_hashes.insert(filename, (index, leaf));
        }

        Self {
            clip_hashes,
            video_name: video_name.to_string(),
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

#[derive(Serialize, Deserialize)]
pub struct MerkleVerification {
    pub merkle_proof: Vec<u8>,
    pub index: usize,
    pub count: usize,
}
