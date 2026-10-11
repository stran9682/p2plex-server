use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use iroh::EndpointId;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::{iroh_runtime::IrohRuntime, store::VideoInfo};

pub fn generate_random_secret_key() -> iroh::SecretKey {
    let mut rng = rand::rng();
    let signing_key = SigningKey::generate(&mut rng);
    let bytes = signing_key.to_bytes();
    iroh::SecretKey::from(bytes)
}

pub fn generate_random_endpoint() -> EndpointId {
    generate_random_secret_key().public()
}

/// Quickly uploads a synthetic HLS video without ffmpeg invocation (~1ms),
/// computing real SHA-256 Merkle tree leaves, root, and cryptographic ACL signatures.
pub async fn upload_synthetic_video(
    runtime: &IrohRuntime,
    namespace: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let temp_dir = TempDir::new()?;
    let playlist_path = temp_dir.path().join("playlist.m3u8");
    let chunk0_path = temp_dir.path().join("chunk0.ts");
    let chunk1_path = temp_dir.path().join("chunk1.ts");

    let mut playlist_file = File::create(&playlist_path).await?;
    playlist_file
        .write_all(
            b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n#EXTINF:10.0,\nchunk0.ts\n#EXTINF:10.0,\nchunk1.ts\n#EXT-X-ENDLIST\n",
        )
        .await?;
    playlist_file.flush().await?;

    let mut chunk0 = File::create(&chunk0_path).await?;
    chunk0.write_all(b"MOCK_VIDEO_SEGMENT_0000").await?;
    chunk0.flush().await?;

    let mut chunk1 = File::create(&chunk1_path).await?;
    chunk1.write_all(b"MOCK_VIDEO_SEGMENT_0001").await?;
    chunk1.flush().await?;

    let ns = runtime
        .access_control()
        .upload_new(
            &temp_dir.path().to_string_lossy(),
            "synthetic_video.mp4",
            namespace,
        )
        .await?;

    let local_videos = runtime.get_local_videos().await?;
    let videos = local_videos.get(&ns).expect("Namespace videos found");
    let video_info: &VideoInfo = &videos[0];
    let resource = video_info
        .tag
        .split('/')
        .nth(1)
        .expect("Tag has namespace/resource format")
        .to_string();

    Ok((ns, resource))
}

/// Ingests a real MP4 video with full ffmpeg sidecar transcoding
pub async fn upload_real_video(
    runtime: &IrohRuntime,
    mp4_name: &str,
    namespace: Option<String>,
) -> anyhow::Result<(String, String)> {
    let raw_path = PathBuf::from(mp4_name);
    let mp4_path = if raw_path.exists() {
        raw_path
    } else {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let p = manifest_dir.join(mp4_name);
        if p.exists() {
            p
        } else {
            let parent_dir = manifest_dir.parent().unwrap_or(&manifest_dir);
            let p2 = parent_dir.join(mp4_name);
            if p2.exists() {
                p2
            } else {
                anyhow::bail!("Video file not found at: '{}'", mp4_name);
            }
        }
    };

    println!("[*] Transcoding and ingesting video from: {:?}", mp4_path);
    let ns = runtime.add_dir(mp4_path, namespace).await?;
    let local_videos = runtime.get_local_videos().await?;
    let videos = local_videos
        .get(&ns)
        .ok_or_else(|| anyhow::anyhow!("Namespace videos not found for {ns}"))?;
    let video_info: &VideoInfo = &videos[0];
    let resource = video_info
        .tag
        .split('/')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Tag does not have namespace/resource format"))?
        .to_string();

    Ok((ns, resource))
}

/// Helper that either ingests a real video file (if provided) or falls back to synthetic video
pub async fn prepare_benchmark_video(
    runtime: &IrohRuntime,
    video_path: Option<&str>,
    namespace: Option<&str>,
) -> anyhow::Result<(String, String)> {
    if let Some(path) = video_path {
        upload_real_video(runtime, path, namespace.map(|s| s.to_string())).await
    } else {
        upload_synthetic_video(runtime, namespace).await
    }
}

