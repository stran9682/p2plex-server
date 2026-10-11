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
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mp4_path = manifest_dir.join(mp4_name);
    assert!(
        mp4_path.exists(),
        "Video file not found at {:?}",
        mp4_path
    );

    let ns = runtime.add_dir(mp4_path, namespace).await?;
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
