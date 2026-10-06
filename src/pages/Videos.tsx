import { useEffect, useState } from "react";
import "../styles/Videos.css";
import { invoke } from "@tauri-apps/api/core";

type ErrorKind = {
	kind: "databaseErr" | "irohErr" | "inputErr";
	message: string;
};

interface VideoInfo {
	tag: string;
	videoName: string;
}

type Videos = Record<string, VideoInfo[]>;

const VideoPlayer = ({
	selectedVideo,
	onClose,
}: {
	selectedVideo: string;
	onClose: () => void;
}) => {
	const [namespace, resource] = selectedVideo.split("/");

	useEffect(() => {
		invoke("start_adding_topic_peers", { namespace: namespace }).catch((e) =>
			console.error(e)
		);

		return () => {
			invoke("stop_adding_topic_peers", { namespace: namespace }).catch((e) =>
				console.error(e)
			);
		};
	}, [selectedVideo]);

	const playlist = `http://127.0.0.1:3000/video/${encodeURIComponent(
		namespace
	)}/${encodeURIComponent(resource)}/playlist.m3u8`;

	return (
		<div className="player-container">
			<div className="player-header">
				<h3>Now Playing: {resource}</h3>
				<button className="header-button" onClick={onClose}>
					✕ Close
				</button>
			</div>
			<video
				className="player-video"
				src={playlist}
				controls
				autoPlay
				playsInline
			/>
		</div>
	);
};

function VideosPage() {
	const [videos, setVideos] = useState<Videos>();
	const [error, setError] = useState<string | null>(null);
	const [selectedVideo, setSelectedVideo] = useState<string | null>(null);
	const [myEndpoint, setMyEndpoint] = useState<string>("");
	const [copied, setCopied] = useState(false);

	const loadVideos = () => {
		invoke<Videos>("request_authorized_videos")
			.then((vids) => {
				console.log("request_authorized_videos returned:", vids);
				setVideos(vids);
			})
			.catch((e: ErrorKind) => setError(e.message));
	};

	useEffect(() => {
		loadVideos();
		invoke<string>("get_my_endpoint")
			.then((ep) => setMyEndpoint(ep))
			.catch(() => {});
	}, []);

	const copyEndpoint = () => {
		if (myEndpoint) {
			navigator.clipboard.writeText(myEndpoint);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		}
	};

	const renderList = () => {
		if (videos === undefined) return <div>Loading videos...</div>;

		const videoEntries = Object.entries(videos);

		if (videoEntries.length === 0) {
			return (
				<div className="empty-videos">
					<h3>No authorized videos found</h3>
					<p>To watch videos, a server must add your viewer endpoint to their access list.</p>
					{myEndpoint && (
						<div className="viewer-endpoint-card">
							<p>Your Viewer Endpoint ID:</p>
							<div className="endpoint-display">
								<span className="endpoint-code">{myEndpoint}</span>
								<button className="header-button" onClick={copyEndpoint}>
									{copied ? "Copied!" : "Copy"}
								</button>
							</div>
						</div>
					)}
				</div>
			);
		}

		return (
			<div>
				{videoEntries.map(([namespace, filenames]) => (
					<div key={namespace} className="store-group">
						<div className="store-header-title">
							<h2>Store</h2>
							<span className="store-hash">{namespace}</span>
						</div>
						<div className="video-list">
							{filenames.length === 0 ? (
								<p style={{ color: "#8b8899", fontSize: "0.85em", padding: "8px 0" }}>
									No authorized videos found in this store for your endpoint.
								</p>
							) : (
								filenames.map((video) => (
									<div
										key={video.tag}
										className={`video-item ${
											selectedVideo === video.tag ? "active" : ""
										}`}
										onClick={() => setSelectedVideo(video.tag)}
									>
										<div className="video-info">
											<span className="video-title">{video.videoName}</span>
											<span className="video-tag">{video.tag}</span>
										</div>
										<span className="play-badge">▶ Play</span>
									</div>
								))
							)}
						</div>
					</div>
				))}
			</div>
		);
	};

	return (
		<div className="videos-container">
			<div className="videos-header">
				<h1>Videos</h1>
				<button className="header-button" onClick={loadVideos}>
					Refresh
				</button>
			</div>

			{selectedVideo && (
				<VideoPlayer
					selectedVideo={selectedVideo}
					onClose={() => setSelectedVideo(null)}
				/>
			)}

			{error ? (
				<p style={{ color: "red", margin: "0 0 1em 0" }}>{error}</p>
			) : (
				renderList()
			)}
		</div>
	);
}

export default VideosPage;
