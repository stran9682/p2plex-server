import { useEffect, useState } from "react";
import "../styles/Server.css";
import { invoke } from "@tauri-apps/api/core";

type ErrorKind = {
	kind: "databaseErr" | "irohErr" | "inputErr";
	message: string;
};

interface VideoInfo {
	tag: string;
	videoName: string;
}

type StoresMap = Record<string, VideoInfo[]>;

function TicketPopup({
	namespace,
	setPopup,
}: {
	namespace: string;
	setPopup: () => void;
}) {
	const [ticket, setTicket] = useState<string>("");
	const [error, setError] = useState<string | null>(null);
	const [copied, setCopied] = useState<boolean>(false);

	useEffect(() => {
		invoke<string>("generate_ticket", { namespace: namespace })
			.then((t) => setTicket(t))
			.catch((err: ErrorKind) => setError(err.message));
	}, [namespace]);

	const copyTicket = () => {
		if (ticket) {
			navigator.clipboard.writeText(ticket);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		}
	};

	return (
		<div className="popup">
			<div className="popup-container">
				<h2>Server Ticket</h2>
				<p style={{ margin: "0 0 1em 0", fontSize: "0.85em", color: "#b0adb9" }}>
					Share this ticket with other servers to synchronize this store and its access control list.
				</p>

				{error && <p style={{ color: "red", margin: "0 0 1em 0" }}>{error}</p>}

				{ticket ? (
					<textarea
						className="ticket-textarea"
						readOnly
						value={ticket}
						onClick={(e) => (e.target as HTMLTextAreaElement).select()}
					/>
				) : (
					<p>Generating ticket...</p>
				)}

				<div className="popup-actions">
					<button disabled={!ticket} onClick={copyTicket}>
						{copied ? "Copied!" : "Copy"}
					</button>
					<button onClick={setPopup}>Close</button>
				</div>
			</div>
		</div>
	);
}

function AclPopup({
	namespace,
	video,
	setPopup,
}: {
	namespace: string;
	video: VideoInfo;
	setPopup: () => void;
}) {
	const [viewers, setViewers] = useState<string[]>([]);
	const [newViewer, setNewViewer] = useState<string>("");
	const [error, setError] = useState<string | null>(null);

	const resource = video.tag.split("/")[1] || "";

	const loadViewers = () => {
		invoke<string[]>("get_viewers", {
			namespace: namespace,
			resource: resource,
		})
			.then((list) => setViewers(list))
			.catch((err: ErrorKind) => setError(err.message));
	};

	useEffect(() => {
		loadViewers();
	}, [namespace, resource]);

	const handleAddViewer = () => {
		const trimmed = newViewer.trim();
		if (!trimmed) return;

		setError(null);
		invoke("add_viewer", {
			namespace: namespace,
			resource: resource,
			viewer: trimmed,
		})
			.then(() => {
				setNewViewer("");
				loadViewers();
			})
			.catch((err: ErrorKind) => setError(err.message));
	};

	const handleRemoveViewer = (viewer: string) => {
		setError(null);
		invoke("remove_viewer", {
			namespace: namespace,
			resource: resource,
			viewer: viewer,
		})
			.then(() => loadViewers())
			.catch((err: ErrorKind) => setError(err.message));
	};

	return (
		<div className="popup">
			<div className="popup-container">
				<h2>Manage Access</h2>
				<p style={{ margin: "0", fontSize: "0.9em", color: "#ffffff", fontWeight: 600 }}>
					{video.videoName}
				</p>
				<p className="server-store-hash" style={{ marginBottom: "0.8em" }}>
					{video.tag}
				</p>

				{error && <p style={{ color: "red", margin: "0 0 0.5em 0" }}>{error}</p>}

				<h3>Authorized Viewers ({viewers.length})</h3>

				<div className="acl-viewers-list">
					{viewers.length === 0 ? (
						<p style={{ fontSize: "0.85em", color: "#8b8899", margin: "0.5em 0" }}>
							No viewers added yet (only servers can view this video).
						</p>
					) : (
						viewers.map((viewer) => (
							<div key={viewer} className="acl-viewer-row">
								<span>{viewer}</span>
								<button
									className="btn-small-danger"
									onClick={() => handleRemoveViewer(viewer)}
								>
									Revoke
								</button>
							</div>
						))
					)}
				</div>

				<div className="add-viewer-row">
					<input
						type="text"
						placeholder="Viewer Endpoint ID"
						value={newViewer}
						onChange={(e) => setNewViewer(e.target.value)}
					/>
					<button disabled={newViewer.trim() === ""} onClick={handleAddViewer}>
						Add
					</button>
				</div>

				<div className="popup-actions" style={{ marginTop: "1em" }}>
					<button onClick={setPopup}>Close</button>
				</div>
			</div>
		</div>
	);
}

function ServerPage() {
	const [stores, setStores] = useState<StoresMap | null>(null);
	const [serverPeers, setServerPeers] = useState<Record<string, string[]>>({});
	const [error, setError] = useState<string | null>(null);
	const [ticketNamespace, setTicketNamespace] = useState<string | null>(null);
	const [aclTarget, setAclTarget] = useState<{
		namespace: string;
		video: VideoInfo;
	} | null>(null);
	const [myEndpoint, setMyEndpoint] = useState<string>("");
	const [copied, setCopied] = useState<boolean>(false);

	const loadStores = () => {
		invoke<StoresMap>("get_local_videos")
			.then(async (data) => {
				setStores(data);

				const peersMap: Record<string, string[]> = {};
				for (const ns of Object.keys(data)) {
					try {
						const peers = await invoke<string[]>("get_servers", { namespace: ns });
						peersMap[ns] = peers;
					} catch {
						peersMap[ns] = [];
					}
				}
				setServerPeers(peersMap);
			})
			.catch((err: ErrorKind) => setError(err.message));
	};

	useEffect(() => {
		loadStores();
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

	return (
		<div className="server-container">
			<div className="server-header">
				<h1>Server Management</h1>
				<button className="header-button" onClick={loadStores}>
					Refresh
				</button>
			</div>

			{myEndpoint && (
				<div style={{ marginBottom: "1.5em" }}>
					<span style={{ fontSize: "0.85em", color: "#a09dae" }}>Node Endpoint ID: </span>
					<span className="endpoint-code">{myEndpoint}</span>
					<button
						className="header-button"
						style={{ marginLeft: "0.5em", padding: "4px 10px" }}
						onClick={copyEndpoint}
					>
						{copied ? "Copied!" : "Copy"}
					</button>
				</div>
			)}

			{error && <p style={{ color: "red", margin: "0 0 1em 0" }}>{error}</p>}

			{ticketNamespace && (
				<TicketPopup
					namespace={ticketNamespace}
					setPopup={() => setTicketNamespace(null)}
				/>
			)}

			{aclTarget && (
				<AclPopup
					namespace={aclTarget.namespace}
					video={aclTarget.video}
					setPopup={() => setAclTarget(null)}
				/>
			)}

			{stores === null ? (
				<p>Loading stores...</p>
			) : Object.keys(stores).length === 0 ? (
				<div className="empty-videos">
					<h3>No hosted stores found</h3>
					<p>You can create a store by adding a video or importing a ticket in the Add menu.</p>
				</div>
			) : (
				Object.entries(stores).map(([namespace, videos]) => {
					const peers = serverPeers[namespace] || [];
					return (
						<div key={namespace} className="server-store-card">
							<div className="server-store-header">
								<div className="server-store-title">
									<h2>Store</h2>
									<span className="server-store-hash">{namespace}</span>
								</div>
								<div className="server-store-actions">
									<button onClick={() => setTicketNamespace(namespace)}>
										Generate Ticket
									</button>
								</div>
							</div>

							{peers.length > 0 && (
								<div className="server-peers-info">
									<span>Server Peers ({peers.length}):</span>
									<div className="server-peers-list">
										{peers.map((peer) => (
											<span key={peer} className="server-peer-chip" title={peer}>
												{peer.substring(0, 12)}...
											</span>
										))}
									</div>
								</div>
							)}

							<div className="server-videos-title">Hosted Videos ({videos.length})</div>

							{videos.length === 0 ? (
								<p style={{ color: "#8b8899", fontSize: "0.85em" }}>
									No videos uploaded to this store yet.
								</p>
							) : (
								videos.map((vid) => (
									<div key={vid.tag} className="server-video-item">
										<div className="server-video-meta">
											<span className="server-video-name">{vid.videoName}</span>
											<span className="server-video-tag">{vid.tag}</span>
										</div>
										<button
											onClick={() =>
												setAclTarget({ namespace: namespace, video: vid })
											}
										>
											Access List
										</button>
									</div>
								))
							)}
						</div>
					);
				})
			)}
		</div>
	);
}

export default ServerPage;
