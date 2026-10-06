import { useState } from "react";
import "../styles/Add.css";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

enum Popup {
	Ticket,
	Local,
	Remote,
}

type ErrorKind = {
	kind: 'databaseErr' | 'irohErr' | 'inputErr';
	message: string;
};


function TicketPopup({ setPopup }: { setPopup: () => void }) {
	const [ticket, setTicket] = useState<string>("");
	const [error, setError] = useState<string | null>(null);

	const importTicket = (ticket: string) => {
		invoke("import_ticket", { ticket: ticket })
		.then(() => setPopup())
		.catch((error: ErrorKind) =>
			setError(error.message)
		);
	};

	return (
		<div className="popup">
			<div className="popup-container">
				<h2>Add Ticket</h2>
				<input
					type="text"
					value={ticket}
					onChange={(e) => setTicket(e.target.value)}
				/>

				{error && <p style={{ color: "red", margin: "0 0 1em 0" }}>{error}</p>}

				<div className="popup-actions">
					<button disabled={ticket === ""} onClick={() => importTicket(ticket)}>
						Add
					</button>
					<button onClick={() => setPopup()}>Close</button>
				</div>
			</div>
		</div>
	);
}

function RemotePopup({ setPopup }: { setPopup: () => void }) {
	const [endpoint, setEndpoint] = useState<string>("");
	const [namespace, setNamespace] = useState<string>("");
	const [error, setError] = useState<string | null>(null);

	const importRemote = (endpoint: string, namespace: string) => {
		invoke("add_remote_store", { endpoint: endpoint, namespace: namespace })
		.then(() => setPopup())
		.catch((error: ErrorKind) => setError(error.message));
	};

	return (
		<div className="popup">
			<div className="popup-container">
				<h2>Add Remote</h2>

				<h3>Endpoint</h3>
				<input
					type="text"
					value={endpoint}
					onChange={(e) => setEndpoint(e.target.value)}
				/>

				<h3>Namespace</h3>
				<input
					type="text"
					value={namespace}
					onChange={(e) => setNamespace(e.target.value)}
				/>

				{error && <p style={{ color: "red", margin: "0 0 1em 0" }}>{error}</p>}

				<div className="popup-actions">
					<button disabled = {endpoint === "" && namespace === ""} onClick={() => importRemote(endpoint, namespace)}>Add</button>
					<button onClick={() => setPopup()}>Close</button>
				</div>
			</div>
		</div>
	);
}

function LocalPopup({ setPopup }: { setPopup: () => void }) {
	const [filepath, setFilepath] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [namespace, setNamespace] = useState<string| null>(null);

	const add_dir = () => {
		invoke("add_dir", { filepath: filepath, namespace: namespace ? namespace : null })
			.then(() => setPopup())
			.catch((error: ErrorKind) => setError(error.message));
	};

	const handlePickFile = async () => {
		try {
			setError(null);

			const selected = await open({
				multiple: false,
				directory: false,
				filters: [
					{
						name: "Videos",
						extensions: ["mp4"],
					},
				],
			});

			if (selected === null) {
				console.log("User cancelled the file selection");
				return;
			}

			setFilepath(selected);
		} catch (err) {
			console.error("Failed to open file picker:", err);
			setError("Could not open file dialog. Check your permissions config.");
		}
	};

	return (
		<div className="popup">
			<div className="popup-container">
				<button className="filepick-button" onClick={handlePickFile}>Select a File</button>

				{error && <p style={{ color: "red", marginTop: "10px" }}>{error}</p>}

				{filepath && (<>
					
					<div>
						<h3>Selected Path:</h3>
							<div className="filepath"> 
							{filepath}
						</div>
					</div>

					<h3>Namespace</h3>
					
					<input
						type="text"
						placeholder="Optional"
						onChange={(e) => setNamespace(e.target.value)}
					/>
				</>)}

				<div className="popup-actions">
					<button disabled={filepath === null} onClick={() => add_dir()}>Add</button>
					<button onClick={() => setPopup()}>Close</button>
				</div>
			</div>
		</div>
	);
}

function Add() {
	const [popup, setPopup] = useState<Popup | null>(null);

	const renderPopup = () => {
		if (popup === null) {
			return;
		}

		const handleClose = () => setPopup(null);

		switch (popup) {
			case Popup.Ticket:
				return <TicketPopup setPopup={handleClose} />;
			case Popup.Local:
				return <LocalPopup setPopup={handleClose} />;
			case Popup.Remote:
				return <RemotePopup setPopup={handleClose} />;
		}
	};

	return (
		<div className="menu">
			<h1>Add</h1>

			{popup !== null && renderPopup()}

			<div className="menu-item">
				<div className="menu-label">
					<h3>Import ticket</h3>
					Sync a store with a peer
				</div>

				<button onClick={() => setPopup(Popup.Ticket)}>Add</button>
			</div>

			<div className="menu-item">
				<div className="menu-label">
					<h3>Add video from local</h3>
					Create a syncable store, or add to an existing one
				</div>

				<button onClick={() => setPopup(Popup.Local)}>Add</button>
			</div>

			<div className="menu-item">
				<h3>Add a remote</h3>

				<button onClick={() => setPopup(Popup.Remote)}>Add</button>
			</div>
		</div>
	);
}

export default Add;
