import { useState } from "react";
import "./App.css";
import Add from "./pages/Add";
import VideosPage from "./pages/Videos";
import ServerPage from "./pages/Server";

enum Page {
	Videos = "Videos",
	Server = "Server",
	Add = "Add",
}

function App() {
	const [currentPage, setCurrentPage] = useState<Page>(Page.Videos);

	const renderContent = () => {
		switch (currentPage) {
			case Page.Videos:
				return <VideosPage />;
			case Page.Server:
				return <ServerPage />;
			case Page.Add:
				return <Add />;
		}
	};

	return (
		<main className="container">
			<div data-tauri-drag-region className="nav-menu">
				<button
					className={currentPage === Page.Videos ? "active" : ""}
					onClick={() => setCurrentPage(Page.Videos)}
					title="Videos"
				>
					<img src="play.svg" alt="Videos" />
				</button>

				<button
					className={currentPage === Page.Server ? "active" : ""}
					onClick={() => setCurrentPage(Page.Server)}
					title="Server"
				>
					<img src="server.svg" alt="Server" />
				</button>

				<button
					className={currentPage === Page.Add ? "active" : ""}
					onClick={() => setCurrentPage(Page.Add)}
					title="Add"
				>
					<img src="add.svg" alt="Add" />
				</button>
			</div>

			<div className="page">{renderContent()}</div>
		</main>
	);
}

export default App;
