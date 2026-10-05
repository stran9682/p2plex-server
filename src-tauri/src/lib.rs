use std::sync::Arc;

use axum::{routing::get, Router};
use sea_orm::{Database, DbErr};
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tower_http::cors::{Any, CorsLayer};

use crate::iroh_runtime::{download_handler, IrohRuntime};

mod access_list;
mod discovery;
mod entities;
mod ipc;
mod iroh;
mod iroh_runtime;
mod protocol;
mod store;

pub const ALPN: &[u8] = b"gate";
pub const DISCOVERY_ALPN: &[u8] = b"discovery";

#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Denied,
    Allowed,
    FileNotFound,
    ResourceNotFound,
    UnknownError,
}

impl TryFrom<u8> for Status {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Status::Denied),
            1 => Ok(Status::Allowed),
            2 => Ok(Status::FileNotFound),
            3 => Ok(Status::ResourceNotFound),
            _ => Ok(Status::UnknownError),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    DatabaseErr(#[from] DbErr),

    #[error("Data has invalid format, {0}")]
    InputErr(String),

    #[error("Iroh had an error, {0}")]
    IrohErr(String),

    #[error(transparent)]
    IOErr(#[from] std::io::Error),
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "message")]
#[serde(rename_all = "camelCase")]
enum ErrorKind {
    DatabaseErr(String),
    IrohErr(String),
    InputErr(String),
    IOErr(String),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoInfo {
    pub tag: String,
    pub video_name: String,
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let error_message = self.to_string();
        let error_kind = match self {
            Self::DatabaseErr(_) => ErrorKind::DatabaseErr(error_message),
            Self::IrohErr(_) => ErrorKind::IrohErr(error_message),
            Self::InputErr(_) => ErrorKind::InputErr(error_message),
            Self::IOErr(_) => ErrorKind::IOErr(error_message),
        };
        error_kind.serialize(serializer)
    }
}

async fn setup(app_handle: tauri::AppHandle) -> anyhow::Result<Arc<IrohRuntime>> {
    let db = Database::connect("sqlite::memory:").await?;
    db.get_schema_registry(module_path!().split("::").next().unwrap())
        .sync(&db)
        .await?;
    // let path = app_handle.path().app_data_dir()?;
    // let db = Database::connect(format!(
    //     "sqlite://{}db.sqlite?mode=rwc",
    //     path.to_string_lossy()
    // ))
    // .await?;

    let iroh = Arc::new(IrohRuntime::new(db).await?);

    app_handle.manage(iroh.clone());

    Ok(iroh)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                ffmpeg_sidecar::download::auto_download().unwrap();

                match setup(app_handle).await {
                    Ok(iroh) => {
                        let cors = CorsLayer::new()
                            .allow_origin(Any)
                            .allow_methods(Any)
                            .allow_headers(Any);

                        let app = Router::new()
                            .route(
                                "/video/{namespace}/{resource}/{filename}",
                                get(download_handler),
                            )
                            .layer(cors)
                            .with_state(Arc::clone(&iroh));

                        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
                            .await
                            .unwrap();
                        println!("Successfully setup");

                        axum::serve(listener, app).await.unwrap();
                    }
                    Err(e) => {
                        eprintln!("error occured {}", e);
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::import_ticket,
            ipc::add_remote_store,
            ipc::request_authorized_videos,
            ipc::start_adding_topic_peers,
            ipc::stop_adding_topic_peers,
            ipc::add_dir,
            ipc::add_viewer,
            ipc::remove_viewer,
            ipc::get_my_endpoint,
            ipc::generate_ticket,
            ipc::get_viewers,
            ipc::get_servers,
            ipc::get_local_videos,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
