use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{iroh_runtime::IrohRuntime, Error, VideoInfo};

#[tauri::command]
pub async fn import_ticket(
    ticket: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<(), Error> {
    let iroh_runtime = state.inner();

    iroh_runtime.import_ticket(ticket).await?;

    Ok(())
}

#[tauri::command]
pub async fn add_dir(
    filepath: PathBuf,
    namespace: Option<String>,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<(), Error> {
    let iroh_runtime = state.inner();

    iroh_runtime.add_dir(filepath, namespace).await?;

    Ok(())
}

#[tauri::command]
pub async fn add_remote_store(
    endpoint: String,
    namespace: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<(), Error> {
    let iroh_runtime = state.inner();

    iroh_runtime.add_remote_store(endpoint, namespace).await?;

    Ok(())
}

#[tauri::command]
pub async fn request_authorized_videos(
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<HashMap<String, Vec<VideoInfo>>, Error> {
    let iroh_runtime = state.inner();

    iroh_runtime.request_authorized_videos().await
}

#[tauri::command]
pub async fn start_adding_topic_peers(
    namespace: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<(), Error> {
    let iroh_runtime = state.inner();
    iroh_runtime
        .start_adding_namespace_servers(namespace)
        .await?;
    Ok(())
}

#[tauri::command]
pub async fn stop_adding_topic_peers(
    namespace: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<bool, Error> {
    let iroh_runtime = state.inner();
    iroh_runtime.stop_adding_namespace_servers(namespace).await
}

#[tauri::command]
pub async fn add_viewer(
    namespace: String,
    resource: String,
    viewer: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<bool, Error> {
    let iroh_runtime = state.inner();
    iroh_runtime.add_viewer(namespace, resource, viewer).await
}

#[tauri::command]
pub async fn remove_viewer(
    namespace: String,
    resource: String,
    viewer: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<bool, Error> {
    let iroh_runtime = state.inner();
    iroh_runtime
        .remove_viewer(namespace, resource, viewer)
        .await
}

#[tauri::command]
pub fn get_my_endpoint(state: tauri::State<'_, Arc<IrohRuntime>>) -> Result<String, Error> {
    let iroh_runtime = state.inner();
    Ok(iroh_runtime.endpoint_id().to_string())
}

#[tauri::command]
pub async fn generate_ticket(
    namespace: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<String, Error> {
    let iroh_runtime = state.inner();
    iroh_runtime.generate_ticket(&namespace).await
}

#[tauri::command]
pub async fn get_viewers(
    namespace: String,
    resource: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<Vec<String>, Error> {
    let iroh_runtime = state.inner();
    iroh_runtime.get_viewers(&namespace, &resource).await
}

#[tauri::command]
pub async fn get_servers(
    namespace: String,
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<Vec<String>, Error> {
    let iroh_runtime: &Arc<IrohRuntime> = state.inner();
    iroh_runtime.get_server_peers(&namespace).await
}

#[tauri::command]
pub async fn get_local_videos(
    state: tauri::State<'_, Arc<IrohRuntime>>,
) -> Result<HashMap<String, Vec<VideoInfo>>, Error> {
    let iroh_runtime = state.inner();
    iroh_runtime.get_local_videos().await
}
