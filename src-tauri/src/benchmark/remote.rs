use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use iroh::{endpoint::presets, Endpoint, EndpointId};
use serde::{Deserialize, Serialize};

use crate::{
    benchmark::node::{generate_random_endpoint, upload_synthetic_video},
    iroh_runtime::IrohRuntime,
    protocol::{viewer::Viewer, Request},
    store::PermissionLevel,
};

#[derive(Clone)]
pub struct DaemonState {
    pub name: String,
    pub runtime: Arc<IrohRuntime>,
    pub namespace: Arc<tokio::sync::RwLock<String>>,
    pub resource: Arc<tokio::sync::RwLock<String>>,
}

#[derive(Serialize)]
pub struct DaemonStatus {
    pub name: String,
    pub endpoint_id: String,
    pub namespace: String,
    pub resource: String,
    pub ticket: String,
    pub servers: Vec<String>,
}

#[derive(Deserialize)]
pub struct ViewerAuthReq {
    pub viewer: String,
    pub namespace: Option<String>,
    pub resource: Option<String>,
}

#[derive(Deserialize)]
pub struct ServerReq {
    pub server: String,
}

#[derive(Deserialize)]
pub struct TicketReq {
    pub ticket: String,
}

#[derive(Serialize)]
pub struct AuthCheckResp {
    pub authorized: bool,
    pub level: String,
}

pub async fn run_server_daemon(
    name: String,
    control_port: u16,
    ticket_opt: Option<String>,
) -> anyhow::Result<()> {
    let runtime = Arc::new(IrohRuntime::create_in_memory().await?);

    let (namespace, resource) = if let Some(ref t) = ticket_opt {
        runtime.import_ticket(t.clone()).await?;
        let parsed = crate::store::ServerTicket::parse(t)?;
        let mut res = "synthetic_video.mp4".to_string();
        if let Ok(videos) = runtime.get_local_videos().await {
            if let Some(vids) = videos.get(&parsed.namespace) {
                if let Some(first) = vids.first() {
                    if let Some(r) = first.tag.split('/').nth(1) {
                        res = r.to_string();
                    }
                }
            }
        }
        (parsed.namespace, res)
    } else {
        upload_synthetic_video(&runtime, None).await?
    };

    let state = DaemonState {
        name: name.clone(),
        runtime: runtime.clone(),
        namespace: Arc::new(tokio::sync::RwLock::new(namespace)),
        resource: Arc::new(tokio::sync::RwLock::new(resource)),
    };

    let app = Router::new()
        .route("/status", get(get_status))
        .route("/new_viewer_key", get(get_new_viewer_key))
        .route("/add_server", post(post_add_server))
        .route("/grant", post(post_grant))
        .route("/revoke", post(post_revoke))
        .route("/check_auth", post(post_check_auth))
        .route("/import_ticket", post(post_import_ticket))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], control_port));
    println!(
        "[*] Node '{}' [ep={}] HTTP control plane running on http://{}",
        name,
        runtime.endpoint_id(),
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_status(State(state): State<DaemonState>) -> impl IntoResponse {
    let ns = state.namespace.read().await.clone();
    let res = state.resource.read().await.clone();
    let ticket = state.runtime.generate_ticket(&ns).await.unwrap_or_default();
    let servers = state.runtime.get_server_peers(&ns).await.unwrap_or_default();

    Json(DaemonStatus {
        name: state.name,
        endpoint_id: state.runtime.endpoint_id().to_string(),
        namespace: ns,
        resource: res,
        ticket,
        servers,
    })
}

async fn get_new_viewer_key() -> impl IntoResponse {
    generate_random_endpoint().to_string()
}

async fn post_add_server(
    State(state): State<DaemonState>,
    Json(payload): Json<ServerReq>,
) -> impl IntoResponse {
    let ns = state.namespace.read().await.clone();
    match state.runtime.add_server(ns, payload.server).await {
        Ok(ok) => (StatusCode::OK, Json(serde_json::json!({ "success": ok }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn post_grant(
    State(state): State<DaemonState>,
    Json(payload): Json<ViewerAuthReq>,
) -> impl IntoResponse {
    let ns = payload.namespace.unwrap_or(state.namespace.read().await.clone());
    let res = payload.resource.unwrap_or(state.resource.read().await.clone());
    match state.runtime.add_viewer(ns, res, payload.viewer).await {
        Ok(ok) => (StatusCode::OK, Json(serde_json::json!({ "success": ok }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn post_revoke(
    State(state): State<DaemonState>,
    Json(payload): Json<ViewerAuthReq>,
) -> impl IntoResponse {
    let ns = payload.namespace.unwrap_or(state.namespace.read().await.clone());
    let res = payload.resource.unwrap_or(state.resource.read().await.clone());
    match state.runtime.remove_viewer(ns, res, payload.viewer).await {
        Ok(ok) => (StatusCode::OK, Json(serde_json::json!({ "success": ok }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn post_check_auth(
    State(state): State<DaemonState>,
    Json(payload): Json<ViewerAuthReq>,
) -> impl IntoResponse {
    let ns = payload.namespace.unwrap_or(state.namespace.read().await.clone());
    let mut res = payload.resource;
    if res.is_none() {
        if let Ok(videos) = state.runtime.get_local_videos().await {
            if let Some(vids) = videos.get(&ns) {
                if let Some(first) = vids.first() {
                    if let Some(r) = first.tag.split('/').nth(1) {
                        res = Some(r.to_string());
                    }
                }
            }
        }
    }
    let res_str = res.unwrap_or(state.resource.read().await.clone());

    let Ok(ep) = EndpointId::from_str(&payload.viewer) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid EndpointId" })),
        );
    };

    let level = state
        .runtime
        .access_control()
        .list_manager()
        .check_authorization(&ns, Some(&res_str), &ep)
        .await
        .unwrap_or(PermissionLevel::Unauthorized);

    let authorized = level == PermissionLevel::Viewer
        || level == PermissionLevel::Server
        || level == PermissionLevel::Writer;

    (
        StatusCode::OK,
        Json(serde_json::json!(AuthCheckResp {
            authorized,
            level: format!("{:?}", level),
        })),
    )
}

async fn post_import_ticket(
    State(state): State<DaemonState>,
    Json(payload): Json<TicketReq>,
) -> impl IntoResponse {
    match state.runtime.import_ticket(payload.ticket.clone()).await {
        Ok(_) => {
            if let Ok(parsed) = crate::store::ServerTicket::parse(&payload.ticket) {
                *state.namespace.write().await = parsed.namespace.clone();
                if let Ok(videos) = state.runtime.get_local_videos().await {
                    if let Some(vids) = videos.get(&parsed.namespace) {
                        if let Some(first) = vids.first() {
                            if let Some(r) = first.tag.split('/').nth(1) {
                                *state.resource.write().await = r.to_string();
                            }
                        }
                    }
                }
            }
            (StatusCode::OK, Json(serde_json::json!({ "success": true })))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

pub async fn run_standalone_viewer(
    server_endpoint_id: EndpointId,
    namespace: String,
    resource: String,
    requests: usize,
    concurrency: usize,
) -> anyhow::Result<()> {
    println!(
        "[*] Launching viewer load generator against server {} ({} reqs, concurrency={})",
        server_endpoint_id, requests, concurrency
    );

    let reqs_per_worker = requests / concurrency;
    let mut handles = Vec::with_capacity(concurrency);
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(requests)));

    let start_all = Instant::now();

    for _ in 0..concurrency {
        let ep = Endpoint::bind(presets::N0).await?;
        let viewer = Viewer::new(ep);
        let ns = namespace.clone();
        let res = resource.clone();
        let lat_vec = latencies.clone();

        handles.push(tokio::spawn(async move {
            let req = Request::new(ns, res, "playlist.m3u8".to_string());
            for _ in 0..reqs_per_worker {
                let start = Instant::now();
                let _ = viewer.retreive_remote(server_endpoint_id, &req).await;
                let elapsed = start.elapsed().as_secs_f64() * 1_000_000.0;
                let mut v = lat_vec.lock().await;
                v.push(elapsed);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total_time_s = start_all.elapsed().as_secs_f64();
    let samples = latencies.lock().await.clone();
    let res = crate::benchmark::stats::BenchmarkResult::compute(
        "Remote Load Generator",
        "QUIC Wire Gate Requests",
        concurrency,
        samples,
    );

    crate::benchmark::stats::print_result_row(&res);
    println!(
        "Completed {} requests in {:.2}s ({:.1} req/s)",
        requests,
        total_time_s,
        requests as f64 / total_time_s
    );

    Ok(())
}
