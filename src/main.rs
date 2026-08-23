mod config;
mod profile;
mod session;
mod ssh;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use russh::ChannelMsg;
use serde::Deserialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use config::ConnectParams;
use profile::{ConnectionProfile, ProfileStore, default_store_path};
use session::SessionManager;
use ssh::SshClient;

#[derive(Clone)]
struct AppState {
    profiles: Arc<ProfileStore>,
    sessions: SessionManager,
}

#[derive(thiserror::Error, Debug)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Internal(_) => StatusCode::BAD_GATEWAY,
        };
        (status, self.to_string()).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    let state = AppState {
        profiles: Arc::new(ProfileStore::load(default_store_path())?),
        sessions: SessionManager::new(),
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/api/profiles", get(list_profiles).post(create_profile))
        .route("/api/profiles/{id}/connect", post(connect_profile))
        .route("/ws/sessions/{id}", get(shell_ws))
        .layer(cors)
        .with_state(state);

    println!("listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn list_profiles(State(state): State<AppState>) -> Json<Vec<ConnectionProfile>> {
    Json(state.profiles.list())
}

#[derive(Deserialize)]
struct CreateProfileRequest {
    name: String,
    host: String,
    port: u16,
    username: String,
    key_path: String,
    passphrase: Option<String>,
}

async fn create_profile(
    State(state): State<AppState>,
    Json(req): Json<CreateProfileRequest>,
) -> Result<Json<ConnectionProfile>, ApiError> {
    let params = ConnectParams {
        host: req.host.clone(),
        port: req.port,
        username: req.username.clone(),
        key_path: req.key_path.clone(),
        passphrase: req.passphrase,
        trust_unknown_hosts: true,
    };

    let client = SshClient::connect(&params)
        .await
        .map_err(|e| ApiError::BadRequest(format!("connection failed: {e:#}")))?;

    let profile = ConnectionProfile {
        id: Uuid::new_v4(),
        name: req.name,
        host: req.host,
        port: req.port,
        username: req.username,
        key_path: req.key_path,
    };

    state.profiles.add(profile.clone())?;
    state.sessions.insert(profile.id, client).await;

    Ok(Json(profile))
}

#[derive(serde::Serialize)]
struct ConnectResponse {
    session_id: Uuid,
}

async fn connect_profile(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectResponse>, ApiError> {
    if state.sessions.get(id).await.is_some() {
        return Ok(Json(ConnectResponse { session_id: id }));
    }

    let profile = state
        .profiles
        .get(id)
        .ok_or_else(|| ApiError::BadRequest("unknown profile id".to_string()))?;

    let params = ConnectParams {
        host: profile.host,
        port: profile.port,
        username: profile.username,
        key_path: profile.key_path,
        passphrase: None,
        trust_unknown_hosts: true,
    };

    let client = SshClient::connect(&params)
        .await
        .map_err(|e| ApiError::BadRequest(format!("connection failed: {e:#}")))?;

    state.sessions.insert(id, client).await;

    Ok(Json(ConnectResponse { session_id: id }))
}

async fn shell_ws(
    ws: WebSocketUpgrade,
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| bridge_shell(socket, id, state))
}

/// Pumps bytes between the browser's WebSocket and the remote PTY shell
/// until either side closes.
async fn bridge_shell(socket: WebSocket, id: Uuid, state: AppState) {
    let Some(client) = state.sessions.get(id).await else {
        return;
    };

    let channel = match client.open_shell().await {
        Ok(channel) => channel,
        Err(err) => {
            eprintln!("failed to open shell for session {id}: {err:#}");
            return;
        }
    };

    let (mut read_half, write_half) = channel.split();
    let (mut ws_tx, mut ws_rx) = socket.split();

    let outbound = async {
        while let Some(msg) = read_half.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ext: 1 } => {
                    if ws_tx.send(Message::Binary(data.to_vec().into())).await.is_err() {
                        break;
                    }
                }
                ChannelMsg::Close | ChannelMsg::Eof => break,
                _ => {}
            }
        }
    };

    let inbound = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            let bytes = match msg {
                Message::Binary(data) => data.to_vec(),
                Message::Text(text) => text.as_bytes().to_vec(),
                Message::Close(_) => break,
                _ => continue,
            };
            if write_half.data_bytes(bytes).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = outbound => {}
        _ = inbound => {}
    }
}
