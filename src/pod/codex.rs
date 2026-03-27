//! Codex App Server lifecycle and WebSocket proxy.
//!
//! The pod server exposes a `/codex` WebSocket endpoint. On the first
//! connection, it spawns `codex app-server --listen ws://127.0.0.1:4500`
//! as a background process. Subsequent connections reuse the same
//! app-server, which persists thread state across client reconnections.
//! All WebSocket frames are forwarded bidirectionally between the
//! connecting client and the app-server.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite;

const CODEX_APP_SERVER_ADDR: &str = "127.0.0.1:4500";

/// Shared handle to the codex app-server child process.
pub type CodexAppServer = Arc<Mutex<Option<Child>>>;

pub fn new_codex_app_server() -> CodexAppServer {
    Arc::new(Mutex::new(None))
}

pub async fn codex_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<super::server::PodServerState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_codex_proxy(socket, state.codex_app_server))
}

async fn handle_codex_proxy(mut client_ws: WebSocket, app_server: CodexAppServer) {
    if let Err(e) = ensure_app_server_running(&app_server).await {
        eprintln!("codex: failed to start app-server: {e:#}");
        let _ = client_ws
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1011,
                reason: format!("failed to start codex app-server: {e}").into(),
            })))
            .await;
        return;
    }

    if let Err(e) = proxy_to_app_server(client_ws).await {
        eprintln!("codex: proxy error: {e:#}");
    }
}

/// Start the codex app-server if it is not already running.
async fn ensure_app_server_running(app_server: &CodexAppServer) -> Result<()> {
    let mut guard = app_server.lock().await;

    // Check if the existing child is still alive.
    if let Some(ref mut child) = *guard {
        match child.try_wait() {
            Ok(None) => {
                // Still running -- check if it is actually accepting connections.
                if health_check().await {
                    return Ok(());
                }
                // Process is alive but not healthy yet; fall through to wait.
                return wait_for_healthy().await;
            }
            Ok(Some(_status)) => {
                // Exited -- will restart below.
            }
            Err(e) => {
                eprintln!("codex: failed to poll app-server child: {e}");
            }
        }
    }

    let codex_bin = find_codex_cli()?;
    let child = Command::new(&codex_bin)
        .args([
            "app-server",
            "--listen",
            &format!("ws://{CODEX_APP_SERVER_ADDR}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning codex app-server from {}", codex_bin.display()))?;

    *guard = Some(child);
    // Drop the lock before the potentially slow health-check loop.
    drop(guard);

    wait_for_healthy().await
}

/// Poll the app-server's health endpoint until it responds.
async fn wait_for_healthy() -> Result<()> {
    let url = format!("http://{CODEX_APP_SERVER_ADDR}/healthz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .context("building HTTP client")?;

    for _ in 0..300 {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }

    Err(anyhow::anyhow!(
        "codex app-server did not become healthy within 30 seconds"
    ))
}

/// Quick health check without retries.
async fn health_check() -> bool {
    let url = format!("http://{CODEX_APP_SERVER_ADDR}/healthz");
    reqwest::get(&url)
        .await
        .is_ok_and(|r| r.status().is_success())
}

/// Connect to the app-server and bidirectionally forward WebSocket frames.
async fn proxy_to_app_server(client_ws: WebSocket) -> Result<()> {
    let ws_url = format!("ws://{CODEX_APP_SERVER_ADDR}");
    let (server_ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("connecting to codex app-server WebSocket")?;

    let (mut server_write, mut server_read) = server_ws.split();
    let (mut client_write, mut client_read) = client_ws.split();

    loop {
        tokio::select! {
            msg = client_read.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let tung_msg = axum_to_tungstenite(msg);
                        if server_write.send(tung_msg).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            msg = server_read.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        let axum_msg = tungstenite_to_axum(msg);
                        if client_write.send(axum_msg).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Message conversion between axum and tungstenite WebSocket types
// ---------------------------------------------------------------------------

fn axum_to_tungstenite(msg: Message) -> tungstenite::Message {
    match msg {
        Message::Text(t) => tungstenite::Message::Text(t.to_string().into()),
        Message::Binary(b) => tungstenite::Message::Binary(b.to_vec().into()),
        Message::Ping(p) => tungstenite::Message::Ping(p.to_vec().into()),
        Message::Pong(p) => tungstenite::Message::Pong(p.to_vec().into()),
        Message::Close(Some(cf)) => {
            tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::from(cf.code),
                reason: cf.reason.to_string().into(),
            }))
        }
        Message::Close(None) => tungstenite::Message::Close(None),
    }
}

fn tungstenite_to_axum(msg: tungstenite::Message) -> Message {
    match msg {
        tungstenite::Message::Text(t) => Message::Text(t.to_string().into()),
        tungstenite::Message::Binary(b) => Message::Binary(b.to_vec().into()),
        tungstenite::Message::Ping(p) => Message::Ping(p.to_vec().into()),
        tungstenite::Message::Pong(p) => Message::Pong(p.to_vec().into()),
        tungstenite::Message::Close(Some(cf)) => {
            Message::Close(Some(axum::extract::ws::CloseFrame {
                code: cf.code.into(),
                reason: cf.reason.to_string().into(),
            }))
        }
        tungstenite::Message::Close(None) => Message::Close(None),
        tungstenite::Message::Frame(_) => Message::Binary(Vec::new().into()),
    }
}

// ---------------------------------------------------------------------------
// Codex CLI resolution
// ---------------------------------------------------------------------------

/// Return the path to the codex binary inside the container.
fn find_codex_cli() -> Result<PathBuf> {
    let bin_path = Path::new(crate::daemon::CODEX_CONTAINER_BIN);
    if bin_path.exists() {
        return Ok(bin_path.to_path_buf());
    }

    if let Some(found) = crate::which("codex") {
        return Ok(found);
    }

    Err(anyhow::anyhow!(
        "Codex CLI not found at {} or in PATH",
        crate::daemon::CODEX_CONTAINER_BIN
    ))
}
