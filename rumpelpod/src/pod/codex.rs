// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Codex App Server lifecycle and WebSocket proxy.
//!
//! The pod server exposes a `/codex` WebSocket endpoint. On the first
//! connection, it spawns `codex app-server --listen ws://127.0.0.1:4500`
//! as a background process. Subsequent connections reuse the same
//! app-server, which persists thread state across client reconnections.
//! All WebSocket frames are forwarded bidirectionally between the
//! connecting client and the app-server.
//!
//! A separate monitoring connection tracks thread status independently
//! of TUI client connections so that `rumpel list` always reflects the
//! current codex state while the app-server is running.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite;

const CODEX_APP_SERVER_ADDR: &str = "127.0.0.1:4500";
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap how much app-server stderr we keep for diagnostics so a chatty
/// process cannot balloon memory while we wait.
const STDERR_BUF_CAP: usize = 16 * 1024;

/// Running codex app-server plus its captured stderr.
pub struct AppServerHandle {
    child: Child,
    stderr: Arc<StdMutex<String>>,
}

/// Shared handle to the codex app-server child process.
pub type CodexAppServer = Arc<Mutex<Option<AppServerHandle>>>;

pub fn new_codex_app_server() -> CodexAppServer {
    Arc::new(Mutex::new(None))
}

pub async fn codex_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<super::server::PodServerState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_codex_proxy(socket, state))
}

async fn handle_codex_proxy(mut client_ws: WebSocket, state: super::server::PodServerState) {
    let repo_path = match state.repo_path.lock().await.clone() {
        Some(repo_path) => repo_path,
        None => {
            eprintln!("codex: repo_path not set yet");
            let _ = client_ws
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011,
                    reason: "repo_path not set yet".into(),
                })))
                .await;
            return;
        }
    };

    if let Err(e) = ensure_app_server_running(&state.codex_app_server, &repo_path).await {
        eprintln!("codex: failed to start app-server: {e:#}");
        let _ = client_ws
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1011,
                reason: format!("failed to start codex app-server: {e}").into(),
            })))
            .await;
        return;
    }

    // Spawn the state monitor once.  The monitor maintains its own
    // WebSocket connection to the app-server and tracks thread status
    // changes independently of the TUI proxy below.
    if !state.codex_monitor_started.swap(true, Ordering::SeqCst) {
        tokio::spawn(codex_state_monitor(state.codex_state.clone()));
    }

    if let Err(e) = proxy_to_app_server(client_ws).await {
        eprintln!("codex: proxy error: {e:#}");
    }
}

/// Start the codex app-server if it is not already running.
///
/// Holds the app-server mutex across the health-check loop so that
/// concurrent /codex connections do not race to spawn a second
/// app-server, and so that the first arriving caller's captured
/// stderr is the one every retry sees on failure.
async fn ensure_app_server_running(app_server: &CodexAppServer, repo_path: &Path) -> Result<()> {
    let mut guard = app_server.lock().await;

    // Reuse a live handle if its /healthz already answers.
    if let Some(handle) = guard.as_mut() {
        match handle.child.try_wait() {
            Ok(None) if health_check().await => return Ok(()),
            Ok(None) => {
                return wait_for_healthy(&mut handle.child, &handle.stderr).await;
            }
            Ok(Some(_)) => {
                // Exited -- fall through to respawn.
            }
            Err(e) => {
                eprintln!("codex: try_wait error on app-server: {e}");
            }
        }
    }

    let codex_bin = find_codex_cli()?;
    let repo_path_display = repo_path.display();
    let mut child = Command::new(&codex_bin)
        .args([
            "app-server",
            "--listen",
            &format!("ws://{CODEX_APP_SERVER_ADDR}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .current_dir(repo_path)
        .spawn()
        .with_context(|| {
            format!(
                "spawning codex app-server from {} in {repo_path_display}",
                codex_bin.display()
            )
        })?;

    // Drain stderr into a shared buffer (and echo to our own stderr
    // so container logs still show it in real time).  The buffer is
    // what wait_for_healthy reaches for when the process dies or
    // stays unhealthy, so that the error bubbling back to the client
    // explains *why*, not just "did not become healthy".
    let stderr_buf = Arc::new(StdMutex::new(String::new()));
    if let Some(pipe) = child.stderr.take() {
        let buf = Arc::clone(&stderr_buf);
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(pipe);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        eprint!("codex app-server: {line}");
                        let mut buf_guard = buf.lock().unwrap();
                        buf_guard.push_str(&line);
                        if buf_guard.len() > STDERR_BUF_CAP {
                            let excess = buf_guard.len() - STDERR_BUF_CAP;
                            buf_guard.drain(..excess);
                        }
                    }
                }
            }
        });
    }

    *guard = Some(AppServerHandle {
        child,
        stderr: Arc::clone(&stderr_buf),
    });
    let handle = guard.as_mut().unwrap();
    wait_for_healthy(&mut handle.child, &handle.stderr).await
}

/// Poll the app-server's health endpoint until it responds or the
/// wall-clock deadline passes.  Also bails out early if the child has
/// already exited, since polling a dead process just wastes time.
async fn wait_for_healthy(child: &mut Child, stderr: &Arc<StdMutex<String>>) -> Result<()> {
    let url = format!("http://{CODEX_APP_SERVER_ADDR}/healthz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .context("building HTTP client")?;

    let deadline = Instant::now() + HEALTH_CHECK_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let captured = stderr.lock().unwrap().clone();
            return Err(anyhow::anyhow!(
                "codex app-server exited with {status} before becoming healthy\nstderr:\n{captured}"
            ));
        }

        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            let captured = stderr.lock().unwrap().clone();
            let secs = HEALTH_CHECK_TIMEOUT.as_secs();
            return Err(anyhow::anyhow!(
                "codex app-server did not become healthy within {secs}s\nstderr:\n{captured}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
// State monitor -- dedicated connection for tracking thread status
// ---------------------------------------------------------------------------

/// Long-running task that maintains a WebSocket connection to the codex
/// app-server and updates the shared state channel from
/// `thread/status/changed` notifications.
async fn codex_state_monitor(tx: tokio::sync::watch::Sender<Option<super::types::CodexState>>) {
    loop {
        if let Err(e) = run_codex_monitor(&tx).await {
            eprintln!("codex state monitor: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Single monitoring session: connect, handshake, and read notifications
/// until the connection drops.
async fn run_codex_monitor(
    tx: &tokio::sync::watch::Sender<Option<super::types::CodexState>>,
) -> Result<()> {
    let ws_url = format!("ws://{CODEX_APP_SERVER_ADDR}");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("connecting to codex app-server")?;

    // -- Initialize handshake --
    // Opt out of high-volume notifications we do not need for state
    // tracking.  thread/status/changed is NOT in this list so it will
    // be delivered.
    let init_req = serde_json::json!({
        "id": "rumpelpod-init",
        "method": "initialize",
        "params": {
            "clientInfo": {
                "name": "rumpelpod-monitor",
                "version": "0.1.0"
            },
            "capabilities": {
                "optOutNotificationMethods": [
                    "item/agentMessage/delta",
                    "item/started",
                    "item/completed",
                    "turn/started",
                    "turn/completed"
                ]
            }
        }
    });
    ws.send(tungstenite::Message::Text(init_req.to_string().into()))
        .await
        .context("sending initialize")?;

    // The server may send notifications before the initialize response.
    // Keep reading until we see our response.
    loop {
        let msg = ws
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed during handshake"))?
            .context("reading handshake message")?;
        if let tungstenite::Message::Text(ref text) = msg {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text.as_ref()) {
                // Process any notifications that arrive before the response.
                extract_codex_state(&obj, tx);
                if obj.get("id").and_then(|v| v.as_str()) == Some("rumpelpod-init") {
                    break;
                }
            }
        }
    }

    ws.send(tungstenite::Message::Text(
        r#"{"method":"initialized"}"#.into(),
    ))
    .await
    .context("sending initialized")?;

    // -- Read notifications until disconnect --
    while let Some(msg) = ws.next().await {
        let msg = msg.context("reading notification")?;
        if let tungstenite::Message::Text(ref text) = msg {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text.as_ref()) {
                extract_codex_state(&obj, tx);
            }
        }
    }

    Ok(())
}

/// Update codex state from a parsed JSON message if it is a
/// `thread/status/changed` notification.
///
/// The status field is a tagged enum:
///   `{"type": "active", "activeFlags": ["waitingOnUserInput"]}`
///   `{"type": "idle"}`
///   `{"type": "systemError"}`
fn extract_codex_state(
    msg: &serde_json::Value,
    tx: &tokio::sync::watch::Sender<Option<super::types::CodexState>>,
) {
    use super::types::CodexState;

    if msg.get("method").and_then(|m| m.as_str()) != Some("thread/status/changed") {
        return;
    }
    let Some(params) = msg.get("params") else {
        return;
    };
    let Some(status) = params.get("status") else {
        return;
    };
    let Some(status_type) = status.get("type").and_then(|t| t.as_str()) else {
        return;
    };

    let state = match status_type {
        "active" => {
            // waitingOnUserInput means the agent needs text from the
            // user, which looks like idle from the outside.
            let waiting = status
                .get("activeFlags")
                .and_then(|f| f.as_array())
                .is_some_and(|flags| {
                    flags
                        .iter()
                        .any(|v| v.as_str() == Some("waitingOnUserInput"))
                });
            if waiting {
                CodexState::Idle
            } else {
                CodexState::Processing
            }
        }
        "idle" => CodexState::Idle,
        "systemError" => CodexState::Error,
        // notLoaded and unknown values -- not actionable.
        _ => return,
    };

    tx.send_replace(Some(state));
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
