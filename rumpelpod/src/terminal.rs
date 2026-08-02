// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal sessions shared by the CLI and editor integrations.
//!
//! The daemon exposes one Unix-socket WebSocket endpoint. Codex sessions
//! terminate in the daemon, while pod-hosted agents and shells are relayed to
//! the authenticated pod server without adding a local pseudo-terminal.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, State};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::{self, Message as TungsteniteMessage};
use url::Url;

use crate::daemon::{self, DaemonServer};
use crate::pty_attach::{PtyTransport, ReconnectConfig, SessionParams, WireParams};

pub(crate) fn prepare_editor_session(cmd: &crate::cli::EditorSessionCommand) -> Result<()> {
    let host_args = crate::cli::HostArgs {
        host: None,
        kubernetes_context: None,
        kubernetes_namespace: None,
        kubernetes_registry: None,
        container_engine: None,
    };
    let prepared = match cmd.kind {
        crate::cli::EditorTerminalKind::Claude => {
            crate::claude::prepare_terminal(&crate::cli::ClaudeCommand {
                name: cmd.name.clone(),
                action: None,
                host_args,
                create: true,
                no_dangerously_skip_permissions: false,
                dangerously_skip_permissions_hook: false,
                args: vec![],
            })?
        }
        crate::cli::EditorTerminalKind::Codex => {
            crate::codex::prepare_terminal(&crate::cli::CodexCommand {
                name: cmd.name.clone(),
                host_args,
                create: true,
                no_dangerously_bypass_approvals_and_sandbox: false,
                args: vec![],
            })?
        }
        crate::cli::EditorTerminalKind::Grok => {
            crate::grok::prepare_terminal(&crate::cli::GrokCommand {
                name: cmd.name.clone(),
                host_args,
                create: true,
                no_always_approve: false,
                args: vec![],
            })?
        }
        crate::cli::EditorTerminalKind::Pi => {
            crate::pi::prepare_terminal(&crate::cli::PiCommand {
                name: cmd.name.clone(),
                host_args,
                create: true,
                args: vec![],
            })?
        }
        crate::cli::EditorTerminalKind::Shell => {
            crate::enter::prepare_terminal(&crate::cli::EnterCommand {
                name: cmd.name.clone(),
                host_args,
                create: true,
                command: vec![],
            })?
        }
    };
    prepared.print_descriptor()
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TerminalKind {
    Claude,
    Codex,
    Grok,
    Pi,
    Shell,
}

impl TerminalKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Grok => "grok",
            Self::Pi => "pi",
            Self::Shell => "shell",
        }
    }
}

pub(crate) struct PreparedTerminal {
    pub(crate) kind: TerminalKind,
    pub(crate) pod: String,
    pub(crate) repo_path: PathBuf,
    pub(crate) params: WireParams,
    pub(crate) codex_cli_path: Option<PathBuf>,
    pub(crate) reconnect: Option<ReconnectConfig>,
}

impl PreparedTerminal {
    pub(crate) fn attach(self) -> Result<()> {
        let socket = daemon::socket_path()?;
        let path = terminal_path(
            self.kind,
            &self.repo_path,
            &self.pod,
            self.codex_cli_path.as_deref(),
        );
        let outcome = crate::pty_attach::attach(
            PtyTransport::Unix { socket },
            &path,
            "",
            self.params,
            self.reconnect,
        )?;
        match outcome {
            crate::pty_attach::AttachOutcome::Detached => {
                eprintln!("[detached from session]");
            }
            crate::pty_attach::AttachOutcome::SessionEnded => {}
        }
        Ok(())
    }

    pub(crate) fn print_descriptor(self) -> Result<()> {
        let socket_path = daemon::socket_path()?;
        let path = terminal_path(
            self.kind,
            &self.repo_path,
            &self.pod,
            self.codex_cli_path.as_deref(),
        );
        let request = match self.params {
            WireParams::Session(SessionParams {
                name,
                cmd,
                workdir,
                env,
            }) => TerminalRequest::Session {
                name,
                cmd,
                workdir,
                env,
            },
            WireParams::Attach { extra_args } => TerminalRequest::Attach { extra_args },
        };
        serde_json::to_writer(
            std::io::stdout(),
            &TerminalDescriptor {
                socket_path,
                path,
                request,
            },
        )
        .context("serializing terminal descriptor")?;
        println!();
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalDescriptor {
    socket_path: PathBuf,
    path: String,
    request: TerminalRequest,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TerminalRequest {
    Session {
        name: String,
        cmd: Vec<String>,
        workdir: Option<String>,
        env: Vec<String>,
    },
    Attach {
        extra_args: Vec<String>,
    },
}

fn terminal_path(
    kind: TerminalKind,
    repo_path: &Path,
    pod: &str,
    codex_cli_path: Option<&Path>,
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("repo_path", &repo_path.to_string_lossy());
    if let Some(codex_cli_path) = codex_cli_path {
        query.append_pair("codex_cli_path", &codex_cli_path.to_string_lossy());
    }
    if matches!(kind, TerminalKind::Codex) {
        query.append_pair("no_dangerously_bypass_approvals_and_sandbox", "false");
    }
    let kind = kind.as_str();
    let query = query.finish();
    match kind {
        "codex" => format!("/pod/codex/{pod}?{query}"),
        "claude" | "grok" | "pi" | "shell" => {
            format!("/pod/terminal/{kind}/{pod}?{query}")
        }
        _ => unreachable!("all terminal kinds have explicit routes"),
    }
}

pub(crate) fn daemon_routes(daemon: Arc<DaemonServer>) -> Router<()> {
    Router::new()
        .route("/pod/terminal/{kind}/{name}", any(terminal_ws_handler))
        .with_state(daemon)
}

#[derive(Debug, Deserialize)]
struct TerminalQuery {
    repo_path: PathBuf,
}

async fn terminal_ws_handler(
    ws: WebSocketUpgrade,
    State(daemon): State<Arc<DaemonServer>>,
    AxumPath((kind, name)): AxumPath<(String, String)>,
    Query(query): Query<TerminalQuery>,
) -> Response {
    ws.on_upgrade(move |socket| async move {
        let result = match kind.as_str() {
            "claude" | "grok" | "pi" | "shell" => {
                proxy_pod_terminal(socket, daemon, &query.repo_path, &name, &kind).await
            }
            "codex" => Err(anyhow::anyhow!(
                "codex terminals must use the daemon-owned codex route"
            )),
            _ => Err(anyhow::anyhow!("unknown terminal kind '{kind}'")),
        };
        if let Err(error) = result {
            eprintln!("terminal WebSocket failed: {error:#}");
        }
    })
}

async fn proxy_pod_terminal(
    mut client: WebSocket,
    daemon: Arc<DaemonServer>,
    repo_path: &Path,
    pod: &str,
    kind: &str,
) -> Result<()> {
    let (container_url, token) = daemon
        .connected_pod_endpoint(repo_path, pod)
        .with_context(|| format!("no live terminal endpoint for pod '{pod}'"))?;
    let request = build_pod_ws_request(&container_url, &token, &format!("/{kind}"))?;
    let (mut server, _) = tokio_tungstenite::connect_async(request)
        .await
        .with_context(|| format!("connecting to pod terminal /{kind}"))?;

    loop {
        tokio::select! {
            message = client.next() => {
                match message {
                    Some(Ok(message)) => {
                        let close = matches!(message, AxumMessage::Close(_));
                        server.send(axum_to_tungstenite(message)).await
                            .context("forwarding terminal message to pod")?;
                        if close {
                            break;
                        }
                    }
                    Some(Err(error)) => return Err(error).context("reading terminal client"),
                    None => break,
                }
            }
            message = server.next() => {
                match message {
                    Some(Ok(TungsteniteMessage::Frame(_))) => {}
                    Some(Ok(message)) => {
                        let close = matches!(message, TungsteniteMessage::Close(_));
                        client.send(tungstenite_to_axum(message)).await
                            .context("forwarding terminal message from pod")?;
                        if close {
                            break;
                        }
                    }
                    Some(Err(error)) => return Err(error).context("reading pod terminal"),
                    None => break,
                }
            }
        }
    }
    Ok(())
}

fn axum_to_tungstenite(message: AxumMessage) -> TungsteniteMessage {
    match message {
        AxumMessage::Text(text) => TungsteniteMessage::Text(text.to_string().into()),
        AxumMessage::Binary(data) => TungsteniteMessage::Binary(data),
        AxumMessage::Ping(data) => TungsteniteMessage::Ping(data),
        AxumMessage::Pong(data) => TungsteniteMessage::Pong(data),
        AxumMessage::Close(_) => TungsteniteMessage::Close(None),
    }
}

fn tungstenite_to_axum(message: TungsteniteMessage) -> AxumMessage {
    match message {
        TungsteniteMessage::Text(text) => AxumMessage::Text(text.to_string().into()),
        TungsteniteMessage::Binary(data) => AxumMessage::Binary(data),
        TungsteniteMessage::Ping(data) => AxumMessage::Ping(data),
        TungsteniteMessage::Pong(data) => AxumMessage::Pong(data),
        TungsteniteMessage::Close(_) => AxumMessage::Close(None),
        TungsteniteMessage::Frame(_) => {
            unreachable!("frame messages are filtered before conversion")
        }
    }
}

fn build_pod_ws_request(
    container_url: &str,
    token: &str,
    path: &str,
) -> Result<tungstenite::http::Request<()>> {
    let mut ws_url = Url::parse(container_url).context("parsing container URL")?;
    let scheme = match ws_url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => return Err(anyhow::anyhow!("unexpected container URL scheme: {other}")),
    };
    ws_url
        .set_scheme(scheme)
        .expect("ws/wss are always valid schemes");
    ws_url.set_path(path);

    let host = match ws_url.port() {
        Some(port) => format!("{}:{port}", ws_url.host_str().unwrap_or("localhost")),
        None => ws_url.host_str().unwrap_or("localhost").to_string(),
    };
    tungstenite::http::Request::builder()
        .uri(ws_url.as_str())
        .header("Host", host)
        .header("Authorization", format!("Bearer {token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .context("building pod terminal WebSocket request")
}
