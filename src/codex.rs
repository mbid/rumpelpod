//! Host-side `rumpel codex` command and daemon-managed WebSocket proxy.
//!
//! Launches a pod, forwards codex credentials into it, asks the daemon
//! to start a WebSocket proxy, and spawns the codex TUI pointing at it.
//! The daemon keeps the proxy alive across TUI restarts so the codex
//! app-server session inside the pod survives disconnects.

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;
use url::Url;

use crate::cli::CodexCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName, StartCodexProxyRequest};
use crate::enter::{launch_pod, load_and_resolve};
use crate::git::get_repo_root;
use crate::pod::types::{base64_encode, HomeFileEntry};

pub fn codex(cmd: &CodexCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let host_override = cmd.host_args.resolve()?;
    let (_devcontainer, _docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, host_override.clone())?;

    let result = launch_pod(&cmd.name, host_override)?;

    let pod = crate::pod::PodClient::connect(&result.container_url, &result.container_token)?;
    write_codex_credentials(&pod)?;

    let codex_bin = find_host_codex_cli()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);
    let port = client.start_codex_proxy(StartCodexProxyRequest {
        pod_name: PodName(cmd.name.clone()),
        repo_path: repo_root,
        container_url: result.container_url,
        container_token: result.container_token,
    })?;

    let remote_url = format!("ws://127.0.0.1:{port}");
    let mut child_cmd = std::process::Command::new(&codex_bin);
    child_cmd.args(["--remote", &remote_url]);
    child_cmd.args(&cmd.args);

    let status = child_cmd
        .status()
        .with_context(|| format!("spawning codex TUI from {}", codex_bin.display()))?;

    if !status.success() {
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
    }

    Ok(())
}

/// Copy the host's codex credentials into the pod.
///
/// Copies ~/.codex/auth.json from the host home directory into the
/// container so the codex app-server can authenticate with the OpenAI
/// API. The user is expected to have run `codex login` beforehand.
fn write_codex_credentials(pod: &crate::pod::PodClient) -> Result<()> {
    let host_home = dirs::home_dir().context("could not determine home directory")?;
    match std::fs::read(host_home.join(".codex/auth.json")) {
        Ok(data) => {
            pod.write_home_files(
                vec![HomeFileEntry {
                    path: ".codex/auth.json".to_string(),
                    content: base64_encode(&data),
                    create_parents: true,
                }],
                vec![],
            )?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow::anyhow!(
            "No codex credentials found at ~/.codex/auth.json. Run `codex login` first."
        )),
        Err(e) => Err(anyhow::Error::from(e).context("reading ~/.codex/auth.json")),
    }
}

fn find_host_codex_cli() -> Result<std::path::PathBuf> {
    crate::which("codex").ok_or_else(|| {
        anyhow::anyhow!(
            "codex CLI not found in PATH. Install it from https://github.com/openai/codex"
        )
    })
}

// ---------------------------------------------------------------------------
// WebSocket proxy (runs inside the daemon process)
// ---------------------------------------------------------------------------

/// Accept loop for the daemon-managed codex WebSocket proxy.
///
/// Each incoming connection from the local codex TUI is forwarded to
/// the pod server's `/codex` endpoint.
pub async fn run_codex_proxy(
    listener: tokio::net::TcpListener,
    container_url: String,
    container_token: String,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("codex proxy: accept error: {e}");
                continue;
            }
        };
        let url = container_url.clone();
        let token = container_token.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy_connection(stream, &url, &token).await {
                eprintln!("codex proxy: connection error: {e:#}");
            }
        });
    }
}

async fn proxy_connection(
    stream: tokio::net::TcpStream,
    container_url: &str,
    container_token: &str,
) -> Result<()> {
    let client_ws = tokio_tungstenite::accept_async(stream)
        .await
        .context("accepting WebSocket from codex TUI")?;

    // The pod server may not be ready yet (e.g. container-serve is
    // still starting). Retry the upstream connection briefly so a
    // slow container start does not cause a permanent failure.
    let mut server_ws = None;
    for _ in 0..50 {
        let request = build_pod_ws_request(container_url, container_token)?;
        match tokio_tungstenite::connect_async(request).await {
            Ok((ws, _)) => {
                server_ws = Some(ws);
                break;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    let server_ws = server_ws
        .ok_or_else(|| anyhow::anyhow!("could not connect to pod server /codex after retries"))?;

    let (mut client_write, mut client_read) = client_ws.split();
    let (mut server_write, mut server_read) = server_ws.split();

    loop {
        tokio::select! {
            msg = client_read.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if server_write.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            msg = server_read.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if client_write.send(msg).await.is_err() {
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

fn build_pod_ws_request(
    container_url: &str,
    token: &str,
) -> Result<tungstenite::http::Request<()>> {
    let mut ws_url = Url::parse(container_url).context("parsing container URL")?;
    let scheme = match ws_url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => return Err(anyhow::anyhow!("unexpected scheme: {other}")),
    };
    ws_url
        .set_scheme(scheme)
        .expect("ws/wss are always valid schemes");
    ws_url.set_path("/codex");

    let host = match ws_url.port() {
        Some(port) => format!("{}:{port}", ws_url.host_str().unwrap_or("localhost")),
        None => ws_url.host_str().unwrap_or("localhost").to_string(),
    };
    tungstenite::http::Request::builder()
        .uri(ws_url.as_str())
        .header("Host", &host)
        .header("Authorization", format!("Bearer {token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .context("building WebSocket request for pod server")
}
