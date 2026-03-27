//! Host-side `rumpel codex` command.
//!
//! Launches a pod, forwards OpenAI credentials into it, starts a local
//! WebSocket proxy, and spawns the codex TUI connected to the proxy.
//! The proxy forwards frames to the pod server's `/codex` endpoint,
//! which in turn proxies to the codex app-server inside the container.

use std::path::Path;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use log::trace;
use tokio_tungstenite::tungstenite;
use url::Url;

use crate::async_runtime::block_on;
use crate::cli::CodexCommand;
use crate::enter::{launch_pod, load_and_resolve};
use crate::git::get_repo_root;
use crate::pod::types::{base64_encode, HomeFileEntry};

pub fn codex(cmd: &CodexCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let host_override = cmd.host_args.resolve()?;
    let (_devcontainer, _docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, host_override.clone())?;

    let result = launch_pod(&cmd.name, host_override)?;

    // Write OpenAI credentials into the container so the codex
    // app-server can authenticate with the OpenAI API.
    let pod = crate::pod::PodClient::connect(&result.container_url, &result.container_token)?;
    write_codex_credentials(&pod)?;

    let codex_bin = find_host_codex_cli()?;

    block_on(async {
        let port =
            start_local_proxy(result.container_url.clone(), result.container_token.clone()).await?;

        let remote_url = format!("ws://127.0.0.1:{port}");
        let mut child_cmd = std::process::Command::new(&codex_bin);
        child_cmd.args(["--remote", &remote_url]);
        child_cmd.args(&cmd.args);

        // The host-side codex TUI also checks for auth before
        // connecting. Pass the API key so it skips the login flow.
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            child_cmd.env("CODEX_API_KEY", &key);
        } else if let Ok(key) = std::env::var("CODEX_API_KEY") {
            child_cmd.env("CODEX_API_KEY", &key);
        }

        let status = child_cmd
            .status()
            .with_context(|| format!("spawning codex TUI from {}", codex_bin.display()))?;

        if !status.success() {
            if let Some(code) = status.code() {
                std::process::exit(code);
            }
        }

        Ok(())
    })
}

/// Write OpenAI credentials into the pod's ~/.codex/auth.json.
///
/// Reads from OPENAI_API_KEY env var or ~/.codex/auth.json on the host.
fn write_codex_credentials(pod: &crate::pod::PodClient) -> Result<()> {
    let mut files: Vec<HomeFileEntry> = Vec::new();

    // Prefer OPENAI_API_KEY env var (simple API key auth).
    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        let auth_json = serde_json::json!({
            "auth_mode": "apikey",
            "OPENAI_API_KEY": api_key,
        });
        let data = serde_json::to_vec_pretty(&auth_json).context("serializing auth.json")?;
        files.push(HomeFileEntry {
            path: ".codex/auth.json".to_string(),
            content: base64_encode(&data),
            create_parents: true,
        });
    } else {
        // Fall back to copying the host's auth.json (from `codex login`).
        let host_home = dirs::home_dir().context("could not determine home directory")?;
        match std::fs::read(host_home.join(".codex/auth.json")) {
            Ok(data) => {
                files.push(HomeFileEntry {
                    path: ".codex/auth.json".to_string(),
                    content: base64_encode(&data),
                    create_parents: true,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(anyhow::anyhow!(
                    "No OpenAI credentials found. Set OPENAI_API_KEY or run `codex login`."
                ));
            }
            Err(e) => {
                return Err(anyhow::Error::from(e).context("reading ~/.codex/auth.json"));
            }
        }
    }

    if !files.is_empty() {
        pod.write_home_files(files, vec![])?;
    }
    Ok(())
}

/// Start a local TCP WebSocket proxy that forwards to the pod server's
/// /codex endpoint. Returns the port the proxy is listening on.
async fn start_local_proxy(container_url: String, container_token: String) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding local proxy listener")?;
    let port = listener.local_addr()?.port();
    trace!("codex: local proxy listening on 127.0.0.1:{port}");

    tokio::spawn(async move {
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
    });

    Ok(port)
}

/// Proxy a single incoming TCP connection (from the codex TUI) to the
/// pod server's /codex WebSocket endpoint.
async fn proxy_connection(
    stream: tokio::net::TcpStream,
    container_url: &str,
    container_token: &str,
) -> Result<()> {
    // Accept the incoming WebSocket upgrade from the codex TUI.
    let client_ws = tokio_tungstenite::accept_async(stream)
        .await
        .context("accepting WebSocket from codex TUI")?;

    // Connect to the pod server's /codex endpoint.
    let request = build_pod_ws_request(container_url, container_token)?;
    let (server_ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .context("connecting to pod server /codex")?;

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

/// Build a WebSocket request to the pod server's /codex endpoint.
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

/// Find the codex binary on the host's PATH.
fn find_host_codex_cli() -> Result<std::path::PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join("codex");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!(
        "codex CLI not found in PATH. Install it from https://github.com/openai/codex"
    ))
}
