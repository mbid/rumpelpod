// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Git HTTP server for exposing host repositories to pods.
//!
//! Runs a single axum server that serves git repositories via
//! git-http-backend CGI, allowing containers to fetch from and push to the host.
//!
//! Authentication uses bearer tokens: each pod is assigned a unique token
//! when registered. The server maintains a mapping from tokens to pod info
//! (git directory and pod name). When a request arrives, the server looks up
//! the token to determine which repo to serve and which pod name to set.
//!
//! The server sets the `POD_NAME` environment variable when invoking git-http-backend,
//! which is then available to git hooks for access control.
//!
//! The server can listen on TCP sockets (for local containers) or Unix sockets
//! (for SSH remote port forwarding to remote containers).
//!
//! Additionally, the server implements a minimal Git LFS Batch API so that
//! pods can download LFS objects from the host repo's `.git/lfs/` and
//! upload new LFS objects.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::Connection;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use cgi_service::{CgiConfig, CgiService};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::task::JoinHandle;
use tower_service::Service;

use crate::async_runtime::RUNTIME;

/// Locate git-http-backend by querying `git --exec-path`.
fn git_http_backend_path() -> &'static str {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(output) = std::process::Command::new("git")
            .arg("--exec-path")
            .output()
        {
            if output.status.success() {
                let exec_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let path = format!("{exec_path}/git-http-backend");
                if Path::new(&path).exists() {
                    return path;
                }
            }
        }
        "/usr/lib/git-core/git-http-backend".to_string()
    })
}

/// Environment variable set by the HTTP server to identify the pod.
/// This is used by the pre-receive hook for access control.
pub const POD_NAME_ENV: &str = "POD_NAME";

/// Information about a registered pod.
#[derive(Clone)]
struct PodInfo {
    /// Path to the host repository's `.git` directory.
    git_dir: PathBuf,
    /// Resolved git directories for submodules, keyed by displaypath.
    submodule_git_dirs: Vec<(String, PathBuf)>,
    /// Name of the pod (used for access control in hooks).
    pod_name: String,
    /// Path to the host-side ssh-agent Unix socket for this pod.
    /// May not exist yet if no keys have been added.
    agent_sock: Option<PathBuf>,
}

/// Shared state for the git HTTP server.
///
/// Validates bearer tokens by querying the SQLite database on each
/// request.  Pod metadata (git directory, submodules, agent socket)
/// is derived from the database record rather than cached in memory,
/// so no registration/unregistration is needed.
#[derive(Clone)]
pub struct SharedGitServerState {
    db: Arc<Mutex<Connection>>,
}

impl SharedGitServerState {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self { db }
    }

    /// Look up pod info by token.  Queries the database and derives
    /// the git directory, submodule paths, and agent socket from the
    /// stored repo_path and pod_name.
    fn get_pod_info(&self, token: &str) -> Option<PodInfo> {
        let conn = self.db.lock().unwrap();
        let record = crate::daemon::db::get_pod_by_token(&conn, token).ok()??;

        let repo_path = PathBuf::from(&record.repo_path);
        let git_dir = std::fs::canonicalize(repo_path.join(".git")).ok()?;
        let submodule_git_dirs = crate::gateway::resolve_submodule_git_dirs(&repo_path);
        let pod_name = crate::daemon::protocol::PodName(record.name.clone());
        let agent_sock = crate::daemon::ssh_agent_dir(&repo_path, &pod_name).join("agent.sock");

        Some(PodInfo {
            git_dir,
            submodule_git_dirs,
            pod_name: record.name,
            agent_sock: Some(agent_sock),
        })
    }

    /// Generate a new random token for a pod.
    pub fn generate_token() -> String {
        use rand::distr::Alphanumeric;
        use rand::RngExt;
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }
}

/// A running git HTTP server instance.
/// Stops the server when dropped.
pub struct GitHttpServer {
    /// Handle to the spawned tokio task running the server.
    task_handle: JoinHandle<()>,
    /// The port the server is bound to.
    pub port: u16,
}

impl GitHttpServer {
    /// Start a new git HTTP server with shared state for handling multiple pods.
    ///
    /// The server binds to the specified address. If port is 0, a random port is assigned.
    /// Returns the server instance.
    pub fn start(
        bind_address: &str,
        port: u16,
        state: SharedGitServerState,
        llm_cache_proxy: Option<crate::llm::cache_proxy::LlmCacheProxyState>,
    ) -> Result<Self> {
        let addr: SocketAddr = format!("{bind_address}:{port}")
            .parse()
            .context("parsing bind address")?;

        debug!(
            "Starting git HTTP server on {} (requested port: {})",
            addr, port
        );

        // Bind manually using socket2 to ensure SO_REUSEADDR is set.
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket =
            Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).context("creating socket")?;

        socket
            .set_reuse_address(true)
            .context("setting SO_REUSEADDR")?;

        socket
            .bind(&addr.into())
            .context("binding git HTTP server")?;
        socket.listen(128).context("listening on socket")?;

        let std_listener: TcpListener = socket.into();
        std_listener
            .set_nonblocking(true)
            .context("setting nonblocking mode")?;

        let bound_addr = std_listener.local_addr().context("getting local address")?;
        let actual_port = bound_addr.port();

        // Convert to tokio listener
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .context("converting to tokio listener")?;

        // Build router with explicit LFS routes before the CGI fallback
        let app = build_router(state, llm_cache_proxy);

        // Spawn the server in the background
        let task_handle = RUNTIME.spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Git HTTP server error: {e}");
            }
        });

        Ok(GitHttpServer {
            task_handle,
            port: actual_port,
        })
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        self.task_handle.abort();
    }
}

impl Drop for GitHttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build the axum router with LFS routes and the git-http-backend fallback.
fn build_router(
    state: SharedGitServerState,
    llm_cache_proxy: Option<crate::llm::cache_proxy::LlmCacheProxyState>,
) -> Router {
    let mut router = Router::new()
        .route(
            "/rumpelpod.git/info/lfs/objects/batch",
            post(lfs_batch_handler),
        )
        .route(
            "/rumpelpod.git/lfs/objects/{oid}",
            get(lfs_download_handler).put(lfs_upload_handler),
        )
        .route("/ssh-agent", get(ssh_agent_handler))
        .fallback(handle_request)
        .with_state(state);

    if let Some(proxy_state) = llm_cache_proxy {
        use axum::routing::any;
        // Merge the cache proxy routes before the git fallback so they
        // take priority over the CGI catch-all.
        let proxy_router = Router::new()
            .route(
                "/llm-cache-proxy/{provider}/{*rest}",
                any(crate::llm::cache_proxy::handle_llm_cache_proxy),
            )
            .with_state(proxy_state);
        router = proxy_router.merge(router);
    }

    router
}

// -- LFS JSON types -----------------------------------------------------------

#[derive(Deserialize)]
struct LfsBatchRequest {
    operation: String,
    #[serde(default)]
    objects: Vec<LfsObject>,
}

#[derive(Deserialize)]
struct LfsObject {
    oid: String,
    size: u64,
}

#[derive(Serialize)]
struct LfsBatchResponse {
    transfer: String,
    objects: Vec<LfsObjectResponse>,
}

#[derive(Serialize)]
struct LfsObjectResponse {
    oid: String,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<HashMap<String, LfsAction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<LfsError>,
}

#[derive(Serialize)]
struct LfsAction {
    href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
struct LfsError {
    code: u16,
    message: String,
}

// -- LFS helpers --------------------------------------------------------------

const LFS_OID_LEN: usize = 64;

/// Authenticate a request and return the pod info and bearer token.
fn authenticate(
    state: &SharedGitServerState,
    req: &Request<Body>,
) -> Result<(PodInfo, String), Box<Response>> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err(Box::new(StatusCode::UNAUTHORIZED.into_response())),
    };

    match state.get_pod_info(token) {
        Some(info) => Ok((info, token.to_string())),
        None => Err(Box::new(StatusCode::UNAUTHORIZED.into_response())),
    }
}

fn is_valid_lfs_oid(oid: &str) -> bool {
    oid.len() == LFS_OID_LEN && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Return the path where an LFS object is stored under a given base directory.
/// Layout: `<base>/lfs/objects/XX/YY/<oid>` (XX = oid[0..2], YY = oid[2..4]).
fn lfs_object_path(base: &Path, oid: &str) -> Option<PathBuf> {
    if !is_valid_lfs_oid(oid) {
        return None;
    }

    Some(
        base.join("lfs")
            .join("objects")
            .join(&oid[..2])
            .join(&oid[2..4])
            .join(oid),
    )
}

/// Construct an LFS response with the correct content type.
fn lfs_json_response(status: StatusCode, body: &impl Serialize) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/vnd.git-lfs+json")],
        serde_json::to_string(body).unwrap(),
    )
        .into_response()
}

// -- LFS handlers -------------------------------------------------------------

/// Handle `POST /rumpelpod.git/info/lfs/objects/batch`.
///
/// For downloads, checks whether the object exists in the host's LFS
/// storage and returns a download URL.  For uploads, returns an upload URL
/// (or omits `actions` if the object already exists).
async fn lfs_batch_handler(
    State(state): State<SharedGitServerState>,
    req: Request<Body>,
) -> Response {
    let (info, token) = match authenticate(&state, &req) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let auth_value = format!("Bearer {token}");

    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let batch_req: LfsBatchRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut response_objects = Vec::new();

    for obj in &batch_req.objects {
        let host_obj = match lfs_object_path(&info.git_dir, &obj.oid) {
            Some(path) => path,
            None => return StatusCode::BAD_REQUEST.into_response(),
        };

        match batch_req.operation.as_str() {
            "download" => {
                if host_obj.exists() {
                    let mut headers = HashMap::new();
                    headers.insert("Authorization".to_string(), auth_value.clone());
                    let mut actions = HashMap::new();
                    actions.insert(
                        "download".to_string(),
                        LfsAction {
                            href: format!(
                                "http://{}/rumpelpod.git/lfs/objects/{}",
                                host_header, obj.oid
                            ),
                            header: Some(headers),
                        },
                    );
                    response_objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: Some(actions),
                        error: None,
                    });
                } else {
                    response_objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: None,
                        error: Some(LfsError {
                            code: 404,
                            message: "Object not found".to_string(),
                        }),
                    });
                }
            }
            "upload" => {
                // Omit actions when the object already exists to signal
                // "already have it" per the LFS batch API spec.
                if host_obj.exists() {
                    response_objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: None,
                        error: None,
                    });
                } else {
                    let mut headers = HashMap::new();
                    headers.insert("Authorization".to_string(), auth_value.clone());
                    let mut actions = HashMap::new();
                    actions.insert(
                        "upload".to_string(),
                        LfsAction {
                            href: format!(
                                "http://{}/rumpelpod.git/lfs/objects/{}",
                                host_header, obj.oid
                            ),
                            header: Some(headers),
                        },
                    );
                    response_objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: Some(actions),
                        error: None,
                    });
                }
            }
            _ => {
                response_objects.push(LfsObjectResponse {
                    oid: obj.oid.clone(),
                    size: obj.size,
                    actions: None,
                    error: Some(LfsError {
                        code: 400,
                        message: {
                            let operation = &batch_req.operation;
                            format!("Unknown operation: {operation}")
                        },
                    }),
                });
            }
        }
    }

    let response = LfsBatchResponse {
        transfer: "basic".to_string(),
        objects: response_objects,
    };

    lfs_json_response(StatusCode::OK, &response)
}

/// Handle `GET /rumpelpod.git/lfs/objects/:oid`.
///
/// Serves the LFS object from the host repo's `.git/lfs/` storage.
async fn lfs_download_handler(
    State(state): State<SharedGitServerState>,
    AxumPath(oid): AxumPath<String>,
    req: Request<Body>,
) -> Response {
    let (info, _) = match authenticate(&state, &req) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let file_path = match lfs_object_path(&info.git_dir, &oid) {
        Some(path) => path,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !file_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    match tokio::fs::read(&file_path).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to read LFS object {oid}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handle `PUT /rumpelpod.git/lfs/objects/:oid`.
///
/// Reads the request body, verifies the SHA-256 digest matches the OID, and
/// writes the object into the host repo's `.git/lfs/` storage.
async fn lfs_upload_handler(
    State(state): State<SharedGitServerState>,
    AxumPath(oid): AxumPath<String>,
    req: Request<Body>,
) -> Response {
    let (info, _) = match authenticate(&state, &req) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let obj_path = match lfs_object_path(&info.git_dir, &oid) {
        Some(path) => path,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // 500 MB upper bound -- LFS objects can be large
    let body_bytes = match axum::body::to_bytes(req.into_body(), 500 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let computed = hex::encode(hasher.finalize());
    if computed != oid {
        return (StatusCode::BAD_REQUEST, "SHA-256 mismatch").into_response();
    }

    if let Some(parent) = obj_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            warn!("Failed to create LFS object directory: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    match tokio::fs::write(&obj_path, &body_bytes).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            warn!("Failed to write LFS object {oid}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handle an incoming request by validating the bearer token and dispatching to git-http-backend.
async fn handle_request(State(state): State<SharedGitServerState>, req: Request<Body>) -> Response {
    // Extract bearer token from Authorization header
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // Look up pod info
    let info = match state.get_pod_info(token) {
        Some(info) => info,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // Resolve the git directory for this request.  The URL path
    // determines whether this targets the main repo or a submodule:
    //   /rumpelpod.git/...                          -> main repo
    //   /submodules/<displaypath>/rumpelpod.git/... -> submodule
    let uri_path = req.uri().path();
    let served_git_dir = resolve_git_dir_for_request(uri_path, &info);

    // Keep refs/rumpelpod/host-head in sync with HEAD so pods always
    // see the current commit when fetching, even in detached-HEAD state.
    let host_head_dir = served_git_dir.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let dir = host_head_dir.to_string_lossy().to_string();
        let _ = std::process::Command::new("git")
            .args([
                "--git-dir",
                &dir,
                "update-ref",
                "refs/rumpelpod/host-head",
                "HEAD",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    })
    .await;

    // Configure CGI service for this specific pod.
    // http.receivepack is passed via env vars so we do not need to
    // modify the host repo's git config.
    //
    // git-http-backend uses GIT_PROJECT_ROOT + the first URL path
    // component to locate the repo.  We set the project root to the
    // PARENT of the served git dir and rewrite the URL to use the
    // git dir's basename (typically ".git" or "modules/<name>").
    let project_root = served_git_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"));
    let git_dir_name = served_git_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| ".git".to_string());

    let new_path = rewrite_url_path(uri_path, &git_dir_name);
    let (mut parts, body) = req.into_parts();
    // Preserve the query string when rewriting the URI.
    let new_uri_str = match parts.uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };
    if let Ok(new_uri) = new_uri_str.parse::<axum::http::Uri>() {
        parts.uri = new_uri;
    }
    let req = Request::from_parts(parts, body);

    let cgi_config = CgiConfig::new(git_http_backend_path())
        .env("GIT_PROJECT_ROOT", project_root.to_string_lossy())
        .env("GIT_HTTP_EXPORT_ALL", "")
        .env(POD_NAME_ENV, &info.pod_name)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "http.receivepack")
        .env("GIT_CONFIG_VALUE_0", "true")
        .script_name("");

    let mut cgi_service = CgiService::with_config(cgi_config);

    // Call the CGI service
    match cgi_service.call(req).await {
        Ok(response) => response.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// -- URL routing helpers ------------------------------------------------------

/// Determine the git directory to serve for a given request URL path.
///
/// `/rumpelpod.git/...` routes to the main repo's git dir.
/// `/submodules/<displaypath>/rumpelpod.git/...` routes to the matching
/// submodule's git dir.  Falls back to the main repo for unrecognized paths.
fn resolve_git_dir_for_request(uri_path: &str, info: &PodInfo) -> PathBuf {
    // Extract the displaypath between "/submodules/" and "/rumpelpod.git".
    let submodule_path = uri_path
        .strip_prefix("/submodules/")
        .and_then(|rest| rest.find("/rumpelpod.git").map(|pos| &rest[..pos]));

    match submodule_path {
        Some(displaypath) => {
            match info
                .submodule_git_dirs
                .iter()
                .find(|(dp, _)| dp == displaypath)
            {
                Some((_, git_dir)) => git_dir.clone(),
                // Pod requested a submodule the daemon did not register.
                // This should not happen in normal operation.
                None => {
                    warn!("submodule '{displaypath}' not registered, serving main repo");
                    info.git_dir.clone()
                }
            }
        }
        // Main repo request (/rumpelpod.git/...) or unrecognized path.
        None => info.git_dir.clone(),
    }
}

/// Rewrite the URL path so git-http-backend finds the repo.
///
/// Replaces the repo-name portion of the path (e.g. `repo.git` or
/// `submodules/foo/rumpelpod.git`) with the actual git dir basename so
/// that `GIT_PROJECT_ROOT/<basename>` resolves to the correct directory.
fn rewrite_url_path(uri_path: &str, git_dir_name: &str) -> String {
    // Find where the git service path starts (after the repo name).
    let service_start = uri_path
        .find("/info/")
        .or_else(|| uri_path.find("/git-"))
        .or_else(|| uri_path.find("/HEAD"))
        .or_else(|| uri_path.find("/objects/"));

    match service_start {
        Some(pos) => format!("/{git_dir_name}{}", &uri_path[pos..]),
        None => format!("/{git_dir_name}"),
    }
}

// -- SSH agent relay ----------------------------------------------------------

/// WebSocket endpoint that bridges to the host-side ssh-agent Unix socket.
///
/// The container-serve process inside the pod connects here (through the
/// existing tunnel) when an SSH client connects to SSH_AUTH_SOCK.  Bytes
/// are piped bidirectionally between the WebSocket and the agent socket.
async fn ssh_agent_handler(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(state): State<SharedGitServerState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let token = match auth {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let info = match state.get_pod_info(token) {
        Some(i) => i,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let agent_sock = match info.agent_sock {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                "no ssh-agent configured for this pod",
            )
                .into_response()
        }
    };

    ws.on_upgrade(move |socket| ssh_agent_bridge(socket, agent_sock))
}

async fn ssh_agent_bridge(mut ws: axum::extract::ws::WebSocket, agent_sock: PathBuf) {
    use axum::extract::ws::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let agent = match tokio::net::UnixStream::connect(&agent_sock).await {
        Ok(s) => s,
        Err(e) => {
            let path = agent_sock.display();
            warn!("ssh-agent relay: cannot connect to {path}: {e}");
            if let Err(e) = ws.send(Message::Close(None)).await {
                warn!("ssh-agent relay: failed to send close frame: {e}");
            }
            return;
        }
    };
    let (mut agent_read, mut agent_write) = tokio::io::split(agent);

    // Read from the agent socket in a background task and feed a channel,
    // because we cannot split axum's WebSocket into independent read/write
    // halves.
    let (agent_tx, mut agent_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let agent_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match agent_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if agent_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            ws_msg = ws.recv() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data)))
                        if agent_write.write_all(&data).await.is_err() =>
                    {
                        break;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            agent_data = agent_rx.recv() => {
                match agent_data {
                    Some(data) => {
                        if ws.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    agent_reader.abort();
    if let Err(e) = ws.send(Message::Close(None)).await {
        warn!("ssh-agent relay: failed to send close frame: {e}");
    }
}
