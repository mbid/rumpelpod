//! Git HTTP server for exposing gateway repositories to pods.
//!
//! Runs a single axum server that serves multiple gateway git repositories via
//! git-http-backend CGI, allowing containers to fetch from the host.
//!
//! Authentication uses bearer tokens: each pod is assigned a unique token
//! when registered. The server maintains a mapping from tokens to pod info
//! (gateway path and pod name). When a request arrives, the server looks up
//! the token to determine which gateway to serve and which pod name to set.
//!
//! The server sets the `POD_NAME` environment variable when invoking git-http-backend,
//! which is then available to git hooks for access control.
//!
//! The server can listen on TCP sockets (for local containers) or Unix sockets
//! (for SSH remote port forwarding to remote containers).
//!
//! Additionally, the server implements a minimal Git LFS Batch API so that
//! pods can download LFS objects (served from the host repo's `.git/lfs/`
//! or the gateway's LFS storage) and upload new LFS objects to the gateway.

use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bollard::Docker;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use cgi_service::{CgiConfig, CgiService};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use rand::{distr::Alphanumeric, RngExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::task::JoinHandle;
use tower::ServiceExt;
use tower_service::Service;

use crate::async_runtime::RUNTIME;

/// Path to git-http-backend CGI script.
const GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// Environment variable set by the HTTP server to identify the pod.
/// This is used by the pre-receive hook for access control.
pub const POD_NAME_ENV: &str = "POD_NAME";

/// Information about a registered pod.
#[derive(Clone)]
struct PodInfo {
    /// Path to the gateway.git bare repository.
    gateway_path: PathBuf,
    /// Name of the pod (used for access control in hooks).
    pod_name: String,
    /// Path to the host repository, used to locate `.git/lfs/objects/`.
    host_repo_path: PathBuf,
}

/// Shared state for the git HTTP server.
/// Maps bearer tokens to pod information.
#[derive(Clone, Default)]
pub struct SharedGitServerState {
    inner: Arc<Mutex<BTreeMap<String, PodInfo>>>,
}

impl SharedGitServerState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Register a pod and return its bearer token.
    pub fn register(
        &self,
        gateway_path: PathBuf,
        pod_name: String,
        host_repo_path: PathBuf,
    ) -> String {
        let token: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let info = PodInfo {
            gateway_path,
            pod_name,
            host_repo_path,
        };

        self.inner.lock().unwrap().insert(token.clone(), info);
        token
    }

    /// Unregister a pod by its token.
    pub fn unregister(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }

    /// Look up pod info by token.
    fn get(&self, token: &str) -> Option<PodInfo> {
        self.inner.lock().unwrap().get(token).cloned()
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
    pub fn start(bind_address: &str, port: u16, state: SharedGitServerState) -> Result<Self> {
        let addr: SocketAddr = format!("{}:{}", bind_address, port)
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
        let app = build_router(state);

        // Spawn the server in the background
        let task_handle = RUNTIME.spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Git HTTP server error: {}", e);
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

/// A git HTTP server listening on a Unix socket.
/// Used for SSH remote port forwarding to expose the server to remote containers.
pub struct UnixGitHttpServer {
    /// Handle to the spawned tokio task running the server.
    task_handle: JoinHandle<()>,
    /// The path to the Unix socket.
    pub socket_path: PathBuf,
}

impl UnixGitHttpServer {
    /// Start a new git HTTP server listening on a Unix socket.
    ///
    /// The server binds to the specified socket path.
    /// Returns the server instance.
    pub fn start(socket_path: &Path, state: SharedGitServerState) -> Result<Self> {
        let socket_path = socket_path.to_path_buf();

        // Remove stale socket file if it exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).with_context(|| {
                format!("Failed to remove stale socket: {}", socket_path.display())
            })?;
        }

        debug!(
            "Starting git HTTP server on Unix socket: {}",
            socket_path.display()
        );

        // Bind the Unix socket
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind Unix socket: {}", socket_path.display()))?;
        listener
            .set_nonblocking(true)
            .context("Failed to set Unix socket to non-blocking")?;

        let tokio_listener = tokio::net::UnixListener::from_std(listener)
            .context("Failed to convert to tokio UnixListener")?;

        info!(
            "Git HTTP server listening on Unix socket: {}",
            socket_path.display()
        );

        // Build router with explicit LFS routes before the CGI fallback
        let app = build_router(state);

        let socket_path_clone = socket_path.clone();

        // Spawn the server in the background
        let task_handle = RUNTIME.spawn(async move {
            loop {
                match tokio_listener.accept().await {
                    Ok((stream, _)) => {
                        let app = app.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = hyper::service::service_fn(
                                move |req: Request<hyper::body::Incoming>| {
                                    // Convert incoming body to axum's Body type
                                    let (parts, body) = req.into_parts();
                                    let body = Body::new(body);
                                    let req = Request::from_parts(parts, body);
                                    let app = app.clone();
                                    async move {
                                        let response: Response =
                                            app.oneshot(req).await.unwrap_or_else(|e| match e {});
                                        Ok::<_, std::convert::Infallible>(response)
                                    }
                                },
                            );
                            if let Err(e) =
                                http1::Builder::new().serve_connection(io, service).await
                            {
                                debug!("Unix socket connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!(
                            "Unix socket accept error on {}: {}",
                            socket_path_clone.display(),
                            e
                        );
                    }
                }
            }
        });

        Ok(UnixGitHttpServer {
            task_handle,
            socket_path,
        })
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        self.task_handle.abort();
        // Clean up socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for UnixGitHttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build the axum router with LFS routes and the git-http-backend fallback.
fn build_router(state: SharedGitServerState) -> Router {
    Router::new()
        .route(
            "/gateway.git/info/lfs/objects/batch",
            post(lfs_batch_handler),
        )
        .route(
            "/gateway.git/lfs/objects/{oid}",
            get(lfs_download_handler).put(lfs_upload_handler),
        )
        .fallback(handle_request)
        .with_state(state)
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

    match state.get(token) {
        Some(info) => Ok((info, token.to_string())),
        None => Err(Box::new(StatusCode::UNAUTHORIZED.into_response())),
    }
}

/// Return the path where an LFS object is stored under a given base directory.
/// Layout: `<base>/lfs/objects/XX/YY/<oid>` (XX = oid[0..2], YY = oid[2..4]).
fn lfs_object_path(base: &Path, oid: &str) -> PathBuf {
    base.join("lfs")
        .join("objects")
        .join(&oid[..2])
        .join(&oid[2..4])
        .join(oid)
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

/// Handle `POST /gateway.git/info/lfs/objects/batch`.
///
/// For downloads, checks whether the object exists in gateway or host LFS
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

    let auth_value = format!("Bearer {}", token);

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
        let gateway_obj = lfs_object_path(&info.gateway_path, &obj.oid);
        let host_obj = lfs_object_path(&info.host_repo_path.join(".git"), &obj.oid);

        match batch_req.operation.as_str() {
            "download" => {
                if gateway_obj.exists() || host_obj.exists() {
                    let mut headers = HashMap::new();
                    headers.insert("Authorization".to_string(), auth_value.clone());
                    let mut actions = HashMap::new();
                    actions.insert(
                        "download".to_string(),
                        LfsAction {
                            href: format!(
                                "http://{}/gateway.git/lfs/objects/{}",
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
                if gateway_obj.exists() || host_obj.exists() {
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
                                "http://{}/gateway.git/lfs/objects/{}",
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
                        message: format!("Unknown operation: {}", batch_req.operation),
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

/// Handle `GET /gateway.git/lfs/objects/:oid`.
///
/// Serves the LFS object from gateway storage (pod uploads) or host storage
/// (objects that exist on the host).  Gateway storage is checked first so that
/// pod-uploaded objects take precedence.
async fn lfs_download_handler(
    State(state): State<SharedGitServerState>,
    AxumPath(oid): AxumPath<String>,
    req: Request<Body>,
) -> Response {
    let (info, _) = match authenticate(&state, &req) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    let gateway_obj = lfs_object_path(&info.gateway_path, &oid);
    let host_obj = lfs_object_path(&info.host_repo_path.join(".git"), &oid);

    let file_path = if gateway_obj.exists() {
        gateway_obj
    } else if host_obj.exists() {
        host_obj
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match tokio::fs::read(&file_path).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to read LFS object {}: {}", oid, e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handle `PUT /gateway.git/lfs/objects/:oid`.
///
/// Reads the request body, verifies the SHA-256 digest matches the OID, and
/// writes the object into the gateway's LFS storage.
async fn lfs_upload_handler(
    State(state): State<SharedGitServerState>,
    AxumPath(oid): AxumPath<String>,
    req: Request<Body>,
) -> Response {
    let (info, _) = match authenticate(&state, &req) {
        Ok(r) => r,
        Err(resp) => return *resp,
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

    let obj_path = lfs_object_path(&info.gateway_path, &oid);
    if let Some(parent) = obj_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            warn!("Failed to create LFS object directory: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    match tokio::fs::write(&obj_path, &body_bytes).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            warn!("Failed to write LFS object {}: {}", oid, e);
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
    let info = match state.get(token) {
        Some(info) => info,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // Get the parent directory of gateway.git for GIT_PROJECT_ROOT
    let gateway_parent = info
        .gateway_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"));

    // Configure CGI service for this specific pod
    let cgi_config = CgiConfig::new(GIT_HTTP_BACKEND)
        .env("GIT_PROJECT_ROOT", gateway_parent.to_string_lossy())
        .env("GIT_HTTP_EXPORT_ALL", "")
        .env(POD_NAME_ENV, &info.pod_name)
        .script_name("");

    let mut cgi_service = CgiService::with_config(cgi_config);

    // Call the CGI service
    match cgi_service.call(req).await {
        Ok(response) => response.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Get the gateway IP address for a docker network.
/// This is the IP address the host uses on the network, which containers can reach.
pub fn get_network_gateway_ip(network_name: &str) -> Result<String> {
    use crate::async_runtime::block_on;

    let docker = Docker::connect_with_socket_defaults().context("connecting to Docker daemon")?;

    let network =
        block_on(docker.inspect_network(network_name, None)).context("inspecting network")?;

    // Find the first gateway IP in the IPAM config
    let gateway_ip = network
        .ipam
        .and_then(|ipam| ipam.config)
        .and_then(|configs| {
            configs
                .into_iter()
                .find_map(|config| config.gateway.filter(|g| !g.is_empty()))
        })
        .with_context(|| format!("no gateway IP found for network {}", network_name))?;

    Ok(gateway_ip)
}

/// Get the gateway IP address for a docker network via a specific socket.
/// Used for remote Docker hosts accessed via SSH forwarding.
pub fn get_network_gateway_ip_via_socket(socket_path: &Path, network_name: &str) -> Result<String> {
    use crate::async_runtime::block_on;

    let docker = Docker::connect_with_socket(
        socket_path.to_string_lossy().as_ref(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("connecting to Docker daemon via socket")?;

    let network =
        block_on(docker.inspect_network(network_name, None)).context("inspecting network")?;

    // Find the first gateway IP in the IPAM config
    let gateway_ip = network
        .ipam
        .and_then(|ipam| ipam.config)
        .and_then(|configs| {
            configs
                .into_iter()
                .find_map(|config| config.gateway.filter(|g| !g.is_empty()))
        })
        .with_context(|| format!("no gateway IP found for network {}", network_name))?;

    Ok(gateway_ip)
}

/// Get the URL for the git HTTP server accessible from within a container.
pub fn git_http_url(ip: &str, port: u16) -> String {
    format!("http://{}:{}/gateway.git", ip, port)
}
