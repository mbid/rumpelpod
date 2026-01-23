//! Git HTTP server for exposing gateway repositories to sandboxes.
//!
//! Runs a single axum server that serves multiple gateway git repositories via
//! git-http-backend CGI, allowing containers to fetch from the host.
//!
//! Authentication uses bearer tokens: each sandbox is assigned a unique token
//! when registered. The server maintains a mapping from tokens to sandbox info
//! (gateway path and sandbox name). When a request arrives, the server looks up
//! the token to determine which gateway to serve and which sandbox name to set.
//!
//! The server sets the `SANDBOX_NAME` environment variable when invoking git-http-backend,
//! which is then available to git hooks for access control.
//!
//! The server can listen on TCP sockets (for local containers) or Unix sockets
//! (for SSH remote port forwarding to remote containers).

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bollard::Docker;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use cgi_service::{CgiConfig, CgiService};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use rand::{distr::Alphanumeric, Rng};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::task::JoinHandle;
use tower::ServiceExt;
use tower_service::Service;

use crate::async_runtime::RUNTIME;

/// Path to git-http-backend CGI script.
const GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// Environment variable set by the HTTP server to identify the sandbox.
/// This is used by the pre-receive hook for access control.
pub const SANDBOX_NAME_ENV: &str = "SANDBOX_NAME";

/// Information about a registered sandbox.
#[derive(Clone)]
struct SandboxInfo {
    /// Path to the gateway.git bare repository.
    gateway_path: PathBuf,
    /// Name of the sandbox (used for access control in hooks).
    sandbox_name: String,
}

/// Shared state for the git HTTP server.
/// Maps bearer tokens to sandbox information.
#[derive(Clone, Default)]
pub struct SharedGitServerState {
    inner: Arc<Mutex<BTreeMap<String, SandboxInfo>>>,
}

impl SharedGitServerState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Register a sandbox and return its bearer token.
    pub fn register(&self, gateway_path: PathBuf, sandbox_name: String) -> String {
        let token: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let info = SandboxInfo {
            gateway_path,
            sandbox_name,
        };

        self.inner.lock().unwrap().insert(token.clone(), info);
        token
    }

    /// Unregister a sandbox by its token.
    pub fn unregister(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }

    /// Look up sandbox info by token.
    fn get(&self, token: &str) -> Option<SandboxInfo> {
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
    /// Start a new git HTTP server with shared state for handling multiple sandboxes.
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

        // Build router that handles all requests via our auth handler
        let app = Router::new().fallback(handle_request).with_state(state);

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
                format!(
                    "Failed to remove stale socket: {}",
                    socket_path.display()
                )
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

        // Build router
        let app = Router::new().fallback(handle_request).with_state(state);

        let socket_path_clone = socket_path.clone();

        // Spawn the server in the background
        let task_handle = RUNTIME.spawn(async move {
            loop {
                match tokio_listener.accept().await {
                    Ok((stream, _)) => {
                        let app = app.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service =
                                hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                    // Convert incoming body to axum's Body type
                                    let (parts, body) = req.into_parts();
                                    let body = Body::new(body);
                                    let req = Request::from_parts(parts, body);
                                    let app = app.clone();
                                    async move {
                                        let response: Response = app.oneshot(req).await.unwrap_or_else(|e| match e {});
                                        Ok::<_, std::convert::Infallible>(response)
                                    }
                                });
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
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

    // Look up sandbox info
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

    // Configure CGI service for this specific sandbox
    let cgi_config = CgiConfig::new(GIT_HTTP_BACKEND)
        .env("GIT_PROJECT_ROOT", gateway_parent.to_string_lossy())
        .env("GIT_HTTP_EXPORT_ALL", "")
        .env(SANDBOX_NAME_ENV, &info.sandbox_name)
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
