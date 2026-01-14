//! Git HTTP server for exposing the gateway repository to sandboxes.
//!
//! Runs an axum server that serves the gateway git repository via
//! git-http-backend CGI, allowing containers to fetch from the host.
//!
//! Each sandbox gets its own HTTP server bound to its docker network's gateway IP.
//! The server sets the `SANDBOX_NAME` environment variable when invoking git-http-backend,
//! which is then available to git hooks for access control. This is secure because:
//! - The sandbox cannot modify this variable (it's set by the server, not the client)
//! - The sandbox can only reach its own network's HTTP server (network isolation)

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use axum::Router;
use cgi_service::{CgiConfig, CgiService};
use log::{debug, error};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::task::JoinHandle;

use crate::command_ext::CommandExt;
use crate::r#async::RUNTIME;

/// Port used for the git HTTP server on each container's network.
pub const GIT_HTTP_PORT: u16 = 8417;

/// Path to git-http-backend CGI script.
const GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// Environment variable set by the HTTP server to identify the sandbox.
/// This is used by the pre-receive hook for access control.
pub const SANDBOX_NAME_ENV: &str = "SANDBOX_NAME";

/// A running git HTTP server instance.
/// Stops the server when dropped.
pub struct GitHttpServer {
    /// Handle to the spawned tokio task running the server.
    task_handle: JoinHandle<()>,
}

impl GitHttpServer {
    /// Start a new git HTTP server for the given gateway repository.
    ///
    /// The server binds to the specified address. If port is 0, a random port is assigned.
    /// Returns the server instance and the actual port bound.
    ///
    /// The `sandbox_name` is passed to git-http-backend as an environment variable,
    /// which hooks can use for access control.
    pub fn start(
        gateway_path: &Path,
        bind_address: &str,
        port: u16,
        sandbox_name: &str,
    ) -> Result<(Self, u16)> {
        let gateway_parent = gateway_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"));

        let addr: SocketAddr = format!("{}:{}", bind_address, port)
            .parse()
            .context("parsing bind address")?;

        debug!(
            "Starting git HTTP server on {} (requested port: {}) for {} (sandbox: {})",
            addr,
            port,
            gateway_path.display(),
            sandbox_name
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

        // Configure the CGI service for git-http-backend.
        // git-http-backend expects:
        //   - GIT_PROJECT_ROOT: parent directory containing the bare repo
        //   - PATH_INFO: full request path including repo name (e.g., /gateway.git/info/refs)
        //   - SCRIPT_NAME: empty (the script itself is at root)
        //
        // We also set SANDBOX_NAME so the pre-receive hook can enforce access control.
        // This is secure because the sandbox cannot modify this - it's set by the server.
        let cgi_config = CgiConfig::new(GIT_HTTP_BACKEND)
            .env("GIT_PROJECT_ROOT", gateway_parent.to_string_lossy())
            .env("GIT_HTTP_EXPORT_ALL", "")
            .env(SANDBOX_NAME_ENV, sandbox_name)
            .script_name("");

        let cgi_service = CgiService::with_config(cgi_config);

        // Build router that handles all requests via CGI
        let app = Router::new().fallback_service(cgi_service);

        // Spawn the server in the background
        let task_handle = RUNTIME.spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Git HTTP server error: {}", e);
            }
        });

        Ok((GitHttpServer { task_handle }, actual_port))
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

/// Get the gateway IP address for a docker network.
/// This is the IP address the host uses on the network, which containers can reach.
pub fn get_network_gateway_ip(network_name: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
            network_name,
        ])
        .success()
        .context("getting network gateway IP")?;

    let gateway_ip = String::from_utf8_lossy(&output).trim().to_string();
    if gateway_ip.is_empty() {
        anyhow::bail!("no gateway IP found for network {}", network_name);
    }

    Ok(gateway_ip)
}

/// Spawn a git HTTP server for a container and manage its lifecycle.
///
/// This function:
/// 1. Starts an axum server bound to the provided address and port
/// 2. Spawns a background task that waits for the container to stop and then
///    shuts down the server
///
/// Returns the actual port bound.
pub fn spawn_git_http_server(
    gateway_path: &Path,
    bind_address: &str,
    port: u16,
    sandbox_name: &str,
    container_id: &str,
) -> Result<u16> {
    debug!(
        "Starting git HTTP server on {}:{} for container {} (sandbox: {})",
        bind_address, port, container_id, sandbox_name
    );

    let (server, actual_port) =
        GitHttpServer::start(gateway_path, bind_address, port, sandbox_name)?;

    // Spawn a task to wait for the container to stop and then shut down the server
    let container_id = container_id.to_string();
    RUNTIME.spawn(async move {
        // Move server into this task so it lives until we're done
        let mut server = server;

        // docker wait blocks until the container stops
        let result = tokio::process::Command::new("docker")
            .args(["wait", &container_id])
            .output()
            .await;

        match result {
            Ok(output) => {
                if output.status.success() {
                    debug!(
                        "Container {} stopped, stopping git HTTP server",
                        container_id
                    );
                } else {
                    let combined = String::from_utf8_lossy(&output.stdout).to_string()
                        + &String::from_utf8_lossy(&output.stderr);
                    error!(
                        "docker wait for {} exited with {}: {}",
                        container_id,
                        output.status,
                        combined.trim()
                    );
                }
            }
            Err(e) => {
                error!("docker wait failed: {}", e);
            }
        }

        server.stop();
    });

    Ok(actual_port)
}

/// Get the URL for the git HTTP server accessible from within a container.
pub fn git_http_url(ip: &str, port: u16) -> String {
    format!("http://{}:{}/gateway.git", ip, port)
}
