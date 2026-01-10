//! Git HTTP server for exposing the gateway repository to sandboxes.
//!
//! Runs an axum server that serves the gateway git repository via
//! git-http-backend CGI, allowing containers to fetch from the host.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use axum::Router;
use cgi_service::{CgiConfig, CgiService};
use log::{debug, error};
use tokio::task::JoinHandle;

use crate::command_ext::CommandExt;
use crate::r#async::RUNTIME;

/// Port used for the git HTTP server on each container's network.
pub const GIT_HTTP_PORT: u16 = 8417;

/// Path to git-http-backend CGI script.
const GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// A running git HTTP server instance.
/// Stops the server when dropped.
pub struct GitHttpServer {
    /// Handle to the spawned tokio task running the server.
    task_handle: JoinHandle<()>,
}

impl GitHttpServer {
    /// Start a new git HTTP server for the given gateway repository.
    ///
    /// The server binds to the specified address (typically the docker network
    /// gateway IP) and serves the gateway repo via git-http-backend.
    pub fn start(gateway_path: &Path, bind_address: &str) -> Result<Self> {
        let gateway_parent = gateway_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"));

        let addr: SocketAddr = format!("{}:{}", bind_address, GIT_HTTP_PORT)
            .parse()
            .context("parsing bind address")?;

        debug!(
            "Starting git HTTP server on {} for {}",
            addr,
            gateway_path.display()
        );

        // Configure the CGI service for git-http-backend.
        // git-http-backend expects:
        //   - GIT_PROJECT_ROOT: parent directory containing the bare repo
        //   - PATH_INFO: full request path including repo name (e.g., /gateway.git/info/refs)
        //   - SCRIPT_NAME: empty (the script itself is at root)
        let cgi_config = CgiConfig::new(GIT_HTTP_BACKEND)
            .env("GIT_PROJECT_ROOT", gateway_parent.to_string_lossy())
            .env("GIT_HTTP_EXPORT_ALL", "")
            .script_name("");

        let cgi_service = CgiService::with_config(cgi_config);

        // Build router that handles all requests via CGI
        let app = Router::new().fallback_service(cgi_service);

        // Spawn the server in the background
        let task_handle = RUNTIME.spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind git HTTP server to {}: {}", addr, e);
                    return;
                }
            };

            if let Err(e) = axum::serve(listener, app).await {
                error!("Git HTTP server error: {}", e);
            }
        });

        Ok(GitHttpServer { task_handle })
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
/// 1. Gets the gateway IP for the container's network
/// 2. Starts an axum server bound to that IP serving git-http-backend via CGI
/// 3. Spawns a background task that waits for the container to stop and then
///    shuts down the server
pub fn spawn_git_http_server(
    gateway_path: &Path,
    network_name: &str,
    container_id: &str,
) -> Result<()> {
    let gateway_ip = get_network_gateway_ip(network_name)?;

    debug!(
        "Starting git HTTP server on {}:{} for container {}",
        gateway_ip, GIT_HTTP_PORT, container_id
    );

    let server = GitHttpServer::start(gateway_path, &gateway_ip)?;

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

    Ok(())
}

/// Get the URL for the git HTTP server accessible from within a container.
pub fn git_http_url(network_name: &str) -> Result<String> {
    let gateway_ip = get_network_gateway_ip(network_name)?;
    Ok(format!(
        "http://{}:{}/gateway.git",
        gateway_ip, GIT_HTTP_PORT
    ))
}
