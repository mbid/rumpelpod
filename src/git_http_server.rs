//! Git HTTP server for exposing the gateway repository to sandboxes.
//!
//! Spawns a lighttpd process that serves the gateway git repository via
//! git-http-backend CGI, allowing containers to fetch from the host.

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;

use anyhow::{Context, Result};
use indoc::formatdoc;
use log::{debug, error};
use tempfile::{NamedTempFile, TempPath};

use crate::command_ext::CommandExt;

/// Port used for the git HTTP server on each container's network.
pub const GIT_HTTP_PORT: u16 = 8417;

/// Path to git-http-backend CGI script.
const GIT_HTTP_BACKEND: &str = "/usr/lib/git-core/git-http-backend";

/// Generate a lighttpd configuration file for serving a git repository.
fn generate_lighttpd_config(gateway_path: &Path, bind_address: &str, port: u16) -> String {
    let gateway_parent = gateway_path
        .parent()
        .map(|p| p.to_string_lossy())
        .unwrap_or_else(|| "/".into());

    // lighttpd config for git-http-backend.
    // The entire domain/port is dedicated to git-http-backend. We alias "" (root)
    // to the git-http-backend script.
    formatdoc! {r#"
        server.modules = (
            "mod_setenv",
            "mod_cgi",
            "mod_alias"
        )

        server.document-root = "/var/empty"
        server.bind = "{bind_address}"
        server.port = {port}

        # Disable logging to avoid noise
        server.errorlog = "/dev/null"

        # CGI configuration for git-http-backend
        # The entire server is dedicated to git, so we alias root to git-http-backend
        alias.url = ( "" => "{GIT_HTTP_BACKEND}" )
        setenv.set-environment = (
            "GIT_PROJECT_ROOT" => "{gateway_parent}",
            "GIT_HTTP_EXPORT_ALL" => ""
        )
        cgi.assign = ( "" => "" )
    "#}
}

/// A running git HTTP server instance.
/// Stops the server when dropped.
pub struct GitHttpServer {
    /// The lighttpd process.
    process: Child,
    /// Path to the temp config file. The file is deleted when this is dropped.
    /// We don't keep the file handle open because lighttpd needs to read it.
    _config_path: TempPath,
}

impl GitHttpServer {
    /// Start a new git HTTP server for the given gateway repository.
    ///
    /// The server binds to the specified address (typically the docker network
    /// gateway IP) and serves the gateway repo via git-http-backend.
    pub fn start(gateway_path: &Path, bind_address: &str) -> Result<Self> {
        let config_content = generate_lighttpd_config(gateway_path, bind_address, GIT_HTTP_PORT);

        // Create temp config file
        let mut config_file = NamedTempFile::new().context("creating temp config file")?;
        config_file
            .write_all(config_content.as_bytes())
            .context("writing lighttpd config")?;
        config_file.flush()?;

        let config_path = config_file.path().to_owned();

        // Close the file handle but keep the TempPath for cleanup on drop
        let temp_path = config_file.into_temp_path();

        debug!(
            "Starting lighttpd with config:\n{}",
            config_content.trim_start()
        );

        // Start lighttpd with the config
        // -D = don't daemonize (run in foreground)
        let process = Command::new("lighttpd")
            .args(["-D", "-f"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning lighttpd")?;

        Ok(GitHttpServer {
            process,
            _config_path: temp_path,
        })
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        if let Err(e) = self.process.kill() {
            // ESRCH (no such process) is expected if process already exited
            if e.kind() != std::io::ErrorKind::InvalidInput
                && !e.to_string().contains("No such process")
            {
                error!("Failed to kill lighttpd process: {}", e);
            }
        }
        if let Err(e) = self.process.wait() {
            error!("Failed to wait for lighttpd process: {}", e);
        }
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
/// 2. Starts a lighttpd server bound to that IP
/// 3. Spawns a background thread that waits for the container to stop and then
///    kills the lighttpd process
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

    // Spawn a thread to wait for the container to stop and then kill the server
    let container_id = container_id.to_string();
    thread::spawn(move || {
        // Move server into this thread so it lives until we're done
        let mut server = server;

        // docker wait blocks until the container stops
        let result = Command::new("docker")
            .args(["wait", &container_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match result {
            Ok(status) if status.success() => {
                debug!(
                    "Container {} stopped, stopping git HTTP server",
                    container_id
                );
            }
            Ok(status) => {
                // docker wait exited non-zero (container might not exist)
                error!(
                    "docker wait for {} exited with {}, stopping server",
                    container_id, status
                );
            }
            Err(e) => {
                error!("docker wait failed: {}, stopping server", e);
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
