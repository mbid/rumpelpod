//! SSH socket forwarding for remote Docker hosts.
//!
//! This module manages SSH tunnels that forward remote Docker sockets to local
//! Unix sockets, enabling transparent remote Docker operations. It also supports
//! remote port forwarding to expose local services (like the git HTTP server)
//! to containers running on remote Docker hosts.
//!
//! The module uses SSH control sockets (multiplexing) to maintain a single SSH
//! connection per remote host, allowing dynamic addition of forwards via `-O forward`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};

use crate::config::{get_runtime_dir, RemoteDocker};

/// Initial delay for exponential backoff on reconnection.
const INITIAL_DELAY: Duration = Duration::from_secs(1);

/// Maximum delay for exponential backoff.
const MAX_DELAY: Duration = Duration::from_secs(60);

/// Environment variable to specify a custom SSH config file.
///
/// When set, SSH commands will use `-F <path>` to read configuration from the
/// specified file instead of the default locations. This is primarily useful
/// for testing, allowing tests to provide their own SSH keys and settings
/// without depending on or polluting the user's SSH configuration.
pub const SSH_CONFIG_FILE_ENV: &str = "SSH_CONFIG_FILE";

/// Remote Docker socket path.
const REMOTE_DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Key for identifying a unique remote host connection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RemoteHost {
    destination: String,
    port: u16,
}

impl RemoteHost {
    fn from_remote_docker(remote: &RemoteDocker) -> Self {
        RemoteHost {
            destination: remote.destination.clone(),
            port: remote.port,
        }
    }

    /// Generate a hash prefix for unique naming based on host+port.
    fn hash_prefix(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.destination.as_bytes());
        hasher.update(self.port.to_le_bytes());
        let hash = hex::encode(hasher.finalize());
        hash[..12].to_string()
    }

    /// Generate a unique socket filename for the Docker socket forward.
    fn docker_socket_name(&self) -> String {
        format!("docker-{}.sock", self.hash_prefix())
    }

    /// Generate a unique socket filename for the SSH control socket.
    fn control_socket_name(&self) -> String {
        format!("ssh-ctl-{}.sock", self.hash_prefix())
    }
}

/// Information about remote port forwards for a connection.
/// These are used to expose the local git HTTP server to remote containers.
#[derive(Debug, Clone, Default)]
pub struct RemoteForwards {
    /// Port on remote's bridge network gateway IP forwarding to local git HTTP socket.
    pub bridge_port: Option<u16>,
    /// Port on remote's localhost forwarding to local git HTTP socket.
    pub localhost_port: Option<u16>,
    /// The remote's bridge network gateway IP.
    pub bridge_ip: Option<String>,
}

/// An active SSH forwarding session.
struct ForwardSession {
    /// Path to the local Unix socket for Docker.
    docker_socket: PathBuf,
    /// Path to the SSH control socket for multiplexing.
    control_socket: PathBuf,
    /// The SSH process handle.
    process: Child,
    /// Last time we verified the connection was alive.
    last_check: Instant,
    /// Current backoff delay for reconnection attempts.
    backoff: Duration,
    /// Number of consecutive failures.
    failures: u32,
    /// Remote port forwards (for git HTTP server).
    remote_forwards: RemoteForwards,
}

impl ForwardSession {
    /// Check if the SSH process is still running and sockets exist.
    fn is_alive(&mut self) -> bool {
        // First check if the process is still running
        let process_alive = match self.process.try_wait() {
            Ok(None) => true,     // Still running
            Ok(Some(_)) => false, // Exited
            Err(_) => false,      // Error checking - assume dead
        };

        // Also verify that the responsible sockets exist
        let sockets_exist = self.control_socket.exists() && self.docker_socket.exists();

        process_alive && sockets_exist
    }
}

impl Drop for ForwardSession {
    fn drop(&mut self) {
        // Kill the SSH process when the session is dropped
        let _ = self.process.kill();
        let _ = self.process.wait();

        // Clean up socket files
        let _ = std::fs::remove_file(&self.docker_socket);
        let _ = std::fs::remove_file(&self.control_socket);
    }
}

/// Manager for SSH socket forwarding connections.
///
/// Maintains one SSH connection per remote host configuration, shared across
/// all sandboxes using that remote host.
pub struct SshForwardManager {
    /// Map from remote host to active forwarding session.
    connections: Mutex<HashMap<RemoteHost, ForwardSession>>,
    /// Base directory for forwarded sockets.
    socket_dir: PathBuf,
}

impl SshForwardManager {
    /// Create a new SSH forward manager.
    pub fn new() -> Result<Self> {
        let socket_dir = get_runtime_dir()?;

        // Ensure the socket directory exists
        std::fs::create_dir_all(&socket_dir).with_context(|| {
            format!(
                "Failed to create socket directory: {}",
                socket_dir.display()
            )
        })?;

        Ok(Self {
            connections: Mutex::new(HashMap::new()),
            socket_dir,
        })
    }

    /// Get or create a forwarded socket for the given remote Docker specification.
    ///
    /// Returns the local socket path to use for Docker connections.
    pub fn get_socket(&self, remote: &RemoteDocker) -> Result<PathBuf> {
        let remote_host = RemoteHost::from_remote_docker(remote);
        self.ensure_connection(&remote_host)
    }

    /// Try to get an existing forwarded socket for the given remote Docker specification.
    ///
    /// Returns the socket path if a connection already exists and is alive, otherwise None.
    /// Unlike `get_socket`, this does not create a new connection.
    pub fn try_get_socket(&self, remote: &RemoteDocker) -> Option<PathBuf> {
        let remote_host = RemoteHost::from_remote_docker(remote);
        let mut connections = self.connections.lock().unwrap();

        if let Some(session) = connections.get_mut(&remote_host) {
            if session.is_alive() {
                return Some(session.docker_socket.clone());
            }
        }
        None
    }

    /// Ensure a connection exists and is alive for the given remote host.
    fn ensure_connection(&self, host: &RemoteHost) -> Result<PathBuf> {
        let mut connections = self.connections.lock().unwrap();

        // Check if we have an existing connection
        if let Some(session) = connections.get_mut(host) {
            if session.is_alive() {
                session.last_check = Instant::now();
                debug!(
                    "Reusing existing SSH connection to {}:{}",
                    host.destination, host.port
                );
                return Ok(session.docker_socket.clone());
            }

            // Connection died, remove it and reconnect with backoff
            warn!(
                "SSH connection to {}:{} died, reconnecting...",
                host.destination, host.port
            );
            let old_session = connections.remove(host).unwrap();
            let backoff = next_backoff(old_session.backoff);
            let failures = old_session.failures + 1;

            // Apply backoff delay
            if failures > 1 {
                info!(
                    "Waiting {:?} before reconnecting (attempt {})",
                    backoff, failures
                );
                std::thread::sleep(backoff);
            }

            // Start new connection with accumulated backoff
            let session = self.start_forwarding(host, backoff, failures)?;
            let socket = session.docker_socket.clone();
            connections.insert(host.clone(), session);
            return Ok(socket);
        }

        // No existing connection, start a new one
        info!(
            "Establishing SSH connection to {}:{}",
            host.destination, host.port
        );
        let session = self.start_forwarding(host, INITIAL_DELAY, 0)?;
        let socket = session.docker_socket.clone();
        connections.insert(host.clone(), session);
        Ok(socket)
    }

    /// Start a new SSH forwarding process with control socket for multiplexing.
    fn start_forwarding(
        &self,
        host: &RemoteHost,
        backoff: Duration,
        failures: u32,
    ) -> Result<ForwardSession> {
        let docker_socket = self.socket_dir.join(host.docker_socket_name());
        let control_socket = self.socket_dir.join(host.control_socket_name());

        // Remove stale socket files if they exist
        if docker_socket.exists() {
            std::fs::remove_file(&docker_socket).with_context(|| {
                format!("Failed to remove stale socket: {}", docker_socket.display())
            })?;
        }
        if control_socket.exists() {
            std::fs::remove_file(&control_socket).with_context(|| {
                format!(
                    "Failed to remove stale control socket: {}",
                    control_socket.display()
                )
            })?;
        }

        let mut cmd = Command::new("ssh");

        // Use custom config file if specified (for testing)
        if let Ok(config_file) = std::env::var(SSH_CONFIG_FILE_ENV) {
            cmd.args(["-F", &config_file]);
        }

        // Don't execute a remote command
        cmd.arg("-N");

        // Enable control socket for multiplexing (allows adding forwards later)
        cmd.args(["-o", &format!("ControlPath={}", control_socket.display())]);
        cmd.args(["-o", "ControlMaster=yes"]);
        // Do not fork to background
        cmd.args(["-o", "ControlPersist=no"]);

        // Local socket forwarding: local_socket -> remote docker socket
        cmd.arg("-L");
        cmd.arg(format!(
            "{}:{}",
            docker_socket.display(),
            REMOTE_DOCKER_SOCKET
        ));

        // SSH options for reliable connection handling
        cmd.args(["-o", "ServerAliveInterval=5"]);
        cmd.args(["-o", "ServerAliveCountMax=3"]);
        cmd.args(["-o", "ExitOnForwardFailure=yes"]);
        cmd.args(["-o", "BatchMode=yes"]);

        // SSH port
        cmd.args(["-p", &host.port.to_string()]);

        // Target: destination (user@host or host)
        cmd.arg(&host.destination);

        debug!("Starting SSH: {:?}", cmd);

        let mut process = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "Failed to spawn SSH process for {}:{}",
                    host.destination, host.port
                )
            })?;

        // Spawn threads to log stdout and stderr from the SSH process
        let ssh_target = format!("{}:{}", host.destination, host.port);

        if let Some(stdout) = process.stdout.take() {
            let target = ssh_target.clone();
            thread::Builder::new()
                .name(format!("ssh-stdout-{}", host.hash_prefix()))
                .spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        match line {
                            Ok(line) => {
                                if !line.trim().is_empty() {
                                    info!("SSH {}: {}", target, line);
                                }
                            }
                            Err(e) => {
                                debug!("Error reading SSH stdout for {}: {}", target, e);
                                break;
                            }
                        }
                    }
                })
                .context("Failed to spawn SSH stdout logging thread")?;
        }

        if let Some(stderr) = process.stderr.take() {
            let target = ssh_target.clone();
            thread::Builder::new()
                .name(format!("ssh-stderr-{}", host.hash_prefix()))
                .spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines() {
                        match line {
                            Ok(line) => {
                                if !line.trim().is_empty() {
                                    error!("SSH {}: {}", target, line);
                                }
                            }
                            Err(e) => {
                                debug!("Error reading SSH stderr for {}: {}", target, e);
                                break;
                            }
                        }
                    }
                })
                .context("Failed to spawn SSH stderr logging thread")?;
        }

        // Wait for the docker socket to appear (SSH needs time to establish the tunnel)
        let start = Instant::now();
        let timeout = Duration::from_secs(30);

        while start.elapsed() < timeout {
            if docker_socket.exists() {
                info!(
                    "SSH tunnel established to {}:{} -> {}",
                    host.destination,
                    host.port,
                    docker_socket.display()
                );
                return Ok(ForwardSession {
                    docker_socket,
                    control_socket,
                    process,
                    last_check: Instant::now(),
                    backoff,
                    failures,
                    remote_forwards: RemoteForwards::default(),
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Timeout - kill the process and return error
        let _ = process.kill();

        anyhow::bail!(
            "SSH tunnel to {}:{} failed to establish within {:?}. Check SSH configuration and connectivity. See logs above for SSH error details.",
            host.destination,
            host.port,
            timeout
        );
    }

    /// Add a remote port forward using the SSH control socket.
    ///
    /// Uses `-O forward` to dynamically add a forward to an existing connection.
    /// Returns the allocated port on the remote host.
    fn add_remote_forward(
        &self,
        host: &RemoteHost,
        control_socket: &Path,
        remote_bind_addr: &str,
        local_socket: &Path,
    ) -> Result<u16> {
        let forward_spec = format!("{}:0:{}", remote_bind_addr, local_socket.display());

        debug!(
            "Adding remote forward via control socket: -R {}",
            forward_spec
        );

        let mut cmd = Command::new("ssh");

        // Use custom config file if specified (for testing)
        if let Ok(config_file) = std::env::var(SSH_CONFIG_FILE_ENV) {
            cmd.args(["-F", &config_file]);
        }

        cmd.args(["-o", &format!("ControlPath={}", control_socket.display())]);
        cmd.args(["-O", "forward"]);
        cmd.args(["-R", &forward_spec]);
        cmd.arg(&host.destination);

        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute ssh -O forward")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "Failed to add remote forward -R {}: {}",
                forward_spec,
                stderr.trim()
            );
        }

        // Parse the allocated port from stdout
        // Format: "Allocated port XXXXX for remote forward to /path/to/socket"
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_allocated_port(&stdout).with_context(|| {
            format!(
                "Failed to parse allocated port from ssh output: {}",
                stdout.trim()
            )
        })
    }

    /// Set up remote port forwards for the git HTTP server.
    ///
    /// This forwards connections from the remote host (both bridge network IP and localhost)
    /// to a local unix socket where the git HTTP server is listening.
    pub fn setup_git_http_forwards(
        &self,
        remote: &RemoteDocker,
        local_git_socket: &Path,
        remote_bridge_ip: &str,
    ) -> Result<RemoteForwards> {
        let host = RemoteHost::from_remote_docker(remote);
        let mut connections = self.connections.lock().unwrap();

        let session = connections
            .get_mut(&host)
            .context("No SSH connection for this remote host")?;

        // Check if forwards are already set up
        if session.remote_forwards.bridge_port.is_some() {
            debug!(
                "Remote forwards already configured for {}",
                host.destination
            );
            return Ok(session.remote_forwards.clone());
        }

        // Add forward for bridge network (containers in default network mode)
        let bridge_port = self.add_remote_forward(
            &host,
            &session.control_socket,
            remote_bridge_ip,
            local_git_socket,
        )?;
        info!(
            "Remote forward established: {}:{} -> {}",
            remote_bridge_ip,
            bridge_port,
            local_git_socket.display()
        );

        // Add forward for localhost (containers in unsafe-host network mode)
        let localhost_port = self.add_remote_forward(
            &host,
            &session.control_socket,
            "127.0.0.1",
            local_git_socket,
        )?;
        info!(
            "Remote forward established: 127.0.0.1:{} -> {}",
            localhost_port,
            local_git_socket.display()
        );

        session.remote_forwards = RemoteForwards {
            bridge_port: Some(bridge_port),
            localhost_port: Some(localhost_port),
            bridge_ip: Some(remote_bridge_ip.to_string()),
        };

        Ok(session.remote_forwards.clone())
    }

    /// Get the current remote forwards for a remote host, if any.
    pub fn get_remote_forwards(&self, remote: &RemoteDocker) -> Option<RemoteForwards> {
        let host = RemoteHost::from_remote_docker(remote);
        let connections = self.connections.lock().unwrap();
        connections
            .get(&host)
            .map(|s| s.remote_forwards.clone())
            .filter(|f| f.bridge_port.is_some())
    }
}

impl Drop for SshForwardManager {
    fn drop(&mut self) {
        // Clean up all connections
        let mut connections = self.connections.lock().unwrap();
        for (host, session) in connections.drain() {
            debug!(
                "Closing SSH connection to {}:{}",
                host.destination, host.port
            );
            drop(session); // ForwardSession::drop will kill the process
        }
    }
}

/// Calculate the next backoff delay.
fn next_backoff(current: Duration) -> Duration {
    std::cmp::min(current.saturating_mul(2), MAX_DELAY)
}

/// Parse the allocated port from SSH's `-O forward` output.
///
/// Handles multiple SSH output formats:
/// - "Allocated port XXXXX for remote forward to ..." (verbose format)
/// - "XXXXX" (just the port number, some SSH versions)
fn parse_allocated_port(output: &str) -> Option<u16> {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try verbose format: "Allocated port XXXXX for remote forward to ..."
        if let Some(rest) = line.strip_prefix("Allocated port ") {
            if let Some(port_str) = rest.split_whitespace().next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(port);
                }
            }
        }

        // Try bare port number format
        if let Ok(port) = line.parse::<u16>() {
            return Some(port);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_host_from_remote_docker() {
        let remote = RemoteDocker {
            destination: "deploy@docker.example.com".to_string(),
            port: 2222,
        };
        let host = RemoteHost::from_remote_docker(&remote);
        assert_eq!(host.destination, "deploy@docker.example.com");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn test_socket_names() {
        let host1 = RemoteHost {
            destination: "deploy@docker1.example.com".to_string(),
            port: 22,
        };
        let host2 = RemoteHost {
            destination: "deploy@docker2.example.com".to_string(),
            port: 22,
        };

        // Different hosts should have different socket names
        assert_ne!(host1.docker_socket_name(), host2.docker_socket_name());
        assert_ne!(host1.control_socket_name(), host2.control_socket_name());

        // Same host should always produce the same socket name
        assert_eq!(host1.docker_socket_name(), host1.docker_socket_name());
        assert_eq!(host1.control_socket_name(), host1.control_socket_name());

        // Socket names should have expected format
        assert!(host1.docker_socket_name().starts_with("docker-"));
        assert!(host1.docker_socket_name().ends_with(".sock"));
        assert!(host1.control_socket_name().starts_with("ssh-ctl-"));
        assert!(host1.control_socket_name().ends_with(".sock"));
    }

    #[test]
    fn test_backoff() {
        let delay = Duration::from_secs(1);
        assert_eq!(next_backoff(delay), Duration::from_secs(2));

        let delay = Duration::from_secs(32);
        assert_eq!(next_backoff(delay), Duration::from_secs(60)); // Capped at MAX_DELAY

        let delay = Duration::from_secs(60);
        assert_eq!(next_backoff(delay), Duration::from_secs(60)); // Stays at MAX_DELAY
    }

    #[test]
    fn test_parse_allocated_port() {
        // Standard verbose format from ssh -O forward
        let output = "Allocated port 43567 for remote forward to /run/sandbox/git-http.sock\n";
        assert_eq!(parse_allocated_port(output), Some(43567));

        // Bare port number format (some SSH versions)
        let output = "36481\n";
        assert_eq!(parse_allocated_port(output), Some(36481));

        // Bare port number without newline
        let output = "12345";
        assert_eq!(parse_allocated_port(output), Some(12345));

        // With extra lines (verbose format)
        let output =
            "Some other output\nAllocated port 12345 for remote forward to /path\nMore stuff";
        assert_eq!(parse_allocated_port(output), Some(12345));

        // No match
        let output = "Connection established\n";
        assert_eq!(parse_allocated_port(output), None);

        // Invalid port number in verbose format
        let output = "Allocated port notaport for remote forward";
        assert_eq!(parse_allocated_port(output), None);

        // Empty output
        let output = "";
        assert_eq!(parse_allocated_port(output), None);

        // Whitespace only
        let output = "   \n  \n";
        assert_eq!(parse_allocated_port(output), None);
    }
}
