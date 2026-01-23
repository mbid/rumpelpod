//! SSH socket forwarding for remote Docker hosts.
//!
//! This module manages SSH tunnels that forward remote Docker sockets to local
//! Unix sockets, enabling transparent remote Docker operations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{debug, info, warn};
use sha2::{Digest, Sha256};

use crate::config::{get_runtime_dir, RemoteDocker};

/// Initial delay for exponential backoff on reconnection.
const INITIAL_DELAY: Duration = Duration::from_secs(1);

/// Maximum delay for exponential backoff.
const MAX_DELAY: Duration = Duration::from_secs(60);

/// Remote Docker socket path.
const REMOTE_DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Key for identifying a unique remote host connection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RemoteHost {
    host: String,
    port: u16,
    user: String,
}

impl RemoteHost {
    fn from_remote_docker(remote: &RemoteDocker) -> Self {
        RemoteHost {
            host: remote.host.clone(),
            port: remote.port,
            user: remote.user.clone(),
        }
    }

    /// Generate a unique socket filename based on host+port+user.
    fn socket_name(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.host.as_bytes());
        hasher.update(self.port.to_le_bytes());
        hasher.update(self.user.as_bytes());
        let hash = hex::encode(hasher.finalize());
        format!("docker-{}.sock", &hash[..12])
    }
}

/// An active SSH forwarding session.
struct ForwardSession {
    /// Path to the local Unix socket.
    local_socket: PathBuf,
    /// The SSH process handle.
    process: Child,
    /// Last time we verified the connection was alive.
    last_check: Instant,
    /// Current backoff delay for reconnection attempts.
    backoff: Duration,
    /// Number of consecutive failures.
    failures: u32,
}

impl ForwardSession {
    /// Check if the SSH process is still running.
    fn is_alive(&mut self) -> bool {
        match self.process.try_wait() {
            Ok(None) => true,     // Still running
            Ok(Some(_)) => false, // Exited
            Err(_) => false,      // Error checking - assume dead
        }
    }
}

impl Drop for ForwardSession {
    fn drop(&mut self) {
        // Kill the SSH process when the session is dropped
        let _ = self.process.kill();
        let _ = self.process.wait();

        // Clean up the socket file
        let _ = std::fs::remove_file(&self.local_socket);
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

    /// Ensure a connection exists and is alive for the given remote host.
    fn ensure_connection(&self, host: &RemoteHost) -> Result<PathBuf> {
        let mut connections = self.connections.lock().unwrap();

        // Check if we have an existing connection
        if let Some(session) = connections.get_mut(host) {
            if session.is_alive() {
                session.last_check = Instant::now();
                debug!(
                    "Reusing existing SSH connection to {}@{}:{}",
                    host.user, host.host, host.port
                );
                return Ok(session.local_socket.clone());
            }

            // Connection died, remove it and reconnect with backoff
            warn!(
                "SSH connection to {}@{}:{} died, reconnecting...",
                host.user, host.host, host.port
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
            let socket = session.local_socket.clone();
            connections.insert(host.clone(), session);
            return Ok(socket);
        }

        // No existing connection, start a new one
        info!(
            "Establishing SSH connection to {}@{}:{}",
            host.user, host.host, host.port
        );
        let session = self.start_forwarding(host, INITIAL_DELAY, 0)?;
        let socket = session.local_socket.clone();
        connections.insert(host.clone(), session);
        Ok(socket)
    }

    /// Start a new SSH forwarding process.
    fn start_forwarding(
        &self,
        host: &RemoteHost,
        backoff: Duration,
        failures: u32,
    ) -> Result<ForwardSession> {
        let local_socket = self.socket_dir.join(host.socket_name());

        // Remove stale socket file if it exists
        if local_socket.exists() {
            std::fs::remove_file(&local_socket).with_context(|| {
                format!("Failed to remove stale socket: {}", local_socket.display())
            })?;
        }

        let mut cmd = Command::new("ssh");

        // Don't execute a remote command
        cmd.arg("-N");

        // Local socket forwarding: local_socket -> remote docker socket
        cmd.arg("-L");
        cmd.arg(format!(
            "{}:{}",
            local_socket.display(),
            REMOTE_DOCKER_SOCKET
        ));

        // SSH options for reliable connection handling
        cmd.args(["-o", "ServerAliveInterval=5"]);
        cmd.args(["-o", "ServerAliveCountMax=3"]);
        cmd.args(["-o", "ExitOnForwardFailure=yes"]);
        cmd.args(["-o", "BatchMode=yes"]);
        cmd.args(["-o", "ControlMaster=no", "-o", "ControlPath=none"]);

        // SSH port
        cmd.args(["-p", &host.port.to_string()]);

        // Target: user@host
        cmd.arg(format!("{}@{}", host.user, host.host));

        debug!("Starting SSH: {:?}", cmd);

        let process = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "Failed to spawn SSH process for {}@{}:{}",
                    host.user, host.host, host.port
                )
            })?;

        // Wait for the socket to appear (SSH needs time to establish the tunnel)
        let start = Instant::now();
        let timeout = Duration::from_secs(30);

        while start.elapsed() < timeout {
            if local_socket.exists() {
                info!(
                    "SSH tunnel established to {}@{}:{} -> {}",
                    host.user,
                    host.host,
                    host.port,
                    local_socket.display()
                );
                return Ok(ForwardSession {
                    local_socket,
                    process,
                    last_check: Instant::now(),
                    backoff,
                    failures,
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Timeout - kill the process and return error
        let mut process = process;
        let _ = process.kill();

        // Try to get stderr for error message
        let stderr = process.stderr.take();
        let error_msg = stderr
            .and_then(|mut s| {
                use std::io::Read;
                let mut buf = String::new();
                s.read_to_string(&mut buf).ok()?;
                Some(buf)
            })
            .unwrap_or_default();

        anyhow::bail!(
            "SSH tunnel to {}@{}:{} failed to establish within {:?}. {}",
            host.user,
            host.host,
            host.port,
            timeout,
            if error_msg.is_empty() {
                "Check SSH configuration and connectivity.".to_string()
            } else {
                format!("SSH error: {}", error_msg.trim())
            }
        );
    }
}

impl Drop for SshForwardManager {
    fn drop(&mut self) {
        // Clean up all connections
        let mut connections = self.connections.lock().unwrap();
        for (host, session) in connections.drain() {
            debug!(
                "Closing SSH connection to {}@{}:{}",
                host.user, host.host, host.port
            );
            drop(session); // ForwardSession::drop will kill the process
        }
    }
}

/// Calculate the next backoff delay.
fn next_backoff(current: Duration) -> Duration {
    std::cmp::min(current.saturating_mul(2), MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_host_from_remote_docker() {
        let remote = RemoteDocker {
            host: "docker.example.com".to_string(),
            user: "deploy".to_string(),
            port: 2222,
        };
        let host = RemoteHost::from_remote_docker(&remote);
        assert_eq!(host.host, "docker.example.com");
        assert_eq!(host.user, "deploy");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn test_socket_name() {
        let host1 = RemoteHost {
            host: "docker1.example.com".to_string(),
            port: 22,
            user: "deploy".to_string(),
        };
        let host2 = RemoteHost {
            host: "docker2.example.com".to_string(),
            port: 22,
            user: "deploy".to_string(),
        };

        // Different hosts should have different socket names
        assert_ne!(host1.socket_name(), host2.socket_name());

        // Same host should always produce the same socket name
        assert_eq!(host1.socket_name(), host1.socket_name());

        // Socket name should have expected format
        assert!(host1.socket_name().starts_with("docker-"));
        assert!(host1.socket_name().ends_with(".sock"));
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
}
