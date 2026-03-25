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
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{debug, info, warn};
use sha2::{Digest, Sha256};

use crate::command_ext::CommandExt;
use crate::config::{get_runtime_dir, Host};
use crate::jitter;
use crate::RetryPolicy;

/// Initial delay for exponential backoff on reconnection.
const INITIAL_DELAY: Duration = Duration::from_secs(1);

/// Maximum delay for exponential backoff.
const MAX_DELAY: Duration = Duration::from_secs(60);

/// Timeout for the ping operation (hard limit via thread).
///
/// This is the ceiling for how long we wait to determine if a tunnel is broken.
/// Must be longer than the inner socket timeouts to allow them to fire first.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Remote Docker socket path.
const REMOTE_DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Ping the Docker daemon via Unix socket to verify connectivity.
///
/// Makes a simple HTTP request to the Docker API's `/_ping` endpoint.
/// Returns true if the daemon responds, false otherwise.
///
/// This function uses a thread with hard timeout to ensure it never hangs,
/// even if the SSH tunnel is in a broken state where socket operations block.
fn ping_docker_socket(socket_path: &Path) -> bool {
    let socket_path = socket_path.to_path_buf();
    let (tx, rx) = mpsc::channel();

    // Spawn a thread to do the actual ping.
    // If SSH is stuck, socket operations might block indefinitely despite timeouts.
    std::thread::spawn(move || {
        let result = ping_docker_socket_inner(&socket_path);
        // Ignore send errors - the receiver might have timed out and been dropped
        let _ = tx.send(result);
    });

    // Wait for result with a hard timeout
    match rx.recv_timeout(PING_TIMEOUT) {
        Ok(result) => result,
        Err(_) => {
            // Timeout or channel closed - assume the ping failed
            debug!("ping_docker_socket timed out after {PING_TIMEOUT:?}");
            false
        }
    }
}

/// Inner implementation of ping_docker_socket that does the actual work.
fn ping_docker_socket_inner(socket_path: &Path) -> bool {
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Short timeout so broken tunnels are detected quickly.
    let timeout = Duration::from_secs(3);
    stream
        .set_read_timeout(Some(timeout))
        .expect("set_read_timeout should always succeed on connected UnixStream");
    stream
        .set_write_timeout(Some(timeout))
        .expect("set_write_timeout should always succeed on connected UnixStream");

    // Send HTTP request to Docker's ping endpoint
    let request = "GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    // Read response - we just need to see any valid HTTP response
    let mut response = [0u8; 256];
    match stream.read(&mut response) {
        Ok(n) if n > 0 => {
            let response_str = String::from_utf8_lossy(&response[..n]);
            // Check for HTTP 200 OK response
            response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200")
        }
        _ => false,
    }
}

/// Key for identifying a unique remote host connection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RemoteHost {
    destination: String,
    port: u16,
}

impl RemoteHost {
    fn from_docker_host(host: &Host) -> Self {
        RemoteHost {
            destination: host.ssh_destination().to_string(),
            port: host.ssh_port(),
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
        let hash = self.hash_prefix();
        format!("docker-{hash}.sock")
    }

    /// Generate a unique socket filename for the SSH control socket.
    fn control_socket_name(&self) -> String {
        let hash = self.hash_prefix();
        format!("ssh-ctl-{hash}.sock")
    }
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

        if !process_alive || !sockets_exist {
            return false;
        }

        // Verify the Docker daemon is actually responding through the tunnel.
        // This catches cases where SSH is still running but the tunnel is broken
        // (e.g., remote host restarted and SSH hasn't detected it yet).
        ping_docker_socket(&self.docker_socket)
    }
}

impl Drop for ForwardSession {
    fn drop(&mut self) {
        // Kill the SSH process when the session is dropped
        let _ = self.process.kill();

        // Wait for process to exit with a timeout to avoid hanging indefinitely.
        // SIGKILL should terminate immediately, but we add a timeout just in case.
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        loop {
            match self.process.try_wait() {
                Ok(Some(_)) => break, // Process exited
                Ok(None) => {
                    // Still running
                    if start.elapsed() > timeout {
                        warn!("SSH process did not exit within {timeout:?} after SIGKILL");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    warn!("Error waiting for SSH process: {e}");
                    break;
                }
            }
        }

        // Clean up socket files
        let _ = std::fs::remove_file(&self.docker_socket);
        let _ = std::fs::remove_file(&self.control_socket);
    }
}

/// Manager for SSH socket forwarding connections.
///
/// Maintains one SSH connection per remote host configuration, shared across
/// all pods using that remote host.
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
            let socket_dir = socket_dir.display();
            format!("Failed to create socket directory: {socket_dir}")
        })?;

        Ok(Self {
            connections: Mutex::new(HashMap::new()),
            socket_dir,
        })
    }

    /// Get or create a forwarded socket for the given remote Docker specification.
    ///
    /// `UserBlocking` resets any accumulated backoff and retries
    /// indefinitely (the user can Ctrl-C).  `Background` uses the
    /// existing backoff state and gives up after one attempt.
    pub fn get_socket(&self, docker_host: &Host, policy: RetryPolicy) -> Result<PathBuf> {
        let remote_host = RemoteHost::from_docker_host(docker_host);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.ensure_connection(&remote_host, policy) {
                Ok(path) => return Ok(path),
                Err(e) => {
                    if policy == RetryPolicy::Background {
                        return Err(e);
                    }
                    let dest = &remote_host.destination;
                    let port = remote_host.port;
                    warn!(
                        "SSH connection to {dest}:{port} failed \
                         (attempt {attempt}): {e:#}. Retrying..."
                    );
                    std::thread::sleep(jitter(Duration::from_secs(2)));
                }
            }
        }
    }

    /// Make a single connection attempt without retrying.
    ///
    /// Returns the socket path on success.  If the tunnel is already alive
    /// the path is returned immediately; otherwise one SSH attempt is made.
    /// Used by the reconnect coordinator which manages its own backoff.
    pub fn try_connect_once(&self, docker_host: &Host) -> Result<PathBuf> {
        let remote_host = RemoteHost::from_docker_host(docker_host);
        self.ensure_connection(&remote_host, crate::RetryPolicy::UserBlocking)
    }

    /// Try to get an existing forwarded socket for the given remote Docker specification.
    ///
    /// Returns the socket path if a connection already exists and is alive, otherwise None.
    /// Unlike `get_socket`, this does not create a new connection.
    pub fn try_get_socket(&self, docker_host: &Host) -> Option<PathBuf> {
        let remote_host = RemoteHost::from_docker_host(docker_host);
        let mut connections = self.connections.lock().unwrap();

        if let Some(session) = connections.get_mut(&remote_host) {
            if session.is_alive() {
                return Some(session.docker_socket.clone());
            }
        }
        None
    }

    /// Ensure a connection exists and is alive for the given remote host.
    ///
    /// `UserBlocking` resets accumulated backoff so a fresh user action
    /// does not inherit delays from earlier failures.  `Background`
    /// keeps the accumulated backoff from the previous session.
    fn ensure_connection(&self, host: &RemoteHost, policy: RetryPolicy) -> Result<PathBuf> {
        let mut connections = self.connections.lock().unwrap();

        // Check if we have an existing connection
        if let Some(session) = connections.get_mut(host) {
            if session.is_alive() {
                session.last_check = Instant::now();
                let destination = &host.destination;
                let port = host.port;
                debug!("Reusing existing SSH connection to {destination}:{port}");
                return Ok(session.docker_socket.clone());
            }

            // Connection died, remove it and reconnect.
            let destination = &host.destination;
            let port = host.port;
            warn!("SSH connection to {destination}:{port} died, reconnecting...");
            let old_session = connections.remove(host).unwrap();

            // UserBlocking: fresh user action, start clean.
            // Background: carry forward the accumulated backoff.
            let (backoff, failures) = match policy {
                RetryPolicy::UserBlocking => (INITIAL_DELAY, 0),
                RetryPolicy::Background => {
                    (next_backoff(old_session.backoff), old_session.failures + 1)
                }
            };

            // Drop the old session BEFORE starting the new one.
            // This is important because Drop cleans up socket files, and the new
            // session will use the same socket paths (derived from host+port hash).
            drop(old_session);

            // Apply backoff delay
            if failures > 1 {
                let delay = jitter(backoff);
                info!("Waiting {delay:?} before reconnecting (attempt {failures})");
                std::thread::sleep(delay);
            }

            // Start new connection with accumulated backoff
            let session = self.start_forwarding(host, backoff, failures)?;
            let socket = session.docker_socket.clone();
            connections.insert(host.clone(), session);
            return Ok(socket);
        }

        // No existing connection, start a new one
        let destination = &host.destination;
        let port = host.port;
        info!("Establishing SSH connection to {destination}:{port}");
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
                let docker_socket = docker_socket.display();
                format!("Failed to remove stale socket: {docker_socket}")
            })?;
        }
        if control_socket.exists() {
            std::fs::remove_file(&control_socket).with_context(|| {
                let control_socket = control_socket.display();
                format!("Failed to remove stale control socket: {control_socket}")
            })?;
        }

        let mut cmd = Command::new("ssh");

        // SSH resolves ~ from the passwd database, not $HOME.  When the
        // daemon runs with a non-default HOME (e.g. in tests), the user
        // config at $HOME/.ssh/config would be silently ignored.  Pass
        // -F explicitly so SSH reads the right file.
        let home = std::env::var("HOME").context("HOME not set")?;
        let user_config = PathBuf::from(&home).join(".ssh/config");
        if user_config.exists() {
            let user_config = user_config.display();
            cmd.args(["-F", &format!("{user_config}")]);
        }

        // Don't execute a remote command
        cmd.arg("-N");

        // Enable control socket for multiplexing (allows adding forwards later)
        let control_socket_display = control_socket.display();
        cmd.args(["-o", &format!("ControlPath={control_socket_display}")]);
        cmd.args(["-o", "ControlMaster=yes"]);
        // Do not fork to background
        cmd.args(["-o", "ControlPersist=no"]);

        // Local socket forwarding: local_socket -> remote docker socket
        cmd.arg("-L");
        let docker_socket_display = docker_socket.display();
        cmd.arg(format!("{docker_socket_display}:{REMOTE_DOCKER_SOCKET}"));

        // SSH options for reliable connection handling
        cmd.args(["-o", "ServerAliveInterval=5"]);
        cmd.args(["-o", "ServerAliveCountMax=3"]);
        cmd.args(["-o", "ExitOnForwardFailure=yes"]);
        cmd.args(["-o", "BatchMode=yes"]);

        // SSH port
        cmd.args(["-p", &host.port.to_string()]);

        // Target: destination (user@host or host)
        cmd.arg(&host.destination);

        debug!("Starting SSH: {cmd:?}");

        cmd.stdin(Stdio::null());

        let destination = &host.destination;
        let port = host.port;
        let ssh_target = format!("SSH {destination}:{port}");
        let mut process = cmd
            .spawn_with_logging(&ssh_target)
            .with_context(|| format!("Failed to spawn SSH process for {destination}:{port}"))?;

        // Wait for the docker socket to appear (SSH needs time to establish the tunnel)
        let start = Instant::now();
        let timeout = Duration::from_secs(30);

        while start.elapsed() < timeout {
            if let Ok(Some(status)) = process.try_wait() {
                return Err(anyhow::anyhow!(
                    "SSH process exited prematurely with status: {status}"
                ));
            }

            if docker_socket.exists() {
                // Verify the Docker daemon is actually responding through the tunnel.
                // This is more robust than just checking socket connectivity - it ensures
                // the full path works: SSH tunnel -> remote Docker socket -> Docker daemon.
                if ping_docker_socket(&docker_socket) {
                    // One final check that SSH hasn't exited
                    if let Ok(Some(status)) = process.try_wait() {
                        return Err(anyhow::anyhow!(
                            "SSH process exited after establishing socket (status: {status})"
                        ));
                    }

                    let docker_socket_display = docker_socket.display();
                    info!(
                        "SSH tunnel established to {destination}:{port} -> {docker_socket_display}"
                    );
                    return Ok(ForwardSession {
                        docker_socket,
                        control_socket,
                        process,
                        last_check: Instant::now(),
                        backoff,
                        failures,
                    });
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Timeout - kill the process and return error
        let _ = process.kill();

        Err(anyhow::anyhow!(
            "SSH tunnel to {destination}:{port} failed to establish within {timeout:?}. Check SSH configuration and connectivity. See logs above for SSH error details."
        ))
    }

    /// Add a local port forward (`-L`) through an existing SSH connection.
    pub fn add_local_forward(
        &self,
        docker_host: &Host,
        local_port: u16,
        remote_addr: &str,
        remote_port: u16,
    ) -> Result<()> {
        let host = RemoteHost::from_docker_host(docker_host);
        let connections = self.connections.lock().unwrap();

        let session = connections
            .get(&host)
            .context("No SSH connection for this remote host")?;

        let forward_spec = format!("127.0.0.1:{local_port}:{remote_addr}:{remote_port}");

        debug!("Adding local forward via control socket: -L {forward_spec}");

        let mut cmd = Command::new("ssh");

        let control_socket_display = session.control_socket.display();
        cmd.args(["-o", &format!("ControlPath={control_socket_display}")]);
        cmd.args(["-O", "forward"]);
        cmd.args(["-L", &forward_spec]);
        cmd.arg(&host.destination);

        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute ssh -O forward")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            return Err(anyhow::anyhow!(
                "Failed to add local forward -L {forward_spec}: {stderr}"
            ));
        }

        let destination = &host.destination;
        info!("SSH local forward active: -L {forward_spec} via {destination}");

        Ok(())
    }
}

impl Drop for SshForwardManager {
    fn drop(&mut self) {
        // Clean up all connections
        let mut connections = self.connections.lock().unwrap();
        for (host, session) in connections.drain() {
            let destination = &host.destination;
            let port = host.port;
            debug!("Closing SSH connection to {destination}:{port}");
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
    fn test_remote_host_from_docker_host() {
        let docker_host = Host::parse("ssh://deploy@docker.example.com:2222").unwrap();
        let host = RemoteHost::from_docker_host(&docker_host);
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
}
