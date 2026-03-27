//! Per-pod event listeners that maintain SSE connections to pod servers
//! and broadcast reconnection status to PTY clients.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::debug;
use retry::delay::jitter;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::config::Host;
use crate::daemon::ssh_forward::SshForwardManager;

const INITIAL_DELAY: Duration = Duration::from_secs(1);
/// Cap retry backoff low so the user's terminal reconnects promptly once
/// the host is reachable again.
const MAX_DELAY: Duration = Duration::from_secs(5);

/// Events streamed to clients waiting for a pod reconnection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReconnectEvent {
    /// The daemon is attempting to reconnect (SSH or pod).
    Attempting,
    /// The SSH tunnel has been restored; now connecting to the pod.
    HostConnected,
    /// The pod event endpoint confirmed the connection (state event received).
    Connected,
    /// A reconnection attempt failed; the daemon will retry.
    Failed { error: String },
    /// The pod was intentionally stopped; the client should exit.
    Stopped,
}

struct PodState {
    tx: broadcast::Sender<ReconnectEvent>,
    stop: Arc<AtomicBool>,
    _thread: std::thread::JoinHandle<()>,
}

/// Manages persistent SSE connections to each running pod's `/events`
/// endpoint.  When a connection drops the manager reconnects (waiting
/// for the SSH tunnel first on remote hosts) and broadcasts status
/// events so PTY clients know when the pod is reachable again.
pub struct PodEventManager {
    ssh_forward: Arc<SshForwardManager>,
    pods: Mutex<HashMap<(PathBuf, String), PodState>>,
}

impl PodEventManager {
    pub fn new(ssh_forward: Arc<SshForwardManager>) -> Self {
        Self {
            ssh_forward,
            pods: Mutex::new(HashMap::new()),
        }
    }

    /// Start (or restart) the event listener for a pod.
    pub fn start(
        &self,
        repo_path: PathBuf,
        pod_name: String,
        container_url: String,
        container_token: String,
        host: Host,
    ) {
        let key = (repo_path, pod_name.clone());
        let mut pods = self.pods.lock().unwrap();

        // Stop existing listener if any.
        if let Some(old) = pods.remove(&key) {
            old.stop.store(true, Ordering::SeqCst);
        }

        let (tx, _) = broadcast::channel(64);
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let tx = tx.clone();
            let stop = stop.clone();
            let ssh_forward = self.ssh_forward.clone();
            std::thread::Builder::new()
                .name(format!("pod-events-{pod_name}"))
                .spawn(move || {
                    pod_event_loop(ssh_forward, host, container_url, container_token, stop, tx);
                })
                .expect("failed to spawn pod event listener thread")
        };

        pods.insert(
            key,
            PodState {
                tx,
                stop,
                _thread: thread,
            },
        );
    }

    /// Stop the event listener for a pod.
    ///
    /// Broadcasts a `Stopped` event to any subscribers before tearing
    /// down the listener, so clients waiting for reconnection know the
    /// pod was intentionally stopped and should exit.
    pub fn stop(&self, repo_path: &Path, pod_name: &str) {
        let key = (repo_path.to_path_buf(), pod_name.to_string());
        let mut pods = self.pods.lock().unwrap();
        if let Some(state) = pods.remove(&key) {
            let _ = state.tx.send(ReconnectEvent::Stopped);
            state.stop.store(true, Ordering::SeqCst);
        }
    }

    /// Subscribe to reconnection events for a pod.
    pub fn subscribe(
        &self,
        repo_path: &Path,
        pod_name: &str,
    ) -> Option<broadcast::Receiver<ReconnectEvent>> {
        let key = (repo_path.to_path_buf(), pod_name.to_string());
        let pods = self.pods.lock().unwrap();
        pods.get(&key).map(|state| state.tx.subscribe())
    }
}

/// Try to connect to the pod's /events endpoint and read the initial
/// `state` event.  Returns Ok(response) positioned after the state event.
fn connect_pod_events(
    url: &str,
    token: &str,
) -> Result<BufReader<reqwest::blocking::Response>, anyhow::Error> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(None)
        .build()
        .expect("failed to build reqwest client");

    let response = client
        .get(format!("{url}/events"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .map_err(|e| anyhow::anyhow!("connecting to pod events: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        return Err(anyhow::anyhow!("pod events returned {status}"));
    }

    let mut reader = BufReader::new(response);

    // Wait for the `state` event (the pod's hello after pushing branches).
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("reading pod event stream: {e}"))?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "pod event stream closed before state event"
            ));
        }
        if line.trim() == "event: state" {
            // Consume the data line and blank separator.
            let mut data_line = String::new();
            reader.read_line(&mut data_line).ok();
            let mut blank = String::new();
            reader.read_line(&mut blank).ok();
            return Ok(reader);
        }
    }
}

/// Background loop that maintains the SSE connection to a pod.
fn pod_event_loop(
    ssh_forward: Arc<SshForwardManager>,
    host: Host,
    container_url: String,
    container_token: String,
    stop: Arc<AtomicBool>,
    tx: broadcast::Sender<ReconnectEvent>,
) {
    // Initial connection -- no reconnect signalling needed.
    let mut reader = match connect_pod_events(&container_url, &container_token) {
        Ok(r) => r,
        Err(e) => {
            debug!("initial pod event connection failed: {e:#}");
            let mut backoff = INITIAL_DELAY;
            loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(jitter(backoff));
                backoff = std::cmp::min(backoff.saturating_mul(2), MAX_DELAY);
                match connect_pod_events(&container_url, &container_token) {
                    Ok(r) => break r,
                    Err(e) => {
                        debug!("pod event reconnect failed: {e:#}");
                    }
                }
            }
        }
    };

    // Read events until the connection drops.
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                // Connection lost -- enter reconnect loop.
            }
            Ok(_) => continue,
        }

        // Reconnect loop.
        let mut backoff = INITIAL_DELAY;
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }

            // For SSH hosts, reconnect the tunnel first.
            if matches!(host, Host::Ssh { .. }) {
                let _ = tx.send(ReconnectEvent::Attempting);
                match ssh_forward.try_connect_once(&host) {
                    Ok(_) => {
                        let _ = tx.send(ReconnectEvent::HostConnected);
                    }
                    Err(e) => {
                        let _ = tx.send(ReconnectEvent::Failed {
                            error: format!("{e:#}"),
                        });
                        std::thread::sleep(jitter(backoff));
                        backoff = std::cmp::min(backoff.saturating_mul(2), MAX_DELAY);
                        continue;
                    }
                }
            }

            // Try to connect to the pod's event endpoint.
            match connect_pod_events(&container_url, &container_token) {
                Ok(new_reader) => {
                    let _ = tx.send(ReconnectEvent::Connected);
                    reader = new_reader;
                    break;
                }
                Err(e) => {
                    let _ = tx.send(ReconnectEvent::Failed {
                        error: format!("{e:#}"),
                    });
                    std::thread::sleep(jitter(backoff));
                    backoff = std::cmp::min(backoff.saturating_mul(2), MAX_DELAY);
                }
            }
        }
    }
}
