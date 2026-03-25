//! Coordinates reconnection to remote hosts on behalf of waiting clients.
//!
//! When a PTY client loses its WebSocket connection to a remote pod, it
//! subscribes to the daemon's SSE endpoint.  The coordinator retries the
//! SSH tunnel with exponential backoff, notifying all subscribers of each
//! attempt.  A new subscriber triggers an immediate retry and resets the
//! backoff so the user is not stuck waiting for a long interval to elapse.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::debug;
use retry::delay::jitter;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Notify};

use crate::config::Host;
use crate::daemon::ssh_forward::SshForwardManager;

const INITIAL_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(60);

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
}

struct HostState {
    tx: broadcast::Sender<ReconnectEvent>,
    new_waiter: Arc<Notify>,
    task_running: Arc<AtomicBool>,
}

pub struct ReconnectCoordinator {
    ssh_forward: Arc<SshForwardManager>,
    hosts: Mutex<HashMap<String, HostState>>,
}

impl ReconnectCoordinator {
    pub fn new(ssh_forward: Arc<SshForwardManager>) -> Self {
        Self {
            ssh_forward,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to reconnection events for the given host.
    ///
    /// If a background reconnection task is already running, the new
    /// subscription resets its backoff and triggers an immediate retry.
    /// If no task is running, one is spawned.
    pub fn subscribe(&self, host: &Host) -> broadcast::Receiver<ReconnectEvent> {
        let key = serde_json::to_string(host).expect("Host is always serializable");
        let mut hosts = self.hosts.lock().unwrap();

        let state = hosts.entry(key).or_insert_with(|| {
            let (tx, _) = broadcast::channel(64);
            HostState {
                tx,
                new_waiter: Arc::new(Notify::new()),
                task_running: Arc::new(AtomicBool::new(false)),
            }
        });

        let rx = state.tx.subscribe();

        // Wake the background task so it retries immediately with reset
        // backoff.  If no task is running yet, the permit is picked up
        // by the freshly spawned task on its first iteration.
        state.new_waiter.notify_one();

        if !state.task_running.swap(true, Ordering::SeqCst) {
            let ssh_forward = self.ssh_forward.clone();
            let host = host.clone();
            let tx = state.tx.clone();
            let new_waiter = state.new_waiter.clone();
            let task_running = state.task_running.clone();

            tokio::spawn(async move {
                reconnect_loop(ssh_forward, host, tx, new_waiter).await;
                task_running.store(false, Ordering::SeqCst);
            });
        }

        rx
    }
}

async fn reconnect_loop(
    ssh_forward: Arc<SshForwardManager>,
    host: Host,
    tx: broadcast::Sender<ReconnectEvent>,
    new_waiter: Arc<Notify>,
) {
    let mut backoff = INITIAL_DELAY;

    loop {
        if tx.receiver_count() == 0 {
            debug!("no more reconnect subscribers, stopping");
            return;
        }

        let _ = tx.send(ReconnectEvent::Attempting);

        let fwd = ssh_forward.clone();
        let h = host.clone();
        let result = tokio::task::spawn_blocking(move || fwd.try_connect_once(&h)).await;

        match result {
            Ok(Ok(_)) => {
                let _ = tx.send(ReconnectEvent::Connected);
                return;
            }
            Ok(Err(e)) => {
                let _ = tx.send(ReconnectEvent::Failed {
                    error: format!("{e:#}"),
                });
            }
            Err(e) => {
                let _ = tx.send(ReconnectEvent::Failed {
                    error: format!("internal error: {e}"),
                });
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(jitter(backoff)) => {
                backoff = std::cmp::min(backoff.saturating_mul(2), MAX_DELAY);
            }
            _ = new_waiter.notified() => {
                backoff = INITIAL_DELAY;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-pod event listener
// ---------------------------------------------------------------------------

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
    pub fn stop(&self, repo_path: &Path, pod_name: &str) {
        let key = (repo_path.to_path_buf(), pod_name.to_string());
        let mut pods = self.pods.lock().unwrap();
        if let Some(state) = pods.remove(&key) {
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
