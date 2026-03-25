//! Coordinates reconnection to remote hosts on behalf of waiting clients.
//!
//! When a PTY client loses its WebSocket connection to a remote pod, it
//! subscribes to the daemon's SSE endpoint.  The coordinator retries the
//! SSH tunnel with exponential backoff, notifying all subscribers of each
//! attempt.  A new subscriber triggers an immediate retry and resets the
//! backoff so the user is not stuck waiting for a long interval to elapse.

use std::collections::HashMap;
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

/// Events streamed to clients waiting for a host reconnection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReconnectEvent {
    /// The daemon is attempting to reconnect.
    Attempting,
    /// The connection has been re-established.
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
