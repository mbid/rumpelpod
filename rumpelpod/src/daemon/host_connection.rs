// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-host connection objects.
//!
//! One `HostConnection` per `Host` (localhost, ssh remote, k8s
//! cluster).  The connection owns whatever state is needed to talk
//! to that host:
//!
//! * `Localhost`: nothing.  Always considered up.
//! * `Ssh`: direct `ssh ... docker system dial-stdio` probes; Docker
//!   clients create their own SSH-backed transports.
//! * `Kubernetes`: a cached `kube` client.
//!
//! The connection establishes itself lazily.  Callers (typically
//! `Executor::new`) trigger a short liveness probe before using a
//! remote host.  Kubernetes keeps a background monitor task for
//! liveness; SSH deliberately does not, because OpenSSH and the
//! user's SSH config own the transport policy.
//!
//! Connections know nothing about pods or executors.  They emit
//! `HostConnectionEvent`s on a daemon-wide mpsc channel; the daemon
//! is the single reader and decides what to do per pod on
//! `Connected`/`Disconnected` transitions.

use std::collections::HashMap;
use std::ffi::OsString;
use std::process::Stdio;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::async_runtime::RUNTIME;
use crate::config::Host;
use crate::k8s::K8sClient;

/// Identity of a host: collapses `Host::Kubernetes`'s extra fields
/// (registry, builder, node_selector, tolerations) down to what
/// actually determines which API server we are talking to.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HostKey {
    Localhost,
    Ssh { destination: String },
    Kubernetes { context: String, namespace: String },
}

impl HostKey {
    pub fn from_host(host: &Host) -> Self {
        match host {
            Host::Localhost => HostKey::Localhost,
            Host::Ssh { ssh_destination } => HostKey::Ssh {
                destination: ssh_destination.clone(),
            },
            Host::Kubernetes {
                context, namespace, ..
            } => HostKey::Kubernetes {
                context: context.clone(),
                namespace: namespace.clone(),
            },
        }
    }
}

impl std::fmt::Display for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostKey::Localhost => write!(f, "localhost"),
            HostKey::Ssh { destination } => write!(f, "ssh://{destination}"),
            HostKey::Kubernetes { context, namespace } => {
                write!(f, "k8s:{context}/{namespace}")
            }
        }
    }
}

/// Events emitted to the daemon when a connection's state flips.
///
/// `GaveUp` is reserved for a future eviction path (no producer
/// today) so the central reader can already match on it.
#[derive(Debug, Clone)]
pub enum HostConnectionEvent {
    Connected(HostKey),
    Disconnected(HostKey),
    #[allow(dead_code)]
    GaveUp(HostKey),
}

pub type HostConnectionEventTx = mpsc::UnboundedSender<HostConnectionEvent>;
pub type HostConnectionEventRx = mpsc::UnboundedReceiver<HostConnectionEvent>;

/// Daemon-wide registry of host connections, deduplicating by
/// `HostKey`.  All connections share a single mpsc sender so the
/// daemon's central reader can match host events to per-pod state.
pub struct HostConnectionRegistry {
    events_tx: HostConnectionEventTx,
    conns: Mutex<HashMap<HostKey, Arc<HostConnection>>>,
}

impl HostConnectionRegistry {
    pub fn new(events_tx: HostConnectionEventTx) -> Self {
        Self {
            events_tx,
            conns: Mutex::new(HashMap::new()),
        }
    }

    /// Look up an existing connection or build a new one for `host`.
    /// New connections start out down; the caller drives bring-up
    /// via `HostConnection::ensure_connected` (or, more commonly,
    /// `Executor::new`).
    pub fn get_or_create(&self, host: &Host) -> Result<Arc<HostConnection>> {
        let key = HostKey::from_host(host);
        let mut conns = self.conns.lock().unwrap();
        if let Some(c) = conns.get(&key) {
            return Ok(c.clone());
        }
        let conn = Arc::new(HostConnection::new(host, self.events_tx.clone())?);
        conns.insert(key, conn.clone());
        Ok(conn)
    }

    /// Return the connection for `host` without creating one.  Used
    /// by paths like `list_pods` that should not implicitly start
    /// new remote connections.
    pub fn get(&self, host: &Host) -> Option<Arc<HostConnection>> {
        let key = HostKey::from_host(host);
        self.conns.lock().unwrap().get(&key).cloned()
    }

    /// Remove the connection for `host` from the registry.  The
    /// underlying `Arc<HostConnection>` may live on if other Arcs
    /// are held; drop happens when the last reference goes away.
    /// Used by the central reader on `GaveUp` events.
    pub fn remove(&self, key: &HostKey) -> Option<Arc<HostConnection>> {
        self.conns.lock().unwrap().remove(key)
    }
}

/// How often the Kubernetes background monitor verifies liveness
/// and re-attempts bring-up when down.
const HEALTH_INTERVAL: Duration = Duration::from_secs(15);

/// Per-host connection handle, behind `Arc` in the registry.
pub enum HostConnection {
    Localhost(Arc<LocalhostConnection>),
    Ssh(Arc<SshConnection>),
    Kubernetes(Arc<K8sConnection>),
}

impl HostConnection {
    /// Spawn a new connection.  Localhost is trivial and emits a
    /// single `Connected` event; Kubernetes spawns a monitor task.
    /// SSH stays idle until a caller asks for a Docker probe.
    pub fn new(host: &Host, events_tx: HostConnectionEventTx) -> Result<Self> {
        match host {
            Host::Localhost => Ok(HostConnection::Localhost(LocalhostConnection::new(
                events_tx,
            ))),
            Host::Ssh { ssh_destination } => Ok(HostConnection::Ssh(SshConnection::new(
                ssh_destination.clone(),
                events_tx,
            ))),
            Host::Kubernetes {
                context, namespace, ..
            } => Ok(HostConnection::Kubernetes(K8sConnection::new(
                context.clone(),
                namespace.clone(),
                events_tx,
            ))),
        }
    }

    pub fn key(&self) -> HostKey {
        match self {
            HostConnection::Localhost(_) => HostKey::Localhost,
            HostConnection::Ssh(c) => c.key(),
            HostConnection::Kubernetes(c) => c.key(),
        }
    }

    /// Whether the connection currently has a live handle.  Cheap
    /// snapshot; does not attempt to bring the connection up.
    pub fn is_connected(&self) -> bool {
        match self {
            HostConnection::Localhost(_) => true,
            HostConnection::Ssh(c) => c.is_connected(),
            HostConnection::Kubernetes(c) => c.state.lock().unwrap().client.is_some(),
        }
    }

    /// Verify the host connection.  Localhost is trivial, SSH runs a
    /// real dial-stdio ping, and Kubernetes reuses a cached client when
    /// it still answers.
    pub fn ensure_connected(&self) -> Result<()> {
        match self {
            HostConnection::Localhost(_) => Ok(()),
            HostConnection::Ssh(c) => c.ensure_connected(),
            HostConnection::Kubernetes(c) => c.ensure_client().map(|_| ()),
        }
    }
}

/// Aborts the held tokio task on drop so monitors are torn down
/// when the connection is dropped from the registry.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ============================================================
// Localhost
// ============================================================

pub struct LocalhostConnection {
    // Held only so a future caller can read the events tx if
    // needed; today the constructor uses it once and the field
    // exists to mirror the other variants.
    _events_tx: HostConnectionEventTx,
}

impl LocalhostConnection {
    fn new(events_tx: HostConnectionEventTx) -> Arc<Self> {
        // Emit Connected once so the daemon's reader handles
        // localhost uniformly with the other variants.
        let _ = events_tx.send(HostConnectionEvent::Connected(HostKey::Localhost));
        Arc::new(Self {
            _events_tx: events_tx,
        })
    }
}

// ============================================================
// SSH
// ============================================================

pub struct SshConnection {
    destination: String,
    events_tx: HostConnectionEventTx,
    state: Arc<Mutex<SshState>>,
    /// Serializes demand-driven probes.
    bring_up: Mutex<()>,
}

struct SshState {
    connected: bool,
}

impl SshConnection {
    fn new(destination: String, events_tx: HostConnectionEventTx) -> Arc<Self> {
        Arc::new(SshConnection {
            destination,
            events_tx,
            state: Arc::new(Mutex::new(SshState { connected: false })),
            bring_up: Mutex::new(()),
        })
    }

    pub fn key(&self) -> HostKey {
        HostKey::Ssh {
            destination: self.destination.clone(),
        }
    }

    pub fn is_connected(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.connected
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// Verify that Docker answers through `ssh ... docker system
    /// dial-stdio`.  There is no long-lived proxy for the SSH case, so
    /// each call performs a real probe and updates the daemon's host
    /// connection state from the result.
    pub fn ensure_connected(&self) -> Result<()> {
        let _guard = self.bring_up.lock().unwrap();

        if ping_ssh_docker(&self.destination) {
            let changed = {
                let mut state = self.state.lock().unwrap();
                let changed = !state.connected;
                state.connected = true;
                changed
            };
            if changed {
                let _ = self
                    .events_tx
                    .send(HostConnectionEvent::Connected(self.key()));
            }
            return Ok(());
        }

        mark_disconnected(&self.state, &self.events_tx, &self.key());
        Err(anyhow::anyhow!(
            "SSH Docker transport to {} failed to answer /_ping within {:?}. \
             Check SSH configuration, remote Docker, and Docker socket permissions.",
            self.key(),
            PING_TIMEOUT
        ))
    }
}

fn mark_disconnected(
    state: &Arc<Mutex<SshState>>,
    events_tx: &HostConnectionEventTx,
    key: &HostKey,
) {
    let changed = {
        let mut state = state.lock().unwrap();
        let changed = state.connected;
        state.connected = false;
        changed
    };
    if changed {
        let _ = events_tx.send(HostConnectionEvent::Disconnected(key.clone()));
    }
}

fn ssh_dial_stdio_args(destination: &str) -> Vec<OsString> {
    vec![
        OsString::from("-o"),
        OsString::from("BatchMode=yes"),
        OsString::from(destination),
        OsString::from("docker"),
        OsString::from("system"),
        OsString::from("dial-stdio"),
    ]
}

/// Hard ceiling on the docker `/_ping` round-trip over SSH.
const PING_TIMEOUT: Duration = Duration::from_secs(30);

fn ping_ssh_docker(destination: &str) -> bool {
    let destination = destination.to_string();
    match RUNTIME
        .block_on(async { timeout(PING_TIMEOUT, ping_ssh_docker_inner(destination)).await })
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            debug!("ssh docker ping failed: {e:#}");
            false
        }
        Err(_) => {
            debug!("ssh docker ping timed out after {PING_TIMEOUT:?}");
            false
        }
    }
}

async fn ping_ssh_docker_inner(destination: String) -> Result<()> {
    let mut child = TokioCommand::new("ssh")
        .args(ssh_dial_stdio_args(&destination))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("spawning ssh docker dial-stdio")?;

    let mut stdin = child.stdin.take().context("ssh child stdin missing")?;
    let mut stdout = child.stdout.take().context("ssh child stdout missing")?;

    let request = "GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stdin
        .write_all(request.as_bytes())
        .await
        .context("writing docker ping request")?;
    stdin
        .shutdown()
        .await
        .context("closing docker ping request")?;

    let mut response = [0u8; 256];
    let n = stdout
        .read(&mut response)
        .await
        .context("reading docker ping response")?;
    let status = child.wait().await.context("waiting for ssh docker ping")?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "ssh docker dial-stdio exited with {status}"
        ));
    }
    if n == 0 {
        return Err(anyhow::anyhow!("empty docker ping response"));
    }

    let response_str = String::from_utf8_lossy(&response[..n]);
    if response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(anyhow::anyhow!("unexpected docker ping response"))
    }
}

// ============================================================
// Kubernetes
// ============================================================

pub struct K8sConnection {
    context: String,
    namespace: String,
    events_tx: HostConnectionEventTx,
    state: Mutex<K8sState>,
    bring_up: Mutex<()>,
    _monitor: AbortOnDrop,
}

struct K8sState {
    client: Option<K8sClient>,
}

impl K8sConnection {
    fn new(context: String, namespace: String, events_tx: HostConnectionEventTx) -> Arc<Self> {
        Arc::new_cyclic(|weak: &Weak<K8sConnection>| {
            let weak = weak.clone();
            let task = RUNTIME.spawn(k8s_monitor(weak));
            K8sConnection {
                context,
                namespace,
                events_tx,
                state: Mutex::new(K8sState { client: None }),
                bring_up: Mutex::new(()),
                _monitor: AbortOnDrop(task),
            }
        })
    }

    pub fn key(&self) -> HostKey {
        HostKey::Kubernetes {
            context: self.context.clone(),
            namespace: self.namespace.clone(),
        }
    }

    /// Return a usable `K8sClient`, building one if the connection
    /// is currently down or the cached client no longer answers
    /// the API server.  The returned client is a clone of the
    /// cached one (kube's `Client` is `Clone` and shares the
    /// underlying connection pool).
    pub fn ensure_client(&self) -> Result<K8sClient> {
        let _guard = self.bring_up.lock().unwrap();

        let cached = {
            let state = self.state.lock().unwrap();
            state.client.clone()
        };

        if let Some(client) = cached {
            if check_k8s_alive(&client).is_ok() {
                return Ok(client);
            }
            // Stale client: clear and emit Disconnected.
            self.state.lock().unwrap().client = None;
            let _ = self
                .events_tx
                .send(HostConnectionEvent::Disconnected(self.key()));
        }

        let client =
            K8sClient::new(&self.context, &self.namespace).context("building kube client")?;
        // Cheap probe so we don't cache a client that fails on its
        // first real call.
        check_k8s_alive(&client)?;
        {
            let mut state = self.state.lock().unwrap();
            state.client = Some(client.clone());
        }
        let _ = self
            .events_tx
            .send(HostConnectionEvent::Connected(self.key()));
        Ok(client)
    }
}

/// Background monitor for a k8s connection: a periodic
/// `ensure_client` ping that doubles as liveness check and
/// reconnect attempt.
async fn k8s_monitor(weak: Weak<K8sConnection>) {
    loop {
        tokio::time::sleep(HEALTH_INTERVAL).await;
        let Some(conn) = weak.upgrade() else { return };
        let key = conn.key();
        let conn_clone = conn.clone();
        match tokio::task::spawn_blocking(move || conn_clone.ensure_client()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => debug!("{key}: k8s monitor bring-up failed: {e:#}"),
            Err(e) => debug!("{key}: k8s monitor task join error: {e}"),
        }
    }
}

/// Cheap synchronous liveness check for a `K8sClient`.
fn check_k8s_alive(client: &K8sClient) -> Result<()> {
    crate::async_runtime::block_on(check_k8s_alive_async(client))
}

async fn check_k8s_alive_async(client: &K8sClient) -> Result<()> {
    let fut = client.client().apiserver_version();
    timeout(Duration::from_secs(5), fut)
        .await
        .context("apiserver version timed out")?
        .context("apiserver version failed")?;
    Ok(())
}

#[cfg(test)]
fn args_to_strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect()
}

#[cfg(test)]
mod ssh_tests {
    use super::*;

    fn assert_no_rumpelpod_ssh_policy(args: &[String]) {
        let joined = args.join(" ");
        for forbidden in [
            "ControlPath",
            "ControlMaster",
            "ControlPersist",
            "ServerAliveInterval",
            "ServerAliveCountMax",
        ] {
            assert!(
                !joined.contains(forbidden),
                "ssh args should not include {forbidden}: {joined}"
            );
        }
    }

    #[test]
    fn ssh_args_do_not_include_port() {
        let args = args_to_strings(&ssh_dial_stdio_args("dev"));

        assert_eq!(
            args,
            vec![
                "-o",
                "BatchMode=yes",
                "dev",
                "docker",
                "system",
                "dial-stdio"
            ]
        );
        assert_no_rumpelpod_ssh_policy(&args);
        assert!(!args.iter().any(|arg| arg == "-p"));
    }
}
