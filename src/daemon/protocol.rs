//! RPC protocol between the rumpel CLI and the daemon.
//!
//! Both sides are always the same rumpel binary, so these types do not
//! need serde defaults, deny_unknown_fields, or any other backwards-
//! compatibility machinery.  Treat changes as a regular Rust API: add
//! or remove fields freely and let the compiler catch all call sites.

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::serve::Listener;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::task::block_in_place;
use tokio_stream::StreamExt;
use url::Url;

use crate::async_runtime::block_on;
use crate::config::Host;
use crate::daemon::reconnect::ReconnectEvent;
use crate::devcontainer::DevContainer;
use crate::git::GitIdentity;
use crate::image::OutputLine;

/// Opaque wrapper for docker image names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image(pub String);

/// Opaque wrapper for container IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerId(pub String);

/// Result of launching a pod.
#[derive(Debug, Clone)]
pub struct LaunchResult {
    pub container_id: ContainerId,
    /// The resolved user for the pod. This is either the user specified in the config,
    /// or the user from the image's USER directive.
    pub user: String,
    /// The Docker socket path to use for connecting to the Docker daemon.
    /// `None` for Kubernetes pods (which use kubectl instead of docker).
    pub docker_socket: Option<std::path::PathBuf>,
    /// The host where the pod is running.
    pub host: Host,
    /// Whether a devcontainer image was built during this launch.
    /// False when the image was already cached or when using a pre-built image.
    pub image_built: bool,
    /// Environment variables captured by probing the user's shell init files.
    /// Only contains vars that differ from the base container environment.
    pub probed_env: HashMap<String, String>,
    /// The container user's login shell (e.g. "/bin/bash", "/bin/zsh").
    /// Falls back to "/bin/sh" if it cannot be determined.
    pub user_shell: String,
    /// Base URL of the in-container HTTP server (e.g. "http://172.17.0.2:7890").
    pub container_url: String,
    /// Bearer token for authenticating requests to the in-container HTTP server.
    pub container_token: String,
}

/// Human-readable pod name to distinguish multiple pods for the same repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodName(pub String);

/// Status of a pod container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PodStatus {
    Running,
    Stopped,
    /// Container no longer exists (was deleted outside of rumpel)
    Gone,
    /// Remote pod where we don't have a connection to check actual status
    Disconnected,
    /// Container is being stopped in the background
    Stopping,
    /// Container is being deleted in the background
    Deleting,
    /// Background deletion failed after all retries
    Broken,
}

/// Information about a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInfo {
    pub name: String,
    pub status: PodStatus,
    pub created: String,
    /// Host where the pod runs: "local" or an SSH URL like "user@host:port".
    pub host: String,
    /// State of the repository in the pod (e.g. "ahead 1, behind 2").
    pub repo_state: Option<String>,
    /// Docker container ID of the pod (short 12-char hex), if known.
    pub container_id: Option<String>,
    /// Committer timestamp (unix seconds) of the tip of the pod's primary branch on the host.
    pub last_commit_time: Option<i64>,
}

/// Information about a forwarded port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub container_port: u16,
    pub local_port: u16,
    pub label: String,
}

/// Everything the daemon needs to launch or recreate a pod.
///
/// Contains the devcontainer.json config (with `${localEnv:...}` already
/// resolved and build paths normalized to repo-root-relative by the client)
/// plus a few fields that don't come from devcontainer.json.
#[derive(Debug, Serialize, Deserialize)]
pub struct PodLaunchParams {
    pub pod_name: PodName,
    /// Host-side path to the git repository.
    pub repo_path: PathBuf,
    /// The branch currently checked out on the host, if any.
    /// Used to set the upstream of the primary branch in the pod.
    pub host_branch: Option<String>,
    /// Where the pod runs: localhost, a remote SSH host, or Kubernetes.
    pub host: Host,
    /// The devcontainer.json config, with `${localEnv:...}` already resolved
    /// and build paths normalized to repo-root-relative.
    pub devcontainer: DevContainer,
    /// Git user identity from the host, to be written into the pod's .git/config.
    pub git_identity: Option<GitIdentity>,
    /// Absolute path to the Claude CLI binary on the host, resolved by the
    /// client so the daemon does not depend on its own PATH.
    pub claude_cli_path: Option<PathBuf>,
}

/// Response body for launch/recreate pod endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct PodLaunchResponse {
    pub container_id: ContainerId,
    /// The resolved user for the pod.
    pub user: String,
    /// The Docker socket path to use for connecting to the Docker daemon.
    /// `None` for Kubernetes pods.
    pub docker_socket: Option<PathBuf>,
    /// The host where the pod is running.
    pub host: Host,
    /// Whether a devcontainer image was built during this launch.
    pub image_built: bool,
    /// Environment variables captured by probing the user's shell init files.
    pub probed_env: HashMap<String, String>,
    pub user_shell: String,
    pub container_url: String,
    pub container_token: String,
}

/// Request body for stop_pod endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct StopPodRequest {
    pod_name: PodName,
    repo_path: PathBuf,
    wait: bool,
}

/// Response body for stop_pod endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct StopPodResponse {
    stopped: bool,
}

/// Request body for delete_pod endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct DeletePodRequest {
    pod_name: PodName,
    repo_path: PathBuf,
    wait: bool,
}

/// Response body for delete_pod endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct DeletePodResponse {
    deleted: bool,
}

/// Request body for list_pods endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct ListPodsRequest {
    repo_path: PathBuf,
}

/// Response body for list_pods endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct ListPodsResponse {
    pods: Vec<PodInfo>,
}

/// Request body for list_ports endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct ListPortsRequest {
    pod_name: PodName,
    repo_path: PathBuf,
}

/// Response body for list_ports endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct ListPortsResponse {
    ports: Vec<PortInfo>,
}

/// Request body for ssh_add_key endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct SshAddKeyRequest {
    pod_name: PodName,
    repo_path: PathBuf,
    key_path: PathBuf,
}

/// Response body for ssh_add_key endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct SshAddKeyResponse {
    message: String,
}

/// Request body for ssh_list_keys endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct SshListKeysRequest {
    pod_name: PodName,
    repo_path: PathBuf,
}

/// Response body for ssh_list_keys endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct SshListKeysResponse {
    keys: String,
}

/// Request body for save_conversation endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct SaveConversationRequest {
    /// If present, update existing conversation; otherwise create new.
    pub id: Option<i64>,
    pub repo_path: PathBuf,
    pub pod_name: String,
    pub model: String,
    pub provider: String,
    pub history: serde_json::Value,
}

/// Response body for save_conversation endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct SaveConversationResponse {
    pub id: i64,
}

/// Request body for list_conversations endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListConversationsRequest {
    pub repo_path: PathBuf,
    pub pod_name: String,
}

/// Summary of a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub id: i64,
    pub model: String,
    pub provider: String,
    pub updated_at: String,
}

/// Response body for list_conversations endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListConversationsResponse {
    pub conversations: Vec<ConversationSummary>,
}

/// Response body for get_conversation endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetConversationResponse {
    pub model: String,
    pub provider: String,
    pub history: serde_json::Value,
}

/// Request body for ensure_claude_config endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnsureClaudeConfigRequest {
    pub pod_name: PodName,
    pub repo_path: PathBuf,
    pub container_repo_path: PathBuf,
    pub container_id: ContainerId,
    pub user: String,
    /// The Docker socket path. `None` for Kubernetes pods.
    pub docker_socket: Option<PathBuf>,
    pub container_url: String,
    pub container_token: String,
    /// Install a Claude PermissionRequest hook that auto-approves all tool use.
    pub auto_approve_hook: bool,
}

/// Request body for the host reconnect-events SSE endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct HostReconnectRequest {
    pub host: Host,
}

/// Request body for the pod reconnect-events SSE endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct PodReconnectRequest {
    pub repo_path: PathBuf,
    pub pod_name: String,
}

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Progress handle for a launch/recreate operation.
///
/// Yields build-output lines via `Iterator::next()` and returns the final
/// result from `finish()`.  Implementations exist for the server side
/// (thread-backed), the client side (SSE-backed), and tests (immediate).
pub trait LaunchProgress: Iterator<Item = OutputLine> + Send {
    /// Drain remaining output and return the final result.
    fn finish(self) -> Result<LaunchResult>;
}

/// Trivial `LaunchProgress` that yields no build output -- just wraps a
/// pre-computed result.  Used by mocks and tests.
pub struct ImmediateLaunchProgress(Option<Result<LaunchResult>>);

impl ImmediateLaunchProgress {
    pub fn new(result: Result<LaunchResult>) -> Self {
        Self(Some(result))
    }
}

impl Iterator for ImmediateLaunchProgress {
    type Item = OutputLine;
    fn next(&mut self) -> Option<OutputLine> {
        None
    }
}

impl LaunchProgress for ImmediateLaunchProgress {
    fn finish(mut self) -> Result<LaunchResult> {
        self.0
            .take()
            .expect("finish() called twice on ImmediateLaunchProgress")
    }
}

pub trait Daemon: Send + Sync + 'static {
    type Progress: LaunchProgress;

    // PUT /pod
    fn launch_pod(&self, params: PodLaunchParams) -> Result<Self::Progress>;

    // POST /pod/recreate
    fn recreate_pod(&self, params: PodLaunchParams) -> Result<Self::Progress>;

    // POST /pod/stop
    // Stops a pod container without removing it.  When wait is true, blocks
    // until the container is fully stopped; otherwise returns immediately.
    fn stop_pod(&self, pod_name: PodName, repo_path: PathBuf, wait: bool) -> Result<()>;

    // DELETE /pod
    // Stops and removes a pod container.  When wait is true, blocks until the
    // container is fully removed; otherwise returns immediately.
    fn delete_pod(&self, pod_name: PodName, repo_path: PathBuf, wait: bool) -> Result<()>;

    // GET /pod
    // Lists all pods for a given repository.
    fn list_pods(&self, repo_path: PathBuf) -> Result<Vec<PodInfo>>;

    // GET /pod/ports
    fn list_ports(&self, pod_name: PodName, repo_path: PathBuf) -> Result<Vec<PortInfo>>;

    // POST /conversation
    // Save or update a conversation.
    fn save_conversation(
        &self,
        id: Option<i64>,
        repo_path: PathBuf,
        pod_name: String,
        model: String,
        provider: String,
        history: serde_json::Value,
    ) -> Result<i64>;

    // GET /conversations
    // List all conversations for a pod.
    fn list_conversations(
        &self,
        repo_path: PathBuf,
        pod_name: String,
    ) -> Result<Vec<ConversationSummary>>;

    // GET /conversation/<id>
    // Get a conversation by ID.
    fn get_conversation(&self, id: i64) -> Result<Option<GetConversationResponse>>;

    // PUT /pod/claude-config
    // Ensure Claude Code config files are present in the container.
    // Idempotent: skips the copy if it has already been done for this pod.
    fn ensure_claude_config(&self, request: EnsureClaudeConfigRequest) -> Result<()>;

    // POST /pod/ssh-add
    // Add an SSH private key to the pod's host-side ssh-agent.
    fn ssh_add_key(
        &self,
        pod_name: PodName,
        repo_path: PathBuf,
        key_path: PathBuf,
    ) -> Result<String>;

    // GET /pod/ssh-keys
    // List SSH keys loaded in the pod's host-side ssh-agent.
    fn ssh_list_keys(&self, pod_name: PodName, repo_path: PathBuf) -> Result<String>;

    // POST /host/reconnect-events
    // Subscribe to reconnection events for a remote host (SSH tunnel).
    // Returns None for hosts that do not support reconnection (e.g. localhost).
    fn subscribe_host_reconnect(
        &self,
        _host: &Host,
    ) -> Option<tokio::sync::broadcast::Receiver<ReconnectEvent>> {
        None
    }

    // POST /pod/reconnect-events
    // Subscribe to reconnection events for a pod.
    // Returns None if no event listener is active for the pod.
    fn subscribe_pod_reconnect(
        &self,
        _repo_path: &Path,
        _pod_name: &str,
    ) -> Option<tokio::sync::broadcast::Receiver<ReconnectEvent>> {
        None
    }
}

pub struct DaemonClient {
    client: reqwest::blocking::Client,
    /// Base URL for HTTP requests. For Unix sockets, use any valid URL
    /// (the host is ignored since the socket path is set on the client).
    url: Url,
}

impl DaemonClient {
    /// Create a client that connects via TCP to the given URL.
    #[allow(dead_code)]
    pub fn new(url: Url) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(None)
            .build()
            .expect("Failed to build reqwest client");
        Self { client, url }
    }

    /// Create a client that connects via Unix domain socket.
    #[allow(dead_code)]
    pub fn new_unix(socket_path: &Path) -> Self {
        let client = reqwest::blocking::Client::builder()
            .unix_socket(socket_path)
            .timeout(None)
            .build()
            .expect("Failed to build reqwest client");
        // URL host is ignored for Unix sockets, but we need a valid URL
        let url = Url::parse("http://localhost").unwrap();
        Self { client, url }
    }
}

/// SSE-backed `LaunchProgress` for the HTTP client side.
///
/// Parses `event: build_stdout` / `event: build_stderr` / `event: result` /
/// `event: error` lines from a `text/event-stream` response.
pub struct ClientLaunchProgress {
    lines: std::io::Lines<BufReader<reqwest::blocking::Response>>,
    result: Option<Result<LaunchResult>>,
}

impl ClientLaunchProgress {
    fn new(response: reqwest::blocking::Response) -> Self {
        Self {
            lines: BufReader::new(response).lines(),
            result: None,
        }
    }
}

impl Iterator for ClientLaunchProgress {
    type Item = OutputLine;

    fn next(&mut self) -> Option<OutputLine> {
        // SSE format: "event: <type>\ndata: <json>\n\n"
        // We need to read event + data line pairs.
        loop {
            let line = match self.lines.next()? {
                Ok(l) => l,
                Err(e) => {
                    self.result = Some(Err(anyhow::anyhow!("Failed to read response stream: {e}")));
                    return None;
                }
            };

            // Skip blank lines (SSE record separator)
            if line.is_empty() {
                continue;
            }

            let event_type = match line.strip_prefix("event: ") {
                Some(t) => t.to_string(),
                None => continue,
            };

            // Read the "data: ..." line
            let data_line = match self.lines.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => {
                    self.result = Some(Err(anyhow::anyhow!("Failed to read data line: {e}")));
                    return None;
                }
                None => {
                    self.result = Some(Err(anyhow::anyhow!(
                        "Stream ended mid-event (no data line)"
                    )));
                    return None;
                }
            };

            let data = match data_line.strip_prefix("data: ") {
                Some(d) => d,
                None => {
                    self.result = Some(Err(anyhow::anyhow!(
                        "Expected 'data: ' line, got: {data_line}"
                    )));
                    return None;
                }
            };

            match event_type.as_str() {
                "build_stdout" | "build_stderr" => {
                    // data is a JSON-encoded string
                    match serde_json::from_str::<String>(data) {
                        Ok(s) => {
                            if event_type == "build_stdout" {
                                return Some(OutputLine::Stdout(s));
                            } else {
                                return Some(OutputLine::Stderr(s));
                            }
                        }
                        Err(e) => {
                            self.result = Some(Err(anyhow::anyhow!(
                                "Failed to parse build output data: {e}"
                            )));
                            return None;
                        }
                    }
                }
                "result" => {
                    match serde_json::from_str::<PodLaunchResponse>(data) {
                        Ok(body) => {
                            self.result = Some(Ok(LaunchResult {
                                container_id: body.container_id,
                                user: body.user,
                                docker_socket: body.docker_socket,
                                host: body.host,
                                image_built: body.image_built,
                                probed_env: body.probed_env,
                                user_shell: body.user_shell,
                                container_url: body.container_url,
                                container_token: body.container_token,
                            }));
                        }
                        Err(e) => {
                            self.result =
                                Some(Err(anyhow::anyhow!("Failed to parse result data: {e}")));
                        }
                    }
                    return None;
                }
                "error" => {
                    match serde_json::from_str::<ErrorResponse>(data) {
                        Ok(err) => {
                            let msg = &err.error;
                            self.result = Some(Err(anyhow::anyhow!("Server error: {msg}")));
                        }
                        Err(e) => {
                            self.result =
                                Some(Err(anyhow::anyhow!("Failed to parse error data: {e}")));
                        }
                    }
                    return None;
                }
                other => {
                    self.result = Some(Err(anyhow::anyhow!("Unknown SSE event type: {other}")));
                    return None;
                }
            }
        }
    }
}

impl LaunchProgress for ClientLaunchProgress {
    fn finish(mut self) -> Result<LaunchResult> {
        // Drain any remaining build output
        while self.next().is_some() {}

        self.result.unwrap_or_else(|| {
            Err(anyhow::anyhow!(
                "Server closed stream without sending a result"
            ))
        })
    }
}

impl Daemon for DaemonClient {
    type Progress = ClientLaunchProgress;

    fn launch_pod(&self, params: PodLaunchParams) -> Result<ClientLaunchProgress> {
        let url = self.url.join("/pod")?;

        let response = self
            .client
            .put(url)
            .json(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        Ok(ClientLaunchProgress::new(response))
    }

    fn recreate_pod(&self, params: PodLaunchParams) -> Result<ClientLaunchProgress> {
        let url = self.url.join("/pod/recreate")?;

        let response = self
            .client
            .post(url)
            .json(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        Ok(ClientLaunchProgress::new(response))
    }

    fn stop_pod(&self, pod_name: PodName, repo_path: PathBuf, wait: bool) -> Result<()> {
        let url = self.url.join("/pod/stop")?;
        let request = StopPodRequest {
            pod_name,
            repo_path,
            wait,
        };

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn delete_pod(&self, pod_name: PodName, repo_path: PathBuf, wait: bool) -> Result<()> {
        let url = self.url.join("/pod")?;
        let request = DeletePodRequest {
            pod_name,
            repo_path,
            wait,
        };

        let response = self
            .client
            .delete(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn list_pods(&self, repo_path: PathBuf) -> Result<Vec<PodInfo>> {
        let url = self.url.join("/pod")?;
        let request = ListPodsRequest { repo_path };

        let response = self
            .client
            .get(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            let body: ListPodsResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(body.pods)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn list_ports(&self, pod_name: PodName, repo_path: PathBuf) -> Result<Vec<PortInfo>> {
        let url = self.url.join("/pod/ports")?;
        let request = ListPortsRequest {
            pod_name,
            repo_path,
        };

        let response = self
            .client
            .get(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            let body: ListPortsResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(body.ports)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn save_conversation(
        &self,
        id: Option<i64>,
        repo_path: PathBuf,
        pod_name: String,
        model: String,
        provider: String,
        history: serde_json::Value,
    ) -> Result<i64> {
        let url = self.url.join("/conversation")?;
        let request = SaveConversationRequest {
            id,
            repo_path,
            pod_name,
            model,
            provider,
            history,
        };

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            let body: SaveConversationResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(body.id)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn list_conversations(
        &self,
        repo_path: PathBuf,
        pod_name: String,
    ) -> Result<Vec<ConversationSummary>> {
        let url = self.url.join("/conversations")?;
        let request = ListConversationsRequest {
            repo_path,
            pod_name,
        };

        let response = self
            .client
            .get(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            let body: ListConversationsResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(body.conversations)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn get_conversation(&self, id: i64) -> Result<Option<GetConversationResponse>> {
        let url = self.url.join(&format!("/conversation/{id}"))?;

        let response = self
            .client
            .get(url)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if response.status().is_success() {
            let body: GetConversationResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(Some(body))
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn ensure_claude_config(&self, request: EnsureClaudeConfigRequest) -> Result<()> {
        let url = self.url.join("/pod/claude-config")?;

        let response = self
            .client
            .put(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn ssh_add_key(
        &self,
        pod_name: PodName,
        repo_path: PathBuf,
        key_path: PathBuf,
    ) -> Result<String> {
        let url = self.url.join("/pod/ssh-add")?;
        let request = SshAddKeyRequest {
            pod_name,
            repo_path,
            key_path,
        };

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            let body: SshAddKeyResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(body.message)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }

    fn ssh_list_keys(&self, pod_name: PodName, repo_path: PathBuf) -> Result<String> {
        let url = self.url.join("/pod/ssh-keys")?;
        let request = SshListKeysRequest {
            pod_name,
            repo_path,
        };

        let response = self
            .client
            .get(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if response.status().is_success() {
            let body: SshListKeysResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;
            Ok(body.keys)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            Err(anyhow::anyhow!("Server error: {msg}"))
        }
    }
}

impl DaemonClient {
    /// Subscribe to host-level (SSH tunnel) reconnection events.
    pub fn reconnect_events(&self, host: &Host) -> Result<ReconnectStream> {
        let url = self.url.join("/host/reconnect-events")?;
        let request = HostReconnectRequest { host: host.clone() };

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            return Err(anyhow::anyhow!(
                "reconnect endpoint returned {status}: {msg}"
            ));
        }

        Ok(ReconnectStream::new(response))
    }

    /// Subscribe to pod-level reconnection events (SSH + pod).
    pub fn pod_reconnect_events(
        &self,
        repo_path: &Path,
        pod_name: &str,
    ) -> Result<ReconnectStream> {
        let url = self.url.join("/pod/reconnect-events")?;
        let request = PodReconnectRequest {
            repo_path: repo_path.to_path_buf(),
            pod_name: pod_name.to_string(),
        };

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            let msg = &error.error;
            return Err(anyhow::anyhow!(
                "reconnect endpoint returned {status}: {msg}"
            ));
        }

        Ok(ReconnectStream::new(response))
    }
}

/// SSE-backed iterator over `ReconnectEvent`s from the daemon.
pub struct ReconnectStream {
    lines: std::io::Lines<BufReader<reqwest::blocking::Response>>,
}

impl ReconnectStream {
    fn new(response: reqwest::blocking::Response) -> Self {
        Self {
            lines: BufReader::new(response).lines(),
        }
    }
}

impl Iterator for ReconnectStream {
    type Item = Result<ReconnectEvent>;

    fn next(&mut self) -> Option<Result<ReconnectEvent>> {
        loop {
            let line = match self.lines.next()? {
                Ok(l) => l,
                Err(e) => return Some(Err(anyhow::anyhow!("Failed to read event stream: {e}"))),
            };

            if line.is_empty() {
                continue;
            }

            let event_type = match line.strip_prefix("event: ") {
                Some(t) => t.to_string(),
                None => continue,
            };

            let data_line = match self.lines.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => return Some(Err(anyhow::anyhow!("Failed to read data line: {e}"))),
                None => {
                    return Some(Err(anyhow::anyhow!(
                        "Stream ended mid-event (no data line)"
                    )))
                }
            };

            let data = match data_line.strip_prefix("data: ") {
                Some(d) => d,
                None => {
                    return Some(Err(anyhow::anyhow!(
                        "Expected 'data: ' line, got: {data_line}"
                    )))
                }
            };

            match event_type.as_str() {
                "attempting" => return Some(Ok(ReconnectEvent::Attempting)),
                "host_connected" => return Some(Ok(ReconnectEvent::HostConnected)),
                "connected" => return Some(Ok(ReconnectEvent::Connected)),
                "stopped" => return Some(Ok(ReconnectEvent::Stopped)),
                "failed" => {
                    #[derive(Deserialize)]
                    struct FailedData {
                        error: String,
                    }
                    match serde_json::from_str::<FailedData>(data) {
                        Ok(f) => return Some(Ok(ReconnectEvent::Failed { error: f.error })),
                        Err(e) => {
                            return Some(Err(anyhow::anyhow!(
                                "Failed to parse failed event data: {e}"
                            )))
                        }
                    }
                }
                other => return Some(Err(anyhow::anyhow!("Unknown SSE event type: {other}"))),
            }
        }
    }
}

/// Format a single SSE event with the given type and JSON-encoded data.
fn sse_event(event_type: &str, data: &str) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}

/// Build an SSE streaming response for launch/recreate endpoints.
///
/// Spawns a blocking task that calls `op()` to get a `LaunchProgress`,
/// iterates build output lines (sending each as `event: build_stdout` or
/// `event: build_stderr`),
/// then calls `finish()` and sends `event: result` or `event: error`.
fn streaming_launch_response<D: Daemon>(
    daemon: Arc<D>,
    params: PodLaunchParams,
    op: fn(&D, PodLaunchParams) -> Result<D::Progress>,
) -> Response {
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<String>(64);

    tokio::task::spawn_blocking(move || {
        let mut progress = match op(&daemon, params) {
            Ok(p) => p,
            Err(e) => {
                let msg = sse_event(
                    "error",
                    &serde_json::to_string(&ErrorResponse {
                        error: format!("{e:#}"),
                    })
                    .expect("ErrorResponse is always serializable"),
                );
                let _ = event_tx.blocking_send(msg);
                return;
            }
        };

        // Stream build output lines
        for line in &mut progress {
            let (event_type, text) = match line {
                OutputLine::Stdout(s) => ("build_stdout", s),
                OutputLine::Stderr(s) => ("build_stderr", s),
            };
            let json_str = serde_json::to_string(&text).expect("String is always serializable");
            let msg = sse_event(event_type, &json_str);
            if event_tx.blocking_send(msg).is_err() {
                return;
            }
        }

        // Send final result
        let msg = match progress.finish() {
            Ok(r) => sse_event(
                "result",
                &serde_json::to_string(&PodLaunchResponse {
                    container_id: r.container_id,
                    user: r.user,
                    docker_socket: r.docker_socket,
                    host: r.host,
                    image_built: r.image_built,
                    probed_env: r.probed_env,
                    user_shell: r.user_shell,
                    container_url: r.container_url,
                    container_token: r.container_token,
                })
                .expect("PodLaunchResponse is always serializable"),
            ),
            Err(e) => sse_event(
                "error",
                &serde_json::to_string(&ErrorResponse {
                    error: format!("{e:#}"),
                })
                .expect("ErrorResponse is always serializable"),
            ),
        };
        let _ = event_tx.blocking_send(msg);
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(event_rx)
        .map(Ok::<_, std::convert::Infallible>);

    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("building response never fails")
}

/// Handler for PUT /pod endpoint.
async fn launch_pod_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(params): Json<PodLaunchParams>,
) -> Response {
    streaming_launch_response(daemon, params, D::launch_pod)
}

/// Handler for POST /pod/recreate endpoint.
async fn recreate_pod_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(params): Json<PodLaunchParams>,
) -> Response {
    streaming_launch_response(daemon, params, D::recreate_pod)
}

/// Handler for POST /pod/stop endpoint.
async fn stop_pod_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<StopPodRequest>,
) -> Result<Json<StopPodResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result =
        block_in_place(|| daemon.stop_pod(request.pod_name, request.repo_path, request.wait));

    match result {
        Ok(()) => Ok(Json(StopPodResponse { stopped: true })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for DELETE /pod endpoint.
async fn delete_pod_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<DeletePodRequest>,
) -> Result<Json<DeletePodResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result =
        block_in_place(|| daemon.delete_pod(request.pod_name, request.repo_path, request.wait));

    match result {
        Ok(()) => Ok(Json(DeletePodResponse { deleted: true })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for GET /pod endpoint.
async fn list_pods_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<ListPodsRequest>,
) -> Result<Json<ListPodsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.list_pods(request.repo_path));

    match result {
        Ok(pods) => Ok(Json(ListPodsResponse { pods })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for GET /pod/ports endpoint.
async fn list_ports_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<ListPortsRequest>,
) -> Result<Json<ListPortsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.list_ports(request.pod_name, request.repo_path));

    match result {
        Ok(ports) => Ok(Json(ListPortsResponse { ports })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for POST /conversation endpoint.
async fn save_conversation_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<SaveConversationRequest>,
) -> Result<Json<SaveConversationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| {
        daemon.save_conversation(
            request.id,
            request.repo_path,
            request.pod_name,
            request.model,
            request.provider,
            request.history,
        )
    });

    match result {
        Ok(id) => Ok(Json(SaveConversationResponse { id })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for GET /conversations endpoint.
async fn list_conversations_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<ListConversationsRequest>,
) -> Result<Json<ListConversationsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.list_conversations(request.repo_path, request.pod_name));

    match result {
        Ok(conversations) => Ok(Json(ListConversationsResponse { conversations })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for GET /conversation/<id> endpoint.
async fn get_conversation_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<GetConversationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.get_conversation(id));

    match result {
        Ok(Some(conversation)) => Ok(Json(conversation)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Conversation {id} not found"),
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for PUT /pod/claude-config endpoint.
async fn ensure_claude_config_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<EnsureClaudeConfigRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.ensure_claude_config(request));

    match result {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for POST /pod/ssh-add endpoint.
async fn ssh_add_key_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<SshAddKeyRequest>,
) -> Result<Json<SshAddKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| {
        daemon.ssh_add_key(request.pod_name, request.repo_path, request.key_path)
    });

    match result {
        Ok(message) => Ok(Json(SshAddKeyResponse { message })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Handler for GET /pod/ssh-keys endpoint.
async fn ssh_list_keys_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<SshListKeysRequest>,
) -> Result<Json<SshListKeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.ssh_list_keys(request.pod_name, request.repo_path));

    match result {
        Ok(keys) => Ok(Json(SshListKeysResponse { keys })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{e:#}"),
            }),
        )),
    }
}

/// Build an SSE response from a broadcast receiver of reconnect events.
fn reconnect_sse_response(rx: tokio::sync::broadcast::Receiver<ReconnectEvent>) -> Response {
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<String>(64);

    tokio::spawn(async move {
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let is_terminal =
                        matches!(event, ReconnectEvent::Connected | ReconnectEvent::Stopped);
                    let (event_type, data) = match &event {
                        ReconnectEvent::Attempting => ("attempting", "{}".to_string()),
                        ReconnectEvent::HostConnected => ("host_connected", "{}".to_string()),
                        ReconnectEvent::Connected => ("connected", "{}".to_string()),
                        ReconnectEvent::Failed { error } => (
                            "failed",
                            serde_json::to_string(&serde_json::json!({ "error": error }))
                                .expect("json object is always serializable"),
                        ),
                        ReconnectEvent::Stopped => ("stopped", "{}".to_string()),
                    };
                    let msg = sse_event(event_type, &data);
                    if event_tx.send(msg).await.is_err() {
                        break;
                    }
                    if is_terminal {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(event_rx)
        .map(Ok::<_, std::convert::Infallible>);

    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("building response never fails")
}

fn reconnect_not_available(msg: &str) -> Response {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&ErrorResponse {
                error: msg.to_string(),
            })
            .expect("ErrorResponse is always serializable"),
        ))
        .expect("building response never fails")
}

/// Handler for POST /host/reconnect-events endpoint.
async fn host_reconnect_events_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<HostReconnectRequest>,
) -> Response {
    match daemon.subscribe_host_reconnect(&request.host) {
        Some(rx) => reconnect_sse_response(rx),
        None => reconnect_not_available("Host does not support reconnection"),
    }
}

/// Handler for POST /pod/reconnect-events endpoint.
///
/// When no event listener is active the pod was already stopped (or
/// never started).  Return a single `Stopped` event so the client
/// exits instead of retrying forever.
async fn pod_reconnect_events_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<PodReconnectRequest>,
) -> Response {
    match daemon.subscribe_pod_reconnect(&request.repo_path, &request.pod_name) {
        Some(rx) => reconnect_sse_response(rx),
        None => {
            let (tx, rx) = tokio::sync::broadcast::channel(1);
            let _ = tx.send(ReconnectEvent::Stopped);
            reconnect_sse_response(rx)
        }
    }
}

/// Serve the daemon using the provided listener.
///
/// The listener can be a `tokio::net::TcpListener` or `tokio::net::UnixListener`.
pub fn serve_daemon<D, L>(daemon: D, listener: L) -> !
where
    D: Daemon,
    L: Listener,
    L::Addr: Debug + Send,
    L::Io: Send,
{
    serve_daemon_until(daemon, listener, std::future::pending());
    unreachable!("Server shut down unexpectedly")
}

/// Serve the daemon until the shutdown signal completes.
fn serve_daemon_until<D, L, F>(daemon: D, listener: L, shutdown: F)
where
    D: Daemon,
    L: Listener,
    L::Addr: Debug + Send,
    L::Io: Send,
    F: Future<Output = ()> + Send + 'static,
{
    let daemon = Arc::new(daemon);

    let app = Router::new()
        .route("/pod", put(launch_pod_handler::<D>))
        .route("/pod/recreate", post(recreate_pod_handler::<D>))
        .route("/pod/stop", post(stop_pod_handler::<D>))
        .route("/pod", delete(delete_pod_handler::<D>))
        .route("/pod", get(list_pods_handler::<D>))
        .route("/pod/ports", get(list_ports_handler::<D>))
        .route("/conversation", post(save_conversation_handler::<D>))
        .route("/conversations", get(list_conversations_handler::<D>))
        .route("/conversation/{id}", get(get_conversation_handler::<D>))
        .route("/pod/claude-config", put(ensure_claude_config_handler::<D>))
        .route("/pod/ssh-add", post(ssh_add_key_handler::<D>))
        .route("/pod/ssh-keys", get(ssh_list_keys_handler::<D>))
        .route(
            "/host/reconnect-events",
            post(host_reconnect_events_handler::<D>),
        )
        .route(
            "/pod/reconnect-events",
            post(pod_reconnect_events_handler::<D>),
        )
        .with_state(daemon);

    block_on(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .unwrap();
    });
}
