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
use crate::config::DockerHost;
use crate::devcontainer::DevContainer;

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
    /// Clients must use this socket for all Docker operations on this pod.
    pub docker_socket: std::path::PathBuf,
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
    /// Where the Docker daemon lives: localhost or a remote SSH host.
    pub docker_host: DockerHost,
    /// The devcontainer.json config, with `${localEnv:...}` already resolved
    /// and build paths normalized to repo-root-relative.
    pub devcontainer: DevContainer,
}

/// Response body for launch/recreate pod endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct PodLaunchResponse {
    pub container_id: ContainerId,
    /// The resolved user for the pod.
    pub user: String,
    /// The Docker socket path to use for connecting to the Docker daemon.
    pub docker_socket: PathBuf,
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
    pub docker_socket: PathBuf,
    pub container_url: String,
    pub container_token: String,
    /// Install a Claude PermissionRequest hook that auto-approves all tool use.
    pub auto_approve_hook: bool,
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
pub trait LaunchProgress: Iterator<Item = String> + Send {
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
    type Item = String;
    fn next(&mut self) -> Option<String> {
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
    // Stops a pod container without removing it.
    fn stop_pod(&self, pod_name: PodName, repo_path: PathBuf) -> Result<()>;

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
/// Parses `event: build_output` / `event: result` / `event: error` lines
/// from a `text/event-stream` response.
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
    type Item = String;

    fn next(&mut self) -> Option<String> {
        // SSE format: "event: <type>\ndata: <json>\n\n"
        // We need to read event + data line pairs.
        loop {
            let line = match self.lines.next()? {
                Ok(l) => l,
                Err(e) => {
                    self.result = Some(Err(anyhow::anyhow!(
                        "Failed to read response stream: {}",
                        e
                    )));
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
                    self.result = Some(Err(anyhow::anyhow!("Failed to read data line: {}", e)));
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
                        "Expected 'data: ' line, got: {}",
                        data_line
                    )));
                    return None;
                }
            };

            match event_type.as_str() {
                "build_output" => {
                    // data is a JSON-encoded string
                    match serde_json::from_str::<String>(data) {
                        Ok(s) => return Some(s),
                        Err(e) => {
                            self.result = Some(Err(anyhow::anyhow!(
                                "Failed to parse build_output data: {}",
                                e
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
                                image_built: body.image_built,
                                probed_env: body.probed_env,
                                user_shell: body.user_shell,
                                container_url: body.container_url,
                                container_token: body.container_token,
                            }));
                        }
                        Err(e) => {
                            self.result =
                                Some(Err(anyhow::anyhow!("Failed to parse result data: {}", e)));
                        }
                    }
                    return None;
                }
                "error" => {
                    match serde_json::from_str::<ErrorResponse>(data) {
                        Ok(err) => {
                            self.result = Some(Err(anyhow::anyhow!("Server error: {}", err.error)));
                        }
                        Err(e) => {
                            self.result =
                                Some(Err(anyhow::anyhow!("Failed to parse error data: {}", e)));
                        }
                    }
                    return None;
                }
                other => {
                    self.result = Some(Err(anyhow::anyhow!("Unknown SSE event type: {}", other)));
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
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        Ok(ClientLaunchProgress::new(response))
    }

    fn recreate_pod(&self, params: PodLaunchParams) -> Result<ClientLaunchProgress> {
        let url = self.url.join("/pod/recreate")?;

        let response = self
            .client
            .post(url)
            .json(&params)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        Ok(ClientLaunchProgress::new(response))
    }

    fn stop_pod(&self, pod_name: PodName, repo_path: PathBuf) -> Result<()> {
        let url = self.url.join("/pod/stop")?;
        let request = StopPodRequest {
            pod_name,
            repo_path,
        };

        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
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
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
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
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            let body: ListPodsResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(body.pods)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
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
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            let body: ListPortsResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(body.ports)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
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
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            let body: SaveConversationResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(body.id)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
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
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            let body: ListConversationsResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(body.conversations)
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
        }
    }

    fn get_conversation(&self, id: i64) -> Result<Option<GetConversationResponse>> {
        let url = self.url.join(&format!("/conversation/{}", id))?;

        let response = self
            .client
            .get(url)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if response.status().is_success() {
            let body: GetConversationResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(Some(body))
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
        }
    }

    fn ensure_claude_config(&self, request: EnsureClaudeConfigRequest) -> Result<()> {
        let url = self.url.join("/pod/claude-config")?;

        let response = self
            .client
            .put(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
        }
    }
}

/// Format a single SSE event with the given type and JSON-encoded data.
fn sse_event(event_type: &str, data: &str) -> String {
    format!("event: {}\ndata: {}\n\n", event_type, data)
}

/// Build an SSE streaming response for launch/recreate endpoints.
///
/// Spawns a blocking task that calls `op()` to get a `LaunchProgress`,
/// iterates build output lines (sending each as `event: build_output`),
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
                        error: format!("{:#}", e),
                    })
                    .expect("ErrorResponse is always serializable"),
                );
                let _ = event_tx.blocking_send(msg);
                return;
            }
        };

        // Stream build output lines
        for line in &mut progress {
            let json_str = serde_json::to_string(&line).expect("String is always serializable");
            let msg = sse_event("build_output", &json_str);
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
                    error: format!("{:#}", e),
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
    let result = block_in_place(|| daemon.stop_pod(request.pod_name, request.repo_path));

    match result {
        Ok(()) => Ok(Json(StopPodResponse { stopped: true })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{:#}", e),
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
                error: format!("{:#}", e),
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
                error: format!("{:#}", e),
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
                error: format!("{:#}", e),
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
                error: format!("{:#}", e),
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
                error: format!("{:#}", e),
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
                error: format!("Conversation {} not found", id),
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{:#}", e),
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
                error: format!("{:#}", e),
            }),
        )),
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
        .with_state(daemon);

    block_on(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .unwrap();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

    struct MockDaemon;

    impl Daemon for MockDaemon {
        type Progress = ImmediateLaunchProgress;

        fn launch_pod(&self, params: PodLaunchParams) -> Result<ImmediateLaunchProgress> {
            let user = params
                .devcontainer
                .user()
                .map(String::from)
                .unwrap_or_else(|| "mockuser".to_string());
            let image = params.devcontainer.image.as_deref().unwrap_or("none");
            Ok(ImmediateLaunchProgress::new(Ok(LaunchResult {
                container_id: ContainerId(format!("{}:{}", params.pod_name.0, image)),
                user,
                docker_socket: PathBuf::from("/var/run/docker.sock"),
                image_built: false,
                probed_env: HashMap::new(),
                user_shell: "/bin/sh".to_string(),
                container_url: String::new(),
                container_token: String::new(),
            })))
        }

        fn recreate_pod(&self, params: PodLaunchParams) -> Result<ImmediateLaunchProgress> {
            let user = params
                .devcontainer
                .user()
                .map(String::from)
                .unwrap_or_else(|| "mockuser".to_string());
            let image = params.devcontainer.image.as_deref().unwrap_or("none");
            Ok(ImmediateLaunchProgress::new(Ok(LaunchResult {
                container_id: ContainerId(format!("recreated:{}:{}", params.pod_name.0, image)),
                user,
                docker_socket: PathBuf::from("/var/run/docker.sock"),
                image_built: false,
                probed_env: HashMap::new(),
                user_shell: "/bin/sh".to_string(),
                container_url: String::new(),
                container_token: String::new(),
            })))
        }

        fn stop_pod(&self, _pod_name: PodName, _repo_path: PathBuf) -> Result<()> {
            Ok(())
        }

        fn delete_pod(&self, _pod_name: PodName, _repo_path: PathBuf, _wait: bool) -> Result<()> {
            Ok(())
        }

        fn list_pods(&self, _repo_path: PathBuf) -> Result<Vec<PodInfo>> {
            Ok(vec![])
        }

        fn list_ports(&self, _pod_name: PodName, _repo_path: PathBuf) -> Result<Vec<PortInfo>> {
            Ok(vec![])
        }

        fn save_conversation(
            &self,
            id: Option<i64>,
            _repo_path: PathBuf,
            _pod_name: String,
            _model: String,
            _provider: String,
            _history: serde_json::Value,
        ) -> Result<i64> {
            Ok(id.unwrap_or(1))
        }

        fn list_conversations(
            &self,
            _repo_path: PathBuf,
            _pod_name: String,
        ) -> Result<Vec<ConversationSummary>> {
            Ok(vec![])
        }

        fn get_conversation(&self, _id: i64) -> Result<Option<GetConversationResponse>> {
            Ok(None)
        }

        fn ensure_claude_config(&self, _request: EnsureClaudeConfigRequest) -> Result<()> {
            Ok(())
        }
    }

    /// Helper to start a daemon server in a background thread.
    struct TestServer {
        socket_path: PathBuf,
        shutdown_tx: Option<oneshot::Sender<()>>,
        handle: Option<thread::JoinHandle<()>>,
        #[allow(dead_code)]
        temp_dir: tempfile::TempDir,
    }

    impl TestServer {
        fn start<D: Daemon>(daemon: D) -> Self {
            let temp_dir = tempfile::tempdir().unwrap();
            let socket_path = temp_dir.path().join("daemon.sock");
            let socket_path_clone = socket_path.clone();

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let listener = block_on(async { UnixListener::bind(&socket_path_clone).unwrap() });

            let handle = thread::spawn(move || {
                serve_daemon_until(daemon, listener, async {
                    let _ = shutdown_rx.await;
                });
            });

            // Wait for socket to be ready
            thread::sleep(std::time::Duration::from_millis(50));

            TestServer {
                socket_path,
                shutdown_tx: Some(shutdown_tx),
                handle: Some(handle),
                temp_dir,
            }
        }

        fn client(&self) -> DaemonClient {
            DaemonClient::new_unix(&self.socket_path)
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn test_client_server_roundtrip() {
        let server = TestServer::start(MockDaemon);
        let client = server.client();

        let dc = DevContainer {
            image: Some("test-image".to_string()),
            remote_user: Some("testuser".to_string()),
            run_args: Some(vec!["--runtime=runc".to_string()]),
            ..Default::default()
        };

        let progress = client.launch_pod(PodLaunchParams {
            pod_name: PodName("test-sandbox".to_string()),
            repo_path: PathBuf::from("/tmp/repo"),
            host_branch: Some("main".to_string()),
            docker_host: DockerHost::Localhost,
            devcontainer: dc,
        });

        let launch_result = progress.unwrap().finish().unwrap();
        assert_eq!(launch_result.container_id.0, "test-sandbox:test-image");
    }

    /// A mock daemon that uses a real database for conversation operations.
    struct MockDaemonWithDb {
        db: std::sync::Mutex<rusqlite::Connection>,
    }

    impl MockDaemonWithDb {
        fn new(db_path: &std::path::Path) -> Self {
            let conn = crate::daemon::db::open_db(db_path).unwrap();
            Self {
                db: std::sync::Mutex::new(conn),
            }
        }
    }

    impl Daemon for MockDaemonWithDb {
        type Progress = ImmediateLaunchProgress;

        fn launch_pod(&self, _params: PodLaunchParams) -> Result<ImmediateLaunchProgress> {
            unimplemented!("not needed for conversation tests")
        }

        fn recreate_pod(&self, _params: PodLaunchParams) -> Result<ImmediateLaunchProgress> {
            unimplemented!("not needed for conversation tests")
        }

        fn stop_pod(&self, _pod_name: PodName, _repo_path: PathBuf) -> Result<()> {
            unimplemented!("not needed for conversation tests")
        }

        fn delete_pod(&self, _pod_name: PodName, _repo_path: PathBuf, _wait: bool) -> Result<()> {
            unimplemented!("not needed for conversation tests")
        }

        fn list_pods(&self, _repo_path: PathBuf) -> Result<Vec<PodInfo>> {
            unimplemented!("not needed for conversation tests")
        }

        fn list_ports(&self, _pod_name: PodName, _repo_path: PathBuf) -> Result<Vec<PortInfo>> {
            unimplemented!("not needed for conversation tests")
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
            let conn = self.db.lock().unwrap();
            crate::daemon::db::save_conversation(
                &conn, id, &repo_path, &pod_name, &model, &provider, &history,
            )
        }

        fn list_conversations(
            &self,
            repo_path: PathBuf,
            pod_name: String,
        ) -> Result<Vec<ConversationSummary>> {
            let conn = self.db.lock().unwrap();
            let summaries = crate::daemon::db::list_conversations(&conn, &repo_path, &pod_name)?;
            Ok(summaries
                .into_iter()
                .map(|s| ConversationSummary {
                    id: s.id,
                    model: s.model,
                    provider: s.provider,
                    updated_at: s.updated_at,
                })
                .collect())
        }

        fn get_conversation(&self, id: i64) -> Result<Option<GetConversationResponse>> {
            let conn = self.db.lock().unwrap();
            let conv = crate::daemon::db::get_conversation(&conn, id)?;
            Ok(conv.map(|c| GetConversationResponse {
                model: c.model,
                provider: c.provider,
                history: c.history,
            }))
        }

        fn ensure_claude_config(&self, _request: EnsureClaudeConfigRequest) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_conversation_save_and_list() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let repo_path = PathBuf::from("/home/user/project");

        // Create pod first (directly in DB since protocol doesn't expose this)
        {
            let conn = crate::daemon::db::open_db(&db_path).unwrap();
            crate::daemon::db::create_pod(
                &conn,
                &repo_path,
                "dev",
                crate::daemon::db::LOCALHOST_DB_STR,
            )
            .unwrap();
        }

        let server = TestServer::start(MockDaemonWithDb::new(&db_path));
        let client = server.client();

        let history = serde_json::json!([{"role": "user", "content": "hello"}]);

        // Save a conversation
        let id = client
            .save_conversation(
                None,
                repo_path.clone(),
                "dev".to_string(),
                "claude-sonnet-4-5".to_string(),
                "anthropic".to_string(),
                history.clone(),
            )
            .unwrap();
        assert!(id > 0);

        // List conversations
        let list = client
            .list_conversations(repo_path.clone(), "dev".to_string())
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].model, "claude-sonnet-4-5");
        assert_eq!(list[0].provider, "anthropic");

        // Get the conversation back
        let conv = client.get_conversation(id).unwrap().unwrap();
        assert_eq!(conv.model, "claude-sonnet-4-5");
        assert_eq!(conv.provider, "anthropic");
        assert_eq!(conv.history, history);
    }

    #[test]
    fn test_conversation_update() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let repo_path = PathBuf::from("/home/user/project");

        // Create pod first (directly in DB since protocol doesn't expose this)
        {
            let conn = crate::daemon::db::open_db(&db_path).unwrap();
            crate::daemon::db::create_pod(
                &conn,
                &repo_path,
                "dev",
                crate::daemon::db::LOCALHOST_DB_STR,
            )
            .unwrap();
        }

        let server = TestServer::start(MockDaemonWithDb::new(&db_path));
        let client = server.client();

        let history1 = serde_json::json!([{"role": "user", "content": "hello"}]);
        let history2 = serde_json::json!([
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi there"}
        ]);

        // Save initial
        let id = client
            .save_conversation(
                None,
                repo_path.clone(),
                "dev".to_string(),
                "claude-sonnet-4-5".to_string(),
                "anthropic".to_string(),
                history1,
            )
            .unwrap();

        // Update
        let id2 = client
            .save_conversation(
                Some(id),
                repo_path.clone(),
                "dev".to_string(),
                "claude-opus-4-5".to_string(),
                "anthropic".to_string(),
                history2.clone(),
            )
            .unwrap();
        assert_eq!(id, id2);

        // Verify update
        let conv = client.get_conversation(id).unwrap().unwrap();
        assert_eq!(conv.model, "claude-opus-4-5");
        assert_eq!(conv.provider, "anthropic");
        assert_eq!(conv.history, history2);
    }

    #[test]
    fn test_conversation_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let server = TestServer::start(MockDaemonWithDb::new(&db_path));
        let client = server.client();

        let conv = client.get_conversation(999).unwrap();
        assert!(conv.is_none());
    }
}
