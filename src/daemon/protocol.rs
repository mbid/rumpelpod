use std::fmt::Debug;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::serve::Listener;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::task::block_in_place;
use url::Url;

use crate::async_runtime::block_on;
use crate::config::{Network, RemoteDocker, Runtime};

/// Opaque wrapper for docker image names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image(pub String);

/// Opaque wrapper for container IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerId(pub String);

/// Result of launching a sandbox.
#[derive(Debug, Clone)]
pub struct LaunchResult {
    pub container_id: ContainerId,
    /// The resolved user for the sandbox. This is either the user specified in the config,
    /// or the user from the image's USER directive.
    pub user: String,
    /// The Docker socket path to use for connecting to the Docker daemon.
    /// Clients must use this socket for all Docker operations on this sandbox.
    pub docker_socket: std::path::PathBuf,
}

/// Human-readable sandbox name to distinguish multiple sandboxes for the same repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxName(pub String);

/// Status of a sandbox container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SandboxStatus {
    Running,
    Stopped,
    /// Container no longer exists (was deleted outside of sandbox tool)
    Gone,
    /// Remote sandbox where we don't have a connection to check actual status
    Disconnected,
}

/// Information about a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub name: String,
    pub status: SandboxStatus,
    pub created: String,
    /// Host where the sandbox runs: "local" or an SSH URL like "user@host:port".
    pub host: String,
}

/// Request body for launch_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct LaunchSandboxRequest {
    sandbox_name: SandboxName,
    image: Image,
    repo_path: PathBuf,
    /// Path where the repository is located inside the container.
    /// Git remotes will be configured to point to the gateway HTTP server.
    container_repo_path: PathBuf,
    /// User to run as inside the container, if explicitly specified.
    /// If None, the daemon will use the image's USER directive.
    user: Option<String>,
    /// Container runtime to use (runsc, runc, sysbox-runc).
    runtime: Runtime,
    /// Network configuration.
    network: Network,
    /// The branch currently checked out on the host, if any.
    /// Used to set the upstream of the primary branch in the sandbox.
    host_branch: Option<String>,
    /// Remote Docker host specification (e.g., "user@host:port").
    /// If not set, uses local Docker.
    #[serde(default)]
    remote: Option<RemoteDocker>,
}

/// Response body for launch_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct LaunchSandboxResponse {
    container_id: ContainerId,
    /// The resolved user for the sandbox.
    user: String,
    /// The Docker socket path to use for connecting to the Docker daemon.
    docker_socket: PathBuf,
}

/// Request body for delete_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct DeleteSandboxRequest {
    sandbox_name: SandboxName,
    repo_path: PathBuf,
}

/// Response body for delete_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct DeleteSandboxResponse {
    deleted: bool,
}

/// Request body for list_sandboxes endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct ListSandboxesRequest {
    repo_path: PathBuf,
}

/// Response body for list_sandboxes endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct ListSandboxesResponse {
    sandboxes: Vec<SandboxInfo>,
}

/// Request body for save_conversation endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct SaveConversationRequest {
    /// If present, update existing conversation; otherwise create new.
    pub id: Option<i64>,
    pub repo_path: PathBuf,
    pub sandbox_name: String,
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
    pub sandbox_name: String,
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

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

pub trait Daemon: Send + Sync + 'static {
    // PUT /sandbox
    // with JSON content type for request and response bodies.
    #[allow(clippy::too_many_arguments)]
    fn launch_sandbox(
        &self,
        sandbox_name: SandboxName,
        image: Image,
        repo_path: PathBuf,
        container_repo_path: PathBuf,
        user: Option<String>,
        runtime: Runtime,
        network: Network,
        host_branch: Option<String>,
        remote: Option<RemoteDocker>,
    ) -> Result<LaunchResult>;

    // DELETE /sandbox
    // Stops and removes a sandbox container.
    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()>;

    // GET /sandbox
    // Lists all sandboxes for a given repository.
    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>>;

    // POST /conversation
    // Save or update a conversation.
    fn save_conversation(
        &self,
        id: Option<i64>,
        repo_path: PathBuf,
        sandbox_name: String,
        model: String,
        provider: String,
        history: serde_json::Value,
    ) -> Result<i64>;

    // GET /conversations
    // List all conversations for a sandbox.
    fn list_conversations(
        &self,
        repo_path: PathBuf,
        sandbox_name: String,
    ) -> Result<Vec<ConversationSummary>>;

    // GET /conversation/<id>
    // Get a conversation by ID.
    fn get_conversation(&self, id: i64) -> Result<Option<GetConversationResponse>>;
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

impl Daemon for DaemonClient {
    fn launch_sandbox(
        &self,
        sandbox_name: SandboxName,
        image: Image,
        repo_path: PathBuf,
        container_repo_path: PathBuf,
        user: Option<String>,
        runtime: Runtime,
        network: Network,
        host_branch: Option<String>,
        remote: Option<RemoteDocker>,
    ) -> Result<LaunchResult> {
        let url = self.url.join("/sandbox")?;
        let request = LaunchSandboxRequest {
            sandbox_name,
            image,
            repo_path,
            container_repo_path,
            user,
            runtime,
            network,
            host_branch,
            remote,
        };

        let response = self
            .client
            .put(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            let body: LaunchSandboxResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(LaunchResult {
                container_id: body.container_id,
                user: body.user,
                docker_socket: body.docker_socket,
            })
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "Unknown error".to_string(),
            });
            Err(anyhow::anyhow!("Server error: {}", error.error))
        }
    }

    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()> {
        let url = self.url.join("/sandbox")?;
        let request = DeleteSandboxRequest {
            sandbox_name,
            repo_path,
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

    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
        let url = self.url.join("/sandbox")?;
        let request = ListSandboxesRequest { repo_path };

        let response = self
            .client
            .get(url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if response.status().is_success() {
            let body: ListSandboxesResponse = response
                .json()
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
            Ok(body.sandboxes)
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
        sandbox_name: String,
        model: String,
        provider: String,
        history: serde_json::Value,
    ) -> Result<i64> {
        let url = self.url.join("/conversation")?;
        let request = SaveConversationRequest {
            id,
            repo_path,
            sandbox_name,
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
        sandbox_name: String,
    ) -> Result<Vec<ConversationSummary>> {
        let url = self.url.join("/conversations")?;
        let request = ListConversationsRequest {
            repo_path,
            sandbox_name,
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
}

/// Handler for PUT /sandbox endpoint.
async fn launch_sandbox_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<LaunchSandboxRequest>,
) -> Result<Json<LaunchSandboxResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| {
        daemon.launch_sandbox(
            request.sandbox_name,
            request.image,
            request.repo_path,
            request.container_repo_path,
            request.user,
            request.runtime,
            request.network,
            request.host_branch,
            request.remote,
        )
    });

    match result {
        Ok(launch_result) => Ok(Json(LaunchSandboxResponse {
            container_id: launch_result.container_id,
            user: launch_result.user,
            docker_socket: launch_result.docker_socket,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{:#}", e),
            }),
        )),
    }
}

/// Handler for DELETE /sandbox endpoint.
async fn delete_sandbox_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<DeleteSandboxRequest>,
) -> Result<Json<DeleteSandboxResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.delete_sandbox(request.sandbox_name, request.repo_path));

    match result {
        Ok(()) => Ok(Json(DeleteSandboxResponse { deleted: true })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{:#}", e),
            }),
        )),
    }
}

/// Handler for GET /sandbox endpoint.
async fn list_sandboxes_handler<D: Daemon>(
    State(daemon): State<Arc<D>>,
    Json(request): Json<ListSandboxesRequest>,
) -> Result<Json<ListSandboxesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = block_in_place(|| daemon.list_sandboxes(request.repo_path));

    match result {
        Ok(sandboxes) => Ok(Json(ListSandboxesResponse { sandboxes })),
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
            request.sandbox_name,
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
    let result =
        block_in_place(|| daemon.list_conversations(request.repo_path, request.sandbox_name));

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
        .route("/sandbox", put(launch_sandbox_handler::<D>))
        .route("/sandbox", delete(delete_sandbox_handler::<D>))
        .route("/sandbox", get(list_sandboxes_handler::<D>))
        .route("/conversation", post(save_conversation_handler::<D>))
        .route("/conversations", get(list_conversations_handler::<D>))
        .route("/conversation/{id}", get(get_conversation_handler::<D>))
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
        fn launch_sandbox(
            &self,
            sandbox_name: SandboxName,
            image: Image,
            _repo_path: PathBuf,
            _container_repo_path: PathBuf,
            user: Option<String>,
            _runtime: Runtime,
            _network: Network,
            _host_branch: Option<String>,
            _remote: Option<RemoteDocker>,
        ) -> Result<LaunchResult> {
            // Return a container ID that encodes the inputs for verification
            Ok(LaunchResult {
                container_id: ContainerId(format!("{}:{}", sandbox_name.0, image.0)),
                user: user.unwrap_or_else(|| "mockuser".to_string()),
                docker_socket: PathBuf::from("/var/run/docker.sock"),
            })
        }

        fn delete_sandbox(&self, _sandbox_name: SandboxName, _repo_path: PathBuf) -> Result<()> {
            Ok(())
        }

        fn list_sandboxes(&self, _repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
            Ok(vec![])
        }

        fn save_conversation(
            &self,
            id: Option<i64>,
            _repo_path: PathBuf,
            _sandbox_name: String,
            _model: String,
            _provider: String,
            _history: serde_json::Value,
        ) -> Result<i64> {
            Ok(id.unwrap_or(1))
        }

        fn list_conversations(
            &self,
            _repo_path: PathBuf,
            _sandbox_name: String,
        ) -> Result<Vec<ConversationSummary>> {
            Ok(vec![])
        }

        fn get_conversation(&self, _id: i64) -> Result<Option<GetConversationResponse>> {
            Ok(None)
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

        let result = client.launch_sandbox(
            SandboxName("test-sandbox".to_string()),
            Image("test-image".to_string()),
            PathBuf::from("/tmp/repo"),
            PathBuf::from("/workspace"),
            Some("testuser".to_string()),
            Runtime::Runc,
            Network::Default,
            Some("main".to_string()),
            None, // No remote Docker
        );

        let launch_result = result.unwrap();
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
        fn launch_sandbox(
            &self,
            _sandbox_name: SandboxName,
            _image: Image,
            _repo_path: PathBuf,
            _container_repo_path: PathBuf,
            _user: Option<String>,
            _runtime: Runtime,
            _network: Network,
            _host_branch: Option<String>,
            _remote: Option<RemoteDocker>,
        ) -> Result<LaunchResult> {
            unimplemented!("not needed for conversation tests")
        }

        fn delete_sandbox(&self, _sandbox_name: SandboxName, _repo_path: PathBuf) -> Result<()> {
            unimplemented!("not needed for conversation tests")
        }

        fn list_sandboxes(&self, _repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
            unimplemented!("not needed for conversation tests")
        }

        fn save_conversation(
            &self,
            id: Option<i64>,
            repo_path: PathBuf,
            sandbox_name: String,
            model: String,
            provider: String,
            history: serde_json::Value,
        ) -> Result<i64> {
            let conn = self.db.lock().unwrap();
            crate::daemon::db::save_conversation(
                &conn,
                id,
                &repo_path,
                &sandbox_name,
                &model,
                &provider,
                &history,
            )
        }

        fn list_conversations(
            &self,
            repo_path: PathBuf,
            sandbox_name: String,
        ) -> Result<Vec<ConversationSummary>> {
            let conn = self.db.lock().unwrap();
            let summaries =
                crate::daemon::db::list_conversations(&conn, &repo_path, &sandbox_name)?;
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
    }

    #[test]
    fn test_conversation_save_and_list() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let repo_path = PathBuf::from("/home/user/project");

        // Create sandbox first (directly in DB since protocol doesn't expose this)
        {
            let conn = crate::daemon::db::open_db(&db_path).unwrap();
            crate::daemon::db::create_sandbox(
                &conn,
                &repo_path,
                "dev",
                crate::daemon::db::LOCAL_HOST,
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

        // Create sandbox first (directly in DB since protocol doesn't expose this)
        {
            let conn = crate::daemon::db::open_db(&db_path).unwrap();
            crate::daemon::db::create_sandbox(
                &conn,
                &repo_path,
                "dev",
                crate::daemon::db::LOCAL_HOST,
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
