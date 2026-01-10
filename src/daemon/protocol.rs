use std::fmt::Debug;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, put};
use axum::serve::Listener;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::task::block_in_place;
use url::Url;

use crate::config::Runtime;
use crate::r#async::block_on;

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
}

/// Human-readable sandbox name to distinguish multiple sandboxes for the same repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxName(pub String);

/// Status of a sandbox container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SandboxStatus {
    Running,
    Stopped,
}

/// Information about a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub name: String,
    pub status: SandboxStatus,
    pub created: String,
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
}

/// Response body for launch_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct LaunchSandboxResponse {
    container_id: ContainerId,
    /// The resolved user for the sandbox.
    user: String,
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

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

pub trait Daemon: Send + Sync + 'static {
    // PUT /sandbox
    // with JSON content type for request and response bodies.
    fn launch_sandbox(
        &self,
        sandbox_name: SandboxName,
        image: Image,
        repo_path: PathBuf,
        container_repo_path: PathBuf,
        user: Option<String>,
        runtime: Runtime,
    ) -> Result<LaunchResult>;

    // DELETE /sandbox
    // Stops and removes a sandbox container.
    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()>;

    // GET /sandbox
    // Lists all sandboxes for a given repository.
    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>>;
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
        Self {
            client: reqwest::blocking::Client::new(),
            url,
        }
    }

    /// Create a client that connects via Unix domain socket.
    #[allow(dead_code)]
    pub fn new_unix(socket_path: &Path) -> Self {
        let client = reqwest::blocking::Client::builder()
            .unix_socket(socket_path)
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
    ) -> Result<LaunchResult> {
        let url = self.url.join("/sandbox")?;
        let request = LaunchSandboxRequest {
            sandbox_name,
            image,
            repo_path,
            container_repo_path,
            user,
            runtime,
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
        )
    });

    match result {
        Ok(launch_result) => Ok(Json(LaunchSandboxResponse {
            container_id: launch_result.container_id,
            user: launch_result.user,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
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
                error: e.to_string(),
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
                error: e.to_string(),
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
        ) -> Result<LaunchResult> {
            // Return a container ID that encodes the inputs for verification
            Ok(LaunchResult {
                container_id: ContainerId(format!("{}:{}", sandbox_name.0, image.0)),
                user: user.unwrap_or_else(|| "mockuser".to_string()),
            })
        }

        fn delete_sandbox(&self, _sandbox_name: SandboxName, _repo_path: PathBuf) -> Result<()> {
            Ok(())
        }

        fn list_sandboxes(&self, _repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_client_server_roundtrip() {
        // TempDir cleans up on drop, including the socket file inside
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("daemon.sock");

        // Create shutdown channel and listener
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let listener = block_on(async { UnixListener::bind(&socket_path).unwrap() });

        // Spawn server in background thread
        let server_handle = thread::spawn(move || {
            serve_daemon_until(MockDaemon, listener, async {
                let _ = shutdown_rx.await;
            });
        });

        // Give server a moment to start
        thread::sleep(std::time::Duration::from_millis(50));

        // Create client and make request
        let client = DaemonClient::new_unix(&socket_path);

        let result = client.launch_sandbox(
            SandboxName("test-sandbox".to_string()),
            Image("test-image".to_string()),
            PathBuf::from("/tmp/repo"),
            PathBuf::from("/workspace"),
            Some("testuser".to_string()),
            Runtime::Runc, // Use runc for tests (works inside sysbox)
        );

        let launch_result = result.unwrap();
        assert_eq!(launch_result.container_id.0, "test-sandbox:test-image");

        shutdown_tx.send(()).unwrap();
        server_handle.join().unwrap();
    }
}
