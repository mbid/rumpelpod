use std::fmt::Debug;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::put;
use axum::serve::Listener;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::task::block_in_place;
use url::Url;

use crate::r#async::block_on;

/// Opaque wrapper for docker image names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image(pub String);

/// Opaque wrapper for container IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerId(pub String);

/// Human-readable sandbox name to distinguish multiple sandboxes for the same repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxName(pub String);

/// Request body for launch_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct LaunchSandboxRequest {
    sandbox_name: SandboxName,
    image: Image,
    repo_path: PathBuf,
}

/// Response body for launch_sandbox endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct LaunchSandboxResponse {
    container_id: ContainerId,
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
    ) -> Result<ContainerId>;
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
    ) -> Result<ContainerId> {
        let url = self.url.join("/sandbox")?;
        let request = LaunchSandboxRequest {
            sandbox_name,
            image,
            repo_path,
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
            Ok(body.container_id)
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
        daemon.launch_sandbox(request.sandbox_name, request.image, request.repo_path)
    });

    match result {
        Ok(container_id) => Ok(Json(LaunchSandboxResponse { container_id })),
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
        ) -> Result<ContainerId> {
            // Return a container ID that encodes the inputs for verification
            Ok(ContainerId(format!("{}:{}", sandbox_name.0, image.0)))
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
        );

        let container_id = result.unwrap();
        assert_eq!(container_id.0, "test-sandbox:test-image");

        shutdown_tx.send(()).unwrap();
        server_handle.join().unwrap();
    }
}
