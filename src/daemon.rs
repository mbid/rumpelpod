pub mod protocol;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use indoc::indoc;
use log::error;
use tokio::net::UnixListener;

use protocol::{ContainerId, Daemon, Image, SandboxName};

/// Environment variable to override the daemon socket path for testing.
pub const SOCKET_PATH_ENV: &str = "SANDBOX_DAEMON_SOCKET";

/// Get the daemon socket path.
/// Uses $SANDBOX_DAEMON_SOCKET if set, otherwise $XDG_RUNTIME_DIR/sandbox.sock.
pub fn socket_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(SOCKET_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").context(indoc! {"
        XDG_RUNTIME_DIR not set. This usually means you're not running in a
        systemd user session. The sandbox daemon requires systemd for socket activation.
    "})?;
    Ok(PathBuf::from(runtime_dir).join("sandbox.sock"))
}

struct DaemonServer {
    // No state for now. State resides in the docker service.
}

/// Generate a unique container name from repo path and sandbox name.
/// Format: "<repo_dir>-<sandbox_name>-<hash_prefix>"
/// where hash is sha256(repo_path + sandbox_name) truncated to 12 hex chars.
fn container_name(repo_path: &Path, sandbox_name: &SandboxName) -> String {
    use sha2::{Digest, Sha256};

    let repo_dir = repo_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo");

    let mut hasher = Sha256::new();
    hasher.update(repo_path.as_os_str().as_encoded_bytes());
    hasher.update(sandbox_name.0.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let hash_prefix = &hash[..12];

    format!("{}-{}-{}", repo_dir, sandbox_name.0, hash_prefix)
}

/// Container state returned by docker inspect.
struct ContainerState {
    status: String,
    image: String,
    id: String,
}

/// Inspect an existing container by name. Returns None if container doesn't exist.
fn inspect_container(container_name: &str) -> Result<Option<ContainerState>> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.State.Status}} {{.Config.Image}} {{.Id}}",
            container_name,
        ])
        .output()
        .context("Failed to execute docker inspect")?;

    if !output.status.success() {
        // Container doesn't exist
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.trim().splitn(3, ' ').collect();
    if parts.len() != 3 {
        anyhow::bail!("Unexpected docker inspect output: {}", stdout);
    }

    Ok(Some(ContainerState {
        status: parts[0].to_string(),
        image: parts[1].to_string(),
        id: parts[2].to_string(),
    }))
}

/// Start a stopped container.
fn start_container(container_name: &str) -> Result<()> {
    let output = Command::new("docker")
        .args(["start", container_name])
        .output()
        .context("Failed to execute docker start")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker start failed: {}", stderr);
    }

    Ok(())
}

/// Create a new container with docker run.
fn create_container(container_name: &str, image: &Image, repo_path: &Path) -> Result<ContainerId> {
    let output = Command::new("docker")
        .args([
            "run",
            "-d", // Detach to get container ID
            "--name",
            container_name,
            "--mount",
            &format!("type=bind,src={},dst=/repo", repo_path.display()),
            &image.0,
            "sleep",
            "infinity", // Keep container running
        ])
        .output()
        .context("Failed to execute docker run")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("docker run failed: {}", stderr);
        anyhow::bail!("docker run failed: {}", stderr);
    }

    // Container ID is printed to stdout (without trailing newline)
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(ContainerId(container_id))
}

impl Daemon for DaemonServer {
    fn launch_sandbox(
        &self,
        sandbox_name: SandboxName,
        image: Image,
        repo_path: PathBuf,
    ) -> Result<ContainerId> {
        let container_name = container_name(&repo_path, &sandbox_name);

        // TODO: There's a potential race condition between inspect and
        // start/run. Another process could stop/remove the container after we
        // inspect it. For robustness, we'd need to retry on specific failures,
        // but that adds complexity. For now, we accept this limitation.

        if let Some(state) = inspect_container(&container_name)? {
            // Container exists - check if it has the expected image
            if state.image != image.0 {
                anyhow::bail!(
                    "Container '{}' exists with image '{}', but requested image is '{}'",
                    container_name,
                    state.image,
                    image.0
                );
            }

            if state.status == "running" {
                // Already running with correct image
                return Ok(ContainerId(state.id));
            }

            // Container exists but is stopped - restart it
            start_container(&container_name)?;
            return Ok(ContainerId(state.id));
        }

        // Container doesn't exist - create it
        create_container(&container_name, &image, &repo_path)
    }
}

pub fn run_daemon() -> Result<()> {
    let socket = socket_path()?;

    // Remove stale socket file if it exists
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }

    // Enter the runtime context so UnixListener::bind can register with the reactor
    let _guard = crate::r#async::RUNTIME.enter();

    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("Failed to bind to {}", socket.display()))?;

    let daemon = DaemonServer {};
    protocol::serve_daemon(daemon, listener);
}
