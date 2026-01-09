pub mod protocol;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use indoc::indoc;
use log::error;
use tokio::net::UnixListener;

use crate::command_ext::CommandExt;
use protocol::{ContainerId, Daemon, Image, SandboxInfo, SandboxName, SandboxStatus};

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

/// Label key used to store the repository path on containers and networks.
const REPO_PATH_LABEL: &str = "dev.sandbox.repo_path";

/// Label key used to store the sandbox name on containers and networks.
const SANDBOX_NAME_LABEL: &str = "dev.sandbox.name";

/// Generate a unique docker resource name from repo path and sandbox name.
/// Used for both the container and network (they can share the same name).
/// Format: "<repo_dir>-<sandbox_name>-<hash_prefix>"
/// where hash is sha256(repo_path + sandbox_name) truncated to 12 hex chars.
fn docker_name(repo_path: &Path, sandbox_name: &SandboxName) -> String {
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

/// Create a docker network for the sandbox.
/// If the network already exists, returns success.
fn create_network(name: &str, sandbox_name: &SandboxName, repo_path: &Path) -> Result<()> {
    // Check if network already exists
    let check = Command::new("docker")
        .args(["network", "inspect", name])
        .output()
        .context("Failed to execute docker network inspect")?;

    if check.status.success() {
        return Ok(());
    }

    let output = Command::new("docker")
        .args([
            "network",
            "create",
            "--label",
            &format!("{}={}", REPO_PATH_LABEL, repo_path.display()),
            "--label",
            &format!("{}={}", SANDBOX_NAME_LABEL, sandbox_name.0),
            name,
        ])
        .output()
        .context("Failed to execute docker network create")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("docker network create failed: {}", stderr);
        anyhow::bail!("docker network create failed: {}", stderr);
    }

    Ok(())
}

/// Delete a docker network.
fn delete_network(name: &str) -> Result<()> {
    let output = Command::new("docker")
        .args(["network", "rm", name])
        .combined_output()
        .context("Failed to execute docker network rm")?;

    if !output.status.success() {
        // Ignore "not found" errors (already deleted or never existed)
        if !output.combined_output.contains("not found") {
            error!("docker network rm failed: {}", output.combined_output);
            anyhow::bail!(
                "docker network rm failed: {}",
                output.combined_output.trim()
            );
        }
    }

    Ok(())
}

/// Create a new container with docker run.
fn create_container(
    name: &str,
    sandbox_name: &SandboxName,
    image: &Image,
    repo_path: &Path,
) -> Result<ContainerId> {
    let output = Command::new("docker")
        .args([
            "run",
            "-d", // Detach to get container ID
            "--name",
            name,
            "--network",
            name, // Container and network share the same name
            "--label",
            &format!("{}={}", REPO_PATH_LABEL, repo_path.display()),
            "--label",
            &format!("{}={}", SANDBOX_NAME_LABEL, sandbox_name.0),
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

/// List all sandbox containers for a given repository path.
fn list_sandboxes_for_repo(repo_path: &Path) -> Result<Vec<SandboxInfo>> {
    // Use docker ps with filter by label to find containers for this repo
    let output = Command::new("docker")
        .args([
            "ps",
            "-a", // Include stopped containers
            "--filter",
            &format!("label={}={}", REPO_PATH_LABEL, repo_path.display()),
            "--format",
            // Output: name, status, created timestamp, sandbox_name label
            "{{.Names}}\t{{.Status}}\t{{.CreatedAt}}\t{{.Label \"dev.sandbox.name\"}}",
        ])
        .output()
        .context("Failed to execute docker ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker ps failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut sandboxes = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }

        let status_str = parts[1];
        let status = if status_str.starts_with("Up") {
            SandboxStatus::Running
        } else {
            SandboxStatus::Stopped
        };

        // Parse created timestamp (format: "2026-01-09 12:58:00 +0000 UTC")
        // We only want "2026-01-09 12:58"
        let created_raw = parts[2];
        let created = if let Some((date_time, _rest)) = created_raw.split_once(" +") {
            // date_time is "2026-01-09 12:58:00", we want "2026-01-09 12:58"
            // Find last colon and truncate
            if let Some(last_colon_idx) = date_time.rfind(':') {
                date_time[..last_colon_idx].to_string()
            } else {
                date_time.to_string()
            }
        } else {
            created_raw.to_string()
        };

        let sandbox_name = parts[3].to_string();

        sandboxes.push(SandboxInfo {
            name: sandbox_name,
            status,
            created,
        });
    }

    Ok(sandboxes)
}

impl Daemon for DaemonServer {
    fn launch_sandbox(
        &self,
        sandbox_name: SandboxName,
        image: Image,
        repo_path: PathBuf,
    ) -> Result<ContainerId> {
        let name = docker_name(&repo_path, &sandbox_name);

        // TODO: There's a potential race condition between inspect and
        // start/run. Another process could stop/remove the container after we
        // inspect it. For robustness, we'd need to retry on specific failures,
        // but that adds complexity. For now, we accept this limitation.

        if let Some(state) = inspect_container(&name)? {
            // Container exists - check if it has the expected image
            if state.image != image.0 {
                anyhow::bail!(
                    "Container '{}' exists with image '{}', but requested image is '{}'",
                    name,
                    state.image,
                    image.0
                );
            }

            if state.status == "running" {
                // Already running with correct image
                return Ok(ContainerId(state.id));
            }

            // Container exists but is stopped - restart it
            start_container(&name)?;
            return Ok(ContainerId(state.id));
        }

        // Create network and container (both use the same name)
        create_network(&name, &sandbox_name, &repo_path)?;
        create_container(&name, &sandbox_name, &image, &repo_path)
    }

    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()> {
        let name = docker_name(&repo_path, &sandbox_name);

        // Stop the container with immediate SIGKILL (-t 0) because containers typically
        // run `sleep infinity` which won't handle SIGTERM gracefully anyway.
        // TODO: For sysbox/systemd containers that don't invoke the provided run command,
        // we should allow a graceful shutdown period.
        let _ = Command::new("docker")
            .args(["stop", "-t", "0", &name])
            .combined_output();

        // Remove the container
        let output = Command::new("docker")
            .args(["rm", "-f", &name])
            .combined_output()
            .context("Failed to execute docker rm")?;

        if !output.status.success() {
            // Ignore "No such container" errors (already deleted)
            if !output.combined_output.contains("No such container") {
                error!("docker rm failed: {}", output.combined_output);
                anyhow::bail!("docker rm failed: {}", output.combined_output.trim());
            }
        }

        // Remove the network (must be done after removing the container)
        delete_network(&name)?;

        Ok(())
    }

    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
        list_sandboxes_for_repo(&repo_path)
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
