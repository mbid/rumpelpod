pub mod db;
pub mod protocol;
pub mod ssh_forward;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use anyhow::{Context, Result};
use bollard::query_parameters::{
    CreateContainerOptions, ListContainersOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::secret::{ContainerCreateBody, HostConfig};
use bollard::Docker;
use indoc::indoc;
use log::error;
use rusqlite::Connection;
use tokio::net::UnixListener;

use crate::async_runtime::block_on;
use crate::config::{Network, RemoteDocker, Runtime};
use crate::docker_exec::exec_command;
use crate::gateway;
use crate::git_http_server::{self, GitHttpServer, SharedGitServerState};
use protocol::{
    ContainerId, ConversationSummary, Daemon, GetConversationResponse, Image, LaunchResult,
    SandboxInfo, SandboxName, SandboxStatus,
};
use ssh_forward::SshForwardManager;

/// Environment variable to override the daemon socket path for testing.
pub const SOCKET_PATH_ENV: &str = "SANDBOX_DAEMON_SOCKET";

/// The default Docker socket path.
const DEFAULT_DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Returns the default Docker socket path.
/// For now, this always returns the local socket path, but will change
/// in the future to support remote Docker hosts via SSH forwarding.
fn default_docker_socket() -> PathBuf {
    PathBuf::from(DEFAULT_DOCKER_SOCKET)
}

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
    /// SQLite connection for conversation history.
    db: Mutex<Connection>,
    /// Shared state for the git HTTP server (maps tokens to sandbox info).
    git_server_state: SharedGitServerState,
    /// Port the bridge network git HTTP server is listening on.
    bridge_server_port: u16,
    /// Port the localhost git HTTP server is listening on.
    localhost_server_port: u16,
    /// Active tokens for each sandbox: (repo_path, sandbox_name) -> token
    /// Used to clean up tokens when sandboxes are deleted.
    active_tokens: Mutex<BTreeMap<(PathBuf, String), String>>,
    /// SSH forward manager for remote Docker hosts.
    ssh_forward: SshForwardManager,
}

/// Label key used to store the repository path on containers.
const REPO_PATH_LABEL: &str = "dev.sandbox.repo_path";

/// Label key used to store the sandbox name on containers.
const SANDBOX_NAME_LABEL: &str = "dev.sandbox.name";

/// Generate a unique docker container name from repo path and sandbox name.
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

/// Get the USER directive from a Docker image.
/// Returns None if the image has no USER set (defaults to root).
fn get_image_user(docker: &Docker, image: &str) -> Result<Option<String>> {
    let inspect = block_on(docker.inspect_image(image))
        .with_context(|| format!("Failed to inspect image '{}'", image))?;

    let user = inspect.config.and_then(|c| c.user).unwrap_or_default();

    if user.is_empty() {
        Ok(None)
    } else {
        Ok(Some(user))
    }
}

/// Resolve the user for a sandbox.
///
/// If `user` is provided, it is used directly.
/// Otherwise, the image's USER directive is used.
/// Returns an error if no user is specified and the image has no USER or uses root.
fn resolve_user(docker: &Docker, user: Option<String>, image: &str) -> Result<String> {
    if let Some(user) = user {
        return Ok(user);
    }

    let image_user = get_image_user(docker, image)?;

    match image_user {
        Some(user) if user != "root" && !user.starts_with("0:") && user != "0" => Ok(user),
        Some(user) => {
            anyhow::bail!(
                "Image '{}' has USER set to '{}' (root). \
                 For security, sandboxes must run as a non-root user.\n\
                 Either set 'user' in .sandbox.toml, or change the image's USER directive.",
                image,
                user
            );
        }
        None => {
            anyhow::bail!(
                "Image '{}' has no USER directive (defaults to root). \
                 For security, sandboxes must run as a non-root user.\n\
                 Either set 'user' in .sandbox.toml, or add a USER directive to the Dockerfile.",
                image
            );
        }
    }
}

/// Inspect an existing container by name. Returns None if container doesn't exist.
fn inspect_container(docker: &Docker, container_name: &str) -> Result<Option<ContainerState>> {
    use bollard::errors::Error as BollardError;

    match block_on(docker.inspect_container(container_name, None)) {
        Ok(response) => {
            let state = response.state.context("missing container state")?;
            let status = state
                .status
                .map(|s| format!("{:?}", s).to_lowercase())
                .unwrap_or_default();

            Ok(Some(ContainerState {
                status,
                image: response.config.and_then(|c| c.image).unwrap_or_default(),
                id: response.id.unwrap_or_default(),
            }))
        }
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(None),
        Err(e) => Err(e).context("inspecting container"),
    }
}

/// Start a stopped container.
fn start_container(docker: &Docker, container_name: &str) -> Result<()> {
    block_on(docker.start_container(container_name, None)).context("starting container")?;
    Ok(())
}

/// Clean up gateway refs for a deleted sandbox.
///
/// Removes all refs matching `sandbox/*@<sandbox_name>` from both the gateway
/// and host repos, including the alias symref `sandbox/<sandbox_name>`.
fn cleanup_sandbox_refs(gateway_path: &Path, repo_path: &Path, sandbox_name: &SandboxName) {
    // Find all refs matching sandbox/*@<sandbox_name> in gateway
    let pattern = format!("refs/heads/sandbox/*@{}", sandbox_name.0);
    if let Ok(output) = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)", &pattern])
        .current_dir(gateway_path)
        .output()
    {
        if output.status.success() {
            let refs = String::from_utf8_lossy(&output.stdout);
            for ref_name in refs.lines().filter(|s| !s.is_empty()) {
                // Delete from gateway
                let _ = Command::new("git")
                    .args(["update-ref", "-d", ref_name])
                    .current_dir(gateway_path)
                    .output();

                // Delete corresponding remote-tracking ref from host
                let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
                let _ = Command::new("git")
                    .args(["update-ref", "-d", &format!("refs/remotes/{}", branch)])
                    .current_dir(repo_path)
                    .output();
            }
        }
    }

    // Delete the alias symref (sandbox/<name> -> sandbox/<name>@<name>)
    let alias_ref = format!("refs/heads/sandbox/{}", sandbox_name.0);
    let _ = Command::new("git")
        .args(["symbolic-ref", "--delete", &alias_ref])
        .current_dir(gateway_path)
        .output();

    // Delete the alias remote-tracking ref from host
    let alias_remote_ref = format!("refs/remotes/sandbox/{}", sandbox_name.0);
    let _ = Command::new("git")
        .args(["update-ref", "-d", &alias_remote_ref])
        .current_dir(repo_path)
        .output();
}

/// Check that the .git directory inside the container is owned by the expected user.
/// Returns an error with a helpful message if ownership doesn't match.
fn check_git_directory_ownership(
    docker: &Docker,
    container_id: &str,
    container_repo_path: &Path,
    user: &str,
) -> Result<()> {
    let git_dir = container_repo_path.join(".git");
    let git_dir_str = git_dir.to_string_lossy().to_string();

    // Get the owner of the .git directory
    let owner_output = exec_command(
        docker,
        container_id,
        None,
        None,
        None,
        vec!["stat", "-c", "%U", &git_dir_str],
    )
    .with_context(|| format!("checking ownership of {}", git_dir_str))?;

    let owner = String::from_utf8_lossy(&owner_output).trim().to_string();

    // Extract just the username part if user is in "user:group" format
    let expected_user = user.split(':').next().unwrap_or(user);

    if owner != expected_user {
        anyhow::bail!(
            "Git directory {} is owned by '{}', but sandbox is configured to run as '{}'.\n\
             Please ensure the repository inside the container is owned by the configured user.\n\
             You can fix this by running: chown -R {} {}",
            git_dir_str,
            owner,
            expected_user,
            user,
            container_repo_path.display()
        );
    }

    Ok(())
}

/// Set up git remotes and hooks inside the container for the gateway repository.
/// Adds "host" and "sandbox" remotes pointing to the git HTTP server.
/// Git commands are run as the specified user to avoid permission issues.
///
/// The "host" remote is configured with a custom fetch refspec that maps
/// `host/*` branches from the gateway to `host/*` remote refs in the sandbox.
/// This way, when the host's `main` branch is stored as `host/main` in the
/// gateway, it appears as `host/main` (not `host/host/main`) after fetching.
///
/// The "sandbox" remote is configured with a push refspec that maps local branches
/// to `sandbox/<branch>@<sandbox_name>` in the gateway, allowing multiple sandboxes
/// to push branches without conflicts.
///
/// A post-commit hook is installed to automatically push commits to the gateway.
///
/// If `host_branch` is provided (only on first entry), the primary branch's upstream
/// will be set to `host/<host_branch>`. This allows `git pull` and `git status` to
/// show meaningful tracking information relative to the host branch.
fn setup_git_remotes(
    docker: &Docker,
    container_id: &str,
    git_http_url: &str,
    token: &str,
    container_repo_path: &Path,
    sandbox_name: &SandboxName,
    user: &str,
    host_branch: Option<&str>,
) -> Result<()> {
    check_git_directory_ownership(docker, container_id, container_repo_path, user)?;

    let repo_path_str = container_repo_path.to_string_lossy().to_string();

    // Helper to run a git command inside the container
    let run_git = |args: &[&str]| -> Result<Vec<u8>> {
        let mut cmd = vec!["git", "-C", &repo_path_str];
        cmd.extend(args);
        exec_command(docker, container_id, Some(user), None, None, cmd)
    };

    // Configure Bearer authentication
    run_git(&[
        "config",
        "http.extraHeader",
        &format!("Authorization: Bearer {}", token),
    ])
    .context("configuring git http.extraHeader")?;

    // Add "host" remote (or update if exists)
    match run_git(&["remote", "add", "host", &git_http_url]) {
        Ok(_) => {}
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("already exists") {
                run_git(&["remote", "set-url", "host", &git_http_url])
                    .context("updating host remote URL")?;
            } else {
                return Err(e).context("adding host remote");
            }
        }
    }

    // Configure fetch refspec: map gateway's host/* branches to host/* remote refs.
    // This strips the "host/" prefix from the gateway branch names, so the host's
    // "main" branch (stored as "host/main" in gateway) becomes "host/main" in sandbox.
    run_git(&[
        "config",
        "remote.host.fetch",
        "+refs/heads/host/*:refs/remotes/host/*",
    ])
    .context("configuring host remote fetch refspec")?;

    // Disable pushing to the host remote - it's fetch-only.
    run_git(&["config", "remote.host.pushurl", "PUSH_DISABLED"])
        .context("disabling push for host remote")?;

    // Add "sandbox" remote (same URL, for pushing sandbox commits to gateway)
    match run_git(&["remote", "add", "sandbox", &git_http_url]) {
        Ok(_) => {}
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("already exists") {
                run_git(&["remote", "set-url", "sandbox", &git_http_url])
                    .context("updating sandbox remote URL")?;
            } else {
                return Err(e).context("adding sandbox remote");
            }
        }
    }

    // Configure push refspec: map local branches to sandbox/<branch>@<sandbox_name>.
    // This namespaces sandbox branches to avoid conflicts between different sandboxes.
    let push_refspec = format!("+refs/heads/*:refs/heads/sandbox/*@{}", sandbox_name.0);
    run_git(&["config", "remote.sandbox.push", &push_refspec])
        .context("configuring sandbox remote push refspec")?;

    // Fetch all refs from the host remote so sandboxes have access to host branches.
    run_git(&["fetch", "host"]).context("fetching from host remote")?;

    // Install reference-transaction hook to auto-push to gateway on any ref update.
    // We install the hook first because we use its presence to detect whether this
    // is the first entry (hook not installed) or a re-entry (hook already installed).
    let is_first_entry = install_sandbox_reference_transaction_hook(
        docker,
        container_id,
        container_repo_path,
        sandbox_name,
        user,
    )?;

    // Create and checkout a branch named after the sandbox, pointing to host/HEAD.
    // Only do this on initial setup to avoid disrupting work in progress.
    if is_first_entry {
        let branch_name = &sandbox_name.0;
        let branch_exists = run_git(&[
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{}", branch_name),
        ])
        .is_ok();

        if branch_exists {
            // Branch exists (e.g., from the image) - reset it to host/HEAD.
            // Use --no-track to prevent git from auto-setting upstream.
            run_git(&["branch", "-f", "--no-track", branch_name, "host/HEAD"])
                .with_context(|| format!("resetting branch '{}' to host/HEAD", branch_name))?;
        } else {
            // Create the branch pointing to host/HEAD.
            // Use --no-track to prevent git from auto-setting upstream based on
            // the remote-tracking ref. We'll set the proper upstream explicitly
            // below if host_branch is provided.
            run_git(&["branch", "--no-track", branch_name, "host/HEAD"])
                .with_context(|| format!("creating branch '{}'", branch_name))?;
        }

        // Checkout the branch
        run_git(&["checkout", branch_name])
            .with_context(|| format!("checking out branch '{}'", branch_name))?;

        // Set upstream to host/<host_branch> if a branch was checked out on the host.
        // This enables `git status` to show tracking info and `git pull` to work.
        if let Some(host_branch) = host_branch {
            let upstream = format!("host/{}", host_branch);
            run_git(&["branch", "--set-upstream-to", &upstream, branch_name]).with_context(
                || format!("setting upstream of '{}' to '{}'", branch_name, upstream),
            )?;
        }
    }

    Ok(())
}

/// Reference-transaction hook script for sandbox repos that pushes branch updates to the gateway.
///
/// This hook is invoked whenever any reference is updated (commits, branch creation,
/// deletion, resets, etc). It runs in the "committed" state after the reference
/// transaction has been committed.
const SANDBOX_REFERENCE_TRANSACTION_HOOK: &str = indoc::indoc! {r#"
    #!/bin/sh
    # Installed by sandbox to sync branch updates to the gateway repository.
    # This allows the host to pull sandbox changes.
    # This hook runs on reference-transaction events.

    # Only process after the transaction is committed
    [ "$1" = "committed" ] || exit 0

    # Process each ref update from stdin
    while read oldvalue newvalue refname; do
        # Only handle local branches (refs/heads/*)
        case "$refname" in
            refs/heads/*)
                branch="${refname#refs/heads/}"
                if [ "$newvalue" = "0000000000000000000000000000000000000000" ]; then
                    # Branch deleted - remove from gateway
                    git push sandbox --delete "$branch" --quiet 2>/dev/null || true
                else
                    # Branch updated or created - push to gateway
                    git push sandbox "$branch" --force --quiet 2>/dev/null || true
                fi
                ;;
        esac
    done
"#};

/// Install the reference-transaction hook in the sandbox repository.
/// Returns true if this is the first installation (first entry), false if already installed.
fn install_sandbox_reference_transaction_hook(
    docker: &Docker,
    container_id: &str,
    container_repo_path: &Path,
    _sandbox_name: &SandboxName,
    user: &str,
) -> Result<bool> {
    let hooks_dir = container_repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join("reference-transaction");
    let hooks_dir_str = hooks_dir.to_string_lossy().to_string();
    let hook_path_str = hook_path.to_string_lossy().to_string();

    // Ensure hooks directory exists
    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["mkdir", "-p", &hooks_dir_str],
    )
    .context("creating hooks directory")?;

    // Check if hook already exists and contains our signature
    let existing_hook = exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["cat", &hook_path_str],
    )
    .ok()
    .map(|b| String::from_utf8_lossy(&b).to_string());

    let hook_signature = "Installed by sandbox to sync branch updates";

    let final_hook = match existing_hook {
        Some(existing) if existing.contains(hook_signature) => {
            // Already installed - this is a re-entry
            return Ok(false);
        }
        Some(existing) => {
            // Append to existing hook
            format!(
                "{}\n\n{}",
                existing.trim_end(),
                SANDBOX_REFERENCE_TRANSACTION_HOOK
            )
        }
        None => SANDBOX_REFERENCE_TRANSACTION_HOOK.to_string(),
    };

    // Write the hook using sh -c with printf to avoid stdin piping issues
    let escaped_hook = final_hook.replace('\\', "\\\\").replace('\'', "'\\''");
    let write_cmd = format!("printf '%s' '{}' > '{}'", escaped_hook, hook_path_str);
    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["sh", "-c", &write_cmd],
    )
    .context("writing reference-transaction hook")?;

    // Make hook executable
    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["chmod", "+x", &hook_path_str],
    )
    .context("making reference-transaction hook executable")?;

    // First installation - this is the first entry
    Ok(true)
}

/// Returns the docker runtime name to pass to `docker run --runtime`.
fn docker_runtime_flag(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Runsc => "runsc",
        Runtime::Runc => "runc",
        Runtime::SysboxRunc => "sysbox-runc",
    }
}

/// Create a new container using the bollard Docker API.
fn create_container(
    docker: &Docker,
    name: &str,
    sandbox_name: &SandboxName,
    image: &Image,
    repo_path: &Path,
    runtime: Runtime,
    network_config: Network,
) -> Result<ContainerId> {
    let network_mode = match network_config {
        Network::UnsafeHost => "host",
        Network::Default => "bridge",
    };

    let mut labels = HashMap::new();
    labels.insert(REPO_PATH_LABEL.to_string(), repo_path.display().to_string());
    labels.insert(SANDBOX_NAME_LABEL.to_string(), sandbox_name.0.clone());

    let host_config = HostConfig {
        runtime: Some(docker_runtime_flag(runtime).to_string()),
        network_mode: Some(network_mode.to_string()),
        ..Default::default()
    };

    let config = ContainerCreateBody {
        image: Some(image.0.clone()),
        hostname: Some(sandbox_name.0.clone()),
        labels: Some(labels),
        cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
        host_config: Some(host_config),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: Some(name.to_string()),
        ..Default::default()
    };

    // Create the container
    let response =
        block_on(docker.create_container(Some(options), config)).context("creating container")?;

    // Start the container (equivalent to docker run's behavior)
    block_on(docker.start_container(&response.id, None)).context("starting container")?;

    Ok(ContainerId(response.id))
}

/// List all sandbox containers for a given repository path.
fn list_sandboxes_for_repo(repo_path: &Path) -> Result<Vec<SandboxInfo>> {
    use bollard::models::ContainerSummaryStateEnum;
    use chrono::{DateTime, Utc};

    let docker = Docker::connect_with_socket_defaults().context("connecting to Docker daemon")?;

    // Filter by label to find containers for this repo
    let mut filters = HashMap::new();
    filters.insert(
        "label".to_string(),
        vec![format!("{}={}", REPO_PATH_LABEL, repo_path.display())],
    );

    let options = ListContainersOptions {
        all: true, // Include stopped containers
        filters: Some(filters),
        ..Default::default()
    };

    let containers =
        block_on(docker.list_containers(Some(options))).context("listing containers")?;

    let mut sandboxes = Vec::new();

    for container in containers {
        let labels = container.labels.unwrap_or_default();
        let sandbox_name = match labels.get(SANDBOX_NAME_LABEL) {
            Some(name) => name.clone(),
            None => continue, // Skip containers without sandbox name label
        };

        let status = match container.state {
            Some(ContainerSummaryStateEnum::RUNNING) => SandboxStatus::Running,
            _ => SandboxStatus::Stopped,
        };

        // Format created timestamp: Unix timestamp -> "YYYY-MM-DD HH:MM"
        let created = container
            .created
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_default();

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
        container_repo_path: PathBuf,
        user: Option<String>,
        runtime: Runtime,
        network: Network,
        host_branch: Option<String>,
        remote: Option<RemoteDocker>,
    ) -> Result<LaunchResult> {
        // Validate network configuration
        if network == Network::UnsafeHost && runtime != Runtime::Runc {
            anyhow::bail!("network='unsafe-host' is only supported with runtime='runc'");
        }

        // Validate that remote Docker doesn't use features that require local access
        if remote.is_some() {
            // Git syncing between remote sandboxes and local repos is not supported
            // because the git HTTP server runs locally and won't be accessible from
            // the remote Docker host's containers.
            log::warn!(
                "Remote Docker configured. Git syncing between sandbox and host is NOT supported."
            );
        }

        // Get the Docker socket to use (local or forwarded from remote)
        let docker_socket = match &remote {
            Some(r) => self.ssh_forward.get_socket(r)?,
            None => default_docker_socket(),
        };

        let docker = Docker::connect_with_socket(
            docker_socket.to_string_lossy().as_ref(),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .context("connecting to Docker daemon")?;

        // Resolve the user first, before any container operations
        let user = resolve_user(&docker, user, &image.0)?;

        // Set up gateway for git synchronization (idempotent)
        // Skip for remote Docker since git sync is not supported
        if !remote.is_some() {
            gateway::setup_gateway(&repo_path)?;
        }

        let name = docker_name(&repo_path, &sandbox_name);
        let gateway_path = gateway::gateway_path(&repo_path)?;

        // Determine the git HTTP server URL based on network config
        let (server_ip, server_port) = match network {
            Network::UnsafeHost => ("127.0.0.1".to_string(), self.localhost_server_port),
            Network::Default => {
                let bridge_ip = git_http_server::get_network_gateway_ip("bridge")?;
                (bridge_ip, self.bridge_server_port)
            }
        };

        // TODO: There's a potential race condition between inspect and
        // start/run. Another process could stop/remove the container after we
        // inspect it. For robustness, we'd need to retry on specific failures,
        // but that adds complexity. For now, we accept this limitation.

        if let Some(state) = inspect_container(&docker, &name)? {
            // Container exists - check if it has the expected image
            if state.image != image.0 {
                anyhow::bail!(
                    "Container '{}' exists with image '{}', but requested image is '{}'",
                    name,
                    state.image,
                    image.0
                );
            }

            if state.status != "running" {
                // Container exists but is stopped - restart it
                start_container(&docker, &name)?;
            }

            // Skip git setup for remote Docker
            if !remote.is_some() {
                // Register sandbox with the git HTTP server (may already be registered, that's OK)
                let token = self
                    .git_server_state
                    .register(gateway_path.clone(), sandbox_name.0.clone());

                // Store the token for cleanup on delete
                self.active_tokens
                    .lock()
                    .unwrap()
                    .insert((repo_path.clone(), sandbox_name.0.clone()), token.clone());

                let url = git_http_server::git_http_url(&server_ip, server_port);

                // On re-entry, don't pass host_branch - we don't want to change
                // the upstream of an existing branch.
                setup_git_remotes(
                    &docker,
                    &state.id,
                    &url,
                    &token,
                    &container_repo_path,
                    &sandbox_name,
                    &user,
                    None,
                )?;
            }

            return Ok(LaunchResult {
                container_id: ContainerId(state.id),
                user,
                docker_socket,
            });
        }

        // Skip git setup for remote Docker
        if !remote.is_some() {
            // Register sandbox with the git HTTP server
            let token = self
                .git_server_state
                .register(gateway_path, sandbox_name.0.clone());

            // Store the token for cleanup on delete
            self.active_tokens
                .lock()
                .unwrap()
                .insert((repo_path.clone(), sandbox_name.0.clone()), token.clone());
        }

        let container_id = create_container(
            &docker,
            &name,
            &sandbox_name,
            &image,
            &repo_path,
            runtime,
            network,
        )?;

        // Skip git setup for remote Docker
        if !remote.is_some() {
            let token = self
                .active_tokens
                .lock()
                .unwrap()
                .get(&(repo_path.clone(), sandbox_name.0.clone()))
                .cloned()
                .expect("token should have been registered above");

            let url = git_http_server::git_http_url(&server_ip, server_port);

            setup_git_remotes(
                &docker,
                &container_id.0,
                &url,
                &token,
                &container_repo_path,
                &sandbox_name,
                &user,
                host_branch.as_deref(),
            )?;
        }

        Ok(LaunchResult {
            container_id,
            user,
            docker_socket,
        })
    }

    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()> {
        use bollard::errors::Error as BollardError;

        let docker =
            Docker::connect_with_socket_defaults().context("connecting to Docker daemon")?;
        let name = docker_name(&repo_path, &sandbox_name);

        // Stop the container with immediate SIGKILL (-t 0) because containers typically
        // run `sleep infinity` which won't handle SIGTERM gracefully anyway.
        // TODO: For sysbox/systemd containers that don't invoke the provided run command,
        // we should allow a graceful shutdown period.
        let stop_options = StopContainerOptions {
            t: Some(0),
            ..Default::default()
        };
        let _ = block_on(docker.stop_container(&name, Some(stop_options)));

        // Remove the container (force in case it's still running)
        let remove_options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        match block_on(docker.remove_container(&name, Some(remove_options))) {
            Ok(()) => {}
            // Ignore "No such container" errors (already deleted)
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(e) => {
                error!("docker rm failed: {}", e);
                anyhow::bail!("docker rm failed: {}", e);
            }
        }

        // Unregister sandbox from git HTTP server
        if let Some(token) = self
            .active_tokens
            .lock()
            .unwrap()
            .remove(&(repo_path.clone(), sandbox_name.0.clone()))
        {
            self.git_server_state.unregister(&token);
        }

        // Clean up gateway refs for this sandbox
        if let Ok(gateway_path) = gateway::gateway_path(&repo_path) {
            cleanup_sandbox_refs(&gateway_path, &repo_path, &sandbox_name);
        }

        // Delete conversation history for this sandbox
        let conn = self.db.lock().unwrap();
        db::delete_conversations(&conn, &repo_path, &sandbox_name.0)?;

        Ok(())
    }

    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
        list_sandboxes_for_repo(&repo_path)
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
        db::save_conversation(
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
        let summaries = db::list_conversations(&conn, &repo_path, &sandbox_name)?;
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
        let conv = db::get_conversation(&conn, id)?;
        Ok(conv.map(|c| GetConversationResponse {
            model: c.model,
            provider: c.provider,
            history: c.history,
        }))
    }
}

pub fn run_daemon() -> Result<()> {
    let socket = socket_path()?;

    // Remove stale socket file if it exists
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }

    // Initialize database
    let db_path = db::db_path()?;
    let db_conn = db::open_db(&db_path)?;

    // Initialize SSH forward manager for remote Docker hosts
    let ssh_forward = SshForwardManager::new().context("initializing SSH forward manager")?;

    // Enter the runtime context so UnixListener::bind can register with the reactor
    let _guard = crate::async_runtime::RUNTIME.enter();

    // Create shared state for the git HTTP server
    let git_server_state = SharedGitServerState::new();

    // Start git HTTP server on the bridge network's gateway IP.
    // Use port 0 to let the OS auto-assign a port, allowing multiple daemons
    // (e.g., in tests) to run simultaneously without port conflicts.
    let bridge_ip = git_http_server::get_network_gateway_ip("bridge")
        .context("getting bridge network gateway IP")?;
    let bridge_server = GitHttpServer::start(&bridge_ip, 0, git_server_state.clone())
        .context("starting git HTTP server on bridge network")?;

    // TODO: Start this lazily only when a sandbox with unsafe-host network is created,
    // instead of always starting it.
    // Start git HTTP server on localhost for unsafe-host network mode
    let localhost_server = GitHttpServer::start("127.0.0.1", 0, git_server_state.clone())
        .context("starting git HTTP server on localhost")?;

    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("Failed to bind to {}", socket.display()))?;

    let daemon = DaemonServer {
        db: Mutex::new(db_conn),
        git_server_state,
        bridge_server_port: bridge_server.port,
        localhost_server_port: localhost_server.port,
        active_tokens: Mutex::new(BTreeMap::new()),
        ssh_forward,
    };

    // Keep servers alive for the lifetime of the daemon
    let _bridge_server = bridge_server;
    let _localhost_server = localhost_server;

    protocol::serve_daemon(daemon, listener);
}
