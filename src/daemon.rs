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
use bollard::secret::{ContainerCreateBody, HostConfig, Mount as BollardMount, MountTypeEnum};
use bollard::Docker;
use indoc::{formatdoc, indoc};
use listenfd::ListenFd;
use log::error;
use rusqlite::Connection;
use tokio::net::UnixListener;

use crate::async_runtime::block_on;
use crate::config::{is_deterministic_test_mode, Network, RemoteDocker, Runtime};
use crate::devcontainer;
use crate::docker_exec::{exec_check, exec_command};
use crate::gateway;
use crate::git_http_server::{self, GitHttpServer, SharedGitServerState, UnixGitHttpServer};
use protocol::{
    ContainerId, ConversationSummary, Daemon, GetConversationResponse, Image, LaunchResult,
    LifecycleCommands, SandboxInfo, SandboxName, SandboxStatus,
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

fn get_created_files_from_patch(patch: &[u8]) -> Result<Vec<String>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("git")
        .args(["apply", "--summary", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // Ignore stderr
        .spawn()
        .context("spawning git apply")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(patch)
            .context("writing patch to git apply")?;
    }

    let output = child.wait_with_output().context("waiting for git apply")?;
    // Note: git apply might exit non-zero if it detects conflicts, but --summary might still output valid info?
    // Actually --summary should just read headers.

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("create mode ") {
            // format: "100644 filename"
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let filename = parts[1].trim();
                // Basic unquoting if needed
                let clean_name = if filename.starts_with('"') && filename.ends_with('"') {
                    // This is a rough unquote, ideally we unescape
                    &filename[1..filename.len() - 1]
                } else {
                    filename
                };
                files.push(clean_name.to_string());
            }
        }
    }
    Ok(files)
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
    /// Path to the Unix socket for the git HTTP server (used for remote forwarding).
    git_unix_socket: PathBuf,
}

/// Label key used to store the repository path on containers.
const REPO_PATH_LABEL: &str = "dev.sandbox.repo_path";
const CONTAINER_REPO_PATH_LABEL: &str = "dev.sandbox.container_repo_path";

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

/// Ensure a git repository exists at `container_repo_path` inside the container.
///
/// If the directory doesn't contain a `.git`, we clone from the git-http bridge.
/// This handles the devcontainer case where the image doesn't include the repo
/// (unlike .sandbox.toml images which COPY the repo during the build).
fn ensure_repo_initialized(
    docker: &Docker,
    container_id: &str,
    git_http_url: &str,
    token: &str,
    container_repo_path: &Path,
    user: &str,
) -> Result<()> {
    let git_dir = container_repo_path.join(".git");
    let git_dir_str = git_dir.to_string_lossy().to_string();

    // Check if .git already exists
    let has_git = exec_check(
        docker,
        container_id,
        Some(user),
        None,
        vec!["test", "-d", &git_dir_str],
    )?;
    if has_git {
        return Ok(());
    }

    // Ensure parent directories exist
    let parent = container_repo_path.parent().unwrap_or(container_repo_path);
    let parent_str = parent.to_string_lossy().to_string();

    // Create the parent as root (it may be under /workspaces or another root-owned path),
    // then chown the target directory to the sandbox user.
    exec_command(
        docker,
        container_id,
        Some("root"),
        None,
        None,
        vec!["mkdir", "-p", &parent_str],
    )
    .context("creating parent directory for workspaceFolder")?;

    exec_command(
        docker,
        container_id,
        Some("root"),
        None,
        None,
        vec!["chown", user, &parent_str],
    )
    .context("chowning parent directory for workspaceFolder")?;

    // Clone from the git-http bridge with auth header
    let repo_path_str = container_repo_path.to_string_lossy().to_string();
    let auth_header = format!("Authorization: Bearer {}", token);
    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec![
            "git",
            "clone",
            "--config",
            &format!("http.extraHeader={}", auth_header),
            git_http_url,
            &repo_path_str,
        ],
    )
    .context("cloning repository into workspaceFolder")?;

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
#[allow(clippy::too_many_arguments)]
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

    // Configure remotes and fetch in a single shell invocation to avoid
    // transient .git/config lock failures from many sequential docker exec
    // calls (each running a separate `git config`).
    let push_refspec = format!("+refs/heads/*:refs/heads/sandbox/*@{}", sandbox_name.0);
    let setup_script = formatdoc! {r#"
        set -e
        cd "{repo_path_str}"

        git config http.extraHeader "Authorization: Bearer {token}"

        git remote add host "{git_http_url}" 2>/dev/null \
            || git remote set-url host "{git_http_url}"
        git config remote.host.fetch '+refs/heads/host/*:refs/remotes/host/*'
        git config remote.host.pushurl PUSH_DISABLED

        git remote add sandbox "{git_http_url}" 2>/dev/null \
            || git remote set-url sandbox "{git_http_url}"
        git config remote.sandbox.push '{push_refspec}'

        git fetch host
    "#};
    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["sh", "-c", &setup_script],
    )
    .context("configuring git remotes and fetching")?;

    // Helper to run a git command inside the container
    let run_git = |args: &[&str]| -> Result<Vec<u8>> {
        let mut cmd = vec!["git", "-C", &repo_path_str];
        cmd.extend(args);
        exec_command(docker, container_id, Some(user), None, None, cmd)
    };

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
#[allow(clippy::too_many_arguments)]
fn create_container(
    docker: &Docker,
    name: &str,
    sandbox_name: &SandboxName,
    image: &Image,
    repo_path: &Path,
    container_repo_path: &Path,
    runtime: Runtime,
    network_config: Network,
    env: &std::collections::HashMap<String, String>,
    mounts: &[devcontainer::MountObject],
) -> Result<ContainerId> {
    let network_mode = match network_config {
        Network::UnsafeHost => "host",
        Network::Default => "bridge",
    };

    let mut labels = HashMap::new();
    labels.insert(REPO_PATH_LABEL.to_string(), repo_path.display().to_string());
    labels.insert(
        CONTAINER_REPO_PATH_LABEL.to_string(),
        container_repo_path.display().to_string(),
    );
    labels.insert(SANDBOX_NAME_LABEL.to_string(), sandbox_name.0.clone());

    let env_vec = if env.is_empty() {
        None
    } else {
        Some(
            env.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>(),
        )
    };

    // In deterministic PID mode (for tests), we need privileged mode to write to
    // /proc/sys/kernel/ns_last_pid. With --privileged, /proc/sys is mounted rw.
    let deterministic_pids = is_deterministic_test_mode()?;

    let bollard_mounts = if mounts.is_empty() {
        None
    } else {
        Some(
            mounts
                .iter()
                .map(|m| {
                    let typ = match m.mount_type {
                        devcontainer::MountType::Bind => MountTypeEnum::BIND,
                        devcontainer::MountType::Volume => MountTypeEnum::VOLUME,
                        devcontainer::MountType::Tmpfs => MountTypeEnum::TMPFS,
                    };
                    BollardMount {
                        target: Some(m.target.clone()),
                        source: m.source.clone(),
                        typ: Some(typ),
                        read_only: m.read_only,
                        ..Default::default()
                    }
                })
                .collect::<Vec<_>>(),
        )
    };

    let host_config = HostConfig {
        runtime: Some(docker_runtime_flag(runtime).to_string()),
        network_mode: Some(network_mode.to_string()),
        privileged: if deterministic_pids { Some(true) } else { None },
        mounts: bollard_mounts,
        ..Default::default()
    };

    let config = ContainerCreateBody {
        image: Some(image.0.clone()),
        hostname: Some(sandbox_name.0.clone()),
        labels: Some(labels),
        env: env_vec,
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

#[derive(Clone)]
struct SandboxContainerInfo {
    status: SandboxStatus,
}

/// Compute the git status of the sandbox's primary branch vs the currently checked out commit.
/// Returns a string like "ahead 2, behind 3" or "up to date" or None if the ref doesn't exist.
/// "ahead N" means the sandbox is N commits ahead of the host HEAD.
fn compute_git_status(repo_path: &Path, sandbox_name: &str) -> Option<String> {
    use git2::Repository;

    let repo = Repository::open(repo_path).ok()?;

    // Get the current HEAD commit (host)
    let head = repo.head().ok()?;
    let host_oid = head.target()?;

    // Get the sandbox's primary branch ref: refs/remotes/sandbox/<sandbox_name>
    let remote_ref_name = format!("refs/remotes/sandbox/{}", sandbox_name);
    let remote_ref = repo.find_reference(&remote_ref_name).ok()?;
    let sandbox_oid = remote_ref.target()?;

    // If they're the same, we're up to date
    if host_oid == sandbox_oid {
        return Some("up to date".to_string());
    }

    // Count ahead/behind from sandbox's perspective
    // (ahead, behind) = how many commits sandbox is ahead/behind host
    let (ahead, behind) = repo.graph_ahead_behind(sandbox_oid, host_oid).ok()?;

    match (ahead, behind) {
        (0, 0) => Some("up to date".to_string()),
        (a, 0) => Some(format!("ahead {}", a)),
        (0, b) => Some(format!("behind {}", b)),
        (a, b) => Some(format!("ahead {}, behind {}", a, b)),
    }
}

/// List all sandbox containers for a given repository path.
/// Get the status of containers for a repository via a Docker socket.
/// Returns a map from sandbox name to container status.
fn get_container_status_via_socket(
    docker_socket: &Path,
    repo_path: &Path,
) -> Result<HashMap<String, SandboxContainerInfo>> {
    use bollard::models::ContainerSummaryStateEnum;

    let docker = Docker::connect_with_socket(
        docker_socket.to_string_lossy().as_ref(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("connecting to Docker daemon")?;

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

    let mut status_map = HashMap::new();

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

        if container.id.is_some() {
            status_map.insert(sandbox_name, SandboxContainerInfo { status });
        }
    }

    Ok(status_map)
}

/// Execute a single lifecycle command inside a container.
///
/// Supports the three devcontainer command formats:
/// - String: run via shell (`sh -c "command"`)
/// - Array: run directly without shell
/// - Object: run each named command in parallel, wait for all to finish
fn run_lifecycle_command(
    docker: &Docker,
    container_id: &str,
    user: &str,
    workdir: &Path,
    command: &crate::devcontainer::LifecycleCommand,
) -> Result<()> {
    use crate::devcontainer::{LifecycleCommand, StringOrArray};

    let workdir_str = workdir.to_string_lossy();

    match command {
        LifecycleCommand::String(s) => {
            exec_command(
                docker,
                container_id,
                Some(user),
                Some(&workdir_str),
                None,
                vec!["sh", "-c", s],
            )?;
        }
        LifecycleCommand::Array(args) => {
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            exec_command(
                docker,
                container_id,
                Some(user),
                Some(&workdir_str),
                None,
                args_ref,
            )?;
        }
        LifecycleCommand::Object(map) => {
            // Run all named commands in parallel using threads (we're already
            // in a synchronous context). Collect results and fail if any fail.
            let handles: Vec<_> = map
                .iter()
                .map(|(name, cmd_value)| {
                    let cmd_args: Vec<String> = match cmd_value {
                        StringOrArray::String(s) => {
                            vec!["sh".into(), "-c".into(), s.clone()]
                        }
                        StringOrArray::Array(a) => a.clone(),
                    };
                    let docker = docker.clone();
                    let cid = container_id.to_string();
                    let u = user.to_string();
                    let wd = workdir_str.to_string();
                    let task_name = name.clone();

                    std::thread::spawn(move || {
                        let args_ref: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
                        exec_command(&docker, &cid, Some(&u), Some(&wd), None, args_ref)
                            .with_context(|| format!("lifecycle command '{}' failed", task_name))
                    })
                })
                .collect();

            for handle in handles {
                let result = handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("lifecycle command thread panicked"))?;
                result?;
            }
        }
    }

    Ok(())
}

/// Run onCreateCommand and postCreateCommand if they haven't been executed yet.
///
/// These commands run at most once per sandbox lifetime, tracked via the
/// database. If onCreateCommand fails, postCreateCommand is skipped and both
/// are marked as "ran" so they don't retry on subsequent enters.
fn run_once_lifecycle_commands(
    docker: &Docker,
    container_id: &str,
    user: &str,
    workdir: &Path,
    lifecycle: &LifecycleCommands,
    sandbox_id: db::SandboxId,
    db_mutex: &Mutex<rusqlite::Connection>,
) -> Result<()> {
    let on_create_ran = {
        let conn = db_mutex.lock().unwrap();
        db::has_on_create_run(&conn, sandbox_id)?
    };

    if !on_create_ran {
        if let Some(cmd) = &lifecycle.on_create_command {
            if let Err(e) = run_lifecycle_command(docker, container_id, user, workdir, cmd) {
                // Mark both as ran to prevent retries and skip postCreate
                let conn = db_mutex.lock().unwrap();
                db::mark_on_create_ran(&conn, sandbox_id)?;
                db::mark_post_create_ran(&conn, sandbox_id)?;
                return Err(e.context("onCreateCommand failed"));
            }
        }
        let conn = db_mutex.lock().unwrap();
        db::mark_on_create_ran(&conn, sandbox_id)?;
    }

    let post_create_ran = {
        let conn = db_mutex.lock().unwrap();
        db::has_post_create_run(&conn, sandbox_id)?
    };

    if !post_create_ran {
        if let Some(cmd) = &lifecycle.post_create_command {
            if let Err(e) = run_lifecycle_command(docker, container_id, user, workdir, cmd) {
                let conn = db_mutex.lock().unwrap();
                db::mark_post_create_ran(&conn, sandbox_id)?;
                return Err(e.context("postCreateCommand failed"));
            }
        }
        let conn = db_mutex.lock().unwrap();
        db::mark_post_create_ran(&conn, sandbox_id)?;
    }

    Ok(())
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
        env: std::collections::HashMap<String, String>,
        lifecycle: LifecycleCommands,
        mounts: Vec<devcontainer::MountObject>,
    ) -> Result<LaunchResult> {
        // Validate network configuration
        if network == Network::UnsafeHost && runtime != Runtime::Runc {
            anyhow::bail!("network='unsafe-host' is only supported with runtime='runc'");
        }

        // Reject bind mounts on remote Docker hosts — the source paths would
        // reference the remote filesystem, not the developer's machine.
        if remote.is_some() {
            for m in &mounts {
                if m.mount_type == devcontainer::MountType::Bind {
                    anyhow::bail!(
                        "bind mounts are not supported with remote Docker hosts. \
                         The source path '{}' would reference the remote filesystem, \
                         not your local machine. Use volume or tmpfs mounts instead.",
                        m.source.as_deref().unwrap_or("<none>")
                    );
                }
            }
        }

        // Get the host specification string for the database
        let host_spec = remote
            .as_ref()
            .map(|r| format!("ssh://{}:{}", r.destination, r.port))
            .unwrap_or_else(|| db::LOCAL_HOST.to_string());

        // Check for name conflicts between local and remote sandboxes
        {
            let conn = self.db.lock().unwrap();
            if let Some(existing) = db::get_sandbox(&conn, &repo_path, &sandbox_name.0)? {
                // A sandbox with this name exists - check if the host matches
                if existing.host != host_spec {
                    anyhow::bail!(
                        "Sandbox '{}' already exists on {} but was requested on {}.\n\
                         Delete the existing sandbox first with 'sandbox delete {}'.",
                        sandbox_name.0,
                        existing.host,
                        host_spec,
                        sandbox_name.0
                    );
                }
            }
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
        gateway::setup_gateway(&repo_path)?;

        let name = docker_name(&repo_path, &sandbox_name);
        let gateway_path = gateway::gateway_path(&repo_path)?;

        // Determine the git HTTP server URL based on network config and whether remote
        let (server_ip, server_port) = match &remote {
            Some(r) => {
                // Remote Docker: set up SSH remote port forwarding if not already done
                let forwards = match self.ssh_forward.get_remote_forwards(r) {
                    Some(f) => f,
                    None => {
                        // Need to set up forwards - first get the remote's bridge network IP
                        let remote_bridge_ip = git_http_server::get_network_gateway_ip_via_socket(
                            &docker_socket,
                            "bridge",
                        )
                        .context("getting remote bridge network gateway IP")?;

                        self.ssh_forward
                            .setup_git_http_forwards(r, &self.git_unix_socket, &remote_bridge_ip)
                            .context("setting up git HTTP remote forwards")?
                    }
                };

                match network {
                    Network::UnsafeHost => (
                        "127.0.0.1".to_string(),
                        forwards
                            .localhost_port
                            .context("localhost forward not set up")?,
                    ),
                    Network::Default => (
                        forwards.bridge_ip.context("bridge IP not set")?,
                        forwards.bridge_port.context("bridge forward not set up")?,
                    ),
                }
            }
            None => {
                // Local Docker: use the local git HTTP servers directly
                match network {
                    Network::UnsafeHost => ("127.0.0.1".to_string(), self.localhost_server_port),
                    Network::Default => {
                        let bridge_ip = git_http_server::get_network_gateway_ip("bridge")?;
                        (bridge_ip, self.bridge_server_port)
                    }
                }
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

            let was_stopped = state.status != "running";
            if was_stopped {
                // Container exists but is stopped - restart it
                start_container(&docker, &name)?;
            }

            // Ensure sandbox record exists in database
            {
                let conn = self.db.lock().unwrap();
                let sandbox_id = match db::get_sandbox(&conn, &repo_path, &sandbox_name.0)? {
                    Some(sandbox) => sandbox.id,
                    None => db::create_sandbox(&conn, &repo_path, &sandbox_name.0, &host_spec)?,
                };
                db::update_sandbox_status(&conn, sandbox_id, db::SandboxStatus::Ready)?;
            }

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

            // Clone repo if not already present (e.g. devcontainer without COPY)
            ensure_repo_initialized(
                &docker,
                &state.id,
                &url,
                &token,
                &container_repo_path,
                &user,
            )?;

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

            // Container was restarted from stopped state — run postStartCommand
            if was_stopped {
                if let Some(cmd) = &lifecycle.post_start_command {
                    run_lifecycle_command(&docker, &state.id, &user, &container_repo_path, cmd)?;
                }
            }

            // postAttachCommand runs on every enter
            if let Some(cmd) = &lifecycle.post_attach_command {
                run_lifecycle_command(&docker, &state.id, &user, &container_repo_path, cmd)?;
            }

            return Ok(LaunchResult {
                container_id: ContainerId(state.id),
                user,
                docker_socket,
            });
        }

        // Register sandbox with the git HTTP server
        let token = self
            .git_server_state
            .register(gateway_path, sandbox_name.0.clone());

        // Store the token for cleanup on delete
        self.active_tokens
            .lock()
            .unwrap()
            .insert((repo_path.clone(), sandbox_name.0.clone()), token.clone());

        // Create sandbox record in database with status "initializing"
        let sandbox_id = {
            let conn = self.db.lock().unwrap();
            db::create_sandbox(&conn, &repo_path, &sandbox_name.0, &host_spec)?
        };

        // Helper to mark sandbox as error and propagate the original error
        let mark_error = |e: anyhow::Error| -> anyhow::Error {
            if let Ok(conn) = self.db.lock() {
                let _ = db::update_sandbox_status(&conn, sandbox_id, db::SandboxStatus::Error);
            }
            e
        };

        let container_id = create_container(
            &docker,
            &name,
            &sandbox_name,
            &image,
            &repo_path,
            &container_repo_path,
            runtime,
            network,
            &env,
            &mounts,
        )
        .map_err(mark_error)?;

        // Fix ownership of mount targets so the container user can write to them.
        // Docker creates volume/tmpfs mounts as root by default.
        if !mounts.is_empty() {
            let targets: Vec<&str> = mounts.iter().map(|m| m.target.as_str()).collect();
            let mut args = vec!["chown", &user];
            args.extend(targets);
            exec_command(&docker, &container_id.0, Some("root"), None, None, args)
                .context("chown mount targets for container user")
                .map_err(mark_error)?;
        }

        let url = git_http_server::git_http_url(&server_ip, server_port);

        // Clone repo if not already present (e.g. devcontainer without COPY)
        ensure_repo_initialized(
            &docker,
            &container_id.0,
            &url,
            &token,
            &container_repo_path,
            &user,
        )
        .map_err(mark_error)?;

        setup_git_remotes(
            &docker,
            &container_id.0,
            &url,
            &token,
            &container_repo_path,
            &sandbox_name,
            &user,
            host_branch.as_deref(),
        )
        .map_err(mark_error)?;

        // Run lifecycle commands for new container:
        // onCreateCommand -> postCreateCommand -> postStartCommand -> postAttachCommand
        run_once_lifecycle_commands(
            &docker,
            &container_id.0,
            &user,
            &container_repo_path,
            &lifecycle,
            sandbox_id,
            &self.db,
        )
        .map_err(mark_error)?;

        if let Some(cmd) = &lifecycle.post_start_command {
            run_lifecycle_command(&docker, &container_id.0, &user, &container_repo_path, cmd)
                .map_err(mark_error)?;
        }

        if let Some(cmd) = &lifecycle.post_attach_command {
            run_lifecycle_command(&docker, &container_id.0, &user, &container_repo_path, cmd)
                .map_err(mark_error)?;
        }

        // Mark sandbox as ready
        {
            let conn = self.db.lock().unwrap();
            db::update_sandbox_status(&conn, sandbox_id, db::SandboxStatus::Ready)?;
        }

        Ok(LaunchResult {
            container_id,
            user,
            docker_socket,
        })
    }

    fn recreate_sandbox(
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
        env: std::collections::HashMap<String, String>,
        lifecycle: LifecycleCommands,
        mounts: Vec<devcontainer::MountObject>,
    ) -> Result<LaunchResult> {
        let name = docker_name(&repo_path, &sandbox_name);

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

        // 1. Snapshot dirty files if container exists
        let mut patch: Option<Vec<u8>> = None;
        let mut _old_user: Option<String> = None;

        if let Some(state) = inspect_container(&docker, &name)? {
            // Container exists
            if state.status == "running" {
                let resolved_user = resolve_user(&docker, user.clone(), &image.0)?;
                _old_user = Some(resolved_user.clone());

                // Snapshot dirty files
                let repo_path_str = container_repo_path.to_string_lossy().to_string();

                // Add all changes including untracked files
                exec_command(
                    &docker,
                    &state.id,
                    Some(&resolved_user),
                    Some(&repo_path_str),
                    None,
                    vec!["git", "add", "-A"],
                )
                .context("snapshotting: git add -A failed")?;

                // Diff staged changes
                let diff_output = exec_command(
                    &docker,
                    &state.id,
                    Some(&resolved_user),
                    Some(&repo_path_str),
                    None,
                    vec!["git", "diff", "--binary", "--cached"],
                )
                .context("snapshotting: git diff failed")?;

                if !diff_output.is_empty() {
                    patch = Some(diff_output);
                }
            }

            // 2. Delete the container
            // We use the internal deletion logic
            self.delete_sandbox(sandbox_name.clone(), repo_path.clone())?;
        }

        // 3. Create new sandbox
        let launch_result = self.launch_sandbox(
            sandbox_name,
            image,
            repo_path,
            container_repo_path.clone(),
            user,
            runtime,
            network,
            host_branch,
            remote,
            env,
            lifecycle,
            mounts,
        )?;

        // 4. Apply patch if we have one
        if let Some(patch_content) = patch {
            // We need the resolved user from launch_result
            let repo_path_str = container_repo_path.to_string_lossy().to_string();

            // Parse patch to identify files being created that might already exist (e.g. from image)
            // We do this best-effort; if parsing fails, we proceed without deletion.
            if let Ok(created_files) = get_created_files_from_patch(&patch_content) {
                for file in created_files {
                    // Ignore errors (e.g. if file doesn't exist)
                    let _ = exec_command(
                        &docker,
                        &launch_result.container_id.0,
                        Some(&launch_result.user),
                        Some(&repo_path_str),
                        None,
                        vec!["rm", "-f", &file],
                    );
                }
            }

            use crate::docker_exec::exec_with_stdin;

            // Apply the patch
            exec_with_stdin(
                &docker,
                &launch_result.container_id.0,
                Some(&launch_result.user),
                Some(&repo_path_str),
                None,
                vec!["git", "apply", "-"],
                Some(&patch_content),
            )
            .context("applying snapshot patch")?;
        }

        Ok(launch_result)
    }

    fn stop_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()> {
        let name = docker_name(&repo_path, &sandbox_name);

        // Determine Docker socket from DB record
        let docker_socket = {
            let conn = self.db.lock().unwrap();
            match db::get_sandbox(&conn, &repo_path, &sandbox_name.0)? {
                Some(record) => {
                    if record.host == db::LOCAL_HOST {
                        default_docker_socket()
                    } else {
                        let remote = RemoteDocker::parse(&record.host)?;
                        self.ssh_forward.get_socket(&remote)?
                    }
                }
                None => default_docker_socket(),
            }
        };

        let docker = Docker::connect_with_socket(
            docker_socket.to_string_lossy().as_ref(),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .context("connecting to Docker daemon")?;

        let stop_options = bollard::query_parameters::StopContainerOptions {
            t: Some(0),
            ..Default::default()
        };
        block_on(docker.stop_container(&name, Some(stop_options)))
            .with_context(|| format!("stopping container '{}'", name))?;

        Ok(())
    }

    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()> {
        use bollard::errors::Error as BollardError;

        // Retrieve sandbox info to determine host
        let conn = self.db.lock().unwrap();
        let sandbox_record = db::get_sandbox(&conn, &repo_path, &sandbox_name.0)?;
        drop(conn);

        let docker = if let Some(record) = sandbox_record {
            if record.host != db::LOCAL_HOST {
                // Remote sandbox
                let remote =
                    RemoteDocker::parse(&record.host).context("Invalid remote host spec")?;
                let socket_path = self.ssh_forward.get_socket(&remote)?;
                Docker::connect_with_socket(
                    socket_path.to_string_lossy().as_ref(),
                    120,
                    bollard::API_DEFAULT_VERSION,
                )
                .context("connecting to remote Docker daemon")?
            } else {
                Docker::connect_with_socket_defaults().context("connecting to Docker daemon")?
            }
        } else {
            // Sandbox not found in DB. Fallback to local.
            Docker::connect_with_socket_defaults().context("connecting to Docker daemon")?
        };

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

        // Delete sandbox from database (cascades to conversations)
        let conn = self.db.lock().unwrap();
        db::delete_sandbox(&conn, &repo_path, &sandbox_name.0)?;

        Ok(())
    }

    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
        // Get sandboxes from database (includes remote sandboxes)
        let conn = self.db.lock().unwrap();
        let db_sandboxes = db::list_sandboxes(&conn, &repo_path)?;
        drop(conn); // Release lock before calling Docker API

        // Get container status from local Docker
        let local_container_status =
            get_container_status_via_socket(&default_docker_socket(), &repo_path)?;

        // Collect unique remote hosts and check for existing connections
        let mut remote_status_maps: HashMap<String, Option<HashMap<String, SandboxContainerInfo>>> =
            HashMap::new();
        for sandbox in &db_sandboxes {
            if sandbox.host != db::LOCAL_HOST && !remote_status_maps.contains_key(&sandbox.host) {
                // Try to get existing socket for this remote
                let status_map = RemoteDocker::parse(&sandbox.host)
                    .ok()
                    .and_then(|remote| self.ssh_forward.try_get_socket(&remote))
                    .and_then(|socket| get_container_status_via_socket(&socket, &repo_path).ok());
                remote_status_maps.insert(sandbox.host.clone(), status_map);
            }
        }

        // Build combined list with status from Docker where available
        let mut sandboxes = Vec::new();
        for sandbox in db_sandboxes {
            let status = if sandbox.host == db::LOCAL_HOST {
                // Local sandbox - check actual container status
                match local_container_status.get(&sandbox.name) {
                    Some(s) => s.status.clone(),
                    None => {
                        // Container doesn't exist
                        match sandbox.status {
                            db::SandboxStatus::Ready => SandboxStatus::Gone,
                            db::SandboxStatus::Initializing => SandboxStatus::Stopped,
                            db::SandboxStatus::Error => SandboxStatus::Stopped,
                        }
                    }
                }
            } else {
                // Remote sandbox - check if we have live container status
                match remote_status_maps
                    .get(&sandbox.host)
                    .and_then(|m| m.as_ref())
                {
                    Some(status_map) => {
                        // We have a connection - use actual container status
                        match status_map.get(&sandbox.name) {
                            Some(s) => s.status.clone(),
                            None => {
                                // Container doesn't exist on remote
                                match sandbox.status {
                                    db::SandboxStatus::Ready => SandboxStatus::Gone,
                                    db::SandboxStatus::Initializing => SandboxStatus::Stopped,
                                    db::SandboxStatus::Error => SandboxStatus::Stopped,
                                }
                            }
                        }
                    }
                    None => {
                        // No connection - we can't determine the actual status
                        SandboxStatus::Disconnected
                    }
                }
            };

            // Compute git status on the host by comparing HEAD to sandbox/<sandbox_name>
            let repo_state = compute_git_status(&repo_path, &sandbox.name);

            sandboxes.push(SandboxInfo {
                name: sandbox.name,
                status,
                created: sandbox.created_at.format("%Y-%m-%d %H:%M").to_string(),
                host: sandbox.host,
                repo_state,
            });
        }

        Ok(sandboxes)
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

    // Start git HTTP server on a Unix socket for SSH remote port forwarding.
    // This allows the server to be accessed from remote Docker hosts.
    let runtime_dir = crate::config::get_runtime_dir()?;
    let git_unix_socket = runtime_dir.join("git-http.sock");
    let unix_server = UnixGitHttpServer::start(&git_unix_socket, git_server_state.clone())
        .context("starting git HTTP server on Unix socket")?;

    let mut listenfd = ListenFd::from_env();
    let listener = if let Some(listener) = listenfd
        .take_unix_listener(0)
        .context("Failed to take inherited unix listener")?
    {
        listener.set_nonblocking(true)?;
        UnixListener::from_std(listener)?
    } else {
        let socket = socket_path()?;

        // Remove stale socket file if it exists
        if socket.exists() {
            std::fs::remove_file(&socket)?;
        }
        UnixListener::bind(&socket)
            .with_context(|| format!("Failed to bind to {}", socket.display()))?
    };

    let daemon = DaemonServer {
        db: Mutex::new(db_conn),
        git_server_state,
        bridge_server_port: bridge_server.port,
        localhost_server_port: localhost_server.port,
        active_tokens: Mutex::new(BTreeMap::new()),
        ssh_forward,
        git_unix_socket,
    };

    // Keep servers alive for the lifetime of the daemon
    let _bridge_server = bridge_server;
    let _localhost_server = localhost_server;
    let _unix_server = unix_server;

    protocol::serve_daemon(daemon, listener);
}
