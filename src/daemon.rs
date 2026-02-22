pub mod db;
pub mod protocol;
pub mod ssh_forward;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bollard::query_parameters::{
    CreateContainerOptions, ListContainersOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::secret::{
    ContainerCreateBody, DeviceMapping, HostConfig, Mount as BollardMount, MountTypeEnum,
    PortBinding,
};
use bollard::Docker;
use indoc::formatdoc;
use listenfd::ListenFd;
use log::error;
use rusqlite::Connection;
use tokio::net::UnixListener;

use crate::async_runtime::block_on;
use crate::config::{is_deterministic_test_mode, is_direct_git_config_mode, DockerHost};
use crate::devcontainer::{
    self, compute_devcontainer_id, shell_escape, substitute_vars, DevContainer, LifecycleCommand,
    Port, PortAttributes, StringOrArray, SubstitutionContext, UserEnvProbe, WaitFor,
};
use crate::docker_exec::{exec_check, exec_command, exec_with_stdin};
use crate::gateway;
use crate::git_http_server::{self, GitHttpServer, SharedGitServerState, UnixGitHttpServer};
use protocol::{
    ContainerId, ConversationSummary, Daemon, EnsureClaudeConfigRequest, GetConversationResponse,
    Image, LaunchResult, PodInfo, PodLaunchParams, PodName, PodStatus, PortInfo,
};
use ssh_forward::SshForwardManager;

/// Environment variable to override the daemon socket path for testing.
pub const SOCKET_PATH_ENV: &str = "RUMPELPOD_DAEMON_SOCKET";

/// Returns the local Docker socket path.
/// Checks DOCKER_HOST first, then probes standard socket locations.
pub fn default_docker_socket() -> PathBuf {
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        if let Some(path) = host.strip_prefix("unix://") {
            return PathBuf::from(path);
        }
    }
    let mut candidates = vec![PathBuf::from("/var/run/docker.sock")];
    if let Some(home) = dirs::home_dir() {
        // Docker Desktop (macOS 4.13+)
        candidates.push(home.join(".docker/run/docker.sock"));
        // Colima
        candidates.push(home.join(".colima/default/docker.sock"));
        // Rancher Desktop
        candidates.push(home.join(".rd/docker.sock"));
    }
    candidates
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("/var/run/docker.sock"))
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
/// Uses $RUMPELPOD_DAEMON_SOCKET if set, then $XDG_RUNTIME_DIR/rumpelpod.sock,
/// then /tmp/rumpelpod-<uid>/rumpelpod.sock as fallback.
pub fn socket_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(SOCKET_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/rumpelpod-{}", uid))
        });
    Ok(runtime_dir.join("rumpelpod.sock"))
}

struct DaemonServer {
    /// SQLite connection for conversation history.
    db: Arc<Mutex<Connection>>,
    /// Shared state for the git HTTP server (maps tokens to pod info).
    git_server_state: SharedGitServerState,
    /// Port the bridge network git HTTP server is listening on.
    bridge_server_port: u16,
    /// IP that containers on the bridge network should use to reach the git server.
    /// On Linux this is the bridge gateway IP (e.g. 172.17.0.1), on macOS Docker
    /// Desktop it's `host.docker.internal`.
    bridge_container_ip: String,
    /// Port the localhost git HTTP server is listening on.
    localhost_server_port: u16,
    /// Active tokens for each pod: (repo_path, pod_name) -> token
    /// Used to clean up tokens when pods are deleted.
    active_tokens: Arc<Mutex<BTreeMap<(PathBuf, String), String>>>,
    /// SSH forward manager for remote Docker hosts.
    ssh_forward: Arc<SshForwardManager>,
    /// Path to the Unix socket for the git HTTP server (used for remote forwarding).
    git_unix_socket: PathBuf,
}

/// Label key used to store the repository path on containers.
const REPO_PATH_LABEL: &str = "dev.rumpelpod.repo_path";
const CONTAINER_REPO_PATH_LABEL: &str = "dev.rumpelpod.container_repo_path";

/// Label key used to store the pod name on containers.
const POD_NAME_LABEL: &str = "dev.rumpelpod.name";

/// Replace characters that Docker does not allow in container names.
/// Docker names must match `[a-zA-Z0-9][a-zA-Z0-9_.-]+`.
fn sanitize_docker_name(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Strip leading chars that are not alphanumeric (Docker requires
    // the first character to be [a-zA-Z0-9]).
    let trimmed = sanitized.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());

    if trimmed.is_empty() {
        // All characters were invalid; fall back so callers always get
        // a non-empty string.
        "pod".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Sanitize a string for use as a container hostname (RFC 1123):
/// alphanumeric and hyphens only, max 63 chars, cannot start/end with hyphen.
fn sanitize_hostname(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = sanitized.trim_matches('-');

    if trimmed.is_empty() {
        "pod".to_string()
    } else if trimmed.len() > 63 {
        trimmed[..63].trim_end_matches('-').to_string()
    } else {
        trimmed.to_string()
    }
}

/// Generate a unique docker container name from repo path and pod name.
/// Format: "<repo_dir>-<pod_name>-<hash_prefix>"
/// where hash is sha256(repo_path + pod_name) truncated to 12 hex chars.
fn docker_name(repo_path: &Path, pod_name: &PodName) -> String {
    use sha2::{Digest, Sha256};

    let repo_dir = repo_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo");

    let mut hasher = Sha256::new();
    hasher.update(repo_path.as_os_str().as_encoded_bytes());
    hasher.update(pod_name.0.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let hash_prefix = &hash[..12];

    sanitize_docker_name(&format!("{}-{}-{}", repo_dir, pod_name.0, hash_prefix))
}

/// Resolve daemon-side variables: `${containerWorkspaceFolder}`,
/// `${containerWorkspaceFolderBasename}`, and `${devcontainerId}`.
///
/// `workspace_folder` is resolved first since `containerWorkspaceFolder`
/// is derived from its resolved value.
fn resolve_daemon_vars(dc: DevContainer, repo_path: &Path, pod_name: &str) -> DevContainer {
    let devcontainer_id = compute_devcontainer_id(repo_path, pod_name);

    // Strip trailing path separators that libgit2 may add to workdir paths.
    let local_ws = repo_path
        .to_string_lossy()
        .trim_end_matches('/')
        .to_string();
    let local_ws_basename = repo_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string());

    // workspace_folder may itself contain ${devcontainerId} or
    // ${localWorkspaceFolderBasename}, so resolve it before deriving
    // containerWorkspaceFolder from it.
    let workspace_folder = dc.workspace_folder.as_ref().map(|wf| {
        substitute_vars(
            wf,
            &SubstitutionContext {
                local_workspace_folder: Some(local_ws.clone()),
                local_workspace_folder_basename: Some(local_ws_basename.clone()),
                devcontainer_id: Some(devcontainer_id.clone()),
                ..Default::default()
            },
        )
    });
    let dc = DevContainer {
        workspace_folder,
        ..dc
    };

    let container_ws = dc.container_repo_path(repo_path);
    let container_ws_str = container_ws.to_string_lossy().to_string();
    let container_ws_basename = container_ws
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string());

    dc.substitute(&SubstitutionContext {
        local_workspace_folder: Some(local_ws),
        local_workspace_folder_basename: Some(local_ws_basename),
        container_workspace_folder: Some(container_ws_str),
        container_workspace_folder_basename: Some(container_ws_basename),
        devcontainer_id: Some(devcontainer_id),
        ..Default::default()
    })
}

/// Container state returned by docker inspect.
struct ContainerState {
    status: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerArch {
    Amd64,
    Arm64,
}

impl ContainerArch {
    fn from_docker(s: &str) -> Result<Self> {
        match s {
            "amd64" => Ok(Self::Amd64),
            "arm64" => Ok(Self::Arm64),
            other => anyhow::bail!("unsupported container architecture '{}'", other),
        }
    }

    /// Filename for the cross-arch binary, e.g. "rumpel-linux-amd64".
    fn binary_name(self) -> &'static str {
        match self {
            Self::Amd64 => "rumpel-linux-amd64",
            Self::Arm64 => "rumpel-linux-arm64",
        }
    }
}

fn get_image_architecture(docker: &Docker, image: &str) -> Result<Option<ContainerArch>> {
    let inspect = block_on(docker.inspect_image(image))
        .with_context(|| format!("Failed to inspect image '{}'", image))?;
    inspect
        .architecture
        .map(|s| ContainerArch::from_docker(&s))
        .transpose()
}

/// Resolve the user for a pod.
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
                 For security, pods must run as a non-root user.\n\
                 Either set 'containerUser' in devcontainer.json, or change the image's USER directive.",
                image,
                user
            );
        }
        None => {
            anyhow::bail!(
                "Image '{}' has no USER directive (defaults to root). \
                 For security, pods must run as a non-root user.\n\
                 Either set 'containerUser' in devcontainer.json, or add a USER directive to the Dockerfile.",
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

/// Clean up pod refs in a single gateway repo.
///
/// Removes all refs matching `rumpelpod/*@<pod_name>` from the gateway
/// and corresponding remote-tracking refs from `host_repo_path`, including
/// the alias symref `rumpelpod/<pod_name>`.
fn cleanup_pod_refs_in_gateway(gateway_path: &Path, host_repo_path: &Path, pod_name: &PodName) {
    let pattern = format!("refs/heads/rumpelpod/*@{}", pod_name.0);
    if let Ok(output) = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)", &pattern])
        .current_dir(gateway_path)
        .output()
    {
        if output.status.success() {
            let refs = String::from_utf8_lossy(&output.stdout);
            for ref_name in refs.lines().filter(|s| !s.is_empty()) {
                let _ = Command::new("git")
                    .args(["update-ref", "-d", ref_name])
                    .current_dir(gateway_path)
                    .output();

                let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
                let _ = Command::new("git")
                    .args(["update-ref", "-d", &format!("refs/remotes/{}", branch)])
                    .current_dir(host_repo_path)
                    .output();
            }
        }
    }

    let alias_ref = format!("refs/heads/rumpelpod/{}", pod_name.0);
    let _ = Command::new("git")
        .args(["symbolic-ref", "--delete", &alias_ref])
        .current_dir(gateway_path)
        .output();

    let alias_remote_ref = format!("refs/remotes/rumpelpod/{}", pod_name.0);
    let _ = Command::new("git")
        .args(["update-ref", "-d", &alias_remote_ref])
        .current_dir(host_repo_path)
        .output();
}

/// Clean up gateway refs for a deleted pod.
///
/// Cleans up the parent gateway and all submodule gateways.
fn cleanup_pod_refs(gateway_path: &Path, repo_path: &Path, pod_name: &PodName) {
    cleanup_pod_refs_in_gateway(gateway_path, repo_path, pod_name);

    // Also clean up refs in each submodule gateway
    for sub in gateway::detect_submodules(repo_path) {
        if let Ok(sub_gateway) = gateway::submodule_gateway_path(repo_path, &sub.displaypath) {
            if sub_gateway.exists() {
                let sub_workdir = repo_path.join(&sub.displaypath);
                cleanup_pod_refs_in_gateway(&sub_gateway, &sub_workdir, pod_name);
            }
        }
    }
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
            "Git directory {} is owned by '{}', but pod is configured to run as '{}'.\n\
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
/// (unlike pre-built images which COPY the repo during the build).
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
        // On first entry the image may have left the repo in a broken state
        // (detached HEAD, unborn branch, dirty index/tree, untracked files).
        // Clean it up so the subsequent branch checkout in setup_git_remotes
        // can succeed.  We detect first entry by the absence of our hook.
        let hook_path = container_repo_path.join(".git/hooks/reference-transaction");
        let hook_str = hook_path.to_string_lossy().to_string();
        let hook_exists = exec_check(
            docker,
            container_id,
            Some(user),
            None,
            vec!["test", "-f", &hook_str],
        )?;
        if !hook_exists {
            sanitize_existing_repo(docker, container_id, container_repo_path, user)?;
        }
        return Ok(());
    }

    // Ensure parent directories exist
    let parent = container_repo_path.parent().unwrap_or(container_repo_path);
    let parent_str = parent.to_string_lossy().to_string();

    // Create the parent as root (it may be under /workspaces or another root-owned path),
    // then chown the target directory to the pod user.
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

    // Set up git-lfs and pull LFS objects.  If git-lfs is not installed in
    // the container the install command will fail and we skip the pull.
    // If install succeeds but pull fails, that is a real error.
    let repo_dir = container_repo_path.to_string_lossy();
    let lfs_installed = exec_command(
        docker,
        container_id,
        Some(user),
        Some(&repo_dir),
        None,
        vec!["git", "lfs", "install", "--local"],
    )
    .is_ok();

    if lfs_installed {
        let has_lfs_files = exec_command(
            docker,
            container_id,
            Some(user),
            Some(&repo_dir),
            None,
            vec!["sh", "-c", "git lfs ls-files 2>/dev/null | grep -q ."],
        )
        .is_ok();
        if has_lfs_files {
            exec_command(
                docker,
                container_id,
                Some(user),
                Some(&repo_dir),
                None,
                vec!["git", "lfs", "pull"],
            )
            .context("git lfs pull failed")?;
        }
    }

    Ok(())
}

/// Clean up a pre-existing .git that may be in a broken state (e.g. from an
/// image that ran git init, left staged files, got stuck mid-merge, etc.).
/// Aborts any in-progress operations, resets the index and working tree to
/// HEAD, and removes untracked files so the subsequent checkout in
/// setup_git_remotes can succeed.
fn sanitize_existing_repo(
    docker: &Docker,
    container_id: &str,
    container_repo_path: &Path,
    user: &str,
) -> Result<()> {
    let repo_path_str = container_repo_path.to_string_lossy().to_string();

    let script = formatdoc! {r#"
        set -e
        cd "{repo_path_str}"

        # Abort any in-progress operations that block checkout/reset
        git merge --abort 2>/dev/null || true
        git rebase --abort 2>/dev/null || true
        git cherry-pick --abort 2>/dev/null || true
        git revert --abort 2>/dev/null || true
        git am --abort 2>/dev/null || true
        git bisect reset 2>/dev/null || true

        if git rev-parse --verify HEAD >/dev/null 2>&1; then
            git reset --hard HEAD
        else
            git rm --cached -r . 2>/dev/null || true
        fi
        git clean -fd
    "#};

    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["sh", "-c", &script],
    )
    .context("sanitizing existing git repository")?;

    Ok(())
}

/// Set up git remotes and hooks inside the container for the gateway repository.
/// Adds "host" and "rumpelpod" remotes pointing to the git HTTP server.
/// Git commands are run as the specified user to avoid permission issues.
///
/// The "host" remote is configured with a custom fetch refspec that maps
/// `host/*` branches from the gateway to remote refs in the pod.
/// This way, when the host's `main` branch is stored as `host/main` in the
/// gateway, it appears as `host/main` (not `host/host/main`) after fetching.
///
/// The "rumpelpod" remote is configured with a push refspec that maps local branches
/// in the gateway, allowing multiple pods
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
    pod_name: &PodName,
    user: &str,
    host_branch: Option<&str>,
) -> Result<()> {
    check_git_directory_ownership(docker, container_id, container_repo_path, user)?;

    let repo_path_str = container_repo_path.to_string_lossy().to_string();

    let push_refspec = format!("+refs/heads/*:refs/heads/rumpelpod/*@{}", pod_name.0);

    let setup_script = if is_direct_git_config_mode()? {
        // Bypass `git config` / `git remote` and write directly to .git/config
        // to avoid flaky lock failures on overlay2 under heavy test parallelism.
        formatdoc! {r#"
            set -e
            cd "{repo_path_str}"

            cat >> .git/config <<'GIT_CONFIG_EOF'
            [http]
            	extraHeader = Authorization: Bearer {token}
            [remote "host"]
            	url = {git_http_url}
            	fetch = +refs/heads/host/*:refs/remotes/host/*
            	pushurl = PUSH_DISABLED
            [remote "rumpelpod"]
            	url = {git_http_url}
            	push = {push_refspec}
            GIT_CONFIG_EOF

            git fetch host
        "#}
    } else {
        // Configure remotes and fetch in a single shell invocation to avoid
        // transient .git/config lock failures from many sequential docker exec
        // calls (each running a separate `git config`).
        formatdoc! {r#"
            set -e
            cd "{repo_path_str}"

            git config http.extraHeader "Authorization: Bearer {token}"

            git remote add host "{git_http_url}" 2>/dev/null \
                || git remote set-url host "{git_http_url}"
            git config remote.host.fetch '+refs/heads/host/*:refs/remotes/host/*'
            git config remote.host.pushurl PUSH_DISABLED

            git remote add rumpelpod "{git_http_url}" 2>/dev/null \
                || git remote set-url rumpelpod "{git_http_url}"
            git config remote.rumpelpod.push '{push_refspec}'

            git fetch host
        "#}
    };

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
    let is_first_entry = install_pod_reference_transaction_hook(
        docker,
        container_id,
        container_repo_path,
        pod_name,
        user,
    )?;

    // Create and checkout a branch named after the pod, pointing to host/HEAD.
    // Only do this on initial setup to avoid disrupting work in progress.
    if is_first_entry {
        let branch_name = &pod_name.0;
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

/// Thin shim that delegates to the rumpel binary copied into the container.
/// The actual logic lives in src/hook.rs.
const POD_REFERENCE_TRANSACTION_HOOK: &str = indoc::indoc! {r#"
    #!/bin/sh
    # Installed by rumpelpod to sync branch updates to the gateway repository.
    exec /opt/rumpelpod/bin/rumpel git-hook reference-transaction "$@"
"#};

/// Install the reference-transaction hook in the pod repository.
/// Returns true if this is the first installation (first entry), false if already installed.
fn install_pod_reference_transaction_hook(
    docker: &Docker,
    container_id: &str,
    container_repo_path: &Path,
    _pod_name: &PodName,
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

    let hook_signature = "Installed by rumpelpod to sync branch updates";

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
                POD_REFERENCE_TRANSACTION_HOOK
            )
        }
        None => POD_REFERENCE_TRANSACTION_HOOK.to_string(),
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

/// Set up submodule repositories inside the pod container.
///
/// For each host submodule: init, rewrite URL to the submodule gateway,
/// clone from gateway, configure remotes and hooks, fetch host refs,
/// and create+checkout a pod branch from host/HEAD.
#[allow(clippy::too_many_arguments)]
fn setup_pod_submodules(
    docker: &Docker,
    container_id: &str,
    git_http_url: &str,
    token: &str,
    container_repo_path: &Path,
    pod_name: &PodName,
    user: &str,
    submodules: &[gateway::SubmoduleInfo],
    is_first_entry: bool,
) -> Result<()> {
    if submodules.is_empty() {
        return Ok(());
    }

    // Only clone submodules on first entry. On re-entry they are already
    // present and `git submodule update` would destructively reset them to
    // the parent's recorded gitlink, discarding any pod-side work.
    //
    // Submodules are sorted by depth so parents are cloned before children.
    // Each submodule is initialized and updated level-by-level via its
    // immediate parent, which handles nested submodules correctly.
    if is_first_entry {
        let base_url = git_http_url.trim_end_matches("/gateway.git");
        let mut init_script = String::from("set -e\n");

        for sub in submodules {
            // The parent worktree is found by stripping `path` (which is
            // relative to the immediate parent) from `displaypath` (which is
            // relative to the top-level repo).  Using displaypath.parent()
            // would be wrong for submodules whose path contains slashes
            // (e.g. "libs/child-sub") -- those live in a subdirectory but
            // are still direct children of the top-level repo.
            let parent_prefix = sub
                .displaypath
                .strip_suffix(&sub.path)
                .unwrap_or("")
                .trim_end_matches('/');
            let parent_dir = if parent_prefix.is_empty() {
                container_repo_path.to_path_buf()
            } else {
                container_repo_path.join(parent_prefix)
            };
            let parent_dir_str = parent_dir.to_string_lossy();

            let sub_url = format!("{}/submodules/{}/gateway.git", base_url, sub.displaypath);

            init_script.push_str(&format!("cd \"{parent_dir_str}\"\n"));
            init_script.push_str(&format!("git submodule init \"{}\"\n", sub.path));
            init_script.push_str(&format!(
                "git config submodule.{}.url \"{}\"\n",
                sub.name, sub_url
            ));
            init_script.push_str(&format!(
                "git -c http.extraHeader=\"Authorization: Bearer {token}\" submodule update \"{}\"\n",
                sub.path
            ));
        }

        exec_command(
            docker,
            container_id,
            Some(user),
            None,
            None,
            vec!["sh", "-c", &init_script],
        )
        .context("initializing submodules")?;
    }

    // Configure each submodule's remotes, hooks, and branch
    let base_url = git_http_url.trim_end_matches("/gateway.git");
    for sub in submodules {
        let sub_path = container_repo_path.join(&sub.displaypath);
        let sub_path_str = sub_path.to_string_lossy().to_string();
        let sub_url = format!("{}/submodules/{}/gateway.git", base_url, sub.displaypath);

        let push_refspec = format!("+refs/heads/*:refs/heads/rumpelpod/*@{}", pod_name.0);

        let setup_script = if is_direct_git_config_mode()? {
            // Resolve the gitdir inside the container since .git is a gitlink
            formatdoc! {r#"
                set -e
                cd "{sub_path_str}"
                git_dir=$(git rev-parse --git-dir)

                cat >> "$git_dir/config" <<'GIT_CONFIG_EOF'
                [http]
                	extraHeader = Authorization: Bearer {token}
                [remote "host"]
                	url = {sub_url}
                	fetch = +refs/heads/host/*:refs/remotes/host/*
                	pushurl = PUSH_DISABLED
                [remote "rumpelpod"]
                	url = {sub_url}
                	push = {push_refspec}
                GIT_CONFIG_EOF

                git fetch host
            "#}
        } else {
            formatdoc! {r#"
                set -e
                cd "{sub_path_str}"

                git config http.extraHeader "Authorization: Bearer {token}"

                git remote add host "{sub_url}" 2>/dev/null \
                    || git remote set-url host "{sub_url}"
                git config remote.host.fetch '+refs/heads/host/*:refs/remotes/host/*'
                git config remote.host.pushurl PUSH_DISABLED

                git remote add rumpelpod "{sub_url}" 2>/dev/null \
                    || git remote set-url rumpelpod "{sub_url}"
                git config remote.rumpelpod.push '{push_refspec}'

                git fetch host
            "#}
        };

        exec_command(
            docker,
            container_id,
            Some(user),
            None,
            None,
            vec!["sh", "-c", &setup_script],
        )
        .with_context(|| format!("configuring submodule '{}' remotes", sub.displaypath))?;

        // Install reference-transaction hook in the submodule (resolve
        // gitdir since .git is a gitlink file in absorbed submodules).
        let hook_script = formatdoc! {r#"
            set -e
            cd "{sub_path_str}"
            git_dir=$(git rev-parse --git-dir)
            mkdir -p "$git_dir/hooks"
            hook_path="$git_dir/hooks/reference-transaction"
            if [ -f "$hook_path" ] && grep -q "Installed by rumpelpod" "$hook_path"; then
                exit 0
            fi
            cat > "$hook_path" <<'HOOK_EOF'
            #!/bin/sh
            # Installed by rumpelpod to sync branch updates to the gateway repository.
            exec /opt/rumpelpod/bin/rumpel git-hook reference-transaction "$@"
            HOOK_EOF
            chmod +x "$hook_path"
        "#};

        exec_command(
            docker,
            container_id,
            Some(user),
            None,
            None,
            vec!["sh", "-c", &hook_script],
        )
        .with_context(|| format!("installing hook in submodule '{}'", sub.displaypath))?;

        // Create and checkout pod branch from host/HEAD on first entry
        if is_first_entry {
            let branch_name = &pod_name.0;
            let branch_script = formatdoc! {r#"
                set -e
                cd "{sub_path_str}"
                if git show-ref --verify --quiet "refs/heads/{branch_name}"; then
                    git branch -f --no-track "{branch_name}" host/HEAD
                else
                    git branch --no-track "{branch_name}" host/HEAD
                fi
                git checkout "{branch_name}"
            "#};

            exec_command(
                docker,
                container_id,
                Some(user),
                None,
                None,
                vec!["sh", "-c", &branch_script],
            )
            .with_context(|| {
                format!(
                    "creating branch '{}' in submodule '{}'",
                    branch_name, sub.displaypath
                )
            })?;
        }
    }

    Ok(())
}

/// Parsed docker run arguments extracted from devcontainer.json `runArgs`.
///
/// These are mapped to the corresponding bollard `HostConfig` fields when
/// creating the container.  Values we don't recognise are silently ignored
/// (they likely belong to newer Docker versions or are unsupported).
struct DockerRunArgs {
    runtime: Option<String>,
    network: Option<String>,
    devices: Vec<String>,
    cap_add: Vec<String>,
    security_opt: Vec<String>,
    labels: Vec<(String, String)>,
    privileged: bool,
    init: bool,
}

/// Map devcontainer.json `runArgs` strings to bollard `HostConfig` fields.
///
/// Handles `--key=value` and `--key value` forms for all recognised flags.
fn parse_run_args_for_docker(args: &[String]) -> DockerRunArgs {
    let mut result = DockerRunArgs {
        runtime: None,
        network: None,
        devices: Vec::new(),
        cap_add: Vec::new(),
        security_opt: Vec::new(),
        labels: Vec::new(),
        privileged: false,
        init: false,
    };

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(val) = strip_flag(arg, "--runtime") {
            result.runtime = Some(val.to_string());
        } else if arg == "--runtime" {
            if let Some(val) = iter.next() {
                result.runtime = Some(val.to_string());
            }
        } else if let Some(val) = strip_flag(arg, "--network") {
            result.network = Some(val.to_string());
        } else if arg == "--network" {
            if let Some(val) = iter.next() {
                result.network = Some(val.to_string());
            }
        } else if let Some(val) = strip_flag(arg, "--device") {
            result.devices.push(val.to_string());
        } else if arg == "--device" {
            if let Some(val) = iter.next() {
                result.devices.push(val.to_string());
            }
        } else if let Some(val) = strip_flag(arg, "--cap-add") {
            result.cap_add.push(val.to_string());
        } else if arg == "--cap-add" {
            if let Some(val) = iter.next() {
                result.cap_add.push(val.to_string());
            }
        } else if let Some(val) = strip_flag(arg, "--security-opt") {
            result.security_opt.push(val.to_string());
        } else if arg == "--security-opt" {
            if let Some(val) = iter.next() {
                result.security_opt.push(val.to_string());
            }
        } else if let Some(val) = strip_flag(arg, "--label") {
            if let Some((k, v)) = val.split_once('=') {
                result.labels.push((k.to_string(), v.to_string()));
            }
        } else if arg == "--label" {
            if let Some(val) = iter.next() {
                if let Some((k, v)) = val.split_once('=') {
                    result.labels.push((k.to_string(), v.to_string()));
                }
            }
        } else if arg == "--privileged" {
            result.privileged = true;
        } else if arg == "--init" {
            result.init = true;
        }
    }

    result
}

/// Strip `--flag=` prefix and return the value, or None if the arg doesn't
/// start with `--flag=`.
fn strip_flag<'a>(arg: &'a str, flag: &str) -> Option<&'a str> {
    let prefix = format!("{}=", flag);
    arg.strip_prefix(&prefix)
}

/// Merge an optional Vec from devcontainer.json first-class properties with
/// additional values parsed from runArgs.
fn merge_string_vecs(base: Option<&Vec<String>>, extra: &[String]) -> Option<Vec<String>> {
    let mut result: Vec<String> = base.cloned().unwrap_or_default();
    result.extend(extra.iter().cloned());
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse a `--device` spec like `/dev/null:/dev/mynull` or `/dev/fuse` into a DeviceMapping.
fn parse_device_mapping(spec: &str) -> DeviceMapping {
    let parts: Vec<&str> = spec.split(':').collect();
    let (host, container, perms) = match parts.len() {
        1 => (parts[0], parts[0], "rwm"),
        2 => (parts[0], parts[1], "rwm"),
        _ => (parts[0], parts[1], parts[2]),
    };
    DeviceMapping {
        path_on_host: Some(host.to_string()),
        path_in_container: Some(container.to_string()),
        cgroup_permissions: Some(perms.to_string()),
    }
}

/// Create a new container using the bollard Docker API.
///
/// `run_args` are the raw docker run arguments from devcontainer.json,
/// mapped to the corresponding bollard API fields.
#[allow(clippy::too_many_arguments)]
fn create_container(
    docker: &Docker,
    name: &str,
    pod_name: &PodName,
    image: &Image,
    repo_path: &Path,
    container_repo_path: &Path,
    dc: &DevContainer,
    mounts: &[devcontainer::MountObject],
    publish_ports: &HashMap<u16, u16>,
) -> Result<ContainerId> {
    let run_args = dc.run_args.as_deref().unwrap_or(&[]);
    let env = dc.container_env.as_ref();

    // Parse runArgs into bollard HostConfig fields
    let run_args_config = parse_run_args_for_docker(run_args);

    let mut labels = HashMap::new();
    labels.insert(REPO_PATH_LABEL.to_string(), repo_path.display().to_string());
    labels.insert(
        CONTAINER_REPO_PATH_LABEL.to_string(),
        container_repo_path.display().to_string(),
    );
    labels.insert(POD_NAME_LABEL.to_string(), pod_name.0.clone());

    // Apply user-specified labels from runArgs
    for (k, v) in &run_args_config.labels {
        labels.insert(k.clone(), v.clone());
    }

    let env_vec = match env {
        Some(e) if !e.is_empty() => Some(
            e.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>(),
        ),
        _ => None,
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

    // Merge privileged: test deterministic mode OR devcontainer setting OR runArgs
    let privileged =
        if deterministic_pids || dc.privileged == Some(true) || run_args_config.privileged {
            Some(true)
        } else {
            None
        };

    let devices = if run_args_config.devices.is_empty() {
        None
    } else {
        Some(
            run_args_config
                .devices
                .iter()
                .map(|d| parse_device_mapping(d))
                .collect(),
        )
    };

    // Merge cap_add from devcontainer.json properties and runArgs
    let cap_add = merge_string_vecs(dc.cap_add.as_ref(), &run_args_config.cap_add);
    // Merge security_opt from devcontainer.json properties and runArgs
    let security_opt = merge_string_vecs(dc.security_opt.as_ref(), &run_args_config.security_opt);

    let port_bindings: HashMap<String, Option<Vec<PortBinding>>> = publish_ports
        .iter()
        .map(|(&container_port, &host_port)| {
            let key = format!("{}/tcp", container_port);
            let binding = PortBinding {
                host_ip: Some("127.0.0.1".to_string()),
                host_port: Some(host_port.to_string()),
            };
            (key, Some(vec![binding]))
        })
        .collect();

    let host_config = HostConfig {
        runtime: run_args_config.runtime,
        network_mode: Some(
            run_args_config
                .network
                .unwrap_or_else(|| "bridge".to_string()),
        ),
        privileged,
        init: dc.init.or(if run_args_config.init {
            Some(true)
        } else {
            None
        }),
        cap_add,
        security_opt,
        devices,
        mounts: bollard_mounts,
        port_bindings: if port_bindings.is_empty() {
            None
        } else {
            Some(port_bindings)
        },
        ..Default::default()
    };

    let exposed_ports: Option<Vec<String>> = if publish_ports.is_empty() {
        None
    } else {
        Some(
            publish_ports
                .keys()
                .map(|port| format!("{}/tcp", port))
                .collect(),
        )
    };

    // Default is true per the devcontainer spec (for image/Dockerfile configs).
    let override_command = dc.override_command.unwrap_or(true);

    let config = ContainerCreateBody {
        image: Some(image.0.clone()),
        hostname: Some(sanitize_hostname(&pod_name.0)),
        labels: Some(labels),
        env: env_vec,
        cmd: if override_command {
            Some(vec!["sleep".to_string(), "infinity".to_string()])
        } else {
            None
        },
        host_config: Some(host_config),
        exposed_ports,
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

/// Check if an error looks like the known Docker overlay2 issue where the
/// container filesystem is not fully visible right after creation.
fn is_overlay2_setup_error(err: &anyhow::Error) -> bool {
    let msg = format!("{:#}", err);
    // "Directory nonexistent" comes from git clone, "index.lock" from
    // git reset/clean -- both are overlay2 failing to expose .git.
    if (msg.contains("Directory nonexistent") && msg.contains(".git"))
        || (msg.contains("index.lock") && msg.contains("No such file or directory"))
    {
        return true;
    }
    // copy_rumpel_binary runs before git ops and hits the same overlay2
    // issue -- the container filesystem is not yet writeable/visible.
    if msg.contains("creating /opt/rumpelpod/bin")
        || msg.contains("writing rumpel binary")
        || msg.contains("making rumpel binary executable")
    {
        return true;
    }
    false
}

/// Force-remove a container by name (best effort, for cleanup before retry).
fn force_remove_container(docker: &Docker, name: &str) {
    let stop_options = StopContainerOptions {
        t: Some(0),
        ..Default::default()
    };
    if let Err(e) = block_on(docker.stop_container(name, Some(stop_options))) {
        error!("failed to stop broken container {}: {}", name, e);
    }

    let remove_options = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    if let Err(e) = block_on(docker.remove_container(name, Some(remove_options))) {
        error!("failed to remove broken container {}: {}", name, e);
    }
}

/// Parse a Port spec into the numeric container port.
fn resolve_port_number(port: &Port) -> Option<u16> {
    match port {
        Port::Number(n) => Some(*n),
        Port::String(s) => {
            if let Some((_host, container)) = s.split_once(':') {
                container.parse().ok()
            } else {
                s.parse().ok()
            }
        }
    }
}

/// Decide which host port to request for each forwarded container port.
///
/// For local Docker, request the container port number as the host port when
/// available and not allocated by another pod. When taken, let Docker
/// auto-assign (port 0). For remote Docker, always auto-assign since the SSH
/// forward manager handles local port allocation independently.
fn compute_publish_ports(
    conn: &Connection,
    forward_ports: &[Port],
    is_remote: bool,
) -> Result<HashMap<u16, u16>> {
    let all_allocated = db::get_all_allocated_local_ports(conn)?;
    let allocated_set: std::collections::HashSet<u16> = all_allocated.into_iter().collect();

    let mut result = HashMap::new();
    for port_spec in forward_ports {
        let container_port = match resolve_port_number(port_spec) {
            Some(p) => p,
            None => continue,
        };
        let host_port = if is_remote {
            0
        } else if !allocated_set.contains(&container_port) && is_port_available(container_port) {
            container_port
        } else {
            0
        };
        result.insert(container_port, host_port);
    }
    Ok(result)
}

/// Read the host ports Docker assigned for published container ports.
fn get_docker_published_ports(docker: &Docker, container_id: &str) -> Result<HashMap<u16, u16>> {
    let inspect = block_on(docker.inspect_container(container_id, None))
        .context("inspecting container for published ports")?;

    let port_map = inspect
        .network_settings
        .and_then(|ns| ns.ports)
        .unwrap_or_default();

    let mut result = HashMap::new();
    for (key, bindings) in &port_map {
        let container_port: u16 = key
            .split('/')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if container_port == 0 {
            continue;
        }
        if let Some(bindings) = bindings {
            for binding in bindings {
                if let Some(host_port_str) = &binding.host_port {
                    if let Ok(host_port) = host_port_str.parse::<u16>() {
                        result.insert(container_port, host_port);
                        break;
                    }
                }
            }
        }
    }
    Ok(result)
}

/// Set up port forwarding for a pod.
///
/// Reads the host ports Docker assigned via `-p` bindings, records them in the
/// database, and for remote pods establishes SSH local forwards.
#[allow(clippy::too_many_arguments)]
fn setup_port_forwarding(
    conn: &Connection,
    ssh_forward: &SshForwardManager,
    docker: &Docker,
    container_id: &str,
    pod_id: db::PodId,
    forward_ports: &[Port],
    ports_attributes: &std::collections::HashMap<String, PortAttributes>,
    other_ports_attributes: &Option<PortAttributes>,
    docker_host: &DockerHost,
) -> Result<()> {
    if forward_ports.is_empty() {
        return Ok(());
    }

    let published = get_docker_published_ports(docker, container_id)?;

    let existing = db::list_forwarded_ports(conn, pod_id)?;
    let existing_map: std::collections::HashMap<u16, u16> = existing
        .iter()
        .map(|p| (p.container_port, p.local_port))
        .collect();

    let all_allocated = db::get_all_allocated_local_ports(conn)?;
    let mut allocated_set: std::collections::HashSet<u16> = all_allocated.into_iter().collect();

    for port_spec in forward_ports {
        let container_port = match resolve_port_number(port_spec) {
            Some(p) => p,
            None => {
                log::warn!("skipping invalid port spec: {:?}", port_spec);
                continue;
            }
        };

        let docker_host_port = match published.get(&container_port) {
            Some(&p) => p,
            None => {
                log::warn!(
                    "container port {} not found in Docker published ports, skipping",
                    container_port
                );
                continue;
            }
        };

        let label = ports_attributes
            .get(&container_port.to_string())
            .or(other_ports_attributes.as_ref())
            .and_then(|a| a.label.as_deref())
            .unwrap_or("")
            .to_string();

        if let Some(&existing_local) = existing_map.get(&container_port) {
            if docker_host.is_remote() && !is_port_in_use(existing_local) {
                ssh_forward
                    .add_local_forward(docker_host, existing_local, "127.0.0.1", docker_host_port)
                    .with_context(|| {
                        format!(
                            "re-establishing SSH forward {}->127.0.0.1:{}",
                            existing_local, docker_host_port
                        )
                    })?;
            }
            continue;
        }

        let local_port = if docker_host.is_remote() {
            let local =
                if !allocated_set.contains(&container_port) && is_port_available(container_port) {
                    container_port
                } else {
                    find_available_port(&allocated_set)?
                };
            ssh_forward
                .add_local_forward(docker_host, local, "127.0.0.1", docker_host_port)
                .with_context(|| {
                    format!("SSH forward {}->127.0.0.1:{}", local, docker_host_port)
                })?;
            local
        } else {
            docker_host_port
        };

        allocated_set.insert(local_port);
        db::insert_forwarded_port(conn, pod_id, container_port, local_port, &label)?;
    }

    Ok(())
}

/// Check if a local port is available for binding.
fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok()
}

/// Check if a local port is already in use.
fn is_port_in_use(port: u16) -> bool {
    !is_port_available(port)
}

/// Find an available port, avoiding already allocated ports.
fn find_available_port(allocated: &std::collections::HashSet<u16>) -> Result<u16> {
    for port in 10000..65000u16 {
        if !allocated.contains(&port) && is_port_available(port) {
            return Ok(port);
        }
    }
    anyhow::bail!("no available ports in range 10000-65000")
}

#[derive(Clone)]
struct PodContainerInfo {
    status: PodStatus,
    container_id: Option<String>,
}

struct PodGitInfo {
    /// e.g. "ahead 2, behind 3" or "up to date"
    repo_state: String,
    /// Committer timestamp (unix seconds) of the tip of the pod's primary branch.
    last_commit_time: i64,
}

/// Compute the git status of the pod's primary branch vs the currently checked out commit.
/// Returns None if the ref doesn't exist.
/// "ahead N" means the pod is N commits ahead of the host HEAD.
fn compute_git_info(repo_path: &Path, pod_name: &str) -> Option<PodGitInfo> {
    use git2::Repository;

    let repo = Repository::open(repo_path).ok()?;

    // Get the current HEAD commit (host)
    let head = repo.head().ok()?;
    let host_oid = head.target()?;

    // Get the pod's primary branch ref: refs/remotes/rumpelpod/<pod_name>
    let remote_ref_name = format!("refs/remotes/rumpelpod/{}", pod_name);
    let remote_ref = repo.find_reference(&remote_ref_name).ok()?;
    let pod_oid = remote_ref.target()?;

    let commit = repo.find_commit(pod_oid).ok()?;
    let last_commit_time = commit.committer().when().seconds();

    let repo_state = if host_oid == pod_oid {
        "up to date".to_string()
    } else {
        // Count ahead/behind from pod's perspective
        // (ahead, behind) = how many commits pod is ahead/behind host
        let (ahead, behind) = repo.graph_ahead_behind(pod_oid, host_oid).ok()?;

        match (ahead, behind) {
            (0, 0) => "up to date".to_string(),
            (a, 0) => format!("ahead {}", a),
            (0, b) => format!("behind {}", b),
            (a, b) => format!("ahead {}, behind {}", a, b),
        }
    };

    Some(PodGitInfo {
        repo_state,
        last_commit_time,
    })
}

/// List all pod containers for a given repository path.
/// Get the status of containers for a repository via a Docker socket.
/// Returns a map from pod name to container status.
fn get_container_status_via_socket(
    docker_socket: &Path,
    repo_path: &Path,
) -> Result<HashMap<String, PodContainerInfo>> {
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
        let pod_name = match labels.get(POD_NAME_LABEL) {
            Some(name) => name.clone(),
            None => continue, // Skip containers without pod name label
        };

        let status = match container.state {
            Some(ContainerSummaryStateEnum::RUNNING) => PodStatus::Running,
            _ => PodStatus::Stopped,
        };

        if let Some(id) = container.id {
            status_map.insert(
                pod_name,
                PodContainerInfo {
                    status,
                    container_id: Some(id),
                },
            );
        }
    }

    Ok(status_map)
}

/// Stop and remove a Docker container by name, connecting to the right host.
/// Returns Ok if the container was removed or already gone (404).
fn try_remove_container(
    ssh_forward: &SshForwardManager,
    host_str: &Option<String>,
    container_name: &str,
) -> Result<()> {
    use bollard::errors::Error as BollardError;

    let socket_path = if let Some(host) = host_str {
        let host = DockerHost::from_db_string(host)?;
        match &host {
            DockerHost::Ssh { .. } => ssh_forward.get_socket(&host)?,
            DockerHost::Localhost => default_docker_socket(),
        }
    } else {
        default_docker_socket()
    };
    let docker = Docker::connect_with_socket(
        socket_path.to_string_lossy().as_ref(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("connecting to Docker daemon")?;

    // Stop the container with immediate SIGKILL (-t 0) because containers typically
    // run `sleep infinity` which won't handle SIGTERM gracefully anyway.
    let stop_options = StopContainerOptions {
        t: Some(0),
        ..Default::default()
    };
    let _ = block_on(docker.stop_container(container_name, Some(stop_options)));

    // Remove the container (force in case it's still running)
    let remove_options = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    match block_on(docker.remove_container(container_name, Some(remove_options))) {
        Ok(()) => Ok(()),
        // Ignore "No such container" errors (already deleted)
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(()),
        Err(e) => {
            anyhow::bail!("docker rm failed: {}", e);
        }
    }
}

/// Parse null-delimited `env -0` output into a HashMap.
fn parse_null_delimited_env(data: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(data);
    let mut map = HashMap::new();
    for entry in text.split('\0') {
        if let Some((key, value)) = entry.split_once('=') {
            if !key.is_empty() {
                map.insert(key.to_string(), value.to_string());
            }
        }
    }
    map
}

/// Probe the user's shell init files to discover environment variables
/// that tools like nvm/pyenv/cargo add to PATH via .bashrc/.profile.
///
/// Returns only variables that differ from the base container environment.
fn probe_user_env(
    docker: &Docker,
    container_id: &str,
    user: &str,
    probe: &UserEnvProbe,
) -> HashMap<String, String> {
    let flags = match probe.shell_flags_exec() {
        Some(f) => f,
        None => return HashMap::new(),
    };

    // Check if bash is available
    let has_bash = match exec_check(
        docker,
        container_id,
        Some(user),
        None,
        vec!["which", "bash"],
    ) {
        Ok(ok) => ok,
        Err(e) => {
            log::warn!("userEnvProbe: failed to check for bash: {e}");
            return HashMap::new();
        }
    };
    if !has_bash {
        log::warn!("userEnvProbe: bash not found, skipping probe");
        return HashMap::new();
    }

    // Get base environment (no shell init files)
    let base_output = match exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["env", "-0"],
    ) {
        Ok(o) => o,
        Err(e) => {
            log::warn!("userEnvProbe: failed to get base env: {e}");
            return HashMap::new();
        }
    };

    // Get probed environment (with shell init files)
    let probed_output = match exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["bash", flags, "env -0"],
    ) {
        Ok(o) => o,
        Err(e) => {
            log::warn!("userEnvProbe: failed to probe env: {e}");
            return HashMap::new();
        }
    };

    let base = parse_null_delimited_env(&base_output);
    let probed = parse_null_delimited_env(&probed_output);

    // Only keep variables that are new or changed
    let skip = ["_", "SHLVL", "BASH_EXECUTION_STRING"];
    probed
        .into_iter()
        .filter(|(key, value)| !skip.contains(&key.as_str()) && base.get(key) != Some(value))
        .collect()
}

/// Query the container user's login shell from `/etc/passwd`.
fn get_user_shell(docker: &Docker, container_id: &str, user: &str) -> String {
    // `getent passwd <user>` returns a colon-delimited line whose last
    // field is the login shell, e.g. "testuser:x:1000:1000::/home/testuser:/bin/bash".
    match exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["getent", "passwd", user],
    ) {
        Ok(output) => {
            let line = String::from_utf8_lossy(&output);
            line.trim()
                .rsplit_once(':')
                .map(|(_, shell)| shell.to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/bin/sh".to_string())
        }
        Err(e) => {
            log::warn!("failed to get user shell from container: {e}");
            "/bin/sh".to_string()
        }
    }
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
    command: &LifecycleCommand,
    env: Option<Vec<&str>>,
) -> Result<()> {
    let workdir_str = workdir.to_string_lossy();

    match command {
        LifecycleCommand::String(s) => {
            exec_command(
                docker,
                container_id,
                Some(user),
                Some(&workdir_str),
                env,
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
                env,
                args_ref,
            )?;
        }
        LifecycleCommand::Object(map) => {
            // Run all named commands in parallel using threads (we're already
            // in a synchronous context). Collect results and fail if any fail.
            let env_owned: Option<Vec<String>> =
                env.map(|v| v.into_iter().map(String::from).collect());
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
                    let thread_env = env_owned.clone();

                    std::thread::spawn(move || {
                        let args_ref: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
                        let env_ref = thread_env
                            .as_ref()
                            .map(|v| v.iter().map(|s| s.as_str()).collect());
                        exec_command(&docker, &cid, Some(&u), Some(&wd), env_ref, args_ref)
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

/// Copy only the minimal Claude Code config files needed to authenticate and
/// run inside a container. Avoids leaking conversation history, telemetry,
/// stats, and other projects' data into untrusted pods.
///
/// What we copy:
///   ~/.claude/.credentials.json  -- OAuth tokens (needed unless ANTHROPIC_API_KEY is set)
///   ~/.claude/settings.json      -- user preferences (model, mode, attribution)
///   ~/.claude.json               -- stripped to only essential keys
fn copy_claude_config(
    docker: &Docker,
    container_id: &str,
    user: &str,
    repo_path: &Path,
    container_repo_path: &Path,
    pod_name: &str,
    auto_approve_hook: bool,
) -> Result<()> {
    let host_home = dirs::home_dir().context("Could not determine home directory")?;

    // Determine the container user's home directory
    let home_output = exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["sh", "-c", "echo $HOME"],
    )
    .context("determining container home directory")?;
    let container_home = String::from_utf8_lossy(&home_output).trim().to_string();

    // Build a minimal .claude.json with only the keys needed to suppress
    // warnings and onboarding prompts. Everything else (tips history,
    // per-project stats, other projects' settings) is left out.
    match std::fs::read(host_home.join(".claude.json")) {
        Ok(data) => {
            let minimal = strip_claude_json(&data, repo_path, container_repo_path);
            let dest = format!("{}/.claude.json", container_home);
            write_file_via_stdin(docker, container_id, user, &dest, &minimal)
                .context("writing .claude.json")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude.json")),
    }

    // We always need ~/.claude/settings.json for the statusline,
    // so create the directory unconditionally.
    let claude_dir = host_home.join(".claude");
    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["mkdir", "-p", &format!("{}/.claude", container_home)],
    )
    .context("creating .claude directory")?;

    // Copy credentials if present.
    match std::fs::read(claude_dir.join(".credentials.json")) {
        Ok(data) => {
            let dest = format!("{}/.claude/.credentials.json", container_home);
            write_file_via_stdin(docker, container_id, user, &dest, &data)
                .context("writing .claude/.credentials.json")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude/.credentials.json")),
    }

    // Build settings.json: start from host copy or empty object,
    // then layer on statusline (and optionally the PermissionRequest hook).
    let base_data = match std::fs::read(claude_dir.join("settings.json")) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => b"{}".to_vec(),
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude/settings.json")),
    };
    let data = inject_statusline(&base_data, pod_name);
    let data = if auto_approve_hook {
        inject_hooks(&data)
    } else {
        data
    };
    let dest = format!("{}/.claude/settings.json", container_home);
    write_file_via_stdin(docker, container_id, user, &dest, &data)
        .context("writing .claude/settings.json")?;

    // Copy project-specific conversation history and memory so claude inside
    // the sandbox can see prior context for the same project.
    copy_claude_project_dir(
        docker,
        container_id,
        user,
        &host_home,
        &container_home,
        repo_path,
        container_repo_path,
    )?;

    // Copy the global input history (filtered to this project) so up-arrow
    // recall works for prior prompts.
    copy_claude_history(
        docker,
        container_id,
        user,
        &host_home,
        &container_home,
        repo_path,
        container_repo_path,
    )?;

    Ok(())
}

/// Claude stores per-project data under ~/.claude/projects/<dir-name> where
/// <dir-name> is the absolute path with every non-alphanumeric character
/// replaced by `-`.  This matches Claude Code's JS implementation:
///   path.replace(/[^a-zA-Z0-9]/g, "-")
fn claude_project_dir_name(repo_path: &Path) -> String {
    repo_path
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Copy the host's project-specific claude data (conversation history, memory)
/// into the container, remapping the directory name to match the container's
/// repo path.
fn copy_claude_project_dir(
    docker: &Docker,
    container_id: &str,
    user: &str,
    host_home: &Path,
    container_home: &str,
    repo_path: &Path,
    container_repo_path: &Path,
) -> Result<()> {
    let host_dir_name = claude_project_dir_name(repo_path);
    let container_dir_name = claude_project_dir_name(container_repo_path);

    let host_project_dir = host_home.join(".claude/projects").join(&host_dir_name);
    if !host_project_dir.is_dir() {
        return Ok(());
    }

    let container_project_dir =
        format!("{}/.claude/projects/{}", container_home, container_dir_name);

    exec_command(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["mkdir", "-p", &container_project_dir],
    )
    .context("creating claude project directory")?;

    // Stream the whole directory via tar to avoid one docker exec per file.
    let tar_output = Command::new("tar")
        .arg("-c")
        .arg("-C")
        .arg(&host_project_dir)
        .arg(".")
        .output()
        .context("creating tar archive of claude project data")?;

    if !tar_output.status.success() {
        anyhow::bail!(
            "tar failed: {}",
            String::from_utf8_lossy(&tar_output.stderr)
        );
    }

    if !tar_output.stdout.is_empty() {
        exec_with_stdin(
            docker,
            container_id,
            Some(user),
            None,
            None,
            vec!["tar", "-x", "-C", &container_project_dir],
            Some(&tar_output.stdout),
        )
        .context("extracting claude project data into container")?;
    }

    Ok(())
}

/// Copy ~/.claude/history.jsonl into the container, keeping only entries for
/// this project and rewriting the project path so up-arrow input recall works.
fn copy_claude_history(
    docker: &Docker,
    container_id: &str,
    user: &str,
    host_home: &Path,
    container_home: &str,
    repo_path: &Path,
    container_repo_path: &Path,
) -> Result<()> {
    let history_path = host_home.join(".claude/history.jsonl");
    let data = match std::fs::read(&history_path) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };

    let host_project = repo_path.to_string_lossy();
    let container_project = container_repo_path.to_string_lossy();

    let mut filtered = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(mut obj) =
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(line)
        else {
            continue;
        };
        let matches = obj
            .get("project")
            .and_then(|v| v.as_str())
            .is_some_and(|p| p == &*host_project);
        if !matches {
            continue;
        }
        obj.insert(
            "project".to_string(),
            serde_json::Value::String(container_project.to_string()),
        );
        if let Ok(serialized) = serde_json::to_vec(&obj) {
            filtered.extend_from_slice(&serialized);
            filtered.push(b'\n');
        }
    }

    if filtered.is_empty() {
        return Ok(());
    }

    let dest = format!("{}/.claude/history.jsonl", container_home);
    write_file_via_stdin(docker, container_id, user, &dest, &filtered)
        .context("writing .claude/history.jsonl")?;

    Ok(())
}

/// Keep only the keys from ~/.claude.json that are needed for a functional
/// session. Returns the serialized JSON bytes to write into the container.
///
/// Also remaps the per-project entry for `repo_path` so it appears under
/// `container_repo_path`, preserving trust-dialog and onboarding state.
fn strip_claude_json(data: &[u8], repo_path: &Path, container_repo_path: &Path) -> Vec<u8> {
    // Keys that suppress warnings/onboarding or are required for auth.
    const KEEP_KEYS: &[&str] = &[
        "hasCompletedOnboarding",
        "lastOnboardingVersion",
        "oauthAccount",
        "primaryApiKey",
        "bypassPermissionsModeAccepted",
        "customApiKeyResponses",
    ];

    let Ok(mut obj) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(data)
    else {
        // If the file is not valid JSON, pass through an empty object so
        // claude does not complain about a missing file.
        return b"{}".to_vec();
    };

    // Extract the project entry for this repo before stripping.
    let project_entry = obj
        .get("projects")
        .and_then(|v| v.as_object())
        .and_then(|projects| projects.get(&*repo_path.to_string_lossy()).cloned());

    obj.retain(|k, _| KEEP_KEYS.contains(&k.as_str()));

    // Re-insert the project entry under the container path so claude in the
    // sandbox inherits trust-dialog acceptance, onboarding state, etc.
    if let Some(entry) = project_entry {
        let container_key = container_repo_path.to_string_lossy().to_string();
        let mut projects = serde_json::Map::new();
        projects.insert(container_key, entry);
        obj.insert("projects".to_string(), serde_json::Value::Object(projects));
    }

    serde_json::to_vec_pretty(&obj).unwrap_or_else(|_| b"{}".to_vec())
}

/// If the host settings.json has no statusLine configured, inject one that
/// displays the pod name so users can tell which rumpelpod they are in.
fn inject_statusline(data: &[u8], pod_name: &str) -> Vec<u8> {
    let Ok(mut obj) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(data)
    else {
        return data.to_vec();
    };

    if obj.contains_key("statusLine") {
        return data.to_vec();
    }

    let escaped = pod_name.replace('\'', "'\\''");
    let cmd = format!("echo 'Rumpelpod: {}'", escaped);
    let mut sl = serde_json::Map::new();
    sl.insert(
        "type".to_string(),
        serde_json::Value::String("command".to_string()),
    );
    sl.insert("command".to_string(), serde_json::Value::String(cmd));
    obj.insert("statusLine".to_string(), serde_json::Value::Object(sl));

    serde_json::to_vec_pretty(&obj).unwrap_or_else(|_| data.to_vec())
}

const RUMPEL_CONTAINER_BIN: &str = "/opt/rumpelpod/bin/rumpel";

/// Inject a PermissionRequest hook that auto-approves all permission
/// dialogs via the rumpel binary inside the container.
fn inject_hooks(data: &[u8]) -> Vec<u8> {
    let Ok(mut obj) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(data)
    else {
        return data.to_vec();
    };

    let command = format!("{} claude-hook permission-request", RUMPEL_CONTAINER_BIN);
    let hook_entry = serde_json::json!({
        "matcher": "",
        "hooks": [
            { "type": "command", "command": command }
        ]
    });

    let hooks_obj = obj
        .entry("hooks")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let serde_json::Value::Object(hooks_map) = hooks_obj {
        let arr = hooks_map
            .entry("PermissionRequest")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let serde_json::Value::Array(vec) = arr {
            let dominated = vec.iter().any(|v| v == &hook_entry);
            if !dominated {
                vec.push(hook_entry);
            }
        }
    }

    serde_json::to_vec_pretty(&obj).unwrap_or_else(|_| data.to_vec())
}

/// Write file contents into a container by piping data through `cat`.
fn write_file_via_stdin(
    docker: &Docker,
    container_id: &str,
    user: &str,
    dest_path: &str,
    data: &[u8],
) -> Result<()> {
    let cmd = format!("cat > {}", shell_escape(dest_path));
    exec_with_stdin(
        docker,
        container_id,
        Some(user),
        None,
        None,
        vec!["sh", "-c", &cmd],
        Some(data),
    )?;
    Ok(())
}

/// Pick the right rumpel binary for the container architecture.
///
/// When the container arch is unknown, returns the running binary.
/// Otherwise looks for `rumpel-linux-{arch}` next to the running
/// executable.
fn resolve_rumpel_binary(container_arch: Option<ContainerArch>) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolving own binary path")?;

    let arch = match container_arch {
        None => return Ok(exe),
        Some(a) => a,
    };

    let exe_dir = exe.parent().context("resolving executable directory")?;
    let bin = exe_dir.join(arch.binary_name());
    anyhow::ensure!(
        bin.exists(),
        "binary '{}' not found next to {}",
        arch.binary_name(),
        exe.display(),
    );
    Ok(bin)
}

/// Copy the rumpel binary into the container so hook shims can invoke it.
///
/// Inspects the container image architecture and, when it differs from
/// the host, resolves the arch-specific binary from the same directory.
fn copy_rumpel_binary(docker: &Docker, container_id: &str, image: &str) -> Result<()> {
    let container_arch = get_image_architecture(docker, image)?;
    let bin = resolve_rumpel_binary(container_arch)?;
    let data = std::fs::read(&bin).with_context(|| format!("reading {}", bin.display()))?;

    exec_command(
        docker,
        container_id,
        Some("root"),
        None,
        None,
        vec!["mkdir", "-p", "/opt/rumpelpod/bin"],
    )
    .context("creating /opt/rumpelpod/bin")?;

    let cmd = format!("cat > {}", shell_escape("/opt/rumpelpod/bin/rumpel"));
    exec_with_stdin(
        docker,
        container_id,
        Some("root"),
        None,
        None,
        vec!["sh", "-c", &cmd],
        Some(&data),
    )
    .context("writing rumpel binary")?;

    exec_command(
        docker,
        container_id,
        Some("root"),
        None,
        None,
        vec!["chmod", "+x", "/opt/rumpelpod/bin/rumpel"],
    )
    .context("making rumpel binary executable")?;

    Ok(())
}

/// These commands run at most once per pod lifetime, tracked via the
/// database. Order: onCreateCommand -> updateContentCommand -> postCreateCommand.
/// If any command fails, later commands in the chain are skipped and marked as
/// "ran" so they don't retry on subsequent enters.
///
/// Commands after the `wait_for` target are not executed here; instead
/// they are returned for background execution so the enter can complete
/// without waiting.
#[allow(clippy::too_many_arguments)]
fn run_once_lifecycle_commands(
    docker: &Docker,
    container_id: &str,
    user: &str,
    workdir: &Path,
    dc: &DevContainer,
    pod_id: db::PodId,
    db_mutex: &Mutex<rusqlite::Connection>,
    wait_for: &WaitFor,
    env: Option<Vec<&str>>,
) -> Result<Vec<(String, LifecycleCommand)>> {
    let mut background = Vec::new();

    let on_create_ran = {
        let conn = db_mutex.lock().unwrap();
        db::has_on_create_run(&conn, pod_id)?
    };

    if !on_create_ran {
        if let Some(cmd) = &dc.on_create_command {
            if *wait_for >= WaitFor::OnCreateCommand {
                if let Err(e) =
                    run_lifecycle_command(docker, container_id, user, workdir, cmd, env.clone())
                {
                    // Mark both as ran to prevent retries and skip postCreate
                    let conn = db_mutex.lock().unwrap();
                    db::mark_on_create_ran(&conn, pod_id)?;
                    db::mark_post_create_ran(&conn, pod_id)?;
                    return Err(e.context("onCreateCommand failed"));
                }
            } else {
                background.push(("onCreateCommand".to_string(), cmd.clone()));
            }
        }
        let conn = db_mutex.lock().unwrap();
        db::mark_on_create_ran(&conn, pod_id)?;
    }

    if let Some(cmd) = &dc.update_content_command {
        if *wait_for >= WaitFor::UpdateContentCommand {
            if let Err(e) =
                run_lifecycle_command(docker, container_id, user, workdir, cmd, env.clone())
            {
                // Skip postCreateCommand on failure
                let conn = db_mutex.lock().unwrap();
                db::mark_post_create_ran(&conn, pod_id)?;
                return Err(e.context("updateContentCommand failed"));
            }
        } else {
            background.push(("updateContentCommand".to_string(), cmd.clone()));
        }
    }

    let post_create_ran = {
        let conn = db_mutex.lock().unwrap();
        db::has_post_create_run(&conn, pod_id)?
    };

    if !post_create_ran {
        if let Some(cmd) = &dc.post_create_command {
            if *wait_for >= WaitFor::PostCreateCommand {
                if let Err(e) =
                    run_lifecycle_command(docker, container_id, user, workdir, cmd, env.clone())
                {
                    let conn = db_mutex.lock().unwrap();
                    db::mark_post_create_ran(&conn, pod_id)?;
                    return Err(e.context("postCreateCommand failed"));
                }
            } else {
                background.push(("postCreateCommand".to_string(), cmd.clone()));
            }
        }
        let conn = db_mutex.lock().unwrap();
        db::mark_post_create_ran(&conn, pod_id)?;
    }

    Ok(background)
}

/// Run lifecycle commands in a background thread.  Errors are logged but
/// do not propagate, so the user's session is unaffected by background
/// failures.
fn spawn_background_lifecycle_commands(
    docker: Docker,
    container_id: String,
    user: String,
    workdir: PathBuf,
    commands: Vec<(String, LifecycleCommand)>,
    env: Option<Vec<String>>,
) {
    std::thread::spawn(move || {
        for (label, cmd) in &commands {
            let env_refs = env.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect());
            if let Err(e) =
                run_lifecycle_command(&docker, &container_id, &user, &workdir, cmd, env_refs)
            {
                error!("background {} failed: {:#}", label, e);
                break;
            }
        }
    });
}

impl Daemon for DaemonServer {
    fn launch_pod(&self, params: PodLaunchParams) -> Result<LaunchResult> {
        let PodLaunchParams {
            pod_name,
            repo_path,
            host_branch,
            docker_host,
            devcontainer,
        } = params;

        // Resolve daemon-side variables (container workspace paths,
        // devcontainerId).  Client-side variables were already resolved
        // before the config was sent to us.
        let devcontainer = resolve_daemon_vars(devcontainer, &repo_path, &pod_name.0);

        let build_result = crate::image::resolve_image(&devcontainer, &docker_host, &repo_path)?;
        let image = build_result.image;
        let image_built = build_result.built;
        let container_repo_path = devcontainer.container_repo_path(&repo_path);
        let user = devcontainer.user().map(String::from);
        let host_network = devcontainer.has_host_network();
        let mounts = devcontainer.resolved_mounts()?;
        let forward_ports = devcontainer.forward_ports.clone().unwrap_or_default();
        let ports_attributes = devcontainer.ports_attributes.clone().unwrap_or_default();
        let other_ports_attributes = devcontainer.other_ports_attributes.clone();

        // Reject bind mounts on remote Docker hosts -- the source paths would
        // reference the remote filesystem, not the developer's machine.
        if docker_host.is_remote() {
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
        let host_spec = docker_host.to_db_string();

        // Check for name conflicts between local and remote pods
        {
            let conn = self.db.lock().unwrap();
            if let Some(existing) = db::get_pod(&conn, &repo_path, &pod_name.0)? {
                // A pod with this name exists - check if the host matches
                if existing.host != host_spec {
                    anyhow::bail!(
                        "Pod '{}' already exists on {} but was requested on {}.\n\
                         Delete the existing pod first with 'rumpel delete {}'.",
                        pod_name.0,
                        existing.host,
                        host_spec,
                        pod_name.0
                    );
                }
            }
        }

        // Get the Docker socket to use (local or forwarded from remote)
        let docker_socket = match &docker_host {
            DockerHost::Ssh { .. } => self.ssh_forward.get_socket(&docker_host)?,
            DockerHost::Localhost => default_docker_socket(),
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
        let submodules = gateway::detect_submodules(&repo_path);

        let name = docker_name(&repo_path, &pod_name);
        let gateway_path = gateway::gateway_path(&repo_path)?;

        // Determine the git HTTP server URL based on network config and local/remote
        let (server_ip, server_port) = match &docker_host {
            DockerHost::Ssh { .. } => {
                // Remote Docker: set up SSH remote port forwarding if not already done
                let forwards = match self.ssh_forward.get_remote_forwards(&docker_host) {
                    Some(f) => f,
                    None => {
                        // Need to set up forwards -- first get the remote's bridge network IP
                        let remote_bridge_ip = git_http_server::get_network_gateway_ip_via_socket(
                            &docker_socket,
                            "bridge",
                        )
                        .context("getting remote bridge network gateway IP")?;

                        self.ssh_forward
                            .setup_git_http_forwards(
                                &docker_host,
                                &self.git_unix_socket,
                                &remote_bridge_ip,
                            )
                            .context("setting up git HTTP remote forwards")?
                    }
                };

                if host_network {
                    (
                        "127.0.0.1".to_string(),
                        forwards
                            .localhost_port
                            .context("localhost forward not set up")?,
                    )
                } else {
                    (
                        forwards.bridge_ip.context("bridge IP not set")?,
                        forwards.bridge_port.context("bridge forward not set up")?,
                    )
                }
            }
            DockerHost::Localhost => {
                // Local Docker: use the local git HTTP servers directly.
                // On macOS Docker Desktop, host.docker.internal works for
                // both bridge and host-network containers since Docker runs
                // in a VM.
                if host_network && !cfg!(target_os = "macos") {
                    ("127.0.0.1".to_string(), self.localhost_server_port)
                } else {
                    (self.bridge_container_ip.clone(), self.bridge_server_port)
                }
            }
        };

        // TODO: There's a potential race condition between inspect and
        // start/run. Another process could stop/remove the container after we
        // inspect it. For robustness, we'd need to retry on specific failures,
        // but that adds complexity. For now, we accept this limitation.

        if let Some(state) = inspect_container(&docker, &name)? {
            let was_stopped = state.status != "running";
            if was_stopped {
                // Container exists but is stopped - restart it
                start_container(&docker, &name)?;
            }

            // Ensure pod record exists in database
            let pod_id = {
                let conn = self.db.lock().unwrap();
                let pod_id = match db::get_pod(&conn, &repo_path, &pod_name.0)? {
                    Some(pod) => pod.id,
                    None => db::create_pod(&conn, &repo_path, &pod_name.0, &host_spec)?,
                };
                db::update_pod_status(&conn, pod_id, db::PodStatus::Ready)?;
                pod_id
            };

            // Register pod with the git HTTP server (may already be registered, that's OK)
            let token = self.git_server_state.register(
                gateway_path.clone(),
                pod_name.0.clone(),
                repo_path.clone(),
            );

            // Store the token for cleanup on delete
            self.active_tokens
                .lock()
                .unwrap()
                .insert((repo_path.clone(), pod_name.0.clone()), token.clone());

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
                &pod_name,
                &user,
                None,
            )?;

            // Set up submodule repos (re-entry: is_first_entry = false)
            setup_pod_submodules(
                &docker,
                &state.id,
                &url,
                &token,
                &container_repo_path,
                &pod_name,
                &user,
                &submodules,
                false,
            )?;

            // Probe user env from shell init files
            let effective_probe = devcontainer
                .user_env_probe
                .as_ref()
                .unwrap_or(&UserEnvProbe::LoginInteractiveShell);
            let probed_env = probe_user_env(&docker, &state.id, &user, effective_probe);
            let env_strings: Vec<String> =
                probed_env.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let env_refs: Option<Vec<&str>> = if env_strings.is_empty() {
                None
            } else {
                Some(env_strings.iter().map(|s| s.as_str()).collect())
            };

            // Run updateContentCommand, per-start, and per-attach lifecycle
            // commands, respecting the waitFor target for background execution.
            let wait_for = devcontainer.effective_wait_for();
            let mut bg_commands: Vec<(String, LifecycleCommand)> = Vec::new();

            // updateContentCommand runs on every re-entry after git sync
            if let Some(cmd) = &devcontainer.update_content_command {
                if wait_for >= WaitFor::UpdateContentCommand {
                    run_lifecycle_command(
                        &docker,
                        &state.id,
                        &user,
                        &container_repo_path,
                        cmd,
                        env_refs.clone(),
                    )?;
                } else {
                    bg_commands.push(("updateContentCommand".to_string(), cmd.clone()));
                }
            }

            if was_stopped {
                if let Some(cmd) = &devcontainer.post_start_command {
                    if wait_for >= WaitFor::PostStartCommand {
                        run_lifecycle_command(
                            &docker,
                            &state.id,
                            &user,
                            &container_repo_path,
                            cmd,
                            env_refs.clone(),
                        )?;
                    } else {
                        bg_commands.push(("postStartCommand".to_string(), cmd.clone()));
                    }
                }
            }

            if let Some(cmd) = &devcontainer.post_attach_command {
                if wait_for >= WaitFor::PostAttachCommand {
                    run_lifecycle_command(
                        &docker,
                        &state.id,
                        &user,
                        &container_repo_path,
                        cmd,
                        env_refs.clone(),
                    )?;
                } else {
                    bg_commands.push(("postAttachCommand".to_string(), cmd.clone()));
                }
            }

            if !bg_commands.is_empty() {
                spawn_background_lifecycle_commands(
                    docker.clone(),
                    state.id.clone(),
                    user.clone(),
                    container_repo_path.clone(),
                    bg_commands,
                    if env_strings.is_empty() {
                        None
                    } else {
                        Some(env_strings.clone())
                    },
                );
            }

            // Set up port forwarding for existing container on re-entry
            if !forward_ports.is_empty() {
                let conn = self.db.lock().unwrap();
                setup_port_forwarding(
                    &conn,
                    &self.ssh_forward,
                    &docker,
                    &state.id,
                    pod_id,
                    &forward_ports,
                    &ports_attributes,
                    &other_ports_attributes,
                    &docker_host,
                )?;
            }

            let user_shell = get_user_shell(&docker, &state.id, &user);

            return Ok(LaunchResult {
                container_id: ContainerId(state.id),
                user,
                docker_socket,
                image_built,
                probed_env,
                user_shell,
            });
        }

        // Register pod with the git HTTP server
        let token =
            self.git_server_state
                .register(gateway_path, pod_name.0.clone(), repo_path.clone());

        // Store the token for cleanup on delete
        self.active_tokens
            .lock()
            .unwrap()
            .insert((repo_path.clone(), pod_name.0.clone()), token.clone());

        // Create pod record in database with status "initializing"
        let pod_id = {
            let conn = self.db.lock().unwrap();
            db::create_pod(&conn, &repo_path, &pod_name.0, &host_spec)?
        };

        // Helper to mark pod as error and propagate the original error
        let mark_error = |e: anyhow::Error| -> anyhow::Error {
            if let Ok(conn) = self.db.lock() {
                let _ = db::update_pod_status(&conn, pod_id, db::PodStatus::Error);
            }
            e
        };

        let publish_ports = {
            let conn = self.db.lock().unwrap();
            compute_publish_ports(&conn, &forward_ports, docker_host.is_remote())?
        };

        let url = git_http_server::git_http_url(&server_ip, server_port);

        // Create container and run initial git setup.  Closure used so we
        // can retry once on overlay2 filesystem errors (see below).
        let do_create_and_setup = || -> Result<ContainerId> {
            let container_id = create_container(
                &docker,
                &name,
                &pod_name,
                &image,
                &repo_path,
                &container_repo_path,
                &devcontainer,
                &mounts,
                &publish_ports,
            )?;

            // Fix ownership of mount targets so the container user can write
            // to them.  Docker creates volume/tmpfs mounts as root by default.
            if !mounts.is_empty() {
                let targets: Vec<&str> = mounts.iter().map(|m| m.target.as_str()).collect();
                let mut args = vec!["chown", &user];
                args.extend(targets);
                exec_command(&docker, &container_id.0, Some("root"), None, None, args)
                    .context("chown mount targets for container user")?;
            }

            // The rumpel binary must be present before git operations
            // that trigger the reference-transaction hook shim.
            copy_rumpel_binary(&docker, &container_id.0, &image.0)?;

            ensure_repo_initialized(
                &docker,
                &container_id.0,
                &url,
                &token,
                &container_repo_path,
                &user,
            )?;

            setup_git_remotes(
                &docker,
                &container_id.0,
                &url,
                &token,
                &container_repo_path,
                &pod_name,
                &user,
                host_branch.as_deref(),
            )?;

            // Set up submodule repos (new container: is_first_entry = true)
            setup_pod_submodules(
                &docker,
                &container_id.0,
                &url,
                &token,
                &container_repo_path,
                &pod_name,
                &user,
                &submodules,
                true,
            )?;

            Ok(container_id)
        };

        // Docker's overlay2 storage driver occasionally fails to make the
        // container filesystem visible right after creation.  Retry once
        // after removing the broken container.
        let container_id = match do_create_and_setup() {
            Ok(id) => id,
            Err(first_err) if is_overlay2_setup_error(&first_err) => {
                error!(
                    "overlay2 setup error, removing container and retrying: {:#}",
                    first_err
                );
                force_remove_container(&docker, &name);
                do_create_and_setup().map_err(|e| {
                    mark_error(e.context(
                        "container setup failed again after retry; this is a known \
                         Docker/overlay2 limitation -- please retry",
                    ))
                })?
            }
            Err(e) => return Err(mark_error(e)),
        };

        // Probe user env from shell init files
        let effective_probe = devcontainer
            .user_env_probe
            .as_ref()
            .unwrap_or(&UserEnvProbe::LoginInteractiveShell);
        let probed_env = probe_user_env(&docker, &container_id.0, &user, effective_probe);
        let env_strings: Vec<String> = probed_env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let env_refs: Option<Vec<&str>> = if env_strings.is_empty() {
            None
        } else {
            Some(env_strings.iter().map(|s| s.as_str()).collect())
        };

        // Run lifecycle commands for new container:
        // onCreateCommand -> updateContentCommand -> postCreateCommand ->
        // postStartCommand -> postAttachCommand
        // Commands up to and including the waitFor target run synchronously;
        // the rest are handed off to a background thread.
        let wait_for = devcontainer.effective_wait_for();

        let mut bg_commands = run_once_lifecycle_commands(
            &docker,
            &container_id.0,
            &user,
            &container_repo_path,
            &devcontainer,
            pod_id,
            &self.db,
            &wait_for,
            env_refs.clone(),
        )
        .map_err(mark_error)?;

        if wait_for >= WaitFor::PostStartCommand {
            if let Some(cmd) = &devcontainer.post_start_command {
                run_lifecycle_command(
                    &docker,
                    &container_id.0,
                    &user,
                    &container_repo_path,
                    cmd,
                    env_refs.clone(),
                )
                .map_err(mark_error)?;
            }
        } else if let Some(cmd) = &devcontainer.post_start_command {
            bg_commands.push(("postStartCommand".to_string(), cmd.clone()));
        }

        if wait_for >= WaitFor::PostAttachCommand {
            if let Some(cmd) = &devcontainer.post_attach_command {
                run_lifecycle_command(
                    &docker,
                    &container_id.0,
                    &user,
                    &container_repo_path,
                    cmd,
                    env_refs.clone(),
                )
                .map_err(mark_error)?;
            }
        } else if let Some(cmd) = &devcontainer.post_attach_command {
            bg_commands.push(("postAttachCommand".to_string(), cmd.clone()));
        }

        if !bg_commands.is_empty() {
            spawn_background_lifecycle_commands(
                docker.clone(),
                container_id.0.clone(),
                user.clone(),
                container_repo_path.clone(),
                bg_commands,
                if env_strings.is_empty() {
                    None
                } else {
                    Some(env_strings)
                },
            );
        }

        // Mark pod as ready and set up port forwarding
        {
            let conn = self.db.lock().unwrap();
            db::update_pod_status(&conn, pod_id, db::PodStatus::Ready)?;

            if !forward_ports.is_empty() {
                setup_port_forwarding(
                    &conn,
                    &self.ssh_forward,
                    &docker,
                    &container_id.0,
                    pod_id,
                    &forward_ports,
                    &ports_attributes,
                    &other_ports_attributes,
                    &docker_host,
                )
                .map_err(|e| {
                    error!("port forwarding setup failed: {}", e);
                    e
                })?;
            }
        }

        let user_shell = get_user_shell(&docker, &container_id.0, &user);

        Ok(LaunchResult {
            container_id,
            user,
            docker_socket,
            image_built,
            probed_env,
            user_shell,
        })
    }

    fn recreate_pod(&self, mut params: PodLaunchParams) -> Result<LaunchResult> {
        // Resolve daemon-side variables so container_repo_path and other
        // fields are fully resolved before we use them for snapshotting.
        params.devcontainer =
            resolve_daemon_vars(params.devcontainer, &params.repo_path, &params.pod_name.0);

        let pod_name = &params.pod_name;
        let repo_path = &params.repo_path;
        let docker_host = &params.docker_host;
        // resolve_image here is only for resolve_user during snapshotting;
        // the actual image_built flag comes from self.launch_pod below.
        let image =
            crate::image::resolve_image(&params.devcontainer, docker_host, repo_path)?.image;
        let container_repo_path = params.devcontainer.container_repo_path(repo_path);
        let user = params.devcontainer.user().map(String::from);

        let name = docker_name(repo_path, pod_name);

        // Get the Docker socket to use (local or forwarded from remote)
        let docker_socket = match docker_host {
            DockerHost::Ssh { .. } => self.ssh_forward.get_socket(docker_host)?,
            DockerHost::Localhost => default_docker_socket(),
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

            // 2. Delete the container synchronously so launch_pod can reuse the name
            self.delete_pod(pod_name.clone(), repo_path.clone(), true)?;
        }

        // 3. Create new pod
        let launch_result = self.launch_pod(params)?;

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

            // Sync submodule working trees with the gitlinks restored by the
            // patch.  Best-effort: uncommitted changes inside submodules are
            // lost on recreate since git add -A only captures gitlink changes.
            let _ = exec_command(
                &docker,
                &launch_result.container_id.0,
                Some(&launch_result.user),
                Some(&repo_path_str),
                None,
                vec!["git", "submodule", "update", "--recursive"],
            );
        }

        Ok(launch_result)
    }

    fn stop_pod(&self, pod_name: PodName, repo_path: PathBuf) -> Result<()> {
        let name = docker_name(&repo_path, &pod_name);

        // Determine Docker socket from DB record
        let docker_socket = {
            let conn = self.db.lock().unwrap();
            match db::get_pod(&conn, &repo_path, &pod_name.0)? {
                Some(record) => {
                    let host = DockerHost::from_db_string(&record.host)?;
                    match &host {
                        DockerHost::Ssh { .. } => self.ssh_forward.get_socket(&host)?,
                        DockerHost::Localhost => default_docker_socket(),
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

    fn delete_pod(&self, pod_name: PodName, repo_path: PathBuf, wait: bool) -> Result<()> {
        let conn = self.db.lock().unwrap();
        let pod_record = db::get_pod(&conn, &repo_path, &pod_name.0)?;
        if let Some(ref record) = pod_record {
            db::update_pod_status(&conn, record.id, db::PodStatus::Deleting)?;
        }
        let host_str = pod_record.map(|r| r.host);
        drop(conn);

        let container_name = docker_name(&repo_path, &pod_name);

        if wait {
            try_remove_container(&self.ssh_forward, &host_str, &container_name)?;

            if let Some(token) = self
                .active_tokens
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()))
            {
                self.git_server_state.unregister(&token);
            }
            if let Ok(gateway_path) = gateway::gateway_path(&repo_path) {
                cleanup_pod_refs(&gateway_path, &repo_path, &pod_name);
            }
            let conn = self.db.lock().unwrap();
            db::delete_pod(&conn, &repo_path, &pod_name.0)?;
        } else {
            // Docker overlay unmounts sometimes take a while on busy systems.
            // Run removal in the background with retries so the CLI returns
            // immediately.
            let db = self.db.clone();
            let active_tokens = self.active_tokens.clone();
            let git_server_state = self.git_server_state.clone();
            let ssh_forward = self.ssh_forward.clone();
            let repo_path = repo_path.clone();
            let pod_name = pod_name.clone();
            std::thread::spawn(move || {
                let delays_secs = [0, 10, 60];
                for (attempt, &delay) in delays_secs.iter().enumerate() {
                    if delay > 0 {
                        std::thread::sleep(std::time::Duration::from_secs(delay));
                    }
                    match try_remove_container(&ssh_forward, &host_str, &container_name) {
                        Ok(()) => {
                            if let Some(token) = active_tokens
                                .lock()
                                .unwrap()
                                .remove(&(repo_path.clone(), pod_name.0.clone()))
                            {
                                git_server_state.unregister(&token);
                            }
                            if let Ok(gateway_path) = gateway::gateway_path(&repo_path) {
                                cleanup_pod_refs(&gateway_path, &repo_path, &pod_name);
                            }
                            let conn = db.lock().unwrap();
                            let _ = db::delete_pod(&conn, &repo_path, &pod_name.0);
                            return;
                        }
                        Err(e) => {
                            error!(
                                "delete attempt {} for pod '{}' failed: {}",
                                attempt + 1,
                                pod_name.0,
                                e
                            );
                        }
                    }
                }
                error!("all delete attempts failed for pod '{}'", pod_name.0);
                let conn = db.lock().unwrap();
                if let Ok(Some(record)) = db::get_pod(&conn, &repo_path, &pod_name.0) {
                    let _ = db::update_pod_status(&conn, record.id, db::PodStatus::DeleteFailed);
                }
            });
        }

        Ok(())
    }

    fn list_pods(&self, repo_path: PathBuf) -> Result<Vec<PodInfo>> {
        // Get pods from database (includes remote pods)
        let conn = self.db.lock().unwrap();
        let db_pods = db::list_pods(&conn, &repo_path)?;
        drop(conn); // Release lock before calling Docker API

        // Get container status from local Docker
        let local_container_status =
            get_container_status_via_socket(&default_docker_socket(), &repo_path)?;

        // Collect unique remote hosts and check for existing connections
        let mut remote_status_maps: HashMap<String, Option<HashMap<String, PodContainerInfo>>> =
            HashMap::new();
        for pod in &db_pods {
            let host = DockerHost::from_db_string(&pod.host).ok();
            let is_remote = host.as_ref().is_some_and(|h| h.is_remote());
            if is_remote && !remote_status_maps.contains_key(&pod.host) {
                // Try to get existing socket for this remote
                let status_map = host
                    .as_ref()
                    .and_then(|h| self.ssh_forward.try_get_socket(h))
                    .and_then(|socket| get_container_status_via_socket(&socket, &repo_path).ok());
                remote_status_maps.insert(pod.host.clone(), status_map);
            }
        }

        // Build combined list with status from Docker where available
        let mut pods = Vec::new();
        for pod in db_pods {
            let host = DockerHost::from_db_string(&pod.host).ok();
            let is_remote = host.as_ref().is_some_and(|h| h.is_remote());

            let container_info = if !is_remote {
                local_container_status.get(&pod.name)
            } else {
                remote_status_maps
                    .get(&pod.host)
                    .and_then(|m| m.as_ref())
                    .and_then(|status_map| status_map.get(&pod.name))
            };

            let status = match pod.status {
                // DB status takes precedence during deletion
                db::PodStatus::Deleting => PodStatus::Deleting,
                db::PodStatus::DeleteFailed => PodStatus::Broken,
                _ => match container_info {
                    Some(info) => info.status.clone(),
                    None => {
                        if is_remote
                            && remote_status_maps
                                .get(&pod.host)
                                .is_none_or(|m| m.is_none())
                        {
                            // No connection to remote -- can't determine actual status
                            PodStatus::Disconnected
                        } else {
                            // Container doesn't exist locally or on the remote
                            match pod.status {
                                db::PodStatus::Ready => PodStatus::Gone,
                                db::PodStatus::Initializing | db::PodStatus::Error => {
                                    PodStatus::Stopped
                                }
                                // Already handled in outer match
                                db::PodStatus::Deleting | db::PodStatus::DeleteFailed => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                },
            };

            let container_id = container_info.and_then(|info| info.container_id.clone());

            // Compute git status on the host by comparing HEAD to rumpelpod/<pod_name>
            let git_info = compute_git_info(&repo_path, &pod.name);

            // Display using DockerHost::Display to normalize the format
            // (e.g. strip default port 22 from old DB entries).
            let display_host = host
                .map(|h| h.to_string())
                .unwrap_or_else(|| pod.host.clone());

            pods.push(PodInfo {
                name: pod.name,
                status,
                created: pod.created_at.format("%Y-%m-%d %H:%M").to_string(),
                host: display_host,
                repo_state: git_info.as_ref().map(|g| g.repo_state.clone()),
                container_id,
                last_commit_time: git_info.map(|g| g.last_commit_time),
            });
        }

        Ok(pods)
    }

    fn list_ports(&self, pod_name: PodName, repo_path: PathBuf) -> Result<Vec<PortInfo>> {
        let conn = self.db.lock().unwrap();
        let pod_rec = db::get_pod(&conn, &repo_path, &pod_name.0)?.context("pod not found")?;

        let ports = db::list_forwarded_ports(&conn, pod_rec.id)?;
        Ok(ports
            .into_iter()
            .map(|p| PortInfo {
                container_port: p.container_port,
                local_port: p.local_port,
                label: p.label,
            })
            .collect())
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
        db::save_conversation(
            &conn, id, &repo_path, &pod_name, &model, &provider, &history,
        )
    }

    fn list_conversations(
        &self,
        repo_path: PathBuf,
        pod_name: String,
    ) -> Result<Vec<ConversationSummary>> {
        let conn = self.db.lock().unwrap();
        let summaries = db::list_conversations(&conn, &repo_path, &pod_name)?;
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

    fn ensure_claude_config(&self, request: EnsureClaudeConfigRequest) -> Result<()> {
        let pod_id = {
            let conn = self.db.lock().unwrap();
            let pod_rec = db::get_pod(&conn, &request.repo_path, &request.pod_name.0)?
                .context("Pod not found")?;
            if db::has_claude_config_copied(&conn, pod_rec.id)? {
                return Ok(());
            }
            pod_rec.id
        };

        let docker = Docker::connect_with_socket(
            request.docker_socket.to_string_lossy().as_ref(),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .context("connecting to Docker daemon")?;

        copy_claude_config(
            &docker,
            &request.container_id.0,
            &request.user,
            &request.repo_path,
            &request.container_repo_path,
            &request.pod_name.0,
            request.auto_approve_hook,
        )?;

        // Mark as copied only after the full copy succeeds.
        // If this DB write fails, the next invocation will redo the copy,
        // which is fine -- overwriting complete files is idempotent.
        let conn = self.db.lock().unwrap();
        db::mark_claude_config_copied(&conn, pod_id)?;

        Ok(())
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

    // Start git HTTP server for bridge-network containers.
    // Use port 0 to let the OS auto-assign a port, allowing multiple daemons
    // (e.g., in tests) to run simultaneously without port conflicts.
    //
    // On macOS Docker Desktop, Docker runs in a VM so the bridge gateway IP
    // is not reachable from the host. We bind to 0.0.0.0 instead and have
    // containers connect via host.docker.internal.
    let (bridge_bind_ip, bridge_container_ip) = if cfg!(target_os = "macos") {
        ("0.0.0.0".to_string(), "host.docker.internal".to_string())
    } else {
        let ip = git_http_server::get_network_gateway_ip("bridge")
            .context("getting bridge network gateway IP")?;
        (ip.clone(), ip)
    };
    let bridge_server = GitHttpServer::start(&bridge_bind_ip, 0, git_server_state.clone())
        .context("starting git HTTP server on bridge network")?;

    // TODO: Start this lazily only when a pod with unsafe-host network is created,
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

        // The fallback socket dir (/tmp/rumpelpod-<uid>/) may not exist yet
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }

        // Remove stale socket file if it exists
        if socket.exists() {
            std::fs::remove_file(&socket)?;
        }
        UnixListener::bind(&socket)
            .with_context(|| format!("Failed to bind to {}", socket.display()))?
    };

    let daemon = DaemonServer {
        db: Arc::new(Mutex::new(db_conn)),
        git_server_state,
        bridge_server_port: bridge_server.port,
        bridge_container_ip,
        localhost_server_port: localhost_server.port,
        active_tokens: Arc::new(Mutex::new(BTreeMap::new())),
        ssh_forward: Arc::new(ssh_forward),
        git_unix_socket,
    };

    // Keep servers alive for the lifetime of the daemon
    let _bridge_server = bridge_server;
    let _localhost_server = localhost_server;
    let _unix_server = unix_server;

    protocol::serve_daemon(daemon, listener);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_hooks_empty_settings() {
        let input = b"{}";
        let result = inject_hooks(input);
        let obj: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let hooks = obj["hooks"]["PermissionRequest"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["matcher"], "");
        let inner = hooks[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(
            inner[0]["command"],
            format!("{} claude-hook permission-request", RUMPEL_CONTAINER_BIN)
        );
    }

    #[test]
    fn inject_hooks_preserves_existing_fields() {
        let input = br#"{"statusLine":{"type":"command","command":"echo hi"}}"#;
        let result = inject_hooks(input);
        let obj: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(obj["statusLine"]["command"], "echo hi");
        assert!(obj["hooks"]["PermissionRequest"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn inject_hooks_preserves_existing_hooks() {
        let input = br#"{"hooks":{"PreToolUse":[{"type":"command","command":"other"}]}}"#;
        let result = inject_hooks(input);
        let obj: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // Existing PreToolUse entry is untouched
        let pre = obj["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["command"], "other");
        // PermissionRequest was added
        assert_eq!(
            obj["hooks"]["PermissionRequest"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn inject_hooks_idempotent() {
        let input = b"{}";
        let once = inject_hooks(input);
        let twice = inject_hooks(&once);
        let obj: serde_json::Value = serde_json::from_slice(&twice).unwrap();
        assert_eq!(
            obj["hooks"]["PermissionRequest"].as_array().unwrap().len(),
            1,
            "should not duplicate PermissionRequest"
        );
    }

    #[test]
    fn inject_hooks_invalid_json_returns_input() {
        let input = b"not json";
        let result = inject_hooks(input);
        assert_eq!(result, input);
    }
}
