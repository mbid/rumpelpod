pub mod db;
pub mod protocol;
pub mod reconnect;
pub mod ssh_forward;

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
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
use listenfd::ListenFd;
use log::error;
use rand::distr::Alphanumeric;
use rand::RngExt;
use rusqlite::Connection;
use tokio::net::UnixListener;

use sha2::{Digest, Sha256};

use crate::async_runtime::block_on;
use crate::config::{is_deterministic_test_mode, Host};
use crate::devcontainer::{
    self, compute_devcontainer_id, substitute_vars, DevContainer, LifecycleCommand, Port,
    PortAttributes, StringOrArray, SubstitutionContext, UserEnvProbe, WaitFor,
};
use crate::docker_exec::exec_command;
use crate::gateway;
use crate::git_http_server::{GitHttpServer, SharedGitServerState};
use protocol::{
    ContainerId, ConversationSummary, Daemon, EnsureClaudeConfigRequest, GetConversationResponse,
    Image, LaunchResult, PodInfo, PodLaunchParams, PodName, PodStatus, PortInfo,
    StartCodexProxyRequest,
};
use reconnect::PodEventManager;
use ssh_forward::SshForwardManager;

use crate::pod::types::{base64_encode, HomeFileEntry, TarExtractEntry};
use crate::pod::{EnterRequest, PodClient, SubmoduleEntry};
use crate::RetryPolicy;

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
            PathBuf::from(format!("/tmp/rumpelpod-{uid}"))
        });
    Ok(runtime_dir.join("rumpelpod.sock"))
}

/// Compute the host-side directory for a pod's ssh-agent socket.
///
/// Uses the same runtime directory logic as `socket_path()`, placing agent
/// sockets under `<runtime_dir>/rumpelpod/agents/<hash>/`.  The directory
/// name is a short hash to stay within the Unix socket path length limit
/// (108 bytes on Linux).
fn ssh_agent_dir(repo_path: &Path, pod_name: &PodName) -> PathBuf {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/rumpelpod-{uid}"))
        });

    let mut hasher = Sha256::new();
    hasher.update(repo_path.as_os_str().as_encoded_bytes());
    hasher.update(pod_name.0.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let hash_prefix = &hash[..12];

    runtime_dir.join("rumpelpod/agents").join(hash_prefix)
}

/// Handle to a running ssh-agent process managed by the daemon.
struct SshAgentHandle {
    child: std::process::Child,
}

impl Drop for SshAgentHandle {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("warning: failed to kill ssh-agent: {e}");
        }
        if let Err(e) = self.child.wait() {
            eprintln!("warning: failed to wait on ssh-agent: {e}");
        }
    }
}

#[derive(Clone)]
struct DaemonServer {
    /// SQLite connection for conversation history.
    db: Arc<Mutex<Connection>>,
    /// Shared state for the git HTTP server (maps tokens to pod info).
    git_server_state: SharedGitServerState,
    /// Port the localhost git HTTP server is listening on (tunnel target).
    localhost_server_port: u16,
    /// Active tokens for each pod: (repo_path, pod_name) -> token
    /// Used to clean up tokens when pods are deleted.
    active_tokens: Arc<Mutex<BTreeMap<(PathBuf, String), String>>>,
    /// SSH forward manager for remote Docker hosts.
    ssh_forward: Arc<SshForwardManager>,
    /// Per-pod event listeners that maintain SSE connections to pod servers.
    pod_events: Arc<PodEventManager>,
    /// Active port-forward handles for Kubernetes pods.
    /// Dropping handles cancels the forwards.  The first entry is always
    /// the container-serve forward; additional entries are forwardPorts.
    #[allow(clippy::type_complexity)]
    k8s_forwards: Arc<Mutex<HashMap<(PathBuf, String), Vec<crate::k8s::PortForwardHandle>>>>,
    /// Active tunnel handles for Kubernetes pods.
    /// Each tunnel multiplexes TCP over kubectl exec so the pod can reach
    /// the host's git HTTP server on a loopback port.
    #[allow(clippy::type_complexity)]
    k8s_tunnels: Arc<Mutex<HashMap<(PathBuf, String), crate::tunnel::TunnelHandle>>>,
    /// Active tunnel handles for Docker containers.
    /// Each tunnel multiplexes TCP over docker exec so the container can
    /// reach the host's git HTTP server on a loopback port.
    #[allow(clippy::type_complexity)]
    docker_tunnels: Arc<Mutex<HashMap<(PathBuf, String), crate::tunnel::TunnelHandle>>>,
    /// Active exec proxy handles for Docker containers.
    /// Each proxy routes HTTP to container-serve via docker exec instead
    /// of bridge IPs or SSH port forwards.
    #[allow(clippy::type_complexity)]
    exec_proxies: Arc<Mutex<HashMap<(PathBuf, String), crate::exec_proxy::ExecProxyHandle>>>,
    /// Per-pod ssh-agent processes running on the host.
    /// The agent socket is relayed into containers via WebSocket.
    #[allow(clippy::type_complexity)]
    ssh_agents: Arc<Mutex<HashMap<(PathBuf, String), SshAgentHandle>>>,
    /// Per-pod Codex WebSocket proxy listeners.
    /// Each proxy forwards WebSocket connections from localhost to the
    /// pod server's /codex endpoint.
    #[allow(clippy::type_complexity)]
    codex_proxies: Arc<Mutex<HashMap<(PathBuf, String), u16>>>,
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
    let repo_dir = repo_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo");

    let mut hasher = Sha256::new();
    hasher.update(repo_path.as_os_str().as_encoded_bytes());
    hasher.update(pod_name.0.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let hash_prefix = &hash[..12];

    let pod = &pod_name.0;
    sanitize_docker_name(&format!("{repo_dir}-{pod}-{hash_prefix}"))
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
    user: String,
}

/// Get the USER directive from a Docker image.
/// Returns None if the image has no USER set (defaults to root).
fn get_image_user(docker: &Docker, image: &str) -> Result<Option<String>> {
    let inspect = block_on(docker.inspect_image(image))
        .with_context(|| format!("Failed to inspect image '{image}'"))?;

    let user = inspect.config.and_then(|c| c.user).unwrap_or_default();

    if user.is_empty() {
        Ok(None)
    } else {
        Ok(Some(user))
    }
}

/// Resolve the user for a pod.
///
/// If `user` is provided, it is used directly.
/// Otherwise, the image's USER directive is used, falling back to "root".
fn resolve_user(docker: &Docker, user: Option<String>, image: &str) -> Result<String> {
    if let Some(user) = user {
        return Ok(user);
    }

    let image_user = get_image_user(docker, image)?;

    match image_user {
        Some(user) if !user.is_empty() => Ok(user),
        _ => Ok("root".to_string()),
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

            let user = response
                .config
                .as_ref()
                .and_then(|c| c.user.as_deref())
                .unwrap_or("")
                .to_string();
            let user = if user.is_empty() {
                "root".to_string()
            } else {
                user
            };

            Ok(Some(ContainerState {
                status,
                id: response.id.unwrap_or_default(),
                user,
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
    let pod = &pod_name.0;
    let pattern = format!("refs/heads/rumpelpod/*@{pod}");
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
                    .args(["update-ref", "-d", &format!("refs/remotes/{branch}")])
                    .current_dir(host_repo_path)
                    .output();
            }
        }
    }

    let alias_ref = format!("refs/heads/rumpelpod/{pod}");
    let _ = Command::new("git")
        .args(["symbolic-ref", "--delete", &alias_ref])
        .current_dir(gateway_path)
        .output();

    let alias_remote_ref = format!("refs/remotes/rumpelpod/{pod}");
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
    let prefix = format!("{flag}=");
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

/// A bind mount source + container target pair, kept around so the daemon
/// can populate the mount after the container starts.
struct BindSource {
    /// Host-side path to the directory.
    source: PathBuf,
    /// Absolute path inside the container.
    target: String,
}

/// On remote hosts, convert bind mounts to named volumes so the container
/// can be created without referencing the developer's filesystem.  Returns
/// the (possibly converted) mount list and the original bind source/target
/// pairs that still need to be uploaded.
fn split_bind_mounts(
    mounts: Vec<devcontainer::MountObject>,
    host: &Host,
    pod_name: &str,
) -> (Vec<devcontainer::MountObject>, Vec<BindSource>) {
    if !host.is_remote() {
        return (mounts, Vec::new());
    }

    let mut converted = Vec::with_capacity(mounts.len());
    let mut bind_sources = Vec::new();

    for m in mounts {
        if m.mount_type != devcontainer::MountType::Bind {
            converted.push(m);
            continue;
        }

        let source_path = m.source.as_deref().unwrap_or("");
        bind_sources.push(BindSource {
            source: PathBuf::from(source_path),
            target: m.target.clone(),
        });

        // Deterministic volume name so re-creation reuses the same volume.
        let hash_input = format!("{pod_name}\0{}", m.target);
        let hash = Sha256::digest(hash_input.as_bytes());
        let short_hash = hex::encode(&hash[..6]);
        let volume_name = format!("rumpelpod-bind-{short_hash}");

        converted.push(devcontainer::MountObject {
            mount_type: devcontainer::MountType::Volume,
            source: Some(volume_name),
            target: m.target,
            // Writable so we can copy data in; original read_only is not
            // preserved (documented limitation for now).
            read_only: None,
        });
    }

    (converted, bind_sources)
}

/// Build a single tar of all bind mount sources (entries at absolute
/// container paths) and stream it to the pod server in one request.
fn upload_bind_mounts(pod: &PodClient, binds: &[BindSource]) -> Result<()> {
    if binds.is_empty() {
        return Ok(());
    }

    let (read_end, write_end) = std::io::pipe().context("creating pipe for bind mount tar")?;

    let binds_owned: Vec<(PathBuf, String)> = binds
        .iter()
        .map(|b| (b.source.clone(), b.target.clone()))
        .collect();

    let writer_thread = std::thread::spawn(move || -> Result<()> {
        let mut archive = tar::Builder::new(write_end);
        archive.follow_symlinks(true);
        for (source, target) in &binds_owned {
            // target is absolute, e.g. "/mnt/data".  Strip the leading
            // slash so tar entries are "mnt/data/...".
            let target_stripped = target.strip_prefix('/').unwrap_or(target);

            if source.is_dir() {
                for entry in walkdir::WalkDir::new(source) {
                    let entry = entry.with_context(|| {
                        let source = source.display();
                        format!("walking bind source '{source}'")
                    })?;
                    let rel = entry
                        .path()
                        .strip_prefix(source)
                        .expect("walkdir entry must be under source");
                    let tar_path = Path::new(target_stripped).join(rel);
                    let meta = entry.metadata().with_context(|| {
                        let path = entry.path().display();
                        format!("stat '{path}'")
                    })?;
                    if meta.is_dir() {
                        let mut header = tar::Header::new_gnu();
                        header.set_entry_type(tar::EntryType::Directory);
                        header.set_size(0);
                        header.set_mode(meta.permissions().mode());
                        header.set_cksum();
                        archive
                            .append_data(&mut header, &tar_path, std::io::empty())
                            .with_context(|| {
                                let tar_path = tar_path.display();
                                format!("adding directory '{tar_path}' to tar")
                            })?;
                    } else if meta.is_file() {
                        archive
                            .append_path_with_name(entry.path(), &tar_path)
                            .with_context(|| {
                                let tar_path = tar_path.display();
                                format!("adding file '{tar_path}' to tar")
                            })?;
                    }
                    // Skip symlinks, sockets, etc. for now.
                }
            } else {
                // Single file bind mount.
                let file_name = source
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let tar_path = Path::new(target_stripped).join(&file_name);
                archive
                    .append_path_with_name(source, &tar_path)
                    .with_context(|| {
                        let source = source.display();
                        format!("adding file '{source}' to tar")
                    })?;
            }
        }
        archive.into_inner().context("finalizing bind mount tar")?;
        Ok(())
    });

    pod.init_mounts(read_end)
        .context("uploading bind mount data to container")?;

    writer_thread
        .join()
        .expect("bind mount tar writer panicked")?;

    Ok(())
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

    let mut env_list: Vec<String> = match env {
        Some(e) if !e.is_empty() => e.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        _ => Vec::new(),
    };
    env_list.push(format!("SSH_AUTH_SOCK={}", crate::pod::SSH_AGENT_SOCK_PATH));
    let env_vec = Some(env_list);

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
            let key = format!("{container_port}/tcp");
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
                .map(|port| format!("{port}/tcp"))
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
        error!("failed to stop broken container {name}: {e}");
    }

    let remove_options = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    if let Err(e) = block_on(docker.remove_container(name, Some(remove_options))) {
        error!("failed to remove broken container {name}: {e}");
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
    docker_host: &Host,
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
                .with_context(|| format!("SSH forward {local}->127.0.0.1:{docker_host_port}"))?;
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
    std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok()
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
    Err(anyhow::anyhow!("no available ports in range 10000-65000"))
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
    let remote_ref_name = format!("refs/remotes/rumpelpod/{pod_name}");
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
            (a, 0) => format!("ahead {a}"),
            (0, b) => format!("behind {b}"),
            (a, b) => format!("ahead {a}, behind {b}"),
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
    filters.insert("label".to_string(), {
        let repo_path = repo_path.display();
        vec![format!("{REPO_PATH_LABEL}={repo_path}")]
    });

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

/// Stop a Docker container by name, connecting to the right host.
/// Returns Ok if the container was stopped or already stopped/gone (304/404).
fn try_stop_container(
    ssh_forward: &SshForwardManager,
    host_str: &Option<String>,
    container_name: &str,
) -> Result<()> {
    use bollard::errors::Error as BollardError;

    let socket_path = if let Some(host) = host_str {
        let host = serde_json::from_str::<Host>(host)?;
        match &host {
            Host::Ssh { .. } => ssh_forward.get_socket(&host, RetryPolicy::UserBlocking)?,
            Host::Localhost => default_docker_socket(),
            Host::Kubernetes { .. } => {
                return Err(anyhow::anyhow!(
                    "try_stop_container called for Kubernetes host"
                ));
            }
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

    let stop_options = StopContainerOptions {
        t: Some(0),
        ..Default::default()
    };
    match block_on(docker.stop_container(container_name, Some(stop_options))) {
        Ok(()) => Ok(()),
        // Already stopped
        Err(BollardError::DockerResponseServerError {
            status_code: 304, ..
        }) => Ok(()),
        // Already gone
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("docker stop failed: {e}")),
    }
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
        let host = serde_json::from_str::<Host>(host)?;
        match &host {
            Host::Ssh { .. } => ssh_forward.get_socket(&host, RetryPolicy::UserBlocking)?,
            Host::Localhost => default_docker_socket(),
            Host::Kubernetes { .. } => {
                return Err(anyhow::anyhow!(
                    "try_remove_container called for Kubernetes host"
                ));
            }
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
        Err(e) => Err(anyhow::anyhow!("docker rm failed: {e}")),
    }
}

/// Copy only the minimal Claude Code config files needed to authenticate and
/// run inside a container. Avoids leaking conversation history, telemetry,
/// stats, and other projects' data into untrusted pods.
///
/// What we copy:
///   ~/.claude/.credentials.json  -- OAuth tokens (needed unless ANTHROPIC_API_KEY is set)
///   ~/.claude/settings.json      -- user preferences (model, mode, attribution)
///   ~/.claude.json               -- whitelisted global keys only
fn copy_claude_config_via_pod(
    pod: &PodClient,
    repo_path: &Path,
    container_repo_path: &Path,
    pod_name: &str,
    auto_approve_hook: bool,
) -> Result<()> {
    let host_home = dirs::home_dir().context("Could not determine home directory")?;
    let claude_dir = host_home.join(".claude");

    let mut files: Vec<HomeFileEntry> = Vec::new();
    let mut tar_extracts: Vec<TarExtractEntry> = Vec::new();

    // .claude.json -- whitelisted global keys only
    match std::fs::read(host_home.join(".claude.json")) {
        Ok(data) => {
            let minimal = strip_claude_json(&data, repo_path, container_repo_path);
            files.push(HomeFileEntry {
                path: ".claude.json".to_string(),
                content: base64_encode(&minimal),
                create_parents: false,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude.json")),
    }

    // .claude/.credentials.json -- OAuth tokens
    match std::fs::read(claude_dir.join(".credentials.json")) {
        Ok(data) => {
            files.push(HomeFileEntry {
                path: ".claude/.credentials.json".to_string(),
                content: base64_encode(&data),
                create_parents: true,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude/.credentials.json")),
    }

    // .claude/settings.json -- user preferences + statusline + hooks
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
    files.push(HomeFileEntry {
        path: ".claude/settings.json".to_string(),
        content: base64_encode(&data),
        create_parents: true,
    });

    // Project-specific data (conversation history, memory) via tar
    let host_dir_name = claude_project_dir_name(repo_path);
    let container_dir_name = claude_project_dir_name(container_repo_path);
    let host_project_dir = host_home.join(".claude/projects").join(&host_dir_name);
    if host_project_dir.is_dir() {
        let tar_output = Command::new("tar")
            .arg("-c")
            .arg("-C")
            .arg(&host_project_dir)
            .arg(".")
            .output()
            .context("creating tar archive of claude project data")?;
        if !tar_output.status.success() {
            return Err(anyhow::anyhow!(
                "tar failed: {}",
                String::from_utf8_lossy(&tar_output.stderr)
            ));
        }
        if !tar_output.stdout.is_empty() {
            let dest = format!(".claude/projects/{container_dir_name}");
            tar_extracts.push(TarExtractEntry {
                dest,
                data: base64_encode(&tar_output.stdout),
            });
        }
    }

    // history.jsonl -- filtered to this project, with path rewritten
    if let Ok(raw) = std::fs::read(host_home.join(".claude/history.jsonl")) {
        let filtered = filter_history(&raw, repo_path, container_repo_path);
        if !filtered.is_empty() {
            files.push(HomeFileEntry {
                path: ".claude/history.jsonl".to_string(),
                content: base64_encode(&filtered),
                create_parents: true,
            });
        }
    }

    pod.write_home_files(files, tar_extracts)
        .context("writing claude config files")?;

    Ok(())
}

/// Filter history.jsonl to entries matching this project, rewriting the
/// project path from host to container.
fn filter_history(data: &[u8], repo_path: &Path, container_repo_path: &Path) -> Vec<u8> {
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
    filtered
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

/// Snapshot ~/.claude/ and ~/.claude.json from a running container.
///
/// Returns the tar archive bytes (rooted at $HOME), or None if neither
/// exists.  Used by recreate to preserve conversation history across
/// container resets -- ensure_claude_config layers fresh auth on top
/// afterwards.
///
/// Determines the home directory by looking up the owner of the repo
/// in /etc/passwd, so this works regardless of whether the devcontainer
/// config specifies an explicit user.
fn snapshot_claude_config(pod: &PodClient, container_repo_path: &Path) -> Result<Option<Vec<u8>>> {
    let repo_display = container_repo_path.display();

    // Collect whichever of ~/.claude/ and ~/.claude.json exist into a
    // single tar rooted at $HOME.  If neither exists, exit 1 (caught
    // below as "nothing to snapshot").
    let script = format!(
        "u=$(stat -c %U '{repo_display}') && \
         h=$(awk -F: -v u=\"$u\" '$1==u{{print $6}}' /etc/passwd) && \
         cd \"$h\" && \
         items='' && \
         [ -d .claude ] && items=\"$items .claude\" ; \
         [ -f .claude.json ] && items=\"$items .claude.json\" ; \
         [ -n \"$items\" ] && tar -c $items || exit 1"
    );

    let result = pod.run(&["sh", "-c", &script], None, &[], None, Some(30))?;

    if result.exit_code != 0 {
        return Ok(None);
    }

    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&result.stdout)
        .context("decoding tar output")?;

    if data.is_empty() {
        return Ok(None);
    }

    Ok(Some(data))
}

/// Restore a previously snapshotted ~/.claude/ and ~/.claude.json into
/// a new container.
fn restore_claude_config(pod: &PodClient, tar_data: &[u8]) -> Result<()> {
    // The tar was created with paths relative to $HOME (e.g. ".claude/...",
    // ".claude.json").  Extract into "." (the home root).
    pod.write_home_files(
        vec![],
        vec![TarExtractEntry {
            dest: ".".to_string(),
            data: base64_encode(tar_data),
        }],
    )?;
    Ok(())
}

/// Keep only whitelisted keys from ~/.claude.json and remap the per-project
/// entry for `repo_path` so it appears under `container_repo_path`.
fn strip_claude_json(data: &[u8], repo_path: &Path, container_repo_path: &Path) -> Vec<u8> {
    // Global keys that are safe to copy into the container. Keys that leak
    // host filesystem paths (projects, githubRepoPaths) are omitted;
    // projects is remapped separately below.
    const KEEP_KEYS: &[&str] = &[
        "anonymousId",
        "autoUpdates",
        "autoUpdatesProtectedForNative",
        "birthdayHatAnimationCount",
        "bypassPermissionsModeAccepted",
        "cachedChromeExtensionInstalled",
        "cachedDynamicConfigs",
        "cachedExtraUsageDisabledReason",
        "cachedGrowthBookFeatures",
        "cachedStatsigGates",
        "changelogLastFetched",
        "claudeCodeFirstTokenDate",
        "clientDataCache",
        "customApiKeyResponses",
        "effortCalloutDismissed",
        "effortCalloutV2Dismissed",
        "feedbackSurveyState",
        "firstStartTime",
        "groveConfigCache",
        "hasAcknowledgedCostThreshold",
        "hasCompletedOnboarding",
        "hasSeenTasksHint",
        "hasShownOpus45Notice",
        "hasShownOpus46Notice",
        "hasVisitedExtraUsage",
        "hasVisitedPasses",
        "installMethod",
        "lastOnboardingVersion",
        "lastReleaseNotesSeen",
        "lspRecommendationDisabled",
        "numStartups",
        "oauthAccount",
        "officialMarketplaceAutoInstallAttempted",
        "officialMarketplaceAutoInstalled",
        "opus45MigrationComplete",
        "opus46FeedSeenCount",
        "opusProMigrationComplete",
        "passesEligibilityCache",
        "passesLastSeenCampaign",
        "passesLastSeenRemaining",
        "passesUpsellSeenCount",
        "penguinModeOrgEnabled",
        "primaryApiKey",
        "promptQueueUseCount",
        "s1mAccessCache",
        "s1mNonSubscriberAccessCache",
        "sonnet1m45MigrationComplete",
        "sonnet45MigrationComplete",
        "sonnet45MigrationTimestamp",
        "subscriptionNoticeCount",
        "thinkingMigrationComplete",
        "tipsHistory",
        "toolUsage",
        "userID",
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

    // Build the project entry for the container workspace.  Start from the
    // host entry (if any) so per-project settings carry over, then force
    // trust-dialog and project-onboarding to accepted -- showing these
    // inside an already-sandboxed container is pointless friction.
    let container_key = container_repo_path.to_string_lossy().to_string();
    let mut entry = project_entry
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    entry.insert(
        "hasTrustDialogAccepted".to_string(),
        serde_json::Value::Bool(true),
    );
    entry.insert(
        "hasCompletedProjectOnboarding".to_string(),
        serde_json::Value::Bool(true),
    );
    let mut projects = serde_json::Map::new();
    projects.insert(container_key, serde_json::Value::Object(entry));
    obj.insert("projects".to_string(), serde_json::Value::Object(projects));

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
    let cmd = format!("echo 'Rumpelpod: {escaped}'");
    let mut sl = serde_json::Map::new();
    sl.insert(
        "type".to_string(),
        serde_json::Value::String("command".to_string()),
    );
    sl.insert("command".to_string(), serde_json::Value::String(cmd));
    obj.insert("statusLine".to_string(), serde_json::Value::Object(sl));

    serde_json::to_vec_pretty(&obj).unwrap_or_else(|_| data.to_vec())
}

pub(crate) const RUMPEL_CONTAINER_BIN: &str = "/opt/rumpelpod/bin/rumpel";
pub(crate) const CLAUDE_CONTAINER_BIN: &str = "/opt/rumpelpod/bin/claude";
pub(crate) const CODEX_CONTAINER_BIN: &str = "/opt/rumpelpod/bin/codex";

/// Inject a PermissionRequest hook that auto-approves all permission
/// dialogs via the rumpel binary inside the container.
fn inject_hooks(data: &[u8]) -> Vec<u8> {
    let Ok(mut obj) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(data)
    else {
        return data.to_vec();
    };

    let command = format!("{RUMPEL_CONTAINER_BIN} claude-hook permission-request");
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

/// Pick the right rumpel binary for the container architecture.
///
/// When the container arch is unknown, returns the running binary.
/// Otherwise looks for `rumpel-linux-{arch}` next to the running
/// executable.
/// Determine the port container-serve should bind inside the container.
///
/// In host network mode the container shares the host's loopback, so we
/// allocate an ephemeral port to avoid conflicts between concurrent
/// containers.  In bridge mode each container has its own namespace and
/// can safely use the default port.
fn container_serve_port(docker: &Docker, container_id: &str) -> Result<u16> {
    let inspect = block_on(docker.inspect_container(container_id, None))
        .context("inspecting container for network mode")?;

    let host_mode = inspect
        .host_config
        .as_ref()
        .and_then(|hc| hc.network_mode.as_deref())
        == Some("host");

    if host_mode {
        allocate_ephemeral_port()
    } else {
        Ok(crate::pod::DEFAULT_PORT)
    }
}

/// Bind port 0 to get an OS-allocated ephemeral port.
fn allocate_ephemeral_port() -> Result<u16> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").context("allocating ephemeral port")?;
    let port = listener.local_addr()?.port();
    // Drop the listener; the port may be reused, but SSH will bind it next.
    Ok(port)
}

/// Start the in-container HTTP server via detached docker exec and return
/// the bearer token for authenticating subsequent requests.
///
/// If the server is already running (health check succeeds), reads the
/// persisted token from the container instead of restarting.
fn start_container_server(
    docker: &Docker,
    container_id: &str,
    container_url: &str,
    container_port: u16,
    user: &str,
) -> Result<String> {
    use bollard::exec::StartExecOptions;
    use bollard::secret::ExecConfig;

    let url = container_url;
    let poll_client = reqwest::blocking::Client::builder().build().unwrap();
    if poll_client
        .get(format!("{url}/health"))
        .send()
        .is_ok_and(|r| r.status().is_success())
    {
        // Server already running -- recover its token from the container
        let token_bytes = exec_command(
            docker,
            container_id,
            Some(user),
            None,
            None,
            vec!["cat", crate::pod::TOKEN_FILE],
        )
        .context("reading container server token")?;
        return Ok(String::from_utf8_lossy(&token_bytes).trim().to_string());
    }

    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let config = ExecConfig {
        cmd: Some(vec![
            RUMPEL_CONTAINER_BIN.to_string(),
            "container-serve".to_string(),
            "--port".to_string(),
            container_port.to_string(),
            "--token".to_string(),
            token.clone(),
        ]),
        user: Some(user.to_string()),
        ..Default::default()
    };

    let exec = block_on(docker.create_exec(container_id, config))
        .context("creating container-serve exec")?;
    block_on(docker.start_exec(
        &exec.id,
        Some(StartExecOptions {
            detach: true,
            ..Default::default()
        }),
    ))
    .context("starting container-serve")?;

    // Wait for the server to become ready, using exponential backoff so
    // high-latency links (remote Docker over slow WiFi) have enough time.
    let max_delay = std::time::Duration::from_secs(5);
    let delays = retry::delay::Exponential::from_millis(100).map(move |d| d.min(max_delay));
    retry::retry(delays.take(20), || {
        poll_client
            .get(format!("{url}/health"))
            .send()
            .ok()
            .filter(|r| r.status().is_success())
            .map(|_| token.clone())
            .ok_or(())
    })
    .map_err(|_| anyhow::anyhow!("container server did not become ready"))
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
/// Execute a single lifecycle command via the in-container HTTP server.
fn run_lifecycle_command_via_pod(
    pod: &PodClient,
    workdir: &Path,
    command: &LifecycleCommand,
    env: &[String],
) -> Result<()> {
    match command {
        LifecycleCommand::String(s) => {
            let result = pod.run(&["sh", "-c", s], Some(workdir), env, None, None)?;
            if result.exit_code != 0 {
                let stderr = base64_decode_lossy(&result.stderr);
                return Err(anyhow::anyhow!(
                    "lifecycle command failed (exit {}): {}",
                    result.exit_code,
                    stderr
                ));
            }
        }
        LifecycleCommand::Array(args) => {
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = pod.run(&args_ref, Some(workdir), env, None, None)?;
            if result.exit_code != 0 {
                let stderr = base64_decode_lossy(&result.stderr);
                return Err(anyhow::anyhow!(
                    "lifecycle command failed (exit {}): {}",
                    result.exit_code,
                    stderr
                ));
            }
        }
        LifecycleCommand::Object(map) => {
            let handles: Vec<_> = map
                .iter()
                .map(|(name, cmd_value)| {
                    let cmd_args: Vec<String> = match cmd_value {
                        StringOrArray::String(s) => {
                            vec!["sh".into(), "-c".into(), s.clone()]
                        }
                        StringOrArray::Array(a) => a.clone(),
                    };
                    let pod_url = pod.url().to_string();
                    let pod_token = pod.token().to_string();
                    let wd = workdir.to_path_buf();
                    let task_name = name.clone();
                    let thread_env = env.to_vec();

                    std::thread::spawn(move || {
                        let pod = PodClient::new(&pod_url, &pod_token, RetryPolicy::UserBlocking)?;
                        let args_ref: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
                        let result = pod.run(&args_ref, Some(&wd), &thread_env, None, None)?;
                        if result.exit_code != 0 {
                            let stderr = base64_decode_lossy(&result.stderr);
                            return Err(anyhow::anyhow!(
                                "lifecycle command '{}' failed (exit {}): {}",
                                task_name,
                                result.exit_code,
                                stderr
                            ));
                        }
                        Ok(())
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

fn base64_decode_lossy(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_else(|_| s.to_string())
}

/// Spawn lifecycle commands in background via the in-container HTTP server.
fn spawn_background_lifecycle_commands_via_pod(
    container_url: String,
    container_token: String,
    workdir: PathBuf,
    commands: Vec<(String, LifecycleCommand)>,
    env: Vec<String>,
) {
    std::thread::spawn(move || {
        let pod = match PodClient::new(&container_url, &container_token, RetryPolicy::Background) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "background lifecycle: failed to connect to container server: {:#}",
                    e
                );
                return;
            }
        };
        for (label, cmd) in &commands {
            if let Err(e) = run_lifecycle_command_via_pod(&pod, &workdir, cmd, &env) {
                error!("background {label} failed: {e:#}");
                break;
            }
        }
    });
}

/// Run one-time lifecycle commands (onCreate, updateContent, postCreate)
/// via the in-container HTTP server, respecting the waitFor target.
/// Returns any commands that should be deferred to background execution.
#[allow(clippy::too_many_arguments)]
fn run_once_lifecycle_commands_via_pod(
    pod: &PodClient,
    workdir: &Path,
    dc: &DevContainer,
    pod_id: db::PodId,
    db_mutex: &Mutex<rusqlite::Connection>,
    wait_for: &WaitFor,
    env: &[String],
) -> Result<Vec<(String, LifecycleCommand)>> {
    let mut background = Vec::new();

    let on_create_ran = {
        let conn = db_mutex.lock().unwrap();
        db::has_on_create_run(&conn, pod_id)?
    };

    if !on_create_ran {
        if let Some(cmd) = &dc.on_create_command {
            if *wait_for >= WaitFor::OnCreateCommand {
                if let Err(e) = run_lifecycle_command_via_pod(pod, workdir, cmd, env) {
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
            if let Err(e) = run_lifecycle_command_via_pod(pod, workdir, cmd, env) {
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
                if let Err(e) = run_lifecycle_command_via_pod(pod, workdir, cmd, env) {
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

/// Progress handle returned by `DaemonServer::launch_pod` / `recreate_pod`.
///
/// The actual work runs on a background thread that sends build-output lines
/// through a channel.  `Iterator::next()` reads lines; `finish()` joins the
/// thread and returns the final result.
pub struct ServerLaunchProgress {
    rx: Option<std::sync::mpsc::Receiver<crate::image::OutputLine>>,
    handle: Option<std::thread::JoinHandle<Result<LaunchResult>>>,
}

impl Iterator for ServerLaunchProgress {
    type Item = crate::image::OutputLine;

    fn next(&mut self) -> Option<crate::image::OutputLine> {
        self.rx.as_ref()?.recv().ok()
    }
}

impl protocol::LaunchProgress for ServerLaunchProgress {
    fn finish(mut self) -> Result<LaunchResult> {
        // Drop the receiver so the background thread sees a closed channel
        // and stops sending.
        drop(self.rx.take());
        self.handle
            .take()
            .expect("finish() called twice on ServerLaunchProgress")
            .join()
            .map_err(|_| anyhow::anyhow!("launch thread panicked"))?
    }
}

impl DaemonServer {
    #[allow(clippy::too_many_arguments)]
    fn launch_pod_k8s(
        &self,
        pod_name: &PodName,
        repo_path: &Path,
        host_branch: Option<&str>,
        docker_host: &Host,
        devcontainer: &DevContainer,
        image: &str,
        image_built: bool,
        git_identity: Option<&crate::git::GitIdentity>,
        claude_cli_path: Option<&Path>,
        inject_system_prompt: bool,
        description_file: Option<&str>,
    ) -> Result<LaunchResult> {
        let (context, namespace, node_selector, tolerations) = match docker_host {
            Host::Kubernetes {
                context,
                namespace,
                node_selector,
                tolerations,
                ..
            } => (
                context.as_str(),
                namespace.as_str(),
                node_selector.clone(),
                tolerations.clone(),
            ),
            _ => unreachable!("launch_pod_k8s called with non-Kubernetes host"),
        };

        let user = devcontainer.user().unwrap_or("root").to_string();

        let container_repo_path = devcontainer.container_repo_path(repo_path);

        gateway::setup_gateway(repo_path)?;
        let submodules = gateway::detect_submodules(repo_path);

        let k8s_name = crate::k8s::k8s_pod_name(&pod_name.0, repo_path);
        let client = crate::k8s::K8sClient::new(context, namespace)?;
        let gateway_path = gateway::gateway_path(repo_path)?;

        let host_remotes = crate::git::get_remotes(repo_path).unwrap_or_default();
        let prepared = crate::prepared_image::build_prepared_image(
            &Image(image.to_string()),
            docker_host,
            &gateway_path,
            &container_repo_path,
            &user,
            &host_remotes,
            claude_cli_path,
            None,
            inject_system_prompt,
            description_file,
        )?;
        let image = &prepared.image.0;

        gateway::install_host_hooks(repo_path)?;

        // Check DB for existing pod; if the k8s pod is still Running, reconnect
        {
            let conn = self.db.lock().unwrap();
            if let Some(record) = db::get_pod(&conn, repo_path, &pod_name.0)? {
                let status = client.get_pod_status(&k8s_name)?;
                if status == PodStatus::Running {
                    drop(conn);

                    let pf = client
                        .port_forward(&k8s_name, crate::pod::DEFAULT_PORT)
                        .context("re-establishing port forward to existing k8s pod")?;
                    let local_port = pf.local_port;
                    let container_url = format!("http://127.0.0.1:{local_port}");

                    // Read token from the pod, then let PodClient::new
                    // handle the readiness poll.
                    let token_bytes =
                        client.exec_output(&k8s_name, &["cat", crate::pod::TOKEN_FILE])?;
                    let container_token = String::from_utf8_lossy(&token_bytes).trim().to_string();

                    let pod = PodClient::new(
                        &container_url,
                        &container_token,
                        RetryPolicy::UserBlocking,
                    )?;

                    let agent_sock = ssh_agent_dir(repo_path, pod_name).join("agent.sock");
                    let token = self.git_server_state.register(
                        gateway_path.clone(),
                        pod_name.0.clone(),
                        repo_path.to_path_buf(),
                        Some(agent_sock),
                    );
                    self.active_tokens
                        .lock()
                        .unwrap()
                        .insert((repo_path.to_path_buf(), pod_name.0.clone()), token.clone());

                    // Reuse the existing tunnel if it's still alive, otherwise
                    // start a fresh one.
                    let tunnel_key = (repo_path.to_path_buf(), pod_name.0.clone());
                    {
                        let mut tunnels = self.k8s_tunnels.lock().unwrap();
                        if let Some(handle) = tunnels.get(&tunnel_key) {
                            if !handle.is_alive() {
                                let name = &pod_name.0;
                                log::warn!("k8s tunnel for {name} is dead, reconnecting");
                                // Drop the stale handle (and its _cancel_tx) before
                                // start_tunnel runs pkill inside the pod.
                                tunnels.remove(&tunnel_key);
                            }
                        }
                    }
                    let tunnel_port = {
                        let tunnels = self.k8s_tunnels.lock().unwrap();
                        tunnels.get(&tunnel_key).map(|t| t.port)
                    };
                    let tunnel_port = match tunnel_port {
                        Some(port) => port,
                        None => {
                            let tunnel = client
                                .start_tunnel(
                                    &k8s_name,
                                    {
                                        let port = self.localhost_server_port;
                                        &format!("127.0.0.1:{port}")
                                    },
                                    RetryPolicy::UserBlocking,
                                )
                                .context("starting tunnel to existing k8s pod")?;
                            let port = tunnel.port;
                            self.k8s_tunnels.lock().unwrap().insert(tunnel_key, tunnel);
                            port
                        }
                    };

                    let base_url = format!("http://127.0.0.1:{tunnel_port}");

                    let effective_probe = devcontainer
                        .user_env_probe
                        .as_ref()
                        .unwrap_or(&UserEnvProbe::LoginInteractiveShell);
                    let shell_flags = effective_probe.shell_flags_exec();

                    let sub_entries: Vec<SubmoduleEntry> = submodules
                        .iter()
                        .map(|s| SubmoduleEntry {
                            name: s.name.clone(),
                            path: s.path.clone(),
                            displaypath: s.displaypath.clone(),
                        })
                        .collect();

                    // If enter fails (e.g. stale tunnel), drop the tunnel
                    // handle so the next enter creates a fresh one.
                    let enter_result = pod.enter(&EnterRequest {
                        repo_path: container_repo_path.clone(),
                        base_url: base_url.clone(),
                        token: token.clone(),
                        pod_name: pod_name.0.clone(),
                        host_branch: None,
                        git_identity: git_identity.cloned(),
                        submodules: sub_entries,
                        is_first_entry: false,
                        shell_flags: shell_flags.map(String::from),
                    });
                    if enter_result.is_err() {
                        let key = (repo_path.to_path_buf(), pod_name.0.clone());
                        self.k8s_tunnels.lock().unwrap().remove(&key);
                    }
                    let enter_resp = enter_result?;

                    {
                        let conn = self.db.lock().unwrap();
                        db::update_pod_status(&conn, record.id, db::PodStatus::Ready)?;
                    }

                    // Re-establish forwarded ports from DB
                    let mut handles = vec![pf];
                    {
                        let conn = self.db.lock().unwrap();
                        let saved_ports = db::list_forwarded_ports(&conn, record.id)?;
                        for saved in &saved_ports {
                            match client.port_forward(&k8s_name, saved.container_port) {
                                Ok(fwd) => {
                                    if fwd.local_port != saved.local_port {
                                        // Local port changed; update the DB record
                                        let _ = conn.execute(
                                            "UPDATE forwarded_ports SET local_port = ? \
                                             WHERE pod_id = ? AND container_port = ?",
                                            rusqlite::params![
                                                fwd.local_port,
                                                i64::from(record.id),
                                                saved.container_port,
                                            ],
                                        );
                                    }
                                    handles.push(fwd);
                                }
                                Err(e) => {
                                    log::warn!(
                                        "failed to re-establish port forward for {}: {}",
                                        saved.container_port,
                                        e
                                    );
                                }
                            }
                        }
                    }

                    self.k8s_forwards
                        .lock()
                        .unwrap()
                        .insert((repo_path.to_path_buf(), pod_name.0.clone()), handles);

                    return Ok(LaunchResult {
                        container_id: ContainerId(k8s_name),
                        user,
                        docker_socket: None,
                        host: docker_host.clone(),
                        image_built,
                        probed_env: enter_resp.probed_env,
                        user_shell: enter_resp.user_info.shell,
                        container_url,
                        container_token,
                    });
                }

                // Pod exists in DB but is gone from k8s -- clean up the stale record
                db::delete_pod(&conn, repo_path, &pod_name.0)?;
            }
        }

        // Register pod with the git HTTP server
        let agent_sock = ssh_agent_dir(repo_path, pod_name).join("agent.sock");
        let token = self.git_server_state.register(
            gateway_path.clone(),
            pod_name.0.clone(),
            repo_path.to_path_buf(),
            Some(agent_sock),
        );
        self.active_tokens
            .lock()
            .unwrap()
            .insert((repo_path.to_path_buf(), pod_name.0.clone()), token.clone());

        // Create pod record in database
        let pod_id = {
            let conn = self.db.lock().unwrap();
            db::create_pod(&conn, repo_path, &pod_name.0, docker_host)?
        };

        let mark_error = |e: anyhow::Error| -> anyhow::Error {
            if let Ok(conn) = self.db.lock() {
                let _ = db::update_pod_status(&conn, pod_id, db::PodStatus::Error);
            }
            e
        };

        let env: Vec<(String, String)> = devcontainer
            .container_env
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let labels = crate::k8s::K8sClient::pod_labels(&pod_name.0, repo_path);
        let annotations = crate::k8s::K8sClient::pod_annotations();

        // Build K8sPodOptions from devcontainer config
        let all_mounts = devcontainer.resolved_mounts()?;
        let run_args = devcontainer.run_args.as_deref().unwrap_or(&[]);
        let run_args_config = parse_run_args_for_docker(run_args);

        // Separate bind mounts for later upload.
        let mut bind_sources = Vec::new();
        let k8s_volumes: Vec<crate::k8s::K8sVolumeMount> = all_mounts
            .iter()
            .enumerate()
            .map(|(i, m)| match m.mount_type {
                devcontainer::MountType::Volume => crate::k8s::K8sVolumeMount {
                    name: format!("vol-{i}"),
                    mount_path: m.target.clone(),
                    read_only: m.read_only.unwrap_or(false),
                    medium: None,
                },
                devcontainer::MountType::Tmpfs => crate::k8s::K8sVolumeMount {
                    name: format!("vol-{i}"),
                    mount_path: m.target.clone(),
                    read_only: m.read_only.unwrap_or(false),
                    medium: Some("Memory".to_string()),
                },
                devcontainer::MountType::Bind => {
                    bind_sources.push(BindSource {
                        source: PathBuf::from(m.source.as_deref().unwrap_or("")),
                        target: m.target.clone(),
                    });
                    // Disk-backed emptyDir; populated via tar upload
                    // after the pod starts.
                    crate::k8s::K8sVolumeMount {
                        name: format!("vol-{i}"),
                        mount_path: m.target.clone(),
                        read_only: false,
                        medium: None,
                    }
                }
            })
            .collect();

        let privileged = devcontainer.privileged == Some(true) || run_args_config.privileged;
        let cap_add = merge_string_vecs(devcontainer.cap_add.as_ref(), &run_args_config.cap_add)
            .unwrap_or_default();

        let merged_security_opt = merge_string_vecs(
            devcontainer.security_opt.as_ref(),
            &run_args_config.security_opt,
        )
        .unwrap_or_default();
        let mut seccomp_unconfined = false;
        let mut apparmor_unconfined = false;
        for opt in &merged_security_opt {
            if opt == "seccomp=unconfined" || opt == "seccomp:unconfined" {
                seccomp_unconfined = true;
            } else if opt == "apparmor=unconfined" || opt == "apparmor:unconfined" {
                apparmor_unconfined = true;
            } else {
                log::warn!("unrecognized security_opt '{opt}' ignored on Kubernetes");
            }
        }

        let override_command = devcontainer.override_command.unwrap_or(true);

        // Convert hostRequirements to k8s resource requests
        let resource_requests = devcontainer.host_requirements.as_ref().and_then(|hr| {
            let cpu = hr.cpus.map(|c| c.to_string());
            let memory = hr
                .memory
                .as_deref()
                .and_then(crate::k8s::convert_memory_to_k8s);
            if cpu.is_some() || memory.is_some() {
                Some(crate::k8s::K8sResourceRequests { cpu, memory })
            } else {
                None
            }
        });

        // Warn about unsupported features
        let use_init = devcontainer.init == Some(true) || run_args_config.init;
        if use_init {
            log::warn!(
                "init: true has no effect on Kubernetes -- \
                 bake an init process (e.g. tini) into the image instead"
            );
        }
        if !run_args_config.devices.is_empty() {
            log::warn!(
                "--device has no effect on Kubernetes -- \
                 use cluster-specific device plugins instead"
            );
        }

        let k8s_options = crate::k8s::K8sPodOptions {
            volumes: k8s_volumes,
            privileged,
            cap_add,
            seccomp_unconfined,
            apparmor_unconfined,
            override_command,
            resource_requests,
            node_selector,
            tolerations,
        };

        client
            .create_pod(
                &k8s_name,
                image,
                labels,
                annotations,
                Some(&user),
                &env,
                &k8s_options,
            )
            .map_err(|e| mark_error(e.context("creating k8s pod")))?;

        client
            .wait_running(&k8s_name, RetryPolicy::UserBlocking)
            .map_err(|e| mark_error(e.context("waiting for k8s pod to start")))?;

        let container_serve_cmd = format!(
            "/opt/rumpelpod/bin/rumpel container-serve --port {} --token {}",
            crate::pod::DEFAULT_PORT,
            token
        );
        client
            .exec_detached(&k8s_name, &container_serve_cmd)
            .map_err(|e| mark_error(e.context("starting container-serve in k8s pod")))?;

        let pf = client
            .port_forward(&k8s_name, crate::pod::DEFAULT_PORT)
            .map_err(|e| mark_error(e.context("setting up port forward")))?;
        let local_port = pf.local_port;
        let container_url = format!("http://127.0.0.1:{local_port}");

        // PodClient::new polls /health until the server is ready.
        let pod = PodClient::new(&container_url, &token, RetryPolicy::UserBlocking)
            .map_err(mark_error)?;

        // Populate bind mount volumes with data from the host.
        upload_bind_mounts(&pod, &bind_sources)
            .map_err(|e| mark_error(e.context("populating bind mount volumes")))?;

        let tunnel = client
            .start_tunnel(
                &k8s_name,
                &{
                    let port = self.localhost_server_port;
                    format!("127.0.0.1:{port}")
                },
                RetryPolicy::UserBlocking,
            )
            .map_err(|e| mark_error(e.context("starting tunnel to k8s pod")))?;
        let tunnel_port = tunnel.port;
        self.k8s_tunnels
            .lock()
            .unwrap()
            .insert((repo_path.to_path_buf(), pod_name.0.clone()), tunnel);

        let base_url = format!("http://127.0.0.1:{tunnel_port}");

        let effective_probe = devcontainer
            .user_env_probe
            .as_ref()
            .unwrap_or(&UserEnvProbe::LoginInteractiveShell);
        let shell_flags = effective_probe.shell_flags_exec();

        let sub_entries: Vec<SubmoduleEntry> = submodules
            .iter()
            .map(|s| SubmoduleEntry {
                name: s.name.clone(),
                path: s.path.clone(),
                displaypath: s.displaypath.clone(),
            })
            .collect();

        let enter_resp = pod
            .enter(&EnterRequest {
                repo_path: container_repo_path.clone(),
                base_url: base_url.clone(),
                token: token.clone(),
                pod_name: pod_name.0.clone(),
                host_branch: host_branch.map(String::from),
                git_identity: git_identity.cloned(),
                submodules: sub_entries,
                is_first_entry: true,
                shell_flags: shell_flags.map(String::from),
            })
            .map_err(mark_error)?;

        {
            let conn = self.db.lock().unwrap();
            db::update_pod_status(&conn, pod_id, db::PodStatus::Ready)?;
        }

        // Set up port forwarding for forwardPorts
        let forward_ports = devcontainer.forward_ports.as_deref().unwrap_or(&[]);
        let ports_attributes = devcontainer
            .ports_attributes
            .as_ref()
            .cloned()
            .unwrap_or_default();
        let other_ports_attributes = &devcontainer.other_ports_attributes;

        let mut handles = vec![pf];
        if !forward_ports.is_empty() {
            let conn = self.db.lock().unwrap();
            for port_spec in forward_ports {
                let container_port = match resolve_port_number(port_spec) {
                    Some(p) => p,
                    None => {
                        log::warn!("skipping invalid port spec: {:?}", port_spec);
                        continue;
                    }
                };

                match client.port_forward(&k8s_name, container_port) {
                    Ok(fwd) => {
                        let label = ports_attributes
                            .get(&container_port.to_string())
                            .or(other_ports_attributes.as_ref())
                            .and_then(|a| a.label.as_deref())
                            .unwrap_or("")
                            .to_string();

                        db::insert_forwarded_port(
                            &conn,
                            pod_id,
                            container_port,
                            fwd.local_port,
                            &label,
                        )?;
                        handles.push(fwd);
                    }
                    Err(e) => {
                        log::warn!(
                            "failed to set up port forward for {}: {}",
                            container_port,
                            e
                        );
                    }
                }
            }
        }

        self.k8s_forwards
            .lock()
            .unwrap()
            .insert((repo_path.to_path_buf(), pod_name.0.clone()), handles);

        let env_strings: Vec<String> = enter_resp
            .probed_env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        // Run lifecycle commands for new pod
        let wait_for = devcontainer.effective_wait_for();
        let mut bg_commands = run_once_lifecycle_commands_via_pod(
            &pod,
            &container_repo_path,
            devcontainer,
            pod_id,
            &self.db,
            &wait_for,
            &env_strings,
        )
        .map_err(mark_error)?;

        if wait_for >= WaitFor::PostStartCommand {
            if let Some(cmd) = &devcontainer.post_start_command {
                run_lifecycle_command_via_pod(&pod, &container_repo_path, cmd, &env_strings)
                    .map_err(mark_error)?;
            }
        } else if let Some(cmd) = &devcontainer.post_start_command {
            bg_commands.push(("postStartCommand".to_string(), cmd.clone()));
        }

        if wait_for >= WaitFor::PostAttachCommand {
            if let Some(cmd) = &devcontainer.post_attach_command {
                run_lifecycle_command_via_pod(&pod, &container_repo_path, cmd, &env_strings)
                    .map_err(mark_error)?;
            }
        } else if let Some(cmd) = &devcontainer.post_attach_command {
            bg_commands.push(("postAttachCommand".to_string(), cmd.clone()));
        }

        if !bg_commands.is_empty() {
            spawn_background_lifecycle_commands_via_pod(
                container_url.clone(),
                token.clone(),
                container_repo_path.clone(),
                bg_commands,
                env_strings,
            );
        }

        Ok(LaunchResult {
            container_id: ContainerId(k8s_name),
            user,
            docker_socket: None,
            host: docker_host.clone(),
            image_built,
            probed_env: enter_resp.probed_env,
            user_shell: enter_resp.user_info.shell,
            container_url,
            container_token: token,
        })
    }

    /// Core launch logic, called on a background thread.
    ///
    /// Build output lines are sent to `build_tx`; the caller drives the
    /// `ServerLaunchProgress` iterator to forward them to the client.
    fn launch_pod_impl(
        &self,
        params: PodLaunchParams,
        build_tx: std::sync::mpsc::Sender<crate::image::OutputLine>,
    ) -> Result<LaunchResult> {
        let PodLaunchParams {
            pod_name,
            repo_path,
            host_branch,
            host: docker_host,
            devcontainer,
            git_identity,
            claude_cli_path,
            inject_system_prompt,
            description_file,
        } = params;

        // Resolve daemon-side variables (container workspace paths,
        // devcontainerId).  Client-side variables were already resolved
        // before the config was sent to us.
        let devcontainer = resolve_daemon_vars(devcontainer, &repo_path, &pod_name.0);

        let on_output: Option<crate::image::BuildOutputFn> = {
            let tx = build_tx;
            Some(Box::new(move |line: crate::image::OutputLine| {
                let _ = tx.send(line);
            }) as crate::image::BuildOutputFn)
        };

        // On remote hosts, bind mounts are converted to named volumes and
        // populated via tar upload after the container starts.  Split them
        // out so create_container gets only volume/tmpfs mounts.
        let all_mounts = devcontainer.resolved_mounts()?;
        let (mounts, bind_sources) = split_bind_mounts(all_mounts, &docker_host, &pod_name.0);

        // Get the host specification string for the database
        let host_spec = serde_json::to_string(&docker_host)?;

        // Check for name conflicts between local and remote pods
        {
            let conn = self.db.lock().unwrap();
            if let Some(existing) = db::get_pod(&conn, &repo_path, &pod_name.0)? {
                // A pod with this name exists - check if the host matches
                if existing.host != host_spec {
                    let existing_host: Host =
                        serde_json::from_str(&existing.host).unwrap_or(docker_host.clone());
                    return Err(anyhow::anyhow!(
                        "Pod '{}' already exists on {} but was requested on {}.\n\
                         Delete the existing pod first with 'rumpel delete {}'.",
                        pod_name.0,
                        existing_host,
                        docker_host,
                        pod_name.0
                    ));
                }
            }
        }

        if matches!(docker_host, Host::Kubernetes { .. }) {
            let build_result = crate::image::resolve_image(
                &devcontainer,
                &docker_host,
                &repo_path,
                on_output,
                None,
            )?;
            return self.launch_pod_k8s(
                &pod_name,
                &repo_path,
                host_branch.as_deref(),
                &docker_host,
                &devcontainer,
                &build_result.image.0,
                build_result.built,
                git_identity.as_ref(),
                claude_cli_path.as_deref(),
                inject_system_prompt,
                description_file.as_deref(),
            );
        }

        // Establish the SSH tunnel before building so `docker build`
        // connects via the forwarded socket instead of Docker's own SSH
        // transport (which ignores $HOME when resolving ~/.ssh/config).
        let docker_socket = match &docker_host {
            Host::Ssh { .. } => self
                .ssh_forward
                .get_socket(&docker_host, RetryPolicy::UserBlocking)?,
            Host::Localhost => default_docker_socket(),
            Host::Kubernetes { .. } => unreachable!(),
        };

        let container_repo_path = devcontainer.container_repo_path(&repo_path);
        let forward_ports = devcontainer.forward_ports.clone().unwrap_or_default();
        let ports_attributes = devcontainer.ports_attributes.clone().unwrap_or_default();
        let other_ports_attributes = devcontainer.other_ports_attributes.clone();

        let docker = Docker::connect_with_socket(
            docker_socket.to_string_lossy().as_ref(),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .context("connecting to Docker daemon")?;

        // Set up gateway for git synchronization (idempotent)
        gateway::setup_gateway(&repo_path)?;
        let submodules = gateway::detect_submodules(&repo_path);

        let name = docker_name(&repo_path, &pod_name);
        let gateway_path = gateway::gateway_path(&repo_path)?;

        let localhost_server_port = self.localhost_server_port;

        // Wait for any in-progress background stop to finish so we don't
        // race against it when trying to (re)start the container.
        for _ in 0..50 {
            let conn = self.db.lock().unwrap();
            let is_stopping = db::get_pod(&conn, &repo_path, &pod_name.0)?
                .is_some_and(|r| r.status == db::PodStatus::Stopping);
            drop(conn);
            if !is_stopping {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // TODO: There's a potential race condition between inspect and
        // start/run. Another process could stop/remove the container after we
        // inspect it. For robustness, we'd need to retry on specific failures,
        // but that adds complexity. For now, we accept this limitation.

        // Check for existing container before building images -- no point
        // rebuilding when we are just going to restart the same container.
        if let Some(state) = inspect_container(&docker, &name)? {
            // Host hooks must be present before re-entering an existing pod,
            // since the hook syncs host changes to the gateway for the pod to fetch.
            gateway::install_host_hooks(&repo_path)?;
            let user = match devcontainer.user() {
                Some(u) => u.to_string(),
                None => state.user.clone(),
            };
            let was_stopped = state.status != "running";
            if was_stopped {
                // Container exists but is stopped - restart it
                start_container(&docker, &name)?;
            }

            // Route container-serve access through an exec proxy.
            // Reuse an existing proxy if alive, otherwise start a new one.
            let proxy_key = (repo_path.clone(), pod_name.0.clone());
            {
                let mut proxies = self.exec_proxies.lock().unwrap();
                if let Some(handle) = proxies.get(&proxy_key) {
                    if was_stopped || !handle.is_alive() {
                        proxies.remove(&proxy_key);
                    }
                }
            }
            let container_url = {
                let proxies = self.exec_proxies.lock().unwrap();
                proxies.get(&proxy_key).map(|h| {
                    let port = h.port;
                    format!("http://127.0.0.1:{port}")
                })
            };
            let (container_url, serve_port) = match container_url {
                Some(url) => {
                    let serve_port = container_serve_port(&docker, &state.id)?;
                    (url, serve_port)
                }
                None => {
                    let serve_port = container_serve_port(&docker, &state.id)?;
                    let proxy = block_on(crate::exec_proxy::start_exec_proxy(
                        &docker, &state.id, serve_port,
                    ))
                    .context("starting exec proxy for existing container")?;
                    let port = proxy.port;
                    let url = format!("http://127.0.0.1:{port}");
                    self.exec_proxies
                        .lock()
                        .unwrap()
                        .insert(proxy_key.clone(), proxy);
                    (url, serve_port)
                }
            };

            // Ensure the in-container HTTP server is running
            let container_token =
                start_container_server(&docker, &state.id, &container_url, serve_port, &user)?;

            // Ensure pod record exists in database
            let pod_id = {
                let conn = self.db.lock().unwrap();
                let pod_id = match db::get_pod(&conn, &repo_path, &pod_name.0)? {
                    Some(pod) => pod.id,
                    None => db::create_pod(&conn, &repo_path, &pod_name.0, &docker_host)?,
                };
                db::update_pod_status(&conn, pod_id, db::PodStatus::Ready)?;
                pod_id
            };

            // Register pod with the git HTTP server (may already be registered, that's OK)
            let agent_sock = ssh_agent_dir(&repo_path, &pod_name).join("agent.sock");
            let token = self.git_server_state.register(
                gateway_path.clone(),
                pod_name.0.clone(),
                repo_path.clone(),
                Some(agent_sock),
            );

            // Store the token for cleanup on delete
            self.active_tokens
                .lock()
                .unwrap()
                .insert((repo_path.clone(), pod_name.0.clone()), token.clone());

            let pod = PodClient::new(&container_url, &container_token, RetryPolicy::UserBlocking)?;

            // Reuse the existing tunnel if alive, otherwise start a new one.
            // When the container was stopped, the tunnel-server inside it is
            // gone even if the mux task hasn't noticed yet, so always start
            // fresh in that case.
            let tunnel_key = (repo_path.clone(), pod_name.0.clone());
            {
                let mut tunnels = self.docker_tunnels.lock().unwrap();
                if let Some(handle) = tunnels.get(&tunnel_key) {
                    if was_stopped || !handle.is_alive() {
                        tunnels.remove(&tunnel_key);
                    }
                }
            }
            let tunnel_port = {
                let tunnels = self.docker_tunnels.lock().unwrap();
                tunnels.get(&tunnel_key).map(|t| t.port)
            };
            let tunnel_port = match tunnel_port {
                Some(port) => port,
                None => {
                    let tunnel = block_on(crate::tunnel::start_docker_tunnel(
                        &docker,
                        &state.id,
                        &format!("127.0.0.1:{localhost_server_port}"),
                        0,
                        RetryPolicy::UserBlocking,
                    ))
                    .context("starting tunnel to existing docker container")?;
                    let port = tunnel.port;

                    self.docker_tunnels
                        .lock()
                        .unwrap()
                        .insert(tunnel_key.clone(), tunnel);
                    port
                }
            };

            let base_url = format!("http://127.0.0.1:{tunnel_port}");

            let effective_probe = devcontainer
                .user_env_probe
                .as_ref()
                .unwrap_or(&UserEnvProbe::LoginInteractiveShell);
            let shell_flags = effective_probe.shell_flags_exec();

            let sub_entries: Vec<SubmoduleEntry> = submodules
                .iter()
                .map(|s| SubmoduleEntry {
                    name: s.name.clone(),
                    path: s.path.clone(),
                    displaypath: s.displaypath.clone(),
                })
                .collect();

            let enter_result = pod.enter(&EnterRequest {
                repo_path: container_repo_path.clone(),
                base_url: base_url.clone(),
                token: token.clone(),
                pod_name: pod_name.0.clone(),
                host_branch: None,
                git_identity: git_identity.clone(),
                submodules: sub_entries,
                is_first_entry: false,
                shell_flags: shell_flags.map(String::from),
            });
            if enter_result.is_err() {
                self.docker_tunnels.lock().unwrap().remove(&tunnel_key);
                self.exec_proxies.lock().unwrap().remove(&proxy_key);
            }
            let enter_resp = enter_result?;

            let env_strings: Vec<String> = enter_resp
                .probed_env
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();

            // Run updateContentCommand, per-start, and per-attach lifecycle
            // commands, respecting the waitFor target for background execution.
            let wait_for = devcontainer.effective_wait_for();
            let mut bg_commands: Vec<(String, LifecycleCommand)> = Vec::new();

            // updateContentCommand runs on every re-entry after git sync
            if let Some(cmd) = &devcontainer.update_content_command {
                if wait_for >= WaitFor::UpdateContentCommand {
                    run_lifecycle_command_via_pod(&pod, &container_repo_path, cmd, &env_strings)?;
                } else {
                    bg_commands.push(("updateContentCommand".to_string(), cmd.clone()));
                }
            }

            if was_stopped {
                if let Some(cmd) = &devcontainer.post_start_command {
                    if wait_for >= WaitFor::PostStartCommand {
                        run_lifecycle_command_via_pod(
                            &pod,
                            &container_repo_path,
                            cmd,
                            &env_strings,
                        )?;
                    } else {
                        bg_commands.push(("postStartCommand".to_string(), cmd.clone()));
                    }
                }
            }

            if let Some(cmd) = &devcontainer.post_attach_command {
                if wait_for >= WaitFor::PostAttachCommand {
                    run_lifecycle_command_via_pod(&pod, &container_repo_path, cmd, &env_strings)?;
                } else {
                    bg_commands.push(("postAttachCommand".to_string(), cmd.clone()));
                }
            }

            if !bg_commands.is_empty() {
                spawn_background_lifecycle_commands_via_pod(
                    container_url.clone(),
                    container_token.clone(),
                    container_repo_path.clone(),
                    bg_commands,
                    env_strings.clone(),
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

            self.pod_events.start(
                repo_path.clone(),
                pod_name.0.clone(),
                container_url.clone(),
                container_token.clone(),
                docker_host.clone(),
            );

            return Ok(LaunchResult {
                container_id: ContainerId(state.id),
                user,
                docker_socket: Some(docker_socket),
                host: docker_host,
                image_built: false,
                probed_env: enter_resp.probed_env,
                user_shell: enter_resp.user_info.shell,
                container_url,
                container_token,
            });
        }

        // Container does not exist yet -- build the image.
        let build_result = crate::image::resolve_image(
            &devcontainer,
            &docker_host,
            &repo_path,
            on_output,
            Some(&docker_socket),
        )?;
        let image = build_result.image;
        let image_built = build_result.built;

        let user = resolve_user(&docker, devcontainer.user().map(String::from), &image.0)?;

        let host_remotes = crate::git::get_remotes(&repo_path).unwrap_or_default();
        let prepared = crate::prepared_image::build_prepared_image(
            &image,
            &docker_host,
            &gateway_path,
            &container_repo_path,
            &user,
            &host_remotes,
            claude_cli_path.as_deref(),
            Some(&docker_socket),
            inject_system_prompt,
            description_file.as_deref(),
        )?;
        let image = prepared.image;

        gateway::install_host_hooks(&repo_path)?;

        // Register pod with the git HTTP server
        let agent_sock = ssh_agent_dir(&repo_path, &PodName(pod_name.0.clone())).join("agent.sock");
        let token = self.git_server_state.register(
            gateway_path,
            pod_name.0.clone(),
            repo_path.clone(),
            Some(agent_sock),
        );

        // Store the token for cleanup on delete
        self.active_tokens
            .lock()
            .unwrap()
            .insert((repo_path.clone(), pod_name.0.clone()), token.clone());

        // Create pod record in database with status "initializing"
        let pod_id = {
            let conn = self.db.lock().unwrap();
            db::create_pod(&conn, &repo_path, &pod_name.0, &docker_host)?
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

        let docker_tunnels = &self.docker_tunnels;
        let exec_proxies = &self.exec_proxies;

        // Create container and run initial git setup.  Closure used so we
        // can retry once on overlay2 filesystem errors (see below).
        let do_create_and_setup = || -> Result<(ContainerId, String, String)> {
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

            // Route container-serve access through an exec proxy so we
            // don't need bridge IPs or SSH port forwards.
            let serve_port = container_serve_port(&docker, &container_id.0)?;
            let proxy = block_on(crate::exec_proxy::start_exec_proxy(
                &docker,
                &container_id.0,
                serve_port,
            ))
            .context("starting exec proxy for container-serve")?;
            let port = proxy.port;
            let container_url_inner = format!("http://127.0.0.1:{port}");
            exec_proxies
                .lock()
                .unwrap()
                .insert((repo_path.to_path_buf(), pod_name.0.clone()), proxy);

            let container_token_inner = start_container_server(
                &docker,
                &container_id.0,
                &container_url_inner,
                serve_port,
                &user,
            )?;
            let pod_inner = PodClient::new(
                &container_url_inner,
                &container_token_inner,
                RetryPolicy::UserBlocking,
            )?;

            // Fix ownership of mount targets so the container user can write
            // to them.  Docker creates volume/tmpfs mounts as root by default.
            if !mounts.is_empty() {
                let mut chown_args = vec!["chown", &user];
                let target_strings: Vec<String> = mounts.iter().map(|m| m.target.clone()).collect();
                let target_refs: Vec<&str> = target_strings.iter().map(|s| s.as_str()).collect();
                chown_args.extend(target_refs);
                exec_command(
                    &docker,
                    &container_id.0,
                    Some("root"),
                    None,
                    None,
                    chown_args,
                )
                .context("chown mount targets for container user")?;
            }

            // Populate bind mount volumes with data from the host.
            upload_bind_mounts(&pod_inner, &bind_sources)
                .context("populating bind mount volumes")?;

            // Start exec tunnel so the container can reach the git HTTP
            // server on a loopback port.
            let tunnel = block_on(crate::tunnel::start_docker_tunnel(
                &docker,
                &container_id.0,
                &format!("127.0.0.1:{localhost_server_port}"),
                0,
                RetryPolicy::UserBlocking,
            ))
            .context("starting tunnel to docker container")?;
            let tunnel_port = tunnel.port;
            docker_tunnels
                .lock()
                .unwrap()
                .insert((repo_path.to_path_buf(), pod_name.0.clone()), tunnel);

            let base_url = format!("http://127.0.0.1:{tunnel_port}");

            let sub_entries: Vec<SubmoduleEntry> = submodules
                .iter()
                .map(|s| SubmoduleEntry {
                    name: s.name.clone(),
                    path: s.path.clone(),
                    displaypath: s.displaypath.clone(),
                })
                .collect();

            // Env probe deferred to after the retry logic below.
            pod_inner.enter(&EnterRequest {
                repo_path: container_repo_path.clone(),
                base_url: base_url.clone(),
                token: token.clone(),
                pod_name: pod_name.0.clone(),
                host_branch: host_branch.clone(),
                git_identity: git_identity.clone(),
                submodules: sub_entries,
                is_first_entry: true,
                shell_flags: None, // env probe deferred to after retry
            })?;

            Ok((container_id, container_token_inner, container_url_inner))
        };

        // Docker's overlay2 storage driver occasionally fails to make the
        // container filesystem visible right after creation.  Retry once
        // after removing the broken container.
        let (container_id, container_token, container_url) = match do_create_and_setup() {
            Ok(triple) => triple,
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

        let pod = PodClient::new(&container_url, &container_token, RetryPolicy::UserBlocking)?;

        // Probe user env from shell init files (separate call because the
        // env probe was deferred from inside the retry closure above).
        let effective_probe = devcontainer
            .user_env_probe
            .as_ref()
            .unwrap_or(&UserEnvProbe::LoginInteractiveShell);
        let shell_flags = effective_probe.shell_flags_exec();
        // Re-enter to get probed_env + user_info.  The git operations
        // are idempotent so re-running them is safe.
        let tunnel_base_url = {
            let tunnels = self.docker_tunnels.lock().unwrap();
            let port = tunnels
                .get(&(repo_path.to_path_buf(), pod_name.0.clone()))
                .map(|t| t.port)
                .unwrap_or(0);
            format!("http://127.0.0.1:{port}")
        };
        let enter_resp = pod
            .enter(&EnterRequest {
                repo_path: container_repo_path.clone(),
                base_url: tunnel_base_url,
                token: token.clone(),
                pod_name: pod_name.0.clone(),
                host_branch: host_branch.clone(),
                git_identity: git_identity.clone(),
                submodules: vec![],
                is_first_entry: false,
                shell_flags: shell_flags.map(String::from),
            })
            .map_err(mark_error)?;

        let env_strings: Vec<String> = enter_resp
            .probed_env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        // Run lifecycle commands for new container:
        // onCreateCommand -> updateContentCommand -> postCreateCommand ->
        // postStartCommand -> postAttachCommand
        // Commands up to and including the waitFor target run synchronously;
        // the rest are handed off to a background thread.
        let wait_for = devcontainer.effective_wait_for();

        let mut bg_commands = run_once_lifecycle_commands_via_pod(
            &pod,
            &container_repo_path,
            &devcontainer,
            pod_id,
            &self.db,
            &wait_for,
            &env_strings,
        )
        .map_err(mark_error)?;

        if wait_for >= WaitFor::PostStartCommand {
            if let Some(cmd) = &devcontainer.post_start_command {
                run_lifecycle_command_via_pod(&pod, &container_repo_path, cmd, &env_strings)
                    .map_err(mark_error)?;
            }
        } else if let Some(cmd) = &devcontainer.post_start_command {
            bg_commands.push(("postStartCommand".to_string(), cmd.clone()));
        }

        if wait_for >= WaitFor::PostAttachCommand {
            if let Some(cmd) = &devcontainer.post_attach_command {
                run_lifecycle_command_via_pod(&pod, &container_repo_path, cmd, &env_strings)
                    .map_err(mark_error)?;
            }
        } else if let Some(cmd) = &devcontainer.post_attach_command {
            bg_commands.push(("postAttachCommand".to_string(), cmd.clone()));
        }

        if !bg_commands.is_empty() {
            spawn_background_lifecycle_commands_via_pod(
                container_url.clone(),
                container_token.clone(),
                container_repo_path.clone(),
                bg_commands,
                env_strings,
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
                    error!("port forwarding setup failed: {e}");
                    e
                })?;
            }
        }

        self.pod_events.start(
            repo_path.to_path_buf(),
            pod_name.0.clone(),
            container_url.clone(),
            container_token.clone(),
            docker_host.clone(),
        );

        Ok(LaunchResult {
            container_id,
            user,
            docker_socket: Some(docker_socket),
            host: docker_host,
            image_built,
            probed_env: enter_resp.probed_env,
            user_shell: enter_resp.user_info.shell,
            container_url,
            container_token,
        })
    }

    /// Core recreate logic, called on a background thread.
    ///
    /// Calls `launch_pod_impl` directly to avoid spawning a nested thread.
    fn recreate_pod_impl(
        &self,
        mut params: PodLaunchParams,
        build_tx: std::sync::mpsc::Sender<crate::image::OutputLine>,
    ) -> Result<LaunchResult> {
        // Resolve daemon-side variables so container_repo_path and other
        // fields are fully resolved before we use them for snapshotting.
        params.devcontainer =
            resolve_daemon_vars(params.devcontainer, &params.repo_path, &params.pod_name.0);

        let pod_name = &params.pod_name;
        let repo_path = &params.repo_path;
        let docker_host = &params.host;
        let container_repo_path = params.devcontainer.container_repo_path(repo_path);

        let name = docker_name(repo_path, pod_name);

        if let Host::Kubernetes {
            ref context,
            ref namespace,
            ..
        } = docker_host
        {
            let k8s_name = crate::k8s::k8s_pod_name(&pod_name.0, repo_path);
            let client = crate::k8s::K8sClient::new(context, namespace)?;

            // 1. Snapshot dirty files and claude config if the pod is running
            let mut patch: Option<Vec<u8>> = None;
            let mut claude_snapshot: Option<Vec<u8>> = None;

            let status = client.get_pod_status(&k8s_name)?;
            if status == PodStatus::Running {
                let local_port = self
                    .k8s_forwards
                    .lock()
                    .unwrap()
                    .get(&(repo_path.to_path_buf(), pod_name.0.clone()))
                    .and_then(|handles| handles.first().map(|h| h.local_port));

                if let Some(port) = local_port {
                    let container_url = format!("http://127.0.0.1:{port}");
                    if let Ok(token_bytes) =
                        client.exec_output(&k8s_name, &["cat", crate::pod::TOKEN_FILE])
                    {
                        let token = String::from_utf8_lossy(&token_bytes).trim().to_string();
                        if let Ok(old_pod) =
                            PodClient::new(&container_url, &token, RetryPolicy::Background)
                        {
                            patch = old_pod
                                .git_snapshot(Path::new(&container_repo_path))
                                .context("snapshotting dirty files in k8s pod")?;

                            claude_snapshot =
                                snapshot_claude_config(&old_pod, Path::new(&container_repo_path))
                                    .context("snapshotting claude config in k8s pod")?;
                        }
                    }
                }
            }

            // 2. Delete the pod
            Daemon::delete_pod(self, pod_name.clone(), repo_path.clone(), true)?;

            // 3. Create new pod (call impl directly to avoid nested thread)
            let launch_result = self.launch_pod_impl(params, build_tx)?;

            // 4. Restore snapshots
            if patch.is_some() || claude_snapshot.is_some() {
                let new_pod = PodClient::new(
                    &launch_result.container_url,
                    &launch_result.container_token,
                    RetryPolicy::UserBlocking,
                )?;

                if let Some(patch_content) = patch {
                    let created_files =
                        get_created_files_from_patch(&patch_content).unwrap_or_default();
                    new_pod
                        .git_apply_patch(
                            Path::new(&container_repo_path),
                            &patch_content,
                            &created_files,
                        )
                        .context("applying snapshot patch to new k8s pod")?;
                }

                if let Some(tar_data) = claude_snapshot {
                    restore_claude_config(&new_pod, &tar_data)
                        .context("restoring claude config in k8s pod")?;
                }
            }

            return Ok(launch_result);
        }

        // Get the Docker socket to use (local or forwarded from remote)
        let docker_socket = match docker_host {
            Host::Ssh { .. } => self
                .ssh_forward
                .get_socket(docker_host, RetryPolicy::UserBlocking)?,
            Host::Localhost => default_docker_socket(),
            Host::Kubernetes { .. } => unreachable!(),
        };

        let docker = Docker::connect_with_socket(
            docker_socket.to_string_lossy().as_ref(),
            120,
            bollard::API_DEFAULT_VERSION,
        )
        .context("connecting to Docker daemon")?;

        // 1. Snapshot dirty files and claude config if container exists
        let mut patch: Option<Vec<u8>> = None;
        let mut claude_snapshot: Option<Vec<u8>> = None;
        let snapshot_user = params.devcontainer.user().map(String::from);

        if let Some(state) = inspect_container(&docker, &name)? {
            if state.status == "running" {
                // Use a temporary exec proxy to reach the old container's server.
                if let Ok(serve_port) = container_serve_port(&docker, &state.id) {
                    if let Ok(proxy) = block_on(crate::exec_proxy::start_exec_proxy(
                        &docker, &state.id, serve_port,
                    )) {
                        let port = proxy.port;
                        let url = format!("http://127.0.0.1:{port}");
                        if let Ok(container_token) = start_container_server(
                            &docker,
                            &state.id,
                            &url,
                            serve_port,
                            snapshot_user.as_deref().unwrap_or("root"),
                        ) {
                            if let Ok(old_pod) =
                                PodClient::new(&url, &container_token, RetryPolicy::Background)
                            {
                                patch = old_pod
                                    .git_snapshot(&container_repo_path)
                                    .context("snapshotting dirty files")?;

                                claude_snapshot =
                                    snapshot_claude_config(&old_pod, &container_repo_path)
                                        .context("snapshotting claude config")?;
                            }
                        }
                    }
                }
            }

            // 2. Delete the container synchronously so launch_pod can reuse the name
            Daemon::delete_pod(self, pod_name.clone(), repo_path.clone(), true)?;
        }

        // 3. Create new pod (call impl directly to avoid nested thread)
        let launch_result = self.launch_pod_impl(params, build_tx)?;

        // 4. Restore snapshots
        if patch.is_some() || claude_snapshot.is_some() {
            let new_pod = PodClient::new(
                &launch_result.container_url,
                &launch_result.container_token,
                RetryPolicy::UserBlocking,
            )?;

            if let Some(patch_content) = patch {
                // Parse patch to identify files being created that might
                // already exist (e.g. from image).  Best-effort.
                let created_files =
                    get_created_files_from_patch(&patch_content).unwrap_or_default();

                new_pod
                    .git_apply_patch(&container_repo_path, &patch_content, &created_files)
                    .context("applying snapshot patch")?;
            }

            if let Some(tar_data) = claude_snapshot {
                restore_claude_config(&new_pod, &tar_data).context("restoring claude config")?;
            }
        }

        Ok(launch_result)
    }
}

impl Daemon for DaemonServer {
    type Progress = ServerLaunchProgress;

    fn launch_pod(&self, params: PodLaunchParams) -> Result<ServerLaunchProgress> {
        let (tx, rx) = std::sync::mpsc::channel();
        let this = self.clone();
        let handle = std::thread::spawn(move || this.launch_pod_impl(params, tx));
        Ok(ServerLaunchProgress {
            rx: Some(rx),
            handle: Some(handle),
        })
    }

    fn recreate_pod(&self, params: PodLaunchParams) -> Result<ServerLaunchProgress> {
        let (tx, rx) = std::sync::mpsc::channel();
        let this = self.clone();
        let handle = std::thread::spawn(move || this.recreate_pod_impl(params, tx));
        Ok(ServerLaunchProgress {
            rx: Some(rx),
            handle: Some(handle),
        })
    }

    fn stop_pod(&self, pod_name: PodName, repo_path: PathBuf, wait: bool) -> Result<()> {
        let conn = self.db.lock().unwrap();
        let pod_record = db::get_pod(&conn, &repo_path, &pod_name.0)?;

        // Reject k8s pods
        if let Some(ref record) = pod_record {
            let host = serde_json::from_str::<Host>(&record.host)?;
            if let Host::Kubernetes { .. } = &host {
                return Err(anyhow::anyhow!(
                    "Kubernetes pods cannot be stopped. \
                     Use 'rumpel delete {}' instead.",
                    pod_name.0
                ));
            }
            db::update_pod_status(&conn, record.id, db::PodStatus::Stopping)?;
        }
        let host_str = pod_record.map(|r| r.host);
        drop(conn);

        self.pod_events.stop(&repo_path, &pod_name.0);

        let container_name = docker_name(&repo_path, &pod_name);

        if wait {
            let result = try_stop_container(&self.ssh_forward, &host_str, &container_name);
            let conn = self.db.lock().unwrap();
            if let Ok(Some(record)) = db::get_pod(&conn, &repo_path, &pod_name.0) {
                let _ = db::update_pod_status(&conn, record.id, db::PodStatus::Ready);
            }
            result?;
        } else {
            let db = self.db.clone();
            let ssh_forward = self.ssh_forward.clone();
            let repo_path = repo_path.clone();
            let pod_name = pod_name.clone();
            std::thread::spawn(move || {
                if let Err(e) = try_stop_container(&ssh_forward, &host_str, &container_name) {
                    let name = &pod_name.0;
                    error!("failed to stop pod '{name}': {e}");
                }
                let conn = db.lock().unwrap();
                if let Ok(Some(record)) = db::get_pod(&conn, &repo_path, &pod_name.0) {
                    let _ = db::update_pod_status(&conn, record.id, db::PodStatus::Ready);
                }
            });
        }

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

        // Check if this is a Kubernetes pod
        let host = host_str
            .as_deref()
            .and_then(|s| serde_json::from_str::<Host>(s).ok());
        if let Some(Host::Kubernetes {
            ref context,
            ref namespace,
            ..
        }) = host
        {
            let k8s_name = crate::k8s::k8s_pod_name(&pod_name.0, &repo_path);
            let client = crate::k8s::K8sClient::new(context, namespace)?;

            // Delete the k8s pod (ignore "not found" since it may already be gone)
            if let Err(e) = client.delete_pod(&k8s_name) {
                error!("failed to delete k8s pod '{k8s_name}': {e}");
            }

            self.pod_events.stop(&repo_path, &pod_name.0);

            // Drop the port-forward and tunnel handles
            self.k8s_forwards
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()));
            self.k8s_tunnels
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()));

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
            return Ok(());
        }

        self.pod_events.stop(&repo_path, &pod_name.0);

        // Kill the ssh-agent and remove its directory.
        self.ssh_agents
            .lock()
            .unwrap()
            .remove(&(repo_path.clone(), pod_name.0.clone()));
        let agent_dir = ssh_agent_dir(&repo_path, &pod_name);
        if agent_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&agent_dir) {
                let dir = agent_dir.display();
                error!("failed to remove ssh-agent directory {dir}: {e}");
            }
        }

        let container_name = docker_name(&repo_path, &pod_name);

        if wait {
            try_remove_container(&self.ssh_forward, &host_str, &container_name)?;

            self.docker_tunnels
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()));
            self.exec_proxies
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()));
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
            // Drop the tunnel/proxy handles immediately so the exec
            // processes inside the container are cleaned up before removal.
            self.docker_tunnels
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()));
            self.exec_proxies
                .lock()
                .unwrap()
                .remove(&(repo_path.clone(), pod_name.0.clone()));
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
                let name = &pod_name.0;
                error!("all delete attempts failed for pod '{name}'");
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
        // Cache k8s pod statuses per (context, namespace) to avoid repeated API calls
        let mut k8s_status_cache: HashMap<String, Option<PodStatus>> = HashMap::new();
        for pod in &db_pods {
            let host = serde_json::from_str::<Host>(&pod.host).ok();
            match &host {
                Some(Host::Kubernetes {
                    ref context,
                    ref namespace,
                    ..
                }) => {
                    let k8s_name = crate::k8s::k8s_pod_name(&pod.name, &repo_path);
                    let host = &pod.host;
                    let cache_key = format!("{host}/{k8s_name}");
                    k8s_status_cache.entry(cache_key).or_insert_with(|| {
                        crate::k8s::K8sClient::new(context, namespace)
                            .and_then(|c| c.get_pod_status(&k8s_name))
                            .ok()
                    });
                }
                Some(Host::Ssh { .. }) => {
                    if !remote_status_maps.contains_key(&pod.host) {
                        let status_map = host
                            .as_ref()
                            .and_then(|h| self.ssh_forward.try_get_socket(h))
                            .and_then(|socket| {
                                get_container_status_via_socket(&socket, &repo_path).ok()
                            });
                        remote_status_maps.insert(pod.host.clone(), status_map);
                    }
                }
                Some(Host::Localhost) | None => {}
            }
        }

        // Build combined list with status from Docker where available
        let mut pods = Vec::new();
        for pod in db_pods {
            let host = serde_json::from_str::<Host>(&pod.host).ok();
            let is_k8s = host
                .as_ref()
                .is_some_and(|h| matches!(h, Host::Kubernetes { .. }));
            let is_remote = host.as_ref().is_some_and(|h| h.is_remote());

            let (status, container_id) = if is_k8s {
                let k8s_name = crate::k8s::k8s_pod_name(&pod.name, &repo_path);
                let host = &pod.host;
                let cache_key = format!("{host}/{k8s_name}");
                let k8s_status = k8s_status_cache.get(&cache_key).and_then(|s| s.clone());
                let status = match pod.status {
                    db::PodStatus::Stopping => PodStatus::Stopping,
                    db::PodStatus::Deleting => PodStatus::Deleting,
                    db::PodStatus::DeleteFailed => PodStatus::Broken,
                    _ => k8s_status.unwrap_or(PodStatus::Disconnected),
                };
                (status, Some(k8s_name))
            } else {
                let container_info = if !is_remote {
                    local_container_status.get(&pod.name)
                } else {
                    remote_status_maps
                        .get(&pod.host)
                        .and_then(|m| m.as_ref())
                        .and_then(|status_map| status_map.get(&pod.name))
                };

                let status = match pod.status {
                    db::PodStatus::Stopping => PodStatus::Stopping,
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
                                PodStatus::Disconnected
                            } else {
                                match pod.status {
                                    db::PodStatus::Ready => PodStatus::Gone,
                                    db::PodStatus::Initializing | db::PodStatus::Error => {
                                        PodStatus::Stopped
                                    }
                                    db::PodStatus::Stopping
                                    | db::PodStatus::Deleting
                                    | db::PodStatus::DeleteFailed => {
                                        unreachable!()
                                    }
                                }
                            }
                        }
                    },
                };
                let container_id = container_info.and_then(|info| info.container_id.clone());
                (status, container_id)
            };

            // Compute git status on the host by comparing HEAD to rumpelpod/<pod_name>
            let git_info = compute_git_info(&repo_path, &pod.name);

            // Display using Host::Display to normalize the format
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

        let pod = PodClient::new(
            &request.container_url,
            &request.container_token,
            RetryPolicy::UserBlocking,
        )?;

        copy_claude_config_via_pod(
            &pod,
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

    fn start_codex_proxy(&self, request: StartCodexProxyRequest) -> Result<u16> {
        let key = (request.repo_path.clone(), request.pod_name.0.clone());

        // Reuse an existing proxy if one is already listening.
        {
            let proxies = self.codex_proxies.lock().unwrap();
            if let Some(&port) = proxies.get(&key) {
                return Ok(port);
            }
        }

        let container_url = request.container_url.clone();
        let container_token = request.container_token.clone();

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").context("binding codex proxy listener")?;
        listener
            .set_nonblocking(true)
            .context("setting nonblocking")?;
        let port = listener.local_addr()?.port();

        let tokio_listener =
            tokio::net::TcpListener::from_std(listener).context("converting to tokio listener")?;

        tokio::task::spawn(crate::codex::run_codex_proxy(
            tokio_listener,
            container_url,
            container_token,
        ));

        self.codex_proxies.lock().unwrap().insert(key, port);

        Ok(port)
    }

    fn ssh_add_key(
        &self,
        pod_name: PodName,
        repo_path: PathBuf,
        key_path: PathBuf,
    ) -> Result<String> {
        // Verify the pod exists.
        let conn = self.db.lock().unwrap();
        db::get_pod(&conn, &repo_path, &pod_name.0)?.context("pod not found")?;
        drop(conn);

        let agent_dir = ssh_agent_dir(&repo_path, &pod_name);
        let sock_path = agent_dir.join("agent.sock");

        // Start the agent if not already running.
        let mut agents = self.ssh_agents.lock().unwrap();
        let key = (repo_path.clone(), pod_name.0.clone());
        let need_start = if agents.contains_key(&key) {
            // Check if the child is still alive.
            let handle = agents.get_mut(&key).unwrap();
            match handle.child.try_wait() {
                Ok(Some(_)) => {
                    // Exited -- remove stale entry and restart.
                    agents.remove(&key);
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    eprintln!("warning: failed to check ssh-agent status: {e}");
                    agents.remove(&key);
                    true
                }
            }
        } else {
            true
        };

        if need_start {
            // Remove stale socket from a previous daemon run.
            if sock_path.exists() {
                if let Err(e) = std::fs::remove_file(&sock_path) {
                    let path = sock_path.display();
                    eprintln!("warning: failed to remove stale agent socket {path}: {e}");
                }
            }

            std::fs::create_dir_all(&agent_dir).with_context(|| {
                let dir = agent_dir.display();
                format!("creating ssh-agent directory {dir}")
            })?;

            let mut child = Command::new("ssh-agent")
                .args(["-D", "-a"])
                .arg(&sock_path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .context("failed to start ssh-agent")?;

            // Wait for the socket to appear.  The only failure mode is the
            // agent exiting prematurely (e.g. bad socket path).
            while !sock_path.exists() {
                if let Ok(Some(status)) = child.try_wait() {
                    let stderr = child
                        .stderr
                        .take()
                        .and_then(|mut s| {
                            use std::io::Read;
                            let mut buf = String::new();
                            s.read_to_string(&mut buf).ok()?;
                            Some(buf)
                        })
                        .unwrap_or_default();
                    let stderr = stderr.trim();
                    return Err(anyhow::anyhow!("ssh-agent exited with {status}: {stderr}"));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            agents.insert(key, SshAgentHandle { child });
        }
        drop(agents);

        let sock = sock_path.to_string_lossy();
        let output = Command::new("ssh-add")
            .arg(&key_path)
            .env("SSH_AUTH_SOCK", &*sock)
            .output()
            .context("failed to run ssh-add")?;

        if output.status.success() {
            // ssh-add prints the confirmation to stderr.
            let msg = String::from_utf8_lossy(&output.stderr);
            Ok(msg.trim().to_string())
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("ssh-add failed: {}", err.trim()))
        }
    }

    fn ssh_list_keys(&self, pod_name: PodName, repo_path: PathBuf) -> Result<String> {
        let agent_dir = ssh_agent_dir(&repo_path, &pod_name);
        let sock_path = agent_dir.join("agent.sock");

        if !sock_path.exists() {
            return Ok("No keys (ssh-agent not started for this pod)".to_string());
        }

        let sock = sock_path.to_string_lossy();
        let output = Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", &*sock)
            .output()
            .context("failed to run ssh-add -l")?;

        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);

        // Exit code 1 with "no identities" is normal (agent running, no keys).
        // Exit code 2 means the agent is not reachable.
        match output.status.code() {
            Some(0) => Ok(out.trim().to_string()),
            Some(1) => Ok(out.trim().to_string()),
            _ => {
                let msg = if err.is_empty() {
                    out.trim().to_string()
                } else {
                    err.trim().to_string()
                };
                Err(anyhow::anyhow!("ssh-add -l failed: {msg}"))
            }
        }
    }

    fn subscribe_pod_reconnect(
        &self,
        repo_path: &Path,
        pod_name: &str,
    ) -> Option<tokio::sync::broadcast::Receiver<reconnect::ReconnectEvent>> {
        self.pod_events.subscribe(repo_path, pod_name)
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

    // Git HTTP server on localhost, used as the tunnel target.
    // Containers reach it via the exec tunnel, not directly.
    let localhost_server = GitHttpServer::start("127.0.0.1", 0, git_server_state.clone())
        .context("starting git HTTP server on localhost")?;

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
            std::fs::create_dir_all(parent).with_context(|| {
                let parent = parent.display();
                format!("Failed to create {parent}")
            })?;
        }

        // Remove stale socket file if it exists
        if socket.exists() {
            std::fs::remove_file(&socket)?;
        }
        UnixListener::bind(&socket).with_context(|| {
            let socket = socket.display();
            format!("Failed to bind to {socket}")
        })?
    };

    let ssh_forward = Arc::new(ssh_forward);
    let pod_events = Arc::new(PodEventManager::new(ssh_forward.clone()));

    let daemon = DaemonServer {
        db: Arc::new(Mutex::new(db_conn)),
        git_server_state,
        localhost_server_port: localhost_server.port,
        active_tokens: Arc::new(Mutex::new(BTreeMap::new())),
        ssh_forward,
        pod_events,
        k8s_forwards: Arc::new(Mutex::new(HashMap::new())),
        k8s_tunnels: Arc::new(Mutex::new(HashMap::new())),
        docker_tunnels: Arc::new(Mutex::new(HashMap::new())),
        exec_proxies: Arc::new(Mutex::new(HashMap::new())),
        ssh_agents: Arc::new(Mutex::new(HashMap::new())),
        codex_proxies: Arc::new(Mutex::new(HashMap::new())),
    };

    // Keep the server alive for the lifetime of the daemon.
    let _localhost_server = localhost_server;

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
            format!("{RUMPEL_CONTAINER_BIN} claude-hook permission-request")
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
