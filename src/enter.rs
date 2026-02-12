use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use log::{info, trace};

use crate::cli::EnterCommand;
use crate::config::{load_toml_config, DockerHost};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LaunchResult, PodLaunchParams, PodName};
use crate::devcontainer::{
    substitute_vars, ContainerEnvSource, DevContainer, GpuRequirement, HostRequirements, MountType,
    SubstitutionContext,
};
use crate::git::{get_current_branch, get_repo_root};

/// Compute the path relative from `base` to `path`.
/// Both paths must be absolute and `path` must be under `base`.
fn relative_path<'a>(base: &Path, path: &'a Path) -> Result<&'a Path> {
    path.strip_prefix(base)
        .with_context(|| format!("{} is not under {}", path.display(), base.display()))
}

/// Map the host's current directory into the corresponding container path.
fn container_workdir(devcontainer: &DevContainer, repo_root: &Path) -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;
    let container_repo_path = devcontainer.container_repo_path(repo_root);
    let relative = relative_path(repo_root, &current_dir)?;
    Ok(container_repo_path.join(relative))
}

/// Parse a human-readable size string (e.g. "4gb", "512MB") into bytes.
///
/// Supports "tb", "gb", "mb", "kb" suffixes (case-insensitive).
/// Returns None if the string cannot be parsed.
pub fn parse_size_string(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();

    let suffixes: &[(&str, u64)] = &[
        ("tb", 1024 * 1024 * 1024 * 1024),
        ("gb", 1024 * 1024 * 1024),
        ("mb", 1024 * 1024),
        ("kb", 1024),
    ];

    for (suffix, multiplier) in suffixes {
        if let Some(num_str) = s.strip_suffix(suffix) {
            return num_str.trim().parse::<u64>().ok().map(|n| n * multiplier);
        }
    }

    // No suffix -- treat as raw bytes.
    s.parse::<u64>().ok()
}

/// Log hostRequirements and decide whether to enforce them based on host type.
fn check_host_requirements(requirements: &HostRequirements, docker_host: &DockerHost) {
    let mut parts: Vec<String> = Vec::new();

    if let Some(cpus) = requirements.cpus {
        parts.push(format!("cpus={}", cpus));
    }
    if let Some(ref memory) = requirements.memory {
        match parse_size_string(memory) {
            Some(bytes) => parts.push(format!("memory={} ({} bytes)", memory, bytes)),
            None => parts.push(format!("memory={} (unparseable)", memory)),
        }
    }
    if let Some(ref storage) = requirements.storage {
        match parse_size_string(storage) {
            Some(bytes) => parts.push(format!("storage={} ({} bytes)", storage, bytes)),
            None => parts.push(format!("storage={} (unparseable)", storage)),
        }
    }
    if let Some(ref gpu) = requirements.gpu {
        match gpu {
            GpuRequirement::Required(true) => parts.push("gpu=required".to_string()),
            GpuRequirement::Required(false) => {}
            GpuRequirement::Optional(s) => parts.push(format!("gpu={}", s)),
            GpuRequirement::Detailed(details) => parts.push(format!("gpu={:?}", details)),
        }
    }

    if parts.is_empty() {
        return;
    }

    info!("hostRequirements: {}", parts.join(", "));

    // Localhost and remote Docker: the user controls their hardware, so we
    // only log.  A future orchestrator backend (e.g. Kubernetes) should match
    // here and use the parsed values to select an appropriate node or instance
    // type.
    match docker_host {
        DockerHost::Localhost | DockerHost::Ssh { .. } => {
            info!("Running on local/remote Docker -- hostRequirements are advisory only");
        }
    }
}

/// Load devcontainer.json, validate it, and prepare it for the daemon.
///
/// Resolves `${localEnv:...}` and normalizes build paths to repo-root-relative.
/// Returns the DevContainer and the parsed DockerHost.
pub fn load_and_resolve(
    repo_root: &Path,
    host_override: Option<&str>,
) -> Result<(DevContainer, DockerHost)> {
    let toml_config = load_toml_config(repo_root)?;
    let host_str = host_override.or(toml_config.host.as_deref());
    let docker_host = host_str
        .map(DockerHost::parse)
        .transpose()
        .context("Invalid host specification")?
        .unwrap_or(DockerHost::Localhost);

    let (mut devcontainer, devcontainer_dir) = DevContainer::find_and_load(repo_root)?
        .map(|(dc, dir)| {
            dc.warn_unsupported_fields();
            (dc, dir)
        })
        .unwrap_or_else(|| (DevContainer::default(), repo_root.to_path_buf()));

    if devcontainer.image.is_none() && !devcontainer.has_build() {
        bail!(
            "No image or build specified.\n\
             Please set image or build.dockerfile in devcontainer.json."
        );
    }

    devcontainer.resolve_build_paths(&devcontainer_dir, repo_root);

    // Resolve ${localEnv:...} before sending to the daemon, since the daemon
    // does not have access to the calling user's environment variables.
    devcontainer = devcontainer.substitute(&SubstitutionContext {
        resolve_local_env: true,
        ..Default::default()
    });

    if let Some(ref requirements) = devcontainer.host_requirements {
        check_host_requirements(requirements, &docker_host);
    }

    Ok((devcontainer, docker_host))
}

/// Launch a pod and return the container ID and user.
/// This is shared logic between `enter` and `agent` commands.
pub fn launch_pod(pod_name: &str, host_override: Option<&str>) -> Result<LaunchResult> {
    let t = Instant::now();
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host) = load_and_resolve(&repo_root, host_override)?;
    trace!("launch_pod config: {:?}", t.elapsed());

    // Reject bind mounts early for remote Docker
    if docker_host.is_remote() {
        for m in devcontainer.resolved_mounts()? {
            if m.mount_type == MountType::Bind {
                bail!(
                    "bind mounts are not supported with remote Docker hosts. \
                     The source path '{}' would reference the remote filesystem, \
                     not your local machine. Use volume or tmpfs mounts instead.",
                    m.source.as_deref().unwrap_or("<none>")
                );
            }
        }
    }

    let host_branch = get_current_branch(&repo_root);

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let t = Instant::now();
    let result = client.launch_pod(PodLaunchParams {
        pod_name: PodName(pod_name.to_string()),
        repo_path: repo_root,
        host_branch,
        docker_host,
        devcontainer,
    })?;
    trace!("launch_pod daemon RPC: {:?}", t.elapsed());

    if result.image_built {
        eprintln!("Devcontainer image built.");
    }

    Ok(result)
}

/// Resolve `${containerEnv:VAR}` placeholders in `remote_env` by running
/// `docker exec printenv VAR` in the container.  `${localEnv:VAR}` is already
/// resolved at config load time, so only container references remain.
pub fn resolve_remote_env(
    remote_env: &HashMap<String, String>,
    docker_socket: &Path,
    container_id: &str,
) -> Vec<(String, String)> {
    let ctx = SubstitutionContext {
        container_env_source: Some(ContainerEnvSource {
            docker_socket: docker_socket.to_path_buf(),
            container_id: container_id.to_string(),
        }),
        ..Default::default()
    };

    remote_env
        .iter()
        .map(|(key, value)| {
            let resolved = substitute_vars(value, &ctx);
            (key.clone(), resolved)
        })
        .collect()
}

pub fn enter(cmd: &EnterCommand) -> Result<()> {
    let t_total = Instant::now();

    let t = Instant::now();
    let repo_root = get_repo_root()?;
    trace!("get_repo_root: {:?}", t.elapsed());

    let t = Instant::now();
    let (devcontainer, _docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;
    trace!("load_and_resolve: {:?}", t.elapsed());

    let container_repo_path = devcontainer.container_repo_path(&repo_root);
    let workdir = container_workdir(&devcontainer, &repo_root)?;
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let t = Instant::now();
    let LaunchResult {
        container_id,
        user,
        docker_socket,
        image_built: _,
    } = launch_pod(&cmd.name, cmd.host.as_deref())?;
    trace!("launch_pod: {:?}", t.elapsed());

    // The host subdir may not exist in the container yet (e.g. empty dirs
    // are not copied by `docker build`). Create it so --workdir succeeds.
    if workdir != container_repo_path {
        let docker_host_arg = format!("unix://{}", docker_socket.display());
        let status = Command::new("docker")
            .args(["-H", &docker_host_arg])
            .args(["exec", "--user", &user, &container_id.0])
            .args(["mkdir", "-p", &workdir.to_string_lossy()])
            .status()
            .context("Failed to create workdir in container")?;
        if !status.success() {
            bail!(
                "Failed to create workdir {} in container",
                workdir.display()
            );
        }
    }

    let mut command = cmd.command.clone();
    if command.is_empty() {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        command.push(shell);
    }

    let mut docker_cmd = Command::new("docker");
    docker_cmd.args(["-H", &format!("unix://{}", docker_socket.display())]);
    docker_cmd.arg("exec");
    docker_cmd.args(["--user", &user]);
    docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);

    // Inject remoteEnv variables, resolving ${containerEnv:VAR} lazily
    let t = Instant::now();
    let remote_env = resolve_remote_env(&remote_env_map, &docker_socket, &container_id.0);
    trace!("resolve_remote_env: {:?}", t.elapsed());

    for (key, value) in &remote_env {
        docker_cmd.args(["-e", &format!("{}={}", key, value)]);
    }

    if std::io::stdin().is_terminal() {
        docker_cmd.args(["-it"]);
    }
    docker_cmd.arg(&container_id.0);
    docker_cmd.args(&command);

    trace!("total enter startup: {:?}", t_total.elapsed());

    let status = docker_cmd.status()?;

    if !status.success() {
        bail!("docker exec exited with status {}", status);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_gb() {
        assert_eq!(parse_size_string("4gb"), Some(4 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parse_size_case_insensitive() {
        assert_eq!(parse_size_string("512MB"), Some(512 * 1024 * 1024));
    }

    #[test]
    fn parse_size_tb() {
        assert_eq!(
            parse_size_string("2tb"),
            Some(2 * 1024 * 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn parse_size_kb() {
        assert_eq!(parse_size_string("128kb"), Some(128 * 1024));
    }

    #[test]
    fn parse_size_raw_bytes() {
        assert_eq!(parse_size_string("1048576"), Some(1048576));
    }

    #[test]
    fn parse_size_invalid() {
        assert_eq!(parse_size_string("not-a-number"), None);
    }

    #[test]
    fn parse_size_whitespace() {
        assert_eq!(parse_size_string(" 8 gb "), Some(8 * 1024 * 1024 * 1024));
    }
}
