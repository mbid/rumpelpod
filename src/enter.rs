use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::cli::EnterCommand;
use crate::config::{load_toml_config, DockerHost};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LaunchResult, PodLaunchParams, PodName};
use crate::devcontainer::{
    substitute_vars, ContainerEnvSource, DevContainer, MountType, SubstitutionContext,
};
use crate::git::{get_current_branch, get_repo_root};

/// Compute the path relative from `base` to `path`.
/// Both paths must be absolute and `path` must be under `base`.
fn relative_path<'a>(base: &Path, path: &'a Path) -> Result<&'a Path> {
    path.strip_prefix(base)
        .with_context(|| format!("{} is not under {}", path.display(), base.display()))
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

    Ok((devcontainer, docker_host))
}

/// Launch a pod and return the container ID and user.
/// This is shared logic between `enter` and `agent` commands.
pub fn launch_pod(pod_name: &str, host_override: Option<&str>) -> Result<LaunchResult> {
    let repo_root = get_repo_root()?;

    let (devcontainer, docker_host) = load_and_resolve(&repo_root, host_override)?;

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

    client.launch_pod(PodLaunchParams {
        pod_name: PodName(pod_name.to_string()),
        repo_path: repo_root,
        host_branch,
        docker_host,
        devcontainer,
    })
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
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;
    let repo_root = get_repo_root()?;

    let (devcontainer, _docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;
    let container_repo_path = devcontainer.container_repo_path(&repo_root);
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let LaunchResult {
        container_id,
        user,
        docker_socket,
    } = launch_pod(&cmd.name, cmd.host.as_deref())?;

    let mut command = cmd.command.clone();
    if command.is_empty() {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        command.push(shell);
    }

    let relative = relative_path(&repo_root, &current_dir)?;
    let workdir = container_repo_path.join(relative);

    let mut docker_cmd = Command::new("docker");
    docker_cmd.args(["-H", &format!("unix://{}", docker_socket.display())]);
    docker_cmd.arg("exec");
    docker_cmd.args(["--user", &user]);
    docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);

    // Inject remoteEnv variables, resolving ${containerEnv:VAR} lazily
    let remote_env = resolve_remote_env(&remote_env_map, &docker_socket, &container_id.0);
    for (key, value) in &remote_env {
        docker_cmd.args(["-e", &format!("{}={}", key, value)]);
    }

    if std::io::stdin().is_terminal() {
        docker_cmd.args(["-it"]);
    }
    docker_cmd.arg(&container_id.0);
    docker_cmd.args(&command);

    let status = docker_cmd.status()?;

    if !status.success() {
        bail!("docker exec exited with status {}", status);
    }

    Ok(())
}
