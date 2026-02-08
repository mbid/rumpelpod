use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::cli::EnterCommand;
use crate::config::{load_toml_config, RemoteDocker};
use crate::daemon;
use crate::daemon::protocol::{
    Daemon, DaemonClient, LaunchResult, SandboxLaunchParams, SandboxName,
};
use crate::devcontainer::{DevContainer, MountType};
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
/// Returns the DevContainer and the host string from .sandbox.toml.
pub fn load_and_resolve(
    repo_root: &Path,
    host_override: Option<&str>,
) -> Result<(DevContainer, Option<String>)> {
    let toml_config = load_toml_config(repo_root)?;
    let host_str = host_override.map(String::from).or(toml_config.host.clone());

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
    devcontainer.resolve_local_env();

    Ok((devcontainer, host_str))
}

/// Launch a sandbox and return the container ID and user.
/// This is shared logic between `enter` and `agent` commands.
pub fn launch_sandbox(sandbox_name: &str, host_override: Option<&str>) -> Result<LaunchResult> {
    let repo_root = get_repo_root()?;

    let (devcontainer, host_str) = load_and_resolve(&repo_root, host_override)?;

    // Reject bind mounts early for remote Docker
    let remote = host_str
        .as_deref()
        .map(RemoteDocker::parse)
        .transpose()
        .context("Invalid remote Docker specification")?;

    if remote.is_some() {
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

    client.launch_sandbox(SandboxLaunchParams {
        sandbox_name: SandboxName(sandbox_name.to_string()),
        repo_path: repo_root,
        host_branch,
        remote,
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
    remote_env
        .iter()
        .map(|(key, value)| {
            let resolved = resolve_container_env_in_value(value, docker_socket, container_id);
            (key.clone(), resolved)
        })
        .collect()
}

fn resolve_container_env_in_value(value: &str, docker_socket: &Path, container_id: &str) -> String {
    let mut result = value.to_string();
    while let Some(start) = result.find("${containerEnv:") {
        let after = start + "${containerEnv:".len();
        if let Some(end) = result[after..].find('}') {
            let var_name = &result[after..after + end].to_string();
            let replacement =
                read_container_env_var(docker_socket, container_id, var_name).unwrap_or_default();
            result = format!(
                "{}{}{}",
                &result[..start],
                replacement,
                &result[after + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

fn read_container_env_var(
    docker_socket: &Path,
    container_id: &str,
    var_name: &str,
) -> Option<String> {
    let output = Command::new("docker")
        .args(["-H", &format!("unix://{}", docker_socket.display())])
        .args(["exec", container_id, "printenv", var_name])
        .output()
        .ok()?;
    if output.status.success() {
        Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end_matches('\n')
                .to_string(),
        )
    } else {
        None
    }
}

pub fn enter(cmd: &EnterCommand) -> Result<()> {
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;
    let repo_root = get_repo_root()?;

    let (devcontainer, _) = load_and_resolve(&repo_root, cmd.host.as_deref())?;
    let container_repo_path = devcontainer.container_repo_path(&repo_root);
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let LaunchResult {
        container_id,
        user,
        docker_socket,
    } = launch_sandbox(&cmd.name, cmd.host.as_deref())?;

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
