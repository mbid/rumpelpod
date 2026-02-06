use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::cli::EnterCommand;
use crate::config::{RemoteDocker, SandboxConfig};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LaunchResult, LifecycleCommands, SandboxName};
use crate::devcontainer::MountType;
use crate::git::{get_current_branch, get_repo_root};
use crate::image;

/// Compute the path relative from `base` to `path`.
/// Both paths must be absolute and `path` must be under `base`.
fn relative_path<'a>(base: &Path, path: &'a Path) -> Result<&'a Path> {
    path.strip_prefix(base)
        .with_context(|| format!("{} is not under {}", path.display(), base.display()))
}

/// Launch a sandbox and return the container ID and user.
/// This is shared logic between `enter` and `agent` commands.
pub fn launch_sandbox(sandbox_name: &str, host_override: Option<&str>) -> Result<LaunchResult> {
    let repo_root = get_repo_root()?;
    let config = SandboxConfig::load(&repo_root)?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let runtime = config.runtime.unwrap_or_default();

    // Get the current branch on the host (if any) to set as upstream for the
    // sandbox's primary branch.
    let host_branch = get_current_branch(&repo_root);

    // Parse remote Docker specification if provided
    let host_str = host_override.or(config.host.as_deref());
    let remote = host_str
        .map(RemoteDocker::parse)
        .transpose()
        .context("Invalid remote Docker specification")?;

    // Reject bind mounts early for remote Docker — the source paths would
    // reference the remote filesystem, not the developer's machine.
    if remote.is_some() {
        for m in &config.mounts {
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

    let image = image::resolve_image(
        &config.image,
        config.pending_build.as_ref(),
        config.host.as_deref(),
        &repo_root,
    )?;

    // Resolve environment variables from config
    let mut env = std::collections::HashMap::new();
    for (key, value) in &config.container_env {
        let resolved_value = if let Some(var_name) = value
            .strip_prefix("${localEnv:")
            .and_then(|s| s.strip_suffix("}"))
        {
            std::env::var(var_name).unwrap_or_default()
        } else {
            value.clone()
        };
        env.insert(key.clone(), resolved_value);
    }

    let lifecycle = LifecycleCommands {
        on_create_command: config.on_create_command,
        post_create_command: config.post_create_command,
        post_start_command: config.post_start_command,
        post_attach_command: config.post_attach_command,
        wait_for: config.wait_for,
    };

    client.launch_sandbox(
        SandboxName(sandbox_name.to_string()),
        image,
        repo_root,
        config.repo_path,
        config.user,
        runtime,
        config.network,
        host_branch,
        remote,
        env,
        lifecycle,
        config.mounts,
        config.runtime_options,
        config.forward_ports,
        config.ports_attributes,
    )
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
    let config = SandboxConfig::load(&repo_root)?;

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
    let workdir = config.repo_path.join(relative);

    let mut docker_cmd = Command::new("docker");
    docker_cmd.args(["-H", &format!("unix://{}", docker_socket.display())]);
    docker_cmd.arg("exec");
    docker_cmd.args(["--user", &user]);
    docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);

    // Inject remoteEnv variables, resolving ${containerEnv:VAR} lazily
    let remote_env = resolve_remote_env(&config.remote_env, &docker_socket, &container_id.0);
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
