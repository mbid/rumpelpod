use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::cli::EnterCommand;
use crate::config::{RemoteDocker, SandboxConfig};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LaunchResult, SandboxName};
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
    )
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
