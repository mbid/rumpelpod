use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::cli::EnterCommand;
use crate::config::SandboxConfig;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, Image, SandboxName};
use crate::git::get_repo_root;

/// Compute the path relative from `base` to `path`.
/// Both paths must be absolute and `path` must be under `base`.
fn relative_path<'a>(base: &Path, path: &'a Path) -> Result<&'a Path> {
    path.strip_prefix(base)
        .with_context(|| format!("{} is not under {}", path.display(), base.display()))
}

pub fn enter(cmd: &EnterCommand) -> Result<()> {
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;
    let repo_root = get_repo_root()?;
    let config = SandboxConfig::load(&repo_root)?;

    let image = config.image.unwrap_or_else(|| "ubuntu:24.04".to_string());

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let container_id = client.launch_sandbox(
        SandboxName(cmd.name.clone()),
        Image(image),
        repo_root.clone(),
    )?;

    let mut command = cmd.command.clone();
    if command.is_empty() {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        command.push(shell);
    }

    let mut docker_cmd = Command::new("docker");
    docker_cmd.arg("exec");

    // Set user if configured
    if let Some(ref user) = config.user {
        docker_cmd.args(["--user", user]);
    }

    // Set working directory if repo-path is configured
    if let Some(ref container_repo_path) = config.repo_path {
        let relative = relative_path(&repo_root, &current_dir)?;
        let workdir = container_repo_path.join(relative);
        docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);
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
