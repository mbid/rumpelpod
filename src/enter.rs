use std::io::IsTerminal;
use std::process::Command;

use anyhow::{bail, Result};

use crate::cli::EnterCommand;
use crate::config::SandboxConfig;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, Image, SandboxName};
use crate::git::get_repo_root;

pub fn enter(cmd: &EnterCommand) -> Result<()> {
    let repo_path = get_repo_root()?;
    let config = SandboxConfig::load(&repo_path)?;

    let image = config.image.unwrap_or_else(|| "ubuntu:24.04".to_string());

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let container_id =
        client.launch_sandbox(SandboxName(cmd.name.clone()), Image(image), repo_path)?;

    let mut command = cmd.command.clone();
    if command.is_empty() {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        command.push(shell);
    }

    let mut docker_cmd = Command::new("docker");
    docker_cmd.arg("exec");
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
