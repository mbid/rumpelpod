use anyhow::{Context, Result};

use crate::cli::RecreateCommand;
use crate::config::RemoteDocker;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, SandboxLaunchParams, SandboxName};
use crate::enter::load_and_resolve;
use crate::git::{get_current_branch, get_repo_root};

pub fn recreate(cmd: &RecreateCommand) -> Result<()> {
    let repo_root = get_repo_root()?;

    let (devcontainer, host_str) = load_and_resolve(&repo_root, cmd.host.as_deref())?;

    let remote = host_str
        .as_deref()
        .map(RemoteDocker::parse)
        .transpose()
        .context("Invalid remote Docker specification")?;

    let host_branch = get_current_branch(&repo_root);

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.recreate_sandbox(SandboxLaunchParams {
        sandbox_name: SandboxName(cmd.name.clone()),
        repo_path: repo_root,
        host_branch,
        remote,
        devcontainer,
    })?;

    println!("Sandbox '{}' recreated successfully.", cmd.name);

    Ok(())
}
