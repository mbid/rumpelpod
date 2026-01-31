use anyhow::{Context, Result};

use crate::cli::RecreateCommand;
use crate::config::{RemoteDocker, SandboxConfig};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, SandboxName};
use crate::git::{get_current_branch, get_repo_root};
use crate::image;

pub fn recreate(cmd: &RecreateCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let config = SandboxConfig::load(&repo_root)?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let runtime = config.runtime.unwrap_or_default();

    // Get the current branch on the host
    let host_branch = get_current_branch(&repo_root);

    // Parse remote Docker specification if provided
    let host_str = cmd.host.as_deref().or(config.host.as_deref());
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

    client.recreate_sandbox(
        SandboxName(cmd.name.clone()),
        image,
        repo_root,
        config.repo_path,
        config.user,
        runtime,
        config.network,
        host_branch,
        remote,
    )?;

    println!("Sandbox '{}' recreated successfully.", cmd.name);

    Ok(())
}
