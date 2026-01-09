use anyhow::{Context, Result};

use crate::cli::DeleteCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, SandboxName};

pub fn delete(cmd: &DeleteCommand) -> Result<()> {
    let repo_path = std::env::current_dir().context("Failed to get current directory")?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.delete_sandbox(SandboxName(cmd.name.clone()), repo_path)?;

    Ok(())
}
