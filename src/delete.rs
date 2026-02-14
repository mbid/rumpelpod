use anyhow::Result;

use crate::cli::DeleteCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName};
use crate::git::get_repo_root;

pub fn delete(cmd: &DeleteCommand) -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.delete_pod(PodName(cmd.name.clone()), repo_path, cmd.wait)?;

    Ok(())
}
