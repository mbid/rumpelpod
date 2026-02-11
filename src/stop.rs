use anyhow::Result;

use crate::cli::StopCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName};
use crate::git::get_repo_root;

pub fn stop(cmd: &StopCommand) -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.stop_pod(PodName(cmd.name.clone()), repo_path)?;

    Ok(())
}
