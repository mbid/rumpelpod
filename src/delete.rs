use std::io::{self, IsTerminal, Write};

use anyhow::{bail, Result};

use crate::cli::DeleteCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName};
use crate::git::get_repo_root;

/// Returns true if the repo_state string indicates the pod has unmerged
/// commits (i.e. is ahead of the host).
fn is_ahead(repo_state: Option<&str>) -> bool {
    match repo_state {
        Some(s) => s.contains("ahead"),
        None => false,
    }
}

pub fn delete(cmd: &DeleteCommand) -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let pods = client.list_pods(repo_path.clone())?;
    let pod = pods.iter().find(|p| p.name == cmd.name);

    let Some(pod) = pod else {
        bail!("pod '{}' not found", cmd.name);
    };

    if !cmd.force && is_ahead(pod.repo_state.as_deref()) {
        let state = pod.repo_state.as_deref().unwrap_or("");
        if io::stdin().is_terminal() && io::stderr().is_terminal() {
            eprint!(
                "pod '{}' has unmerged commits ({}), delete anyway? [y/N] ",
                cmd.name, state
            );
            io::stderr().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                bail!("aborted");
            }
        } else {
            bail!(
                "pod '{}' has unmerged commits ({}); use --force to delete",
                cmd.name,
                state
            );
        }
    }

    client.delete_pod(PodName(cmd.name.clone()), repo_path, cmd.wait)?;

    Ok(())
}
