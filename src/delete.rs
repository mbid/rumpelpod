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

    let mut failed = 0u32;

    for name in &cmd.names {
        let pod = pods.iter().find(|p| p.name == *name);

        let Some(pod) = pod else {
            eprintln!("pod '{}' not found", name);
            failed += 1;
            continue;
        };

        if !cmd.force && is_ahead(pod.repo_state.as_deref()) {
            let state = pod.repo_state.as_deref().unwrap_or("");
            if io::stdin().is_terminal() && io::stderr().is_terminal() {
                eprint!(
                    "pod '{}' has unmerged commits ({}), delete anyway? [y/N] ",
                    name, state
                );
                io::stderr().flush()?;

                let mut answer = String::new();
                io::stdin().read_line(&mut answer)?;
                if !answer.trim().eq_ignore_ascii_case("y") {
                    eprintln!("skipping pod '{}'", name);
                    continue;
                }
            } else {
                eprintln!(
                    "pod '{}' has unmerged commits ({}); use --force to delete",
                    name, state
                );
                failed += 1;
                continue;
            }
        }

        if let Err(e) = client.delete_pod(PodName(name.clone()), repo_path.clone(), cmd.wait) {
            eprintln!("failed to delete pod '{}': {}", name, e);
            failed += 1;
        }
    }

    if failed > 0 {
        bail!("{} pod(s) could not be deleted", failed);
    }

    Ok(())
}
