use std::io::{self, IsTerminal, Write};

use anyhow::{bail, Result};

use crate::cli::PruneCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName, PodStatus};
use crate::git::get_repo_root;

/// Returns true if a pod in this status should be removed by `prune`.
fn is_prunable(status: &PodStatus) -> bool {
    match status {
        PodStatus::Stopped => true,
        PodStatus::Gone => true,
        PodStatus::Broken => true,
        PodStatus::Running => false,
        PodStatus::Disconnected => false,
        PodStatus::Deleting => false,
    }
}

/// Returns true if the repo_state string indicates the pod has unmerged
/// commits (i.e. is ahead of the host).
fn is_ahead(repo_state: Option<&str>) -> bool {
    match repo_state {
        Some(s) => s.contains("ahead"),
        None => false,
    }
}

pub fn prune(cmd: &PruneCommand) -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let pods = client.list_pods(repo_path.clone())?;

    let prunable: Vec<_> = pods.iter().filter(|p| is_prunable(&p.status)).collect();

    if prunable.is_empty() {
        eprintln!("No stopped pods to remove.");
        return Ok(());
    }

    let mut deleted = 0u32;
    let mut failed = 0u32;

    for pod in &prunable {
        if !cmd.force && is_ahead(pod.repo_state.as_deref()) {
            let state = pod.repo_state.as_deref().unwrap_or("");
            if io::stdin().is_terminal() && io::stderr().is_terminal() {
                eprint!(
                    "pod '{}' has unmerged commits ({}), delete anyway? [y/N] ",
                    pod.name, state
                );
                io::stderr().flush()?;

                let mut answer = String::new();
                io::stdin().read_line(&mut answer)?;
                if !answer.trim().eq_ignore_ascii_case("y") {
                    eprintln!("skipping pod '{}'", pod.name);
                    continue;
                }
            } else {
                eprintln!(
                    "pod '{}' has unmerged commits ({}); use --force to delete",
                    pod.name, state
                );
                failed += 1;
                continue;
            }
        }

        if let Err(e) = client.delete_pod(PodName(pod.name.clone()), repo_path.clone(), true) {
            eprintln!("failed to delete pod '{}': {}", pod.name, e);
            failed += 1;
        } else {
            deleted += 1;
        }
    }

    eprintln!("Deleted {} pod(s).", deleted);

    if failed > 0 {
        bail!("{} pod(s) could not be deleted", failed);
    }

    Ok(())
}
