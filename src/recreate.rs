use anyhow::Result;

use crate::cli::RecreateCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodLaunchParams, PodName};
use crate::enter::load_and_resolve;
use crate::git::{get_current_branch, get_repo_root};

pub fn recreate(cmd: &RecreateCommand) -> Result<()> {
    let repo_root = get_repo_root()?;

    let (devcontainer, docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;

    let host_branch = get_current_branch(&repo_root);

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.recreate_pod(PodLaunchParams {
        pod_name: PodName(cmd.name.clone()),
        repo_path: repo_root,
        host_branch,
        docker_host,
        devcontainer,
    })?;

    println!("Pod '{}' recreated successfully.", cmd.name);

    Ok(())
}
