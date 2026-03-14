use anyhow::Result;

use crate::cli::PortsCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName};
use crate::git::get_repo_root;

pub fn ports(cmd: &PortsCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let ports = client.list_ports(PodName(cmd.name.clone()), repo_root)?;

    println!("{:<12} {:<8} LABEL", "CONTAINER", "LOCAL");
    for p in &ports {
        let container_port = p.container_port;
        let local_port = p.local_port;
        let label = &p.label;
        println!("{container_port:<12} {local_port:<8} {label}");
    }

    Ok(())
}
