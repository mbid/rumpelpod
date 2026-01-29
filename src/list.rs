use anyhow::Result;

use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, SandboxStatus};
use crate::git::get_repo_root;

pub fn list() -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let sandboxes = client.list_sandboxes(repo_path)?;

    // Print header
    println!(
        "{:<20} {:<25} {:<15} {:<20} {:<20}",
        "NAME", "GIT", "STATUS", "CREATED", "HOST"
    );
    println!("{}", "-".repeat(100));

    // Print sandboxes
    for sandbox in sandboxes {
        let status_str = match sandbox.status {
            SandboxStatus::Running => "running",
            SandboxStatus::Stopped => "stopped",
            SandboxStatus::Gone => "gone",
            SandboxStatus::Disconnected => "disconnected",
        };
        let repo_state = sandbox.repo_state.as_deref().unwrap_or("");
        println!(
            "{:<20} {:<25} {:<15} {:<20} {:<20}",
            sandbox.name, repo_state, status_str, sandbox.created, sandbox.host
        );
    }

    Ok(())
}
