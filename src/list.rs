use anyhow::{Context, Result};

use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, SandboxStatus};

pub fn list() -> Result<()> {
    let repo_path = std::env::current_dir().context("Failed to get current directory")?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let sandboxes = client.list_sandboxes(repo_path)?;

    // Print header
    println!("{:<20} {:<15} {:<20}", "NAME", "STATUS", "CREATED");
    println!("{}", "-".repeat(55));

    // Print sandboxes
    for sandbox in sandboxes {
        let status_str = match sandbox.status {
            SandboxStatus::Running => "running",
            SandboxStatus::Stopped => "stopped",
        };
        println!(
            "{:<20} {:<15} {:<20}",
            sandbox.name, status_str, sandbox.created
        );
    }

    Ok(())
}
