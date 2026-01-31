use anyhow::Result;
use comfy_table::presets::NOTHING;
use comfy_table::Table;

use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, SandboxStatus};
use crate::git::get_repo_root;

pub fn list() -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let sandboxes = client.list_sandboxes(repo_path)?;

    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .set_header(vec!["NAME", "GIT", "STATUS", "CREATED", "HOST"]);

    for sandbox in sandboxes {
        let status_str = match sandbox.status {
            SandboxStatus::Running => "running",
            SandboxStatus::Stopped => "stopped",
            SandboxStatus::Gone => "gone",
            SandboxStatus::Disconnected => "disconnected",
        };
        let repo_state = sandbox.repo_state.as_deref().unwrap_or("");

        table.add_row(vec![
            sandbox.name,
            repo_state.to_string(),
            status_str.to_string(),
            sandbox.created,
            sandbox.host,
        ]);
    }

    println!("{table}");

    Ok(())
}
