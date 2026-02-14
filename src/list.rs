use anyhow::Result;
use comfy_table::presets::NOTHING;
use comfy_table::Table;

use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodStatus};
use crate::git::get_repo_root;

pub fn list() -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let pods = client.list_pods(repo_path)?;

    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(vec![
        "NAME",
        "GIT",
        "STATUS",
        "CREATED",
        "HOST",
        "CONTAINER ID",
    ]);

    for pod in pods {
        let status_str = match pod.status {
            PodStatus::Running => "running",
            PodStatus::Stopped => "stopped",
            PodStatus::Gone => "gone",
            PodStatus::Disconnected => "disconnected",
            PodStatus::Deleting => "deleting",
            PodStatus::Broken => "broken",
        };
        let repo_state = pod.repo_state.as_deref().unwrap_or("");
        let header = "CONTAINER ID";
        let container_id = pod.container_id.as_deref().unwrap_or("");
        let container_id = &container_id[..container_id.len().min(header.len())];

        table.add_row(vec![
            pod.name,
            repo_state.to_string(),
            status_str.to_string(),
            pod.created,
            pod.host,
            container_id.to_string(),
        ]);
    }

    println!("{table}");

    Ok(())
}
