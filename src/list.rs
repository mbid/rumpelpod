use std::cmp::Reverse;

use anyhow::Result;
use comfy_table::presets::NOTHING;
use comfy_table::Table;

use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodStatus};
use crate::git::get_repo_root;
use crate::pod::types::ClaudeState;

fn claude_state_str(state: Option<ClaudeState>) -> &'static str {
    match state {
        Some(ClaudeState::Processing) => "processing",
        Some(ClaudeState::WaitingForInput) => "idle",
        Some(ClaudeState::AuthError) => "auth error",
        Some(ClaudeState::Stopped) => "stopped",
        None => "",
    }
}

pub fn list() -> Result<()> {
    let repo_path = get_repo_root()?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let mut pods = client.list_pods(repo_path)?;
    // Running pods first, then by most recent commit on the pod's primary branch.
    pods.sort_by_key(|pod| {
        (
            pod.status != PodStatus::Running,
            Reverse(pod.last_commit_time),
        )
    });

    let show_claude = pods.iter().any(|pod| pod.claude_state.is_some());

    let mut table = Table::new();
    table.load_preset(NOTHING);
    if show_claude {
        table.set_header(vec![
            "NAME",
            "CLAUDE",
            "GIT",
            "STATUS",
            "CREATED",
            "HOST",
            "CONTAINER ID",
        ]);
    } else {
        table.set_header(vec![
            "NAME",
            "GIT",
            "STATUS",
            "CREATED",
            "HOST",
            "CONTAINER ID",
        ]);
    }

    for pod in pods {
        let status_str = match pod.status {
            PodStatus::Running => "running",
            PodStatus::Stopped => "stopped",
            PodStatus::Gone => "gone",
            PodStatus::Disconnected => "disconnected",
            PodStatus::Stopping => "stopping",
            PodStatus::Deleting => "deleting",
            PodStatus::Broken => "broken",
        };
        let repo_state = pod.repo_state.as_deref().unwrap_or("");
        let header = "CONTAINER ID";
        let container_id = pod.container_id.as_deref().unwrap_or("");
        let container_id = &container_id[..container_id.len().min(header.len())];

        if show_claude {
            table.add_row(vec![
                pod.name,
                claude_state_str(pod.claude_state).to_string(),
                repo_state.to_string(),
                status_str.to_string(),
                pod.created,
                pod.host,
                container_id.to_string(),
            ]);
        } else {
            table.add_row(vec![
                pod.name,
                repo_state.to_string(),
                status_str.to_string(),
                pod.created,
                pod.host,
                container_id.to_string(),
            ]);
        }
    }

    println!("{table}");

    Ok(())
}
