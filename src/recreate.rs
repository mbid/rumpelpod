use anyhow::{Context, Result};

use crate::cli::RecreateCommand;
use crate::config::{RemoteDocker, SandboxConfig};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LifecycleCommands, SandboxName};
use crate::git::{get_current_branch, get_repo_root};
use crate::image;

pub fn recreate(cmd: &RecreateCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let config = SandboxConfig::load(&repo_root)?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let runtime = config.runtime.unwrap_or_default();

    // Get the current branch on the host
    let host_branch = get_current_branch(&repo_root);

    // Parse remote Docker specification if provided
    let host_str = cmd.host.as_deref().or(config.host.as_deref());
    let remote = host_str
        .map(RemoteDocker::parse)
        .transpose()
        .context("Invalid remote Docker specification")?;

    let image = image::resolve_image(
        &config.image,
        config.pending_build.as_ref(),
        config.host.as_deref(),
        &repo_root,
    )?;

    // Resolve environment variables from config
    let mut env = std::collections::HashMap::new();
    for (key, value) in &config.container_env {
        let resolved_value = if let Some(var_name) = value
            .strip_prefix("${localEnv:")
            .and_then(|s| s.strip_suffix("}"))
        {
            std::env::var(var_name).unwrap_or_default()
        } else {
            value.clone()
        };
        env.insert(key.clone(), resolved_value);
    }

    let lifecycle = LifecycleCommands {
        on_create_command: config.on_create_command,
        post_create_command: config.post_create_command,
        post_start_command: config.post_start_command,
        post_attach_command: config.post_attach_command,
        wait_for: config.wait_for,
    };

    client.recreate_sandbox(
        SandboxName(cmd.name.clone()),
        image,
        repo_root,
        config.repo_path,
        config.user,
        runtime,
        config.network,
        host_branch,
        remote,
        env,
        lifecycle,
        config.mounts,
        config.runtime_options,
    )?;

    println!("Sandbox '{}' recreated successfully.", cmd.name);

    Ok(())
}
