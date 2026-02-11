use std::process::Command;

use anyhow::{bail, Context, Result};
use log::warn;

use crate::cli::ClaudeCommand;
use crate::daemon;
use crate::daemon::protocol::{
    ContainerId, Daemon, DaemonClient, EnsureClaudeConfigRequest, LaunchResult, PodName,
};
use crate::enter::{launch_pod, load_and_resolve, resolve_remote_env};
use crate::git::get_repo_root;

/// Check if `screen` is available in the container.
fn check_screen_available(docker_host: &str, container_id: &str, user: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["-H", docker_host])
        .args(["exec", "--user", user, container_id, "which", "screen"])
        .output()
        .context("Failed to check for screen in container")?;
    Ok(output.status.success())
}

/// Check if a screen session named "claude" exists in the container.
/// Returns true if there is an attachable session.
///
/// Parses `screen -ls claude` stdout rather than relying on exit codes,
/// because a docker exec or SSH pipe failure could produce an arbitrary
/// exit code that we would misinterpret.
fn screen_session_exists(docker_host: &str, container_id: &str, user: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["-H", docker_host])
        .args([
            "exec",
            "--user",
            user,
            container_id,
            "screen",
            "-ls",
            "claude",
        ])
        .output()
        .context("Failed to check for screen session")?;

    // `screen -ls claude` prints lines like "12345.claude (Detached)" when a
    // matching session exists.  Look for ".claude" in stdout to detect this;
    // if docker exec itself failed, stdout will be empty and we safely return
    // false (the subsequent docker exec to create the session will surface the
    // real error).
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(".claude"))
}

const SCREENRC_PATH: &str = "/tmp/rumpelpod-screenrc";

/// Write a screenrc to a well-known path so we can pass it via `screen -c`
/// without clobbering the user's own ~/.screenrc.
fn write_screenrc(docker_host: &str, container_id: &str, user: &str) {
    let cmd = format!(
        "printf 'termcapinfo xterm* ti@:te@\\ndefscrollback 50000\\n' > {}",
        SCREENRC_PATH,
    );
    let result = Command::new("docker")
        .args(["-H", docker_host])
        .args(["exec", "--user", user, container_id])
        .args(["sh", "-c", &cmd])
        .output();
    if let Err(e) = result {
        warn!("Failed to write {}: {}", SCREENRC_PATH, e);
    }
}

pub fn claude(cmd: &ClaudeCommand) -> Result<()> {
    let repo_root = get_repo_root()?;

    let (devcontainer, _docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let LaunchResult {
        container_id,
        user,
        docker_socket,
    } = launch_pod(&cmd.name, cmd.host.as_deref())?;

    let docker_host = format!("unix://{}", docker_socket.display());

    // Check if screen is installed
    if !check_screen_available(&docker_host, &container_id.0, &user)? {
        bail!(
            "screen is not installed in the container.\n\
             Add `screen` to your container image to use `rumpel claude`."
        );
    }

    // Ask the daemon to copy config files (idempotent -- skips if already done)
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);
    client.ensure_claude_config(EnsureClaudeConfigRequest {
        pod_name: PodName(cmd.name.clone()),
        repo_path: repo_root,
        container_id: ContainerId(container_id.0.clone()),
        user: user.clone(),
        docker_socket: docker_socket.clone(),
    })?;

    write_screenrc(&docker_host, &container_id.0, &user);

    // Build the docker exec command for the interactive screen session
    let mut docker_cmd = Command::new("docker");
    docker_cmd.args(["-H", &docker_host]);
    docker_cmd.arg("exec");
    docker_cmd.args(["--user", &user]);

    // Inject remoteEnv variables
    let remote_env = resolve_remote_env(&remote_env_map, &docker_socket, &container_id.0);
    for (key, value) in &remote_env {
        docker_cmd.args(["-e", &format!("{}={}", key, value)]);
    }

    docker_cmd.args(["-it"]);
    docker_cmd.arg(&container_id.0);

    if screen_session_exists(&docker_host, &container_id.0, &user)? {
        // Reattach to existing session
        docker_cmd.args(["screen", "-c", SCREENRC_PATH, "-U", "-d", "-R", "claude"]);
    } else {
        // Create new screen session running claude
        docker_cmd.args([
            "screen",
            "-c",
            SCREENRC_PATH,
            "-U",
            "-S",
            "claude",
            "--",
            "claude",
            "--dangerously-skip-permissions",
        ]);
        docker_cmd.args(&cmd.args);
    }

    let status = docker_cmd.status()?;

    if !status.success() {
        bail!("docker exec exited with status {}", status);
    }

    Ok(())
}
