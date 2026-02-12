use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use log::trace;

use crate::cli::ClaudeCommand;
use crate::daemon;
use crate::daemon::protocol::{
    ContainerId, Daemon, DaemonClient, EnsureClaudeConfigRequest, LaunchResult, PodName,
};
use crate::enter::{launch_pod, load_and_resolve, resolve_remote_env};
use crate::git::get_repo_root;

const SCREENRC_PATH: &str = "/tmp/rumpelpod-screenrc";

struct ScreenState {
    available: bool,
    session_exists: bool,
}

/// Check if screen is available, write a screenrc, and detect an existing
/// session -- all in a single `docker exec` to avoid multiple round trips.
fn prepare_screen(docker_host: &str, container_id: &str, user: &str) -> Result<ScreenState> {
    let script = format!(
        "which screen >/dev/null 2>&1 || {{ echo SCREEN_MISSING; exit 0; }}; \
         printf 'termcapinfo xterm* ti@:te@\\ndefscrollback 50000\\n' > {SCREENRC_PATH}; \
         screen -ls claude 2>/dev/null | grep -q '\\.claude' && echo SESSION_EXISTS || echo SESSION_NEW"
    );

    let output = Command::new("docker")
        .args(["-H", docker_host])
        .args(["exec", "--user", user, container_id])
        .args(["sh", "-c", &script])
        .output()
        .context("Failed to prepare screen in container")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("SCREEN_MISSING") {
        return Ok(ScreenState {
            available: false,
            session_exists: false,
        });
    }

    Ok(ScreenState {
        available: true,
        session_exists: stdout.contains("SESSION_EXISTS"),
    })
}

pub fn claude(cmd: &ClaudeCommand) -> Result<()> {
    let t_total = Instant::now();

    let t = Instant::now();
    let repo_root = get_repo_root()?;
    trace!("get_repo_root: {:?}", t.elapsed());

    let t = Instant::now();
    let (devcontainer, _docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;
    trace!("load_and_resolve: {:?}", t.elapsed());

    let workdir = devcontainer.container_repo_path(&repo_root);
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let t = Instant::now();
    let LaunchResult {
        container_id,
        user,
        docker_socket,
        image_built: _,
    } = launch_pod(&cmd.name, cmd.host.as_deref())?;
    trace!("launch_pod: {:?}", t.elapsed());

    let docker_host = format!("unix://{}", docker_socket.display());

    // Run screen preparation and config copy in parallel to avoid
    // sequential round trips to the Docker daemon.
    let t = Instant::now();
    let (screen_state, config_result) = std::thread::scope(|s| {
        let config_handle = s.spawn(|| {
            let tc = Instant::now();
            let socket_path = daemon::socket_path()?;
            let client = DaemonClient::new_unix(&socket_path);
            let result = client.ensure_claude_config(EnsureClaudeConfigRequest {
                pod_name: PodName(cmd.name.clone()),
                repo_path: repo_root.clone(),
                container_repo_path: workdir.clone(),
                container_id: ContainerId(container_id.0.clone()),
                user: user.clone(),
                docker_socket: docker_socket.clone(),
            });
            trace!("ensure_claude_config: {:?}", tc.elapsed());
            result
        });

        let ts = Instant::now();
        let screen_state = prepare_screen(&docker_host, &container_id.0, &user);
        trace!("prepare_screen: {:?}", ts.elapsed());

        let config_result = config_handle.join().unwrap();
        (screen_state, config_result)
    });
    trace!("parallel screen+config: {:?}", t.elapsed());

    config_result?;
    let screen_state = screen_state?;

    if !screen_state.available {
        bail!(
            "screen is not installed in the container.\n\
             Add `screen` to your container image to use `rumpel claude`."
        );
    }

    // Build the docker exec command for the interactive screen session
    let mut docker_cmd = Command::new("docker");
    docker_cmd.args(["-H", &docker_host]);
    docker_cmd.arg("exec");
    docker_cmd.args(["--user", &user]);
    docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);

    // Inject remoteEnv variables
    let t = Instant::now();
    let remote_env = resolve_remote_env(&remote_env_map, &docker_socket, &container_id.0);
    trace!("resolve_remote_env: {:?}", t.elapsed());

    for (key, value) in &remote_env {
        docker_cmd.args(["-e", &format!("{}={}", key, value)]);
    }

    docker_cmd.args(["-it"]);
    docker_cmd.arg(&container_id.0);

    if screen_state.session_exists {
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

    trace!("total claude startup: {:?}", t_total.elapsed());

    let status = docker_cmd.status()?;

    if !status.success() {
        bail!("docker exec exited with status {}", status);
    }

    Ok(())
}
