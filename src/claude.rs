use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use log::trace;

use crate::cli::ClaudeCommand;
use crate::config::{load_toml_config, Host};
use crate::daemon;
use crate::daemon::protocol::{
    ContainerId, Daemon, DaemonClient, EnsureClaudeConfigRequest, PodName,
};
use crate::devcontainer::shell_escape;
use crate::enter::{launch_pod, load_and_resolve, merge_env, resolve_remote_env_via_pod};
use crate::git::get_repo_root;

const SCREENRC_PATH: &str = "/tmp/rumpelpod-screenrc";
// Wrapper that lowers the fd limit before exec'ing screen.
// screen iterates all possible fds at startup to close leaked ones,
// and containers often have ulimit -n in the billions, making that
// loop take 10+ seconds.
const SCREEN_WRAPPER_PATH: &str = "/tmp/rumpelpod-screen";

struct ScreenState {
    available: bool,
    session_exists: bool,
}

/// Check if screen is available, write a screenrc, and detect an existing
/// session -- all in a single `docker exec` to avoid multiple round trips.
fn prepare_screen(docker_host: &str, container_id: &str, user: &str) -> Result<ScreenState> {
    let script = format!(
        "which screen >/dev/null 2>&1 || {{ echo SCREEN_MISSING; exit 0; }}; \
         ulimit -n 65536; \
         printf 'startup_message off\\ndefscrollback 50000\\n' > {SCREENRC_PATH}; \
         printf '#!/bin/sh\\nulimit -n 65536\\nexec screen \"$@\"\\n' > {SCREEN_WRAPPER_PATH} \
         && chmod +x {SCREEN_WRAPPER_PATH}; \
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

/// Like prepare_screen but via the in-container HTTP server.
/// Works for any host type including Kubernetes.
fn prepare_screen_via_pod(pod: &crate::pod::PodClient) -> Result<ScreenState> {
    let script = format!(
        "which screen >/dev/null 2>&1 || {{ echo SCREEN_MISSING; exit 0; }}; \
         ulimit -n 65536; \
         printf 'startup_message off\\ndefscrollback 50000\\n' > {SCREENRC_PATH}; \
         printf '#!/bin/sh\\nulimit -n 65536\\nexec screen \"$@\"\\n' > {SCREEN_WRAPPER_PATH} \
         && chmod +x {SCREEN_WRAPPER_PATH}; \
         screen -ls claude 2>/dev/null | grep -q '\\.claude' && echo SESSION_EXISTS || echo SESSION_NEW"
    );

    let run_result = pod
        .run(&["sh", "-c", &script], None, None, &[], None, Some(10))
        .context("Failed to prepare screen in container")?;

    use base64::Engine;
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(&run_result.stdout)
        .unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout);

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
    let toml_config = load_toml_config(&repo_root)?;
    let (devcontainer, _docker_host) = load_and_resolve(&repo_root, cmd.host.as_deref())?;
    trace!("load_and_resolve: {:?}", t.elapsed());

    // CLI --no-dangerously-skip-permissions wins over the toml setting.
    let skip_permissions_hook = !cmd.no_dangerously_skip_permissions
        && (cmd.dangerously_skip_permissions_hook
            || toml_config.claude.dangerously_skip_permissions_hook);

    let workdir = devcontainer.container_repo_path(&repo_root);
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let t = Instant::now();
    let result = launch_pod(&cmd.name, cmd.host.as_deref())?;
    trace!("launch_pod: {:?}", t.elapsed());

    // Run screen preparation and config copy in parallel to avoid
    // sequential round trips.
    let t = Instant::now();
    let (screen_state, config_result) = std::thread::scope(|s| {
        let config_handle = s.spawn(|| {
            let tc = Instant::now();
            let socket_path = daemon::socket_path()?;
            let client = DaemonClient::new_unix(&socket_path);
            let cfg_result = client.ensure_claude_config(EnsureClaudeConfigRequest {
                pod_name: PodName(cmd.name.clone()),
                repo_path: repo_root.clone(),
                container_repo_path: workdir.clone(),
                container_id: ContainerId(result.container_id.0.clone()),
                user: result.user.clone(),
                docker_socket: result.docker_socket.clone(),
                container_url: result.container_url.clone(),
                container_token: result.container_token.clone(),
                auto_approve_hook: skip_permissions_hook,
            });
            trace!("ensure_claude_config: {:?}", tc.elapsed());
            cfg_result
        });

        let ts = Instant::now();
        let screen_state = match &result.host {
            Host::Kubernetes { .. } => {
                let pod = match crate::pod::PodClient::new(
                    &result.container_url,
                    &result.container_token,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        return (Err(e), config_handle.join().unwrap());
                    }
                };
                prepare_screen_via_pod(&pod)
            }
            Host::Localhost | Host::Ssh { .. } => {
                let docker_socket = match result.docker_socket.as_ref() {
                    Some(s) => s,
                    None => {
                        return (
                            Err(anyhow::anyhow!(
                                "docker_socket is required for Docker hosts"
                            )),
                            config_handle.join().unwrap(),
                        );
                    }
                };
                let docker_host = format!("unix://{}", docker_socket.display());
                prepare_screen(&docker_host, &result.container_id.0, &result.user)
            }
        };
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

    // Resolve ${containerEnv:VAR} via the in-container HTTP server (works for all host types).
    let pod = crate::pod::PodClient::new(&result.container_url, &result.container_token)?;
    let remote_env = resolve_remote_env_via_pod(&remote_env_map, &pod);
    let merged_env = merge_env(result.probed_env, remote_env);

    let status = match &result.host {
        Host::Kubernetes { context, namespace } => {
            // Build the screen command with env vars and workdir baked in,
            // since kubectl exec has no --workdir or -e flags.
            let env_prefix: String = merged_env
                .iter()
                .map(|(k, v)| format!("{}={}", k, shell_escape(v)))
                .collect::<Vec<_>>()
                .join(" ");

            let screen_cmd = if screen_state.session_exists {
                format!(
                    "{} -c {} -U -d -R claude",
                    SCREEN_WRAPPER_PATH, SCREENRC_PATH
                )
            } else {
                let mut parts = vec![format!(
                    "{} -c {} -U -S claude -- claude",
                    SCREEN_WRAPPER_PATH, SCREENRC_PATH
                )];
                if !skip_permissions_hook && !cmd.no_dangerously_skip_permissions {
                    parts.push("--dangerously-skip-permissions".to_string());
                }
                for arg in &cmd.args {
                    parts.push(shell_escape(arg));
                }
                parts.join(" ")
            };

            let wrapper = if env_prefix.is_empty() {
                format!(
                    "cd {} && exec {}",
                    shell_escape(&workdir.to_string_lossy()),
                    screen_cmd,
                )
            } else {
                format!(
                    "cd {} && exec env {} {}",
                    shell_escape(&workdir.to_string_lossy()),
                    env_prefix,
                    screen_cmd,
                )
            };

            let mut kubectl = Command::new("kubectl");
            kubectl.args(["--context", context]);
            kubectl.args(["--namespace", namespace]);
            kubectl.args(["exec", "-it"]);
            kubectl.arg(&result.container_id.0);
            kubectl.args(["--", "sh", "-c", &wrapper]);

            trace!("total claude startup: {:?}", t_total.elapsed());
            kubectl.status()?
        }

        Host::Localhost | Host::Ssh { .. } => {
            let docker_socket = result
                .docker_socket
                .as_ref()
                .context("docker_socket is required for Docker hosts")?;
            let docker_host = format!("unix://{}", docker_socket.display());

            let mut docker_cmd = Command::new("docker");
            docker_cmd.args(["-H", &docker_host]);
            docker_cmd.arg("exec");
            docker_cmd.args(["--user", &result.user]);
            docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);

            for (key, value) in &merged_env {
                docker_cmd.args(["-e", &format!("{}={}", key, value)]);
            }

            docker_cmd.args(["-it"]);
            docker_cmd.arg(&result.container_id.0);

            if screen_state.session_exists {
                // Reattach to existing session
                docker_cmd.args([
                    SCREEN_WRAPPER_PATH,
                    "-c",
                    SCREENRC_PATH,
                    "-U",
                    "-d",
                    "-R",
                    "claude",
                ]);
            } else {
                // Create new screen session running claude
                docker_cmd.args([
                    SCREEN_WRAPPER_PATH,
                    "-c",
                    SCREENRC_PATH,
                    "-U",
                    "-S",
                    "claude",
                    "--",
                    "claude",
                ]);
                if !skip_permissions_hook && !cmd.no_dangerously_skip_permissions {
                    docker_cmd.arg("--dangerously-skip-permissions");
                }
                docker_cmd.args(&cmd.args);
            }

            trace!("total claude startup: {:?}", t_total.elapsed());
            docker_cmd.status()?
        }
    };

    if !status.success() {
        bail!("exec exited with status {}", status);
    }

    Ok(())
}
