use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use log::trace;

use crate::cli::ClaudeCommand;
use crate::config::load_toml_config;
use crate::daemon;
use crate::daemon::protocol::{
    ContainerId, Daemon, DaemonClient, EnsureClaudeConfigRequest, PodName,
};
use crate::enter::{launch_pod, load_and_resolve, merge_env, resolve_remote_env_via_pod};
use crate::git::get_repo_root;
use crate::pod::types::{base64_encode, HomeFileEntry};
use crate::pod::PodClient;
use crate::pty_attach;

const PTY_SESSION_NAME: &str = "claude";

pub fn claude(cmd: &ClaudeCommand) -> Result<()> {
    let t_total = Instant::now();

    let t = Instant::now();
    let repo_root = get_repo_root()?;
    let elapsed = t.elapsed();
    trace!("get_repo_root: {elapsed:?}");

    let host_override = cmd.host_args.resolve()?;

    let t = Instant::now();
    let toml_config = load_toml_config(&repo_root)?;
    let (devcontainer, _docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, host_override.clone())?;
    let elapsed = t.elapsed();
    trace!("load_and_resolve: {elapsed:?}");

    // CLI --no-dangerously-skip-permissions wins over the toml setting.
    let skip_permissions_hook = !cmd.no_dangerously_skip_permissions
        && (cmd.dangerously_skip_permissions_hook
            || toml_config.claude.dangerously_skip_permissions_hook);

    let workdir = devcontainer.container_repo_path(&repo_root);
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let t = Instant::now();
    let result = launch_pod(&cmd.name, host_override)?;
    let elapsed = t.elapsed();
    trace!("launch_pod: {elapsed:?}");

    // Copy Claude config into the container.
    let t = Instant::now();
    let config_result = {
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
        let elapsed = tc.elapsed();
        trace!("ensure_claude_config: {elapsed:?}");
        cfg_result
    };
    let elapsed = t.elapsed();
    trace!("config: {elapsed:?}");

    config_result?;

    // Resolve ${containerEnv:VAR} via the in-container HTTP server.
    let pod = crate::pod::PodClient::connect(&result.container_url, &result.container_token)?;
    let remote_env = resolve_remote_env_via_pod(&remote_env_map, &pod);
    let merged_env = merge_env(result.probed_env, remote_env);

    let mut env_strings: Vec<String> = merged_env.iter().map(|(k, v)| format!("{k}={v}")).collect();

    // Forward terminal capability vars from the host so the PTY child
    // matches the user's actual terminal. The defaults in pty.rs only
    // apply when these are truly absent (e.g. headless invocation).
    for var in ["TERM", "COLORTERM"] {
        if !merged_env.iter().any(|(k, _)| k == var) {
            if let Ok(val) = std::env::var(var) {
                env_strings.push(format!("{var}={val}"));
            }
        }
    }

    let mut claude_cmd = vec![crate::daemon::CLAUDE_CONTAINER_BIN.to_string()];
    if !skip_permissions_hook && !cmd.no_dangerously_skip_permissions {
        claude_cmd.push("--dangerously-skip-permissions".to_string());
    }
    claude_cmd.extend(cmd.args.clone());

    let workdir_str = workdir.to_string_lossy().to_string();

    let elapsed = t_total.elapsed();
    trace!("total claude startup: {elapsed:?}");

    let outcome = pty_attach::attach(
        &result.container_url,
        &result.container_token,
        pty_attach::SessionParams {
            name: PTY_SESSION_NAME.to_string(),
            cmd: claude_cmd,
            workdir: Some(workdir_str),
            env: env_strings,
        },
    )?;

    match outcome {
        pty_attach::AttachOutcome::Detached => {
            eprintln!("[detached from session]");
        }
        pty_attach::AttachOutcome::SessionEnded => {}
    }

    Ok(())
}

/// Copy only authentication credentials from the host into the pod.
///
/// Supports both OAuth (.credentials.json) and API keys (primaryApiKey
/// in .claude.json). Useful when host credentials have been refreshed
/// (e.g. token expiry) without needing to recreate the pod.
pub fn reauth(cmd: &ClaudeCommand) -> Result<()> {
    let host_override = cmd.host_args.resolve()?;
    let result = launch_pod(&cmd.name, host_override)?;
    let pod = PodClient::connect(&result.container_url, &result.container_token)?;

    let host_home = dirs::home_dir().context("could not determine home directory")?;

    let mut files: Vec<HomeFileEntry> = Vec::new();

    // .claude/.credentials.json -- OAuth tokens
    match std::fs::read(host_home.join(".claude/.credentials.json")) {
        Ok(data) => {
            files.push(HomeFileEntry {
                path: ".claude/.credentials.json".to_string(),
                content: base64_encode(&data),
                create_parents: true,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude/.credentials.json")),
    }

    // primaryApiKey -- read-modify-write on .claude.json
    match std::fs::read(host_home.join(".claude.json")) {
        Ok(host_data) => {
            let host_obj: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&host_data).context("parsing ~/.claude.json")?;
            if let Some(key) = host_obj.get("primaryApiKey") {
                // Write credentials first so we can read the container's
                // .claude.json to merge the API key into it.
                let resp = pod.write_home_files(files.clone(), vec![])?;
                let container_path = Path::new(&resp.home).join(".claude.json");
                let container_data = pod.fs_read(&container_path).unwrap_or_default();
                let mut container_obj: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_slice(&container_data).unwrap_or_default();
                container_obj.insert("primaryApiKey".to_string(), key.clone());
                let updated = serde_json::to_vec_pretty(&container_obj)
                    .context("serializing updated .claude.json")?;
                files.push(HomeFileEntry {
                    path: ".claude.json".to_string(),
                    content: base64_encode(&updated),
                    create_parents: false,
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::Error::from(e).context("reading ~/.claude.json")),
    }

    if !files.is_empty() {
        pod.write_home_files(files, vec![])?;
    }

    eprintln!("Authentication credentials updated.");
    Ok(())
}
