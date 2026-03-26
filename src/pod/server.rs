//! HTTP server that runs inside containers as the devcontainer user.
//!
//! Started via `rumpel container-serve` after the binary is copied into the container.
//! Listens on 127.0.0.1:7890 and implements filesystem, git, environment, and command
//! execution operations in Rust instead of composing shell scripts via docker exec.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::types::*;
use crate::async_runtime::block_on;

pub const DEFAULT_PORT: u16 = 7890;
pub const TOKEN_FILE: &str = "/opt/rumpelpod/server-token";
/// In-container path for the SSH agent socket served by the relay.
pub const SSH_AGENT_SOCK_PATH: &str = "/tmp/rumpelpod-ssh-agent/agent.sock";

/// Configuration for relaying SSH agent connections back to the host.
#[derive(Clone)]
pub struct SshRelayConfig {
    /// Base URL of the git HTTP server (reachable via tunnel).
    pub url: String,
    /// Bearer token for authenticating to the git HTTP server.
    pub token: String,
}

/// Shared state for the in-container HTTP server.
#[derive(Clone)]
pub struct PodServerState {
    pub pty_sessions: super::pty::PtySessions,
    pub token: String,
    pub ssh_relay: std::sync::Arc<tokio::sync::Mutex<Option<SshRelayConfig>>>,
    /// Repository path inside the container, set after the first /enter call.
    pub repo_path: std::sync::Arc<tokio::sync::Mutex<Option<PathBuf>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub fn run_container_server(port: u16, token: String) -> ! {
    // Ensure identity env vars match the running user so child
    // processes (shell profile scripts, git) see the right values.
    // Docker exec does not always propagate these.
    if let Some(user) = nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
    {
        let home = user.dir.to_string_lossy();
        std::env::set_var("HOME", &*home);
        std::env::set_var("USER", &user.name);
        std::env::set_var("LOGNAME", &user.name);
    }

    let state = PodServerState {
        pty_sessions: super::pty::PtySessions::new(),
        token: token.clone(),
        ssh_relay: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        repo_path: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
    };

    // POST routes require bearer token authentication
    let authenticated_routes = Router::new()
        .route("/enter", post(enter_handler))
        .route("/write-home-files", post(write_home_files_handler))
        .route("/fs/read", post(fs_read_handler))
        .route("/fs/write", post(fs_write_handler))
        .route("/fs/stat", post(fs_stat_handler))
        .route("/git/snapshot", post(git_snapshot_handler))
        .route("/git/apply-patch", post(git_apply_patch_handler))
        .route("/cp", get(cp_download_handler).post(cp_upload_handler))
        .route("/run", post(run_handler))
        .route("/events", get(events_handler))
        .route("/claude", any(super::pty::claude_session_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            token.clone(),
            require_bearer_token,
        ));

    let app = Router::new()
        .route("/health", get(health_handler))
        .merge(authenticated_routes)
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::decompression::RequestDecompressionLayer::new());

    block_on(async {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("failed to bind container server port");

        // Persist token so the daemon can recover it after restart
        std::fs::write(TOKEN_FILE, &token).expect("failed to write token file");

        axum::serve(listener, app).await.unwrap();
    });

    unreachable!("container server exited")
}

/// Middleware that rejects requests without a valid Bearer token.
async fn require_bearer_token(
    axum::extract::State(expected): axum::extract::State<String>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth {
        Some(value) if value == format!("Bearer {expected}") => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ok_json<T: Serialize>(val: T) -> Result<Json<T>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Json(val))
}

fn err_json(e: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!("{e:#}"),
        }),
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Events (SSE)
// ---------------------------------------------------------------------------

/// Format a single SSE event.
fn sse_event(event_type: &str, data: &str) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}

/// SSE endpoint the daemon connects to while a pod is running.
///
/// On each new connection the pod pushes all local branches to the
/// gateway -- recovering any pushes that failed while the daemon was
/// disconnected.  After the initial push a `state` event is sent
/// (currently empty; will carry pod state in the future), followed by
/// periodic keepalives.
async fn events_handler(State(state): State<PodServerState>) -> Response {
    let repo_path = match state.repo_path.lock().await.clone() {
        Some(p) => p,
        None => {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&ErrorResponse {
                        error: "pod not initialized (enter not called)".to_string(),
                    })
                    .expect("ErrorResponse is always serializable"),
                ))
                .expect("building response never fails");
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    tokio::task::spawn_blocking(move || {
        // Push all local branches to the gateway.  Best-effort: the
        // tunnel may not be fully up yet on the very first connection.
        match Command::new("git")
            .args(["push", "rumpelpod", "--force", "--quiet"])
            .current_dir(&repo_path)
            .env("GIT_HTTP_LOW_SPEED_LIMIT", "1")
            .env("GIT_HTTP_LOW_SPEED_TIME", "10")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let status = output.status;
                eprintln!("events: git push rumpelpod exited {status}: {stderr}");
            }
            Err(e) => {
                eprintln!("events: git push rumpelpod failed: {e}");
            }
            Ok(_) => {}
        }

        if tx.blocking_send(sse_event("state", "{}")).is_err() {
            return;
        }

        loop {
            std::thread::sleep(Duration::from_secs(30));
            if tx.blocking_send(sse_event("keepalive", "{}")).is_err() {
                return;
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let stream = tokio_stream::StreamExt::map(stream, Ok::<_, std::convert::Infallible>);

    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("building response never fails")
}

// ---------------------------------------------------------------------------
// Enter
// ---------------------------------------------------------------------------

async fn enter_handler(
    State(state): State<PodServerState>,
    Json(req): Json<EnterRequest>,
) -> Result<Json<EnterResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Cloned before req is moved into the blocking task.
    let ssh_url = req.base_url.clone();
    let ssh_token = req.token.clone();
    let repo_path = req.repo_path.clone();

    let result = tokio::task::spawn_blocking(move || enter_impl(req))
        .await
        .expect("enter_impl panicked");

    if result.is_ok() {
        *state.repo_path.lock().await = Some(repo_path);
    }

    setup_ssh_relay(&state, &ssh_url, &ssh_token)
        .await
        .map_err(err_json)?;

    match result {
        Ok(resp) => ok_json(resp),
        Err(e) => Err(err_json(e)),
    }
}

async fn setup_ssh_relay(state: &PodServerState, url: &str, token: &str) -> Result<()> {
    let config = SshRelayConfig {
        url: url.to_string(),
        token: token.to_string(),
    };

    let sock_path = Path::new(SSH_AGENT_SOCK_PATH);
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).context("creating ssh-agent socket directory")?;
    }
    if sock_path.exists() {
        if let Err(e) = std::fs::remove_file(sock_path) {
            eprintln!("warning: failed to remove stale ssh-agent socket: {e}");
        }
    }

    *state.ssh_relay.lock().await = Some(config);

    let relay_for_task = state.ssh_relay.clone();
    tokio::spawn(async move {
        if let Err(e) = run_ssh_agent_listener(relay_for_task).await {
            eprintln!("ssh-agent relay listener failed: {e:#}");
        }
    });

    Ok(())
}

fn enter_impl(req: EnterRequest) -> Result<EnterResponse> {
    let git_http_url = format!("{}/gateway.git", req.base_url);

    // -- 1. Ensure repo exists -----------------------------------------------
    let git_dir = req.repo_path.join(".git");
    match std::fs::metadata(&git_dir) {
        Ok(meta) if meta.is_dir() => {
            // Repo exists.  If our hook is missing this is the first entry
            // after the image was built -- sanitize to recover from any
            // broken state left by the build.
            let hook_path = req.repo_path.join(".git/hooks/reference-transaction");
            match std::fs::metadata(&hook_path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    sanitize_impl(&req.repo_path)?;
                }
                Err(e) => {
                    let path = hook_path.display();
                    return Err(anyhow::anyhow!("checking hook {path}: {e}"));
                }
            }
        }
        Ok(_) => {
            let path = git_dir.display();
            return Err(anyhow::anyhow!("{path} exists but is not a directory"));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Clone the repo from the git HTTP bridge.
            if let Some(parent) = req.repo_path.parent() {
                std::fs::create_dir_all(parent).context("creating parent directories")?;
            }
            clone_repo(&git_http_url, &req.repo_path, &req.token)?;
        }
        Err(e) => {
            let path = git_dir.display();
            return Err(anyhow::anyhow!("checking {path}: {e}"));
        }
    }

    // -- 2. Configure git remotes, hooks, branches ---------------------------
    setup_git_impl(&GitSetupRequest {
        repo_path: req.repo_path.clone(),
        url: git_http_url,
        token: req.token.clone(),
        pod_name: req.pod_name.clone(),
        host_branch: req.host_branch,
        git_identity: req.git_identity,
    })?;

    // -- 3. Set up submodules ------------------------------------------------
    setup_submodules_impl(&GitSetupSubmodulesRequest {
        repo_path: req.repo_path.clone(),
        submodules: req.submodules,
        base_url: req.base_url,
        token: req.token,
        pod_name: req.pod_name,
        is_first_entry: req.is_first_entry,
    })?;

    // -- 4. Probe user environment -------------------------------------------
    let probed_env = match req.shell_flags {
        Some(ref flags) => probe_env_impl(flags).unwrap_or_else(|e| {
            eprintln!("userEnvProbe failed: {e}");
            HashMap::new()
        }),
        None => HashMap::new(),
    };

    // -- 5. Collect user info ------------------------------------------------
    let user_info = get_user_info()?;

    Ok(EnterResponse {
        user_info,
        probed_env,
    })
}

/// Clone a repo from the git HTTP bridge with auth, including LFS.
fn clone_repo(url: &str, dest: &Path, token: &str) -> Result<()> {
    let auth_header = format!("Authorization: Bearer {token}");
    let config_arg = format!("http.extraHeader={auth_header}");
    let dest_str = dest.to_string_lossy();
    run_git_command(&["clone", "--config", &config_arg, url, &dest_str], None)?;

    // Try to set up git-lfs; skip if not available
    let lfs_installed = run_git_command(&["lfs", "install", "--local"], Some(dest)).is_ok();
    if lfs_installed {
        run_git_command(&["lfs", "pull"], Some(dest)).context("git lfs pull failed")?;
    }

    Ok(())
}

/// Look up the server's own user info (uid, home, shell).
fn get_user_info() -> Result<UserInfoResponse> {
    let uid = nix::unistd::getuid();
    let user = nix::unistd::User::from_uid(uid)
        .with_context(|| format!("looking up uid {uid}"))?
        .with_context(|| format!("uid {uid} not found in passwd"))?;
    Ok(UserInfoResponse {
        home: user.dir.to_string_lossy().to_string(),
        shell: user.shell.to_string_lossy().to_string(),
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
    })
}

// ---------------------------------------------------------------------------
// Write home files
// ---------------------------------------------------------------------------

async fn write_home_files_handler(
    Json(req): Json<WriteHomeFilesRequest>,
) -> Result<Json<WriteHomeFilesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = tokio::task::spawn_blocking(move || write_home_files_impl(req))
        .await
        .expect("write_home_files_impl panicked");
    match result {
        Ok(resp) => ok_json(resp),
        Err(e) => Err(err_json(e)),
    }
}

fn write_home_files_impl(req: WriteHomeFilesRequest) -> Result<WriteHomeFilesResponse> {
    let user_info = get_user_info()?;
    let home = Path::new(&user_info.home);

    // Write individual files
    for entry in &req.files {
        let dest = home.join(&entry.path);
        if entry.create_parents {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    let p = parent.display();
                    format!("creating parent dirs for {p}")
                })?;
            }
        }
        let content = base64_decode(&entry.content)?;
        let dest_display = dest.display();
        std::fs::write(&dest, &content).with_context(|| format!("writing {dest_display}"))?;
    }

    // Extract tar archives
    for extract in &req.tar_extracts {
        let dest = home.join(&extract.dest);
        let dest_display = dest.display();
        std::fs::create_dir_all(&dest).with_context(|| format!("creating {dest_display}"))?;

        let data = base64_decode(&extract.data)?;
        let mut archive = tar::Archive::new(data.as_slice());
        for entry in archive
            .entries()
            .with_context(|| format!("reading tar entries for {dest_display}"))?
        {
            let mut entry =
                entry.with_context(|| format!("reading tar entry for {dest_display}"))?;
            // Strip the leading "./" that tar -c . produces
            let path = entry.path()?.into_owned();
            let path = path.strip_prefix(".").unwrap_or(&path);
            if path.as_os_str().is_empty() {
                continue;
            }
            let target = dest.join(path);
            if entry.header().entry_type().is_dir() {
                std::fs::create_dir_all(&target)?;
            } else {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                entry.unpack(&target).with_context(|| {
                    let t = target.display();
                    format!("extracting to {t}")
                })?;
            }
        }
    }

    Ok(WriteHomeFilesResponse {
        home: user_info.home,
    })
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

async fn fs_read_handler(
    Json(req): Json<FsReadRequest>,
) -> Result<Json<FsReadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let path = req.path.display();
    let data =
        std::fs::read(&req.path).map_err(|e| err_json(anyhow::anyhow!("reading {path}: {e}")))?;
    ok_json(FsReadResponse {
        content: base64_encode(&data),
    })
}

async fn fs_write_handler(
    Json(req): Json<FsWriteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let content = base64_decode(&req.content).map_err(err_json)?;

    if req.create_parents {
        if let Some(parent) = req.path.parent() {
            let path = req.path.display();
            std::fs::create_dir_all(parent)
                .map_err(|e| err_json(anyhow::anyhow!("creating parent dirs for {path}: {e}")))?;
        }
    }

    let path = req.path.display();
    std::fs::write(&req.path, &content)
        .map_err(|e| err_json(anyhow::anyhow!("writing {path}: {e}")))?;

    ok_json(serde_json::json!({}))
}

async fn fs_stat_handler(
    Json(req): Json<FsStatRequest>,
) -> Result<Json<FsStatResponse>, (StatusCode, Json<ErrorResponse>)> {
    match std::fs::metadata(&req.path) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt;
            let owner = nix::unistd::Uid::from_raw(meta.uid());
            let owner_name = nix::unistd::User::from_uid(owner)
                .ok()
                .flatten()
                .map(|u| u.name);
            ok_json(FsStatResponse {
                exists: true,
                is_dir: meta.is_dir(),
                is_file: meta.is_file(),
                owner: owner_name,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ok_json(FsStatResponse {
            exists: false,
            is_dir: false,
            is_file: false,
            owner: None,
        }),
        Err(e) => {
            let path = req.path.display();
            Err(err_json(anyhow::anyhow!("stat {path}: {e}")))
        }
    }
}

fn setup_git_impl(req: &GitSetupRequest) -> Result<()> {
    let repo_path = &req.repo_path;
    let pod_name = &req.pod_name;
    let token = &req.token;
    let push_refspec = format!("+refs/heads/*:refs/heads/rumpelpod/*@{pod_name}");

    run_git_command(
        &[
            "config",
            "http.extraHeader",
            &format!("Authorization: Bearer {token}"),
        ],
        Some(repo_path),
    )?;

    // Set up host remote
    if run_git_command(&["remote", "add", "host", &req.url], Some(repo_path)).is_err() {
        run_git_command(&["remote", "set-url", "host", &req.url], Some(repo_path))?;
    }
    run_git_command(
        &[
            "config",
            "remote.host.fetch",
            "+refs/heads/host/*:refs/remotes/host/*",
        ],
        Some(repo_path),
    )?;
    run_git_command(
        &["config", "remote.host.pushurl", "PUSH_DISABLED"],
        Some(repo_path),
    )?;

    // Set up rumpelpod remote
    if run_git_command(&["remote", "add", "rumpelpod", &req.url], Some(repo_path)).is_err() {
        run_git_command(
            &["remote", "set-url", "rumpelpod", &req.url],
            Some(repo_path),
        )?;
    }
    run_git_command(
        &["config", "remote.rumpelpod.push", &push_refspec],
        Some(repo_path),
    )?;
    run_git_command(
        &[
            "config",
            "remote.rumpelpod.fetch",
            "+refs/heads/rumpelpod/*:refs/remotes/rumpelpod/*",
        ],
        Some(repo_path),
    )?;

    // Fetch from host
    run_git_command(&["fetch", "host"], Some(repo_path))?;

    // Install reference-transaction hook; detect first entry from return value
    let is_first_entry = install_hook_impl(repo_path)?;

    if is_first_entry {
        let branch_name = &req.pod_name;

        let branch_exists = run_git_command(
            &[
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch_name}"),
            ],
            Some(repo_path),
        )
        .is_ok();

        if branch_exists {
            run_git_command(
                &["branch", "-f", "--no-track", branch_name, "host/HEAD"],
                Some(repo_path),
            )
            .with_context(|| format!("resetting branch '{branch_name}' to host/HEAD"))?;
        } else {
            run_git_command(
                &["branch", "--no-track", branch_name, "host/HEAD"],
                Some(repo_path),
            )
            .with_context(|| format!("creating branch '{branch_name}'"))?;
        }

        run_git_command(&["checkout", branch_name], Some(repo_path))
            .with_context(|| format!("checking out branch '{branch_name}'"))?;

        if let Some(ref host_branch) = req.host_branch {
            let upstream = format!("host/{host_branch}");
            run_git_command(
                &["branch", "--set-upstream-to", &upstream, branch_name],
                Some(repo_path),
            )
            .with_context(|| format!("setting upstream of '{branch_name}' to '{upstream}'"))?;
        }
    }

    // Write host git identity into the pod's .git/config
    if let Some(ref identity) = req.git_identity {
        if let Some(ref name) = identity.name {
            run_git_command(&["config", "user.name", name], Some(repo_path))?;
        }
        if let Some(ref email) = identity.email {
            run_git_command(&["config", "user.email", email], Some(repo_path))?;
        }
    }

    Ok(())
}

/// Hook content that delegates to the rumpel binary inside the container.
const POD_REFERENCE_TRANSACTION_HOOK: &str = "\
#!/bin/sh\n\
# Installed by rumpelpod (pod)\n\
exec /opt/rumpelpod/bin/rumpel git-hook reference-transaction \"$@\"\n";

const HOOK_SIGNATURE: &str = "Installed by rumpelpod (pod)";

/// Install the reference-transaction hook. Returns true on first install.
///
/// Strips any host-side hook lines first (they reference binaries that
/// do not exist in the container), then appends the pod hook.
fn install_hook_impl(repo_path: &Path) -> Result<bool> {
    let hooks_dir = repo_path.join(".git/hooks");
    let hooks_dir_display = hooks_dir.display();
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("creating hooks dir {hooks_dir_display}"))?;

    let hook_path = hooks_dir.join("reference-transaction");

    let existing = std::fs::read_to_string(&hook_path).ok();

    let final_hook = match existing {
        Some(ref content) if content.contains(HOOK_SIGNATURE) => {
            return Ok(false);
        }
        Some(ref content) => {
            let cleaned = crate::gateway::strip_host_hooks(content);
            let trimmed = cleaned.trim_end();
            format!("{trimmed}\n\n{POD_REFERENCE_TRANSACTION_HOOK}")
        }
        None => POD_REFERENCE_TRANSACTION_HOOK.to_string(),
    };

    let hook_path_display = hook_path.display();
    std::fs::write(&hook_path, &final_hook)
        .with_context(|| format!("writing hook {hook_path_display}"))?;

    let mut perms = std::fs::metadata(&hook_path)
        .context("reading hook metadata")?
        .permissions();
    perms.set_mode(perms.mode() | 0o111);
    std::fs::set_permissions(&hook_path, perms).context("chmod +x hook")?;

    Ok(true)
}

fn setup_submodules_impl(req: &GitSetupSubmodulesRequest) -> Result<()> {
    if req.submodules.is_empty() {
        return Ok(());
    }

    let container_repo_path = &req.repo_path;

    // Clone submodules on first entry
    if req.is_first_entry {
        for sub in &req.submodules {
            // Derive the parent worktree by stripping `path` (relative to
            // the immediate parent) from `displaypath` (relative to the
            // top-level repo).  Using displaypath.parent() would be wrong
            // for submodules whose path contains slashes (e.g.
            // "libs/child-sub").
            let parent_prefix = sub
                .displaypath
                .strip_suffix(&sub.path)
                .unwrap_or("")
                .trim_end_matches('/');
            let parent_dir = if parent_prefix.is_empty() {
                container_repo_path.to_path_buf()
            } else {
                container_repo_path.join(parent_prefix)
            };

            let base_url = &req.base_url;
            let displaypath = &sub.displaypath;
            let sub_url = format!("{base_url}/submodules/{displaypath}/gateway.git");

            run_git_command(&["submodule", "init", &sub.path], Some(&parent_dir))?;
            let sub_name = &sub.name;
            let sub_config_key = format!("submodule.{sub_name}.url");
            run_git_command(&["config", &sub_config_key, &sub_url], Some(&parent_dir))?;
            let token = &req.token;
            let auth_header = format!("http.extraHeader=Authorization: Bearer {token}");
            run_git_command(
                &["-c", &auth_header, "submodule", "update", &sub.path],
                Some(&parent_dir),
            )?;
        }
    }

    // Configure each submodule's remotes, hooks, and branch
    for sub in &req.submodules {
        let sub_path = container_repo_path.join(&sub.displaypath);
        let base_url = &req.base_url;
        let displaypath = &sub.displaypath;
        let sub_url = format!("{base_url}/submodules/{displaypath}/gateway.git");
        let pod_name = &req.pod_name;
        let push_refspec = format!("+refs/heads/*:refs/heads/rumpelpod/*@{pod_name}");

        // Resolve the git dir (submodules use gitlink files)
        let git_dir_output = git_command()
            .args(["rev-parse", "--git-dir"])
            .current_dir(&sub_path)
            .output()
            .context("resolving submodule git dir")?;
        let git_dir_relative = String::from_utf8_lossy(&git_dir_output.stdout)
            .trim()
            .to_string();
        let git_dir = if Path::new(&git_dir_relative).is_absolute() {
            PathBuf::from(&git_dir_relative)
        } else {
            sub_path.join(&git_dir_relative)
        };

        let token = &req.token;
        run_git_command(
            &[
                "config",
                "http.extraHeader",
                &format!("Authorization: Bearer {token}"),
            ],
            Some(&sub_path),
        )?;

        if run_git_command(&["remote", "add", "host", &sub_url], Some(&sub_path)).is_err() {
            run_git_command(&["remote", "set-url", "host", &sub_url], Some(&sub_path))?;
        }
        run_git_command(
            &[
                "config",
                "remote.host.fetch",
                "+refs/heads/host/*:refs/remotes/host/*",
            ],
            Some(&sub_path),
        )?;
        run_git_command(
            &["config", "remote.host.pushurl", "PUSH_DISABLED"],
            Some(&sub_path),
        )?;

        if run_git_command(&["remote", "add", "rumpelpod", &sub_url], Some(&sub_path)).is_err() {
            run_git_command(
                &["remote", "set-url", "rumpelpod", &sub_url],
                Some(&sub_path),
            )?;
        }
        run_git_command(
            &["config", "remote.rumpelpod.push", &push_refspec],
            Some(&sub_path),
        )?;

        run_git_command(&["fetch", "host"], Some(&sub_path))
            .with_context(|| format!("fetching host in submodule '{displaypath}'"))?;

        // Install hook in submodule
        let hooks_dir = git_dir.join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        let hook_path = hooks_dir.join("reference-transaction");

        let existing = std::fs::read_to_string(&hook_path).ok();
        let needs_install = existing
            .as_ref()
            .is_none_or(|c| !c.contains(HOOK_SIGNATURE));

        if needs_install {
            let content = match existing {
                Some(ref c) => {
                    let cleaned = crate::gateway::strip_host_hooks(c);
                    let trimmed = cleaned.trim_end();
                    format!("{trimmed}\n\n{POD_REFERENCE_TRANSACTION_HOOK}")
                }
                None => POD_REFERENCE_TRANSACTION_HOOK.to_string(),
            };
            std::fs::write(&hook_path, &content)?;
            let mut perms = std::fs::metadata(&hook_path)?.permissions();
            perms.set_mode(perms.mode() | 0o111);
            std::fs::set_permissions(&hook_path, perms)?;
        }

        // Create and checkout pod branch on first entry
        if req.is_first_entry {
            let branch_name = &req.pod_name;
            let branch_exists = run_git_command(
                &[
                    "show-ref",
                    "--verify",
                    "--quiet",
                    &format!("refs/heads/{branch_name}"),
                ],
                Some(&sub_path),
            )
            .is_ok();

            if branch_exists {
                run_git_command(
                    &["branch", "-f", "--no-track", branch_name, "host/HEAD"],
                    Some(&sub_path),
                )?;
            } else {
                run_git_command(
                    &["branch", "--no-track", branch_name, "host/HEAD"],
                    Some(&sub_path),
                )?;
            }
            run_git_command(&["checkout", branch_name], Some(&sub_path))?;
        }
    }

    Ok(())
}

fn sanitize_impl(repo_path: &Path) -> Result<()> {
    // Abort any in-progress operations
    for op in &[
        &["merge", "--abort"][..],
        &["rebase", "--abort"],
        &["cherry-pick", "--abort"],
        &["revert", "--abort"],
        &["am", "--abort"],
        &["bisect", "reset"],
    ] {
        let _ = git_command()
            .args(*op)
            .current_dir(repo_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Check if HEAD is valid
    let has_head = git_command()
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repo_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if has_head {
        run_git_command(&["reset", "--hard", "HEAD"], Some(repo_path))?;
    } else {
        let _ = git_command()
            .args(["rm", "--cached", "-r", "."])
            .current_dir(repo_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    run_git_command(&["clean", "-fd"], Some(repo_path))?;
    Ok(())
}

async fn git_snapshot_handler(
    Json(req): Json<GitSnapshotRequest>,
) -> Result<Json<GitSnapshotResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = snapshot_impl(&req.repo_path);
    match result {
        Ok(patch) => ok_json(GitSnapshotResponse {
            patch: patch.map(|p| base64_encode(&p)),
        }),
        Err(e) => Err(err_json(e)),
    }
}

fn snapshot_impl(repo_path: &Path) -> Result<Option<Vec<u8>>> {
    run_git_command(&["add", "-A"], Some(repo_path))?;

    let output = git_command()
        .args(["diff", "--binary", "--cached"])
        .current_dir(repo_path)
        .output()
        .context("git diff")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("git diff failed: {stderr}"));
    }

    if output.stdout.is_empty() {
        Ok(None)
    } else {
        Ok(Some(output.stdout))
    }
}

async fn git_apply_patch_handler(
    Json(req): Json<GitApplyPatchRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let result = apply_patch_impl(&req);
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn apply_patch_impl(req: &GitApplyPatchRequest) -> Result<()> {
    let patch = base64_decode(&req.patch)?;

    // Remove files that the patch creates (they may already exist from the image)
    for file in &req.created_files {
        let _ = std::fs::remove_file(req.repo_path.join(file));
    }

    // Apply patch via stdin
    let mut child = git_command()
        .args(["apply", "-"])
        .current_dir(&req.repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning git apply")?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(&patch)
            .context("writing patch to git apply")?;
    }

    let output = child.wait_with_output().context("waiting for git apply")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("git apply failed: {stderr}"));
    }

    // Best-effort submodule sync
    let _ = git_command()
        .args(["submodule", "update", "--recursive"])
        .current_dir(&req.repo_path)
        .status();

    Ok(())
}

fn probe_env_impl(shell_flags: &str) -> Result<HashMap<String, String>> {
    // Check if bash is available
    let has_bash = Command::new("which")
        .arg("bash")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());

    if !has_bash {
        return Ok(HashMap::new());
    }

    // Get base environment
    let base_output = Command::new("env")
        .arg("-0")
        .output()
        .context("getting base env")?;
    let base = parse_null_delimited_env(&base_output.stdout);

    // Get probed environment via bash with shell flags
    let probed_output = Command::new("bash")
        .arg(shell_flags)
        .arg("env -0")
        .output()
        .context("probing env")?;
    let probed = parse_null_delimited_env(&probed_output.stdout);

    let skip = ["_", "SHLVL", "BASH_EXECUTION_STRING"];
    Ok(probed
        .into_iter()
        .filter(|(key, value)| !skip.contains(&key.as_str()) && base.get(key) != Some(value))
        .collect())
}

fn parse_null_delimited_env(data: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(data);
    let mut map = HashMap::new();
    for entry in text.split('\0') {
        if let Some((key, value)) = entry.split_once('=') {
            if !key.is_empty() {
                map.insert(key.to_string(), value.to_string());
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Streaming helpers for tar transfer
// ---------------------------------------------------------------------------

/// Adapter: sends written bytes as chunks through a tokio mpsc channel.
/// Used to stream tar output into an HTTP response body.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes = axum::body::Bytes::copy_from_slice(buf);
        self.tx
            .blocking_send(Ok(bytes))
            .map_err(|_| std::io::Error::other("receiver dropped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Copy handlers
// ---------------------------------------------------------------------------

async fn cp_download_handler(
    axum::extract::Query(req): axum::extract::Query<CpDownloadRequest>,
) -> Result<axum::response::Response, (StatusCode, Json<ErrorResponse>)> {
    // Validate the path before starting the stream, so we can return
    // a proper error response for the most common failure (not found).
    let check_path = req.path.clone();
    let meta = tokio::task::spawn_blocking(move || std::fs::symlink_metadata(&check_path))
        .await
        .expect("stat panicked");
    if let Err(e) = meta {
        let path_display = req.path.display();
        return Err(err_json(anyhow::anyhow!("stat {path_display}: {e}")));
    }

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let writer = ChannelWriter { tx };
        if let Err(e) = cp_download_impl(req, writer) {
            eprintln!("cp_download error: {e:#}");
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Ok(axum::response::Response::builder()
        .header("Content-Type", "application/x-tar")
        .body(axum::body::Body::from_stream(stream))
        .unwrap())
}

fn cp_download_impl(req: CpDownloadRequest, writer: impl std::io::Write) -> Result<()> {
    let path = &req.path;
    let path_display = path.display();

    let mut archive = tar::Builder::new(writer);
    archive.follow_symlinks(req.follow_symlinks);

    let meta = std::fs::symlink_metadata(path).with_context(|| format!("stat {path_display}"))?;

    let name = path
        .file_name()
        .with_context(|| format!("no file name in {path_display}"))?;
    let wrapper_name = Path::new("_").join(name);

    if meta.is_dir() {
        archive
            .append_dir_all(&wrapper_name, path)
            .with_context(|| format!("archiving directory {path_display}"))?;
    } else {
        archive
            .append_path_with_name(path, &wrapper_name)
            .with_context(|| format!("archiving file {path_display}"))?;
    }

    archive
        .into_inner()
        .with_context(|| format!("finalizing tar for {path_display}"))?;
    Ok(())
}

async fn cp_upload_handler(
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let path = headers
        .get("X-Path")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err_json(anyhow::anyhow!("missing X-Path header")))?;
    let path = PathBuf::from(path);

    use tokio_stream::StreamExt;
    let stream = body
        .into_data_stream()
        .map(|result| result.map_err(std::io::Error::other));
    let async_reader = tokio_util::io::StreamReader::new(stream);
    let sync_reader = tokio_util::io::SyncIoBridge::new(async_reader);

    let result = tokio::task::spawn_blocking(move || cp_upload_impl(&path, sync_reader))
        .await
        .expect("cp_upload_impl panicked");
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn cp_upload_impl(path: &Path, reader: impl std::io::Read) -> Result<()> {
    let path_display = path.display();
    // Match standard cp: when the destination is an existing directory,
    // place the content inside it rather than overwriting it.
    let dest_is_dir = path.is_dir();

    let mut archive = tar::Archive::new(reader);
    for entry in archive
        .entries()
        .with_context(|| format!("reading tar entries for {path_display}"))?
    {
        let mut entry = entry.with_context(|| format!("reading tar entry for {path_display}"))?;
        let entry_path = entry.path().context("reading entry path")?.into_owned();

        let relative = match entry_path.strip_prefix("_") {
            Ok(r) if !r.as_os_str().is_empty() => r,
            _ => continue,
        };

        let target = if dest_is_dir {
            path.join(relative)
        } else {
            let mut components = relative.components();
            components.next();
            let rest: PathBuf = components.collect();

            if rest.as_os_str().is_empty() {
                path.to_path_buf()
            } else {
                path.join(&rest)
            }
        };

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&target).with_context(|| format!("creating {path_display}"))?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent for {path_display}"))?;
            }
            let target_display = target.display();
            entry
                .unpack(&target)
                .with_context(|| format!("extracting to {target_display}"))?;
        }
    }

    Ok(())
}

async fn run_handler(
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = tokio::task::spawn_blocking(|| run_impl(req))
        .await
        .expect("run_impl panicked");
    match result {
        Ok(resp) => ok_json(resp),
        Err(e) => Err(err_json(e)),
    }
}

fn run_impl(req: RunRequest) -> Result<RunResponse> {
    use std::io::Read;

    if req.cmd.is_empty() {
        return Err(anyhow::anyhow!("empty command"));
    }

    let mut cmd = Command::new(&req.cmd[0]);
    cmd.args(&req.cmd[1..]);

    if let Some(ref workdir) = req.workdir {
        cmd.current_dir(workdir);
    }

    for env_str in &req.env {
        if let Some((key, value)) = env_str.split_once('=') {
            cmd.env(key, value);
        }
    }

    let has_stdin = req.stdin.is_some();
    if has_stdin {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawning command")?;

    if let Some(ref stdin_b64) = req.stdin {
        let data = base64_decode(stdin_b64)?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(&data).context("writing stdin")?;
        }
    }

    // Drain stdout and stderr in background threads to prevent deadlock
    // when the child produces more output than the OS pipe buffer (~64KB).
    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut reader = child_stdout;
        let _ = reader.read_to_end(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut reader = child_stderr;
        let _ = reader.read_to_end(&mut buf);
        buf
    });

    let timeout = req.timeout_secs.map(std::time::Duration::from_secs);

    let (status, timed_out) = if let Some(dur) = timeout {
        let start = std::time::Instant::now();
        loop {
            match child.try_wait()? {
                Some(status) => break (status, false),
                None => {
                    if start.elapsed() >= dur {
                        let _ = child.kill();
                        let status = child.wait().context("waiting after kill")?;
                        break (status, true);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    } else {
        let status = child.wait().context("waiting for command")?;
        (status, false)
    };

    let stdout = stdout_thread.join().expect("stdout reader panicked");
    let stderr = stderr_thread.join().expect("stderr reader panicked");

    Ok(RunResponse {
        exit_code: if timed_out {
            -1
        } else {
            status.code().unwrap_or(-1)
        },
        stdout: base64_encode(&stdout),
        stderr: base64_encode(&stderr),
        timed_out,
    })
}

// ---------------------------------------------------------------------------
// SSH agent relay
// ---------------------------------------------------------------------------

/// Listen on the SSH_AUTH_SOCK Unix socket and relay each connection
/// to the host-side ssh-agent via WebSocket through the git HTTP server.
async fn run_ssh_agent_listener(
    relay: std::sync::Arc<tokio::sync::Mutex<Option<SshRelayConfig>>>,
) -> Result<()> {
    let sock_path = SSH_AGENT_SOCK_PATH;
    let listener = tokio::net::UnixListener::bind(sock_path)
        .with_context(|| format!("binding {sock_path}"))?;

    // Make the socket accessible to all users in the container.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o666))
            .context("chmod ssh-agent socket")?;
    }

    loop {
        let (stream, _) = listener.accept().await.context("accepting connection")?;
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_ssh_agent_connection(stream, relay).await {
                eprintln!("ssh-agent relay connection failed: {e:#}");
            }
        });
    }
}

/// Bridge a single SSH agent connection to the host via WebSocket.
async fn handle_ssh_agent_connection(
    stream: tokio::net::UnixStream,
    relay: std::sync::Arc<tokio::sync::Mutex<Option<SshRelayConfig>>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite;

    let config = relay
        .lock()
        .await
        .clone()
        .context("ssh-agent relay not configured (tunnel not ready yet?)")?;

    // Connect to the git HTTP server's /ssh-agent WebSocket endpoint.
    let ws_url = format!(
        "{}/ssh-agent",
        config
            .url
            .replace("http://", "ws://")
            .replace("https://", "wss://")
    );
    let ws_request = tungstenite::http::Request::builder()
        .uri(&ws_url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Host", "localhost")
        .body(())
        .context("building WebSocket request")?;

    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_request)
        .await
        .context("connecting to ssh-agent relay WebSocket")?;

    use futures_util::{SinkExt, StreamExt};

    let (mut ws_write, mut ws_read) = ws_stream.split();
    let (mut unix_read, mut unix_write) = tokio::io::split(stream);

    // Unix socket -> WebSocket (via channel, since we need select!)
    let (unix_tx, mut unix_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match unix_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if unix_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            ws_msg = ws_read.next() => {
                match ws_msg {
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        if unix_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            unix_data = unix_rx.recv() => {
                match unix_data {
                    Some(data) => {
                        if ws_write.send(tungstenite::Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    reader_task.abort();
    if let Err(e) = ws_write.send(tungstenite::Message::Close(None)).await {
        eprintln!("ssh-agent relay: failed to send close frame: {e}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Build a `git` Command. The server runs as the devcontainer user
/// who owns the repo, so no safe.directory override or uid switching
/// is needed.
fn git_command() -> Command {
    Command::new("git")
}

fn run_git_command(args: &[&str], workdir: Option<&Path>) -> Result<Vec<u8>> {
    let mut cmd = git_command();
    cmd.args(args);
    if let Some(dir) = workdir {
        cmd.current_dir(dir);
    }
    let output = cmd.output().context("running git command")?;
    if !output.status.success() {
        let subcmd = args.first().unwrap_or(&"");
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("git {subcmd} failed: {stderr}"));
    }
    Ok(output.stdout)
}
