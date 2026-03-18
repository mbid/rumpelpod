//! HTTP server that runs inside containers to replace shell-scripted operations.
//!
//! Started via `rumpel container-serve` after the binary is copied into the container.
//! Listens on 0.0.0.0:7890 and implements filesystem, git, environment, and command
//! execution operations in Rust instead of composing shell scripts via docker exec.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use nix::unistd::{Uid, User};
use serde::{Deserialize, Serialize};

use super::types::*;
use crate::async_runtime::block_on;

pub const DEFAULT_PORT: u16 = 7890;
pub const TOKEN_FILE: &str = "/tmp/rumpelpod-server-token";

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub fn run_container_server(port: u16, token: String) -> ! {
    // POST routes require bearer token authentication
    let authenticated_routes = Router::new()
        .route("/fs/read", post(fs_read_handler))
        .route("/fs/write", post(fs_write_handler))
        .route("/fs/stat", post(fs_stat_handler))
        .route("/fs/mkdir", post(fs_mkdir_handler))
        .route("/fs/chown", post(fs_chown_handler))
        .route("/git/clone", post(git_clone_handler))
        .route("/git/setup", post(git_setup_handler))
        .route("/git/install-hook", post(git_install_hook_handler))
        .route("/git/setup-submodules", post(git_setup_submodules_handler))
        .route("/git/sanitize", post(git_sanitize_handler))
        .route("/git/snapshot", post(git_snapshot_handler))
        .route("/git/apply-patch", post(git_apply_patch_handler))
        .route("/env/user-info", post(env_user_info_handler))
        .route("/env/probe", post(env_probe_handler))
        .route("/cp", get(cp_download_handler).post(cp_upload_handler))
        .route("/run", post(run_handler))
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
// Helper: resolve user name to uid/gid
// ---------------------------------------------------------------------------

fn resolve_user(name: &str) -> Result<User> {
    User::from_name(name)?.with_context(|| format!("user '{name}' not found"))
}

fn chown_path(path: &Path, owner: &str) -> Result<()> {
    let user = resolve_user(owner)?;
    let path_display = path.display();
    nix::unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("chown {path_display} to {owner}"))
}

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
            if let Some(ref owner) = req.owner {
                // chown each ancestor that we may have created
                let mut p = parent;
                loop {
                    let _ = chown_path(p, owner);
                    match p.parent() {
                        Some(pp) if pp != p => p = pp,
                        _ => break,
                    }
                }
            }
        }
    }

    let path = req.path.display();
    std::fs::write(&req.path, &content)
        .map_err(|e| err_json(anyhow::anyhow!("writing {path}: {e}")))?;

    if let Some(ref owner) = req.owner {
        chown_path(&req.path, owner).map_err(err_json)?;
    }

    ok_json(serde_json::json!({}))
}

async fn fs_stat_handler(
    Json(req): Json<FsStatRequest>,
) -> Result<Json<FsStatResponse>, (StatusCode, Json<ErrorResponse>)> {
    match std::fs::metadata(&req.path) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt;
            let owner = Uid::from_raw(meta.uid());
            let owner_name = User::from_uid(owner).ok().flatten().map(|u| u.name);
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

async fn fs_mkdir_handler(
    Json(req): Json<FsMkdirRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let path = req.path.display();
    std::fs::create_dir_all(&req.path)
        .map_err(|e| err_json(anyhow::anyhow!("mkdir {path}: {e}")))?;

    if let Some(ref owner) = req.owner {
        chown_path(&req.path, owner).map_err(err_json)?;
    }

    ok_json(serde_json::json!({}))
}

async fn fs_chown_handler(
    Json(req): Json<FsChownRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user(&req.owner).map_err(err_json)?;
    let owner = &req.owner;
    for path in &req.paths {
        let path_display = path.display();
        nix::unistd::chown(path, Some(user.uid), Some(user.gid))
            .map_err(|e| err_json(anyhow::anyhow!("chown {path_display} to {owner}: {e}")))?;
    }
    ok_json(serde_json::json!({}))
}

async fn git_clone_handler(
    Json(req): Json<GitCloneRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let result = (|| -> Result<()> {
        let user = resolve_user_opt(&req.user)?;
        let u = user.as_ref();

        let mut args = vec!["clone".to_string()];

        if let Some(ref auth) = req.auth_header {
            args.push("--config".to_string());
            args.push(format!("http.extraHeader={auth}"));
        }

        args.push(req.url.clone());
        args.push(req.dest.to_string_lossy().to_string());

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_git_command(&args_ref, None, u)?;

        if req.lfs {
            // Try to install git-lfs; skip if not available
            let lfs_installed =
                run_git_command(&["lfs", "install", "--local"], Some(&req.dest), u).is_ok();
            if lfs_installed {
                run_git_command(&["lfs", "pull"], Some(&req.dest), u)
                    .context("git lfs pull failed")?;
            }
        }

        Ok(())
    })();

    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

async fn git_setup_handler(
    Json(req): Json<GitSetupRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user_opt(&req.user).map_err(err_json)?;
    let result = setup_git_impl(&req, user.as_ref());
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn setup_git_impl(req: &GitSetupRequest, u: Option<&User>) -> Result<()> {
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
        u,
    )?;

    // Set up host remote
    if run_git_command(&["remote", "add", "host", &req.url], Some(repo_path), u).is_err() {
        run_git_command(&["remote", "set-url", "host", &req.url], Some(repo_path), u)?;
    }
    run_git_command(
        &[
            "config",
            "remote.host.fetch",
            "+refs/heads/host/*:refs/remotes/host/*",
        ],
        Some(repo_path),
        u,
    )?;
    run_git_command(
        &["config", "remote.host.pushurl", "PUSH_DISABLED"],
        Some(repo_path),
        u,
    )?;

    // Set up rumpelpod remote
    if run_git_command(
        &["remote", "add", "rumpelpod", &req.url],
        Some(repo_path),
        u,
    )
    .is_err()
    {
        run_git_command(
            &["remote", "set-url", "rumpelpod", &req.url],
            Some(repo_path),
            u,
        )?;
    }
    run_git_command(
        &["config", "remote.rumpelpod.push", &push_refspec],
        Some(repo_path),
        u,
    )?;

    // Fetch from host
    run_git_command(&["fetch", "host"], Some(repo_path), u)?;

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
            u,
        )
        .is_ok();

        if branch_exists {
            run_git_command(
                &["branch", "-f", "--no-track", branch_name, "host/HEAD"],
                Some(repo_path),
                u,
            )
            .with_context(|| format!("resetting branch '{branch_name}' to host/HEAD"))?;
        } else {
            run_git_command(
                &["branch", "--no-track", branch_name, "host/HEAD"],
                Some(repo_path),
                u,
            )
            .with_context(|| format!("creating branch '{branch_name}'"))?;
        }

        run_git_command(&["checkout", branch_name], Some(repo_path), u)
            .with_context(|| format!("checking out branch '{branch_name}'"))?;

        if let Some(ref host_branch) = req.host_branch {
            let upstream = format!("host/{host_branch}");
            run_git_command(
                &["branch", "--set-upstream-to", &upstream, branch_name],
                Some(repo_path),
                u,
            )
            .with_context(|| format!("setting upstream of '{branch_name}' to '{upstream}'"))?;
        }
    }

    // Write host git identity into the pod's .git/config
    if let Some(ref identity) = req.git_identity {
        if let Some(ref name) = identity.name {
            run_git_command(&["config", "user.name", name], Some(repo_path), u)?;
        }
        if let Some(ref email) = identity.email {
            run_git_command(&["config", "user.email", email], Some(repo_path), u)?;
        }
    }

    Ok(())
}

/// Hook content that delegates to the rumpel binary inside the container.
const POD_REFERENCE_TRANSACTION_HOOK: &str = "\
#!/bin/sh\n\
# Installed by rumpelpod to sync branch updates to the gateway repository.\n\
exec /opt/rumpelpod/bin/rumpel git-hook reference-transaction \"$@\"\n";

const HOOK_SIGNATURE: &str = "Installed by rumpelpod to sync branch updates";

async fn git_install_hook_handler(
    Json(req): Json<GitInstallHookRequest>,
) -> Result<Json<GitInstallHookResponse>, (StatusCode, Json<ErrorResponse>)> {
    let first = install_hook_impl(&req.repo_path).map_err(err_json)?;
    ok_json(GitInstallHookResponse {
        first_install: first,
    })
}

/// Install the reference-transaction hook. Returns true on first install.
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
            let trimmed = content.trim_end();
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

async fn git_setup_submodules_handler(
    Json(req): Json<GitSetupSubmodulesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user_opt(&req.user).map_err(err_json)?;
    let result = setup_submodules_impl(&req, user.as_ref());
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn setup_submodules_impl(req: &GitSetupSubmodulesRequest, u: Option<&User>) -> Result<()> {
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

            run_git_command(&["submodule", "init", &sub.path], Some(&parent_dir), u)?;
            let sub_name = &sub.name;
            let sub_config_key = format!("submodule.{sub_name}.url");
            run_git_command(&["config", &sub_config_key, &sub_url], Some(&parent_dir), u)?;
            let token = &req.token;
            let auth_header = format!("http.extraHeader=Authorization: Bearer {token}");
            run_git_command(
                &["-c", &auth_header, "submodule", "update", &sub.path],
                Some(&parent_dir),
                u,
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
        let git_dir_output = git_command(u)
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
            u,
        )?;

        if run_git_command(&["remote", "add", "host", &sub_url], Some(&sub_path), u).is_err() {
            run_git_command(&["remote", "set-url", "host", &sub_url], Some(&sub_path), u)?;
        }
        run_git_command(
            &[
                "config",
                "remote.host.fetch",
                "+refs/heads/host/*:refs/remotes/host/*",
            ],
            Some(&sub_path),
            u,
        )?;
        run_git_command(
            &["config", "remote.host.pushurl", "PUSH_DISABLED"],
            Some(&sub_path),
            u,
        )?;

        if run_git_command(
            &["remote", "add", "rumpelpod", &sub_url],
            Some(&sub_path),
            u,
        )
        .is_err()
        {
            run_git_command(
                &["remote", "set-url", "rumpelpod", &sub_url],
                Some(&sub_path),
                u,
            )?;
        }
        run_git_command(
            &["config", "remote.rumpelpod.push", &push_refspec],
            Some(&sub_path),
            u,
        )?;

        run_git_command(&["fetch", "host"], Some(&sub_path), u)
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
                    let trimmed = c.trim_end();
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
                u,
            )
            .is_ok();

            if branch_exists {
                run_git_command(
                    &["branch", "-f", "--no-track", branch_name, "host/HEAD"],
                    Some(&sub_path),
                    u,
                )?;
            } else {
                run_git_command(
                    &["branch", "--no-track", branch_name, "host/HEAD"],
                    Some(&sub_path),
                    u,
                )?;
            }
            run_git_command(&["checkout", branch_name], Some(&sub_path), u)?;
        }
    }

    Ok(())
}

async fn git_sanitize_handler(
    Json(req): Json<GitSanitizeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user_opt(&req.user).map_err(err_json)?;
    let result = sanitize_impl(&req.repo_path, user.as_ref());
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn sanitize_impl(repo_path: &Path, u: Option<&User>) -> Result<()> {
    // Abort any in-progress operations
    for op in &[
        &["merge", "--abort"][..],
        &["rebase", "--abort"],
        &["cherry-pick", "--abort"],
        &["revert", "--abort"],
        &["am", "--abort"],
        &["bisect", "reset"],
    ] {
        let _ = git_command(u)
            .args(*op)
            .current_dir(repo_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Check if HEAD is valid
    let has_head = git_command(u)
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repo_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if has_head {
        run_git_command(&["reset", "--hard", "HEAD"], Some(repo_path), u)?;
    } else {
        let _ = git_command(u)
            .args(["rm", "--cached", "-r", "."])
            .current_dir(repo_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    run_git_command(&["clean", "-fd"], Some(repo_path), u)?;
    Ok(())
}

async fn git_snapshot_handler(
    Json(req): Json<GitSnapshotRequest>,
) -> Result<Json<GitSnapshotResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user_opt(&req.user).map_err(err_json)?;
    let result = snapshot_impl(&req.repo_path, user.as_ref());
    match result {
        Ok(patch) => ok_json(GitSnapshotResponse {
            patch: patch.map(|p| base64_encode(&p)),
        }),
        Err(e) => Err(err_json(e)),
    }
}

fn snapshot_impl(repo_path: &Path, u: Option<&User>) -> Result<Option<Vec<u8>>> {
    run_git_command(&["add", "-A"], Some(repo_path), u)?;

    let output = git_command(u)
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
    let user = resolve_user_opt(&req.user).map_err(err_json)?;
    let result = apply_patch_impl(&req, user.as_ref());
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn apply_patch_impl(req: &GitApplyPatchRequest, u: Option<&User>) -> Result<()> {
    let patch = base64_decode(&req.patch)?;

    // Remove files that the patch creates (they may already exist from the image)
    for file in &req.created_files {
        let _ = std::fs::remove_file(req.repo_path.join(file));
    }

    // Apply patch via stdin
    let mut child = git_command(u)
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
    let _ = git_command(u)
        .args(["submodule", "update", "--recursive"])
        .current_dir(&req.repo_path)
        .status();

    Ok(())
}

async fn env_user_info_handler(
    Json(req): Json<UserInfoRequest>,
) -> Result<Json<UserInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user(&req.user).map_err(err_json)?;
    ok_json(UserInfoResponse {
        home: user.dir.to_string_lossy().to_string(),
        shell: user.shell.to_string_lossy().to_string(),
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
    })
}

async fn env_probe_handler(
    Json(req): Json<ProbeEnvRequest>,
) -> Result<Json<ProbeEnvResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = probe_env_impl(&req.user, &req.shell_flags);
    match result {
        Ok(env) => ok_json(ProbeEnvResponse { env }),
        Err(e) => Err(err_json(e)),
    }
}

fn probe_env_impl(user: &str, shell_flags: &str) -> Result<HashMap<String, String>> {
    let user_info = resolve_user(user)?;
    let uid = user_info.uid;
    let gid = user_info.gid;
    let home = user_info.dir.to_string_lossy().to_string();

    // Check if bash is available
    let has_bash = Command::new("which")
        .arg("bash")
        .uid(uid.as_raw())
        .gid(gid.as_raw())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());

    if !has_bash {
        return Ok(HashMap::new());
    }

    // Set identity env vars so login shells source the right profile files.
    // Without these, the inherited root environment causes bash to read
    // /root/.profile instead of the target user's.
    let user_env = [("HOME", home.as_str()), ("USER", user), ("LOGNAME", user)];

    // Get base environment
    let base_output = Command::new("env")
        .arg("-0")
        .uid(uid.as_raw())
        .gid(gid.as_raw())
        .envs(user_env)
        .output()
        .context("getting base env")?;
    let base = parse_null_delimited_env(&base_output.stdout);

    // Get probed environment via bash with shell flags
    let probed_output = Command::new("bash")
        .arg(shell_flags)
        .arg("env -0")
        .uid(uid.as_raw())
        .gid(gid.as_raw())
        .envs(user_env)
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

/// Adapter: reads bytes received through a tokio mpsc channel.
/// Used to stream an HTTP request body into a tar extractor.
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<axum::body::Bytes>,
    cursor: std::io::Cursor<axum::body::Bytes>,
}

impl ChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<axum::body::Bytes>) -> Self {
        Self {
            rx,
            cursor: std::io::Cursor::new(axum::body::Bytes::new()),
        }
    }
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cursor.position() as usize >= self.cursor.get_ref().len() {
            match self.rx.blocking_recv() {
                Some(bytes) => self.cursor = std::io::Cursor::new(bytes),
                None => return Ok(0),
            }
        }
        std::io::Read::read(&mut self.cursor, buf)
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
    let owner = headers
        .get("X-Owner")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Stream body chunks into a channel that the blocking extractor reads from.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        use tokio_stream::StreamExt;
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if tx.send(bytes).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("cp_upload body read error: {e}");
                    break;
                }
            }
        }
    });

    let reader = ChannelReader::new(rx);
    let result =
        tokio::task::spawn_blocking(move || cp_upload_impl(&path, reader, owner.as_deref()))
            .await
            .expect("cp_upload_impl panicked");
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn cp_upload_impl(path: &Path, reader: impl std::io::Read, owner: Option<&str>) -> Result<()> {
    let path_display = path.display();

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

        let mut components = relative.components();
        components.next();
        let rest: PathBuf = components.collect();

        let target = if rest.as_os_str().is_empty() {
            path.to_path_buf()
        } else {
            path.join(&rest)
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

    if let Some(owner) = owner {
        chown_recursive(path, owner).with_context(|| format!("chown {path_display} to {owner}"))?;
    }

    Ok(())
}

/// Recursively chown a path and all its descendants.
fn chown_recursive(path: &Path, owner: &str) -> Result<()> {
    let user = resolve_user(owner)?;
    for entry in walkdir::WalkDir::new(path) {
        let entry = entry?;
        nix::unistd::chown(entry.path(), Some(user.uid), Some(user.gid))?;
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

    if let Some(ref user) = req.user {
        let user_info = resolve_user(user)?;
        cmd.uid(user_info.uid.as_raw());
        cmd.gid(user_info.gid.as_raw());
    }

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
// Utilities
// ---------------------------------------------------------------------------

/// Build a `git` Command that trusts all repo directories and
/// optionally runs as a specific user.
///
/// The container server runs as root, so git's safe.directory check
/// would otherwise reject repos owned by container users.
fn git_command(user: Option<&User>) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "safe.directory=*"]);
    if let Some(u) = user {
        cmd.uid(u.uid.as_raw());
        cmd.gid(u.gid.as_raw());
    }
    cmd
}

fn resolve_user_opt(name: &Option<String>) -> Result<Option<User>> {
    match name {
        Some(n) => Ok(Some(resolve_user(n)?)),
        None => Ok(None),
    }
}

fn run_git_command(args: &[&str], workdir: Option<&Path>, user: Option<&User>) -> Result<Vec<u8>> {
    let mut cmd = git_command(user);
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
