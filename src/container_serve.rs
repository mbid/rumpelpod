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

use crate::async_runtime::block_on;

pub const DEFAULT_PORT: u16 = 7890;
pub const TOKEN_FILE: &str = "/tmp/rumpelpod-server-token";

// ---------------------------------------------------------------------------
// Shared request/response types (also used by PodClient)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct FsReadRequest {
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsReadResponse {
    /// Base64-encoded file content.
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsWriteRequest {
    pub path: PathBuf,
    /// Base64-encoded file content.
    pub content: String,
    pub owner: Option<String>,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsStatRequest {
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsStatResponse {
    pub exists: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsMkdirRequest {
    pub path: PathBuf,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsChownRequest {
    pub paths: Vec<PathBuf>,
    pub owner: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitCloneRequest {
    pub url: String,
    pub dest: PathBuf,
    pub auth_header: Option<String>,
    #[serde(default)]
    pub lfs: bool,
    /// Run git as this user so working tree files have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSetupRemotesRequest {
    pub repo_path: PathBuf,
    pub url: String,
    pub token: String,
    pub pod_name: String,
    pub host_branch: Option<String>,
    #[serde(default)]
    pub direct_config: bool,
    /// Run git as this user so fetched objects have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitInstallHookRequest {
    pub repo_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitInstallHookResponse {
    pub first_install: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmoduleEntry {
    pub name: String,
    pub path: String,
    pub displaypath: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSetupSubmodulesRequest {
    pub repo_path: PathBuf,
    pub submodules: Vec<SubmoduleEntry>,
    pub base_url: String,
    pub token: String,
    pub pod_name: String,
    #[serde(default)]
    pub is_first_entry: bool,
    #[serde(default)]
    pub direct_config: bool,
    /// Run git as this user so submodule files have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSanitizeRequest {
    pub repo_path: PathBuf,
    /// Run git as this user so restored files have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSnapshotRequest {
    pub repo_path: PathBuf,
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSnapshotResponse {
    /// Base64-encoded patch, or null if there are no changes.
    pub patch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitApplyPatchRequest {
    pub repo_path: PathBuf,
    /// Base64-encoded patch content.
    pub patch: String,
    #[serde(default)]
    pub created_files: Vec<String>,
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoRequest {
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub home: String,
    pub shell: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeEnvRequest {
    pub user: String,
    pub shell_flags: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeEnvResponse {
    pub env: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunRequest {
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub workdir: Option<PathBuf>,
    #[serde(default)]
    pub env: Vec<String>,
    /// Base64-encoded stdin data.
    pub stdin: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunResponse {
    pub exit_code: i32,
    /// Base64-encoded stdout.
    pub stdout: String,
    /// Base64-encoded stderr.
    pub stderr: String,
    #[serde(default)]
    pub timed_out: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

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
        .route("/git/setup-remotes", post(git_setup_remotes_handler))
        .route("/git/install-hook", post(git_install_hook_handler))
        .route("/git/setup-submodules", post(git_setup_submodules_handler))
        .route("/git/sanitize", post(git_sanitize_handler))
        .route("/git/snapshot", post(git_snapshot_handler))
        .route("/git/apply-patch", post(git_apply_patch_handler))
        .route("/env/user-info", post(env_user_info_handler))
        .route("/env/probe", post(env_probe_handler))
        .route("/run", post(run_handler))
        .layer(axum::middleware::from_fn_with_state(
            token.clone(),
            require_bearer_token,
        ));

    let app = Router::new()
        .route("/health", get(health_handler))
        .merge(authenticated_routes);

    block_on(async {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
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
        Some(value) if value == format!("Bearer {}", expected) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// ---------------------------------------------------------------------------
// Helper: resolve user name to uid/gid
// ---------------------------------------------------------------------------

fn resolve_user(name: &str) -> Result<User> {
    User::from_name(name)?.with_context(|| format!("user '{}' not found", name))
}

fn chown_path(path: &Path, owner: &str) -> Result<()> {
    let user = resolve_user(owner)?;
    nix::unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("chown {} to {}", path.display(), owner))
}

fn ok_json<T: Serialize>(val: T) -> Result<Json<T>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Json(val))
}

fn err_json(e: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!("{:#}", e),
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
    let data = std::fs::read(&req.path)
        .map_err(|e| err_json(anyhow::anyhow!("reading {}: {}", req.path.display(), e)))?;
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
            std::fs::create_dir_all(parent).map_err(|e| {
                err_json(anyhow::anyhow!(
                    "creating parent dirs for {}: {}",
                    req.path.display(),
                    e
                ))
            })?;
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

    std::fs::write(&req.path, &content)
        .map_err(|e| err_json(anyhow::anyhow!("writing {}: {}", req.path.display(), e)))?;

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
        Err(e) => Err(err_json(anyhow::anyhow!(
            "stat {}: {}",
            req.path.display(),
            e
        ))),
    }
}

async fn fs_mkdir_handler(
    Json(req): Json<FsMkdirRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    std::fs::create_dir_all(&req.path)
        .map_err(|e| err_json(anyhow::anyhow!("mkdir {}: {}", req.path.display(), e)))?;

    if let Some(ref owner) = req.owner {
        chown_path(&req.path, owner).map_err(err_json)?;
    }

    ok_json(serde_json::json!({}))
}

async fn fs_chown_handler(
    Json(req): Json<FsChownRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user(&req.owner).map_err(err_json)?;
    for path in &req.paths {
        nix::unistd::chown(path, Some(user.uid), Some(user.gid)).map_err(|e| {
            err_json(anyhow::anyhow!(
                "chown {} to {}: {}",
                path.display(),
                req.owner,
                e
            ))
        })?;
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
            args.push(format!("http.extraHeader={}", auth));
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

async fn git_setup_remotes_handler(
    Json(req): Json<GitSetupRemotesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = resolve_user_opt(&req.user).map_err(err_json)?;
    let result = setup_git_remotes_impl(&req, user.as_ref());
    result.map_err(err_json)?;
    ok_json(serde_json::json!({}))
}

fn setup_git_remotes_impl(req: &GitSetupRemotesRequest, u: Option<&User>) -> Result<()> {
    let repo_path = &req.repo_path;
    let push_refspec = format!("+refs/heads/*:refs/heads/rumpelpod/*@{}", req.pod_name);

    if req.direct_config {
        // Append directly to .git/config to avoid lock contention under parallelism.
        let config_path = repo_path.join(".git/config");
        let mut config = std::fs::read_to_string(&config_path)
            .with_context(|| format!("reading {}", config_path.display()))?;

        use std::fmt::Write;
        write!(
            config,
            "\n[http]\n\textraHeader = Authorization: Bearer {token}\n\
             [remote \"host\"]\n\turl = {url}\n\tfetch = +refs/heads/host/*:refs/remotes/host/*\n\tpushurl = PUSH_DISABLED\n\
             [remote \"rumpelpod\"]\n\turl = {url}\n\tpush = {push_refspec}\n",
            token = req.token,
            url = req.url,
        )?;
        std::fs::write(&config_path, config)
            .with_context(|| format!("writing {}", config_path.display()))?;
    } else {
        run_git_command(
            &[
                "config",
                "http.extraHeader",
                &format!("Authorization: Bearer {}", req.token),
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
    }

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
                &format!("refs/heads/{}", branch_name),
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
            .with_context(|| format!("resetting branch '{}' to host/HEAD", branch_name))?;
        } else {
            run_git_command(
                &["branch", "--no-track", branch_name, "host/HEAD"],
                Some(repo_path),
                u,
            )
            .with_context(|| format!("creating branch '{}'", branch_name))?;
        }

        run_git_command(&["checkout", branch_name], Some(repo_path), u)
            .with_context(|| format!("checking out branch '{}'", branch_name))?;

        if let Some(ref host_branch) = req.host_branch {
            let upstream = format!("host/{}", host_branch);
            run_git_command(
                &["branch", "--set-upstream-to", &upstream, branch_name],
                Some(repo_path),
                u,
            )
            .with_context(|| format!("setting upstream of '{}' to '{}'", branch_name, upstream))?;
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
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("creating hooks dir {}", hooks_dir.display()))?;

    let hook_path = hooks_dir.join("reference-transaction");

    let existing = std::fs::read_to_string(&hook_path).ok();

    let final_hook = match existing {
        Some(ref content) if content.contains(HOOK_SIGNATURE) => {
            return Ok(false);
        }
        Some(ref content) => {
            format!(
                "{}\n\n{}",
                content.trim_end(),
                POD_REFERENCE_TRANSACTION_HOOK
            )
        }
        None => POD_REFERENCE_TRANSACTION_HOOK.to_string(),
    };

    std::fs::write(&hook_path, &final_hook)
        .with_context(|| format!("writing hook {}", hook_path.display()))?;

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

            let sub_url = format!(
                "{}/submodules/{}/gateway.git",
                req.base_url, sub.displaypath
            );

            run_git_command(&["submodule", "init", &sub.path], Some(&parent_dir), u)?;
            run_git_command(
                &["config", &format!("submodule.{}.url", sub.name), &sub_url],
                Some(&parent_dir),
                u,
            )?;
            run_git_command(
                &[
                    "-c",
                    &format!("http.extraHeader=Authorization: Bearer {}", req.token),
                    "submodule",
                    "update",
                    &sub.path,
                ],
                Some(&parent_dir),
                u,
            )?;
        }
    }

    // Configure each submodule's remotes, hooks, and branch
    for sub in &req.submodules {
        let sub_path = container_repo_path.join(&sub.displaypath);
        let sub_url = format!(
            "{}/submodules/{}/gateway.git",
            req.base_url, sub.displaypath
        );
        let push_refspec = format!("+refs/heads/*:refs/heads/rumpelpod/*@{}", req.pod_name);

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

        if req.direct_config {
            let config_path = git_dir.join("config");
            let mut config = std::fs::read_to_string(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?;

            use std::fmt::Write;
            write!(
                config,
                "\n[http]\n\textraHeader = Authorization: Bearer {token}\n\
                 [remote \"host\"]\n\turl = {sub_url}\n\tfetch = +refs/heads/host/*:refs/remotes/host/*\n\tpushurl = PUSH_DISABLED\n\
                 [remote \"rumpelpod\"]\n\turl = {sub_url}\n\tpush = {push_refspec}\n",
                token = req.token,
            )?;
            std::fs::write(&config_path, config)?;
        } else {
            run_git_command(
                &[
                    "config",
                    "http.extraHeader",
                    &format!("Authorization: Bearer {}", req.token),
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
        }

        run_git_command(&["fetch", "host"], Some(&sub_path), u)
            .with_context(|| format!("fetching host in submodule '{}'", sub.displaypath))?;

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
                Some(ref c) => format!("{}\n\n{}", c.trim_end(), POD_REFERENCE_TRANSACTION_HOOK),
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
                    &format!("refs/heads/{}", branch_name),
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
        anyhow::bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
        anyhow::bail!(
            "git apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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

async fn run_handler(
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = run_impl(req);
    match result {
        Ok(resp) => ok_json(resp),
        Err(e) => Err(err_json(e)),
    }
}

fn run_impl(req: RunRequest) -> Result<RunResponse> {
    if req.cmd.is_empty() {
        anyhow::bail!("empty command");
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

    let timeout = req.timeout_secs.map(std::time::Duration::from_secs);

    if let Some(dur) = timeout {
        // Poll with timeout
        let start = std::time::Instant::now();
        loop {
            match child.try_wait()? {
                Some(status) => {
                    let output = child.wait_with_output()?;
                    return Ok(RunResponse {
                        exit_code: status.code().unwrap_or(-1),
                        stdout: base64_encode(&output.stdout),
                        stderr: base64_encode(&output.stderr),
                        timed_out: false,
                    });
                }
                None => {
                    if start.elapsed() >= dur {
                        // Kill the process
                        let _ = child.kill();
                        let output = child.wait_with_output()?;
                        return Ok(RunResponse {
                            exit_code: -1,
                            stdout: base64_encode(&output.stdout),
                            stderr: base64_encode(&output.stderr),
                            timed_out: true,
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    } else {
        let output = child.wait_with_output().context("waiting for command")?;
        Ok(RunResponse {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: base64_encode(&output.stdout),
            stderr: base64_encode(&output.stderr),
            timed_out: false,
        })
    }
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
        anyhow::bail!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode")
}
