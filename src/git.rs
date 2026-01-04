use anyhow::{bail, Context, Result};
use git2::{Oid, Repository};
use log::{debug, error, info, warn};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::sandbox::SandboxInfo;

/// Find the root of the current git repository.
pub fn find_repo_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to run git rev-parse")?;

    if !output.status.success() {
        bail!("Not in a git repository");
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

/// Create a shared clone of a git repository.
/// A shared clone uses --shared to reference the source repo's objects.
pub fn create_shared_clone(source: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        debug!("Shared clone already exists at: {}", dest.display());
        return Ok(());
    }

    // Create parent directory if needed
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    info!(
        "Creating shared clone: {} -> {}",
        source.display(),
        dest.display()
    );

    let status = Command::new("git")
        .args([
            "clone",
            "--shared",
            &source.to_string_lossy(),
            &dest.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run git clone")?;

    if !status.success() {
        bail!("Git clone failed");
    }

    Ok(())
}

/// Add a remote to a git repository.
pub fn add_remote(repo: &Path, name: &str, url: &Path) -> Result<()> {
    // Check if remote already exists
    let output = Command::new("git")
        .current_dir(repo)
        .args(["remote", "get-url", name])
        .output()
        .context("Failed to check remote")?;

    if output.status.success() {
        // Remote exists, update it
        let status = Command::new("git")
            .current_dir(repo)
            .args(["remote", "set-url", name, &url.to_string_lossy()])
            .status()
            .context("Failed to update remote")?;

        if !status.success() {
            bail!("Failed to update remote: {}", name);
        }
    } else {
        // Remote doesn't exist, add it
        let status = Command::new("git")
            .current_dir(repo)
            .args(["remote", "add", name, &url.to_string_lossy()])
            .status()
            .context("Failed to add remote")?;

        if !status.success() {
            bail!("Failed to add remote: {}", name);
        }
    }

    Ok(())
}

/// Checkout a branch, creating it if it doesn't exist.
pub fn checkout_or_create_branch(repo: &Path, branch_name: &str) -> Result<()> {
    // Try to checkout existing branch first
    let status = Command::new("git")
        .current_dir(repo)
        .args(["checkout", branch_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run git checkout")?;

    if !status.success() {
        // Branch doesn't exist, create it
        let status = Command::new("git")
            .current_dir(repo)
            .args(["checkout", "-b", branch_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Failed to create branch")?;

        if !status.success() {
            bail!("Failed to create branch: {}", branch_name);
        }
    }

    // git clone creates a local branch for the remote HEAD (e.g., master).
    // Delete it to keep only the sandbox branch.
    delete_other_local_branches(repo, branch_name)?;

    Ok(())
}

/// Delete all local branches except the specified one.
fn delete_other_local_branches(repo: &Path, keep_branch: &str) -> Result<()> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["branch", "--format=%(refname:short)"])
        .output()
        .context("Failed to list branches")?;

    if !output.status.success() {
        bail!("Failed to list branches");
    }

    let branches = String::from_utf8_lossy(&output.stdout);
    for branch in branches.lines() {
        let branch = branch.trim();
        if !branch.is_empty() && branch != keep_branch {
            let status = Command::new("git")
                .current_dir(repo)
                .args(["branch", "-D", branch])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .context("Failed to delete branch")?;

            if !status.success() {
                warn!("Failed to delete branch: {}", branch);
            }
        }
    }

    Ok(())
}

/// Ensure the meta.git bare repository exists.
/// Creates a bare clone of the host repo if it doesn't exist.
/// Returns true if a new meta.git was created, false if it already existed.
pub fn ensure_meta_git(host_repo: &Path, meta_git_dir: &Path) -> Result<bool> {
    if meta_git_dir.exists() {
        return Ok(false);
    }

    // Create parent directory if needed
    if let Some(parent) = meta_git_dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    info!(
        "Creating meta.git bare clone: {} -> {}",
        host_repo.display(),
        meta_git_dir.display()
    );

    let status = Command::new("git")
        .args([
            "clone",
            "--bare",
            &host_repo.to_string_lossy(),
            &meta_git_dir.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run git clone --bare")?;

    if !status.success() {
        bail!("Git bare clone failed");
    }

    // Sync main branch from host to ensure it's up to date
    sync_main_to_meta(host_repo, meta_git_dir)?;

    Ok(true)
}

/// Get the primary branch name (main or master) of a repository.
fn get_primary_branch(repo: &Path) -> Result<String> {
    // Try to get the default branch from HEAD
    let output = Command::new("git")
        .current_dir(repo)
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .context("Failed to get HEAD branch")?;

    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            return Ok(branch);
        }
    }

    // Fallback: check if main exists, otherwise use master
    let status = Command::new("git")
        .current_dir(repo)
        .args(["show-ref", "--verify", "--quiet", "refs/heads/main"])
        .status()
        .context("Failed to check for main branch")?;

    if status.success() {
        Ok("main".to_string())
    } else {
        Ok("master".to_string())
    }
}

/// Sync the primary branch (main/master) from host repo to meta.git.
/// This is a ONE-WAY sync: host -> meta only.
/// Uses force-update (+) because host always has precedence over meta.git.
pub fn sync_main_to_meta(host_repo: &Path, meta_git_dir: &Path) -> Result<()> {
    let branch = get_primary_branch(host_repo)?;

    // Force-fetch the branch from host into meta.git (+ prefix forces non-fast-forward updates)
    let status = Command::new("git")
        .current_dir(meta_git_dir)
        .args([
            "fetch",
            &host_repo.to_string_lossy(),
            &format!("+{}:refs/heads/{}", branch, branch),
        ])
        .status()
        .context("Failed to fetch main branch to meta.git")?;

    if !status.success() {
        bail!("Failed to sync {} branch to meta.git", branch);
    }

    Ok(())
}

/// Sync a sandbox branch from the sandbox repo to meta.git.
///
/// Note: This is no longer used by the file-watching sync mechanism.
/// Sandbox->meta.git sync is now handled by post-commit hooks that push
/// to the HTTP remote. This function is kept for potential manual use.
#[allow(dead_code)]
pub fn sync_sandbox_to_meta(meta_git_dir: &Path, sandbox_repo: &Path, branch: &str) -> Result<()> {
    let status = Command::new("git")
        .current_dir(meta_git_dir)
        .args([
            "fetch",
            &sandbox_repo.to_string_lossy(),
            &format!("+{}:refs/heads/{}", branch, branch),
        ])
        .status()
        .context("Failed to sync sandbox branch to meta.git")?;

    if !status.success() {
        bail!("Failed to sync branch {} to meta.git", branch);
    }

    Ok(())
}

/// Sync a branch from meta.git to the host repo's remote tracking refs.
/// Updates refs/remotes/sandbox/<branch> in the host repo.
pub fn sync_meta_to_host(host_repo: &Path, meta_git_dir: &Path, branch: &str) -> Result<()> {
    // Fetch the specific branch from meta.git and update the remote tracking ref
    let status = Command::new("git")
        .current_dir(host_repo)
        .args([
            "fetch",
            &meta_git_dir.to_string_lossy(),
            &format!("+refs/heads/{}:refs/remotes/sandbox/{}", branch, branch),
        ])
        .status()
        .context("Failed to sync meta.git branch to host")?;

    if !status.success() {
        bail!("Failed to sync branch {} from meta.git to host", branch);
    }

    Ok(())
}

/// Sync branches from meta.git to the sandbox repo's remote tracking refs.
/// Updates refs/remotes/sandbox/master and refs/remotes/sandbox/<sandbox_name>.
///
/// NOTE: This is no longer called automatically. The sandbox can fetch from
/// the "sandbox" remote manually if it needs to pull changes from meta.git.
#[allow(dead_code)]
pub fn sync_meta_to_sandbox(
    meta_git_dir: &Path,
    sandbox_repo: &Path,
    sandbox_name: &str,
) -> Result<()> {
    let primary_branch = get_primary_branch(meta_git_dir)?;

    // Fetch master/main branch from meta.git to sandbox's remote tracking ref
    let status = Command::new("git")
        .current_dir(sandbox_repo)
        .args([
            "fetch",
            &meta_git_dir.to_string_lossy(),
            &format!(
                "+refs/heads/{}:refs/remotes/sandbox/{}",
                primary_branch, primary_branch
            ),
        ])
        .status()
        .context("Failed to sync primary branch to sandbox")?;

    if !status.success() {
        bail!(
            "Failed to sync {} branch from meta.git to sandbox",
            primary_branch
        );
    }

    // Fetch sandbox branch from meta.git to sandbox's remote tracking ref
    let status = Command::new("git")
        .current_dir(sandbox_repo)
        .args([
            "fetch",
            &meta_git_dir.to_string_lossy(),
            &format!(
                "+refs/heads/{}:refs/remotes/sandbox/{}",
                sandbox_name, sandbox_name
            ),
        ])
        .status()
        .context("Failed to sync sandbox branch to sandbox remote")?;

    if !status.success() {
        bail!(
            "Failed to sync {} branch from meta.git to sandbox",
            sandbox_name
        );
    }

    Ok(())
}

/// Setup the "sandbox" remote in the host repo pointing to meta.git.
pub fn setup_host_sandbox_remote(host_repo: &Path, meta_git_dir: &Path) -> Result<()> {
    add_remote(host_repo, "sandbox", meta_git_dir)
}

/// Setup remotes for a sandbox repo.
/// Renames the "origin" remote (created by git clone) to "sandbox".
pub fn setup_sandbox_remotes(meta_git_dir: &Path, sandbox_repo: &Path) -> Result<()> {
    // Check if "sandbox" remote already exists
    let sandbox_exists = Command::new("git")
        .current_dir(sandbox_repo)
        .args(["remote", "get-url", "sandbox"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to check sandbox remote")?
        .success();

    if !sandbox_exists {
        // Rename "origin" (created by git clone --shared) to "sandbox"
        let status = Command::new("git")
            .current_dir(sandbox_repo)
            .args(["remote", "rename", "origin", "sandbox"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Failed to rename origin remote to sandbox")?;

        if !status.success() {
            bail!("Failed to rename origin remote to sandbox");
        }
    }

    // Update the URL to ensure it points to meta_git_dir
    let status = Command::new("git")
        .current_dir(sandbox_repo)
        .args([
            "remote",
            "set-url",
            "sandbox",
            &meta_git_dir.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to set sandbox remote URL")?;

    if !status.success() {
        bail!("Failed to set sandbox remote URL");
    }

    // Allow fetching arbitrary SHAs (useful for syncing specific commits)
    let status = Command::new("git")
        .current_dir(sandbox_repo)
        .args(["config", "uploadpack.allowAnySHA1InWant", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to configure uploadpack.allowAnySHA1InWant")?;

    if !status.success() {
        bail!("Failed to configure sandbox repo");
    }

    Ok(())
}

/// Setup git hooks in the sandbox repo to push commits to meta.git via HTTP.
///
/// Installs a post-commit hook that pushes the current branch to the HTTP
/// remote exposed by the daemon. This replaces the file-watching-based
/// sync mechanism for sandbox->meta.git direction.
pub fn setup_sandbox_hooks(sandbox_repo: &Path, branch_name: &str) -> Result<()> {
    let hooks_dir = sandbox_repo.join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    // Post-commit hook: push to meta.git via HTTP after each commit
    let post_commit_path = hooks_dir.join("post-commit");
    let post_commit_script = format!(
        r#"#!/bin/sh
# Auto-generated hook to sync commits to meta.git via HTTP
# Only pushes the sandbox branch (write access to other branches is rejected by server)
# Uses --force to handle history rewrites (amend, rebase, etc.)

BRANCH="{}"
REMOTE_URL="http://host.docker.internal:$SANDBOX_GIT_HTTP_PORT/meta.git"

# Only push if SANDBOX_GIT_HTTP_PORT is set (we're inside a sandbox container)
if [ -n "$SANDBOX_GIT_HTTP_PORT" ]; then
    git push --force --quiet "$REMOTE_URL" "HEAD:refs/heads/$BRANCH" 2>/dev/null || true
fi
"#,
        branch_name
    );

    std::fs::write(&post_commit_path, post_commit_script)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&post_commit_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&post_commit_path, perms)?;
    }

    debug!("Created post-commit hook at {}", post_commit_path.display());
    Ok(())
}

// --- Git OID helpers using git2 ---

/// Get the OID of a reference in a repository.
/// Returns None if the reference doesn't exist.
fn get_ref_oid(repo_path: &Path, ref_name: &str) -> Option<Oid> {
    let repo = Repository::open(repo_path).ok()?;
    let reference = repo.find_reference(ref_name).ok()?;
    reference.target()
}

/// Get the OID of a branch in a repository.
fn get_branch_oid(repo_path: &Path, branch_name: &str) -> Option<Oid> {
    get_ref_oid(repo_path, &format!("refs/heads/{}", branch_name))
}

/// Get the OID of a remote tracking ref.
fn get_remote_ref_oid(repo_path: &Path, remote: &str, branch: &str) -> Option<Oid> {
    get_ref_oid(repo_path, &format!("refs/remotes/{}/{}", remote, branch))
}

// --- Full git sync ---

/// Run a full git sync for a sandbox.
///
/// Syncs:
/// - host main/master -> meta.git (one-way, host has precedence)
/// - meta.git sandbox branch -> host remote tracking refs
///
/// Note: sandbox -> meta.git is handled by post-commit hook inside the
/// container, which pushes to the HTTP remote. meta.git -> sandbox sync
/// is NOT automatic; the sandbox can `git fetch sandbox` to pull changes.
pub fn run_full_sync(info: &SandboxInfo) -> Result<()> {
    sync_main_to_meta(&info.repo_root, &info.meta_git_dir)
        .context("syncing main branch to meta.git")?;
    sync_meta_to_host(&info.repo_root, &info.meta_git_dir, &info.name)
        .context("syncing meta.git to host")?;
    Ok(())
}

/// Check if sync from host main to meta.git is needed.
fn needs_main_to_meta_sync(info: &SandboxInfo) -> bool {
    let primary_branch = get_primary_branch(&info.repo_root).unwrap_or_else(|_| "main".to_string());
    let host_oid = get_branch_oid(&info.repo_root, &primary_branch);
    let meta_oid = get_branch_oid(&info.meta_git_dir, &primary_branch);
    host_oid != meta_oid
}

/// Check if sync from meta.git to host remote refs is needed.
fn needs_meta_to_host_sync(info: &SandboxInfo) -> bool {
    let meta_oid = get_branch_oid(&info.meta_git_dir, &info.name);
    let host_remote_oid = get_remote_ref_oid(&info.repo_root, "sandbox", &info.name);
    meta_oid != host_remote_oid
}

/// Check if sync from meta.git to sandbox remote refs is needed.
/// NOTE: This is no longer used since meta->sandbox sync is disabled.
/// Kept for potential future use or manual syncing.
#[allow(dead_code)]
fn needs_meta_to_sandbox_sync(info: &SandboxInfo) -> bool {
    let primary_branch = get_primary_branch(&info.repo_root).unwrap_or_else(|_| "main".to_string());

    // Check primary branch
    let meta_primary_oid = get_branch_oid(&info.meta_git_dir, &primary_branch);
    let sandbox_remote_primary_oid =
        get_remote_ref_oid(&info.clone_dir, "sandbox", &primary_branch);
    if meta_primary_oid != sandbox_remote_primary_oid {
        return true;
    }

    // Check sandbox branch
    let meta_sandbox_oid = get_branch_oid(&info.meta_git_dir, &info.name);
    let sandbox_remote_sandbox_oid = get_remote_ref_oid(&info.clone_dir, "sandbox", &info.name);
    meta_sandbox_oid != sandbox_remote_sandbox_oid
}

/// Check if any sync operation is needed for a sandbox.
///
/// Note: sandbox -> meta.git sync is handled by post-commit hook, not file watching.
/// Note: meta.git -> sandbox sync is disabled; sandbox can `git fetch sandbox` manually.
fn needs_sync(info: &SandboxInfo) -> bool {
    needs_main_to_meta_sync(info) || needs_meta_to_host_sync(info)
}

// --- Git Sync ---

/// Internal state for tracking watched sandboxes.
/// Not exposed outside GitSync.
struct GitSyncState {
    /// Sandbox infos keyed by sandbox key, used by watcher callback
    sandboxes: HashMap<String, SandboxInfo>,
    /// Paths being watched for each sandbox
    watched_paths: HashMap<String, Vec<PathBuf>>,
}

impl GitSyncState {
    fn new() -> Self {
        GitSyncState {
            sandboxes: HashMap::new(),
            watched_paths: HashMap::new(),
        }
    }

    /// Check if a path is being watched by any sandbox.
    fn is_path_watched(&self, path: &Path) -> bool {
        self.watched_paths
            .values()
            .any(|paths| paths.iter().any(|p| p == path))
    }
}

/// Manages git synchronization for all sandboxes.
/// Watches refs/heads directories and triggers sync when changes are detected.
pub struct GitSync {
    watcher: RecommendedWatcher,
    state: Arc<Mutex<GitSyncState>>,
}

impl GitSync {
    /// Create a new GitSync instance with an empty watcher.
    pub fn new() -> Result<Self> {
        let state = Arc::new(Mutex::new(GitSyncState::new()));
        let state_for_callback = state.clone();

        let watcher = RecommendedWatcher::new(
            move |res: std::result::Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        // Ignore access events
                        if event.kind.is_access() {
                            return;
                        }

                        debug!("Git sync watcher event: {:?}", event);

                        // Acquire the lock and sync all sandboxes that need it
                        let state = state_for_callback.lock().unwrap();
                        for (key, info) in state.sandboxes.iter() {
                            if needs_sync(info) {
                                debug!("Syncing sandbox: {}", key);
                                if let Err(e) = run_full_sync(info) {
                                    error!("Git sync failed for {}: {:#}", key, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Git sync watcher error: {}", e);
                    }
                }
            },
            Config::default(),
        )
        .context("creating git sync watcher")?;

        Ok(GitSync { watcher, state })
    }

    /// Add a sandbox to be watched and run initial sync.
    /// First registers watch paths (to avoid missing changes), then runs initial sync.
    ///
    /// Watches:
    /// - host refs/heads (for main/master changes)
    /// - meta.git refs/heads (for changes pushed from sandbox via HTTP)
    ///
    /// Note: sandbox refs/heads is NOT watched because sandbox->meta.git sync
    /// is handled by post-commit hook pushing to HTTP remote.
    pub fn add_sandbox(&mut self, key: String, info: SandboxInfo) -> Result<()> {
        // Determine paths to watch (not sandbox refs - hook handles that direction)
        let host_refs = info.repo_root.join(".git/refs/heads");
        let meta_refs = info.meta_git_dir.join("refs/heads");

        // Ensure directories exist
        std::fs::create_dir_all(&host_refs)
            .with_context(|| format!("creating {}", host_refs.display()))?;
        std::fs::create_dir_all(&meta_refs)
            .with_context(|| format!("creating {}", meta_refs.display()))?;

        let paths_to_watch = vec![host_refs, meta_refs];

        // Determine which paths need to be watched (check state briefly)
        let paths_to_add: Vec<PathBuf> = {
            let state = self.state.lock().unwrap();
            paths_to_watch
                .iter()
                .filter(|p| !state.is_path_watched(p))
                .cloned()
                .collect()
        };

        // Register watch paths WITHOUT holding the state lock to avoid deadlock
        // (watcher callback also acquires the state lock)
        for path in &paths_to_add {
            self.watcher
                .watch(path, RecursiveMode::NonRecursive)
                .with_context(|| format!("watching {}", path.display()))?;
            info!("Git sync watching: {}", path.display());
        }

        // Now update state
        {
            let mut state = self.state.lock().unwrap();
            state.watched_paths.insert(key.clone(), paths_to_watch);
            state.sandboxes.insert(key.clone(), info.clone());
        }

        // Run initial sync (watcher is already active, so no changes will be missed)
        if let Err(e) = run_full_sync(&info) {
            error!("Initial git sync failed for {}: {:#}", key, e);
        }

        Ok(())
    }

    /// Remove a sandbox from being watched after running final sync.
    /// First runs final sync, then removes watch paths.
    pub fn remove_sandbox(&mut self, key: &str) {
        // Get the info before removing from state, to run final sync
        let info = {
            let state = self.state.lock().unwrap();
            state.sandboxes.get(key).cloned()
        };

        // Run final sync before removing watcher
        if let Some(ref info) = info {
            if let Err(e) = run_full_sync(info) {
                error!("Final git sync failed for {}: {:#}", key, e);
            }
        }

        // Remove from state and determine which paths to unwatch
        let paths_to_unwatch: Vec<PathBuf> = {
            let mut state = self.state.lock().unwrap();
            state.sandboxes.remove(key);

            if let Some(removed_paths) = state.watched_paths.remove(key) {
                // Only unwatch paths no longer needed by any sandbox
                removed_paths
                    .into_iter()
                    .filter(|p| !state.is_path_watched(p))
                    .collect()
            } else {
                Vec::new()
            }
        };

        // Unwatch paths WITHOUT holding the state lock to avoid deadlock
        for path in paths_to_unwatch {
            if let Err(e) = self.watcher.unwatch(&path) {
                warn!("Failed to unwatch {}: {}", path.display(), e);
            } else {
                info!("Git sync unwatching: {}", path.display());
            }
        }
    }
}
