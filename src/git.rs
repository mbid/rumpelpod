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

/// Get the current HEAD commit SHA of a repository.
pub fn get_head_commit(repo: &Path) -> Result<String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .context("Failed to run git rev-parse HEAD")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to get HEAD commit: {}", stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Create a shared clone of a git repository.
/// A shared clone uses --shared to reference the source repo's objects.
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
/// Ensure the meta.git bare repository exists.
/// Creates a bare clone of the host repo if it doesn't exist.
/// Returns true if a new meta.git was created, false if it already existed.
pub fn ensure_meta_git(host_repo: &Path, meta_git_dir: &Path) -> Result<bool> {
    if meta_git_dir.exists() {
        return Ok(false);
    }

    // Create parent directory if needed
    if let Some(parent) = meta_git_dir.parent() {
        let path = parent.display();
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {path}"))?;
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
            &format!("+{branch}:refs/heads/{branch}"),
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
            &format!("+{branch}:refs/heads/{branch}"),
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
            &format!("+refs/heads/{branch}:refs/remotes/sandbox/{branch}"),
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
            &format!("+refs/heads/{primary_branch}:refs/remotes/sandbox/{primary_branch}"),
        ])
        .status()
        .context("Failed to sync primary branch to sandbox")?;

    if !status.success() {
        bail!("Failed to sync {primary_branch} branch from meta.git to sandbox");
    }

    // Fetch sandbox branch from meta.git to sandbox's remote tracking ref
    let status = Command::new("git")
        .current_dir(sandbox_repo)
        .args([
            "fetch",
            &meta_git_dir.to_string_lossy(),
            &format!("+refs/heads/{sandbox_name}:refs/remotes/sandbox/{sandbox_name}"),
        ])
        .status()
        .context("Failed to sync sandbox branch to sandbox remote")?;

    if !status.success() {
        bail!("Failed to sync {sandbox_name} branch from meta.git to sandbox");
    }

    Ok(())
}

/// Setup the "sandbox" remote in the host repo pointing to meta.git.
pub fn setup_host_sandbox_remote(host_repo: &Path, meta_git_dir: &Path) -> Result<()> {
    add_remote(host_repo, "sandbox", meta_git_dir)
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
    get_ref_oid(repo_path, &format!("refs/heads/{branch_name}"))
}

/// Get the OID of a remote tracking ref.
fn get_remote_ref_oid(repo_path: &Path, remote: &str, branch: &str) -> Option<Oid> {
    get_ref_oid(repo_path, &format!("refs/remotes/{remote}/{branch}"))
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
        let host_refs_display = host_refs.display();
        std::fs::create_dir_all(&host_refs)
            .with_context(|| format!("creating {host_refs_display}"))?;
        let meta_refs_display = meta_refs.display();
        std::fs::create_dir_all(&meta_refs)
            .with_context(|| format!("creating {meta_refs_display}"))?;

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
            let path_display = path.display();
            self.watcher
                .watch(path, RecursiveMode::NonRecursive)
                .with_context(|| format!("watching {path_display}"))?;
            info!("Git sync watching: {path_display}");
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
