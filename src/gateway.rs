//! Git gateway repository management.
//!
//! Creates and maintains a bare "gateway" git repository that acts as an intermediary
//! between the host repository and sandboxes. This allows sandboxes to fetch commits
//! without direct access to the host repo.
//!
//! # Repository sync architecture
//!
//! There are three types repositories involved:
//!
//! 1. **Host repo**: The user's working repository on the host machine.
//! 2. **Gateway repo**: A bare repository at `~/.local/state/sandbox/<hash>/gateway.git`
//!    that acts as an intermediary. Sandboxes cannot access the host repo directly.
//! 3. **Sandbox repos**: The repositories inside each sandbox container.
//!
//! ## Current sync: Host -> Gateway (implemented)
//!
//! Commits are synced from the host repo to the gateway repo:
//!
//! - On setup, all local branches are pushed to the gateway as `refs/heads/host/<branch>`.
//! - A post-commit hook in the host repo automatically pushes new commits to the gateway.
//! - The push uses the "sandbox" remote (host repo -> gateway repo).
//!
//! The gateway repo stores these as local branches (not remote refs), e.g.:
//! - Host branch `main` becomes gateway branch `host/main`
//! - Host branch `feature` becomes gateway branch `host/feature`
//!
//! ## Sandbox access to gateway
//!
//! Sandbox repos have a "host" remote pointing to the gateway (via HTTP server on the
//! docker network gateway IP). The remote is configured with a custom fetch refspec
//! (`+refs/heads/host/*:refs/remotes/host/*`) that strips the `host/` prefix, so:
//! - Gateway branch `host/main` → Sandbox remote ref `host/main`
//! - Gateway branch `host/feature` → Sandbox remote ref `host/feature`
//!
//! This means `git fetch host` in the sandbox gives clean remote ref names like
//! `host/main` rather than the redundant `host/host/main`.
//!
//! ## Sandbox -> Gateway sync
//!
//! Sandboxes can push their changes to the gateway for the host to pull.
//!
//! Sandbox branches in the gateway repo are in a separate namespace "sandbox/" to distinguish
//! them from host branches, and are annotated with the name of the sandbox to distinguish them
//! from a branch with the same name in another sandbox.
//! A branch `foo` in a sandbox `bar` thus becomes branch `sandbox/foo@bar`. Note the `@` here.
//! To keep this unambiguous, sandbox names must not contain the `@` character.
//! By default, every sandbox is launched with the sandbox name as the branch, the *primary* branch
//! of a sandbox.
//!
//! To make accessing more ergonomic, the host can fetch just branch `bar` (instead of
//! `sandbox/bar@bar`) from the gateway via custom refspecs.
//!
//! A post-commit hook in the sandbox automatically pushes new commits to the gateway.
//!
//! ## Access control
//!
//! The gateway enforces that each sandbox can only write to its own namespace:
//! - Sandboxes can only push to `refs/heads/sandbox/*@<sandbox_name>` where `<sandbox_name>`
//!   is their own sandbox name.
//! - The host can push to `refs/heads/host/*` branches.
//! - Reading (fetch) is unrestricted - all branches are visible to everyone.
//!
//! This is enforced by a pre-receive hook in the gateway that validates the sandbox name.
//! The sandbox name is determined server-side by the git HTTP server based on which
//! docker network the request came from. Each sandbox has its own isolated network and
//! can only reach the HTTP server bound to that network's gateway IP. The server sets
//! the SANDBOX_NAME environment variable which hooks can trust (the client cannot forge it).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use indoc::indoc;
use sha2::{Digest, Sha256};

use crate::command_ext::CommandExt;
use crate::config::get_state_dir;

/// Name of the remote added to the host repo pointing to the gateway.
const SANDBOX_REMOTE: &str = "sandbox";

/// Name of the remote added to the gateway pointing to the host repo.
const HOST_REMOTE: &str = "host";

/// Post-commit hook script that pushes the current branch to the gateway.
const POST_COMMIT_HOOK: &str = indoc! {r#"
    #!/bin/sh
    # Installed by sandbox to sync commits to the gateway repository.
    # The gateway allows sandboxes to fetch commits without direct host access.

    branch=$(git symbolic-ref --short HEAD 2>/dev/null)
    if [ -n "$branch" ]; then
        git push sandbox "$branch:host/$branch" --force --quiet || true
    fi
"#};

/// Pre-receive hook for the gateway repository.
///
/// Enforces access control: sandboxes can only push to their own namespace.
/// The sandbox name is provided via the SANDBOX_NAME environment variable,
/// which is set by the git HTTP server (not by the client). This is secure
/// because the sandbox cannot modify this variable.
///
/// Access rules:
/// - If SANDBOX_NAME is set, only allow refs matching `refs/heads/sandbox/*@<name>`
/// - If SANDBOX_NAME is not set (host push), only allow refs matching `refs/heads/host/*`
const GATEWAY_PRE_RECEIVE_HOOK: &str = indoc! {r#"
    #!/bin/sh
    # Gateway access control: sandboxes can only write to their own namespace.
    #
    # SANDBOX_NAME is set by the git HTTP server based on network identity.
    # The sandbox cannot forge this - it's set server-side.

    sandbox_name="$SANDBOX_NAME"

    # Read all refs being pushed
    while read old_oid new_oid refname; do
        # Skip deletions (new_oid is all zeros)
        if echo "$new_oid" | grep -q '^0\{40\}$'; then
            continue
        fi

        if [ -n "$sandbox_name" ]; then
            # Sandbox push: only allow sandbox/*@<sandbox_name>
            expected_suffix="@$sandbox_name"
            case "$refname" in
                refs/heads/sandbox/*"$expected_suffix")
                    # OK: matches sandbox namespace
                    ;;
                *)
                    echo "error: sandbox '$sandbox_name' cannot push to '$refname'"
                    echo "error: sandboxes can only push to refs/heads/sandbox/*@$sandbox_name"
                    exit 1
                    ;;
            esac
        else
            # Host push (no SANDBOX_NAME): only allow host/*
            case "$refname" in
                refs/heads/host/*)
                    # OK: host namespace
                    ;;
                *)
                    echo "error: host can only push to refs/heads/host/*"
                    echo "error: attempted to push to '$refname'"
                    exit 1
                    ;;
            esac
        fi
    done

    exit 0
"#};

/// Compute a hash of the repo path for use in the gateway directory name.
fn repo_path_hash(repo_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(repo_path.as_os_str().as_encoded_bytes());
    hex::encode(hasher.finalize())
}

/// Get the path to the gateway repository for a given host repo.
pub fn gateway_path(repo_path: &Path) -> Result<PathBuf> {
    let state_dir = get_state_dir()?;
    let hash = repo_path_hash(repo_path);
    Ok(state_dir.join(&hash).join("gateway.git"))
}

/// Check if the given path is inside a git repository.
fn is_git_repo(path: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Initialize the gateway repository and set up remotes and hooks.
///
/// This function is idempotent - it can be called multiple times safely.
/// It will:
/// 1. Create a bare gateway repo if it doesn't exist
/// 2. Add the "sandbox" remote to the host repo (pointing to gateway)
/// 3. Add the "host" remote to the gateway (pointing to host repo)
/// 4. Install a post-commit hook in the host repo
/// 5. Push all existing branches to the gateway
///
/// If the repo_path is not a git repository, this function does nothing.
///
/// Note: There's a race condition if called concurrently for the same repo
/// (e.g. from different processes). Two callers might both attempt to initialize
/// the gateway simultaneously. This is unlikely in practice and the worst case
/// is a transient error that resolves on retry.
pub fn setup_gateway(repo_path: &Path) -> Result<()> {
    // Only set up gateway if the host is a git repository
    if !is_git_repo(repo_path) {
        return Ok(());
    }

    let gateway = gateway_path(repo_path)?;

    // Create gateway directory and initialize bare repo if needed
    if !gateway.exists() {
        fs::create_dir_all(&gateway).with_context(|| {
            format!("Failed to create gateway directory: {}", gateway.display())
        })?;

        Command::new("git")
            .args(["init", "--bare"])
            .current_dir(&gateway)
            .success()
            .context("git init --bare failed")?;
    }

    // Configure gateway settings (idempotent - safe to run on every call).
    // Enable anonymous pushes via HTTP for sandboxes to push to gateway.
    // This is safe because the gateway is only accessible from our sandboxes.
    Command::new("git")
        .args(["config", "http.receivepack", "true"])
        .current_dir(&gateway)
        .success()
        .context("enabling http.receivepack failed")?;

    // Install access control hook (overwrites any existing hook).
    install_gateway_pre_receive_hook(&gateway)?;

    // Add "sandbox" remote to host repo (pointing to gateway)
    ensure_remote(repo_path, SANDBOX_REMOTE, &gateway)?;

    // Add "host" remote to gateway (pointing to host repo)
    ensure_remote(&gateway, HOST_REMOTE, repo_path)?;

    // Install post-commit hook
    install_post_commit_hook(repo_path)?;

    // Push all existing branches to the gateway
    push_all_branches(repo_path)?;

    Ok(())
}

/// Ensure a remote exists with the correct URL, adding or updating as needed.
fn ensure_remote(repo_path: &Path, remote_name: &str, remote_url: &Path) -> Result<()> {
    let url_str = remote_url.to_string_lossy();

    // Check if remote already exists (failure expected if it doesn't)
    let existing_url = Command::new("git")
        .args(["remote", "get-url", remote_name])
        .current_dir(repo_path)
        .success()
        .ok();

    match existing_url {
        Some(url) if String::from_utf8_lossy(&url).trim() == url_str => {
            // Remote exists with correct URL, nothing to do
        }
        Some(_) => {
            // Remote exists with wrong URL, update it
            Command::new("git")
                .args(["remote", "set-url", remote_name, &url_str])
                .current_dir(repo_path)
                .success()
                .context("git remote set-url failed")?;
        }
        None => {
            // Remote doesn't exist, add it
            Command::new("git")
                .args(["remote", "add", remote_name, &url_str])
                .current_dir(repo_path)
                .success()
                .context("git remote add failed")?;
        }
    }

    Ok(())
}

/// Install the pre-receive hook in the gateway repository for access control.
fn install_gateway_pre_receive_hook(gateway_path: &Path) -> Result<()> {
    let hooks_dir = gateway_path.join("hooks");
    let hook_path = hooks_dir.join("pre-receive");

    // Ensure hooks directory exists
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Failed to create hooks directory: {}", hooks_dir.display()))?;

    // Always overwrite the hook (we own this file completely)
    fs::write(&hook_path, GATEWAY_PRE_RECEIVE_HOOK)
        .with_context(|| format!("Failed to write hook: {}", hook_path.display()))?;

    // Make hook executable
    let mut perms = fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms)?;

    Ok(())
}

/// Install the post-commit hook in the host repository.
///
/// If a post-commit hook already exists and wasn't installed by us, we append
/// our hook invocation to it.
fn install_post_commit_hook(repo_path: &Path) -> Result<()> {
    let hooks_dir = repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join("post-commit");

    // Ensure hooks directory exists
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Failed to create hooks directory: {}", hooks_dir.display()))?;

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)
            .with_context(|| format!("Failed to read existing hook: {}", hook_path.display()))?;

        // Check if our hook is already installed (look for our signature comment)
        if existing.contains("Installed by sandbox to sync commits") {
            // Already installed, nothing to do
            return Ok(());
        }

        // Append our hook to the existing one
        let combined = format!("{}\n\n{}", existing.trim_end(), POST_COMMIT_HOOK);
        fs::write(&hook_path, combined)
            .with_context(|| format!("Failed to update hook: {}", hook_path.display()))?;
    } else {
        // Create new hook
        fs::write(&hook_path, POST_COMMIT_HOOK)
            .with_context(|| format!("Failed to write hook: {}", hook_path.display()))?;
    }

    // Make hook executable
    let mut perms = fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms)?;

    Ok(())
}

/// Push all local branches to the gateway as host/<branch>.
fn push_all_branches(repo_path: &Path) -> Result<()> {
    // Get list of all local branches
    let output = Command::new("git")
        .args(["for-each-ref", "--format=%(refname:short)", "refs/heads/"])
        .current_dir(repo_path)
        .success()
        .context("git for-each-ref failed")?;

    let output_str = String::from_utf8_lossy(&output);
    let branches: Vec<&str> = output_str.lines().filter(|s| !s.is_empty()).collect();

    if branches.is_empty() {
        return Ok(());
    }

    // Build refspecs for all branches: branch:host/branch
    let refspecs: Vec<String> = branches
        .iter()
        .map(|b| format!("{}:host/{}", b, b))
        .collect();
    let mut args: Vec<&str> = vec!["push", SANDBOX_REMOTE, "--force"];
    args.extend(refspecs.iter().map(|s| s.as_str()));

    Command::new("git")
        .args(&args)
        .current_dir(repo_path)
        .success()
        .context("git push to gateway failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_path_hash_deterministic() {
        let path = Path::new("/home/user/project");
        let hash1 = repo_path_hash(path);
        let hash2 = repo_path_hash(path);
        assert_eq!(hash1, hash2);
        // Should be a valid hex string of sha256 length
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_repo_path_hash_different_paths() {
        let path1 = Path::new("/home/user/project1");
        let path2 = Path::new("/home/user/project2");
        assert_ne!(repo_path_hash(path1), repo_path_hash(path2));
    }
}
