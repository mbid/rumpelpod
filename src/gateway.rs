//! Git gateway repository management.
//!
//! Creates and maintains a bare "gateway" git repository that acts as an intermediary
//! between the host repository and pods. This allows pods to fetch commits
//! without direct access to the host repo.
//!
//! # Repository sync architecture
//!
//! There are three types repositories involved:
//!
//! 1. **Host repo**: The user's working repository on the host machine.
//! 2. **Gateway repo**: A bare repository at `~/.local/state/rumpelpod/<hash>/gateway.git`
//!    that acts as an intermediary. Pods cannot access the host repo directly.
//! 3. **Pod repos**: The repositories inside each pod container.
//!
//! ## Current sync: Host -> Gateway (implemented)
//!
//! Commits are synced from the host repo to the gateway repo:
//!
//! - On setup, all local branches are pushed to the gateway as `refs/heads/host/<branch>`.
//! - The current HEAD commit is also pushed as `refs/heads/host/HEAD`, allowing pods
//!   to find the host's current commit even when in detached HEAD state.
//! - A reference-transaction hook in the host repo automatically pushes branch updates
//!   to the gateway whenever any reference changes (commits, branch creation/deletion, resets).
//! - The push uses the "rumpelpod" remote (host repo -> gateway repo).
//!
//! The gateway repo stores these as local branches (not remote refs), e.g.:
//! - Host branch `main` becomes gateway branch `host/main`
//! - Host branch `feature` becomes gateway branch `host/feature`
//! - Host HEAD commit becomes gateway branch `host/HEAD`
//!
//! ## Pod access to gateway
//!
//! Pod repos have a "host" remote pointing to the gateway (via HTTP server on the
//! docker network gateway IP). The remote is configured with a custom fetch refspec
//! (`+refs/heads/host/*:refs/remotes/host/*`) that strips the `host/` prefix, so:
//! - Gateway branch → Pod remote ref `host/main`
//! - Gateway branch → Pod remote ref `host/feature`
//!
//! This means `git fetch host` in the pod gives clean remote ref names like
//! `host/main` rather than the redundant `host/host/main`.
//!
//! ## Pod -> Gateway sync
//!
//! Pods can push their changes to the gateway for the host to pull.
//!
//! Pod branches in the gateway repo are in a separate namespace "rumpelpod/" to distinguish
//! them from host branches, and are annotated with the name of the pod to distinguish them
//! from a branch with the same name in another pod.
//! A branch `foo` in a pod `bar` thus becomes branch `rumpelpod/foo@bar`. Note the `@` here.
//! To keep this unambiguous, pod names must not contain the `@` character.
//! By default, every pod is launched with the pod name as the branch, the *primary* branch
//! of a pod.
//!
//! To make accessing more ergonomic, the host can fetch just branch `bar` (instead of
//! `rumpelpod/bar@bar`) from the gateway via custom refspecs.
//!
//! A reference-transaction hook in the pod automatically pushes branch updates to the gateway.
//!
//! ## Access control
//!
//! The gateway enforces that each pod can only write to its own namespace:
//! - Pods can only push to `refs/heads/rumpelpod/*@<pod_name>` where `<pod_name>`
//!   is their own pod name.
//! - The host can push to `refs/heads/host/*` branches.
//! - Reading (fetch) is unrestricted - all branches are visible to everyone.
//!
//! This is enforced by a pre-receive hook in the gateway that validates the pod name.
//! The pod name is determined server-side by the git HTTP server based on the
//! bearer token in the request. Each pod is assigned a unique token when created,
//! and the server maps tokens to pod info. The server sets the POD_NAME
//! environment variable which hooks can trust (the client cannot forge it).

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::command_ext::CommandExt;
use crate::config::{get_state_dir, is_direct_git_config_mode};

/// Name of the remote added to the host repo pointing to the gateway.
const RUMPELPOD_REMOTE: &str = "rumpelpod";

/// Name of the remote added to the gateway pointing to the host repo.
const HOST_REMOTE: &str = "host";

/// Generate a shim script that delegates to `rumpel hook <subcommand>`.
/// The rumpel binary path is resolved at install time and embedded in the shim.
fn hook_shim(rumpel_path: &str, signature: &str, subcommand: &str, use_exec: bool) -> String {
    let invoke = if use_exec { "exec " } else { "" };
    format!(
        "#!/bin/sh\n\
         # {signature}\n\
         {invoke}{rumpel_path} hook {subcommand} \"$@\"\n"
    )
}

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
/// 2. Add the "rumpelpod" remote to the host repo (pointing to gateway)
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
    // Enable anonymous pushes via HTTP for pods to push to gateway.
    // This is safe because the gateway is only accessible from our pods.
    if is_direct_git_config_mode()? {
        // Bypass `git config` / `git remote` and write directly to the config
        // files to avoid flaky lock failures on overlay2 under heavy test
        // parallelism.
        append_git_config(
            &gateway,
            &format!(
                "[http]\n\treceivepack = true\n\
                 [remote \"{}\"]\n\turl = {}\n",
                HOST_REMOTE,
                repo_path.to_string_lossy(),
            ),
        )?;
        append_git_config(
            repo_path,
            &format!(
                "[remote \"{}\"]\n\turl = {}\n",
                RUMPELPOD_REMOTE,
                gateway.to_string_lossy(),
            ),
        )?;
    } else {
        Command::new("git")
            .args(["config", "http.receivepack", "true"])
            .current_dir(&gateway)
            .success()
            .context("enabling http.receivepack failed")?;

        // Add "rumpelpod" remote to host repo (pointing to gateway)
        ensure_remote(repo_path, RUMPELPOD_REMOTE, &gateway)?;

        // Add "host" remote to gateway (pointing to host repo)
        ensure_remote(&gateway, HOST_REMOTE, repo_path)?;
    }

    let rumpel_exe = std::env::current_exe()
        .context("resolving rumpel binary path")?
        .to_string_lossy()
        .to_string();

    // Install gateway hooks (overwrites any existing hooks).
    install_gateway_pre_receive_hook(&gateway, &rumpel_exe)?;
    install_gateway_post_receive_hook(&gateway, &rumpel_exe)?;

    // Install hook to sync branch updates from host to gateway.
    install_reference_transaction_hook(repo_path, &rumpel_exe)?;

    // Older git versions (notably Apple Git 2.39) don't fire the
    // reference-transaction hook when HEAD changes via checkout/switch.
    // Install a post-checkout hook as fallback for those versions.
    if !git_supports_symref_in_ref_transaction(repo_path) {
        install_post_checkout_hook(repo_path, &rumpel_exe)?;
    }

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

/// Append raw config text to a repo's `.git/config` (or `config` for bare repos).
/// Used in test mode to avoid `git config` lock contention on overlay2.
fn append_git_config(repo_path: &Path, content: &str) -> Result<()> {
    // Bare repos store config at `<repo>/config`, non-bare at `<repo>/.git/config`.
    let config_path = if repo_path.join("HEAD").exists() {
        repo_path.join("config")
    } else {
        repo_path.join(".git/config")
    };
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&config_path)
        .with_context(|| format!("failed to open {}", config_path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write to {}", config_path.display()))?;
    Ok(())
}

/// Install the pre-receive hook in the gateway repository for access control.
fn install_gateway_pre_receive_hook(gateway_path: &Path, rumpel_exe: &str) -> Result<()> {
    let content = hook_shim(
        rumpel_exe,
        "Gateway access control: pods can only write to their own namespace.",
        "gateway-pre-receive",
        true,
    );
    install_gateway_hook(gateway_path, "pre-receive", &content)
}

/// Install the post-receive hook in the gateway repository.
/// This hook syncs pod refs to the host repo as remote-tracking refs.
fn install_gateway_post_receive_hook(gateway_path: &Path, rumpel_exe: &str) -> Result<()> {
    let content = hook_shim(
        rumpel_exe,
        "Sync pod refs from gateway to host repo.",
        "gateway-post-receive",
        true,
    );
    install_gateway_hook(gateway_path, "post-receive", &content)
}

/// Install a hook script in the gateway repository.
fn install_gateway_hook(gateway_path: &Path, hook_name: &str, hook_content: &str) -> Result<()> {
    let hooks_dir = gateway_path.join("hooks");
    let hook_path = hooks_dir.join(hook_name);

    // Ensure hooks directory exists
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Failed to create hooks directory: {}", hooks_dir.display()))?;

    // Always overwrite the hook (we own this file completely)
    fs::write(&hook_path, hook_content)
        .with_context(|| format!("Failed to write hook: {}", hook_path.display()))?;

    // Make hook executable
    let mut perms = fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms)?;

    Ok(())
}

/// Install the reference-transaction hook in the host repository.
///
/// If a reference-transaction hook already exists and wasn't installed by us, we append
/// our hook invocation to it.
fn install_reference_transaction_hook(repo_path: &Path, rumpel_exe: &str) -> Result<()> {
    let hooks_dir = repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join("reference-transaction");

    let signature = "Installed by rumpelpod to sync branch updates";
    let shim = hook_shim(rumpel_exe, signature, "host-reference-transaction", false);

    // Ensure hooks directory exists
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Failed to create hooks directory: {}", hooks_dir.display()))?;

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)
            .with_context(|| format!("Failed to read existing hook: {}", hook_path.display()))?;

        // Check if our hook is already installed (look for our signature comment)
        if existing.contains(signature) {
            // Already installed, nothing to do
            return Ok(());
        }

        // Append our hook to the existing one
        let combined = format!("{}\n\n{}", existing.trim_end(), shim);
        fs::write(&hook_path, combined)
            .with_context(|| format!("Failed to update hook: {}", hook_path.display()))?;
    } else {
        // Create new hook
        fs::write(&hook_path, shim)
            .with_context(|| format!("Failed to write hook: {}", hook_path.display()))?;
    }

    // Make hook executable
    let mut perms = fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms)?;

    Ok(())
}

/// Signature used to detect whether the post-checkout hook was installed by us.
const POST_CHECKOUT_SIGNATURE: &str = "Installed by rumpelpod to sync HEAD";

/// Check whether `git checkout` triggers the reference-transaction hook for
/// HEAD changes. Older git versions (including Apple Git 2.39) only fire the
/// hook for direct ref updates, not for symbolic ref changes.
fn git_supports_symref_in_ref_transaction(repo_path: &Path) -> bool {
    let output = Command::new("git")
        .args(["--version"])
        .current_dir(repo_path)
        .success();

    let version_str = match output {
        Ok(out) => String::from_utf8_lossy(&out).trim().to_string(),
        Err(_) => return false,
    };

    // Parse "git version X.Y.Z" or "git version X.Y.Z (Apple Git-NNN)"
    let version_part = version_str
        .strip_prefix("git version ")
        .unwrap_or(&version_str);

    // Extract major.minor
    let parts: Vec<&str> = version_part.split('.').collect();
    let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Git 2.40+ fires reference-transaction for symbolic ref changes during checkout.
    // Apple Git 2.39 does not. We use 2.40 as the cutoff.
    major > 2 || (major == 2 && minor >= 40)
}

/// Install the post-checkout hook in the host repository.
fn install_post_checkout_hook(repo_path: &Path, rumpel_exe: &str) -> Result<()> {
    let hooks_dir = repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join("post-checkout");

    let shim = hook_shim(
        rumpel_exe,
        POST_CHECKOUT_SIGNATURE,
        "host-post-checkout",
        false,
    );

    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Failed to create hooks directory: {}", hooks_dir.display()))?;

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)
            .with_context(|| format!("Failed to read existing hook: {}", hook_path.display()))?;

        if existing.contains(POST_CHECKOUT_SIGNATURE) {
            return Ok(());
        }

        let combined = format!("{}\n\n{}", existing.trim_end(), shim);
        fs::write(&hook_path, combined)
            .with_context(|| format!("Failed to update hook: {}", hook_path.display()))?;
    } else {
        fs::write(&hook_path, shim)
            .with_context(|| format!("Failed to write hook: {}", hook_path.display()))?;
    }

    let mut perms = fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms)?;

    Ok(())
}

/// Push all local branches and current HEAD to the gateway.
///
/// Branches are pushed as `host/<branch>`, and HEAD is pushed as `host/HEAD`.
/// The `host/HEAD` ref allows pods to find the host's current commit
/// even when the host is in detached HEAD state.
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
    let mut refspecs: Vec<String> = branches
        .iter()
        .map(|b| format!("{}:host/{}", b, b))
        .collect();

    // Also push HEAD to host/HEAD so pods can find the current commit.
    // We use the fully qualified ref path because when HEAD is detached (pointing
    // to a commit rather than a branch), git requires the full ref name.
    refspecs.push("HEAD:refs/heads/host/HEAD".to_string());

    let mut args: Vec<&str> = vec!["push", RUMPELPOD_REMOTE, "--force"];
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
