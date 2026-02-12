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
use indoc::indoc;
use sha2::{Digest, Sha256};

use crate::command_ext::CommandExt;
use crate::config::{get_state_dir, is_direct_git_config_mode};

/// Name of the remote added to the host repo pointing to the gateway.
const RUMPELPOD_REMOTE: &str = "rumpelpod";

/// Name of the remote added to the gateway pointing to the host repo.
const HOST_REMOTE: &str = "host";

/// Reference-transaction hook script that pushes branch updates to the gateway.
///
/// This hook is invoked whenever any reference is updated (commits, branch creation,
/// deletion, resets, etc). It runs in the "committed" state after the reference
/// transaction has been committed.
///
/// The hook reads updated refs from stdin in the format:
/// `<old-value> <new-value> <ref-name>`
///
/// For branch updates (refs/heads/*), it pushes the change to the gateway:
/// - For updates/creates: push the new commit
/// - For deletes (new-value is all zeros): delete the branch from gateway
///
/// For HEAD updates, it pushes the current HEAD commit to `host/HEAD` in the gateway.
/// This ensures pods can always find the host's current commit, even when
/// the host is in detached HEAD state.
const REFERENCE_TRANSACTION_HOOK: &str = indoc! {r#"
    #!/bin/sh
    # Installed by rumpelpod to sync branch updates to the gateway repository.
    # The gateway allows pods to fetch commits without direct host access.
    # This hook runs on reference-transaction events.

    # Only process after the transaction is committed
    [ "$1" = "committed" ] || exit 0

    # Process each ref update from stdin
    while read oldvalue newvalue refname; do
        case "$refname" in
            HEAD)
                # HEAD changed - sync current commit to host/HEAD in gateway.
                # The newvalue may be a symbolic ref (e.g., "ref:refs/heads/main")
                # or a commit hash (detached HEAD). We always resolve to the commit.
                # We use the fully qualified ref because when HEAD is a commit hash,
                # git requires the full ref path for the destination.
                head_commit=$(git rev-parse HEAD 2>/dev/null)
                if [ -n "$head_commit" ]; then
                    git push rumpelpod "$head_commit:refs/heads/host/HEAD" --force --no-verify --quiet 2>/dev/null || true
                fi
                ;;
            refs/heads/*)
                branch="${refname#refs/heads/}"
                if [ "$newvalue" = "0000000000000000000000000000000000000000" ]; then
                    # Branch deleted - remove from gateway
                    git push rumpelpod --delete "host/$branch" --no-verify --quiet 2>/dev/null || true
                else
                    # Branch updated or created - push to gateway
                    git push rumpelpod "$branch:host/$branch" --force --no-verify --quiet 2>/dev/null || true
                fi
                ;;
        esac
    done
"#};

/// Pre-receive hook for the gateway repository.
///
/// Enforces access control: pods can only push to their own namespace.
/// The pod name is provided via the POD_NAME environment variable,
/// which is set by the git HTTP server (not by the client). This is secure
/// because the pod cannot modify this variable.
///
/// Access rules:
/// - If POD_NAME is set, only allow refs matching `refs/heads/rumpelpod/*@<name>`
/// - If POD_NAME is not set (host push), only allow refs matching `refs/heads/host/*`
const GATEWAY_PRE_RECEIVE_HOOK: &str = indoc! {r#"
    #!/bin/sh
    # Gateway access control: pods can only write to their own namespace.
    #
    # POD_NAME is set by the git HTTP server based on the bearer token.
    # The pod cannot forge this - it's set server-side.

    pod_name="$POD_NAME"

    # Read all refs being pushed
    while read old_oid new_oid refname; do
        # Skip deletions (new_oid is all zeros)
        if echo "$new_oid" | grep -q '^0\{40\}$'; then
            continue
        fi

        if [ -n "$pod_name" ]; then
            # Pod push: only allow rumpelpod/*@<pod_name>
            expected_suffix="@$pod_name"
            case "$refname" in
                refs/heads/rumpelpod/*"$expected_suffix")
                    # OK: matches pod namespace
                    ;;
                *)
                    echo "error: pod '$pod_name' cannot push to '$refname'"
                    echo "error: pods can only push to refs/heads/rumpelpod/*@$pod_name"
                    exit 1
                    ;;
            esac
        else
            # Host push (no POD_NAME): only allow host/*
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

/// Post-receive hook for the gateway repository.
///
/// Syncs pod refs from the gateway to the host repo's remote-tracking refs.
/// When a pod pushes `refs/heads/rumpelpod/*@<name>`, this hook mirrors it to
/// the host repo as `refs/remotes/rumpelpod/*@<name>`.
///
/// For primary branches (where branch name equals pod name, e.g., `foo@foo`),
/// this hook also creates a symbolic ref alias `rumpelpod/<name>` -> `rumpelpod/<name>@<name>`.
/// This allows users to refer to a pod's primary branch simply as `rumpelpod/alice`
/// instead of the full `rumpelpod/alice@alice`.
///
/// The post-receive hook runs after refs are updated but before git-receive-pack
/// sends the response to the client. This means the pushing pod's `git push`
/// blocks until this hook completes, ensuring refs are visible in the host repo
/// immediately after the push returns.
const GATEWAY_POST_RECEIVE_HOOK: &str = indoc! {r#"
    #!/bin/sh
    # Sync pod refs from gateway to host repo's remote-tracking refs.
    # When pod pushes refs/heads/rumpelpod/*@<name>, mirror to host as
    # refs/remotes/rumpelpod/*@<name>.
    #
    # For primary branches (foo@foo), also create an alias symref rumpelpod/foo.

    while read oldvalue newvalue refname; do
        case "$refname" in
            refs/heads/rumpelpod/*)
                # Extract branch name (rumpelpod/foo@bar)
                branch="${refname#refs/heads/}"
                ref_suffix="${branch#rumpelpod/}"  # foo@bar
                branch_part="${ref_suffix%@*}"   # foo
                pod_part="${ref_suffix##*@}" # bar

                if [ "$newvalue" = "0000000000000000000000000000000000000000" ]; then
                    # Deletion - remove from host
                    git push host --delete "refs/remotes/$branch" --quiet 2>/dev/null || true
                    # Remove alias if this was a primary branch (foo@foo)
                    if [ "$branch_part" = "$pod_part" ]; then
                        git symbolic-ref --delete "refs/heads/rumpelpod/$pod_part" 2>/dev/null || true
                        git push host --delete "refs/remotes/rumpelpod/$pod_part" --quiet 2>/dev/null || true
                    fi
                else
                    # Update - push to host as remote-tracking ref
                    git push host "$refname:refs/remotes/$branch" --force --quiet 2>/dev/null || true
                    # Create alias if this is a primary branch (foo@foo)
                    if [ "$branch_part" = "$pod_part" ]; then
                        git symbolic-ref "refs/heads/rumpelpod/$pod_part" "$refname"
                        git push host "$refname:refs/remotes/rumpelpod/$pod_part" --force --quiet 2>/dev/null || true
                    fi
                fi
                ;;
        esac
    done
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

    // Install gateway hooks (overwrites any existing hooks).
    install_gateway_pre_receive_hook(&gateway)?;
    install_gateway_post_receive_hook(&gateway)?;

    // Install reference-transaction hook to sync branch updates
    install_reference_transaction_hook(repo_path)?;

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
fn install_gateway_pre_receive_hook(gateway_path: &Path) -> Result<()> {
    install_gateway_hook(gateway_path, "pre-receive", GATEWAY_PRE_RECEIVE_HOOK)
}

/// Install the post-receive hook in the gateway repository.
/// This hook syncs pod refs to the host repo as remote-tracking refs.
fn install_gateway_post_receive_hook(gateway_path: &Path) -> Result<()> {
    install_gateway_hook(gateway_path, "post-receive", GATEWAY_POST_RECEIVE_HOOK)
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

/// Install the post-commit hook in the host repository.
///
/// If a reference-transaction hook already exists and wasn't installed by us, we append
/// our hook invocation to it.
fn install_reference_transaction_hook(repo_path: &Path) -> Result<()> {
    let hooks_dir = repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join("reference-transaction");

    // Ensure hooks directory exists
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("Failed to create hooks directory: {}", hooks_dir.display()))?;

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path)
            .with_context(|| format!("Failed to read existing hook: {}", hook_path.display()))?;

        // Check if our hook is already installed (look for our signature comment)
        if existing.contains("Installed by rumpelpod to sync branch updates") {
            // Already installed, nothing to do
            return Ok(());
        }

        // Append our hook to the existing one
        let combined = format!("{}\n\n{}", existing.trim_end(), REFERENCE_TRANSACTION_HOOK);
        fs::write(&hook_path, combined)
            .with_context(|| format!("Failed to update hook: {}", hook_path.display()))?;
    } else {
        // Create new hook
        fs::write(&hook_path, REFERENCE_TRANSACTION_HOOK)
            .with_context(|| format!("Failed to write hook: {}", hook_path.display()))?;
    }

    // Make hook executable
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
