// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Git repository preparation logic for containers.
//!
//! Sets up remotes, hooks, branches, submodules, and identity so that
//! the pod can push/fetch through the gateway.

use std::env::VarError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use indoc::formatdoc;
use serde::{Deserialize, Serialize};

use crate::command_ext::CommandExt;
use crate::git::{GitIdentity, GitRemote};

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSetupRequest {
    pub repo_path: PathBuf,
    pub url: String,
    pub token: String,
    pub pod_name: String,
    /// Extra refspecs appended to `git fetch host`.  Used by `rumpel
    /// fork` to pull source-pod branches into a `source-pod/<branch>`
    /// namespace before checking out forked branches.
    pub extra_host_fetch: Vec<String>,
    /// Branches to create on first entry.  Each is created from `base`
    /// and (optionally) tracked against `upstream`.
    pub branches: Vec<GitSetupBranch>,
    /// The branch to check out and write into `git config
    /// rumpelpod.pod-name`.  Must appear in `branches` or already exist.
    pub primary: String,
    /// Git user identity from the host to write into the pod's .git/config.
    pub git_identity: Option<GitIdentity>,
    pub remotes: Vec<GitRemote>,
    pub description_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSetupBranch {
    pub name: String,
    /// Any ref reachable after the host fetch (e.g. "host/HEAD",
    /// "host/master", "source-pod/main").
    pub base: String,
    /// Upstream to set on the new branch (e.g. "host/master",
    /// "rumpelpod/foo@main").  None leaves the branch with no upstream.
    pub upstream: Option<String>,
}

#[derive(Debug)]
pub(crate) struct GitSetupSubmodulesRequest {
    pub repo_path: PathBuf,
    pub base_url: String,
    pub token: String,
    pub pod_name: String,
    pub is_first_entry: bool,
}

#[derive(Debug)]
pub(crate) struct GitGatewayRefreshRequest {
    pub repo_path: PathBuf,
    pub base_url: String,
    pub token: String,
}

// ---------------------------------------------------------------------------
// Hook constants
// ---------------------------------------------------------------------------

/// Hook content that delegates to the rumpel binary inside the container.
const POD_REFERENCE_TRANSACTION_HOOK: &str = "\
#!/bin/sh\n\
# Installed by rumpelpod (pod)\n\
exec /opt/rumpelpod/bin/rumpel git-hook reference-transaction \"$@\"\n";

const HOOK_SIGNATURE: &str = "Installed by rumpelpod (pod)";

// ---------------------------------------------------------------------------
// Git setup
// ---------------------------------------------------------------------------

/// Return whether the repository was created so image-supplied files can be
/// preserved instead of sanitized as an existing checkout.
pub(crate) fn initialize_repository(repo_path: &Path) -> Result<bool> {
    if repo_path
        .join(".git")
        .try_exists()
        .context("checking for an existing repository")?
    {
        return Ok(false);
    }
    Command::new("git")
        .arg("init")
        .arg(repo_path)
        .success()
        .context("initializing repository for the host fetch")?;
    Ok(true)
}

pub fn setup_git_impl(req: &GitSetupRequest) -> Result<()> {
    let repo_path = &req.repo_path;
    let pod_name = &req.pod_name;
    let token = &req.token;
    let push_refspec = format!("+refs/heads/*:refs/rumpelpod/*@{pod_name}");
    let repo_url = &req.url;

    configure_remotes(repo_path, &req.remotes)?;
    if let Some(description_file) = &req.description_file {
        install_pre_commit_hook(repo_path, description_file)?;
    }
    // Forks need the source pod's policy even if host settings have changed
    // or the pod server has restarted. An empty value means no DESCRIPTION policy.
    Command::new("git")
        .args([
            "config",
            "rumpelpod.description-file",
            req.description_file.as_deref().unwrap_or(""),
        ])
        .current_dir(repo_path)
        .success()
        .context("recording description policy for forks")?;

    // Set up gateway remotes. `host` fetches branches directly from
    // the host repo; `rumpelpod` pushes pod branches back through the
    // same gateway endpoint.
    configure_gateway_urls(repo_path, repo_url, token)?;
    // Clear existing fetch refspecs (may be multi-valued from a prior
    // entry) and set the two we need.
    let _ = Command::new("git")
        .args(["config", "--unset-all", "remote.host.fetch"])
        .current_dir(repo_path)
        .success();
    Command::new("git")
        .args([
            "config",
            "--add",
            "remote.host.fetch",
            "+refs/heads/*:refs/remotes/host/*",
        ])
        .current_dir(repo_path)
        .success()?;
    // Also fetch refs/rumpelpod/host-head so we can resolve host/HEAD
    // even when the host is in detached-HEAD state.
    Command::new("git")
        .args([
            "config",
            "--add",
            "remote.host.fetch",
            "+refs/rumpelpod/host-head:refs/remotes/host/HEAD",
        ])
        .current_dir(repo_path)
        .success()?;
    // Caller-supplied extra refspecs (e.g. `rumpel fork` adds the
    // source pod's branch namespace).
    for refspec in &req.extra_host_fetch {
        Command::new("git")
            .args(["config", "--add", "remote.host.fetch", refspec])
            .current_dir(repo_path)
            .success()?;
    }
    Command::new("git")
        .args(["config", "remote.host.pushurl", "PUSH_DISABLED"])
        .current_dir(repo_path)
        .success()?;

    // Push refspecs: all branches go to refs/rumpelpod/<branch>@<pod>,
    // and the primary branch also goes to refs/rumpelpod/<pod> as a
    // shortcut so the host sees a clean rumpelpod/<pod> remote ref.
    let primary = &req.primary;
    let _ = Command::new("git")
        .args(["config", "--unset-all", "remote.rumpelpod.push"])
        .current_dir(repo_path)
        .success();
    Command::new("git")
        .args(["config", "--add", "remote.rumpelpod.push", &push_refspec])
        .current_dir(repo_path)
        .success()?;
    let primary_push = format!("+refs/heads/{primary}:refs/rumpelpod/{pod_name}");
    Command::new("git")
        .args(["config", "--add", "remote.rumpelpod.push", &primary_push])
        .current_dir(repo_path)
        .success()?;
    Command::new("git")
        .args([
            "config",
            "remote.rumpelpod.fetch",
            "+refs/rumpelpod/*:refs/remotes/rumpelpod/*",
        ])
        .current_dir(repo_path)
        .success()?;

    // Store pod name so the reference-transaction hook can push the
    // primary branch shortcut.
    Command::new("git")
        .args(["config", "rumpelpod.pod-name", primary])
        .current_dir(repo_path)
        .success()?;

    // Fetch from host (pulls extra_host_fetch refspecs too).
    Command::new("git")
        .args(["fetch", "host"])
        .current_dir(repo_path)
        .success()?;

    // Install reference-transaction hook; detect first entry from return value
    let is_first_entry = install_hook_impl(repo_path)?;

    if is_first_entry {
        // Detach HEAD before mutating branches: forks can rewrite a
        // branch (e.g. "master") that the baked image happens to have
        // checked out, and `git branch -f` refuses to touch a branch
        // currently in use by a worktree.  Skip when HEAD is unborn
        // (no commits yet) -- nothing is checked out to conflict with.
        let has_commit = Command::new("git")
            .args(["rev-parse", "--verify", "--quiet", "HEAD"])
            .current_dir(repo_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if has_commit {
            Command::new("git")
                .args(["checkout", "--detach", "HEAD"])
                .current_dir(repo_path)
                .success()
                .context("detaching HEAD before branch setup")?;
        }

        for branch in &req.branches {
            create_or_reset_branch(repo_path, branch)?;
        }

        Command::new("git")
            .args(["checkout", primary])
            .current_dir(repo_path)
            .success()
            .with_context(|| format!("checking out primary branch '{primary}'"))?;
    }

    // Write host git identity into the pod's .git/config
    if let Some(ref identity) = req.git_identity {
        if let Some(ref name) = identity.name {
            Command::new("git")
                .args(["config", "user.name", name])
                .current_dir(repo_path)
                .success()?;
        }
        if let Some(ref email) = identity.email {
            Command::new("git")
                .args(["config", "user.email", email])
                .current_dir(repo_path)
                .success()?;
        }
    }

    Ok(())
}

pub(crate) fn refresh_gateway_urls_impl(req: &GitGatewayRefreshRequest) -> Result<()> {
    let repo_url = format!("{}/rumpelpod.git", req.base_url);
    configure_gateway_urls(&req.repo_path, &repo_url, &req.token)?;
    refresh_submodule_gateway_urls(&req.repo_path, &req.base_url, &req.token)?;
    Ok(())
}

const MANAGED_REMOTES: &[&str] = &["host", "rumpelpod"];

/// Write `.git/hooks/pre-commit` in the cloned repo.  The hook fails
/// the commit when the DESCRIPTION file is missing or not formatted
/// like a git commit message.  Signed with a distinct comment so the
/// host-hook stripper and the pod-side reference-transaction installer
/// leave it alone.
fn install_pre_commit_hook(repo_path: &Path, description_file: &str) -> Result<()> {
    let hooks_dir = repo_path.join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir).with_context(|| {
        let p = hooks_dir.display();
        format!("creating hooks dir {p}")
    })?;
    let hook_path = hooks_dir.join("pre-commit");

    // Single-quote the path for the shell and escape any embedded
    // single quotes so a config-supplied path cannot inject commands.
    let escaped = description_file.replace('\'', "'\\''");
    let content = formatdoc! {"
        #!/bin/sh
        # Installed by rumpelpod (pod pre-commit)
        exec /opt/rumpelpod/bin/rumpel git-hook pre-commit-description --file '{escaped}'
    "};

    std::fs::write(&hook_path, content).with_context(|| {
        let p = hook_path.display();
        format!("writing pre-commit hook {p}")
    })?;
    let mut perms = std::fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&hook_path, perms).with_context(|| {
        let p = hook_path.display();
        format!("setting mode on {p}")
    })?;
    Ok(())
}

/// Apply the original repository remotes before adding gateway remotes.
///
/// Also removes any pre-existing remotes (from the base image) that
/// are not in the provided list and not rumpelpod-managed.
fn configure_remotes(repo_path: &Path, remotes: &[GitRemote]) -> Result<()> {
    if remotes.is_empty() {
        return Ok(());
    }

    // List existing remotes in the repo.
    let existing_output = Command::new("git")
        .args(["remote"])
        .current_dir(repo_path)
        .success()
        .context("listing existing remotes")?;
    let existing: Vec<&str> = std::str::from_utf8(&existing_output)
        .context("non-UTF-8 remote names")?
        .lines()
        .collect();

    let managed = MANAGED_REMOTES;

    // Remove stale remotes that are not in the host list and not managed.
    for name in &existing {
        if managed.contains(name) {
            continue;
        }
        if !remotes.iter().any(|remote| remote.name == *name) {
            Command::new("git")
                .args(["remote", "remove", name])
                .current_dir(repo_path)
                .success()
                .with_context(|| format!("removing remote '{name}'"))?;
        }
    }

    // Add or update remotes from the host.
    for remote in remotes {
        let name = remote.name.as_str();
        let url = remote.url.as_str();
        if managed.contains(&name) {
            continue;
        }
        if existing.contains(&name) {
            Command::new("git")
                .args(["remote", "set-url", name, url])
                .current_dir(repo_path)
                .success()
                .with_context(|| format!("setting URL for remote '{name}'"))?;
        } else {
            Command::new("git")
                .args(["remote", "add", name, url])
                .current_dir(repo_path)
                .success()
                .with_context(|| format!("adding remote '{name}'"))?;
        }
    }

    Ok(())
}

fn configure_gateway_urls(repo_path: &Path, repo_url: &str, token: &str) -> Result<()> {
    // Baked checkouts can carry the pod's previous gateway configuration.
    // Remove unscoped bearer headers without discarding unrelated headers.
    unset_git_config(
        repo_path,
        "http.extraHeader",
        Some("^Authorization: Bearer "),
    )?;

    for remote in MANAGED_REMOTES {
        let output = Command::new("git")
            .args([
                "config",
                "--local",
                "--get",
                &format!("remote.{remote}.url"),
            ])
            .current_dir(repo_path)
            .output()
            .context("reading previous gateway URL")?;
        match output.status.code() {
            Some(0) => {
                let old_url = std::str::from_utf8(&output.stdout)
                    .context("non-UTF-8 gateway URL")?
                    .trim();
                if old_url != repo_url {
                    // A retired tunnel port can be reused by an unrelated server.
                    for setting in ["extraHeader", "followRedirects"] {
                        unset_git_config(repo_path, &format!("http.{old_url}.{setting}"), None)?;
                    }
                }
            }
            Some(1) => {}
            _ => return Err(anyhow::anyhow!("reading previous gateway URL failed")),
        }
    }

    run_git_with_secret(
        Command::new("git")
            .args([
                "config",
                &format!("http.{repo_url}.extraHeader"),
                &format!("Authorization: Bearer {token}"),
            ])
            .current_dir(repo_path),
        token,
    )?;
    // Git matches HTTP options against the initial URL, not redirect targets.
    Command::new("git")
        .args([
            "config",
            &format!("http.{repo_url}.followRedirects"),
            "false",
        ])
        .current_dir(repo_path)
        .success()?;
    set_remote_url(repo_path, "host", repo_url)?;
    set_remote_url(repo_path, "rumpelpod", repo_url)?;
    Ok(())
}

// CommandExt::success includes argv in errors, which would expose the token.
fn run_git_with_secret(command: &mut Command, token: &str) -> Result<()> {
    let output = command
        .output()
        .context("running Git with gateway credentials")?;
    if !output.status.success() {
        let status = output.status;
        let stderr = String::from_utf8_lossy(&output.stderr).replace(token, "[REDACTED]");
        return Err(anyhow::anyhow!(
            "Git with gateway credentials failed ({status}): {stderr}"
        ));
    }
    Ok(())
}

fn unset_git_config(repo_path: &Path, key: &str, pattern: Option<&str>) -> Result<()> {
    let mut command = Command::new("git");
    command.args(["config", "--local", "--unset-all", key]);
    if let Some(pattern) = pattern {
        command.arg(pattern);
    }
    let output = command
        .current_dir(repo_path)
        .output()
        .with_context(|| format!("removing Git setting {key}"))?;
    match output.status.code() {
        Some(0) | Some(5) => Ok(()),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("removing Git setting {key}: {stderr}"))
        }
    }
}

fn set_remote_url(repo_path: &Path, remote: &str, url: &str) -> Result<()> {
    if Command::new("git")
        .args(["remote", "add", remote, url])
        .current_dir(repo_path)
        .success()
        .is_err()
    {
        Command::new("git")
            .args(["remote", "set-url", remote, url])
            .current_dir(repo_path)
            .success()?;
    }
    Ok(())
}

pub fn needs_sanitize_impl(repo_path: &Path) -> Result<bool> {
    if git_operation_in_progress(repo_path)? {
        return Ok(true);
    }

    let has_head = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .current_dir(repo_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !has_head {
        return Ok(true);
    }

    let status = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .current_dir(repo_path)
        .output()
        .context("checking repository status before sanitize")?;
    if !status.status.success() {
        return Ok(true);
    }

    Ok(!status.stdout.is_empty())
}

fn git_operation_in_progress(repo_path: &Path) -> Result<bool> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(repo_path)
        .output()
        .context("resolving git directory before sanitize")?;
    if !output.status.success() {
        return Ok(true);
    }

    let git_dir = String::from_utf8(output.stdout).context("git directory path was not UTF-8")?;
    let git_dir = git_dir.trim();
    let git_dir = Path::new(git_dir);
    let git_dir = if git_dir.is_absolute() {
        git_dir.to_path_buf()
    } else {
        repo_path.join(git_dir)
    };

    for marker in [
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "BISECT_LOG",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
    ] {
        if git_dir.join(marker).exists() {
            return Ok(true);
        }
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// Hook installation
// ---------------------------------------------------------------------------

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

/// Create (or reset) a local branch at `base` and optionally set upstream.
fn create_or_reset_branch(repo_path: &Path, branch: &GitSetupBranch) -> Result<()> {
    let name = &branch.name;
    let base = &branch.base;

    let branch_exists = Command::new("git")
        .args([
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{name}"),
        ])
        .current_dir(repo_path)
        .success()
        .is_ok();

    if branch_exists {
        Command::new("git")
            .args(["branch", "-f", "--no-track", name, base])
            .current_dir(repo_path)
            .success()
            .with_context(|| format!("resetting branch '{name}' to '{base}'"))?;
    } else {
        Command::new("git")
            .args(["branch", "--no-track", name, base])
            .current_dir(repo_path)
            .success()
            .with_context(|| format!("creating branch '{name}' from '{base}'"))?;
    }

    if let Some(ref upstream) = branch.upstream {
        Command::new("git")
            .args(["branch", "--set-upstream-to", upstream, name])
            .current_dir(repo_path)
            .success()
            .with_context(|| format!("setting upstream of '{name}' to '{upstream}'"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Submodule types and detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SubmoduleEntry {
    name: String,
    path: String,
    displaypath: String,
}

/// Detect submodules by parsing .gitmodules, recursing into nested ones
/// after they are cloned.  Returns entries sorted parents-before-children.
fn detect_submodules_from_gitmodules(repo_path: &Path, prefix: &str) -> Vec<SubmoduleEntry> {
    let gitmodules_path = repo_path.join(".gitmodules");
    if !gitmodules_path.exists() {
        return Vec::new();
    }
    let output = match Command::new("git")
        .args([
            "config",
            "--file",
            ".gitmodules",
            "--get-regexp",
            r"submodule\..*\.path",
        ])
        .current_dir(repo_path)
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let mut subs = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        // Lines look like: submodule.foo.path libs/foo
        let mut parts = line.splitn(2, ' ');
        let key = match parts.next() {
            Some(k) => k,
            None => continue,
        };
        let path = match parts.next() {
            Some(p) => p.to_string(),
            None => continue,
        };
        // Extract name from "submodule.<name>.path"
        let name = key
            .strip_prefix("submodule.")
            .and_then(|s| s.strip_suffix(".path"))
            .unwrap_or(&path)
            .to_string();
        let displaypath = if prefix.is_empty() {
            path.clone()
        } else {
            format!("{prefix}/{path}")
        };
        subs.push(SubmoduleEntry {
            name,
            path,
            displaypath,
        });
    }
    subs
}

fn detect_existing_submodules_recursive(parent_dir: &Path, prefix: &str) -> Vec<SubmoduleEntry> {
    let submodules = detect_submodules_from_gitmodules(parent_dir, prefix);
    let mut all = Vec::new();
    for sub in submodules {
        let sub_worktree = parent_dir.join(&sub.path);
        // An uninitialized submodule leaves at most an empty
        // placeholder directory in the worktree.  Git commands run
        // there resolve to the parent repo and would rewrite its
        // config, so only include submodules with a gitlink.
        if !sub_worktree.join(".git").exists() {
            continue;
        }
        all.push(sub.clone());
        all.extend(detect_existing_submodules_recursive(
            &sub_worktree,
            &sub.displaypath,
        ));
    }
    all
}

fn submodule_parent_dir(container_repo_path: &Path, sub: &SubmoduleEntry) -> PathBuf {
    if sub.displaypath == sub.path {
        return container_repo_path.to_path_buf();
    }

    let suffix = format!("/{}", sub.path);
    let parent_displaypath = sub
        .displaypath
        .strip_suffix(&suffix)
        .expect("nested submodule displaypath ends with its local path");
    container_repo_path.join(parent_displaypath)
}

fn refresh_submodule_gateway_urls(
    container_repo_path: &Path,
    base_url: &str,
    token: &str,
) -> Result<()> {
    let submodules = detect_existing_submodules_recursive(container_repo_path, "");
    for sub in &submodules {
        refresh_submodule_gateway_url(container_repo_path, sub, base_url, token)?;
    }
    Ok(())
}

fn refresh_submodule_gateway_url(
    container_repo_path: &Path,
    sub: &SubmoduleEntry,
    base_url: &str,
    token: &str,
) -> Result<()> {
    let sub_path = container_repo_path.join(&sub.displaypath);
    let displaypath = &sub.displaypath;
    let sub_url = format!("{base_url}/submodules/{displaypath}/rumpelpod.git");

    let parent_dir = submodule_parent_dir(container_repo_path, sub);
    let submodule_url_key = format!("submodule.{}.url", sub.name);
    Command::new("git")
        .args(["config", &submodule_url_key, &sub_url])
        .current_dir(&parent_dir)
        .success()
        .with_context(|| format!("updating URL for submodule '{displaypath}'"))?;

    configure_gateway_urls(&sub_path, &sub_url, token)
        .with_context(|| format!("updating gateway for submodule '{displaypath}'"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Submodule setup
// ---------------------------------------------------------------------------

pub fn setup_submodules_impl(req: &GitSetupSubmodulesRequest) -> Result<()> {
    let container_repo_path = &req.repo_path;

    // Detect submodules from .gitmodules in the repo.
    let submodules = detect_submodules_from_gitmodules(container_repo_path, "");
    if submodules.is_empty() {
        return Ok(());
    }

    // Clone submodules on first entry, then recurse for nested ones.
    if req.is_first_entry {
        fn clone_recursive(
            parent_dir: &Path,
            prefix: &str,
            base_url: &str,
            token: &str,
        ) -> Result<Vec<SubmoduleEntry>> {
            let subs = detect_submodules_from_gitmodules(parent_dir, prefix);
            let mut all = Vec::new();
            for sub in &subs {
                let displaypath = &sub.displaypath;
                let sub_url = format!("{base_url}/submodules/{displaypath}/rumpelpod.git");

                Command::new("git")
                    .args(["submodule", "init", &sub.path])
                    .current_dir(parent_dir)
                    .success()?;
                let sub_name = &sub.name;
                let sub_config_key = format!("submodule.{sub_name}.url");
                Command::new("git")
                    .args(["config", &sub_config_key, &sub_url])
                    .current_dir(parent_dir)
                    .success()?;
                // Submodule paths can contain '=', so keep configuration keys
                // separate from values instead of using Git's -c key=value syntax.
                let config_count = match std::env::var("GIT_CONFIG_COUNT") {
                    Ok(value) => value.parse::<usize>().context("invalid GIT_CONFIG_COUNT")?,
                    Err(VarError::NotPresent) => 0,
                    Err(error) => return Err(error).context("reading GIT_CONFIG_COUNT"),
                };
                let new_count = config_count
                    .checked_add(2)
                    .context("GIT_CONFIG_COUNT overflow")?;
                let redirect_index = config_count + 1;
                run_git_with_secret(
                    Command::new("git")
                        .args(["submodule", "update", &sub.path])
                        .env("GIT_CONFIG_COUNT", new_count.to_string())
                        .env(
                            format!("GIT_CONFIG_KEY_{config_count}"),
                            format!("http.{sub_url}.extraHeader"),
                        )
                        .env(
                            format!("GIT_CONFIG_VALUE_{config_count}"),
                            format!("Authorization: Bearer {token}"),
                        )
                        .env(
                            format!("GIT_CONFIG_KEY_{redirect_index}"),
                            format!("http.{sub_url}.followRedirects"),
                        )
                        .env(format!("GIT_CONFIG_VALUE_{redirect_index}"), "false")
                        .current_dir(parent_dir),
                    token,
                )?;

                // Recurse into the cloned submodule for nested submodules.
                let sub_worktree = parent_dir.join(&sub.path);
                let nested = clone_recursive(&sub_worktree, displaypath, base_url, token)?;
                all.push(sub.clone());
                all.extend(nested);
            }
            Ok(all)
        }

        let all_subs = clone_recursive(container_repo_path, "", &req.base_url, &req.token)?;

        // Configure remotes, hooks, branches for all discovered submodules.
        for sub in &all_subs {
            configure_submodule(
                container_repo_path,
                sub,
                &req.base_url,
                &req.token,
                &req.pod_name,
                true,
            )?;
        }
        return Ok(());
    }

    // Re-entry: just reconfigure existing submodules.
    for sub in &submodules {
        configure_submodule(
            container_repo_path,
            sub,
            &req.base_url,
            &req.token,
            &req.pod_name,
            false,
        )?;
    }
    Ok(())
}

fn configure_submodule(
    container_repo_path: &Path,
    sub: &SubmoduleEntry,
    base_url: &str,
    token: &str,
    pod_name: &str,
    is_first_entry: bool,
) -> Result<()> {
    let sub_path = container_repo_path.join(&sub.displaypath);
    let displaypath = &sub.displaypath;
    let sub_url = format!("{base_url}/submodules/{displaypath}/rumpelpod.git");
    let push_refspec = format!("+refs/heads/*:refs/rumpelpod/*@{pod_name}");

    // Resolve the git dir (submodules use gitlink files)
    let git_dir_output = Command::new("git")
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

    configure_gateway_urls(&sub_path, &sub_url, token)?;
    let _ = Command::new("git")
        .args(["config", "--unset-all", "remote.host.fetch"])
        .current_dir(&sub_path)
        .success();
    Command::new("git")
        .args([
            "config",
            "--add",
            "remote.host.fetch",
            "+refs/heads/*:refs/remotes/host/*",
        ])
        .current_dir(&sub_path)
        .success()?;
    Command::new("git")
        .args([
            "config",
            "--add",
            "remote.host.fetch",
            "+refs/rumpelpod/host-head:refs/remotes/host/HEAD",
        ])
        .current_dir(&sub_path)
        .success()?;
    Command::new("git")
        .args(["config", "remote.host.pushurl", "PUSH_DISABLED"])
        .current_dir(&sub_path)
        .success()?;

    let _ = Command::new("git")
        .args(["config", "--unset-all", "remote.rumpelpod.push"])
        .current_dir(&sub_path)
        .success();
    Command::new("git")
        .args(["config", "--add", "remote.rumpelpod.push", &push_refspec])
        .current_dir(&sub_path)
        .success()?;
    let primary_push = format!("+refs/heads/{pod_name}:refs/rumpelpod/{pod_name}");
    Command::new("git")
        .args(["config", "--add", "remote.rumpelpod.push", &primary_push])
        .current_dir(&sub_path)
        .success()?;
    Command::new("git")
        .args([
            "config",
            "remote.rumpelpod.fetch",
            "+refs/rumpelpod/*:refs/remotes/rumpelpod/*",
        ])
        .current_dir(&sub_path)
        .success()?;

    Command::new("git")
        .args(["fetch", "host"])
        .current_dir(&sub_path)
        .success()
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

    if is_first_entry {
        let branch_name = pod_name;
        let branch_exists = Command::new("git")
            .args([
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch_name}"),
            ])
            .current_dir(&sub_path)
            .success()
            .is_ok();

        if branch_exists {
            Command::new("git")
                .args(["branch", "-f", "--no-track", branch_name, "host/HEAD"])
                .current_dir(&sub_path)
                .success()?;
        } else {
            Command::new("git")
                .args(["branch", "--no-track", branch_name, "host/HEAD"])
                .current_dir(&sub_path)
                .success()?;
        }
        Command::new("git")
            .args(["checkout", branch_name])
            .current_dir(&sub_path)
            .success()?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sanitize
// ---------------------------------------------------------------------------

pub fn sanitize_impl(repo_path: &Path) -> Result<()> {
    // Abort any in-progress operations
    for op in &[
        &["merge", "--abort"][..],
        &["rebase", "--abort"],
        &["cherry-pick", "--abort"],
        &["revert", "--abort"],
        &["am", "--abort"],
        &["bisect", "reset"],
    ] {
        let _ = Command::new("git")
            .args(*op)
            .current_dir(repo_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Check if HEAD is valid
    let has_head = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repo_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if has_head {
        Command::new("git")
            .args(["reset", "--hard", "HEAD"])
            .current_dir(repo_path)
            .success()?;
    } else {
        let _ = Command::new("git")
            .args(["rm", "--cached", "-r", "."])
            .current_dir(repo_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Command::new("git")
        .args(["clean", "-fd"])
        .current_dir(repo_path)
        .success()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{run_git_with_secret, setup_git_impl, GitSetupRequest};
    use crate::command_ext::CommandExt;

    #[test]
    fn gateway_credential_errors_do_not_expose_token() {
        let repo = tempfile::tempdir().expect("creating repository directory");
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(repo.path())
            .success()
            .expect("initializing repository");
        let url = "http://127.0.0.1:1/rumpelpod.git";
        // Multiple values force the credential write to fail before any fetch,
        // exercising the error reported during pod startup.
        for value in ["first", "second"] {
            Command::new("git")
                .args(["config", "--add", &format!("http.{url}.extraHeader"), value])
                .current_dir(repo.path())
                .success()
                .expect("setting conflicting headers");
        }
        let token = "secret-that-must-not-appear-in-errors";
        let error = setup_git_impl(&GitSetupRequest {
            repo_path: repo.path().to_path_buf(),
            url: url.to_string(),
            token: token.to_string(),
            pod_name: "auth-error".to_string(),
            extra_host_fetch: Vec::new(),
            branches: Vec::new(),
            primary: "auth-error".to_string(),
            git_identity: None,
            remotes: Vec::new(),
            description_file: None,
        })
        .expect_err("multiple header values must reject the credential write");
        let error = format!("{error:#}");
        assert!(
            error.contains("multiple values"),
            "unexpected error: {error}"
        );
        assert!(
            !error.contains(token),
            "credential appeared in the Git error"
        );

        let error = run_git_with_secret(
            Command::new("git")
                .args([
                    "config",
                    &format!("http.{url}.extraHeader"),
                    &format!("Authorization: Bearer {token}"),
                ])
                .env("GIT_TRACE", "1")
                .current_dir(repo.path()),
            token,
        )
        .expect_err("the credential write must also fail with Git tracing enabled");
        let error = format!("{error:#}");
        assert!(
            error.contains("[REDACTED]"),
            "expected a redacted Git trace"
        );
        assert!(
            !error.contains(token),
            "credential appeared in the Git trace error"
        );
    }

    #[test]
    fn gateway_credentials_remove_stale_scopes() {
        let repo = tempfile::tempdir().expect("creating repository directory");
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(repo.path())
            .success()
            .expect("initializing repository");
        let old_url = "http://127.0.0.1:2/rumpelpod.git";
        let new_url = "http://127.0.0.1:1/rumpelpod.git";
        for remote in ["host", "rumpelpod"] {
            Command::new("git")
                .args(["remote", "add", remote, old_url])
                .current_dir(repo.path())
                .success()
                .expect("setting previous gateway URL");
        }
        for (key, value) in [
            (
                format!("http.{old_url}.extraHeader"),
                "Authorization: Bearer old-token",
            ),
            (
                "http.extraHeader".to_string(),
                "Authorization: Bearer baked-token",
            ),
            ("http.extraHeader".to_string(), "X-Unrelated: keep"),
        ] {
            Command::new("git")
                .args(["config", "--add", &key, value])
                .current_dir(repo.path())
                .success()
                .expect("setting baked checkout headers");
        }
        // Setup writes the gateway configuration before fetching. A closed local
        // port lets this exercise replacement without a running container backend.
        let error = setup_git_impl(&GitSetupRequest {
            repo_path: repo.path().to_path_buf(),
            url: new_url.to_string(),
            token: "new-token".to_string(),
            pod_name: "auth-refresh".to_string(),
            extra_host_fetch: Vec::new(),
            branches: Vec::new(),
            primary: "auth-refresh".to_string(),
            git_identity: None,
            remotes: Vec::new(),
            description_file: None,
        })
        .expect_err("the new gateway is not listening yet");
        assert!(
            format!("{error:#}").contains("fetch"),
            "unexpected error: {error:#}"
        );

        for url in [old_url, "https://example.invalid/unrelated.git"] {
            let headers = Command::new("git")
                .args(["config", "--get-urlmatch", "http.extraHeader", url])
                .current_dir(repo.path())
                .success()
                .expect("reading headers for unrelated URL");
            assert_eq!(headers, b"X-Unrelated: keep\n");
        }
        let headers = Command::new("git")
            .args(["config", "--get-urlmatch", "http.extraHeader", new_url])
            .current_dir(repo.path())
            .success()
            .expect("reading current gateway headers");
        assert_eq!(headers, b"Authorization: Bearer new-token\n");
    }
}
