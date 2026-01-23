//! Review sandbox changes using git difftool.
//!
//! This module implements the `sandbox review` command, which shows the diff
//! between a sandbox's primary branch and the merge base with its upstream.

use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::cli::ReviewCommand;
use crate::config::SandboxConfig;
use crate::enter::launch_sandbox;
use crate::git::get_repo_root;

/// Get the upstream branch for a branch inside the sandbox.
/// Returns the upstream in the format "host/<branch>" or None if no upstream is set.
fn get_sandbox_upstream(
    container_id: &str,
    user: &str,
    repo_path: &str,
    branch: &str,
) -> Result<Option<String>> {
    // Use git rev-parse to get the upstream tracking branch
    let result = Command::new("docker")
        .arg("exec")
        .args(["--user", user])
        .args(["--workdir", repo_path])
        .arg(container_id)
        .args([
            "git",
            "rev-parse",
            "--abbrev-ref",
            &format!("{}@{{upstream}}", branch),
        ])
        .output()
        .context("Failed to execute docker exec")?;

    if !result.status.success() {
        // No upstream set
        return Ok(None);
    }

    let upstream = String::from_utf8_lossy(&result.stdout).trim().to_string();
    if upstream.is_empty() {
        Ok(None)
    } else {
        Ok(Some(upstream))
    }
}

pub fn review(cmd: &ReviewCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let config = SandboxConfig::load(&repo_root)?;
    let container_repo_path = config.repo_path.to_string_lossy().to_string();

    // Launch the sandbox (or ensure it's running)
    let launch_result = launch_sandbox(&cmd.name)?;
    let container_id = &launch_result.container_id.0;
    let user = &launch_result.user;

    // Get the upstream of the sandbox's primary branch
    let upstream = get_sandbox_upstream(container_id, user, &container_repo_path, &cmd.name)?;

    let upstream = match upstream {
        Some(u) => u,
        None => {
            bail!(
                "Sandbox '{}' has no upstream branch set.\n\
                 This typically happens when the sandbox was created while the host \
                 was in detached HEAD state (not on a branch).\n\
                 The review command requires an upstream to compute the merge base.",
                cmd.name
            );
        }
    };

    // Parse the upstream to extract the host branch name
    // The upstream is in the format "host/<branch>"
    let host_branch = upstream
        .strip_prefix("host/")
        .with_context(|| format!("Unexpected upstream format: {}", upstream))?;

    // Verify the sandbox remote-tracking ref exists on the host
    let sandbox_ref = format!("sandbox/{}", cmd.name);
    let ref_check = Command::new("git")
        .args([
            "rev-parse",
            "--verify",
            &format!("refs/remotes/{}", sandbox_ref),
        ])
        .current_dir(&repo_root)
        .output()
        .context("Failed to check sandbox ref")?;

    if !ref_check.status.success() {
        bail!(
            "Sandbox ref '{}' not found in host repository.\n\
             Make sure the sandbox has made at least one commit.",
            sandbox_ref
        );
    }

    // Compute the merge base between the sandbox branch and the host branch
    let merge_base_output = Command::new("git")
        .args(["merge-base", &sandbox_ref, host_branch])
        .current_dir(&repo_root)
        .output()
        .context("Failed to compute merge base")?;

    if !merge_base_output.status.success() {
        let stderr = String::from_utf8_lossy(&merge_base_output.stderr);
        bail!(
            "Failed to compute merge base between '{}' and '{}':\n{}",
            sandbox_ref,
            host_branch,
            stderr.trim()
        );
    }

    let merge_base = String::from_utf8_lossy(&merge_base_output.stdout)
        .trim()
        .to_string();

    // Invoke git difftool to show the diff
    // Use --no-prompt (-y) to avoid prompting for each file
    let status = Command::new("git")
        .args(["difftool", "-y", &merge_base, &sandbox_ref])
        .current_dir(&repo_root)
        .status()
        .context("Failed to run git difftool")?;

    if !status.success() {
        bail!("git difftool exited with status {}", status);
    }

    Ok(())
}
