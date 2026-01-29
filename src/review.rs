//! Review sandbox changes using git difftool.
//!
//! This module implements the `sandbox review` command, which shows the diff
//! between a sandbox's primary branch and the merge base with its upstream.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

use crate::cli::ReviewCommand;
use crate::config::SandboxConfig;
use crate::enter::launch_sandbox;
use crate::git::get_repo_root;

/// Translate a difftool name to its executable path.
/// This mirrors Git's `translate_merge_tool_path()` logic from the mergetools/ directory.
///
/// Git has built-in knowledge of certain tool aliases that map to different executables.
/// For example, "nvimdiff" is not a real executable - it needs to be translated to "nvim".
///
/// This function implements the same mappings as Git's built-in mergetool definitions.
fn translate_tool_path(tool: &str) -> String {
    // vimdiff variants (from mergetools/vimdiff)
    // These cover: vimdiff, vimdiff1, vimdiff2, vimdiff3 and g/n prefixed versions
    if tool.starts_with("nvimdiff") {
        return "nvim".to_string();
    }
    if tool.starts_with("gvimdiff") {
        return "gvim".to_string();
    }
    if tool.starts_with("vimdiff") {
        return "vim".to_string();
    }

    // Other common tool mappings from Git's mergetools/
    match tool {
        "araxis" => "compare".to_string(),
        "emerge" => "emacs".to_string(),
        "vscode" => "code".to_string(),
        "deltawalker" => "DeltaWalker".to_string(),

        // bc (Beyond Compare) - we use the simpler form here
        // Git checks if bcomp exists first, but we'll let the OS handle that
        "bc" | "bc3" | "bc4" => "bcomp".to_string(),

        // Tools where the name matches the executable (no translation needed)
        // Including: meld, kdiff3, diffuse, kompare, tkdiff, xxdiff, opendiff,
        // p4merge, smerge, diffmerge, ecmerge, guiffy, tortoisemerge, etc.
        _ => tool.to_string(),
    }
}

/// Get the configured difftool name from git config.
fn get_difftool_name(repo_root: &std::path::Path) -> Result<String> {
    let output = Command::new("git")
        .args(["config", "--get", "diff.tool"])
        .current_dir(repo_root)
        .output()
        .context("Failed to query git config for diff.tool")?;

    if !output.status.success() {
        bail!(
            "No difftool configured. Set one with:\n  \
             git config diff.tool <toolname>\n  \
             git config difftool.<toolname>.cmd '<command>'"
        );
    }

    let tool = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tool.is_empty() {
        bail!("diff.tool is set but empty");
    }

    Ok(tool)
}

/// Get the executable path for a difftool.
/// This mirrors Git's logic in git-mergetool--lib.sh:
/// 1. Check difftool.<tool>.path config
/// 2. Check mergetool.<tool>.path config  
/// 3. Fall back to translate_tool_path()
fn get_tool_path(repo_root: &std::path::Path, tool: &str) -> Result<String> {
    // First check difftool.<tool>.path
    let difftool_path_key = format!("difftool.{}.path", tool);
    let output = Command::new("git")
        .args(["config", "--get", &difftool_path_key])
        .current_dir(repo_root)
        .output()
        .context("Failed to query git config for difftool path")?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(path);
        }
    }

    // Then check mergetool.<tool>.path
    let mergetool_path_key = format!("mergetool.{}.path", tool);
    let output = Command::new("git")
        .args(["config", "--get", &mergetool_path_key])
        .current_dir(repo_root)
        .output()
        .context("Failed to query git config for mergetool path")?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(path);
        }
    }

    // Fall back to translating the tool name
    Ok(translate_tool_path(tool))
}

/// Get the command for a difftool from git config.
/// Returns None if no custom command is configured (meaning it's a built-in tool).
fn get_difftool_cmd(repo_root: &std::path::Path, tool: &str) -> Result<Option<String>> {
    let config_key = format!("difftool.{}.cmd", tool);
    let output = Command::new("git")
        .args(["config", "--get", &config_key])
        .current_dir(repo_root)
        .output()
        .context("Failed to query git config for difftool cmd")?;

    if !output.status.success() {
        // No custom command configured - tool is either built-in or will be invoked directly
        return Ok(None);
    }

    let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if cmd.is_empty() {
        Ok(None)
    } else {
        Ok(Some(cmd))
    }
}

/// Get the list of files changed between two commits.
fn get_changed_files(repo_root: &std::path::Path, base: &str, target: &str) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", base, target])
        .current_dir(repo_root)
        .output()
        .context("Failed to get list of changed files")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to get changed files: {}", stderr.trim());
    }

    let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    Ok(files)
}

/// Get the content of a file at a specific commit.
/// Returns Ok(None) if the file doesn't exist at that commit.
fn get_file_at_commit(
    repo_root: &std::path::Path,
    commit: &str,
    file_path: &str,
) -> Result<Option<Vec<u8>>> {
    let output = Command::new("git")
        .args(["show", &format!("{}:{}", commit, file_path)])
        .current_dir(repo_root)
        .output()
        .context("Failed to get file content from commit")?;

    if !output.status.success() {
        // File doesn't exist at this commit (new or deleted file)
        return Ok(None);
    }

    Ok(Some(output.stdout))
}

/// Write content to a temporary file.
fn write_temp_file(dir: &std::path::Path, name: &str, content: Option<&[u8]>) -> Result<PathBuf> {
    let path = dir.join(name);

    // Create parent directories if the file path contains subdirectories
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create parent directories")?;
    }

    let mut file = File::create(&path).context("Failed to create temp file")?;
    if let Some(content) = content {
        file.write_all(content)
            .context("Failed to write temp file")?;
    }

    Ok(path)
}

/// Invoke the difftool for a pair of files.
fn invoke_difftool(
    tool_path: &str,
    cmd_template: Option<&str>,
    local_path: &PathBuf,
    remote_path: &PathBuf,
) -> Result<()> {
    if let Some(template) = cmd_template {
        // Custom command with $LOCAL and $REMOTE placeholders
        let cmd = template
            .replace("$LOCAL", &local_path.to_string_lossy())
            .replace("$REMOTE", &remote_path.to_string_lossy());

        Command::new("sh")
            .args(["-c", &cmd])
            .status()
            .context("Failed to run difftool command")?;
    } else {
        // Built-in tool - invoke the executable path directly with two file arguments
        Command::new(tool_path)
            .arg(local_path)
            .arg(remote_path)
            .status()
            .context("Failed to run difftool")?;
    }

    // Note: We don't check the exit status here. Many difftools return
    // non-zero when files differ, and git difftool doesn't propagate
    // individual tool exit codes as errors.

    Ok(())
}

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
    let launch_result = launch_sandbox(&cmd.name, None)?;
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

    // Get the configured difftool
    let tool = get_difftool_name(&repo_root)?;
    let cmd_template = get_difftool_cmd(&repo_root, &tool)?;
    let tool_path = get_tool_path(&repo_root, &tool)?;

    // Get the list of changed files
    let changed_files = get_changed_files(&repo_root, &merge_base, &sandbox_ref)?;

    if changed_files.is_empty() {
        // No changes to review
        return Ok(());
    }

    // Create a temporary directory for the diff files (cleaned up on drop)
    let temp_dir = TempDir::with_prefix("sandbox-review-")?;
    let local_dir = temp_dir.path().join("local");
    let remote_dir = temp_dir.path().join("remote");
    fs::create_dir_all(&local_dir).context("Failed to create local temp dir")?;
    fs::create_dir_all(&remote_dir).context("Failed to create remote temp dir")?;

    // Process each changed file
    for file_path in &changed_files {
        // Get file content at merge base (local/old version)
        let local_content = get_file_at_commit(&repo_root, &merge_base, file_path)?;

        // Get file content at sandbox ref (remote/new version)
        let remote_content = get_file_at_commit(&repo_root, &sandbox_ref, file_path)?;

        // Write temp files
        let local_file = write_temp_file(&local_dir, file_path, local_content.as_deref())?;
        let remote_file = write_temp_file(&remote_dir, file_path, remote_content.as_deref())?;

        // Invoke the difftool
        invoke_difftool(
            &tool_path,
            cmd_template.as_deref(),
            &local_file,
            &remote_file,
        )?;
    }

    Ok(())
}
