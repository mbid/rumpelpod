use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::cli::MergeCommand;
use crate::config::{load_toml_config, DescriptionFileSetting};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, PodName};
use crate::enter;
use crate::git::get_repo_root;

/// Check for uncommitted changes inside the pod container.
/// Prints a warning to stderr if the working tree is dirty.
fn check_dirty_checkout(pod_name: &str, repo_root: &Path) -> Result<()> {
    let result = enter::launch_pod(pod_name, None)?;
    let (devcontainer, _, _default_image_dir) = enter::load_and_resolve(repo_root, None)?;
    let container_repo_path = devcontainer.container_repo_path(repo_root);

    let pod = crate::pod::PodClient::connect(&result.container_url, &result.container_token)?;
    let run_result = pod
        .run(
            &[
                "git",
                "-C",
                &container_repo_path.to_string_lossy(),
                "status",
                "--porcelain",
            ],
            None,
            &[],
            None,
            Some(30),
        )
        .context("Failed to check pod working tree status")?;

    if run_result.exit_code != 0 {
        use base64::Engine;
        let stderr = base64::engine::general_purpose::STANDARD
            .decode(&run_result.stderr)
            .unwrap_or_default();
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr = stderr.trim();
        return Err(anyhow::anyhow!(
            "git status in pod '{pod_name}' failed: {stderr}"
        ));
    }

    use base64::Engine;
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(&run_result.stdout)
        .unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout);
    if !stdout.trim().is_empty() {
        eprintln!("warning: pod '{pod_name}' has uncommitted changes");
    }

    Ok(())
}

// -- description file helpers ------------------------------------------------

struct Description {
    content: String,
    path: String,
}

/// Read a file from a git ref. Returns None if the file does not exist.
fn read_file_from_ref(repo_root: &Path, git_ref: &str, path: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["show", &format!("{git_ref}:{path}")])
        .current_dir(repo_root)
        .stderr(Stdio::null())
        .output()
        .context("Failed to read file from git ref")?;

    if !output.status.success() {
        return Ok(None);
    }

    let contents =
        String::from_utf8(output.stdout).context("Description file is not valid UTF-8")?;
    let trimmed = contents.trim_end();

    if trimmed.is_empty() {
        return Ok(None);
    }

    Ok(Some(trimmed.to_string()))
}

/// Check whether a file exists in a git ref.
fn file_exists_in_ref(repo_root: &Path, git_ref: &str, path: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["cat-file", "-e", &format!("{git_ref}:{path}")])
        .current_dir(repo_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to check file in git ref")?;
    Ok(status.success())
}

/// Decide whether to use a description file for the merge commit message.
///
/// Resolution order: CLI flags > config.
///
/// --description-file <path> requires the file to exist on the pod branch.
/// The config path is best-effort -- if the file is absent on the pod
/// branch, merge proceeds without it.
fn resolve_description(
    repo_root: &Path,
    pod_ref: &str,
    config: &DescriptionFileSetting,
    cli_file: Option<&str>,
    cli_no_file: bool,
) -> Result<Option<Description>> {
    if cli_no_file {
        return Ok(None);
    }

    // --description-file requires the file to exist
    if let Some(path) = cli_file {
        return match read_file_from_ref(repo_root, pod_ref, path)? {
            Some(content) => Ok(Some(Description {
                content,
                path: path.to_string(),
            })),
            None => Err(anyhow::anyhow!(
                "description file '{path}' not found on pod branch"
            )),
        };
    }

    // Config path is best-effort: use it if found, skip if absent
    match config {
        DescriptionFileSetting::Disabled => Ok(None),
        DescriptionFileSetting::Path(path) => Ok(read_file_from_ref(repo_root, pod_ref, path)?
            .map(|content| Description {
                content,
                path: path.clone(),
            })),
    }
}

/// Remove the description file from HEAD and amend the commit.
fn remove_description_file(repo_root: &Path, description_path: &str) -> Result<()> {
    if !file_exists_in_ref(repo_root, "HEAD", description_path)? {
        return Ok(());
    }

    let rm_status = Command::new("git")
        .args(["rm", description_path])
        .current_dir(repo_root)
        .stdout(Stdio::null())
        .status()
        .context("Failed to git rm description file")?;

    if !rm_status.success() {
        return Err(anyhow::anyhow!("git rm {description_path} failed"));
    }

    let amend_status = Command::new("git")
        .args(["commit", "--amend", "--no-edit"])
        .current_dir(repo_root)
        .status()
        .context("Failed to amend merge commit")?;

    if !amend_status.success() {
        return Err(anyhow::anyhow!(
            "Failed to amend merge commit to remove {description_path}"
        ));
    }

    Ok(())
}

// -- main entry point --------------------------------------------------------

pub fn merge(cmd: &MergeCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let toml_config = load_toml_config(&repo_root)?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    // 1. Verify the pod exists in the daemon
    let pods = client.list_pods(repo_root.clone())?;
    if !pods.iter().any(|p| p.name == cmd.name) {
        let name = &cmd.name;
        return Err(anyhow::anyhow!("pod '{name}' not found"));
    }

    // 2. Verify the pod ref exists on the host
    let name = &cmd.name;
    let pod_ref = format!("rumpelpod/{name}");
    let ref_check = Command::new("git")
        .args(["rev-parse", "--verify", &format!("refs/remotes/{pod_ref}")])
        .current_dir(&repo_root)
        .output()
        .context("Failed to check pod ref")?;

    if !ref_check.status.success() {
        return Err(anyhow::anyhow!(
            "Pod ref '{pod_ref}' not found in host repository.\n\
             Make sure the pod has made at least one commit."
        ));
    }

    // 3. Warn about uncommitted changes in the pod
    check_dirty_checkout(&cmd.name, &repo_root)?;

    // 4. Check if there is nothing to merge (pod ref is ancestor of HEAD)
    let ancestor_check = Command::new("git")
        .args(["merge-base", "--is-ancestor", &pod_ref, "HEAD"])
        .current_dir(&repo_root)
        .status()
        .context("Failed to run merge-base --is-ancestor")?;

    if ancestor_check.success() {
        let name = &cmd.name;
        eprintln!("warning: nothing to merge -- host is already up to date with pod '{name}'");
        client.stop_pod(PodName(cmd.name.clone()), repo_root, false)?;
        return Ok(());
    }

    // 5. Resolve the description file
    let description = resolve_description(
        &repo_root,
        &pod_ref,
        &toml_config.merge.description_file,
        cmd.description_file.as_deref(),
        cmd.no_description_file,
    )?;

    // 6. Run git merge with passthrough flags
    let mut merge_cmd = Command::new("git");
    merge_cmd.arg("merge");

    if let Some(ref desc) = description {
        if !cmd.git_args.iter().any(|a| a == "--no-ff") {
            merge_cmd.arg("--no-ff");
        }
        merge_cmd.args(["-m", &desc.content]);
    }

    for arg in &cmd.git_args {
        merge_cmd.arg(arg);
    }
    merge_cmd.arg(&pod_ref);
    merge_cmd.current_dir(&repo_root);

    let merge_status = merge_cmd.status().context("Failed to run git merge")?;

    if !merge_status.success() {
        let code = merge_status.code().unwrap_or(-1);
        // Abort the merge so the working tree is not left in a conflicted state.
        let abort_status = Command::new("git")
            .args(["merge", "--abort"])
            .current_dir(&repo_root)
            .status();
        if let Err(e) = abort_status {
            eprintln!("warning: failed to abort merge: {e}");
        }
        return Err(anyhow::anyhow!("git merge exited with status {code}"));
    }

    // 7. Remove the description file from the merge result
    if let Some(ref desc) = description {
        remove_description_file(&repo_root, &desc.path)?;
    }

    // Only stop pod after successful merge
    client.stop_pod(PodName(cmd.name.clone()), repo_root, false)?;

    Ok(())
}
