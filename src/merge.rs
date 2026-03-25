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
fn check_dirty_checkout(pod_name: &str, repo_root: &std::path::Path) -> Result<()> {
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

/// Read the description file from the pod ref, if configured.
/// Returns the trimmed file contents if found, None otherwise.
fn read_description(
    repo_root: &std::path::Path,
    pod_ref: &str,
    setting: &DescriptionFileSetting,
) -> Result<Option<String>> {
    let path = match setting {
        DescriptionFileSetting::Path(p) => p,
        DescriptionFileSetting::Disabled => return Ok(None),
    };

    let output = Command::new("git")
        .args(["show", &format!("{pod_ref}:{path}")])
        .current_dir(repo_root)
        .stderr(Stdio::null())
        .output()
        .context("Failed to read description file from pod ref")?;

    if !output.status.success() {
        return Ok(None);
    }

    let contents =
        String::from_utf8(output.stdout).context("Description file is not valid UTF-8")?;
    let contents = contents.trim_end();

    if contents.is_empty() {
        return Ok(None);
    }

    Ok(Some(contents.to_string()))
}

/// Remove the description file from HEAD and amend the commit.
fn remove_description_file(repo_root: &std::path::Path, description_path: &str) -> Result<()> {
    let in_head = Command::new("git")
        .args(["cat-file", "-e", &format!("HEAD:{description_path}")])
        .current_dir(repo_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to check description file in HEAD")?;

    if !in_head.success() {
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

    // 5. Read description file from pod branch (if configured)
    let description = read_description(&repo_root, &pod_ref, &toml_config.merge.description_file)?;

    // 6. Run git merge with passthrough flags
    let mut merge_cmd = Command::new("git");
    merge_cmd.arg("merge");

    if let Some(ref msg) = description {
        if !cmd.git_args.iter().any(|a| a == "--no-ff") {
            merge_cmd.arg("--no-ff");
        }
        merge_cmd.args(["-m", msg]);
    }

    for arg in &cmd.git_args {
        merge_cmd.arg(arg);
    }
    merge_cmd.arg(&pod_ref);
    merge_cmd.current_dir(&repo_root);

    let merge_status = merge_cmd.status().context("Failed to run git merge")?;

    if !merge_status.success() {
        let code = merge_status.code().unwrap_or(-1);
        return Err(anyhow::anyhow!("git merge exited with status {code}"));
    }

    // 7. Remove the description file from the merge result
    if description.is_some() {
        let path = match &toml_config.merge.description_file {
            DescriptionFileSetting::Path(p) => p.as_str(),
            DescriptionFileSetting::Disabled => unreachable!(),
        };
        remove_description_file(&repo_root, path)?;
    }

    // Only stop pod after successful merge
    client.stop_pod(PodName(cmd.name.clone()), repo_root, false)?;

    Ok(())
}
