use std::process::Command;

use anyhow::{Context, Result};

use crate::cli::MergeCommand;
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

    let pod = crate::pod::PodClient::new(&result.container_url, &result.container_token)?;
    let run_result = pod
        .run(
            &[
                "git",
                "-C",
                &container_repo_path.to_string_lossy(),
                "status",
                "--porcelain",
            ],
            Some(&result.user),
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
        return Err(anyhow::anyhow!(
            "git status in pod '{}' failed: {}",
            pod_name,
            stderr.trim()
        ));
    }

    use base64::Engine;
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(&run_result.stdout)
        .unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout);
    if !stdout.trim().is_empty() {
        eprintln!("warning: pod '{}' has uncommitted changes", pod_name);
    }

    Ok(())
}

pub fn merge(cmd: &MergeCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    // 1. Verify the pod exists in the daemon
    let pods = client.list_pods(repo_root.clone())?;
    if !pods.iter().any(|p| p.name == cmd.name) {
        return Err(anyhow::anyhow!("pod '{}' not found", cmd.name));
    }

    // 2. Verify the pod ref exists on the host
    let pod_ref = format!("rumpelpod/{}", cmd.name);
    let ref_check = Command::new("git")
        .args([
            "rev-parse",
            "--verify",
            &format!("refs/remotes/{}", pod_ref),
        ])
        .current_dir(&repo_root)
        .output()
        .context("Failed to check pod ref")?;

    if !ref_check.status.success() {
        return Err(anyhow::anyhow!(
            "Pod ref '{}' not found in host repository.\n\
             Make sure the pod has made at least one commit.",
            pod_ref
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
        eprintln!(
            "warning: nothing to merge -- host is already up to date with pod '{}'",
            cmd.name
        );
        client.stop_pod(PodName(cmd.name.clone()), repo_root, false)?;
        return Ok(());
    }

    // 5. Run git merge with passthrough flags
    let mut merge_cmd = Command::new("git");
    merge_cmd.arg("merge");
    for arg in &cmd.git_args {
        merge_cmd.arg(arg);
    }
    merge_cmd.arg(&pod_ref);
    merge_cmd.current_dir(&repo_root);

    let merge_status = merge_cmd.status().context("Failed to run git merge")?;

    let merge_failed = !merge_status.success();
    if merge_failed {
        eprintln!(
            "warning: git merge exited with status {}",
            merge_status.code().unwrap_or(-1)
        );
    }

    // 6. Stop pod unconditionally
    client.stop_pod(PodName(cmd.name.clone()), repo_root, false)?;

    // 7. Propagate merge failure
    if merge_failed {
        return Err(anyhow::anyhow!("git merge failed"));
    }

    Ok(())
}
