//! Integration tests for the `rumpel delete` subcommand.

use std::io::Write;
use std::process::Stdio;

use crate::common::{build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo};

use super::agent::llm_cache_dir;
use super::ssh::{create_ssh_config, write_remote_pod_config, SshRemoteHost};

#[test]
fn delete_smoke_test() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First create a pod by entering it
    let output = pod_command(&repo, &daemon)
        .args(["enter", "test-delete", "--", "echo", "created"])
        .output()
        .expect("Failed to run rumpel enter command");

    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Now delete the pod
    let output = pod_command(&repo, &daemon)
        .args(["delete", "--wait", "test-delete"])
        .output()
        .expect("Failed to run rumpel delete command");

    assert!(
        output.status.success(),
        "rumpel delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn delete_unknown_pod_fails() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["delete", "nonexistent"])
        .output()
        .expect("Failed to run rumpel delete command");

    assert!(
        !output.status.success(),
        "rumpel delete of unknown pod should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found"),
        "Expected 'not found' in stderr: {}",
        stderr
    );
}

/// Helper: create a pod and make a commit inside it so it becomes "ahead 1".
fn create_ahead_pod(repo: &TestRepo, daemon: &TestDaemon, name: &str) {
    let output = pod_command(repo, daemon)
        .args(["enter", name, "--", "touch", "newfile"])
        .output()
        .expect("Failed to touch file");
    assert!(output.status.success(), "touch failed");

    let output = pod_command(repo, daemon)
        .args(["enter", name, "--", "git", "add", "newfile"])
        .output()
        .expect("Failed to git add");
    assert!(output.status.success(), "git add failed");

    let output = pod_command(repo, daemon)
        .args(["enter", name, "--", "git", "commit", "-m", "new file"])
        .output()
        .expect("Failed to git commit");
    assert!(output.status.success(), "git commit failed");
}

#[test]
fn delete_unmerged_pod_fails_without_tty() {
    // In non-tty mode (piped output), deleting an unmerged pod should fail
    // with a helpful error message.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    create_ahead_pod(&repo, &daemon, "unmerged");

    // pod_command pipes stdout/stderr, so this is non-tty
    let output = pod_command(&repo, &daemon)
        .args(["delete", "unmerged"])
        .output()
        .expect("Failed to run rumpel delete command");

    assert!(
        !output.status.success(),
        "delete of unmerged pod should fail without --force"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unmerged commits") && stderr.contains("--force"),
        "Expected 'unmerged commits' and '--force' hint in stderr: {}",
        stderr
    );
}

#[test]
fn delete_unmerged_pod_succeeds_with_force() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    create_ahead_pod(&repo, &daemon, "force-del");

    let output = pod_command(&repo, &daemon)
        .args(["delete", "--wait", "--force", "force-del"])
        .output()
        .expect("Failed to run rumpel delete command");

    assert!(
        output.status.success(),
        "delete with --force should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify pod is gone
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("force-del"),
        "pod should be gone after forced delete: {}",
        stdout
    );
}

#[test]
fn delete_then_recreate_same_name() {
    // After deleting a pod, we should be able to create a new one with the same name.
    // This verifies that all resources (container, network) are properly cleaned up.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "recyclable", "--", "echo", "first"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "first rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Delete pod (--wait so the container is fully gone before re-entering)
    let output = pod_command(&repo, &daemon)
        .args(["delete", "--wait", "recyclable"])
        .output()
        .expect("Failed to run rumpel delete command");
    assert!(
        output.status.success(),
        "rumpel delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create pod with the same name again
    let output = pod_command(&repo, &daemon)
        .args(["enter", "recyclable", "--", "echo", "second"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "second rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Helper to run agent with a prompt, returning the output.
fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    pod_name: &str,
    prompt: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let cache_dir = llm_cache_dir();
    let mut cmd = pod_command(repo, daemon);
    cmd.args(["agent", pod_name, "--model", "claude-haiku-4-5", "--cache"]);
    cmd.arg(cache_dir);
    cmd.args(extra_args);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn agent");

    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    writeln!(stdin, "{}", prompt).expect("Failed to write to stdin");
    drop(child.stdin.take());

    child.wait_with_output().expect("Failed to wait for agent")
}

#[test]
fn delete_pod_clears_conversation_history() {
    // Deleting a pod should also delete all conversation history for that pod.
    // This test verifies that after deletion, an agent started in a recreated pod
    // with the same name does NOT have access to the old conversation history.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First, create a conversation and tell the agent a secret
    let unique_marker = "PELICAN_GAMMA_5555";
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "history-test",
        &format!("Remember this code: {unique_marker}. Acknowledge."),
        &[],
    );
    assert!(
        output1.status.success(),
        "First agent run should succeed: {}",
        String::from_utf8_lossy(&output1.stderr)
    );

    // Delete the pod (--wait so history is cleared before re-entering)
    let output = pod_command(&repo, &daemon)
        .args(["delete", "--wait", "history-test"])
        .output()
        .expect("Failed to run rumpel delete command");
    assert!(
        output.status.success(),
        "rumpel delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Now start a new agent in a pod with the same name and ask about the code.
    // Since the pod was deleted, the conversation history should be gone,
    // and the agent should NOT know the code.
    let output2 = run_agent_with_prompt(
        &repo,
        &daemon,
        "history-test",
        "Do you remember any code I asked you to remember? If so, what is it?",
        &[],
    );
    assert!(
        output2.status.success(),
        "Second agent run should succeed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        !stdout2.contains("PELICAN") && !stdout2.contains("GAMMA") && !stdout2.contains("5555"),
        "Agent should NOT remember the code after pod deletion.\n\
         This indicates conversation history was not deleted.\nstdout: {}",
        stdout2
    );
}

#[test]
fn ssh_remote_pod_delete() {
    let repo = TestRepo::new();

    // Build test image locally
    let image_id =
        crate::common::build_test_image(repo.path(), "").expect("Failed to build test image");

    // Start remote host and load the image
    let remote = SshRemoteHost::start();
    let remote_image_id = remote
        .load_image(&image_id)
        .expect("Failed to load image into remote Docker");

    // Create SSH config and start daemon
    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    // Write pod config
    write_remote_pod_config(&repo, &remote_image_id, &remote.ssh_spec());

    // Create a pod on the remote
    let pod_name = "delete-test-remote";
    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "true"])
        .output()
        .expect("rumpel enter failed to execute");
    assert!(
        output.status.success(),
        "rumpel enter failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify it exists in list
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("rumpel list failed to execute");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(pod_name),
        "pod should exist before delete"
    );

    // Delete the pod (--wait so it's fully gone before checking list)
    let output = pod_command(&repo, &daemon)
        .args(["delete", "--wait", pod_name])
        .output()
        .expect("rumpel delete failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rumpel delete failed: stdout={}, stderr={}",
        stdout,
        stderr
    );

    // Verify it is gone from list
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("rumpel list failed to execute");

    let stdout_list = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout_list.contains(pod_name),
        "pod should not exist after delete in list output: {}",
        stdout_list
    );

    // Verify container is gone on remote host
    let remote_containers = remote
        .ssh_command(
            &ssh_config.path,
            &["docker", "ps", "-a", "--format", "{{.Names}}"],
        )
        .expect("docker ps failed");
    let remote_containers_str = String::from_utf8_lossy(&remote_containers);

    // The container name usually contains the pod name.
    assert!(
        !remote_containers_str.contains(pod_name),
        "remote container should be deleted: {}",
        remote_containers_str
    );
}
