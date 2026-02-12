//! Integration tests for the `rumpel list` subcommand.

#[cfg(not(target_os = "macos"))]
use super::ssh::{create_ssh_config, write_remote_pod_config, SshRemoteHost, SSH_USER};
use crate::common::{build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo};

#[test]
fn list_empty_returns_header_only() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    assert!(
        output.status.success(),
        "rumpel list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NAME"));
    assert!(stdout.contains("GIT"));
    assert!(stdout.contains("STATUS"));
    assert!(stdout.contains("CREATED"));
    assert!(stdout.contains("HOST"));
    assert!(stdout.contains("CONTAINER ID"));
}

#[test]
fn list_shows_created_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "test-list", "--", "echo", "hello"])
        .output()
        .expect("Failed to run rumpel enter command");

    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List pods
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    assert!(
        output.status.success(),
        "rumpel list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test-list"),
        "Expected pod 'test-list' in output: {}",
        stdout
    );
    assert!(
        stdout.contains("running"),
        "Expected 'running' status in output: {}",
        stdout
    );
    assert!(
        stdout.contains("localhost"),
        "Expected 'localhost' host in output: {}",
        stdout
    );

    // Running pods should show a truncated docker container ID (12-char hex prefix)
    let lines: Vec<&str> = stdout.lines().collect();
    let pod_line = lines
        .iter()
        .find(|l| l.contains("test-list"))
        .expect("Expected pod line in output");
    let has_container_id = pod_line
        .split_whitespace()
        .any(|word| word.len() == 12 && word.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        has_container_id,
        "Expected a 12-char container ID (hex string) in pod line: {}",
        pod_line
    );
}

#[test]
fn list_shows_repo_state() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "test-state", "--", "echo", "hello"])
        .output()
        .expect("Failed to run rumpel enter command");

    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Initial state should be "up to date" (tracked via branch)
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("up to date") || stdout.contains("ahead") || stdout.contains("behind"),
        "Expected repo state in output: {}",
        stdout
    );

    // Make a commit in the pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "test-state", "--", "touch", "newfile"])
        .output()
        .expect("Failed to touch file");
    assert!(output.status.success());

    let output = pod_command(&repo, &daemon)
        .args(["enter", "test-state", "--", "git", "add", "newfile"])
        .output()
        .expect("Failed to git add");
    assert!(output.status.success());

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "test-state",
            "--",
            "git",
            "commit",
            "-m",
            "new file",
        ])
        .output()
        .expect("Failed to git commit");
    assert!(output.status.success());

    // Check list again - should show ahead
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ahead 1"),
        "Expected 'ahead 1' in output: {}",
        stdout
    );
}

#[test]
fn list_shows_multiple_pods() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create first pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "pod-one", "--", "echo", "one"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "first rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create second pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "pod-two", "--", "echo", "two"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "second rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List pods
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    assert!(
        output.status.success(),
        "rumpel list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pod-one"),
        "Expected 'pod-one' in output: {}",
        stdout
    );
    assert!(
        stdout.contains("pod-two"),
        "Expected 'pod-two' in output: {}",
        stdout
    );
}

#[test]
fn list_does_not_show_other_repo_pods() {
    let repo1 = TestRepo::new();
    let image_id1 = build_test_image(repo1.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo1, &image_id1);

    let repo2 = TestRepo::new();
    let image_id2 = build_test_image(repo2.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo2, &image_id2);

    let daemon = TestDaemon::start();

    // Create pod in repo1
    let output = pod_command(&repo1, &daemon)
        .args(["enter", "repo1-pod", "--", "echo", "repo1"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "repo1 rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create pod in repo2
    let output = pod_command(&repo2, &daemon)
        .args(["enter", "repo2-pod", "--", "echo", "repo2"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "repo2 rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List pods from repo1 - should only see repo1-pod
    let output = pod_command(&repo1, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    assert!(
        output.status.success(),
        "rumpel list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repo1-pod"),
        "Expected 'repo1-pod' in output: {}",
        stdout
    );
    assert!(
        !stdout.contains("repo2-pod"),
        "Should not see pod from other repo in output: {}",
        stdout
    );

    // List pods from repo2 - should only see repo2-pod
    let output = pod_command(&repo2, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run rumpel list command");

    assert!(
        output.status.success(),
        "rumpel list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repo2-pod"),
        "Expected 'repo2-pod' in output: {}",
        stdout
    );
    assert!(
        !stdout.contains("repo1-pod"),
        "Should not see pod from other repo in output: {}",
        stdout
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn ssh_remote_pod_list() {
    let repo = TestRepo::new();

    // Build test image locally
    let image_id =
        crate::common::build_test_image(repo.path(), "").expect("Failed to build test image");

    // Start remote host and load the image
    let remote = SshRemoteHost::start();
    remote
        .load_image(&image_id)
        .expect("Failed to load image into remote Docker");

    // Create SSH config and start daemon
    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    // Write pod config
    write_remote_pod_config(&repo, &image_id, &remote.ssh_spec());

    // Create a pod on the remote
    let output = pod_command(&repo, &daemon)
        .args(["enter", "list-test-remote", "--", "true"])
        .output()
        .expect("rumpel enter failed to execute");
    assert!(
        output.status.success(),
        "rumpel enter failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // List should show the pod with the remote host
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("rumpel list failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rumpel list failed: stdout={}, stderr={}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("list-test-remote"),
        "rumpel list should show the pod: stdout={}, stderr={}",
        stdout,
        stderr
    );
    // The remote host should be shown as "testuser@<ip>"
    assert!(
        stdout.contains(&format!("{}@", SSH_USER)),
        "rumpel list should show the remote host: stdout={}, stderr={}",
        stdout,
        stderr
    );
}
