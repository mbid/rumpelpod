//! Integration tests for the `rumpel list` subcommand.

use retry::delay::Exponential;
use retry::OperationResult;

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

/// Running pods should appear before stopped pods, even when the stopped pod has
/// a more recent commit.
#[test]
fn list_shows_running_pods_before_stopped() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create first pod (stays running, never gets a new commit)
    let output = pod_command(&repo, &daemon)
        .args(["enter", "active-pod", "--", "echo", "one"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "first rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create second pod and give it a newer commit so its committer date wins
    let output = pod_command(&repo, &daemon)
        .args(["enter", "halted-pod", "--", "touch", "newfile"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "second rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for args in [
        vec!["enter", "halted-pod", "--", "git", "add", "newfile"],
        vec![
            "enter",
            "halted-pod",
            "--",
            "git",
            "commit",
            "-m",
            "new file",
        ],
        vec!["stop", "halted-pod"],
    ] {
        let output = pod_command(&repo, &daemon)
            .args(&args)
            .output()
            .unwrap_or_else(|_| panic!("Failed to run: {:?}", args));
        assert!(
            output.status.success(),
            "{:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Docker may need a moment to report the container as stopped.
    // Poll until the list output reflects the stopped status.
    let stdout = retry::retry(Exponential::from_millis(100).take(8), || {
        let output = pod_command(&repo, &daemon)
            .arg("list")
            .output()
            .expect("Failed to run rumpel list command");
        assert!(
            output.status.success(),
            "rumpel list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let pod_line = stdout
            .lines()
            .find(|l| l.contains("halted-pod"))
            .unwrap_or("");
        if pod_line.contains("stopped") {
            OperationResult::Ok(stdout)
        } else {
            OperationResult::Retry(stdout)
        }
    })
    .expect("halted-pod never showed as stopped in list output");

    // Running pod should appear before stopped pod, even though the
    // stopped pod has a more recent commit.
    let active_pos = stdout
        .find("active-pod")
        .expect("Expected 'active-pod' in output");
    let halted_pos = stdout
        .find("halted-pod")
        .expect("Expected 'halted-pod' in output");
    assert!(
        active_pos < halted_pos,
        "Running pod should appear before stopped pod in output: {}",
        stdout
    );
}

/// Within the same status group, pods with a more recent commit on their primary
/// branch should appear first.
#[test]
fn list_sorts_by_commit_date_within_status() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create two pods -- both start at the same host HEAD commit.
    for name in ["stale-pod", "fresh-pod"] {
        let output = pod_command(&repo, &daemon)
            .args(["enter", name, "--", "echo", "hello"])
            .output()
            .unwrap_or_else(|_| panic!("Failed to create {}", name));
        assert!(
            output.status.success(),
            "rumpel enter {} failed: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Make a commit in fresh-pod so its branch ref gets a newer committer date.
    for args in [
        vec!["enter", "fresh-pod", "--", "touch", "newfile"],
        vec!["enter", "fresh-pod", "--", "git", "add", "newfile"],
        vec![
            "enter",
            "fresh-pod",
            "--",
            "git",
            "commit",
            "-m",
            "new file",
        ],
    ] {
        let output = pod_command(&repo, &daemon)
            .args(&args)
            .output()
            .unwrap_or_else(|_| panic!("Failed to run: {:?}", args));
        assert!(
            output.status.success(),
            "{:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // List - fresh-pod should come before stale-pod (both running, sorted by commit date)
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
    let fresh_pos = stdout
        .find("fresh-pod")
        .expect("Expected 'fresh-pod' in output");
    let stale_pos = stdout
        .find("stale-pod")
        .expect("Expected 'stale-pod' in output");
    assert!(
        fresh_pos < stale_pos,
        "Pod with newer commit should appear first: {}",
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

#[test]
fn ssh_remote_pod_list() {
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
