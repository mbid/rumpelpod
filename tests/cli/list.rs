//! Integration tests for the `rumpel list` subcommand.

use std::fs;

use retry::delay::Exponential;
use retry::OperationResult;

use crate::common::{pod_command, TestRepo};
use crate::executor::{write_test_devcontainer, TestExecutor};

#[test]
fn list_empty_returns_header_only() {
    let repo = TestRepo::new();
    let exec = TestExecutor::start("list-empty");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let output = pod_command(&repo, &exec.daemon)
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
    let exec = TestExecutor::start("list-shows-pod");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Create a pod
    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "test-list", "--", "echo", "hello"])
        .output()
        .expect("Failed to run rumpel enter command");

    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List pods
    let output = pod_command(&repo, &exec.daemon)
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
}

#[test]
fn list_shows_repo_state() {
    let repo = TestRepo::new();
    let exec = TestExecutor::start("list-repo-state");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Create a pod
    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "test-state", "--", "echo", "hello"])
        .output()
        .expect("Failed to run rumpel enter command");

    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Initial state should be "up to date" (tracked via branch)
    let output = pod_command(&repo, &exec.daemon)
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
    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "test-state", "--", "touch", "newfile"])
        .output()
        .expect("Failed to touch file");
    assert!(output.status.success());

    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "test-state", "--", "git", "add", "newfile"])
        .output()
        .expect("Failed to git add");
    assert!(output.status.success());

    let output = pod_command(&repo, &exec.daemon)
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
    let output = pod_command(&repo, &exec.daemon)
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
    let exec = TestExecutor::start("list-multi");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Create first pod
    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "pod-one", "--", "echo", "one"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "first rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create second pod
    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "pod-two", "--", "echo", "two"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "second rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List pods
    let output = pod_command(&repo, &exec.daemon)
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
    let exec = TestExecutor::start("list-run-before-stop");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Create first pod (stays running, never gets a new commit)
    let output = pod_command(&repo, &exec.daemon)
        .args(["enter", "active-pod", "--", "echo", "one"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "first rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create second pod and give it a newer commit so its committer date wins
    let output = pod_command(&repo, &exec.daemon)
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
        let output = pod_command(&repo, &exec.daemon)
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
        let output = pod_command(&repo, &exec.daemon)
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
    let exec = TestExecutor::start("list-sort-date");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Create two pods -- both start at the same host HEAD commit.
    for name in ["stale-pod", "fresh-pod"] {
        let output = pod_command(&repo, &exec.daemon)
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
        let output = pod_command(&repo, &exec.daemon)
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
    let output = pod_command(&repo, &exec.daemon)
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
    let exec1 = TestExecutor::start("list-other-repo-1");
    write_test_devcontainer(&repo1, "", "");
    fs::write(repo1.path().join(".rumpelpod.toml"), &exec1.toml).unwrap();

    let repo2 = TestRepo::new();
    let exec2 = TestExecutor::start("list-other-repo-2");
    write_test_devcontainer(&repo2, "", "");
    fs::write(repo2.path().join(".rumpelpod.toml"), &exec2.toml).unwrap();

    // Create pod in repo1
    let output = pod_command(&repo1, &exec1.daemon)
        .args(["enter", "repo1-pod", "--", "echo", "repo1"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "repo1 rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create pod in repo2
    let output = pod_command(&repo2, &exec2.daemon)
        .args(["enter", "repo2-pod", "--", "echo", "repo2"])
        .output()
        .expect("Failed to run rumpel enter command");
    assert!(
        output.status.success(),
        "repo2 rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List pods from repo1 - should only see repo1-pod
    let output = pod_command(&repo1, &exec1.daemon)
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
    let output = pod_command(&repo2, &exec2.daemon)
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
    if !matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::Ssh
    ) {
        return;
    }
    let repo = TestRepo::new();
    let exec = TestExecutor::start("ssh-list-remote");
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Create a pod on the remote
    let output = pod_command(&repo, &exec.daemon)
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
    let output = pod_command(&repo, &exec.daemon)
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
        stdout.contains(&format!("{}@", super::ssh::SSH_USER)),
        "rumpel list should show the remote host: stdout={}, stderr={}",
        stdout,
        stderr
    );
}
