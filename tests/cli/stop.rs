//! Integration tests for the `rumpel stop` subcommand (multi-pod support).

use std::fs;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::{executor_supports_stop, ExecutorResources};

#[test]
fn stop_multiple_pods() {
    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "stop-multi");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Create three pods
    for name in ["sm-a", "sm-b", "sm-c"] {
        let output = pod_command(&repo, &daemon)
            .args(["enter", name, "--", "true"])
            .output()
            .expect("Failed to run rumpel enter");
        assert!(
            output.status.success(),
            "creating pod '{name}' failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Stop all three in one command
    let output = pod_command(&repo, &daemon)
        .args(["stop", "--wait", "sm-a", "sm-b", "sm-c"])
        .output()
        .expect("Failed to run rumpel stop");
    assert!(
        output.status.success(),
        "multi-stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify all are stopped
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["sm-a", "sm-b", "sm-c"] {
        let line = stdout
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("pod '{name}' should still be listed: {stdout}"));
        assert!(
            line.contains("stopped"),
            "pod '{name}' should be stopped: {line}"
        );
    }
}

#[test]
fn stop_multiple_continues_past_unknown() {
    // When one pod in a multi-stop does not exist, the others should
    // still be stopped and the command should report the failure.
    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "stop-unknown");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Create two pods
    for name in ["su-a", "su-c"] {
        let output = pod_command(&repo, &daemon)
            .args(["enter", name, "--", "true"])
            .output()
            .expect("Failed to run rumpel enter");
        assert!(output.status.success());
    }

    // Stop with a nonexistent pod in the middle
    let output = pod_command(&repo, &daemon)
        .args(["stop", "--wait", "su-a", "no-such-pod", "su-c"])
        .output()
        .expect("Failed to run rumpel stop");

    // Command should fail overall because one pod was unknown
    assert!(
        !output.status.success(),
        "should fail when a pod is unknown"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1 pod(s) could not be stopped"),
        "should report failure count: {stderr}"
    );

    // The other two should still have been stopped
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["su-a", "su-c"] {
        let line = stdout
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("pod '{name}' should still be listed: {stdout}"));
        assert!(
            line.contains("stopped"),
            "pod '{name}' should be stopped despite the unknown one: {line}"
        );
    }
}
