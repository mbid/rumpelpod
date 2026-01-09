//! Integration tests for the `sandbox enter` subcommand.

use std::fs;

use crate::common::{sandbox_command, TestDaemon, TestRepo};

#[test]
fn enter_smoke_test() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "123"])
        .output()
        .expect("Failed to run sandbox command");

    assert!(
        output.status.success(),
        "sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "123");
}

#[test]
fn enter_twice_sequentially() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // First enter
    let output1 = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "first"])
        .output()
        .expect("Failed to run sandbox command");

    assert!(
        output1.status.success(),
        "first sandbox enter failed: {}",
        String::from_utf8_lossy(&output1.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output1.stdout).trim(), "first");

    // Second enter - should reuse the existing sandbox
    let output2 = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "second"])
        .output()
        .expect("Failed to run sandbox command");

    assert!(
        output2.status.success(),
        "second sandbox enter failed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output2.stdout).trim(), "second");
}

#[test]
fn enter_from_subdir_uses_same_container() {
    // Entering a sandbox from the repo root vs a subdirectory should result in
    // the same container (we detect the git repo root).
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    // Create a subdirectory
    let subdir = repo.path().join("some/nested/subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");

    let daemon = TestDaemon::start();

    // Enter from repo root and create a marker file
    let output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "subdir-test",
            "--",
            "sh",
            "-c",
            "echo marker > /tmp/marker.txt",
        ])
        .output()
        .expect("Failed to run sandbox command from repo root");

    assert!(
        output.status.success(),
        "sandbox enter from repo root failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Enter from subdirectory and verify the marker file exists
    let output = sandbox_command(&repo, &daemon)
        .current_dir(&subdir)
        .args([
            "enter",
            "subdir-test",
            "--",
            "sh",
            "-c",
            "cat /tmp/marker.txt",
        ])
        .output()
        .expect("Failed to run sandbox command from subdir");

    assert!(
        output.status.success(),
        "sandbox enter from subdir failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "marker",
        "Marker file should exist - subdir and root should use the same container"
    );
}

#[test]
fn enter_outside_git_repo_fails() {
    // Trying to enter a sandbox outside of a git repository should fail with
    // a clear error message.
    let repo = TestRepo::new_without_git();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "hello"])
        .output()
        .expect("Failed to run sandbox command");

    assert!(
        !output.status.success(),
        "sandbox enter should fail outside git repo"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("git repository"),
        "Error should mention git repository: {}",
        stderr
    );
}
