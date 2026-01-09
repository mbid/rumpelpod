//! Integration tests for the `sandbox list` subcommand.

mod common;

use std::fs;

use common::{sandbox_command, TestDaemon, TestRepo};

#[test]
fn list_empty_returns_header_only() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should have header line and separator
    assert!(stdout.contains("NAME"));
    assert!(stdout.contains("STATUS"));
    assert!(stdout.contains("CREATED"));
    assert!(stdout.contains("---"));
}

#[test]
fn list_shows_created_sandbox() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Create a sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-list", "--", "echo", "hello"])
        .output()
        .expect("Failed to run sandbox enter command");

    assert!(
        output.status.success(),
        "sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List sandboxes
    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test-list"),
        "Expected sandbox 'test-list' in output: {}",
        stdout
    );
    assert!(
        stdout.contains("running"),
        "Expected 'running' status in output: {}",
        stdout
    );
}

#[test]
fn list_shows_multiple_sandboxes() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Create first sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-one", "--", "echo", "one"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "first sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create second sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-two", "--", "echo", "two"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "second sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List sandboxes
    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sandbox-one"),
        "Expected 'sandbox-one' in output: {}",
        stdout
    );
    assert!(
        stdout.contains("sandbox-two"),
        "Expected 'sandbox-two' in output: {}",
        stdout
    );
}

#[test]
fn list_does_not_show_other_repo_sandboxes() {
    let repo1 = TestRepo::new();
    fs::write(repo1.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let repo2 = TestRepo::new();
    fs::write(repo2.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Create sandbox in repo1
    let output = sandbox_command(&repo1, &daemon)
        .args(["enter", "repo1-sandbox", "--", "echo", "repo1"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "repo1 sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create sandbox in repo2
    let output = sandbox_command(&repo2, &daemon)
        .args(["enter", "repo2-sandbox", "--", "echo", "repo2"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "repo2 sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List sandboxes from repo1 - should only see repo1-sandbox
    let output = sandbox_command(&repo1, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repo1-sandbox"),
        "Expected 'repo1-sandbox' in output: {}",
        stdout
    );
    assert!(
        !stdout.contains("repo2-sandbox"),
        "Should not see 'repo2-sandbox' from other repo in output: {}",
        stdout
    );

    // List sandboxes from repo2 - should only see repo2-sandbox
    let output = sandbox_command(&repo2, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repo2-sandbox"),
        "Expected 'repo2-sandbox' in output: {}",
        stdout
    );
    assert!(
        !stdout.contains("repo1-sandbox"),
        "Should not see 'repo1-sandbox' from other repo in output: {}",
        stdout
    );
}
