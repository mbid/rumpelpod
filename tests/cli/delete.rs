//! Integration tests for the `sandbox delete` subcommand.

use std::fs;

use crate::common::{sandbox_command, TestDaemon, TestRepo};

#[test]
fn delete_smoke_test() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // First create a sandbox by entering it
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-delete", "--", "echo", "created"])
        .output()
        .expect("Failed to run sandbox enter command");

    assert!(
        output.status.success(),
        "sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Now delete the sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "test-delete"])
        .output()
        .expect("Failed to run sandbox delete command");

    assert!(
        output.status.success(),
        "sandbox delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn delete_nonexistent_sandbox_succeeds() {
    // Deleting a sandbox that doesn't exist should succeed (idempotent)
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "nonexistent"])
        .output()
        .expect("Failed to run sandbox delete command");

    assert!(
        output.status.success(),
        "sandbox delete of nonexistent sandbox failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn delete_then_recreate_same_name() {
    // After deleting a sandbox, we should be able to create a new one with the same name.
    // This verifies that all resources (container, network) are properly cleaned up.
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Create sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "recyclable", "--", "echo", "first"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "first sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Delete sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "recyclable"])
        .output()
        .expect("Failed to run sandbox delete command");
    assert!(
        output.status.success(),
        "sandbox delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create sandbox with the same name again
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "recyclable", "--", "echo", "second"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "second sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
