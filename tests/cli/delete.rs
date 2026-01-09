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
