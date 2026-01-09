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
