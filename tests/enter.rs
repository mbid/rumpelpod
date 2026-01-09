//! Integration tests for the `sandbox enter` subcommand.

mod common;

use std::fs;
use std::process::Command;

use common::{TestDaemon, TestRepo, SOCKET_PATH_ENV};

#[test]
fn enter_smoke_test() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("sandbox"))
        .current_dir(repo.path())
        .env(SOCKET_PATH_ENV, &daemon.socket_path)
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
