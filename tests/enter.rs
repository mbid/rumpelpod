//! Integration tests for the `sandbox enter` subcommand.

mod common;

use std::fs;
use std::process::Command;

use indoc::indoc;

use common::{run_git, SandboxFixture};

#[test]
fn smoke_test_sandbox_enter() {
    let fixture = SandboxFixture::new("test-sandbox");

    // Get the commit hash (after adding Dockerfile via SandboxFixture::new)
    let output = run_git(&fixture.repo.dir, &["rev-parse", "HEAD"]);
    let expected_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Test 1: Verify README.md content inside sandbox
    let output = fixture.run(&["cat", "README.md"]);
    assert!(
        output.status.success(),
        "Failed to read README.md in sandbox: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let readme_content = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        readme_content.trim(),
        "TEST",
        "README.md content mismatch. Got: '{}'",
        readme_content.trim()
    );

    // Test 2: Verify we're on the correct branch (sandbox name)
    let output = fixture.run(&["git", "branch", "--show-current"]);
    assert!(
        output.status.success(),
        "Failed to get current branch: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let current_branch = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        current_branch.trim(),
        fixture.name,
        "Branch mismatch. Expected '{}', got '{}'",
        fixture.name,
        current_branch.trim()
    );

    // Test 3: Verify we're on the correct commit
    let output = fixture.run(&["git", "rev-parse", "HEAD"]);
    assert!(
        output.status.success(),
        "Failed to get current commit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let current_commit = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        current_commit.trim(),
        expected_commit,
        "Commit mismatch. Expected '{}', got '{}'",
        expected_commit,
        current_commit.trim()
    );
}

#[test]
fn test_enter_passthrough_env() {
    let fixture = SandboxFixture::new("test-env-passthrough");

    // Configure .sandbox to require MY_TEST_VAR
    fs::write(
        fixture.repo.dir.join(".sandbox.toml"),
        indoc! {r#"
            env = ["MY_TEST_VAR"]
        "#},
    )
    .expect("Failed to write .sandbox.toml");

    run_git(&fixture.repo.dir, &["add", ".sandbox.toml"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    let env_value = "SECRET_ENV_VALUE_42";

    // Test 1: Verify env var is passed through when set on host
    let output = Command::new(assert_cmd::cargo::cargo_bin!("sandbox"))
        .current_dir(&fixture.repo.dir)
        .env("SANDBOX_DAEMON_SOCKET", &fixture.daemon.socket_path)
        .env("XDG_STATE_HOME", &fixture.daemon.state_dir)
        .env("MY_TEST_VAR", env_value)
        .args([
            "enter",
            &fixture.name,
            "--runtime",
            "runc",
            "--",
            "sh",
            "-c",
            "echo $MY_TEST_VAR",
        ])
        .output()
        .expect("Failed to run sandbox");

    assert!(
        output.status.success(),
        "Failed to run command with required env var: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        env_value,
        "Env var not passed through. Got: '{}'",
        stdout.trim()
    );

    // Test 2: Verify error when required env var is not set on host
    // This error happens before connecting to daemon, so socket path doesn't matter
    fs::write(
        fixture.repo.dir.join(".sandbox.toml"),
        indoc! {r#"
            env = ["NONEXISTENT_VAR_XYZ"]
        "#},
    )
    .expect("Failed to write .sandbox.toml");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("sandbox"))
        .current_dir(&fixture.repo.dir)
        .env("SANDBOX_DAEMON_SOCKET", &fixture.daemon.socket_path)
        .env("XDG_STATE_HOME", &fixture.daemon.state_dir)
        .args([
            "enter",
            &fixture.name,
            "--runtime",
            "runc",
            "--",
            "echo",
            "should not reach here",
        ])
        .output()
        .expect("Failed to run sandbox");

    assert!(
        !output.status.success(),
        "Should fail when env var is not set: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NONEXISTENT_VAR_XYZ"),
        "Error message should mention the missing env var. Got: '{}'",
        stderr
    );

    // Test 3: Verify multiple env vars can be passed
    fs::write(
        fixture.repo.dir.join(".sandbox.toml"),
        indoc! {r#"
            env = ["VAR_ONE", "VAR_TWO"]
        "#},
    )
    .expect("Failed to write .sandbox.toml");

    let output = Command::new(assert_cmd::cargo::cargo_bin!("sandbox"))
        .current_dir(&fixture.repo.dir)
        .env("SANDBOX_DAEMON_SOCKET", &fixture.daemon.socket_path)
        .env("XDG_STATE_HOME", &fixture.daemon.state_dir)
        .env("VAR_ONE", "value1")
        .env("VAR_TWO", "value2")
        .args([
            "enter",
            &fixture.name,
            "--runtime",
            "runc",
            "--",
            "sh",
            "-c",
            "echo $VAR_ONE-$VAR_TWO",
        ])
        .output()
        .expect("Failed to run sandbox");

    assert!(
        output.status.success(),
        "Failed to run with multiple required env vars: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "value1-value2",
        "Multiple env vars not passed correctly. Got: '{}'",
        stdout.trim()
    );
}
