//! Integration tests for the `sandbox enter` subcommand.

use std::fs;

use sandbox::CommandExt;

use crate::common::{
    build_test_image, sandbox_command, write_test_sandbox_config, TestDaemon, TestRepo,
    TEST_REPO_PATH, TEST_USER,
};

#[test]
fn enter_smoke_test() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "123"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "123");
}

#[test]
fn enter_twice_sequentially() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First enter
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "first"])
        .success()
        .expect("first sandbox enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "first");

    // Second enter - should reuse the existing sandbox
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "second"])
        .success()
        .expect("second sandbox enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "second");
}

#[test]
fn enter_from_subdir_uses_same_container() {
    // Entering a sandbox from the repo root vs a subdirectory should result in
    // the same container (we detect the git repo root).
    let repo = TestRepo::new();

    // Create a subdirectory before building the image so it's included
    let subdir = repo.path().join("some/nested/subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Enter from repo root and create a marker file
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "subdir-test",
            "--",
            "sh",
            "-c",
            "echo marker > /tmp/marker.txt",
        ])
        .success()
        .expect("sandbox enter from repo root failed");

    // Enter from subdirectory and verify the marker file exists
    let stdout = sandbox_command(&repo, &daemon)
        .current_dir(&subdir)
        .args([
            "enter",
            "subdir-test",
            "--",
            "sh",
            "-c",
            "cat /tmp/marker.txt",
        ])
        .success()
        .expect("sandbox enter from subdir failed");

    let stdout = String::from_utf8_lossy(&stdout);
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

    // Write a minimal config (image/user/repo-path are now required but the
    // command should fail before parsing completes because we're not in a git repo)
    fs::write(
        repo.path().join(".sandbox.toml"),
        "image = \"debian:13\"\nuser = \"root\"\nrepo-path = \"/repo\"",
    )
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

#[test]
fn enter_verifies_user_and_repo_path() {
    // Verify that the standard test image runs as the expected user and in the expected directory
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Verify running as the configured user
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "verify-test", "--", "whoami"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        TEST_USER,
        "Should be running as {}, got: {}",
        TEST_USER,
        stdout.trim()
    );

    // Verify working directory is repo-path
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "verify-test", "--", "pwd"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        TEST_REPO_PATH,
        "Working directory should be {}, got: {}",
        TEST_REPO_PATH,
        stdout.trim()
    );
}

#[test]
fn enter_subdir_workdir_is_relative() {
    // Verify that entering from a subdirectory sets workdir relative to repo-path
    let repo = TestRepo::new();

    // Create a subdirectory before building the image
    let subdir = repo.path().join("subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Enter from subdir - should use TEST_REPO_PATH/subdir as workdir
    let stdout = sandbox_command(&repo, &daemon)
        .current_dir(&subdir)
        .args(["enter", "subdir-test", "--", "pwd"])
        .success()
        .expect("sandbox enter from subdir failed");

    let stdout = String::from_utf8_lossy(&stdout);
    let expected = format!("{}/subdir", TEST_REPO_PATH);
    assert_eq!(
        stdout.trim(),
        expected,
        "Working directory from subdir should be {}, got: {}",
        expected,
        stdout.trim()
    );
}
