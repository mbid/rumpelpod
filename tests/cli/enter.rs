//! Integration tests for the `sandbox enter` subcommand.

use std::fs;

use indoc::{formatdoc, indoc};
use sandbox::CommandExt;

use crate::common::{build_docker_image, sandbox_command, DockerBuild, TestDaemon, TestRepo};

#[test]
fn enter_smoke_test() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

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
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

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
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    // Create a subdirectory
    let subdir = repo.path().join("some/nested/subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");

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

#[test]
fn enter_with_custom_user() {
    // Build a custom image with a non-root user
    let dockerfile = indoc! {"
        FROM debian:13
        RUN useradd -m -s /bin/bash testuser
    "};

    let image_id = build_docker_image(DockerBuild {
        dockerfile: dockerfile.to_string(),
        build_context: None,
    })
    .expect("Failed to build custom docker image");

    let repo = TestRepo::new();
    let config = formatdoc! {r#"
        image = "{image_id}"
        user = "testuser"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "whoami"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "testuser",
        "Should be running as testuser, got: {}",
        stdout.trim()
    );
}

#[test]
fn enter_with_custom_repo_path() {
    // Build a custom image with a git repo at a custom path
    let dockerfile = indoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN mkdir -p /custom/repo/path/subdir
        WORKDIR /custom/repo/path
        RUN git init && \
            git config user.email "test@example.com" && \
            git config user.name "Test" && \
            git commit --allow-empty -m "init"
    "#};

    let image_id = build_docker_image(DockerBuild {
        dockerfile: dockerfile.to_string(),
        build_context: None,
    })
    .expect("Failed to build custom docker image");

    let repo = TestRepo::new();

    // Create a subdirectory in the host repo to test relative path handling
    let subdir = repo.path().join("subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");

    let config = formatdoc! {r#"
        image = "{image_id}"
        repo-path = "/custom/repo/path"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Enter from repo root - should use /custom/repo/path as workdir
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "repo-path-test", "--", "pwd"])
        .success()
        .expect("sandbox enter from root failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "/custom/repo/path",
        "Working directory from root should be /custom/repo/path, got: {}",
        stdout.trim()
    );

    // Enter from subdir - should use /custom/repo/path/subdir as workdir
    let stdout = sandbox_command(&repo, &daemon)
        .current_dir(&subdir)
        .args(["enter", "repo-path-test", "--", "pwd"])
        .success()
        .expect("sandbox enter from subdir failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "/custom/repo/path/subdir",
        "Working directory from subdir should be /custom/repo/path/subdir, got: {}",
        stdout.trim()
    );
}
