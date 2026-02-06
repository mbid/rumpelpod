//! Integration tests for workspaceFolder handling in devcontainer.json.
//!
//! Tests cover the default workspace path, custom paths, repo initialization
//! via git-http bridge, and incremental sync on sandbox enter.

use indoc::formatdoc;
use sandbox::CommandExt;
use std::fs;

use crate::common::{sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

/// Write a devcontainer.json with a Dockerfile that installs git and creates
/// the test user.  `extra_config` is spliced into the JSON object so callers
/// can set (or omit) `workspaceFolder` and other properties.
fn write_devcontainer(repo: &TestRepo, extra_config: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1000 {TEST_USER}
        USER {TEST_USER}
    "#};
    fs::write(devcontainer_dir.join("Dockerfile"), dockerfile).expect("Failed to write Dockerfile");

    // Build from Dockerfile; caller controls workspaceFolder via extra_config
    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]{extra_config}
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

fn write_minimal_sandbox_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");
}

/// Without an explicit workspaceFolder the spec default is
/// `/workspaces/<basename>`.  Verify the container's working directory
/// matches that convention.
#[test]
fn workspace_folder_default() {
    let repo = TestRepo::new();

    // No workspaceFolder in config — should fall back to /workspaces/<basename>
    write_devcontainer(&repo, "");
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "ws-default", "--", "pwd"])
        .success()
        .expect("sandbox enter should succeed with default workspaceFolder");

    let cwd = String::from_utf8_lossy(&stdout).trim().to_string();
    let basename = repo.path().file_name().unwrap().to_str().unwrap();
    let expected = format!("/workspaces/{basename}");
    assert_eq!(
        cwd, expected,
        "default workspaceFolder should be /workspaces/<basename>"
    );
}

/// When `workspaceFolder` is set to a custom path the container's working
/// directory should be that path.
#[test]
fn workspace_folder_custom() {
    let repo = TestRepo::new();

    write_devcontainer(
        &repo,
        r#",
            "workspaceFolder": "/custom/path""#,
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "ws-custom", "--", "pwd"])
        .success()
        .expect("sandbox enter should succeed with custom workspaceFolder");

    let cwd = String::from_utf8_lossy(&stdout).trim().to_string();
    assert_eq!(
        cwd, "/custom/path",
        "workspaceFolder should be the custom path"
    );
}

/// The host repository should be cloned into `workspaceFolder` so that
/// `.git` exists and contains commits from the host repo.
#[test]
fn workspace_folder_repo_initialized() {
    let repo = TestRepo::new();

    write_devcontainer(
        &repo,
        &formatdoc! {r#",
        "workspaceFolder": "{TEST_REPO_PATH}""#},
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "ws-repo-init",
            "--",
            "git",
            "-C",
            TEST_REPO_PATH,
            "log",
            "--oneline",
        ])
        .success()
        .expect("sandbox enter should succeed and repo should be initialized");

    let log = String::from_utf8_lossy(&stdout).trim().to_string();
    assert!(
        log.contains("Initial commit"),
        "repo in container should contain the host's initial commit, got: {log}"
    );
}
