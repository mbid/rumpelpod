//! Tests that unsupported devcontainer.json properties emit warnings.

use std::fs;

use indoc::formatdoc;

use crate::common::{pod_command, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::executor::ExecutorResources;

/// Write a Dockerfile and devcontainer.json where `extra_fields` is injected
/// as additional top-level JSON properties (include leading comma).
fn write_devcontainer_with_unsupported(repo: &TestRepo, extra_fields: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1000 {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};
    fs::write(devcontainer_dir.join("Dockerfile"), dockerfile).expect("Failed to write Dockerfile");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]{extra_fields}
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

#[test]
fn warns_on_workspace_mount() {
    let repo = TestRepo::new();

    write_devcontainer_with_unsupported(
        &repo,
        r#",
            "workspaceMount": "source=/host/path,target=/workspace,type=bind""#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "unsup-wsmount");
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "unsupported-wsmount", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspaceMount") && stderr.contains("not supported"),
        "stderr should warn about unsupported workspaceMount, got: {stderr}",
    );
}

#[test]
fn warns_on_app_port() {
    let repo = TestRepo::new();

    write_devcontainer_with_unsupported(
        &repo,
        r#",
            "appPort": [3000, 8080]"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "unsup-appport");
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "unsupported-appport", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("appPort") && stderr.contains("not supported"),
        "stderr should warn about unsupported appPort, got: {stderr}",
    );
}

#[test]
fn warns_on_docker_compose_file() {
    let repo = TestRepo::new();

    write_devcontainer_with_unsupported(
        &repo,
        r#",
            "dockerComposeFile": "docker-compose.yml""#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "unsup-compose");
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "unsupported-compose", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dockerComposeFile") && stderr.contains("not supported"),
        "stderr should warn about unsupported dockerComposeFile, got: {stderr}",
    );
}

#[test]
fn warns_on_multiple_unsupported() {
    let repo = TestRepo::new();

    write_devcontainer_with_unsupported(
        &repo,
        r#",
            "workspaceMount": "source=/host,target=/ws,type=bind",
            "appPort": 3000,
            "service": "web",
            "runServices": ["web", "db"]"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "unsup-multi");
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "unsupported-multi", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("workspaceMount"),
        "stderr should warn about workspaceMount, got: {stderr}",
    );
    assert!(
        stderr.contains("appPort"),
        "stderr should warn about appPort, got: {stderr}",
    );
    assert!(
        stderr.contains("service"),
        "stderr should warn about service, got: {stderr}",
    );
    assert!(
        stderr.contains("runServices"),
        "stderr should warn about runServices, got: {stderr}",
    );
}

#[test]
fn warns_on_initialize_command() {
    let repo = TestRepo::new();

    write_devcontainer_with_unsupported(
        &repo,
        r#",
            "initializeCommand": "echo hello""#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "unsup-initcmd");
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "unsupported-initcmd", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("initializeCommand") && stderr.contains("not supported"),
        "stderr should warn about unsupported initializeCommand, got: {stderr}",
    );
}

#[test]
fn warns_on_features() {
    let repo = TestRepo::new();

    write_devcontainer_with_unsupported(
        &repo,
        r#",
            "features": {
                "ghcr.io/devcontainers/features/node:1": { "version": "20" }
            }"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "unsup-features");
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "unsupported-features", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("features") && stderr.contains("not supported"),
        "stderr should warn about unsupported features, got: {stderr}",
    );
}
