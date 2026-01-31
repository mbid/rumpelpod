use indoc::formatdoc;
use sandbox::CommandExt;
use std::fs;

use crate::common::{sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

fn write_devcontainer_with_env(repo: &TestRepo, env_config: &str) {
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
            "containerEnv": {env_config},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]
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

#[test]
fn container_env_simple() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(&repo, r#"{ "MY_VAR": "simple_value" }"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "env-simple", "--", "printenv", "MY_VAR"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "simple_value");
}

#[test]
fn container_env_local_substitution() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(&repo, r#"{ "HOST_VAR": "${localEnv:TEST_HOST_VAR}" }"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Set the environment variable in the command process
    let stdout = sandbox_command(&repo, &daemon)
        .env("TEST_HOST_VAR", "secret_value")
        .args(["enter", "env-subst", "--", "printenv", "HOST_VAR"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "secret_value");
}

#[test]
fn container_env_local_substitution_missing() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(
        &repo,
        r#"{ "MISSING_VAR": "${localEnv:NON_EXISTENT_VAR}" }"#,
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "env-missing", "--", "printenv", "MISSING_VAR"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "");
}

#[test]
fn container_env_mixed() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(
        &repo,
        r#"{ 
        "STATIC": "static", 
        "DYNAMIC": "${localEnv:TEST_DYNAMIC}"
    }"#,
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .env("TEST_DYNAMIC", "dynamic")
        .args([
            "enter",
            "env-mixed",
            "--",
            "sh",
            "-c",
            "echo $STATIC $DYNAMIC",
        ])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "static dynamic");
}
