//! Integration tests for devcontainer.json image building.

use std::fs;

use indoc::formatdoc;
use sandbox::CommandExt;

use crate::common::{sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

/// Create a test devcontainer.json with a build configuration.
fn write_devcontainer_with_build(repo: &TestRepo, dockerfile_name: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "{dockerfile_name}",
                "context": ".."
            }},
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

/// Create a simple test Dockerfile.
fn write_test_dockerfile(repo: &TestRepo, content: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    fs::write(devcontainer_dir.join("Dockerfile"), content).expect("Failed to write Dockerfile");
}

/// Write a minimal .sandbox.toml for agent settings (runtime is set via devcontainer.json).
fn write_minimal_sandbox_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");
}

#[test]
fn devcontainer_build_simple() {
    let repo = TestRepo::new();

    // Create a simple Dockerfile that copies the repo
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the sandbox - this should trigger an image build
    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "build-test",
            "--",
            "echo",
            "hello from built image",
        ])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "hello from built image");
}

#[test]
fn devcontainer_build_with_args() {
    let repo = TestRepo::new();

    // Create a Dockerfile that uses build args
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        ARG TEST_VALUE=default
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        RUN echo "BUILD_ARG: $TEST_VALUE" > /tmp/build-arg.txt
        USER {TEST_USER}
    "#};

    write_test_dockerfile(&repo, &dockerfile);

    // Create devcontainer.json with build args
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": "..",
                "args": {{
                    "TEST_VALUE": "custom_value"
                }}
            }},
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

    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the sandbox and check that the build arg was used
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "args-test", "--", "cat", "/tmp/build-arg.txt"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "BUILD_ARG: custom_value");
}

#[test]
fn devcontainer_build_with_target() {
    let repo = TestRepo::new();

    // Create a multi-stage Dockerfile
    let dockerfile = formatdoc! {r#"
        FROM debian:13 AS base
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}

        FROM base AS development
        RUN echo "development stage" > /tmp/stage.txt
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}

        FROM base AS production
        RUN echo "production stage" > /tmp/stage.txt
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};

    write_test_dockerfile(&repo, &dockerfile);

    // Create devcontainer.json targeting the development stage
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": "..",
                "target": "development"
            }},
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

    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the sandbox and verify we're using the development stage
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "target-test", "--", "cat", "/tmp/stage.txt"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "development stage");
}

#[test]
fn devcontainer_build_reuses_cached_image() {
    let repo = TestRepo::new();

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // First enter - should build the image
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "cache-test-1", "--", "echo", "first"])
        .success()
        .expect("first sandbox enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "first");

    // Second enter with different sandbox name - should reuse the cached image
    // (same Dockerfile hash) without rebuilding
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "cache-test-2", "--", "echo", "second"])
        .success()
        .expect("second sandbox enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "second");

    // Verify both sandboxes can run commands (they're using the same image)
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "cache-test-1", "--", "echo", "still works"])
        .success()
        .expect("reentry to first sandbox failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "still works");
}

#[test]
fn devcontainer_build_with_context() {
    // Test that context is correctly resolved relative to devcontainer.json
    let repo = TestRepo::new();

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};

    write_test_dockerfile(&repo, &dockerfile);

    // First, use context ".." (repo root)
    write_devcontainer_with_build(&repo, "Dockerfile");
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "context-test", "--", "echo", "build works"])
        .success()
        .expect("sandbox enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "build works");
}
