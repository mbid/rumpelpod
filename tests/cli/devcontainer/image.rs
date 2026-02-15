//! Integration tests for devcontainer.json image building.

use std::fs;
use std::process::Command;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{pod_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

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

/// Write a minimal .rumpelpod.toml for agent settings (runtime is set via devcontainer.json).
fn write_minimal_pod_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// Create a test devcontainer.json with an `image` reference (no build).
fn write_devcontainer_with_image(repo: &TestRepo, image: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image}",
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

/// Build a rumpel Command that does not need a daemon.
///
/// `image build` and `image fetch` call Docker directly, so no daemon socket
/// is required.
fn rumpel_cmd(repo: &TestRepo) -> Command {
    let mut cmd = Command::new(crate::common::rumpel_bin());
    cmd.current_dir(repo.path());
    cmd
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
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the pod - this should trigger an image build
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "build-test",
            "--",
            "echo",
            "hello from built image",
        ])
        .success()
        .expect("rumpel enter failed");

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

    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the pod and check that the build arg was used
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "args-test", "--", "cat", "/tmp/build-arg.txt"])
        .success()
        .expect("rumpel enter failed");

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

    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the pod and verify we're using the development stage
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "target-test", "--", "cat", "/tmp/stage.txt"])
        .success()
        .expect("rumpel enter failed");

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
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // First enter - should build the image
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "cache-test-1", "--", "echo", "first"])
        .success()
        .expect("first rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "first");

    // Second enter with different pod name - should reuse the cached image
    // (same Dockerfile hash) without rebuilding
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "cache-test-2", "--", "echo", "second"])
        .success()
        .expect("second rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "second");

    // Verify both pods can run commands (they're using the same image)
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "cache-test-1", "--", "echo", "still works"])
        .success()
        .expect("reentry to first pod failed");
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
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "context-test", "--", "echo", "build works"])
        .success()
        .expect("rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "build works");
}

#[test]
fn devcontainer_build_skips_when_image_exists() {
    let repo = TestRepo::new();

    let unique = repo.path().file_name().unwrap().to_string_lossy();
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        LABEL test.unique="{unique}"
        USER {TEST_USER}
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // First enter should build the image.
    let output = pod_command(&repo, &daemon)
        .args(["enter", "skip-test-1", "--", "echo", "built"])
        .output()
        .expect("first pod enter failed");
    assert!(output.status.success(), "first enter failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Devcontainer image built"),
        "first enter should build the image, stderr: {stderr}",
    );

    // Second enter with a different pod name should reuse the cached image.
    let output = pod_command(&repo, &daemon)
        .args(["enter", "skip-test-2", "--", "echo", "skipped"])
        .output()
        .expect("second pod enter failed");
    assert!(output.status.success(), "second enter failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Devcontainer image built"),
        "second enter should skip the build, stderr: {stderr}",
    );
}

// ---- rumpel image build / fetch subcommand tests ----

#[test]
fn image_build_builds_and_reports() {
    let repo = TestRepo::new();

    // Embed the repo temp-dir name so the Dockerfile hash is unique across
    // test runs and does not collide with cached images from other tests.
    let unique = repo.path().file_name().unwrap().to_string_lossy();
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        LABEL test.unique="{unique}"
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");

    let stdout = rumpel_cmd(&repo)
        .args(["image", "build"])
        .success()
        .expect("rumpel image build failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("Image built:"),
        "expected 'Image built:' in output, got: {stdout}",
    );
}

#[test]
fn image_build_reports_cached_on_second_run() {
    let repo = TestRepo::new();

    let unique = repo.path().file_name().unwrap().to_string_lossy();
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        LABEL test.unique="{unique}"
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");

    // First build
    rumpel_cmd(&repo)
        .args(["image", "build"])
        .success()
        .expect("first image build failed");

    // Second build -- should report cache hit
    let stdout = rumpel_cmd(&repo)
        .args(["image", "build"])
        .success()
        .expect("second image build failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("Image already up to date:"),
        "expected cache-hit message, got: {stdout}",
    );
}

#[test]
fn image_build_force_rebuilds() {
    let repo = TestRepo::new();

    let unique = repo.path().file_name().unwrap().to_string_lossy();
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        LABEL test.unique="{unique}"
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");

    // First build
    rumpel_cmd(&repo)
        .args(["image", "build"])
        .success()
        .expect("first image build failed");

    // Force rebuild -- should build again, not hit cache
    let stdout = rumpel_cmd(&repo)
        .args(["image", "build", "--force"])
        .success()
        .expect("forced image build failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("Image built:"),
        "expected 'Image built:' after --force, got: {stdout}",
    );
}

#[test]
fn image_build_errors_on_image_only_config() {
    let repo = TestRepo::new();
    write_devcontainer_with_image(&repo, "debian:13");

    let output = rumpel_cmd(&repo)
        .args(["image", "build"])
        .output()
        .expect("failed to run rumpel");

    assert!(
        !output.status.success(),
        "image build should fail for image-only config"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("image fetch"),
        "error should suggest 'image fetch', got: {stderr}",
    );
}

#[test]
fn image_fetch_pulls_image() {
    let repo = TestRepo::new();
    // hello-world is tiny and fast to pull
    write_devcontainer_with_image(&repo, "hello-world:latest");

    let stdout = rumpel_cmd(&repo)
        .args(["image", "fetch"])
        .success()
        .expect("rumpel image fetch failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("Image pulled:"),
        "expected 'Image pulled:' in output, got: {stdout}",
    );
}

#[test]
fn image_fetch_errors_on_build_config() {
    let repo = TestRepo::new();

    let dockerfile = formatdoc! {r#"
        FROM debian:13
    "#};

    write_test_dockerfile(&repo, &dockerfile);
    write_devcontainer_with_build(&repo, "Dockerfile");

    let output = rumpel_cmd(&repo)
        .args(["image", "fetch"])
        .output()
        .expect("failed to run rumpel");

    assert!(
        !output.status.success(),
        "image fetch should fail for build-based config"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("image build"),
        "error should suggest 'image build', got: {stderr}",
    );
}
