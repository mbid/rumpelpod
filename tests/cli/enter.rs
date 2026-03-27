//! Integration tests for the `rumpel enter` subcommand.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use indoc::{formatdoc, indoc};
use rumpelpod::CommandExt;

use crate::common::{
    pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH,
    TEST_USER, TEST_USER_UID,
};
use crate::executor::ExecutorResources;

#[test]
fn enter_smoke_test() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-smoke");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "123"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "123");
}

#[test]
fn enter_twice_sequentially() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-twice");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // First enter
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "first"])
        .success()
        .expect("first rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "first");

    // Second enter - should reuse the existing pod
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "second"])
        .success()
        .expect("second rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "second");
}

#[test]
fn enter_from_subdir_uses_same_container() {
    // Entering a pod from the repo root vs a subdirectory should result in
    // the same container (we detect the git repo root).
    let repo = TestRepo::new();

    // Create a subdirectory before building the image so it's included
    let subdir = repo.path().join("some/nested/subdir");
    fs::create_dir_all(&subdir).expect("Failed to create subdirectory");

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-subdir-same");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Enter from repo root and create a marker file
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "subdir-test",
            "--",
            "sh",
            "-c",
            "echo marker > /tmp/marker.txt",
        ])
        .success()
        .expect("rumpel enter from repo root failed");

    // Enter from subdirectory and verify the marker file exists
    let stdout = pod_command(&repo, &daemon)
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
        .expect("rumpel enter from subdir failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "marker",
        "Marker file should exist - subdir and root should use the same container"
    );
}

#[test]
fn enter_outside_git_repo_fails() {
    // Trying to enter a pod outside of a git repository should fail with
    // a clear error message.
    let repo = TestRepo::new_without_git();

    // Write a minimal config (command should fail before parsing completes
    // because we're not in a git repo)
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        indoc! {r#"
            {
                "image": "debian:13",
                "containerUser": "root",
                "workspaceFolder": "/repo",
                "runArgs": ["--runtime=runc"]
            }
        "#},
    )
    .expect("Failed to write devcontainer.json");

    let home = TestHome::new();
    let _executor = ExecutorResources::setup(&home, "enter-outside-git");
    let daemon = TestDaemon::start(&home);

    let output = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "hello"])
        .output()
        .expect("Failed to run pod command");

    assert!(
        !output.status.success(),
        "rumpel enter should fail outside git repo"
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-verify");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Verify running as the configured user
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "verify-test", "--", "whoami"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        TEST_USER,
        "Should be running as {}, got: {}",
        TEST_USER,
        stdout.trim()
    );

    // Verify working directory is repo-path
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "verify-test", "--", "pwd"])
        .success()
        .expect("rumpel enter failed");

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

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-subdir-wd");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Enter from subdir - should use TEST_REPO_PATH/subdir as workdir
    let stdout = pod_command(&repo, &daemon)
        .current_dir(&subdir)
        .args(["enter", "subdir-test", "--", "pwd"])
        .success()
        .expect("rumpel enter from subdir failed");

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

#[test]
fn enter_uses_image_user_when_not_specified_in_config() {
    // When the config doesn't specify a user, the pod should use the
    // image's USER directive.
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-image-user");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Verify running as the user from the image's USER directive
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "image-user-test", "--", "whoami"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        TEST_USER,
        "Should be running as {} (from image USER), got: {}",
        TEST_USER,
        stdout.trim()
    );
}

#[test]
fn enter_falls_back_to_root_when_image_has_no_user() {
    // When neither the config nor the image specifies a user, the pod
    // should fall back to root (matching VS Code devcontainer behavior).
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-no-user");
    let daemon = TestDaemon::start(&home);
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).unwrap();
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        COPY . {TEST_REPO_PATH}
    "},
    )
    .unwrap();
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"]
        }}
    "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "no-user-test", "--", "whoami"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "root",
        "Should fall back to root when no user is specified"
    );
}

#[test]
fn enter_falls_back_to_root_when_image_user_is_root() {
    // When the image explicitly sets USER to root and the config doesn't
    // specify a user, the pod should use root.
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-root-user");
    let daemon = TestDaemon::start(&home);
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).unwrap();
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        COPY . {TEST_REPO_PATH}
        USER root
    "},
    )
    .unwrap();
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"]
        }}
    "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "root-user-test", "--", "whoami"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "root",
        "Should use root when image USER is root"
    );
}

#[test]
fn enter_allows_explicit_root_user_in_config() {
    // When the config explicitly sets user = "root", it should be allowed
    // (the user made a conscious choice to run as root).
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-explicit-root");
    let daemon = TestDaemon::start(&home);
    // Build an image where root owns the repo (COPY without --chown defaults to root)
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).unwrap();
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        COPY . {TEST_REPO_PATH}
    "},
    )
    .unwrap();
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "root",
            "runArgs": ["--runtime=runc"]
        }}
    "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "explicit-root-test", "--", "whoami"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "root",
        "Should be running as root when explicitly configured, got: {}",
        stdout.trim()
    );
}

#[test]
fn enter_sets_hostname_to_pod_name() {
    // The container's hostname should be set to the pod name.
    // On k8s the hostname is the k8s pod name, not the rumpelpod pod name.
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-hostname");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "my-pod", "--", "hostname"])
        .success()
        .expect("rumpel enter failed");

    let hostname = String::from_utf8_lossy(&stdout).trim().to_string();
    if matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::K8s
    ) {
        assert!(
            hostname.contains("my-pod"),
            "K8s hostname should contain the pod name, got: {}",
            hostname,
        );
    } else {
        assert_eq!(
            hostname, "my-pod",
            "Hostname should be the pod name, got: {}",
            hostname,
        );
    }
}

#[test]
fn enter_uses_container_shell_not_host_shell() {
    // Install a custom "shell" that prints a marker and exits.
    // If enter uses the container user's shell, we see the marker.
    // If it leaks the host's $SHELL or hardcodes bash, we don't.
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-shell");
    let daemon = TestDaemon::start(&home);
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).unwrap();
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN printf '#!/bin/sh\\necho CUSTOM_SHELL_OK\\n' > /usr/local/bin/myshell \
            && chmod +x /usr/local/bin/myshell
        RUN useradd -m -u {TEST_USER_UID} -s /usr/local/bin/myshell {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "},
    )
    .unwrap();
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"]
        }}
    "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // The custom shell just prints and exits, so no PTY needed.
    // Set host SHELL to something bogus -- the old code would try to exec this.
    let stdout = pod_command(&repo, &daemon)
        .env("SHELL", "/nonexistent/host-shell")
        .args(["enter", "shell-test"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("CUSTOM_SHELL_OK"),
        "enter should have launched the container user's custom shell.\n\
         stdout: {stdout}"
    );
}

#[test]
fn enter_forwards_piped_stdin() {
    // Piped stdin must reach the command running inside the container.
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-stdin");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let mut cmd = pod_command(&repo, &daemon);
    cmd.args(["enter", "stdin-test", "--", "cat"]);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn rumpel enter");

    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    writeln!(stdin, "hello from stdin").expect("Failed to write to stdin");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("Failed to wait for child");
    assert!(
        output.status.success(),
        "rumpel enter should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "hello from stdin",
        "cat should echo back what was piped through stdin"
    );
}

#[test]
fn enter_propagates_host_git_identity() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-git-id");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Change host identity after writing config so the pod can only get
    // these values via propagation, not from the baked-in .git/config.
    Command::new("git")
        .args(["config", "user.name", "Pod Author"])
        .current_dir(repo.path())
        .success()
        .expect("git config user.name failed");
    Command::new("git")
        .args(["config", "user.email", "pod@example.org"])
        .current_dir(repo.path())
        .success()
        .expect("git config user.email failed");

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "git-id-test", "--", "git", "config", "user.name"])
        .success()
        .expect("rumpel enter failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "Pod Author",
        "Pod git user.name should match host, got: {}",
        stdout.trim()
    );

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "git-id-test", "--", "git", "config", "user.email"])
        .success()
        .expect("rumpel enter failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "pod@example.org",
        "Pod git user.email should match host, got: {}",
        stdout.trim()
    );
}

#[test]
fn enter_skips_image_build_when_container_exists() {
    // Building the image is expensive and pointless when a container already
    // exists. Verify that the first enter produces build output but a second
    // enter (even after the Dockerfile changes) does not.
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-skip-build");
    let daemon = TestDaemon::start(&home);
    // Include the temp dir name so the Dockerfile content (and thus the
    // devcontainer image tag) is unique across runs, preventing a cached
    // image from suppressing the build output we assert on below.
    let repo_dir = repo.path().file_name().unwrap().to_str().unwrap();
    let extra = format!("RUN echo skip-build-marker-{repo_dir}");
    write_test_devcontainer(&repo, &extra, "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // First enter -- must build the image.
    let output = pod_command(&repo, &daemon)
        .args(["enter", "skip-build-test", "--", "echo", "first"])
        .output()
        .expect("first rumpel enter failed to run");
    assert!(
        output.status.success(),
        "first enter should succeed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let first_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        first_combined.contains("skip-build-marker-"),
        "first enter should contain docker build output, got:\n{first_combined}",
    );

    // Modify the Dockerfile so a naive implementation would rebuild.
    write_test_devcontainer(&repo, "RUN echo skip-build-changed", "");

    // Second enter -- container already exists, skip build entirely.
    let output = pod_command(&repo, &daemon)
        .args(["enter", "skip-build-test", "--", "echo", "second"])
        .output()
        .expect("second rumpel enter failed to run");
    assert!(
        output.status.success(),
        "second enter should succeed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let second_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !second_combined.contains("skip-build-changed"),
        "second enter should NOT contain docker build output, got:\n{second_combined}",
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "second",);
}

#[test]
fn enter_updates_git_identity_on_reentry() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "enter-reentry-id");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // First enter creates the container with the original identity.
    pod_command(&repo, &daemon)
        .args(["enter", "reentry-id-test", "--", "echo", "setup"])
        .success()
        .expect("first enter failed");

    // Change host identity between entries.
    Command::new("git")
        .args(["config", "user.name", "Updated Author"])
        .current_dir(repo.path())
        .success()
        .expect("git config user.name failed");
    Command::new("git")
        .args(["config", "user.email", "updated@example.org"])
        .current_dir(repo.path())
        .success()
        .expect("git config user.email failed");

    // Re-entry should propagate the new identity.
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "reentry-id-test",
            "--",
            "git",
            "config",
            "user.name",
        ])
        .success()
        .expect("re-entry failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "Updated Author",
        "Pod git user.name should be updated on re-entry, got: {}",
        stdout.trim()
    );

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "reentry-id-test",
            "--",
            "git",
            "config",
            "user.email",
        ])
        .success()
        .expect("re-entry failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "updated@example.org",
        "Pod git user.email should be updated on re-entry, got: {}",
        stdout.trim()
    );
}
