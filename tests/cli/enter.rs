//! Integration tests for the `rumpel enter` subcommand.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use indoc::{formatdoc, indoc};
use rumpelpod::CommandExt;

use crate::common::{
    build_docker_image, build_test_image, pod_command, write_test_pod_config,
    write_test_pod_config_with_user, DockerBuild, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER,
    TEST_USER_UID,
};
use crate::executor::TestPod;

#[test]
fn enter_smoke_test() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-smoke");

    let stdout = pod_command(&repo, &pod.daemon)
        .args(["enter", "test", "--", "echo", "123"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "123");
}

#[test]
fn enter_twice_sequentially() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-twice");

    // First enter
    let stdout = pod_command(&repo, &pod.daemon)
        .args(["enter", "test", "--", "echo", "first"])
        .success()
        .expect("first rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "first");

    // Second enter - should reuse the existing pod
    let stdout = pod_command(&repo, &pod.daemon)
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

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-subdir-same");

    // Enter from repo root and create a marker file
    pod_command(&repo, &pod.daemon)
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
    let stdout = pod_command(&repo, &pod.daemon)
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

    let daemon = TestDaemon::start();

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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-verify");

    // Verify running as the configured user
    let stdout = pod_command(&repo, &pod.daemon)
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
    let stdout = pod_command(&repo, &pod.daemon)
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

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-subdir-wd");

    // Enter from subdir - should use TEST_REPO_PATH/subdir as workdir
    let stdout = pod_command(&repo, &pod.daemon)
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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-image-user");

    // Verify running as the user from the image's USER directive
    let stdout = pod_command(&repo, &pod.daemon)
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
    let image_id = crate::common::build_docker_image(crate::common::DockerBuild {
        dockerfile: formatdoc! {"
            FROM debian:13
            RUN apt-get update && apt-get install -y git
            COPY . {TEST_REPO_PATH}
        "},
        build_context: Some(repo.path().to_path_buf()),
    })
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

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
    let image_id = crate::common::build_docker_image(crate::common::DockerBuild {
        dockerfile: formatdoc! {"
            FROM debian:13
            RUN apt-get update && apt-get install -y git
            COPY . {TEST_REPO_PATH}
            USER root
        "},
        build_context: Some(repo.path().to_path_buf()),
    })
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

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
    // Build an image where root owns the repo (COPY without --chown defaults to root)
    let image_id = crate::common::build_docker_image(crate::common::DockerBuild {
        dockerfile: formatdoc! {"
            FROM debian:13
            RUN apt-get update && apt-get install -y git
            COPY . {TEST_REPO_PATH}
        "},
        build_context: Some(repo.path().to_path_buf()),
    })
    .expect("Failed to build test image");

    write_test_pod_config_with_user(&repo, &image_id, "root");

    let daemon = TestDaemon::start();

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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-hostname");

    let stdout = pod_command(&repo, &pod.daemon)
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
    let image_id = build_docker_image(DockerBuild {
        dockerfile: format!(
            "FROM debian:13\n\
             RUN apt-get update && apt-get install -y git\n\
             RUN printf '#!/bin/sh\\necho CUSTOM_SHELL_OK\\n' > /usr/local/bin/myshell \
                 && chmod +x /usr/local/bin/myshell\n\
             RUN useradd -m -u {TEST_USER_UID} -s /usr/local/bin/myshell {TEST_USER}\n\
             COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}\n\
             USER {TEST_USER}\n"
        ),
        build_context: Some(repo.path().to_path_buf()),
    })
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-stdin");

    let mut cmd = pod_command(&repo, &pod.daemon);
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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Change host identity after building the image so the pod can only get
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

    let pod = TestPod::start(&repo, &image_id, "enter-git-id");

    let stdout = pod_command(&repo, &pod.daemon)
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

    let stdout = pod_command(&repo, &pod.daemon)
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
fn enter_updates_git_identity_on_reentry() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "enter-reentry-id");

    // First enter creates the container with the original identity.
    pod_command(&repo, &pod.daemon)
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
    let stdout = pod_command(&repo, &pod.daemon)
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

    let stdout = pod_command(&repo, &pod.daemon)
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
