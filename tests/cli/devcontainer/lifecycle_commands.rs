//! Integration tests for devcontainer.json lifecycle commands.
//!
//! Tests verify the execution semantics of lifecycle commands as specified in
//! the Dev Container spec: ordering, frequency, command formats, failure
//! propagation, and the `waitFor` setting.

use indoc::formatdoc;
use rumpelpod::CommandExt;
use std::fs;

use crate::common::{pod_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

/// Write a devcontainer.json with the given lifecycle command properties spliced
/// in alongside a standard build section.
fn write_devcontainer_with_lifecycle(repo: &TestRepo, lifecycle_json: &str) {
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
            "runArgs": ["--runtime=runc"],
            {lifecycle_json}
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

fn write_minimal_pod_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// onCreateCommand should run only on first container creation — not on
/// subsequent enters that reuse the same container.
#[test]
fn on_create_command_runs_once() {
    let repo = TestRepo::new();

    write_devcontainer_with_lifecycle(&repo, r#""onCreateCommand": "touch /tmp/on_create_marker""#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // First enter — onCreateCommand should have created the marker file.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "lc-once", "--", "cat", "/tmp/on_create_marker"])
        .success()
        .expect("first rumpel enter failed");
    // File exists, so cat succeeds (empty output is fine for an empty file).
    let _ = String::from_utf8_lossy(&stdout);

    // Remove the marker so we can detect if the command runs again.
    pod_command(&repo, &daemon)
        .args(["enter", "lc-once", "--", "rm", "/tmp/on_create_marker"])
        .success()
        .expect("marker removal failed");

    // Second enter — onCreateCommand must NOT run again.
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "lc-once",
            "--",
            "sh",
            "-c",
            "test -f /tmp/on_create_marker && echo exists || echo missing",
        ])
        .success()
        .expect("second rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "missing",
        "onCreateCommand should not re-run on subsequent enters"
    );
}

/// postCreateCommand must run after onCreateCommand — verify via sequence
/// numbers written to files.
#[test]
fn post_create_command_runs_after_on_create() {
    let repo = TestRepo::new();

    // Each command appends a line; ordering is then verifiable.
    write_devcontainer_with_lifecycle(
        &repo,
        r#""onCreateCommand": "echo 1 >> /tmp/lifecycle_order",
            "postCreateCommand": "echo 2 >> /tmp/lifecycle_order""#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "lc-order", "--", "cat", "/tmp/lifecycle_order"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        vec!["1", "2"],
        "onCreateCommand must run before postCreateCommand"
    );
}

/// postStartCommand should execute every time the container starts — including
/// after a stop/start cycle.
#[test]
fn post_start_command_runs_each_start() {
    let repo = TestRepo::new();

    write_devcontainer_with_lifecycle(
        &repo,
        r#""postStartCommand": "echo start >> /tmp/start_count""#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // First enter — triggers a start.
    pod_command(&repo, &daemon)
        .args(["enter", "lc-start", "--", "echo", "ok"])
        .success()
        .expect("first enter failed");

    // Stop the pod, then start it again.
    pod_command(&repo, &daemon)
        .args(["stop", "lc-start"])
        .success()
        .expect("rumpel stop failed");

    pod_command(&repo, &daemon)
        .args(["enter", "lc-start", "--", "echo", "ok"])
        .success()
        .expect("second enter failed");

    // Verify the command ran twice.
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "lc-start",
            "--",
            "sh",
            "-c",
            "grep -c start /tmp/start_count",
        ])
        .success()
        .expect("count check failed");

    let count: usize = String::from_utf8_lossy(&stdout)
        .trim()
        .parse()
        .expect("expected a number");
    assert!(
        count >= 2,
        "postStartCommand should have run at least twice, ran {count} times"
    );
}

/// postAttachCommand should run on every rumpel enter.
#[test]
fn post_attach_command_runs_each_enter() {
    let repo = TestRepo::new();

    write_devcontainer_with_lifecycle(
        &repo,
        r#""postAttachCommand": "echo attach >> /tmp/attach_count""#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter twice without stopping.
    pod_command(&repo, &daemon)
        .args(["enter", "lc-attach", "--", "echo", "ok"])
        .success()
        .expect("first enter failed");

    pod_command(&repo, &daemon)
        .args(["enter", "lc-attach", "--", "echo", "ok"])
        .success()
        .expect("second enter failed");

    // Verify the command ran twice.
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "lc-attach",
            "--",
            "sh",
            "-c",
            "grep -c attach /tmp/attach_count",
        ])
        .success()
        .expect("count check failed");

    let count: usize = String::from_utf8_lossy(&stdout)
        .trim()
        .parse()
        .expect("expected a number");
    assert!(
        count >= 2,
        "postAttachCommand should have run at least twice, ran {count} times"
    );
}

/// A lifecycle command given as a plain string should be executed via a shell.
#[test]
fn lifecycle_command_string_format() {
    let repo = TestRepo::new();

    // Use shell-specific syntax (variable expansion) to prove a shell is used.
    write_devcontainer_with_lifecycle(
        &repo,
        r#""postCreateCommand": "echo hello > /tmp/string_fmt""#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "lc-str", "--", "cat", "/tmp/string_fmt"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "hello");
}

/// A lifecycle command given as an array should be executed directly (no shell).
#[test]
fn lifecycle_command_array_format() {
    let repo = TestRepo::new();

    write_devcontainer_with_lifecycle(
        &repo,
        r#""postCreateCommand": ["sh", "-c", "echo hello > /tmp/array_fmt"]"#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "lc-arr", "--", "cat", "/tmp/array_fmt"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "hello");
}

/// A lifecycle command given as an object should run each value in parallel.
/// Both commands must have completed by the time we inspect results.
#[test]
fn lifecycle_command_object_parallel() {
    let repo = TestRepo::new();

    write_devcontainer_with_lifecycle(
        &repo,
        r#""postCreateCommand": {
                "a": "echo alpha > /tmp/parallel_a",
                "b": "echo bravo > /tmp/parallel_b"
            }"#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "lc-obj",
            "--",
            "sh",
            "-c",
            "cat /tmp/parallel_a /tmp/parallel_b | sort",
        ])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        vec!["alpha", "bravo"],
        "both parallel commands should have run"
    );
}

/// If onCreateCommand fails (non-zero exit), postCreateCommand should NOT run.
#[test]
fn lifecycle_command_failure_stops_chain() {
    let repo = TestRepo::new();

    write_devcontainer_with_lifecycle(
        &repo,
        r#""onCreateCommand": "exit 1",
            "postCreateCommand": "touch /tmp/should_not_exist""#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // The first enter should fail because onCreateCommand exits 1.
    let _ = pod_command(&repo, &daemon)
        .args(["enter", "lc-fail", "--", "echo", "ok"])
        .output();

    // Second enter should succeed (failed lifecycle commands are marked as
    // "ran" and not retried), and postCreateCommand should never have executed.
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "lc-fail",
            "--",
            "sh",
            "-c",
            "test -f /tmp/should_not_exist && echo exists || echo missing",
        ])
        .success()
        .expect("check enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "missing",
        "postCreateCommand must not run when onCreateCommand fails"
    );
}

/// The `waitFor` property should block `rumpel enter` until the specified
/// lifecycle command has completed.
#[test]
fn wait_for_setting() {
    let repo = TestRepo::new();

    // postCreateCommand sleeps briefly then writes a marker. With
    // "waitFor": "postCreateCommand", the enter should block until it finishes.
    write_devcontainer_with_lifecycle(
        &repo,
        r#""postCreateCommand": "sleep 1 && echo done > /tmp/wait_marker",
            "waitFor": "postCreateCommand""#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "lc-wait", "--", "cat", "/tmp/wait_marker"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "done",
        "rumpel enter should have waited for postCreateCommand to finish"
    );
}
