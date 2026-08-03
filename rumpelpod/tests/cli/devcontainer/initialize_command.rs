// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for host-side devcontainer initializeCommand execution.

use std::collections::HashMap;
use std::fs;

use rumpelpod::config::{ContainerEngine, Host};
use rumpelpod::daemon::protocol::{Daemon, DaemonClient, LaunchProgress, PodLaunchParams, PodName};
use rumpelpod::CommandExt;
use serde_json::json;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::{
    executor_mode, executor_supports_stop, skip_test, ExecutorMode, ExecutorResources,
};

fn configure(repo: &TestRepo, home: &TestHome) -> (ExecutorResources, TestDaemon) {
    let executor = ExecutorResources::setup(home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).expect("write rumpelpod config");
    let daemon = TestDaemon::start(home);
    (executor, daemon)
}

fn initialize_json(command: serde_json::Value) -> String {
    format!(r#", "initializeCommand": {command}"#)
}

#[test]
fn initialize_command_string_runs_in_workspace_before_build() {
    let repo = TestRepo::new();
    let extra_dockerfile = "RUN test -f /home/testuser/workspace/initialize.marker";
    let extra_json = initialize_json(json!("printf initialized > initialize.marker"));
    write_test_devcontainer(&repo, extra_dockerfile, &extra_json);

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "init-string", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.marker")).expect("read initialize marker"),
        "initialized"
    );
}

#[test]
fn initialize_command_array_expands_spec_variables() {
    let repo = TestRepo::new();
    let output_path = repo.path().join("initialize.variables");
    let command = json!([
        "/bin/sh",
        "-c",
        r#"output=$1; shift; printf '%s\n' "$@" > "$output""#,
        "initializeCommand",
        "${localEnv:RUMPELPOD_INITIALIZE_OUTPUT}",
        "${devcontainerId}",
        "${localWorkspaceFolder}",
        "${localWorkspaceFolderBasename}",
        "${containerWorkspaceFolder}",
        "${containerWorkspaceFolderBasename}",
        "${localEnv:RUMPELPOD_INITIALIZE_SET}",
        "${localEnv:RUMPELPOD_INITIALIZE_EMPTY:fallback}",
        "${localEnv:RUMPELPOD_INITIALIZE_MISSING:fallback}"
    ]);
    let extra_json = initialize_json(command);
    write_test_devcontainer(&repo, "", &extra_json);

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .env("RUMPELPOD_INITIALIZE_OUTPUT", &output_path)
        .env("RUMPELPOD_INITIALIZE_SET", "from-host")
        .env("RUMPELPOD_INITIALIZE_EMPTY", "")
        .env_remove("RUMPELPOD_INITIALIZE_MISSING")
        .args(["enter", "--create", "init-vars", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    let output = fs::read_to_string(&output_path).expect("read substitution output");
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), 8, "unexpected substitution output: {output}");
    assert_eq!(
        lines[0].len(),
        64,
        "devcontainerId should be a SHA-256 hex digest"
    );
    assert!(
        lines[0].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "devcontainerId should contain only hexadecimal digits"
    );
    let canonical_repo = repo.path().canonicalize().expect("canonicalize repo");
    assert_eq!(lines[1], canonical_repo.to_string_lossy());
    assert_eq!(
        lines[2],
        canonical_repo
            .file_name()
            .expect("repo basename")
            .to_string_lossy()
    );
    assert_eq!(lines[3], "/home/testuser/workspace");
    assert_eq!(lines[4], "workspace");
    assert_eq!(lines[5], "from-host");
    assert_eq!(lines[6], "");
    assert_eq!(lines[7], "fallback");
}

#[test]
fn initialize_command_object_runs_all_commands() {
    let repo = TestRepo::new();
    let command = json!({
        "string": "printf string > initialize.string",
        "array": [
            "/bin/sh",
            "-c",
            "printf array > initialize.array"
        ]
    });
    let extra_json = initialize_json(command);
    write_test_devcontainer(&repo, "", &extra_json);

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "init-object", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.string")).expect("read string marker"),
        "string"
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.array")).expect("read array marker"),
        "array"
    );
}

#[test]
fn initialize_command_failure_aborts_creation() {
    let repo = TestRepo::new();
    let extra_json = initialize_json(json!("printf attempted > initialize.failed; exit 23"));
    write_test_devcontainer(&repo, "", &extra_json);

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "init-failure", "--", "true"])
        .output()
        .expect("run rumpel enter");
    assert!(!output.status.success(), "creation should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("initializeCommand"),
        "unexpected stderr: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.failed")).expect("read failure marker"),
        "attempted"
    );

    write_test_devcontainer(&repo, "", "");
    let output = pod_command(&repo, &daemon)
        .args(["enter", "init-failure", "--", "true"])
        .output()
        .expect("check failed pod absence");
    assert!(
        !output.status.success(),
        "initializer failure should prevent the daemon from creating a pod"
    );
}

#[test]
fn daemon_refuses_creation_without_client_preflight() {
    let repo = TestRepo::new();
    write_test_devcontainer(&repo, "", "");

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    let client = DaemonClient::new_unix(&daemon.socket_path);
    let mut progress = client
        .launch_pod(PodLaunchParams {
            pod_name: PodName::new("init-preflight").expect("valid pod name"),
            repo_path: repo.path().to_path_buf(),
            host_branch: None,
            host: Host::Localhost {
                engine: ContainerEngine::Auto,
            },
            create_token: None,
            git_identity: None,
            claude_cli_path: None,
            codex_cli_path: None,
            pi_cli_path: None,
            grok_cli_path: None,
            inject_system_prompt: false,
            description_file: None,
            local_env_vars: HashMap::new(),
            ssh_auth_sock: None,
        })
        .expect("launch request");
    for _line in &mut progress {}
    let error = progress.finish().expect_err("creation should be rejected");
    let error = format!("{error:#}");
    assert!(
        error.contains("disappeared before create initialization"),
        "unexpected error: {error}"
    );
}

#[test]
fn daemon_serializes_create_reservations() {
    let repo = TestRepo::new();
    write_test_devcontainer(&repo, "", "");

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    let client = DaemonClient::new_unix(&daemon.socket_path);
    let pod_name = PodName::new("init-reservation").expect("valid pod name");
    let token = client
        .reserve_create(pod_name.clone(), repo.path().to_path_buf())
        .expect("first reservation");
    let error = client
        .reserve_create(pod_name.clone(), repo.path().to_path_buf())
        .expect_err("second reservation should be rejected");
    let error = format!("{error:#}");
    assert!(
        error.contains("creation is already in progress"),
        "unexpected error: {error}"
    );
    client
        .release_create_reservation(pod_name.clone(), repo.path().to_path_buf(), token)
        .expect("release first reservation");
    client
        .reserve_create(pod_name, repo.path().to_path_buf())
        .expect("reserve after release");
}

#[test]
fn initialize_command_runs_for_create_and_recreate() {
    let repo = TestRepo::new();
    let extra_json = initialize_json(json!("printf x >> initialize.count"));
    write_test_devcontainer(&repo, "", &extra_json);

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "init-recreate", "--", "true"])
        .success()
        .expect("rumpel enter failed");
    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.count")).expect("read create count"),
        "x"
    );

    pod_command(&repo, &daemon)
        .args(["recreate", "init-recreate"])
        .success()
        .expect("rumpel recreate failed");
    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.count")).expect("read recreate count"),
        "xx"
    );
}

#[test]
fn initialize_command_does_not_run_for_restart() {
    if !executor_supports_stop() {
        return;
    }

    let repo = TestRepo::new();
    let extra_json = initialize_json(json!("printf x >> initialize.count"));
    write_test_devcontainer(&repo, "", &extra_json);

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "init-restart", "--", "true"])
        .success()
        .expect("rumpel enter failed");
    pod_command(&repo, &daemon)
        .args(["stop", "init-restart"])
        .success()
        .expect("rumpel stop failed");
    pod_command(&repo, &daemon)
        .args(["enter", "init-restart", "--", "true"])
        .success()
        .expect("rumpel restart failed");

    assert_eq!(
        fs::read_to_string(repo.path().join("initialize.count")).expect("read restart count"),
        "x"
    );
}

#[test]
fn initialize_command_failure_aborts_recreate() {
    let repo = TestRepo::new();
    write_test_devcontainer(&repo, "", &initialize_json(json!("true")));

    let home = TestHome::new();
    let (_executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "init-recreate-failure",
            "--",
            "/bin/sh",
            "-c",
            "printf preserved > /tmp/initialize-preserved",
        ])
        .success()
        .expect("rumpel enter failed");

    let failing = initialize_json(json!("exit 23"));
    write_test_devcontainer(&repo, "", &failing);
    let output = pod_command(&repo, &daemon)
        .args(["recreate", "init-recreate-failure"])
        .output()
        .expect("run rumpel recreate");
    assert!(!output.status.success(), "recreate should fail");

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "init-recreate-failure",
            "--",
            "cat",
            "/tmp/initialize-preserved",
        ])
        .success()
        .expect("existing pod should survive failed initializer");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "preserved");
}

#[test]
fn initialize_command_receives_target_docker_host() {
    if matches!(executor_mode(), ExecutorMode::Podman | ExecutorMode::K8s) {
        skip_test();
        return;
    }

    let repo = TestRepo::new();
    let output_path = repo.path().join("initialize.docker-host");
    let command = json!([
        "/bin/sh",
        "-c",
        r#"printf '%s\n%s\n' "$DOCKER_HOST" "$1" > "$2""#,
        "initializeCommand",
        "${localEnv:DOCKER_HOST}",
        "${localEnv:RUMPELPOD_INITIALIZE_OUTPUT}"
    ]);
    write_test_devcontainer(&repo, "", &initialize_json(command));

    let home = TestHome::new();
    let (executor, daemon) = configure(&repo, &home);
    pod_command(&repo, &daemon)
        .env("DOCKER_HOST", "unix:///tmp/must-be-replaced.sock")
        .env("RUMPELPOD_INITIALIZE_OUTPUT", &output_path)
        .args(["enter", "--create", "init-docker-host", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    let output = fs::read_to_string(&output_path).expect("read DOCKER_HOST output");
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), 2, "unexpected DOCKER_HOST output: {output}");
    assert_eq!(
        lines[0], lines[1],
        "child environment and localEnv substitution should match"
    );

    let config: serde_json::Value = json5::from_str(&executor.json).expect("parse executor config");
    match config.get("host").and_then(serde_json::Value::as_str) {
        Some(host) => assert_eq!(lines[0], host),
        None => {
            let docker_host = lines[0];
            assert!(
                docker_host.starts_with("unix://"),
                "local Docker should receive a Unix socket target: {docker_host}"
            );
            assert_ne!(docker_host, "unix:///tmp/must-be-replaced.sock");
        }
    }
}
