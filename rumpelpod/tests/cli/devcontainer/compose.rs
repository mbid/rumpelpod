// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{pod_command, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::executor::{ExecutorMode, ExecutorResources};

fn compose_available() -> bool {
    Command::new("docker")
        .args(["compose", "version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn require_local_compose() -> bool {
    if !matches!(crate::executor::executor_mode(), ExecutorMode::Docker) || !compose_available() {
        crate::executor::skip_test();
        return false;
    }
    true
}

fn write_compose_devcontainer(
    repo: &TestRepo,
    agent_command: &str,
    agent_config: &str,
    extra_services: &str,
    extra_devcontainer: &str,
) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("create .devcontainer");
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {r#"
            FROM cgr.dev/chainguard/wolfi-base
            RUN apk add --no-cache git shadow socat
            RUN useradd -m -u 1000 {TEST_USER}
            RUN mkdir -p /home/{TEST_USER}/data && chown {TEST_USER} /home/{TEST_USER}/data
            USER root
        "#},
    )
    .expect("write compose Dockerfile");
    let compose = format!(
        "services:\n  agent:\n    build:\n      context: ..\n      dockerfile: .devcontainer/Dockerfile\n    command: {agent_command}\n{agent_config}\n{extra_services}\n"
    );
    fs::write(devcontainer_dir.join("compose.yaml"), compose).expect("write compose file");
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
            {{
                "dockerComposeFile": "compose.yaml",
                "service": "agent",
                "workspaceFolder": "{TEST_REPO_PATH}",
                "containerUser": "{TEST_USER}"{extra_devcontainer}
            }}
        "#},
    )
    .expect("write compose devcontainer.json");
}

fn try_echo(port: u16, message: &str) -> Option<String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.write_all(message.as_bytes()).ok()?;
    stream.shutdown(std::net::Shutdown::Write).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn forwarded_local_port(repo: &TestRepo, daemon: &TestDaemon, pod_name: &str, target: &str) -> u16 {
    let output = pod_command(repo, daemon)
        .args(["ports", pod_name])
        .success()
        .expect("list compose ports");
    let output = String::from_utf8_lossy(&output);
    output
        .lines()
        .find_map(|line| {
            let mut columns = line.split_whitespace();
            (columns.next() == Some(target))
                .then(|| columns.next().expect("forwarded port has a local port"))
        })
        .expect("forwarded target is listed")
        .parse()
        .expect("local port is numeric")
}

#[test]
fn compose_build_cache_reuses_images_and_tracks_context_content() {
    println!("xtest:timeout=300");
    if !require_local_compose() {
        return;
    }

    let repo = TestRepo::new();
    write_compose_devcontainer(&repo, r#"["sleep", "infinity"]"#, "", "", "");
    let marker = repo.path().join(".devcontainer/cache-marker.txt");
    fs::write(&marker, "version-1\n").expect("write compose cache marker");
    let dockerfile = repo.path().join(".devcontainer/Dockerfile");
    let mut contents = fs::read_to_string(&dockerfile).expect("read compose Dockerfile");
    contents.push_str(
        "COPY .devcontainer/cache-marker.txt /cache-marker.txt\nRUN echo compose-cache-build-marker > /build-marker\n",
    );
    fs::write(&dockerfile, contents).expect("extend compose Dockerfile");

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let first = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "compose-cache-1",
            "--",
            "cat",
            "/cache-marker.txt",
        ])
        .output()
        .expect("create first compose cache pod");
    assert!(first.status.success());
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert_eq!(first_stdout.lines().last(), Some("version-1"));
    let first_output = format!("{first_stdout}{first_stderr}");
    assert!(
        first_output.contains("compose-cache-build-marker"),
        "first pod should run the Compose build: {first_output}"
    );

    let second = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "compose-cache-2",
            "--",
            "cat",
            "/cache-marker.txt",
        ])
        .output()
        .expect("create second compose cache pod");
    assert!(second.status.success());
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(second_stdout.lines().last(), Some("version-1"));
    let second_output = format!("{second_stdout}{second_stderr}");
    assert!(
        !second_output.contains("compose-cache-build-marker"),
        "second pod should reuse the Compose image: {second_output}"
    );

    fs::write(&marker, "version-2\n").expect("update compose cache marker");
    let third = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "compose-cache-3",
            "--",
            "cat",
            "/cache-marker.txt",
        ])
        .output()
        .expect("create third compose cache pod");
    assert!(third.status.success());
    let third_stdout = String::from_utf8_lossy(&third.stdout);
    let third_stderr = String::from_utf8_lossy(&third.stderr);
    assert_eq!(third_stdout.lines().last(), Some("version-2"));
    let third_output = format!("{third_stdout}{third_stderr}");
    assert!(
        third_output.contains("compose-cache-build-marker"),
        "changed context should rerun the Compose build: {third_output}"
    );

    for pod in ["compose-cache-1", "compose-cache-2", "compose-cache-3"] {
        pod_command(&repo, &daemon)
            .args(["delete", "--force", "--wait", pod])
            .success()
            .expect("delete compose cache project");
    }
}

#[test]
fn compose_sidecar_forward_survives_project_restart() {
    println!("xtest:timeout=240");
    if !require_local_compose() {
        return;
    }

    let repo = TestRepo::new();
    write_compose_devcontainer(
        &repo,
        r#"["sleep", "infinity"]"#,
        "",
        r#"  db:
    build:
      context: ..
      dockerfile: .devcontainer/Dockerfile
    command: ["socat", "TCP-LISTEN:19876,fork,reuseaddr", "EXEC:cat"]"#,
        r#",
                "forwardPorts": ["db:19876"]"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let mut daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    pod_command(&repo, &daemon)
        .args(["enter", "--create", "compose-forward", "--", "true"])
        .success()
        .expect("create compose pod");

    let local_port = forwarded_local_port(&repo, &daemon, "compose-forward", "db:19876");
    assert_eq!(
        try_echo(local_port, "compose sidecar"),
        Some("compose sidecar".into())
    );

    daemon.kill();
    drop(daemon);
    let daemon = TestDaemon::start(&home);
    let local_port = forwarded_local_port(&repo, &daemon, "compose-forward", "db:19876");
    assert_eq!(
        try_echo(local_port, "after daemon restart"),
        Some("after daemon restart".into())
    );

    pod_command(&repo, &daemon)
        .args(["stop", "--wait", "compose-forward"])
        .success()
        .expect("stop compose project");
    pod_command(&repo, &daemon)
        .args(["enter", "compose-forward", "--", "true"])
        .success()
        .expect("restart compose project");
    let local_port = forwarded_local_port(&repo, &daemon, "compose-forward", "db:19876");
    assert_eq!(
        try_echo(local_port, "after restart"),
        Some("after restart".into())
    );

    pod_command(&repo, &daemon)
        .args(["delete", "--force", "--wait", "compose-forward"])
        .success()
        .expect("delete compose project");
}

#[test]
fn compose_override_command_and_run_services_are_applied() {
    println!("xtest:timeout=240");
    if !require_local_compose() {
        return;
    }

    let repo = TestRepo::new();
    write_compose_devcontainer(
        &repo,
        r#"["false"]"#,
        "",
        r#"  unused:
    build:
      context: ..
      dockerfile: .devcontainer/Dockerfile
    command: ["sleep", "infinity"]"#,
        r#",
                "overrideCommand": true,
                "runServices": ["agent"]"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    pod_command(&repo, &daemon)
        .args(["enter", "--create", "compose-override", "--", "true"])
        .success()
        .expect("overrideCommand should replace the exiting compose command");

    let repo_filter = format!("label=dev.rumpelpod.repo_path={}", repo.path().display());
    let unused = Command::new("docker")
        .args([
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            "label=com.docker.compose.service=unused",
        ])
        .args(["--filter", &repo_filter])
        .output()
        .expect("query unused compose service");
    assert!(
        unused.status.success(),
        "docker container ls failed: {}",
        String::from_utf8_lossy(&unused.stderr)
    );
    assert!(
        unused.stdout.is_empty(),
        "runServices created the unselected service"
    );
}

#[test]
fn compose_default_command_exit_has_actionable_error() {
    println!("xtest:timeout=240");
    if !require_local_compose() {
        return;
    }

    let repo = TestRepo::new();
    write_compose_devcontainer(&repo, r#"["false"]"#, "", "", "");
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "compose-exits", "--", "true"])
        .output()
        .expect("run compose pod with exiting command");
    assert!(
        !output.status.success(),
        "exiting agent service should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exited") && stderr.contains("overrideCommand"),
        "compose exit error should explain the remedy: {stderr}"
    );
}

#[test]
fn compose_service_user_is_used_when_devcontainer_has_no_user() {
    println!("xtest:timeout=240");
    if !require_local_compose() {
        return;
    }

    let repo = TestRepo::new();
    write_compose_devcontainer(
        &repo,
        r#"["sleep", "infinity"]"#,
        &format!("    user: {TEST_USER}"),
        "",
        "",
    );
    let devcontainer_path = repo.path().join(".devcontainer/devcontainer.json");
    let devcontainer = fs::read_to_string(&devcontainer_path).unwrap();
    let user_property = format!(",\n    \"containerUser\": \"{TEST_USER}\"");
    let devcontainer_without_user = devcontainer.replace(&user_property, "");
    assert_ne!(devcontainer, devcontainer_without_user);
    fs::write(&devcontainer_path, devcontainer_without_user).unwrap();

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "compose-user", "--", "id", "-un"])
        .success()
        .expect("create compose pod with a service-level user");
    assert_eq!(
        String::from_utf8_lossy(&output).lines().last(),
        Some(TEST_USER)
    );

    pod_command(&repo, &daemon)
        .args(["delete", "--force", "--wait", "compose-user"])
        .success()
        .expect("delete compose project");
}

#[test]
fn compose_fork_gets_independent_project_resources() {
    println!("xtest:timeout=240");
    if !require_local_compose() {
        return;
    }

    let repo = TestRepo::new();
    write_compose_devcontainer(
        &repo,
        r#"["sleep", "infinity"]"#,
        r#"    container_name: fixed-compose-container
    volumes:
      - data:/home/testuser/data"#,
        r#"volumes:
  data:"#,
        "",
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "compose-source",
            "--",
            "sh",
            "-c",
            "mkdir -p /home/testuser/data && echo source > /home/testuser/data/marker",
        ])
        .success()
        .expect("create source compose pod");
    pod_command(&repo, &daemon)
        .args(["fork", "compose-source", "compose-fork"])
        .success()
        .expect("fork compose pod");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            "compose-fork",
            "--",
            "test",
            "!",
            "-e",
            "/home/testuser/data/marker",
        ])
        .success()
        .expect("fork should not share the source project's named volume");

    for pod in ["compose-source", "compose-fork"] {
        pod_command(&repo, &daemon)
            .args(["delete", "--force", "--wait", pod])
            .success()
            .expect("delete compose project");
    }
}
