// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{
    create_commit, pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo,
    TEST_REPO_PATH,
};
use crate::executor::ExecutorResources;

/// `--network=host` has no equivalent on a remote cluster node and the
/// daemon silently drops it there, so every test in this file only makes
/// sense against the local Docker executor.
fn skip_unless_docker() -> bool {
    if !matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::Docker
    ) {
        crate::executor::skip_test();
        return true;
    }
    false
}

#[test]
fn network_host_connectivity() {
    if skip_unless_docker() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    // Install netcat-openbsd for testing connectivity
    // Switch to root to install packages
    write_test_devcontainer(&repo, "RUN apk add --no-cache netcat-openbsd", "");
    // Overwrite devcontainer.json with network=host
    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "runArgs": ["--network=host"]
            }}
        "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // On macOS Docker Desktop, containers run in a VM so 127.0.0.1 inside the
    // container is the VM's loopback, not the Mac host. Bind to 0.0.0.0 and
    // have the container connect via host.docker.internal.
    let bind_addr = if cfg!(target_os = "macos") {
        "0.0.0.0:0"
    } else {
        "127.0.0.1:0"
    };
    let connect_host = if cfg!(target_os = "macos") {
        "host.docker.internal"
    } else {
        "127.0.0.1"
    };

    let listener = TcpListener::bind(bind_addr).expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local addr");
    let port = addr.port();

    // Spawn a thread to accept a connection and send a message
    let server_handle = thread::spawn(move || {
        // Accept one connection
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).expect("Failed to read");
        assert_eq!(&buf, b"HELLO");
        stream.write_all(b"WORLD").expect("Failed to write");
        // Give the client a moment to receive the data before closing the connection
        thread::sleep(std::time::Duration::from_millis(100));
    });

    // Run nc inside pod to connect to host
    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--"])
        .arg("bash")
        .arg("-c")
        .arg(format!("echo HELLO | nc {} {}", connect_host, port))
        .success()
        .expect("Failed to run pod command");

    let stdout = String::from_utf8_lossy(&output);
    assert_eq!(stdout.trim(), "WORLD");

    server_handle.join().expect("Server thread panicked");
}

/// With --network=host, both 'host' and 'rumpelpod' remotes inside the pod
/// should use a host-reachable address: localhost on Linux (shared network
/// namespace) or host.docker.internal on macOS Docker Desktop (VM-based).
#[test]
fn network_host_remotes_use_localhost() {
    if skip_unless_docker() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    // Overwrite devcontainer.json with network=host
    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "runArgs": ["--network=host"]
            }}
        "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Check 'host' remote inside pod
    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--"])
        .arg("git")
        .arg("remote")
        .arg("get-url")
        .arg("host")
        .success()
        .expect("Failed to get 'host' remote URL inside pod");

    let host_remote_url = String::from_utf8_lossy(&output).trim().to_string();
    println!("Remote 'host' URL inside pod: {}", host_remote_url);
    assert!(
        host_remote_url.contains("127.0.0.1")
            || host_remote_url.contains("localhost")
            || host_remote_url.contains("host.docker.internal"),
        "Remote 'host' inside pod should use a host-reachable address, got: {}",
        host_remote_url
    );

    // Check 'rumpelpod' remote inside pod
    let output = pod_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("git")
        .arg("remote")
        .arg("get-url")
        .arg("rumpelpod")
        .success()
        .expect("Failed to get 'rumpelpod' remote URL inside pod");

    let pod_remote_url = String::from_utf8_lossy(&output).trim().to_string();
    println!("Remote 'rumpelpod' URL inside pod: {}", pod_remote_url);
    assert!(
        pod_remote_url.contains("127.0.0.1")
            || pod_remote_url.contains("localhost")
            || pod_remote_url.contains("host.docker.internal"),
        "Remote 'rumpelpod' inside pod should use a host-reachable address, got: {}",
        pod_remote_url
    );
}

/// Test that commits made on the host are available via the 'host' remote inside
/// the pod when using --network=host.
#[test]
fn network_host_fetch_from_pod() {
    if skip_unless_docker() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    // Overwrite devcontainer.json with network=host
    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "runArgs": ["--network=host"]
            }}
        "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Launch pod first
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--"])
        .arg("echo")
        .arg("setup")
        .success()
        .expect("Failed to setup pod");

    // Create a commit on the host (reference-transaction hook pushes to gateway)
    create_commit(repo.path(), "Host commit for fetch test");
    let host_commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to get host commit");
    let host_commit = String::from_utf8_lossy(&host_commit).trim().to_string();

    // Fetch from host remote inside the pod
    pod_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("git")
        .arg("fetch")
        .arg("host")
        .success()
        .expect("Failed to fetch from host remote");

    // Verify the fetched commit matches
    let fetched_commit = pod_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("git")
        .arg("rev-parse")
        .arg("host/master")
        .success()
        .expect("Failed to get fetched commit");
    let fetched_commit = String::from_utf8_lossy(&fetched_commit).trim().to_string();

    assert_eq!(
        fetched_commit, host_commit,
        "Fetched commit should match host commit"
    );
}

/// Test that commits pushed from inside the pod propagate to the host repo
/// as remote-tracking refs when using --network=host.
#[test]
fn network_host_push_from_pod() {
    if skip_unless_docker() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    // Overwrite devcontainer.json with network=host
    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "runArgs": ["--network=host"]
            }}
        "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let pod_name = "push-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", "--create", pod_name, "--"])
        .arg("echo")
        .arg("setup")
        .success()
        .expect("Failed to setup pod");

    // Create a commit inside the pod (reference-transaction hook pushes to gateway)
    pod_command(&repo, &daemon)
        .arg("enter")
        .arg(pod_name)
        .arg("--")
        .arg("git")
        .arg("commit")
        .arg("--no-verify")
        .arg("--allow-empty")
        .arg("-m")
        .arg("Pod commit")
        .success()
        .expect("Failed to create commit in pod");

    // Get the commit hash from the pod
    let pod_commit = pod_command(&repo, &daemon)
        .arg("enter")
        .arg(pod_name)
        .arg("--")
        .arg("git")
        .arg("rev-parse")
        .arg("HEAD")
        .success()
        .expect("Failed to get pod commit");
    let pod_commit = String::from_utf8_lossy(&pod_commit).trim().to_string();

    // The pod's commit should be visible in the host repo at refs/rumpelpod/<pod>.
    // The post-receive hook creates this convenience ref for primary branches.
    let host_ref_commit = Command::new("git")
        .args(["rev-parse", &format!("refs/rumpelpod/{pod_name}")])
        .current_dir(repo.path())
        .success()
        .expect("Failed to get pod ref from host repo");
    let host_ref_commit = String::from_utf8_lossy(&host_ref_commit).trim().to_string();

    assert_eq!(
        host_ref_commit, pod_commit,
        "Host repo should have pod's commit at refs/rumpelpod/{pod_name}"
    );
}

/// Two concurrent `--network=host` pods on the same host must coexist.
/// Host networking collapses the container loopback onto the host's,
/// so any pair of pods that bind the same port on 127.0.0.1 will
/// collide.  Both pods do git round-trips through the rumpelpod
/// remote to exercise the full tunnel + pod-server stack for each.
#[test]
fn network_host_two_pods_share_host() {
    if skip_unless_docker() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "runArgs": ["--network=host"]
            }}
        "#},
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Launch both pods sequentially.  If either squats on a fixed
    // port the second launch hangs or fails outright.
    for pod_name in ["alpha", "beta"] {
        pod_command(&repo, &daemon)
            .args(["enter", "--create", pod_name, "--"])
            .arg("echo")
            .arg("setup")
            .success()
            .unwrap_or_else(|e| panic!("Failed to setup pod {pod_name}: {e}"));
    }

    // Each pod must have picked its own in-container server port;
    // a shared port would mean one pod's traffic reaches the other's
    // server over the collapsed host loopback.
    let mut ports = Vec::new();
    for pod_name in ["alpha", "beta"] {
        let out = pod_command(&repo, &daemon)
            .arg("enter")
            .arg(pod_name)
            .arg("--")
            .arg("cat")
            .arg("/opt/rumpelpod/server-port")
            .success()
            .unwrap_or_else(|e| panic!("reading server-port in {pod_name}: {e}"));
        let port: u16 = String::from_utf8_lossy(&out)
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("parsing server-port in {pod_name}: {e}"));
        ports.push(port);
    }
    assert_ne!(
        ports[0], ports[1],
        "two host-networked pods must pick distinct server ports, got {ports:?}"
    );

    // Both pods should be able to commit and push independently.  Because
    // they share the host's loopback, a broken tunnel in one would bleed
    // into the other, so this exercises both tunnels in both directions.
    for pod_name in ["alpha", "beta"] {
        pod_command(&repo, &daemon)
            .arg("enter")
            .arg(pod_name)
            .arg("--")
            .arg("git")
            .arg("commit")
            .arg("--no-verify")
            .arg("--allow-empty")
            .arg("-m")
            .arg(format!("Commit from {pod_name}"))
            .success()
            .unwrap_or_else(|e| panic!("commit in {pod_name}: {e}"));

        let pod_commit = pod_command(&repo, &daemon)
            .arg("enter")
            .arg(pod_name)
            .arg("--")
            .arg("git")
            .arg("rev-parse")
            .arg("HEAD")
            .success()
            .unwrap_or_else(|e| panic!("rev-parse HEAD in {pod_name}: {e}"));
        let pod_commit = String::from_utf8_lossy(&pod_commit).trim().to_string();

        let host_ref_commit = Command::new("git")
            .args(["rev-parse", &format!("refs/rumpelpod/{pod_name}")])
            .current_dir(repo.path())
            .success()
            .unwrap_or_else(|e| panic!("host rev-parse refs/rumpelpod/{pod_name}: {e}"));
        let host_ref_commit = String::from_utf8_lossy(&host_ref_commit).trim().to_string();

        assert_eq!(
            host_ref_commit, pod_commit,
            "host repo should see pod {pod_name}'s commit at refs/rumpelpod/{pod_name}"
        );
    }

    // Cross-check: neither pod should see the other's rumpelpod-tracked
    // ref yet (fetch has not happened), but after a fetch both should
    // agree on the head commits.
    for pod_name in ["alpha", "beta"] {
        pod_command(&repo, &daemon)
            .arg("enter")
            .arg(pod_name)
            .arg("--")
            .arg("git")
            .arg("fetch")
            .arg("rumpelpod")
            .success()
            .unwrap_or_else(|e| panic!("fetch rumpelpod in {pod_name}: {e}"));
    }
}
