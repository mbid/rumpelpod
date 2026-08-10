// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

use rumpelpod::CommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::{self, ExecutorResources};

fn container_id(pod_name: &str) -> String {
    let output = Command::new("docker")
        .args([
            "ps",
            "-q",
            "--filter",
            &format!("label=dev.rumpelpod.name={pod_name}"),
        ])
        .success()
        .expect("docker ps failed");
    let id = String::from_utf8_lossy(&output).trim().to_string();
    assert!(!id.is_empty(), "container for pod '{pod_name}' not found");
    id
}

fn process_pid(container_id: &str, pattern: &str) -> Option<String> {
    let output = Command::new("docker")
        .args(["exec", container_id, "pgrep", "-f", pattern])
        .output()
        .expect("docker exec pgrep failed");
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::to_string)
}

fn tunnel_server_pid(container_id: &str) -> Option<String> {
    process_pid(container_id, "/opt/rumpelpod/bin/rumpel tunnel-server")
}

fn wait_for_new_tunnel_server(container_id: &str, old_pid: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(pid) = tunnel_server_pid(container_id) {
            if pid != old_pid {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "tunnel server in container '{container_id}' was not replaced"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn stop_container_server(container_id: &str) {
    let pid = process_pid(container_id, "/opt/rumpelpod/bin/rumpel container-serve")
        .expect("container server not running");
    Command::new("docker")
        .args(["exec", container_id, "kill", &pid])
        .success()
        .expect("stopping container server failed");

    let deadline = Instant::now() + Duration::from_secs(10);
    while process_pid(container_id, "/opt/rumpelpod/bin/rumpel container-serve").as_deref()
        == Some(pid.as_str())
    {
        assert!(
            Instant::now() < deadline,
            "container server in '{container_id}' did not stop"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn connect_preserves_healthy_transport_and_repairs_a_failed_pod() {
    println!("xtest:timeout=300");
    if !matches!(executor::executor_mode(), executor::ExecutorMode::Docker) {
        executor::skip_test();
        return;
    }

    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "RUN apk add --no-cache procps", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    for name in ["connect-a", "connect-b"] {
        pod_command(&repo, &daemon)
            .args(["enter", "--create", name, "--", "true"])
            .success()
            .unwrap_or_else(|e| panic!("creating pod '{name}' failed: {e}"));
    }

    let container_a = container_id("connect-a");
    let container_b = container_id("connect-b");
    let tunnel_a = tunnel_server_pid(&container_a).expect("pod A tunnel server not running");
    let tunnel_b = tunnel_server_pid(&container_b).expect("pod B tunnel server not running");

    pod_command(&repo, &daemon)
        .args(["connect", "connect-a"])
        .success()
        .expect("probing healthy connections failed");
    assert_eq!(
        tunnel_server_pid(&container_a).as_deref(),
        Some(tunnel_a.as_str()),
        "connect replaced the target pod's healthy tunnel"
    );
    assert_eq!(
        tunnel_server_pid(&container_b).as_deref(),
        Some(tunnel_b.as_str()),
        "connect replaced a sibling pod's healthy tunnel"
    );

    stop_container_server(&container_a);
    pod_command(&repo, &daemon)
        .args(["connect", "connect-a"])
        .success()
        .expect("repairing a failed pod connection failed");
    wait_for_new_tunnel_server(&container_a, &tunnel_a);
    assert_eq!(
        tunnel_server_pid(&container_b).as_deref(),
        Some(tunnel_b.as_str()),
        "repairing one pod replaced a sibling pod's healthy tunnel"
    );
}

#[test]
fn connect_rejects_an_unknown_pod() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let daemon = TestDaemon::start(&home);

    let output = pod_command(&repo, &daemon)
        .args(["connect", "missing"])
        .output()
        .expect("running connect failed");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("pod 'missing' not found"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn connect_has_no_host_flag() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let daemon = TestDaemon::start(&home);

    let output = pod_command(&repo, &daemon)
        .args(["connect", "missing", "--host"])
        .output()
        .expect("running connect failed");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--host'"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
