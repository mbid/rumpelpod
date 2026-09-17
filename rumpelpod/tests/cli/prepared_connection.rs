// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rumpelpod::config::{ContainerEngine, Host};
use rumpelpod::daemon::protocol::{
    ClientContext, ConnectPodRequest, ContainerId, Daemon, DaemonClient, PreparedPodConnection,
};
use rumpelpod::CommandExt;

use crate::common::{
    pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER,
};
use crate::executor::{executor_supports_stop, ExecutorResources};

fn wait_for_prepared_connection(repo: &TestRepo, daemon: &TestDaemon) -> PreparedPodConnection {
    let client = DaemonClient::new_unix(&daemon.socket_path);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(connection) = client
            .prepared_pod_connection(ConnectPodRequest {
                pod_name: "test".into(),
                repo_path: repo.path().to_path_buf(),
                client_context: ClientContext::default(),
            })
            .expect("query prepared connection")
        {
            return connection;
        }
        assert!(Instant::now() < deadline, "pod readiness was not observed");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn enter_warm_connection_skips_preparation() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--", "mkdir", "new-subdir"])
        .success()
        .expect("create pod without Claude configuration");
    wait_for_prepared_connection(&repo, &daemon);

    // Configuration changes on the host must not prevent using a ready pod.
    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        "invalid json",
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), "invalid json").unwrap();
    let subdir = repo.path().join("new-subdir");
    fs::create_dir(&subdir).unwrap();
    let workdir = pod_command(&repo, &daemon)
        .current_dir(subdir)
        .args(["enter", "test", "--", "pwd"])
        .success()
        .expect("enter subdirectory in prepared pod");
    assert_eq!(
        String::from_utf8_lossy(&workdir).trim(),
        format!("{TEST_REPO_PATH}/new-subdir")
    );
    let mut child = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "sh", "-c", "whoami; pwd; cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("enter prepared pod");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped input\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{TEST_USER}\n{TEST_REPO_PATH}\npiped input\n")
    );

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "test",
            "--",
            "sh",
            "-c",
            "echo once >> attempts; exit 7",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exec exited with status"));
    let attempts = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "cat", "attempts"])
        .success()
        .unwrap();
    assert_eq!(attempts, b"once\n", "failed commands must not be replayed");
}

#[test]
fn cp_warm_connection_skips_preparation_in_both_directions() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--", "true"])
        .success()
        .expect("create pod");
    wait_for_prepared_connection(&repo, &daemon);

    fs::write(
        repo.path().join(".devcontainer/devcontainer.json"),
        "invalid json",
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), "invalid json").unwrap();
    let source = home.path().join("source");
    let destination = home.path().join("destination");
    fs::write(&source, "copy through the prepared connection\n").unwrap();
    pod_command(&repo, &daemon)
        .args(["cp", source.to_str().unwrap(), "test:relative-file"])
        .success()
        .expect("upload using stored workspace");
    let container_path = format!("test:{TEST_REPO_PATH}/relative-file");
    pod_command(&repo, &daemon)
        .args(["cp", &container_path, destination.to_str().unwrap()])
        .success()
        .expect("download from original workspace");
    assert_eq!(fs::read(&source).unwrap(), fs::read(&destination).unwrap());

    let output = pod_command(&repo, &daemon)
        .args(["cp", "test:missing-file", destination.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("GET /cp:"));
    assert_eq!(fs::read(&source).unwrap(), fs::read(&destination).unwrap());
}

#[test]
fn enter_prepared_connection_recovers_after_stop_and_recreate() {
    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--", "touch", "/tmp/old-pod"])
        .success()
        .unwrap();
    let original = wait_for_prepared_connection(&repo, &daemon);
    pod_command(&repo, &daemon)
        .args(["stop", "--wait", "test"])
        .success()
        .unwrap();
    let client = DaemonClient::new_unix(&daemon.socket_path);
    assert!(client
        .prepared_pod_connection(ConnectPodRequest {
            pod_name: "test".into(),
            repo_path: repo.path().to_path_buf(),
            client_context: ClientContext::default(),
        })
        .unwrap()
        .is_none());
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "test", "-f", "/tmp/old-pod"])
        .success()
        .expect("restart stopped pod");
    pod_command(&repo, &daemon)
        .args(["delete", "--wait", "--force", "test"])
        .success()
        .unwrap();
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "test",
            "--",
            "test",
            "!",
            "-e",
            "/tmp/old-pod",
        ])
        .success()
        .expect("create replacement pod");
    let replacement = wait_for_prepared_connection(&repo, &daemon);
    assert_ne!(original.container_token, replacement.container_token);
}

#[test]
fn cp_prepared_connection_restarts_stopped_pod() {
    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "test", "--", "true"])
        .success()
        .unwrap();
    wait_for_prepared_connection(&repo, &daemon);
    let source = home.path().join("source");
    let destination = home.path().join("destination");
    fs::write(&source, "survives pod restart\n").unwrap();
    pod_command(&repo, &daemon)
        .args(["stop", "--wait", "test"])
        .success()
        .unwrap();
    pod_command(&repo, &daemon)
        .args(["cp", source.to_str().unwrap(), "test:restarted-file"])
        .success()
        .expect("restart pod before upload");
    pod_command(&repo, &daemon)
        .args(["stop", "--wait", "test"])
        .success()
        .unwrap();
    pod_command(&repo, &daemon)
        .args(["cp", "test:restarted-file", destination.to_str().unwrap()])
        .success()
        .expect("restart pod before download");
    assert_eq!(fs::read(source).unwrap(), fs::read(destination).unwrap());
}

#[derive(Clone, Copy)]
enum BrokenConnection {
    Closed,
    StalledHeaders,
    StalledGreeting,
    LifecycleError,
}

#[test]
fn enter_stale_prepared_connection_falls_back() {
    check_broken_connection(false, BrokenConnection::Closed);
}

#[test]
fn cp_stale_prepared_connection_falls_back() {
    check_broken_connection(true, BrokenConnection::Closed);
}

#[test]
fn enter_prepared_connection_bounds_stalled_headers() {
    check_broken_connection(false, BrokenConnection::StalledHeaders);
}

#[test]
fn cp_prepared_connection_bounds_stalled_headers() {
    check_broken_connection(true, BrokenConnection::StalledHeaders);
}

#[test]
fn enter_prepared_connection_bounds_stalled_greeting() {
    check_broken_connection(false, BrokenConnection::StalledGreeting);
}

#[test]
fn cp_prepared_connection_bounds_stalled_greeting() {
    check_broken_connection(true, BrokenConnection::StalledGreeting);
}

#[test]
fn enter_prepared_connection_rejects_lifecycle_error() {
    check_broken_connection(false, BrokenConnection::LifecycleError);
}

#[test]
fn cp_prepared_connection_rejects_lifecycle_error() {
    check_broken_connection(true, BrokenConnection::LifecycleError);
}

// A fake daemon keeps the stale route deterministic even when real event
// supervision would invalidate it before the next command reaches the CLI.
fn check_broken_connection(copy: bool, failure: BrokenConnection) {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let socket_dir = tempfile::tempdir_in("/tmp").unwrap();
    let socket = socket_dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let pod_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pod_addr = pod_listener.local_addr().unwrap();
    let connection = PreparedPodConnection {
        container_id: ContainerId("unused".into()),
        docker_socket: None,
        host: Host::Localhost {
            engine: ContainerEngine::Docker,
        },
        container_url: format!("http://{pod_addr}"),
        container_token: "test-token".into(),
        container_repo_path: "/workspace".into(),
    };
    let pod = thread::spawn(move || {
        let (mut stream, _) = pod_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        if !matches!(failure, BrokenConnection::Closed) {
            let mut reader = BufReader::new(&mut stream);
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            assert!(request.starts_with("GET /events "));
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                assert!(!header.is_empty());
                if header == "\r\n" {
                    break;
                }
            }
        }
        match failure {
            BrokenConnection::Closed => {}
            BrokenConnection::StalledHeaders | BrokenConnection::StalledGreeting => {
                if matches!(failure, BrokenConnection::StalledGreeting) {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n").unwrap();
                }
                let mut extra = Vec::new();
                stream
                    .read_to_end(&mut extra)
                    .expect("client closes stalled connection");
                assert!(
                    extra.is_empty(),
                    "no transfer should start before readiness"
                );
            }
            BrokenConnection::LifecycleError => {
                let body = "event: state\ndata: {\"lifecycle_error\":\"setup failed\"}\n\n";
                let length = body.len();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}").unwrap();
            }
        }
    });
    let daemon = thread::spawn(move || {
        let responses = [
            (
                "POST /pod/prepared-connection ",
                serde_json::to_string(&connection).unwrap(),
            ),
            (
                "GET /pod ",
                "event: error\ndata: {\"error\":\"fallback-preparation-reached\"}\n\n".to_string(),
            ),
        ];
        for (expected, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert!(request_line.starts_with(expected), "{request_line}");
            let mut content_length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" {
                    break;
                }
                assert!(!header.is_empty());
                let (name, value) = header.split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
            reader.read_exact(&mut vec![0; content_length]).unwrap();
            let length = body.len();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}"
            )
            .unwrap();
        }
    });
    let mut command = Command::new("rumpel");
    command
        .current_dir(repo.path())
        .env("HOME", home.path())
        .env("PATH", home.bin_dir())
        .env("RUMPELPOD_DAEMON_SOCKET", &socket);
    if copy {
        let source = home.path().join("source");
        fs::write(&source, "must not be sent to stale connection").unwrap();
        command.args(["cp", source.to_str().unwrap(), "test:file"]);
    } else {
        command.args(["enter", "test", "--", "true"]);
    }
    let started = Instant::now();
    let output = command.output().unwrap();
    let elapsed = started.elapsed();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("fallback-preparation-reached"), "{stderr}");
    match failure {
        BrokenConnection::StalledHeaders | BrokenConnection::StalledGreeting => {
            assert!(elapsed >= Duration::from_secs(9), "{elapsed:?}");
            assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
        }
        BrokenConnection::Closed | BrokenConnection::LifecycleError => {}
    }
    pod.join().unwrap();
    daemon.join().unwrap();
}
