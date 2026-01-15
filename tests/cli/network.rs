use crate::common::{
    build_test_image, create_commit, sandbox_command, write_test_sandbox_config_with_network,
    TestDaemon, TestRepo,
};
use sandbox::CommandExt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[test]
fn network_host_connectivity() {
    let daemon = TestDaemon::start();
    let repo = TestRepo::new();

    // Install netcat-openbsd for testing connectivity
    // Switch to root to install packages
    let image_id = build_test_image(
        repo.path(),
        "USER root\nRUN apt-get install -y netcat-openbsd\nUSER testuser",
    )
    .expect("Failed to build test image");

    write_test_sandbox_config_with_network(&repo, &image_id, "unsafe-host");

    // Bind a listener on localhost on the host
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
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
    });

    // Run nc inside sandbox to connect to host's localhost
    // We expect 127.0.0.1 to be reachable and map to the host.
    // We don't use -N because we want to read the response.
    let output = sandbox_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg(format!("echo HELLO | nc 127.0.0.1 {}", port))
        .success()
        .expect("Failed to run sandbox command");

    let stdout = String::from_utf8_lossy(&output);
    assert_eq!(stdout.trim(), "WORLD");

    server_handle.join().expect("Server thread panicked");
}

#[test]
#[should_panic(expected = "Sandbox remote on host should be localhost")]
fn network_host_remotes_use_localhost() {
    let daemon = TestDaemon::start();
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    write_test_sandbox_config_with_network(&repo, &image_id, "unsafe-host");

    // Check host remote inside sandbox
    let output = sandbox_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("git")
        .arg("remote")
        .arg("get-url")
        .arg("host")
        .success()
        .expect("Failed to check remote inside sandbox");

    let remote_url = String::from_utf8_lossy(&output).trim().to_string();
    println!("Remote 'host' URL inside sandbox: {}", remote_url);
    assert!(
        remote_url.contains("127.0.0.1") || remote_url.contains("localhost"),
        "Remote 'host' inside sandbox should use localhost"
    );

    // Keep sandbox running to check the remote on the host
    let mut cmd = sandbox_command(&repo, &daemon);
    cmd.arg("enter").arg("test").arg("--").arg("sleep").arg("3");

    let sandbox_handle = thread::spawn(move || {
        cmd.success().expect("Failed to run sandbox sleep");
    });

    thread::sleep(Duration::from_secs(1));

    let output = Command::new("git")
        .args(["remote", "get-url", "sandbox"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to get sandbox remote");

    // Cleanup
    sandbox_handle.join().unwrap();

    let url = String::from_utf8_lossy(&output);
    println!("Remote 'sandbox' URL on host: {}", url);
    assert!(
        url.contains("127.0.0.1") || url.contains("localhost"),
        "Sandbox remote on host should be localhost"
    );
}

#[test]
fn network_host_git_operations() {
    let daemon = TestDaemon::start();
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    write_test_sandbox_config_with_network(&repo, &image_id, "unsafe-host");

    // 1. git fetch host (from inside sandbox)
    create_commit(repo.path(), "Host commit");

    sandbox_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("git")
        .arg("fetch")
        .arg("host")
        .success()
        .expect("Failed to fetch host");

    // 2. git push sandbox (from host)
    // Keep sandbox running
    let mut cmd = sandbox_command(&repo, &daemon);
    cmd.arg("enter").arg("test").arg("--").arg("sleep").arg("5");

    let sandbox_handle = thread::spawn(move || {
        cmd.success().expect("Failed to run sandbox sleep");
    });

    thread::sleep(Duration::from_secs(2));

    Command::new("git")
        .args(["push", "sandbox", "HEAD:host/sandbox-branch"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to push to sandbox");

    sandbox_handle.join().unwrap();
}
