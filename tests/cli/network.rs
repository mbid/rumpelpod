use crate::common::{
    build_test_image, create_commit, pod_command, write_test_pod_config_with_network, TestDaemon,
    TestRepo,
};
use rumpelpod::CommandExt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

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

    write_test_pod_config_with_network(&repo, &image_id, "unsafe-host");

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
        // Give the client a moment to receive the data before closing the connection
        thread::sleep(std::time::Duration::from_millis(100));
    });

    // Run nc inside pod to connect to host's localhost
    // We expect 127.0.0.1 to be reachable and map to the host.
    // We don't use -N because we want to read the response.
    let output = pod_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("bash")
        .arg("-c")
        .arg(format!("echo HELLO | nc 127.0.0.1 {}", port))
        .success()
        .expect("Failed to run pod command");

    let stdout = String::from_utf8_lossy(&output);
    assert_eq!(stdout.trim(), "WORLD");

    server_handle.join().expect("Server thread panicked");
}

/// With --network=host, both 'host' and 'rumpelpod' remotes inside the pod
/// should use localhost since the pod shares the host's network namespace.
#[test]
fn network_host_remotes_use_localhost() {
    let daemon = TestDaemon::start();
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    write_test_pod_config_with_network(&repo, &image_id, "unsafe-host");

    // Check 'host' remote inside pod
    let output = pod_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
        .arg("git")
        .arg("remote")
        .arg("get-url")
        .arg("host")
        .success()
        .expect("Failed to get 'host' remote URL inside pod");

    let host_remote_url = String::from_utf8_lossy(&output).trim().to_string();
    println!("Remote 'host' URL inside pod: {}", host_remote_url);
    assert!(
        host_remote_url.contains("127.0.0.1") || host_remote_url.contains("localhost"),
        "Remote 'host' inside pod should use localhost, got: {}",
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
        pod_remote_url.contains("127.0.0.1") || pod_remote_url.contains("localhost"),
        "Remote 'rumpelpod' inside pod should use localhost, got: {}",
        pod_remote_url
    );
}

/// Test that commits made on the host are available via the 'host' remote inside
/// the pod when using --network=host.
#[test]
fn network_host_fetch_from_pod() {
    let daemon = TestDaemon::start();
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    write_test_pod_config_with_network(&repo, &image_id, "unsafe-host");

    // Launch pod first
    pod_command(&repo, &daemon)
        .arg("enter")
        .arg("test")
        .arg("--")
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
    let daemon = TestDaemon::start();
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    write_test_pod_config_with_network(&repo, &image_id, "unsafe-host");

    let pod_name = "push-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .arg("enter")
        .arg(pod_name)
        .arg("--")
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

    // The pod's commit should be visible in the host repo as a remote-tracking ref.
    // The gateway post-receive hook syncs rumpelpod/<branch>@<name> to the host repo
    // as refs/remotes/rumpelpod/<branch>@<name>.
    // For the primary branch (where branch == pod name), there's also an alias.
    let host_ref_commit = Command::new("git")
        .args(["rev-parse", &format!("rumpelpod/{}", pod_name)])
        .current_dir(repo.path())
        .success()
        .expect("Failed to get pod ref from host repo");
    let host_ref_commit = String::from_utf8_lossy(&host_ref_commit).trim().to_string();

    assert_eq!(
        host_ref_commit, pod_commit,
        "Host repo should have pod's commit at rumpelpod/{} ref",
        pod_name
    );
}
