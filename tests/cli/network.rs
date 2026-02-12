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
        .arg("enter")
        .arg("test")
        .arg("--")
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
