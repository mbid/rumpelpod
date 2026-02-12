//! Integration tests for devcontainer.json port forwarding.
//!
//! Tests verify:
//! - Basic port forwarding from container to host
//! - Multiple ports forwarded simultaneously
//! - Port label display from portsAttributes
//! - Multi-pod port conflict resolution (remapping)
//! - `rumpel ports` CLI command output

use indoc::formatdoc;
use rumpelpod::CommandExt;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[cfg(not(target_os = "macos"))]
use crate::common::{build_docker_image, DockerBuild, TEST_USER_UID};
use crate::common::{pod_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};
#[cfg(not(target_os = "macos"))]
use crate::ssh::{create_ssh_config, SshRemoteHost};

/// Write a devcontainer.json with port forwarding configuration.
fn write_devcontainer_with_ports(repo: &TestRepo, ports_config: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    // Use socat in the image so we can create simple TCP listeners for testing
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git socat
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
            {ports_config}
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]
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

/// Start a TCP echo server inside the container on the given port.
/// Uses socat to listen and echo back whatever is sent.
fn start_echo_server_in_container(repo: &TestRepo, daemon: &TestDaemon, pod_name: &str, port: u16) {
    pod_command(repo, daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "sh",
            "-c",
            &format!("nohup socat TCP-LISTEN:{port},fork,reuseaddr EXEC:'cat' >/dev/null 2>&1 &"),
        ])
        .success()
        .expect("Failed to start echo server");

    // Give socat a moment to start listening
    std::thread::sleep(Duration::from_millis(500));
}

/// Try to connect to a local port and send/receive data.
fn try_echo(port: u16, message: &str) -> Option<String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.write_all(message.as_bytes()).ok()?;
    stream.shutdown(std::net::Shutdown::Write).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    Some(buf)
}

#[test]
fn forward_single_port() {
    let repo = TestRepo::new();

    write_devcontainer_with_ports(&repo, r#""forwardPorts": [9100],"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Create pod (this should set up port forwarding)
    pod_command(&repo, &daemon)
        .args(["enter", "fwd-single", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Start an echo server on port 9100 inside the container
    start_echo_server_in_container(&repo, &daemon, "fwd-single", 9100);

    // Verify we can reach it through the forwarded port
    let response = try_echo(9100, "hello port forwarding");
    assert_eq!(
        response.as_deref(),
        Some("hello port forwarding"),
        "Expected echo response through forwarded port 9100"
    );
}

#[test]
fn forward_multiple_ports() {
    let repo = TestRepo::new();

    write_devcontainer_with_ports(&repo, r#""forwardPorts": [9200, 9201],"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "fwd-multi", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    start_echo_server_in_container(&repo, &daemon, "fwd-multi", 9200);
    start_echo_server_in_container(&repo, &daemon, "fwd-multi", 9201);

    let r1 = try_echo(9200, "port-9200");
    let r2 = try_echo(9201, "port-9201");

    assert_eq!(r1.as_deref(), Some("port-9200"));
    assert_eq!(r2.as_deref(), Some("port-9201"));
}

#[test]
fn ports_command_shows_forwarded_ports() {
    let repo = TestRepo::new();

    write_devcontainer_with_ports(
        &repo,
        r#"
        "forwardPorts": [9300],
        "portsAttributes": {
            "9300": { "label": "My App" }
        },
        "#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "fwd-show", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    let stdout = pod_command(&repo, &daemon)
        .args(["ports", "fwd-show"])
        .success()
        .expect("rumpel ports failed");

    let output = String::from_utf8_lossy(&stdout);
    assert!(output.contains("9300"), "Should show container port 9300");
    assert!(output.contains("My App"), "Should show label 'My App'");
}

#[test]
fn ports_command_empty_when_no_forwards() {
    let repo = TestRepo::new();

    // No forwardPorts at all
    write_devcontainer_with_ports(&repo, "");
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "fwd-empty", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    let stdout = pod_command(&repo, &daemon)
        .args(["ports", "fwd-empty"])
        .success()
        .expect("rumpel ports failed");

    let output = String::from_utf8_lossy(&stdout);
    // Should show the header but no port rows
    assert!(
        !output.contains("9"),
        "Should not show any ports when none are forwarded"
    );
}

#[test]
fn other_ports_attributes_label() {
    let repo = TestRepo::new();

    // Port 9350 is in forwardPorts but NOT in portsAttributes,
    // so it should pick up the label from otherPortsAttributes.
    write_devcontainer_with_ports(
        &repo,
        r#"
        "forwardPorts": [9350],
        "portsAttributes": {
            "9999": { "label": "Explicit" }
        },
        "otherPortsAttributes": { "label": "Fallback" },
        "#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "fwd-other", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    let stdout = pod_command(&repo, &daemon)
        .args(["ports", "fwd-other"])
        .success()
        .expect("rumpel ports failed");

    let output = String::from_utf8_lossy(&stdout);
    assert!(
        output.contains("9350"),
        "Should show container port 9350, got: {}",
        output
    );
    assert!(
        output.contains("Fallback"),
        "Port not in portsAttributes should get otherPortsAttributes label, got: {}",
        output
    );
}

#[test]
fn multi_pod_port_remapping() {
    let repo = TestRepo::new();

    write_devcontainer_with_ports(&repo, r#""forwardPorts": [9400],"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // First pod gets port 9400
    pod_command(&repo, &daemon)
        .args(["enter", "fwd-first", "--", "true"])
        .success()
        .expect("rumpel enter failed for first pod");

    // Second pod also wants port 9400 but should get remapped
    pod_command(&repo, &daemon)
        .args(["enter", "fwd-second", "--", "true"])
        .success()
        .expect("rumpel enter failed for second pod");

    // Check the ports for both pods
    let stdout1 = pod_command(&repo, &daemon)
        .args(["ports", "fwd-first"])
        .success()
        .expect("rumpel ports failed for first");
    let output1 = String::from_utf8_lossy(&stdout1);

    let stdout2 = pod_command(&repo, &daemon)
        .args(["ports", "fwd-second"])
        .success()
        .expect("rumpel ports failed for second");
    let output2 = String::from_utf8_lossy(&stdout2);

    // Both should show container port 9400
    assert!(output1.contains("9400"), "First pod should show port 9400");
    assert!(
        output2.contains("9400"),
        "Second pod should show container port 9400"
    );

    // Extract local ports from each - they must differ
    let local_port_1 = extract_local_port(&output1, 9400);
    let local_port_2 = extract_local_port(&output2, 9400);

    assert_ne!(
        local_port_1, local_port_2,
        "Two pods should not share the same local port for 9400"
    );
}

/// Extract the local port for a given container port from `rumpel ports` output.
/// The output format is: CONTAINER  LOCAL  LABEL
fn extract_local_port(output: &str, container_port: u16) -> u16 {
    let port_str = container_port.to_string();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[0] == port_str {
            return fields[1].parse().expect("local port should be a number");
        }
    }
    panic!(
        "Could not find container port {} in output:\n{}",
        container_port, output
    );
}

#[cfg(not(target_os = "macos"))]
/// Write a devcontainer.json with forwardPorts and a .rumpelpod.toml pointing
/// to a remote Docker host with a pre-built image.
fn write_remote_config_with_ports(
    repo: &TestRepo,
    image_id: &crate::common::ImageId,
    remote_spec: &str,
    ports_config: &str,
) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    // Use a pre-built image rather than building via docker -H ssh://
    // because docker's own SSH client doesn't share our test SSH config.
    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_id}",
            {ports_config}
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    let config = formatdoc! {r#"
        host = "{remote_spec}"

        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn forward_port_remote_ssh() {
    let repo = TestRepo::new();

    // Build a test image locally that includes socat for echo testing.
    // socat must be installed before USER so it's available as root.
    let image_id = build_docker_image(DockerBuild {
        dockerfile: formatdoc! {r#"
            FROM debian:13
            RUN apt-get update && apt-get install -y git socat
            RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
            COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
            USER {TEST_USER}
        "#},
        build_context: Some(repo.path().to_path_buf()),
    })
    .expect("Failed to build test image");

    // Start a remote Docker host (Docker-in-Docker via SSH)
    let remote = SshRemoteHost::start();
    remote
        .load_image(&image_id)
        .expect("Failed to load image into remote Docker");

    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    write_remote_config_with_ports(
        &repo,
        &image_id,
        &remote.ssh_spec(),
        r#""forwardPorts": [9500],"#,
    );

    pod_command(&repo, &daemon)
        .args(["enter", "fwd-remote", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Start an echo server on port 9500 inside the remote container
    start_echo_server_in_container(&repo, &daemon, "fwd-remote", 9500);

    // The port should be forwarded via SSH tunnel from localhost to the
    // container's port 9500 on the remote host's Docker network.
    let stdout = pod_command(&repo, &daemon)
        .args(["ports", "fwd-remote"])
        .success()
        .expect("rumpel ports failed");
    let output = String::from_utf8_lossy(&stdout);
    assert!(
        output.contains("9500"),
        "Should show forwarded port 9500, got: {}",
        output
    );

    // Verify data flows through the SSH-tunnelled forward
    let response = try_echo(9500, "hello remote");
    assert_eq!(
        response.as_deref(),
        Some("hello remote"),
        "Expected echo response through SSH-forwarded port 9500"
    );
}
