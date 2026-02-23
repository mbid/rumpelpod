//! Integration tests for Kubernetes host support.
//!
//! These tests require `kind` and `kubectl` to be installed and a Docker daemon
//! running. A dedicated kind cluster is created per test run and cleaned up on
//! drop.
//!
//! Gated behind `RUMPELPOD_TEST_K8S=1` to avoid running in environments without
//! kind support.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{
    build_docker_image, build_test_image, pod_command, DockerBuild, TestDaemon, TestRepo,
    TEST_REPO_PATH, TEST_USER, TEST_USER_UID,
};

/// Kind cluster name used for all k8s tests.
const CLUSTER_NAME: &str = "rumpelpod-test";

/// Context name that kind creates (always `kind-` prefixed).
const K8S_CONTEXT: &str = "kind-rumpelpod-test";

/// Returns true if k8s tests should run.
fn k8s_enabled() -> bool {
    std::env::var("RUMPELPOD_TEST_K8S").is_ok()
}

/// Shared kind cluster, created once per test run.
fn ensure_kind_cluster() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Check if cluster already exists
        let output = Command::new("kind")
            .args(["get", "clusters"])
            .output()
            .expect("Failed to run kind");
        let clusters = String::from_utf8_lossy(&output.stdout);
        if clusters.lines().any(|l| l.trim() == CLUSTER_NAME) {
            return;
        }

        // Create cluster
        Command::new("kind")
            .args(["create", "cluster", "--name", CLUSTER_NAME])
            .success()
            .expect("Failed to create kind cluster");
    });
}

/// Load a Docker image into the kind cluster by tag.
fn load_image_into_kind(image_tag: &str) {
    Command::new("kind")
        .args(["load", "docker-image", image_tag, "--name", CLUSTER_NAME])
        .success()
        .expect("Failed to load image into kind cluster");
}

/// Tag an image with a stable name so kind can find it.
fn tag_image(image_id: &str, tag: &str) {
    Command::new("docker")
        .args(["tag", image_id, tag])
        .success()
        .expect("Failed to tag docker image");
}

/// Write devcontainer.json with extra fields and .rumpelpod.toml for a k8s test.
///
/// `extra_json` is spliced into the devcontainer.json object, e.g.
/// `r#""mounts": [{"type":"volume","source":"tv","target":"/data"}]"#`.
fn write_k8s_pod_config_with_extras(repo: &TestRepo, image_tag: &str, extra_json: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let comma = if extra_json.is_empty() { "" } else { "," };
    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_tag}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}"{comma}
            {extra_json}
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    let config = formatdoc! {r#"
        host = "k8s://{K8S_CONTEXT}"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// Write devcontainer.json and .rumpelpod.toml for a k8s test.
fn write_k8s_pod_config(repo: &TestRepo, image_tag: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    // k8s hosts require an explicit containerUser since we cannot inspect
    // the image to determine the USER directive.
    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_tag}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}"
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    let config = formatdoc! {r#"
        host = "k8s://{K8S_CONTEXT}"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// Clean up any k8s pods created by rumpelpod in the default namespace.
fn cleanup_k8s_pods() {
    let _ = Command::new("kubectl")
        .args(["--context", K8S_CONTEXT])
        .args([
            "delete",
            "pods",
            "-l",
            "app.kubernetes.io/managed-by=rumpelpod",
            "--grace-period=0",
            "--force",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[test]
fn k8s_enter_smoke() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Tag and load image into kind
    let image_tag = "rumpelpod-test:k8s-enter";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config(&repo, image_tag);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "k8s-test", "--", "echo", "hello from k8s"])
        .output()
        .expect("rumpel enter failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rumpel enter failed: stdout={}, stderr={}",
        stdout,
        stderr,
    );
    assert_eq!(stdout.trim(), "hello from k8s");

    cleanup_k8s_pods();
}

#[test]
fn k8s_list_shows_pod() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-list";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config(&repo, image_tag);

    let daemon = TestDaemon::start();

    // Create a pod first
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-list-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Check it shows up in list
    let stdout = pod_command(&repo, &daemon)
        .args(["list"])
        .success()
        .expect("rumpel list failed");

    let output = String::from_utf8_lossy(&stdout);
    assert!(
        output.contains("k8s-list-test"),
        "list should show pod: {}",
        output,
    );

    cleanup_k8s_pods();
}

#[test]
fn k8s_delete_removes_pod() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-delete";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config(&repo, image_tag);

    let daemon = TestDaemon::start();

    // Create a pod
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-del-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Delete it
    pod_command(&repo, &daemon)
        .args(["delete", "--force", "k8s-del-test"])
        .success()
        .expect("rumpel delete failed");

    // Verify it's gone from list
    let stdout = pod_command(&repo, &daemon)
        .args(["list"])
        .success()
        .expect("rumpel list failed");

    let output = String::from_utf8_lossy(&stdout);
    assert!(
        !output.contains("k8s-del-test"),
        "deleted pod should not appear in list: {}",
        output,
    );

    // Verify k8s pod is also gone
    let kubectl_output = Command::new("kubectl")
        .args(["--context", K8S_CONTEXT])
        .args(["get", "pod", "-l", "rumpelpod/pod-name=k8s-del-test"])
        .args(["-o", "name"])
        .output()
        .expect("kubectl get failed");
    let pods = String::from_utf8_lossy(&kubectl_output.stdout);
    assert!(
        pods.trim().is_empty(),
        "k8s pod should be deleted: {}",
        pods,
    );
}

#[test]
fn k8s_image_build_rejected() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();

    // Write a devcontainer.json with build instead of image
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile"
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}"
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    // Write a minimal Dockerfile
    std::fs::write(devcontainer_dir.join("Dockerfile"), "FROM debian:13\n")
        .expect("Failed to write Dockerfile");

    let config = formatdoc! {r#"
        host = "k8s://{K8S_CONTEXT}"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "build-test", "--", "true"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        !output.status.success(),
        "should fail with build on k8s host",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not supported with Kubernetes"),
        "error should mention k8s: {}",
        stderr,
    );
}

#[test]
fn k8s_cp_to_and_from_pod() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-cp";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config(&repo, image_tag);

    let daemon = TestDaemon::start();

    // Create a pod
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-cp-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Write a local file
    let local_file = repo.path().join("test-upload.txt");
    std::fs::write(&local_file, "hello from host").expect("Failed to write local file");

    // Copy to pod
    pod_command(&repo, &daemon)
        .args([
            "cp",
            &local_file.to_string_lossy(),
            "k8s-cp-test:/tmp/test-upload.txt",
        ])
        .success()
        .expect("rumpel cp to pod failed");

    // Verify file exists in pod
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-cp-test", "--", "cat", "/tmp/test-upload.txt"])
        .success()
        .expect("reading file in pod failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello from host");

    // Copy back from pod
    let local_download = repo.path().join("test-download.txt");
    pod_command(&repo, &daemon)
        .args([
            "cp",
            "k8s-cp-test:/tmp/test-upload.txt",
            &local_download.to_string_lossy(),
        ])
        .success()
        .expect("rumpel cp from pod failed");

    let content = std::fs::read_to_string(&local_download).expect("Failed to read downloaded file");
    assert_eq!(content.trim(), "hello from host");

    cleanup_k8s_pods();
}

#[test]
fn k8s_mount_volume() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-vol";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        r#""mounts": [{"type":"volume","source":"tv","target":"/data"}]"#,
    );

    let daemon = TestDaemon::start();

    // Write a file to the volume mount
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "k8s-vol-test",
            "--",
            "sh",
            "-c",
            "echo hello > /data/test.txt",
        ])
        .success()
        .expect("writing to volume failed");

    // Read it back
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-vol-test", "--", "cat", "/data/test.txt"])
        .success()
        .expect("reading from volume failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello");

    cleanup_k8s_pods();
}

#[test]
fn k8s_mount_tmpfs() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-tmpfs";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        r#""mounts": [{"type":"tmpfs","target":"/tmp/mytmp"}]"#,
    );

    let daemon = TestDaemon::start();

    // Check that the tmpfs mount is present
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-tmpfs-test", "--", "mount"])
        .success()
        .expect("mount command failed");

    let output = String::from_utf8_lossy(&stdout);
    // emptyDir with Memory medium shows up as tmpfs
    assert!(
        output.contains("/tmp/mytmp") && output.contains("tmpfs"),
        "expected tmpfs at /tmp/mytmp in mount output: {}",
        output,
    );

    cleanup_k8s_pods();
}

#[test]
fn k8s_bind_mount_rejected() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-bind";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        r#""mounts": [{"type":"bind","source":"/tmp/x","target":"/mnt/x"}]"#,
    );

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "k8s-bind-test", "--", "true"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        !output.status.success(),
        "should fail with bind mount on k8s",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bind mounts are not supported"),
        "error should mention bind mount restriction: {}",
        stderr,
    );

    cleanup_k8s_pods();
}

#[test]
fn k8s_privileged() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-priv";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, r#""privileged": true"#);

    let daemon = TestDaemon::start();

    // If the cluster allows privileged pods, this should succeed.
    // kind allows privileged by default.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-priv-test", "--", "echo", "privileged-ok"])
        .success()
        .expect("rumpel enter with privileged failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "privileged-ok");

    cleanup_k8s_pods();
}

#[test]
fn k8s_cap_add() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-cap";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, r#""capAdd": ["SYS_PTRACE"]"#);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-cap-test", "--", "echo", "caps-ok"])
        .success()
        .expect("rumpel enter with capAdd failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "caps-ok");

    cleanup_k8s_pods();
}

#[test]
fn k8s_override_command_false() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    // Build an image with explicit CMD that keeps the container running
    let image_id = build_test_image(repo.path(), r#"CMD ["tail", "-f", "/dev/null"]"#)
        .expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-nocmd";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, r#""overrideCommand": false"#);

    let daemon = TestDaemon::start();

    // Check PID 1 is tail, not sleep
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-nocmd-test", "--", "cat", "/proc/1/cmdline"])
        .success()
        .expect("checking PID 1 failed");

    let cmdline = String::from_utf8_lossy(&stdout);
    assert!(
        cmdline.contains("tail"),
        "PID 1 should be tail, got: {:?}",
        cmdline,
    );

    cleanup_k8s_pods();
}

#[test]
fn k8s_host_requirements() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-reqs";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        r#""hostRequirements": {"cpus": 1, "memory": "256mb"}"#,
    );

    let daemon = TestDaemon::start();

    // Enter should succeed on kind (resources are requests, not limits)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-reqs-test", "--", "true"])
        .success()
        .expect("rumpel enter with hostRequirements failed");

    // Verify resource requests are set via kubectl
    let kubectl_output = Command::new("kubectl")
        .args(["--context", K8S_CONTEXT])
        .args([
            "get",
            "pod",
            "-l",
            "rumpelpod/pod-name=k8s-reqs-test",
            "-o",
            "jsonpath={.items[0].spec.containers[0].resources.requests}",
        ])
        .output()
        .expect("kubectl get failed");

    let requests = String::from_utf8_lossy(&kubectl_output.stdout);
    assert!(
        requests.contains("256Mi"),
        "resource requests should include memory: {}",
        requests,
    );
    assert!(
        requests.contains("1"),
        "resource requests should include cpu: {}",
        requests,
    );

    cleanup_k8s_pods();
}

#[test]
fn k8s_init_succeeds_despite_unsupported() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-init";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, r#""init": true"#);

    let daemon = TestDaemon::start();

    // init: true is unsupported on k8s but should not prevent pod creation
    // (the daemon logs a warning instead of failing)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-init-test", "--", "echo", "init-ok"])
        .success()
        .expect("init: true should not prevent pod creation on k8s");

    cleanup_k8s_pods();
}

#[test]
fn k8s_forward_port() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();

    // Build image with socat for echo server
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
    .expect("Failed to build test image with socat");

    let image_tag = "rumpelpod-test:k8s-fwd";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, r#""forwardPorts": [9600]"#);

    let daemon = TestDaemon::start();

    // Create the pod (this should set up the port forward)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-fwd-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Start a socat echo server on port 9600 inside the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "k8s-fwd-test",
            "--",
            "sh",
            "-c",
            "nohup socat TCP-LISTEN:9600,fork,reuseaddr EXEC:'cat' >/dev/null 2>&1 &",
        ])
        .success()
        .expect("Failed to start echo server");

    std::thread::sleep(Duration::from_millis(500));

    // Check rumpel ports shows the forwarded port
    let stdout = pod_command(&repo, &daemon)
        .args(["ports", "k8s-fwd-test"])
        .success()
        .expect("rumpel ports failed");

    let ports_output = String::from_utf8_lossy(&stdout);
    assert!(
        ports_output.contains("9600"),
        "ports output should mention port 9600: {}",
        ports_output,
    );

    // Extract the local port from the ports output to connect to it
    // Format is typically: "  9600 -> 127.0.0.1:XXXXX"
    let local_port: u16 = ports_output
        .lines()
        .find(|l| l.contains("9600"))
        .and_then(|l| {
            // Find the local port number after the last ':'
            l.rsplit(':').next().and_then(|s| s.trim().parse().ok())
        })
        .expect("could not parse local port from ports output");

    // Connect and verify echo
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", local_port)).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"k8s-echo-test").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "k8s-echo-test");

    cleanup_k8s_pods();
}

#[test]
fn k8s_recreate() {
    if !k8s_enabled() {
        return;
    }
    ensure_kind_cluster();

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-recreate";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_kind(image_tag);

    write_k8s_pod_config(&repo, image_tag);

    let daemon = TestDaemon::start();

    // Create a pod and write a dirty (uncommitted) file
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "k8s-recreate-test",
            "--",
            "sh",
            "-c",
            "echo dirty-content > /home/testuser/workspace/dirty.txt",
        ])
        .success()
        .expect("writing dirty file failed");

    // Recreate the pod
    pod_command(&repo, &daemon)
        .args(["recreate", "k8s-recreate-test"])
        .success()
        .expect("rumpel recreate failed");

    // Verify the dirty file survived the recreate
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "k8s-recreate-test",
            "--",
            "cat",
            "/home/testuser/workspace/dirty.txt",
        ])
        .success()
        .expect("reading dirty file after recreate failed");

    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "dirty-content",
        "dirty file should survive recreate",
    );

    cleanup_k8s_pods();
}
