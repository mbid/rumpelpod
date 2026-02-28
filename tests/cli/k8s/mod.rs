//! Integration tests for Kubernetes host support.
//!
//! These tests require `k3d` and `kubectl` to be installed and a Docker daemon
//! running. A dedicated k3d cluster is created per test run and cleaned up on
//! drop.  Each test creates an isolated namespace to avoid conflicts with
//! parallel test runs.

use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{
    build_docker_image, build_test_image, pod_command, DockerBuild, ImageId, TestDaemon, TestRepo,
    TEST_REPO_PATH, TEST_USER, TEST_USER_UID,
};

/// k3d cluster name used for all k8s tests.
const CLUSTER_NAME: &str = "rumpelpod-test";

/// Context name that k3d creates (always `k3d-` prefixed).
const K8S_CONTEXT: &str = "k3d-rumpelpod-test";

/// Node image to use -- must match the version preloaded in the devcontainer.
const K3S_IMAGE: &str = "rancher/k3s:v1.32.5-k3s1";

/// Per-test namespace that is automatically deleted on drop.
struct K8sNamespace {
    name: String,
}

impl K8sNamespace {
    fn new(test_name: &str) -> Self {
        let suffix = format!("{:06x}", rand::random::<u32>() & 0x00ff_ffff);

        let sanitized: String = test_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        // "rp-" (3) + "-" (1) + suffix (6) = 10 chars overhead
        let max_name_len = 63 - 10;
        let truncated = &sanitized[..sanitized.len().min(max_name_len)];
        let name = format!("rp-{}-{}", truncated, suffix);

        Command::new("kubectl")
            .args(["--context", K8S_CONTEXT, "create", "namespace", &name])
            .success()
            .expect("Failed to create k8s namespace");

        Self { name }
    }
}

impl Drop for K8sNamespace {
    fn drop(&mut self) {
        let status = Command::new("kubectl")
            .args([
                "--context",
                K8S_CONTEXT,
                "delete",
                "namespace",
                &self.name,
                "--grace-period=0",
                "--force",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Err(e) = status {
            eprintln!("Failed to delete namespace {}: {}", self.name, e);
        }
    }
}

/// Shared k3d cluster, created once per test run.
fn ensure_k3d_cluster() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Check if cluster already exists
        let output = Command::new("k3d")
            .args(["cluster", "list", "-o", "json"])
            .output()
            .expect("Failed to run k3d");
        let json = String::from_utf8_lossy(&output.stdout);
        if json.contains(&format!("\"name\":\"{}\"", CLUSTER_NAME)) {
            return;
        }

        // Create cluster with the preloaded node image
        Command::new("k3d")
            .args([
                "cluster",
                "create",
                CLUSTER_NAME,
                "--image",
                K3S_IMAGE,
                "--no-lb",
                "--timeout",
                "60s",
            ])
            .success()
            .expect("Failed to create k3d cluster");
    });
}

/// Load a Docker image into the k3d cluster by tag.
///
/// If the image ID already exists in the k3s node's containerd, we just add
/// the new tag locally (instant) instead of running `k3d image import` (~6s
/// each, serialized by a mutex).
fn load_image_into_cluster(image_id: &ImageId, image_tag: &str) {
    let node = format!("k3d-{}-server-0", CLUSTER_NAME);

    // Check if the image ID already exists in the node's containerd.
    let crictl_output = Command::new("docker")
        .args(["exec", &node, "crictl", "images", "-o", "json"])
        .output()
        .expect("Failed to query crictl images");

    if crictl_output.status.success() {
        let json: serde_json::Value =
            serde_json::from_slice(&crictl_output.stdout).expect("Failed to parse crictl JSON");

        if let Some(images) = json["images"].as_array() {
            let existing_ref = images.iter().find_map(|img| {
                if img["id"].as_str() == Some(&image_id.0) {
                    img["repoTags"]
                        .as_array()
                        .and_then(|tags| tags.first())
                        .and_then(|t| t.as_str())
                        .map(String::from)
                } else {
                    None
                }
            });

            if let Some(existing_ref) = existing_ref {
                let target = format!("docker.io/library/{}", image_tag);
                Command::new("docker")
                    .args([
                        "exec",
                        &node,
                        "ctr",
                        "-n",
                        "k8s.io",
                        "images",
                        "tag",
                        &existing_ref,
                        &target,
                    ])
                    .success()
                    .expect("Failed to tag image in containerd");
                return;
            }
        }
    }

    // Image not found in the node -- fall back to the full import.
    static IMPORT_LOCK: Mutex<()> = Mutex::new(());
    let _guard = IMPORT_LOCK.lock().unwrap();

    Command::new("k3d")
        .args(["image", "import", image_tag, "-c", CLUSTER_NAME])
        .success()
        .expect("Failed to load image into k3d cluster");
}

/// Tag an image with a stable name so k3d can find it.
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
fn write_k8s_pod_config_with_extras(
    repo: &TestRepo,
    image_tag: &str,
    namespace: &str,
    extra_json: &str,
) {
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
        [k8s]
        context = "{K8S_CONTEXT}"
        namespace = "{namespace}"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// Write devcontainer.json and .rumpelpod.toml for a k8s test.
fn write_k8s_pod_config(repo: &TestRepo, image_tag: &str, namespace: &str) {
    write_k8s_pod_config_with_extras(repo, image_tag, namespace, "");
}

#[test]
fn k8s_enter_smoke() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("enter-smoke");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Tag and load image into k3d
    let image_tag = "rumpelpod-test:k8s-enter";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config(&repo, image_tag, &ns.name);

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
}

#[test]
fn k8s_list_shows_pod() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("list-shows-pod");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-list";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config(&repo, image_tag, &ns.name);

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
}

#[test]
fn k8s_delete_removes_pod() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("delete-removes-pod");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-delete";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config(&repo, image_tag, &ns.name);

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
        .args(["--namespace", &ns.name])
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
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("image-build-rejected");

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

    let namespace = &ns.name;
    let config = formatdoc! {r#"
        [k8s]
        context = "{K8S_CONTEXT}"
        namespace = "{namespace}"
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
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("cp-to-and-from-pod");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-cp";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config(&repo, image_tag, &ns.name);

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
}

#[test]
fn k8s_mount_volume() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("mount-volume");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-vol";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        &ns.name,
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
}

#[test]
fn k8s_mount_tmpfs() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("mount-tmpfs");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-tmpfs";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        &ns.name,
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
}

#[test]
fn k8s_bind_mount_rejected() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("bind-mount-rejected");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-bind";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        &ns.name,
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
}

#[test]
fn k8s_privileged() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("privileged");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-priv";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, &ns.name, r#""privileged": true"#);

    let daemon = TestDaemon::start();

    // If the cluster allows privileged pods, this should succeed.
    // k3d allows privileged by default.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-priv-test", "--", "echo", "privileged-ok"])
        .success()
        .expect("rumpel enter with privileged failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "privileged-ok");
}

#[test]
fn k8s_cap_add() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("cap-add");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-cap";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, &ns.name, r#""capAdd": ["SYS_PTRACE"]"#);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-cap-test", "--", "echo", "caps-ok"])
        .success()
        .expect("rumpel enter with capAdd failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "caps-ok");
}

#[test]
fn k8s_override_command_false() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("override-command-false");

    let repo = TestRepo::new();
    // Build an image with explicit CMD that keeps the container running
    let image_id = build_test_image(repo.path(), r#"CMD ["tail", "-f", "/dev/null"]"#)
        .expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-nocmd";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, &ns.name, r#""overrideCommand": false"#);

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
}

#[test]
fn k8s_host_requirements() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("host-requirements");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-reqs";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(
        &repo,
        image_tag,
        &ns.name,
        r#""hostRequirements": {"cpus": 1, "memory": "256mb"}"#,
    );

    let daemon = TestDaemon::start();

    // Enter should succeed on k3d (resources are requests, not limits)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-reqs-test", "--", "true"])
        .success()
        .expect("rumpel enter with hostRequirements failed");

    // Verify resource requests are set via kubectl
    let kubectl_output = Command::new("kubectl")
        .args(["--context", K8S_CONTEXT])
        .args(["--namespace", &ns.name])
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
}

#[test]
fn k8s_init_succeeds_despite_unsupported() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("init-unsupported");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-init";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, &ns.name, r#""init": true"#);

    let daemon = TestDaemon::start();

    // init: true is unsupported on k8s but should not prevent pod creation
    // (the daemon logs a warning instead of failing)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-init-test", "--", "echo", "init-ok"])
        .success()
        .expect("init: true should not prevent pod creation on k8s");
}

#[test]
fn k8s_forward_port() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("forward-port");

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
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config_with_extras(&repo, image_tag, &ns.name, r#""forwardPorts": [9600]"#);

    let daemon = TestDaemon::start();

    // Create the pod (this should set up the port forward)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-fwd-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Start a socat listener on port 9600 inside the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "k8s-fwd-test",
            "--",
            "sh",
            "-c",
            "nohup socat TCP-LISTEN:9600,fork,reuseaddr EXEC:cat >/dev/null 2>&1 &",
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

    // Extract the local port from the ports output.
    // Format: "CONTAINER    LOCAL    LABEL"
    //         "9600         43567"
    let local_port: u16 = ports_output
        .lines()
        .find(|l| l.contains("9600") && !l.contains("CONTAINER"))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|s| s.parse().ok()))
        .expect("could not parse local port from ports output");

    // Verify TCP connection through the forwarded port succeeds
    let stream = TcpStream::connect(format!("127.0.0.1:{}", local_port))
        .expect("TCP connect to forwarded port failed");
    drop(stream);
}

#[test]
fn k8s_recreate() {
    ensure_k3d_cluster();
    let ns = K8sNamespace::new("recreate");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let image_tag = "rumpelpod-test:k8s-recreate";
    tag_image(&image_id.to_string(), image_tag);
    load_image_into_cluster(&image_id, image_tag);

    write_k8s_pod_config(&repo, image_tag, &ns.name);

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
}
