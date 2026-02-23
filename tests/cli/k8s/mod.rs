//! Integration tests for Kubernetes host support.
//!
//! These tests require `kind` and `kubectl` to be installed and a Docker daemon
//! running. A dedicated kind cluster is created per test run and cleaned up on
//! drop.
//!
//! Gated behind `RUMPELPOD_TEST_K8S=1` to avoid running in environments without
//! kind support.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{
    build_test_image, pod_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER,
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
