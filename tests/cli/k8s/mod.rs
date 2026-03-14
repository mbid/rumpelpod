//! Integration tests for Kubernetes host support.
//!
//! These tests require an external Kubernetes cluster configured via
//! environment variables.  Each test creates an isolated namespace to
//! avoid conflicts with parallel test runs.
//!
//! Required env vars (tests are `#[ignore]`d, so only checked when
//! explicitly run):
//!   RUMPELPOD_TEST_K8S_CONTEXT   -- kubectl context
//!   RUMPELPOD_TEST_PUSH_REGISTRY -- where `docker push` sends images (e.g. localhost:5000/rumpelpod)
//!   RUMPELPOD_TEST_PULL_REGISTRY -- what pods use to pull (e.g. registry.registry.svc.cluster.local:5000/rumpelpod)

use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{
    build_docker_image, build_test_image, pod_command, DockerBuild, ImageId, TestDaemon, TestRepo,
    TEST_REPO_PATH, TEST_USER, TEST_USER_UID,
};

/// Cluster configuration read from environment variables.
struct K8sClusterConfig {
    context: String,
    push_registry: String,
    pull_registry: String,
}

fn k8s_cluster_config() -> K8sClusterConfig {
    let context = std::env::var("RUMPELPOD_TEST_K8S_CONTEXT")
        .expect("RUMPELPOD_TEST_K8S_CONTEXT must be set to run k8s tests");
    let push_registry = std::env::var("RUMPELPOD_TEST_PUSH_REGISTRY")
        .expect("RUMPELPOD_TEST_PUSH_REGISTRY must be set to run k8s tests");
    let pull_registry = std::env::var("RUMPELPOD_TEST_PULL_REGISTRY")
        .expect("RUMPELPOD_TEST_PULL_REGISTRY must be set to run k8s tests");
    K8sClusterConfig {
        context,
        push_registry,
        pull_registry,
    }
}

/// Push a locally-built image to the test registry and return the
/// pull reference (pull_registry/tag) for use in pod specs.
fn push_image(cluster: &K8sClusterConfig, image_id: &ImageId, tag: &str) -> String {
    let push_ref = format!("{}/{}", cluster.push_registry, tag);
    Command::new("docker")
        .args(["tag", &image_id.to_string(), &push_ref])
        .success()
        .expect("Failed to tag docker image for push");
    Command::new("docker")
        .args(["push", &push_ref])
        .success()
        .expect("Failed to push image to registry");
    format!("{}/{}", cluster.pull_registry, tag)
}

/// Per-test namespace that is automatically deleted on drop.
struct K8sNamespace {
    name: String,
    context: String,
}

impl K8sNamespace {
    fn new(cluster: &K8sClusterConfig, test_name: &str) -> Self {
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
            .args(["--context", &cluster.context, "create", "namespace", &name])
            .success()
            .expect("Failed to create k8s namespace");

        Self {
            name,
            context: cluster.context.clone(),
        }
    }
}

impl Drop for K8sNamespace {
    fn drop(&mut self) {
        let status = Command::new("kubectl")
            .args([
                "--context",
                &self.context,
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

/// Write devcontainer.json with extra fields and .rumpelpod.toml for a k8s test.
///
/// `extra_json` is spliced into the devcontainer.json object, e.g.
/// `r#""mounts": [{"type":"volume","source":"tv","target":"/data"}]"#`.
fn write_k8s_pod_config_with_extras(
    repo: &TestRepo,
    cluster: &K8sClusterConfig,
    pull_ref: &str,
    namespace: &str,
    extra_json: &str,
) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let comma = if extra_json.is_empty() { "" } else { "," };
    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{pull_ref}",
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

    let context = &cluster.context;
    let config = formatdoc! {r#"
        [k8s]
        context = "{context}"
        namespace = "{namespace}"

        [k8s.node-selector]
        pool = "test"

        [[k8s.tolerations]]
        key = "pool"
        value = "test"
        effect = "NoSchedule"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// Write devcontainer.json and .rumpelpod.toml for a k8s test.
fn write_k8s_pod_config(
    repo: &TestRepo,
    cluster: &K8sClusterConfig,
    pull_ref: &str,
    namespace: &str,
) {
    write_k8s_pod_config_with_extras(repo, cluster, pull_ref, namespace, "");
}

#[test]
#[ignore]
fn k8s_enter_smoke() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "enter-smoke");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-enter");

    write_k8s_pod_config(&repo, &cluster, &pull_ref, &ns.name);

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
#[ignore]
fn k8s_list_shows_pod() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "list-shows-pod");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-list");

    write_k8s_pod_config(&repo, &cluster, &pull_ref, &ns.name);

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
#[ignore]
fn k8s_delete_removes_pod() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "delete-removes-pod");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-delete");

    write_k8s_pod_config(&repo, &cluster, &pull_ref, &ns.name);

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
    let context = &cluster.context;
    let kubectl_output = Command::new("kubectl")
        .args(["--context", context])
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

/// Write devcontainer.json with a build section and .rumpelpod.toml with registry
/// config for k8s image build tests.
fn write_k8s_build_config(repo: &TestRepo, cluster: &K8sClusterConfig, namespace: &str) {
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

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
    "#};
    std::fs::write(devcontainer_dir.join("Dockerfile"), dockerfile)
        .expect("Failed to write Dockerfile");

    let context = &cluster.context;
    let push_reg = &cluster.push_registry;
    let pull_reg = &cluster.pull_registry;
    let config = formatdoc! {r#"
        [k8s]
        context = "{context}"
        namespace = "{namespace}"
        registry = "{push_reg}"
        pull-registry = "{pull_reg}"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

#[test]
#[ignore]
fn k8s_image_build_no_registry() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "build-no-registry");

    let repo = TestRepo::new();

    // Write a devcontainer.json with build but no registry in .rumpelpod.toml
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

    std::fs::write(devcontainer_dir.join("Dockerfile"), "FROM debian:13\n")
        .expect("Failed to write Dockerfile");

    let context = &cluster.context;
    let namespace = &ns.name;
    let config = formatdoc! {r#"
        [k8s]
        context = "{context}"
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
        "should fail with build on k8s without registry",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires a registry"),
        "error should mention registry requirement: {}",
        stderr,
    );
}

#[test]
#[ignore]
fn k8s_image_build() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "image-build");

    let repo = TestRepo::new();
    write_k8s_build_config(&repo, &cluster, &ns.name);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "k8s-build-test",
            "--",
            "echo",
            "hello from built image",
        ])
        .output()
        .expect("rumpel enter failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rumpel enter with built image failed: stdout={}, stderr={}",
        stdout,
        stderr,
    );
    // stdout includes build/push output before the command output
    assert!(
        stdout.trim().ends_with("hello from built image"),
        "command output should end with expected message: {}",
        stdout,
    );
}

#[test]
#[ignore]
fn k8s_cp_to_and_from_pod() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "cp-to-and-from-pod");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-cp");

    write_k8s_pod_config(&repo, &cluster, &pull_ref, &ns.name);

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
#[ignore]
fn k8s_mount_volume() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "mount-volume");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-vol");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
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
#[ignore]
fn k8s_mount_tmpfs() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "mount-tmpfs");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-tmpfs");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
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
#[ignore]
fn k8s_bind_mount_rejected() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "bind-mount-rejected");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-bind");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
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
#[ignore]
fn k8s_privileged() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "privileged");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-priv");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
        &ns.name,
        r#""privileged": true"#,
    );

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-priv-test", "--", "echo", "privileged-ok"])
        .success()
        .expect("rumpel enter with privileged failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "privileged-ok");
}

#[test]
#[ignore]
fn k8s_cap_add() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "cap-add");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-cap");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
        &ns.name,
        r#""capAdd": ["SYS_PTRACE"]"#,
    );

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-cap-test", "--", "echo", "caps-ok"])
        .success()
        .expect("rumpel enter with capAdd failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "caps-ok");
}

#[test]
#[ignore]
fn k8s_override_command_false() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "override-command-false");

    let repo = TestRepo::new();
    // Build an image with explicit CMD that keeps the container running
    let image_id = build_test_image(repo.path(), r#"CMD ["tail", "-f", "/dev/null"]"#)
        .expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-nocmd");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
        &ns.name,
        r#""overrideCommand": false"#,
    );

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
#[ignore]
fn k8s_host_requirements() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "host-requirements");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-reqs");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
        &ns.name,
        r#""hostRequirements": {"cpus": 1, "memory": "256mb"}"#,
    );

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "k8s-reqs-test", "--", "true"])
        .success()
        .expect("rumpel enter with hostRequirements failed");

    // Verify resource requests are set via kubectl
    let context = &cluster.context;
    let kubectl_output = Command::new("kubectl")
        .args(["--context", context])
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
#[ignore]
fn k8s_init_succeeds_despite_unsupported() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "init-unsupported");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-init");

    write_k8s_pod_config_with_extras(&repo, &cluster, &pull_ref, &ns.name, r#""init": true"#);

    let daemon = TestDaemon::start();

    // init: true is unsupported on k8s but should not prevent pod creation
    // (the daemon logs a warning instead of failing)
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-init-test", "--", "echo", "init-ok"])
        .success()
        .expect("init: true should not prevent pod creation on k8s");
}

#[test]
#[ignore]
fn k8s_forward_port() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "forward-port");

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

    let pull_ref = push_image(&cluster, &image_id, "k8s-fwd");

    write_k8s_pod_config_with_extras(
        &repo,
        &cluster,
        &pull_ref,
        &ns.name,
        r#""forwardPorts": [9600]"#,
    );

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
#[ignore]
fn k8s_recreate() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "recreate");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-recreate");

    write_k8s_pod_config(&repo, &cluster, &pull_ref, &ns.name);

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

/// Write .rumpelpod.toml with custom TOML content and devcontainer.json for a
/// k8s test. Unlike `write_k8s_pod_config_with_extras`, this lets the caller
/// control the full .rumpelpod.toml (e.g. for node-selector / tolerations).
fn write_k8s_pod_config_custom_toml(
    repo: &TestRepo,
    pull_ref: &str,
    toml_content: &str,
    extra_json: &str,
) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let comma = if extra_json.is_empty() { "" } else { "," };
    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{pull_ref}",
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

    std::fs::write(repo.path().join(".rumpelpod.toml"), toml_content)
        .expect("Failed to write .rumpelpod.toml");
}

#[test]
#[ignore]
fn k8s_node_selector_and_tolerations() {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "node-selector");

    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let pull_ref = push_image(&cluster, &image_id, "k8s-nodeselector");

    let context = &cluster.context;
    let namespace = &ns.name;
    // Target the test pool so the pod actually schedules on a worker,
    // and add an extra label/toleration to verify both appear in the spec.
    let toml_config = formatdoc! {r#"
        [k8s]
        context = "{context}"
        namespace = "{namespace}"

        [k8s.node-selector]
        pool = "test"
        "kubernetes.io/os" = "linux"

        [[k8s.tolerations]]
        key = "pool"
        value = "test"
        effect = "NoSchedule"

        [[k8s.tolerations]]
        key = "example.com/extra"
        value = "yes"
        effect = "NoSchedule"
    "#};

    write_k8s_pod_config_custom_toml(&repo, &pull_ref, &toml_config, "");

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "k8s-ns-test", "--", "true"])
        .success()
        .expect("rumpel enter with node-selector failed");

    // Verify both nodeSelector labels appear
    let kubectl_output = Command::new("kubectl")
        .args(["--context", context])
        .args(["--namespace", namespace])
        .args([
            "get",
            "pod",
            "-l",
            "rumpelpod/pod-name=k8s-ns-test",
            "-o",
            "jsonpath={.items[0].spec.nodeSelector}",
        ])
        .output()
        .expect("kubectl get failed");

    let node_selector = String::from_utf8_lossy(&kubectl_output.stdout);
    assert!(
        node_selector.contains("kubernetes.io/os"),
        "nodeSelector should include kubernetes.io/os: {}",
        node_selector,
    );
    assert!(
        node_selector.contains("pool"),
        "nodeSelector should include pool: {}",
        node_selector,
    );

    // Verify our custom toleration is present alongside the pool one
    let kubectl_output = Command::new("kubectl")
        .args(["--context", context])
        .args(["--namespace", namespace])
        .args([
            "get",
            "pod",
            "-l",
            "rumpelpod/pod-name=k8s-ns-test",
            "-o",
            "jsonpath={.items[0].spec.tolerations}",
        ])
        .output()
        .expect("kubectl get tolerations failed");

    let tolerations = String::from_utf8_lossy(&kubectl_output.stdout);
    assert!(
        tolerations.contains("example.com/extra"),
        "tolerations should include example.com/extra: {}",
        tolerations,
    );
}

// Broken: after killing the tunnel-server, the daemon reconnects the tunnel
// but the git gateway port cached by the pod is stale, so git fetch fails
// with "Could not connect to server".  Needs investigation.
#[test]
#[ignore]
fn k8s_tunnel_reconnect() {}
