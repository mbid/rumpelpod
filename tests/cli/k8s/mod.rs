//! Integration tests for Kubernetes host support.
//!
//! These tests require an external Kubernetes cluster configured via
//! environment variables.  Each test creates an isolated namespace to
//! avoid conflicts with parallel test runs.
//!
//! Required env vars (tests are `#[ignore]`d, so only checked when
//! explicitly run):
//!   RUMPELPOD_TEST_K8S_CONTEXT -- kubectl context
//!   RUMPELPOD_TEST_REGISTRY    -- registry for pushing/pulling images (e.g. ghcr.io/user/rumpelpod)

use std::fs;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{
    pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER,
};

/// Cluster configuration read from environment variables.
pub(super) struct K8sClusterConfig {
    pub(super) context: String,
    pub(super) registry: String,
    /// buildkitd pod name (optional; when set, builds use in-cluster builder).
    pub(super) builder_pod: Option<String>,
    /// Namespace of the buildkitd pod.
    pub(super) builder_namespace: Option<String>,
}

pub(super) fn k8s_cluster_config() -> K8sClusterConfig {
    let context = std::env::var("RUMPELPOD_TEST_K8S_CONTEXT")
        .expect("RUMPELPOD_TEST_K8S_CONTEXT must be set to run k8s tests");
    let registry = std::env::var("RUMPELPOD_TEST_REGISTRY")
        .expect("RUMPELPOD_TEST_REGISTRY must be set to run k8s tests");
    let builder_pod = std::env::var("RUMPELPOD_TEST_K8S_BUILDER_POD").ok();
    let builder_namespace = std::env::var("RUMPELPOD_TEST_K8S_BUILDER_NAMESPACE").ok();
    K8sClusterConfig {
        context,
        registry,
        builder_pod,
        builder_namespace,
    }
}

/// Per-test namespace that is automatically deleted on drop.
pub(super) struct K8sNamespace {
    pub(super) name: String,
    context: String,
}

impl K8sNamespace {
    pub(super) fn new(cluster: &K8sClusterConfig, test_name: &str) -> Self {
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

/// K8s executor resources that always use k8s mode regardless of
/// RUMPELPOD_TEST_EXECUTOR.  K8s-specific tests (#[ignore]) call
/// this directly so they don't need the env var set.
fn k8s_executor(home: &TestHome, test_name: &str) -> K8sExecutor {
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, test_name);

    let context = cluster.context.clone();
    let namespace = ns.name.clone();
    let registry = cluster.registry.clone();

    let builder_lines = match (&cluster.builder_pod, &cluster.builder_namespace) {
        (Some(pod), Some(bns)) => {
            format!("builder-pod = \"{pod}\"\nbuilder-namespace = \"{bns}\"\n")
        }
        (Some(pod), None) => format!("builder-pod = \"{pod}\"\n"),
        _ => String::new(),
    };

    let toml = formatdoc! {r#"
        [k8s]
        context = "{context}"
        namespace = "{namespace}"
        registry = "{registry}"
        {builder_lines}
        [k8s.node-selector]
        pool = "test"

        [[k8s.tolerations]]
        key = "pool"
        value = "test"
        effect = "NoSchedule"
    "#};

    // Write kubeconfig so the daemon can find it
    let kubeconfig_path = home.path().join(".kube");
    std::fs::create_dir_all(&kubeconfig_path).unwrap();
    let src = std::env::var("KUBECONFIG")
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".kube/config").to_string_lossy().to_string()))
        .expect("KUBECONFIG or ~/.kube/config must exist");
    let _ = std::fs::copy(&src, kubeconfig_path.join("config"));

    K8sExecutor {
        toml,
        context,
        namespace,
        _namespace: ns,
    }
}

struct K8sExecutor {
    toml: String,
    context: String,
    namespace: String,
    _namespace: K8sNamespace,
}

#[test]
#[ignore]
fn k8s_enter_smoke() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "enter-smoke");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "list-shows-pod");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "delete-removes-pod");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let context = &executor.context;
    let namespace = &executor.namespace;

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
        .args(["--context", &context])
        .args(["--namespace", &namespace])
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
#[ignore]
fn k8s_image_build_no_registry() {
    // This test verifies that build-on-k8s fails without a registry,
    // so it deliberately omits registry from the toml config.
    let cluster = k8s_cluster_config();
    let ns = K8sNamespace::new(&cluster, "build-no-registry");

    let repo = TestRepo::new();

    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile"
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}"
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    fs::write(devcontainer_dir.join("Dockerfile"), "FROM debian:13\n")
        .expect("Failed to write Dockerfile");

    let context = &cluster.context;
    let namespace = &ns.name;
    let config = formatdoc! {r#"
        [k8s]
        context = "{context}"
        namespace = "{namespace}"
    "#};
    fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");

    let home = TestHome::new();
    let _k8s = k8s_executor(&home, "build-no-registry-daemon");
    let daemon = TestDaemon::start(&home);

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "image-build");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "cp-to-and-from-pod");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Create a pod
    pod_command(&repo, &daemon)
        .args(["enter", "k8s-cp-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Write a local file
    let local_file = repo.path().join("test-upload.txt");
    fs::write(&local_file, "hello from host").expect("Failed to write local file");

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

    let content = fs::read_to_string(&local_download).expect("Failed to read downloaded file");
    assert_eq!(content.trim(), "hello from host");
}

#[test]
#[ignore]
fn k8s_mount_volume() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "mount-volume");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(
        &repo,
        "",
        r#","mounts": [{"type":"volume","source":"tv","target":"/data"}]"#,
    );
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "mount-tmpfs");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(
        &repo,
        "",
        r#","mounts": [{"type":"tmpfs","target":"/tmp/mytmp"}]"#,
    );
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "bind-mount-rejected");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(
        &repo,
        "",
        r#","mounts": [{"type":"bind","source":"/tmp/x","target":"/mnt/x"}]"#,
    );
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "privileged");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", r#","privileged": true"#);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-priv-test", "--", "echo", "privileged-ok"])
        .success()
        .expect("rumpel enter with privileged failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "privileged-ok");
}

#[test]
#[ignore]
fn k8s_cap_add() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "cap-add");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", r#","capAdd": ["SYS_PTRACE"]"#);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "k8s-cap-test", "--", "echo", "caps-ok"])
        .success()
        .expect("rumpel enter with capAdd failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "caps-ok");
}

#[test]
#[ignore]
fn k8s_override_command_false() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "override-command-false");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(
        &repo,
        r#"CMD ["tail", "-f", "/dev/null"]"#,
        r#","overrideCommand": false"#,
    );
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "host-requirements");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(
        &repo,
        "",
        r#","hostRequirements": {"cpus": 1, "memory": "256mb"}"#,
    );
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let context = &executor.context;
    let namespace = &executor.namespace;

    pod_command(&repo, &daemon)
        .args(["enter", "k8s-reqs-test", "--", "true"])
        .success()
        .expect("rumpel enter with hostRequirements failed");

    // Verify resource requests are set via kubectl
    let kubectl_output = Command::new("kubectl")
        .args(["--context", &context])
        .args(["--namespace", &namespace])
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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "init-unsupported");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", r#","init": true"#);
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "forward-port");
    let daemon = TestDaemon::start(&home);
    // Install socat alongside git for the echo server
    write_test_devcontainer(
        &repo,
        "RUN apt-get install -y socat",
        r#","forwardPorts": [9600]"#,
    );
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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
    let stream = TcpStream::connect(format!("127.0.0.1:{local_port}"))
        .expect("TCP connect to forwarded port failed");
    drop(stream);
}

#[test]
#[ignore]
fn k8s_recreate() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "recreate");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

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

#[test]
#[ignore]
fn k8s_node_selector_and_tolerations() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home, "node-selector");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");

    let context = &executor.context;
    let namespace = &executor.namespace;

    // Append extra node-selector and toleration to the executor's toml
    // to verify both appear in the pod spec.
    let extra_toml = formatdoc! {r#"

        [k8s.node-selector]
        "kubernetes.io/os" = "linux"

        [[k8s.tolerations]]
        key = "example.com/extra"
        value = "yes"
        effect = "NoSchedule"
    "#};
    let toml = format!("{}{extra_toml}", executor.toml);
    fs::write(repo.path().join(".rumpelpod.toml"), toml).unwrap();

    pod_command(&repo, &daemon)
        .args(["enter", "k8s-ns-test", "--", "true"])
        .success()
        .expect("rumpel enter with node-selector failed");

    // Verify both nodeSelector labels appear
    let kubectl_output = Command::new("kubectl")
        .args(["--context", &context])
        .args(["--namespace", &namespace])
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
        .args(["--context", &context])
        .args(["--namespace", &namespace])
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
