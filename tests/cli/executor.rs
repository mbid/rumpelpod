//! Executor-agnostic test infrastructure.
//!
//! Reads `RUMPELPOD_TEST_EXECUTOR` to select which executor to use:
//!   - `docker` (default) -- local Docker daemon
//!   - `ssh`              -- remote Docker via SSH tunnel
//!   - `k8s`              -- Kubernetes cluster
//!
//! [`TestPod`] sets up image distribution, config files, and daemon for any
//! executor, letting the same test body run against all three.

#![allow(dead_code)]

use std::path::Path;

use indoc::formatdoc;

use super::common::{ImageId, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

// ---------------------------------------------------------------------------
// Executor mode
// ---------------------------------------------------------------------------

pub enum ExecutorMode {
    Docker,
    Ssh,
    K8s,
}

pub fn executor_mode() -> ExecutorMode {
    match std::env::var("RUMPELPOD_TEST_EXECUTOR").as_deref() {
        Ok("ssh") => ExecutorMode::Ssh,
        Ok("k8s") => ExecutorMode::K8s,
        _ => ExecutorMode::Docker,
    }
}

/// Returns `true` when the current executor supports `rumpel stop`.
/// K8s does not.
pub fn executor_supports_stop() -> bool {
    !matches!(executor_mode(), ExecutorMode::K8s)
}

// ---------------------------------------------------------------------------
// TestPod -- executor-agnostic test environment
// ---------------------------------------------------------------------------

/// Fully-configured test environment.
///
/// Holds the daemon and any executor-specific resources that must stay alive
/// for the duration of the test (SSH remote host, K8s namespace, etc.).
pub struct TestPod {
    pub daemon: TestDaemon,
    /// Prevent the compiler from dropping resources too early.
    _resources: Box<dyn std::any::Any>,
}

struct DockerResources;

struct SshResources {
    _remote: super::ssh::SshRemoteHost,
    _ssh_config: super::ssh::SshConfig,
}

struct K8sResources {
    _namespace: super::k8s::K8sNamespace,
}

impl TestPod {
    /// Standard setup with the default test user from the image.
    ///
    /// Writes devcontainer.json referencing the pre-built image and sets up
    /// .rumpelpod.toml + daemon for the active executor.
    ///
    /// `test_name` must be unique per test; it is used as the K8s namespace
    /// suffix and registry tag.
    pub fn start(repo: &TestRepo, image_id: &ImageId, test_name: &str) -> Self {
        Self::start_inner(repo, image_id, test_name, None)
    }

    /// Setup with an explicit `containerUser` in devcontainer.json.
    pub fn start_with_user(
        repo: &TestRepo,
        image_id: &ImageId,
        test_name: &str,
        user: &str,
    ) -> Self {
        Self::start_inner(repo, image_id, test_name, Some(user))
    }

    /// Executor setup for tests that write their own devcontainer.json.
    ///
    /// Sets up .rumpelpod.toml and daemon for the active executor but does
    /// NOT write devcontainer.json.  The caller is responsible for writing
    /// devcontainer.json (typically with a Dockerfile build section).
    pub fn start_build(repo: &TestRepo, test_name: &str) -> Self {
        Self::start_build_inner(repo, test_name, None)
    }

    /// Like [`start_build`](Self::start_build) but with a custom HOME
    /// directory, isolating the daemon from the host user's config files.
    pub fn start_build_with_home(repo: &TestRepo, test_name: &str, home: &Path) -> Self {
        Self::start_build_inner(repo, test_name, Some(home))
    }

    fn start_build_inner(repo: &TestRepo, test_name: &str, home: Option<&Path>) -> Self {
        match executor_mode() {
            ExecutorMode::Docker => Self::build_docker(repo, home),
            ExecutorMode::Ssh => Self::build_ssh(repo, home),
            ExecutorMode::K8s => Self::build_k8s(repo, test_name, home),
        }
    }

    fn start_inner(
        repo: &TestRepo,
        image_id: &ImageId,
        test_name: &str,
        user: Option<&str>,
    ) -> Self {
        match executor_mode() {
            ExecutorMode::Docker => Self::start_docker(repo, image_id, user),
            ExecutorMode::Ssh => Self::start_ssh(repo, image_id, user),
            ExecutorMode::K8s => Self::start_k8s(repo, image_id, test_name, user),
        }
    }

    fn start_docker(repo: &TestRepo, image_id: &ImageId, user: Option<&str>) -> Self {
        write_docker_config(repo, &image_id.to_string(), user);
        TestPod {
            daemon: TestDaemon::start(),
            _resources: Box::new(DockerResources),
        }
    }

    fn start_ssh(repo: &TestRepo, image_id: &ImageId, user: Option<&str>) -> Self {
        let remote = super::ssh::SshRemoteHost::start();
        let remote_image_id = remote
            .load_image(image_id)
            .expect("Failed to load image into remote Docker");
        let ssh_config = super::ssh::create_ssh_config(&[&remote]);
        let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

        write_docker_config(repo, &remote_image_id.to_string(), user);

        // Override .rumpelpod.toml with the SSH host.
        let remote_spec = remote.ssh_spec();
        let config = formatdoc! {r#"
            host = "{remote_spec}"
        "#};
        std::fs::write(repo.path().join(".rumpelpod.toml"), config)
            .expect("Failed to write .rumpelpod.toml");

        TestPod {
            daemon,
            _resources: Box::new(SshResources {
                _remote: remote,
                _ssh_config: ssh_config,
            }),
        }
    }

    fn start_k8s(repo: &TestRepo, image_id: &ImageId, test_name: &str, user: Option<&str>) -> Self {
        let cluster = super::k8s::k8s_cluster_config();
        let ns = super::k8s::K8sNamespace::new(&cluster, test_name);
        let pull_ref = super::k8s::push_image(&cluster, image_id, test_name);

        // write_k8s_pod_config already sets containerUser to TEST_USER.
        // A custom user override would require refactoring the template.
        assert!(
            user.is_none() || user == Some(TEST_USER),
            "custom containerUser not yet supported on k8s executor"
        );
        super::k8s::write_k8s_pod_config(repo, &cluster, &pull_ref, &ns.name);

        TestPod {
            daemon: TestDaemon::start(),
            _resources: Box::new(K8sResources { _namespace: ns }),
        }
    }

    // -- build variants: set up executor without writing devcontainer.json --

    fn build_docker(repo: &TestRepo, home: Option<&Path>) -> Self {
        write_pod_toml(repo, "");
        let daemon = match home {
            Some(h) => TestDaemon::start_with_home(h),
            None => TestDaemon::start(),
        };
        TestPod {
            daemon,
            _resources: Box::new(DockerResources),
        }
    }

    fn build_ssh(repo: &TestRepo, home: Option<&Path>) -> Self {
        let remote = super::ssh::SshRemoteHost::start();
        let ssh_config = super::ssh::create_ssh_config(&[&remote]);
        let daemon = match home {
            Some(h) => TestDaemon::start_with_ssh_config_and_home(&ssh_config.path, h),
            None => TestDaemon::start_with_ssh_config(&ssh_config.path),
        };

        let remote_spec = remote.ssh_spec();
        write_pod_toml(
            repo,
            &formatdoc! {r#"
            host = "{remote_spec}"
        "#},
        );

        TestPod {
            daemon,
            _resources: Box::new(SshResources {
                _remote: remote,
                _ssh_config: ssh_config,
            }),
        }
    }

    fn build_k8s(repo: &TestRepo, test_name: &str, home: Option<&Path>) -> Self {
        let cluster = super::k8s::k8s_cluster_config();
        let ns = super::k8s::K8sNamespace::new(&cluster, test_name);

        let context = &cluster.context;
        let namespace = &ns.name;
        let push_registry = &cluster.push_registry;
        let pull_registry = &cluster.pull_registry;
        write_pod_toml(
            repo,
            &formatdoc! {r#"
            [k8s]
            context = "{context}"
            namespace = "{namespace}"
            registry = "{push_registry}"
            pull-registry = "{pull_registry}"

            [k8s.node-selector]
            pool = "test"

            [[k8s.tolerations]]
            key = "pool"
            value = "test"
            effect = "NoSchedule"
        "#},
        );

        let daemon = match home {
            Some(h) => TestDaemon::start_with_home(h),
            None => TestDaemon::start(),
        };
        TestPod {
            daemon,
            _resources: Box::new(K8sResources { _namespace: ns }),
        }
    }
}

/// Write .rumpelpod.toml with executor-specific config.
fn write_pod_toml(repo: &TestRepo, executor_config: &str) {
    std::fs::write(repo.path().join(".rumpelpod.toml"), executor_config)
        .expect("Failed to write .rumpelpod.toml");
}

/// Write devcontainer.json and .rumpelpod.toml for Docker/SSH executors.
fn write_docker_config(repo: &TestRepo, image_ref: &str, user: Option<&str>) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let user_field = match user {
        Some(u) => format!(
            r#",
            "containerUser": "{u}""#
        ),
        None => String::new(),
    };

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_ref}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"]{user_field}
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    std::fs::write(repo.path().join(".rumpelpod.toml"), "\n")
        .expect("Failed to write .rumpelpod.toml");
}
