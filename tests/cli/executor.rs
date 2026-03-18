//! Executor-agnostic test infrastructure.
//!
//! Reads `RUMPELPOD_TEST_EXECUTOR` to select which executor to use:
//!   - `docker` (default) -- local Docker daemon
//!   - `ssh`              -- remote Docker via SSH tunnel
//!   - `k8s`              -- Kubernetes cluster
//!
//! [`TestExecutor`] starts a daemon and returns the `.rumpelpod.toml`
//! section for the active executor.  Tests splice this into their own
//! `.rumpelpod.toml`, keeping the config fully visible in the test body.

#![allow(dead_code)]

use std::path::Path;

use indoc::formatdoc;

use super::common::TestDaemon;

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

/// Returns `true` when deterministic PIDs can be used.
///
/// Deterministic PIDs require writing to /proc/sys/kernel/ns_last_pid,
/// which needs SYS_ADMIN (privileged mode). K8s pods run unprivileged.
pub fn executor_supports_deterministic_ids() -> bool {
    !matches!(executor_mode(), ExecutorMode::K8s)
}

// ---------------------------------------------------------------------------
// TestExecutor -- daemon + executor-specific .rumpelpod.toml
// ---------------------------------------------------------------------------

/// Running daemon plus executor resources (SSH remote, K8s namespace)
/// that must stay alive for the duration of the test.
///
/// The `.rumpelpod.toml` content is in [`toml`]; tests write it to disk
/// themselves so the config is visible in the test body.
pub struct TestExecutor {
    pub daemon: TestDaemon,
    /// Executor-specific `.rumpelpod.toml` content.
    pub toml: String,
    /// Resources that must outlive the daemon.
    _resources: ExecutorResources,
}

enum ExecutorResources {
    Docker,
    Ssh {
        _remote: super::ssh::SshRemoteHost,
        _ssh_config: super::ssh::SshConfig,
    },
    K8s {
        _namespace: super::k8s::K8sNamespace,
    },
}

impl TestExecutor {
    /// Start a test executor for the given test name.
    ///
    /// `test_name` must be unique per test; it is used as the K8s
    /// namespace suffix.
    pub fn start(test_name: &str) -> Self {
        Self::start_inner(test_name, None)
    }

    /// Like [`start`](Self::start) but with a custom HOME directory,
    /// isolating the daemon from the host user's config files.
    pub fn start_with_home(test_name: &str, home: &Path) -> Self {
        Self::start_inner(test_name, Some(home))
    }

    fn start_inner(test_name: &str, home: Option<&Path>) -> Self {
        match executor_mode() {
            ExecutorMode::Docker => Self::docker(home),
            ExecutorMode::Ssh => Self::ssh(home),
            ExecutorMode::K8s => Self::k8s(test_name, home),
        }
    }

    fn docker(home: Option<&Path>) -> Self {
        let daemon = match home {
            Some(h) => TestDaemon::start_with_home(h),
            None => TestDaemon::start(),
        };
        TestExecutor {
            daemon,
            toml: String::new(),
            _resources: ExecutorResources::Docker,
        }
    }

    fn ssh(home: Option<&Path>) -> Self {
        let remote = super::ssh::SshRemoteHost::start();
        let ssh_config = super::ssh::create_ssh_config(&[&remote]);
        let daemon = match home {
            Some(h) => TestDaemon::start_with_ssh_config_and_home(&ssh_config.path, h),
            None => TestDaemon::start_with_ssh_config(&ssh_config.path),
        };

        let remote_spec = remote.ssh_spec();
        let toml = formatdoc! {r#"
            host = "{remote_spec}"
        "#};

        TestExecutor {
            daemon,
            toml,
            _resources: ExecutorResources::Ssh {
                _remote: remote,
                _ssh_config: ssh_config,
            },
        }
    }

    fn k8s(test_name: &str, home: Option<&Path>) -> Self {
        let cluster = super::k8s::k8s_cluster_config();
        let ns = super::k8s::K8sNamespace::new(&cluster, test_name);

        let context = &cluster.context;
        let namespace = &ns.name;
        let push_registry = &cluster.push_registry;
        let pull_registry = &cluster.pull_registry;
        let toml = formatdoc! {r#"
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
        "#};

        let daemon = match home {
            Some(h) => TestDaemon::start_with_home(h),
            None => TestDaemon::start(),
        };
        TestExecutor {
            daemon,
            toml,
            _resources: ExecutorResources::K8s { _namespace: ns },
        }
    }
}
