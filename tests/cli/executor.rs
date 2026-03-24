//! Executor-agnostic test infrastructure.
//!
//! Reads `RUMPELPOD_TEST_EXECUTOR` to select which executor to use:
//!   - `docker` (default) -- local Docker daemon
//!   - `ssh`              -- remote Docker via SSH tunnel
//!   - `k8s`              -- Kubernetes cluster
//!
//! [`ExecutorResources`] sets up the active executor's resources and
//! returns the `.rumpelpod.toml` section.  The daemon is started
//! separately by the test.

#![allow(dead_code)]

use indoc::formatdoc;

use super::common::TestHome;

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
// ExecutorResources -- executor-specific setup and .rumpelpod.toml
// ---------------------------------------------------------------------------

/// Executor resources (SSH remote host, K8s namespace) that must stay
/// alive for the duration of the test.
///
/// The `.rumpelpod.toml` content is in [`toml`]; tests write it to disk
/// themselves so the config is visible in the test body.
pub struct ExecutorResources {
    /// Executor-specific `.rumpelpod.toml` content.
    pub toml: String,
    /// Keep resources alive until the test ends.
    _resources: Resources,
}

enum Resources {
    Docker,
    Ssh {
        _remote: super::ssh::SshRemoteHost,
    },
    K8s {
        _namespace: super::k8s::K8sNamespace,
    },
}

impl ExecutorResources {
    /// Set up the executor for the given test.
    ///
    /// For SSH mode, writes the SSH config into `home/.ssh/`.
    /// Must be called before [`TestDaemon::start`] so the daemon
    /// inherits the config via `$HOME`.
    pub fn setup(home: &TestHome, test_name: &str) -> Self {
        match executor_mode() {
            ExecutorMode::Docker => Self::docker(),
            ExecutorMode::Ssh => Self::ssh(home),
            ExecutorMode::K8s => Self::k8s(test_name),
        }
    }

    fn docker() -> Self {
        ExecutorResources {
            toml: String::new(),
            _resources: Resources::Docker,
        }
    }

    fn ssh(home: &TestHome) -> Self {
        let remote = super::ssh::SshRemoteHost::start();
        super::ssh::write_ssh_config(home, &[&remote]);

        let remote_spec = remote.ssh_spec();
        let toml = formatdoc! {r#"
            host = "{remote_spec}"
        "#};

        ExecutorResources {
            toml,
            _resources: Resources::Ssh { _remote: remote },
        }
    }

    fn k8s(test_name: &str) -> Self {
        let cluster = super::k8s::k8s_cluster_config();
        let ns = super::k8s::K8sNamespace::new(&cluster, test_name);

        let context = &cluster.context;
        let namespace = &ns.name;
        let registry = &cluster.registry;

        let builder_lines = match (&cluster.builder_pod, &cluster.builder_namespace) {
            (Some(pod), Some(ns)) => {
                format!("builder-pod = \"{pod}\"\nbuilder-namespace = \"{ns}\"\n")
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

        ExecutorResources {
            toml,
            _resources: Resources::K8s { _namespace: ns },
        }
    }
}
