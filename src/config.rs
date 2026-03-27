//! Configuration types for rumpelpod settings.
//!
//! This module provides:
//! - Model enum for CLI and config file parsing
//! - AgentConfig / TomlConfig for `.rumpelpod.toml`
//! - Utility functions for state directory paths
//!
//! Container settings (image, user, workspace, mounts, runArgs, etc.) come from
//! `devcontainer.json`.  The optional `.rumpelpod.toml` provides pod-specific
//! settings that have no devcontainer equivalent (host, agent).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Model to use for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
pub enum Model {
    // Anthropic
    /// Claude Opus 4.5 - most capable model
    #[serde(rename = "claude-opus-4-5")]
    #[value(name = "claude-opus-4-5")]
    #[default]
    ClaudeOpus,
    /// Claude Opus 4.6
    #[serde(rename = "claude-opus-4-6")]
    #[value(name = "claude-opus-4-6")]
    ClaudeOpus46,
    /// Claude Sonnet 4.5 - balanced performance and cost
    #[serde(rename = "claude-sonnet-4-5")]
    #[value(name = "claude-sonnet-4-5")]
    ClaudeSonnet,
    /// Claude Haiku 4.5 - fast and cost-effective
    #[serde(rename = "claude-haiku-4-5")]
    #[value(name = "claude-haiku-4-5")]
    ClaudeHaiku,

    // Gemini
    /// Gemini 2.5 Flash - fast, stable, best price-performance
    #[serde(rename = "gemini-2.5-flash")]
    #[value(name = "gemini-2.5-flash")]
    Gemini25Flash,
    /// Gemini 3 Flash - frontier model built for speed and scale
    #[serde(rename = "gemini-3-flash-preview")]
    #[value(name = "gemini-3-flash-preview")]
    Gemini3Flash,
    /// Gemini 3 Pro - most intelligent frontier model
    #[serde(rename = "gemini-3-pro-preview")]
    #[value(name = "gemini-3-pro-preview")]
    Gemini3Pro,

    // xAI
    /// Grok 4.1 Fast - frontier model optimized for agentic tool calling
    #[serde(rename = "grok-4-1-fast-reasoning")]
    #[value(name = "grok-4-1-fast-reasoning")]
    Grok41Fast,
    /// Grok 4.1 Fast - non-reasoning variant
    #[serde(rename = "grok-4-1-fast-non-reasoning")]
    #[value(name = "grok-4-1-fast-non-reasoning")]
    Grok41FastNonReasoning,
}

impl std::fmt::Display for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Model::ClaudeOpus => "claude-opus-4-5",
            Model::ClaudeOpus46 => "claude-opus-4-6",
            Model::ClaudeSonnet => "claude-sonnet-4-5",
            Model::ClaudeHaiku => "claude-haiku-4-5",
            Model::Gemini25Flash => "gemini-2.5-flash",
            Model::Gemini3Flash => "gemini-3-flash-preview",
            Model::Gemini3Pro => "gemini-3-pro-preview",
            Model::Grok41Fast => "grok-4-1-fast-reasoning",
            Model::Grok41FastNonReasoning => "grok-4-1-fast-non-reasoning",
        };
        write!(f, "{s}")
    }
}

use url::Url;

/// Where a pod runs.
///
/// Either the local machine, a remote host accessed via SSH, or a Kubernetes
/// cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Host {
    /// The default Docker daemon on the local machine.
    Localhost,
    /// A remote Docker daemon accessed via SSH.
    Ssh {
        /// The SSH destination string (e.g. "user@host" or just "host").
        /// Passed directly to the `ssh` command.
        ssh_destination: String,
        /// SSH port (default 22).
        port: u16,
    },
    /// A Kubernetes cluster accessed via kubeconfig.
    Kubernetes {
        /// The kubeconfig context name.
        context: String,
        /// The Kubernetes namespace (default "default").
        namespace: String,
        /// Registry that pods pull built images from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        registry: Option<String>,
        /// Registry to push built images to.  Defaults to `registry`
        /// when not set.  Separate push/pull registries are needed when
        /// the cluster pulls via an internal address (e.g. ClusterIP)
        /// that differs from the address reachable from the build host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        push_registry: Option<String>,
        /// Node selector labels for pod scheduling.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_selector: Option<BTreeMap<String, String>>,
        /// Tolerations for pod scheduling.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tolerations: Option<Vec<K8sToleration>>,
        /// Name of a `docker buildx` builder to use for image builds.
        /// The builder must already exist (created via
        /// `docker buildx create`).  When not set, images are built
        /// with the local Docker daemon and pushed to the registry.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        builder: Option<String>,
    },
}

impl Host {
    /// Parse a Docker host specification from CLI or config file.
    ///
    /// - `"localhost"` means local Docker.
    /// - `"ssh://user@host"` or `"ssh://host:port"` means remote Docker via SSH.
    ///
    /// Bare hostnames like `"dev"` are rejected -- use `"ssh://dev"` instead.
    /// Kubernetes hosts are configured via `--k8s-context` / `[k8s]` instead.
    pub fn parse(s: &str) -> Result<Self> {
        if s == "localhost" {
            return Ok(Host::Localhost);
        }

        let url = Url::parse(s).with_context(|| {
            if !s.contains("://") {
                format!(
                    "Invalid host '{s}'. Use 'localhost' for local Docker \
                     or 'ssh://host' for remote Docker."
                )
            } else {
                format!("Invalid URL: {s}")
            }
        })?;

        match url.scheme() {
            "ssh" => {
                let host = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("URL must have a host: {s}"))?;
                let port = url.port().unwrap_or(22);
                let username = url.username();

                let ssh_destination = if !username.is_empty() {
                    format!("{username}@{host}")
                } else {
                    host.to_string()
                };

                Ok(Host::Ssh {
                    ssh_destination,
                    port,
                })
            }
            other => Err(anyhow::anyhow!(
                "Unsupported scheme '{other}' in host '{s}'. \
                     Use 'ssh://' for remote Docker, or \
                     '--k8s-context' / '[k8s]' for Kubernetes."
            )),
        }
    }

    /// The SSH destination string (e.g. "user@host" or "host").
    /// Panics if called on a non-SSH host.
    pub fn ssh_destination(&self) -> &str {
        match self {
            Host::Ssh {
                ssh_destination, ..
            } => ssh_destination,
            Host::Localhost | Host::Kubernetes { .. } => {
                panic!("ssh_destination() called on non-SSH host")
            }
        }
    }

    /// The SSH port. Panics if called on a non-SSH host.
    pub fn ssh_port(&self) -> u16 {
        match self {
            Host::Ssh { port, .. } => *port,
            Host::Localhost | Host::Kubernetes { .. } => {
                panic!("ssh_port() called on non-SSH host")
            }
        }
    }

    /// Whether this is a remote host (SSH or Kubernetes).
    pub fn is_remote(&self) -> bool {
        match self {
            Host::Localhost => false,
            Host::Ssh { .. } | Host::Kubernetes { .. } => true,
        }
    }

    /// Whether this host uses Docker for container management.
    pub fn is_docker(&self) -> bool {
        match self {
            Host::Localhost | Host::Ssh { .. } => true,
            Host::Kubernetes { .. } => false,
        }
    }

    /// The docker host URI for `docker -H`, e.g. `"ssh://user@host:22"`.
    /// Returns `None` for localhost (use the default socket instead).
    /// Panics if called on a Kubernetes host.
    pub fn docker_host_uri(&self) -> Option<String> {
        match self {
            Host::Localhost => None,
            Host::Ssh {
                ssh_destination,
                port,
            } => Some(format!("ssh://{ssh_destination}:{port}")),
            Host::Kubernetes { .. } => {
                panic!("docker_host_uri() called on Kubernetes host")
            }
        }
    }
}

impl std::fmt::Display for Host {
    /// Human-readable display for `rumpel list` and error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Localhost => write!(f, "localhost"),
            Host::Ssh {
                ssh_destination,
                port,
            } => {
                if *port == 22 {
                    write!(f, "ssh://{ssh_destination}")
                } else if let Some((user, host)) = ssh_destination.split_once('@') {
                    write!(f, "ssh://{user}@{host}:{port}")
                } else {
                    write!(f, "ssh://{ssh_destination}:{port}")
                }
            }
            Host::Kubernetes {
                context, namespace, ..
            } => {
                if namespace == "default" {
                    write!(f, "k8s:{context}")
                } else {
                    write!(f, "k8s:{context}/{namespace}")
                }
            }
        }
    }
}

/// A single Kubernetes toleration from `[[k8s.tolerations]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct K8sToleration {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
}

/// Kubernetes target from `[k8s]` in `.rumpelpod.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct K8sConfig {
    /// The kubeconfig context name.
    pub context: String,
    /// The Kubernetes namespace (default "default").
    pub namespace: Option<String>,
    /// Registry that pods pull built images from.
    pub registry: Option<String>,
    /// Registry to push built images to (defaults to `registry`).
    pub push_registry: Option<String>,
    /// Node selector labels for pod scheduling.
    #[serde(default)]
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Tolerations for pod scheduling.
    #[serde(default)]
    pub tolerations: Option<Vec<K8sToleration>>,
    /// Name of a `docker buildx` builder for image builds.
    pub builder: Option<String>,
}

/// Configuration from `.rumpelpod.toml`.
///
/// Fields that have equivalents in devcontainer.json (image, user,
/// workspaceFolder, runtime, network) are intentionally omitted -- they
/// should be set in devcontainer.json instead (runtime and network via
/// `runArgs`).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TomlConfig {
    #[serde(default)]
    pub agent: AgentConfig,

    #[serde(default)]
    pub claude: ClaudeConfig,

    #[serde(default)]
    pub merge: MergeConfig,

    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    pub host: Option<String>,

    /// Kubernetes target. Mutually exclusive with `host`.
    pub k8s: Option<K8sConfig>,
}

/// Load `.rumpelpod.toml` from the given repo root, if present.
pub fn load_toml_config(repo_root: &Path) -> Result<TomlConfig> {
    let config_path = repo_root.join(".rumpelpod.toml");
    if config_path.exists() {
        let config_path_display = config_path.display();
        let contents = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read {config_path_display}"))?;
        let config: TomlConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse {config_path_display}"))?;

        // host and [k8s] are mutually exclusive
        if config.host.is_some() && config.k8s.is_some() {
            return Err(anyhow::anyhow!(
                "Configuration error: 'host' and '[k8s]' are mutually exclusive in {config_path_display}."
            ));
        }

        // Validate agent model options
        let model_options_count = config.agent.model.is_some() as usize
            + config.agent.custom_anthropic_model.is_some() as usize
            + config.agent.custom_gemini_model.is_some() as usize
            + config.agent.custom_xai_model.is_some() as usize;
        if model_options_count > 1 {
            return Err(anyhow::anyhow!("Configuration error: Only one of 'model', 'custom-anthropic-model', 'custom-gemini-model', or 'custom-xai-model' can be specified in [agent] section."));
        }

        Ok(config)
    } else {
        Ok(TomlConfig::default())
    }
}

/// Agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AgentConfig {
    /// Default model.
    pub model: Option<Model>,
    /// Custom Anthropic model string.
    pub custom_anthropic_model: Option<String>,
    /// Custom Gemini model string.
    pub custom_gemini_model: Option<String>,
    /// Custom xAI model string.
    pub custom_xai_model: Option<String>,
    /// Anthropic base URL.
    pub anthropic_base_url: Option<String>,
    /// Enable Anthropic web search.
    #[serde(default)]
    pub anthropic_websearch: Option<bool>,
    /// Thinking budget in tokens.
    /// If set, enables thinking mode for supported models (e.g., Claude Opus 4.5).
    pub thinking_budget: Option<u32>,
}

/// Configuration for `rumpel claude`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ClaudeConfig {
    /// Use a PermissionRequest hook instead of --dangerously-skip-permissions.
    #[serde(default)]
    pub dangerously_skip_permissions_hook: bool,

    /// Install a system prompt describing the rumpelpod environment
    /// (devcontainer layout, git remotes, push/fetch behavior) into
    /// /etc/claude-code/CLAUDE.md inside the container.
    /// Defaults to true.
    #[serde(default = "default_true")]
    pub system_prompt: bool,
}

fn default_true() -> bool {
    true
}

/// Whether the merge description file feature is enabled, and if so, which
/// path to use.
///
/// In `.rumpelpod.toml`:
///   description-file = "DESCRIPTION"   # custom path (default value)
///   description-file = false            # disable
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptionFileSetting {
    Path(String),
    Disabled,
}

impl Default for DescriptionFileSetting {
    fn default() -> Self {
        DescriptionFileSetting::Path("DESCRIPTION".to_string())
    }
}

impl<'de> Deserialize<'de> for DescriptionFileSetting {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = DescriptionFileSetting;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a file path string, or false to disable")
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                if v {
                    Ok(DescriptionFileSetting::default())
                } else {
                    Ok(DescriptionFileSetting::Disabled)
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.is_empty() {
                    Err(E::custom("description-file path must not be empty"))
                } else {
                    Ok(DescriptionFileSetting::Path(v.to_string()))
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Merge configuration from `[merge]` in `.rumpelpod.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MergeConfig {
    /// File in the pod branch whose contents become the merge commit message.
    /// The file is removed from the merge result.
    /// Set to `false` to disable. Default: "DESCRIPTION".
    #[serde(default)]
    pub description_file: DescriptionFileSetting,
}

/// Get the state directory for rumpelpod data.
/// Uses $XDG_STATE_HOME/rumpelpod or ~/.local/state/rumpelpod as fallback.
pub fn get_state_dir() -> Result<PathBuf> {
    let state_base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".local/state")
        });

    Ok(state_base.join("rumpelpod"))
}

/// Get the runtime directory for rumpelpod sockets.
/// Uses $XDG_RUNTIME_DIR/rumpelpod or /tmp/rumpelpod-<uid> as fallback.
pub fn get_runtime_dir() -> Result<PathBuf> {
    let runtime_base = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Fallback to /tmp/rumpelpod-<uid>
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/rumpelpod-{uid}"))
        });

    Ok(runtime_base.join("rumpelpod"))
}

/// Check if deterministic test mode is enabled via RUMPELPOD_TEST_DETERMINISTIC_IDS.
///
/// Returns:
/// - `Ok(true)` if set to "1"
/// - `Ok(false)` if not set
/// - `Err(...)` if set to any other value
pub fn is_deterministic_test_mode() -> Result<bool> {
    match std::env::var("RUMPELPOD_TEST_DETERMINISTIC_IDS") {
        Ok(value) if value == "1" => Ok(true),
        Ok(value) => Err(anyhow::anyhow!(
            "RUMPELPOD_TEST_DETERMINISTIC_IDS must be '1' if set, got '{value}'"
        )),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(e).context("failed to read RUMPELPOD_TEST_DETERMINISTIC_IDS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_localhost() {
        let host = Host::parse("localhost").unwrap();
        assert_eq!(host, Host::Localhost);
        assert_eq!(host.to_string(), "localhost");
    }

    #[test]
    fn parse_ssh_url() {
        let host = Host::parse("ssh://dev").unwrap();
        assert_eq!(host.ssh_destination(), "dev");
        assert_eq!(host.ssh_port(), 22);
        assert_eq!(host.to_string(), "ssh://dev");
    }

    #[test]
    fn parse_ssh_url_with_user() {
        let host = Host::parse("ssh://user@dev").unwrap();
        assert_eq!(host.ssh_destination(), "user@dev");
        assert_eq!(host.ssh_port(), 22);
        assert_eq!(host.to_string(), "ssh://user@dev");
    }

    #[test]
    fn parse_ssh_url_with_port() {
        let host = Host::parse("ssh://user@dev:2222").unwrap();
        assert_eq!(host.ssh_destination(), "user@dev");
        assert_eq!(host.ssh_port(), 2222);
        assert_eq!(host.to_string(), "ssh://user@dev:2222");
    }

    #[test]
    fn parse_ssh_default_port_not_shown() {
        let host = Host::parse("ssh://user@dev:22").unwrap();
        assert_eq!(host.to_string(), "ssh://user@dev");
    }

    #[test]
    fn parse_bare_hostname_rejected() {
        let err = Host::parse("dev").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ssh://"),
            "error should suggest ssh:// prefix: {msg}"
        );
    }

    #[test]
    fn parse_unsupported_scheme_rejected() {
        let err = Host::parse("http://dev").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Unsupported scheme"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn parse_k8s_scheme_rejected() {
        let err = Host::parse("k8s://my-cluster").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("k8s-context"),
            "error should suggest --k8s-context: {msg}"
        );
    }

    #[test]
    fn docker_host_uri_localhost() {
        assert_eq!(Host::Localhost.docker_host_uri(), None);
    }

    #[test]
    fn docker_host_uri_ssh() {
        let host = Host::parse("ssh://user@dev:2222").unwrap();
        assert_eq!(
            host.docker_host_uri(),
            Some("ssh://user@dev:2222".to_string())
        );
    }

    #[test]
    fn display_k8s_default_namespace() {
        let host = Host::Kubernetes {
            context: "my-cluster".to_string(),
            namespace: "default".to_string(),
            registry: None,
            node_selector: None,
            tolerations: None,
            builder: None,
            push_registry: None,
        };
        assert_eq!(host.to_string(), "k8s:my-cluster");
    }

    #[test]
    fn display_k8s_custom_namespace() {
        let host = Host::Kubernetes {
            context: "my-cluster".to_string(),
            namespace: "staging".to_string(),
            registry: None,
            node_selector: None,
            tolerations: None,
            builder: None,
            push_registry: None,
        };
        assert_eq!(host.to_string(), "k8s:my-cluster/staging");
    }

    #[test]
    fn k8s_is_remote() {
        let host = Host::Kubernetes {
            context: "my-cluster".to_string(),
            namespace: "default".to_string(),
            registry: None,
            node_selector: None,
            tolerations: None,
            builder: None,
            push_registry: None,
        };
        assert!(host.is_remote());
        assert!(!host.is_docker());
    }

    #[test]
    fn serde_json_roundtrip() {
        let hosts = vec![
            Host::Localhost,
            Host::Ssh {
                ssh_destination: "user@host".to_string(),
                port: 22,
            },
            Host::Ssh {
                ssh_destination: "dev".to_string(),
                port: 2222,
            },
            Host::Kubernetes {
                context: "my-cluster".to_string(),
                namespace: "staging".to_string(),
                registry: None,
                node_selector: None,
                tolerations: None,
                builder: None,
                push_registry: None,
            },
        ];
        for host in hosts {
            let json = serde_json::to_string(&host).unwrap();
            let roundtripped: Host = serde_json::from_str(&json).unwrap();
            assert_eq!(host, roundtripped, "roundtrip failed for {host:?}");
        }
    }

    #[test]
    fn parse_k8s_node_selector_and_tolerations() {
        let toml_str = indoc::indoc! {r#"
            [k8s]
            context = "test-cluster"

            [k8s.node-selector]
            pool = "test"

            [[k8s.tolerations]]
            key = "pool"
            value = "test"
            effect = "NoSchedule"
        "#};
        let config: TomlConfig = toml::from_str(toml_str).unwrap();
        let k8s = config.k8s.unwrap();
        let ns = k8s.node_selector.unwrap();
        assert_eq!(ns.get("pool"), Some(&"test".to_string()));
        let tols = k8s.tolerations.unwrap();
        assert_eq!(tols.len(), 1);
        assert_eq!(tols[0].key, "pool");
        assert_eq!(tols[0].value.as_deref(), Some("test"));
        assert_eq!(tols[0].effect, "NoSchedule");
        assert_eq!(tols[0].operator, None);
    }

    #[test]
    fn k8s_host_roundtrip_with_node_selector() {
        let mut ns = BTreeMap::new();
        ns.insert("pool".to_string(), "test".to_string());
        let host = Host::Kubernetes {
            context: "cluster".to_string(),
            namespace: "default".to_string(),
            registry: None,
            node_selector: Some(ns),
            tolerations: Some(vec![K8sToleration {
                key: "pool".to_string(),
                value: Some("test".to_string()),
                effect: "NoSchedule".to_string(),
                operator: None,
            }]),
            builder: None,
            push_registry: None,
        };
        let json = serde_json::to_string(&host).unwrap();
        let roundtripped: Host = serde_json::from_str(&json).unwrap();
        assert_eq!(host, roundtripped);
    }

    #[test]
    fn parse_merge_default() {
        let config: TomlConfig = toml::from_str("").unwrap();
        assert_eq!(
            config.merge.description_file,
            DescriptionFileSetting::Path("DESCRIPTION".to_string())
        );
    }

    #[test]
    fn parse_merge_custom_path() {
        let config: TomlConfig = toml::from_str(indoc::indoc! {r#"
            [merge]
            description-file = "MERGE_MSG"
        "#})
        .unwrap();
        assert_eq!(
            config.merge.description_file,
            DescriptionFileSetting::Path("MERGE_MSG".to_string())
        );
    }

    #[test]
    fn parse_merge_disabled() {
        let config: TomlConfig = toml::from_str(indoc::indoc! {r#"
            [merge]
            description-file = false
        "#})
        .unwrap();
        assert_eq!(
            config.merge.description_file,
            DescriptionFileSetting::Disabled
        );
    }

    #[test]
    fn parse_merge_true_means_default() {
        let config: TomlConfig = toml::from_str(indoc::indoc! {r#"
            [merge]
            description-file = true
        "#})
        .unwrap();
        assert_eq!(
            config.merge.description_file,
            DescriptionFileSetting::Path("DESCRIPTION".to_string())
        );
    }

    #[test]
    fn parse_merge_empty_path_rejected() {
        let err = toml::from_str::<TomlConfig>(indoc::indoc! {r#"
            [merge]
            description-file = ""
        "#});
        assert!(err.is_err());
    }
}
