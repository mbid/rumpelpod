//! Configuration types for sandbox settings.
//!
//! This module provides:
//! - Runtime and Model enums for CLI and config file parsing
//! - SandboxConfig for merging `devcontainer.json` and optional `.sandbox.toml`
//! - Utility functions for state directory paths
//!
//! Container settings (image, user, workspace, mounts, etc.) come from
//! `devcontainer.json`.  The optional `.sandbox.toml` provides sandbox-specific
//! settings that have no devcontainer equivalent (runtime, network, host, agent).

use crate::devcontainer::{
    DevContainer, LifecycleCommand, MountObject, Port, PortAttributes, WaitFor,
};
use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use indoc::formatdoc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Container runtime to use for sandboxing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    /// gVisor runtime (default) - strong isolation via kernel syscall interception
    #[default]
    Runsc,
    /// Standard OCI runtime - no additional isolation
    Runc,
    /// Sysbox runtime - enables Docker-in-Docker with VM-like isolation
    SysboxRunc,
}

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
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    #[test]
    fn test_model_string_consistency() {
        // This test ensures that for every model variant:
        // 1. The string representation (Display) matches the Clap value name.
        // 2. The string representation matches the Serde serialization (JSON/TOML).

        for model in Model::value_variants() {
            let s = model.to_string();

            // Check Clap name
            let clap_val = model
                .to_possible_value()
                .expect("Model should have a clap value");
            assert_eq!(s, clap_val.get_name(), "Clap name mismatch for {:?}", model);

            // Check Serde serialization
            let json = serde_json::to_string(&model).expect("Failed to serialize");
            let expected_json = format!("\"{}\"", s);
            assert_eq!(
                json, expected_json,
                "Serde serialization mismatch for {:?}",
                model
            );

            // Check Serde deserialization
            let deserialized: Model = serde_json::from_str(&json).expect("Failed to deserialize");
            assert_eq!(
                *model, deserialized,
                "Deserialization mismatch for {:?}",
                model
            );
        }
    }

    #[test]
    fn test_remote_docker_parse_ssh_url() {
        let remote = RemoteDocker::parse("ssh://docker.example.com").unwrap();
        assert_eq!(remote.destination, "docker.example.com");
        assert_eq!(remote.port, 22);

        let remote = RemoteDocker::parse("ssh://user@docker.example.com").unwrap();
        assert_eq!(remote.destination, "user@docker.example.com");
        assert_eq!(remote.port, 22);

        let remote = RemoteDocker::parse("ssh://docker.example.com:2222").unwrap();
        assert_eq!(remote.destination, "docker.example.com");
        assert_eq!(remote.port, 2222);

        let remote = RemoteDocker::parse("ssh://user@docker.example.com:2222").unwrap();
        assert_eq!(remote.destination, "user@docker.example.com");
        assert_eq!(remote.port, 2222);
    }

    #[test]
    fn test_remote_docker_parse_invalid_scheme() {
        assert!(RemoteDocker::parse("http://example.com").is_err());
    }

    #[test]
    fn test_remote_docker_parse_fallback_scheme() {
        let remote = RemoteDocker::parse("docker.example.com").unwrap();
        assert_eq!(remote.destination, "docker.example.com");
        assert_eq!(remote.port, 22);

        let remote = RemoteDocker::parse("user@docker.example.com:2222").unwrap();
        assert_eq!(remote.destination, "user@docker.example.com");
        assert_eq!(remote.port, 2222);
    }

    #[test]
    fn test_remote_docker_parse_invalid_url() {
        // "not-a-url" is treated as a host "not-a-url" with default port 22
        let remote = RemoteDocker::parse("not-a-url").unwrap();
        assert_eq!(remote.destination, "not-a-url");
        assert_eq!(remote.port, 22);
    }

    #[test]
    fn test_parse_run_args_network_equals() {
        let args = vec!["--network=host".to_string()];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, Some(Network::UnsafeHost));
        assert_eq!(parsed.runtime, None);
    }

    #[test]
    fn test_parse_run_args_network_separate() {
        let args = vec!["--network".to_string(), "host".to_string()];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, Some(Network::UnsafeHost));
        assert_eq!(parsed.runtime, None);
    }

    #[test]
    fn test_parse_run_args_runtime_equals() {
        let args = vec!["--runtime=sysbox-runc".to_string()];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, None);
        assert_eq!(parsed.runtime, Some(Runtime::SysboxRunc));
    }

    #[test]
    fn test_parse_run_args_runtime_separate() {
        let args = vec!["--runtime".to_string(), "runsc".to_string()];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, None);
        assert_eq!(parsed.runtime, Some(Runtime::Runsc));
    }

    #[test]
    fn test_parse_run_args_both() {
        let args = vec![
            "--network=host".to_string(),
            "--runtime=sysbox-runc".to_string(),
        ];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, Some(Network::UnsafeHost));
        assert_eq!(parsed.runtime, Some(Runtime::SysboxRunc));
    }

    #[test]
    fn test_parse_run_args_mixed_with_other_args() {
        let args = vec![
            "--privileged".to_string(),
            "--network".to_string(),
            "host".to_string(),
            "-v".to_string(),
            "/host:/container".to_string(),
            "--runtime=runc".to_string(),
        ];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, Some(Network::UnsafeHost));
        assert_eq!(parsed.runtime, Some(Runtime::Runc));
    }

    #[test]
    fn test_parse_run_args_unknown_runtime() {
        let args = vec!["--runtime=unknown-runtime".to_string()];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, None);
        assert_eq!(parsed.runtime, None);
    }

    #[test]
    fn test_parse_run_args_non_host_network() {
        let args = vec!["--network=bridge".to_string()];
        let parsed = super::parse_run_args(&args);
        assert_eq!(parsed.network, None);
        assert_eq!(parsed.runtime, None);
    }

    #[test]
    fn test_toml_remote_unknown_field() {
        let toml_str = r#"
            remote = "user@host:22"
        "#;
        let result: Result<super::TomlConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_toml_host_option() {
        let toml_str = r#"
            host = "user@host:22"
        "#;
        let config: super::TomlConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.host, Some("user@host:22".to_string()));
    }

    #[test]
    fn test_toml_rejects_removed_fields() {
        // image, user, and repo-path were removed — they belong in devcontainer.json
        for field in [
            "image = \"alpine\"",
            "user = \"bob\"",
            "repo-path = \"/ws\"",
        ] {
            let result: Result<super::TomlConfig, _> = toml::from_str(field);
            assert!(result.is_err(), "should reject: {field}");
        }
    }
}

/// Network configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    /// Isolated network (default)
    #[default]
    Default,
    /// Host network - shares network namespace with host (unsafe)
    UnsafeHost,
}

use url::Url;

/// Parsed remote Docker host specification.
///
/// Parsed from a URL like `ssh://user@host:port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteDocker {
    /// The SSH destination (e.g. "user@host" or "host").
    pub destination: String,
    /// SSH port.
    pub port: u16,
}

impl RemoteDocker {
    /// Parse a remote specification string.
    ///
    /// Expects a valid SSH URL, e.g. `ssh://user@host:port`.
    /// Also accepts strings without scheme, assuming `ssh://`.
    pub fn parse(s: &str) -> Result<Self> {
        // If no scheme is present, assume ssh://
        let url_str = if !s.contains("://") {
            format!("ssh://{}", s)
        } else {
            s.to_string()
        };

        let url = Url::parse(&url_str).with_context(|| format!("Invalid URL: {}", s))?;

        if url.scheme() != "ssh" {
            bail!("URL scheme must be 'ssh'");
        }

        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("URL must have a host"))?;
        let port = url.port().unwrap_or(22);
        let username = url.username();

        let destination = if !username.is_empty() {
            format!("{}@{}", username, host)
        } else {
            host.to_string()
        };

        Ok(Self { destination, port })
    }
}

/// Raw configuration structure parsed from `.sandbox.toml`.
/// All fields are optional to allow merging with devcontainer.json.
///
/// Fields that have equivalents in devcontainer.json (image, user,
/// workspaceFolder) are intentionally omitted — they should be set in
/// devcontainer.json instead.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct TomlConfig {
    /// Container runtime (runsc, runc, sysbox-runc).
    runtime: Option<Runtime>,

    /// Network configuration.
    network: Option<Network>,

    #[serde(default)]
    agent: AgentConfig,

    /// Remote Docker host specification (e.g., "user@host:port").
    host: Option<String>,
}

/// Image build recipe from devcontainer.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageRecipe {
    pub dockerfile: String,
    pub context: String,
    pub args: Option<std::collections::HashMap<String, String>>,
    pub target: Option<String>,
    pub cache_from: Option<crate::devcontainer::StringOrArray>,
    pub options: Option<Vec<String>>,
}

/// Container runtime options from devcontainer.json (privileged, init, capAdd, etc.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerRuntimeOptions {
    /// Run container in privileged mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// Use tini as init process (PID 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Linux capabilities to add.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_add: Option<Vec<String>>,

    /// Security options (e.g. seccomp=unconfined).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_opt: Option<Vec<String>>,

    /// Device mappings parsed from runArgs --device flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<String>>,
}

/// Merged configuration from `devcontainer.json` and optional `.sandbox.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Container runtime (runsc, runc, sysbox-runc).
    pub runtime: Option<Runtime>,

    /// Network configuration.
    pub network: Network,

    /// Docker image to use.
    pub image: String,

    /// Image build recipe from devcontainer.json (used if image is not provided).
    pub pending_build: Option<ImageRecipe>,

    /// User to run as inside the sandbox container.
    /// If not specified, the image's USER directive is used.
    /// The image must have a non-root USER set, or this field must be explicitly provided.
    pub user: Option<String>,

    /// Path to the repo checkout inside the container.
    /// `sandbox enter` will use this as the working directory base.
    pub repo_path: PathBuf,

    /// Environment variables for the container.
    pub container_env: std::collections::HashMap<String, String>,

    /// Environment variables applied at exec time (e.g. `sandbox enter`), not
    /// baked into the container itself.  Supports `${localEnv:VAR}` (resolved
    /// eagerly) and `${containerEnv:VAR}` (resolved lazily at exec time).
    pub remote_env: std::collections::HashMap<String, String>,

    /// Additional mounts for the container.
    pub mounts: Vec<MountObject>,

    /// Container runtime options from devcontainer.json.
    #[serde(default)]
    pub runtime_options: ContainerRuntimeOptions,

    /// Ports to forward from container to local machine.
    pub forward_ports: Vec<Port>,

    /// Port-specific attributes (labels, protocol, etc.).
    pub ports_attributes: std::collections::HashMap<String, PortAttributes>,

    /// Agent configuration.
    pub agent: AgentConfig,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// If not set, uses local Docker.
    pub host: Option<String>,

    // Lifecycle commands from devcontainer.json
    pub on_create_command: Option<LifecycleCommand>,
    pub post_create_command: Option<LifecycleCommand>,
    pub post_start_command: Option<LifecycleCommand>,
    pub post_attach_command: Option<LifecycleCommand>,
    pub wait_for: Option<WaitFor>,
}

impl SandboxConfig {
    /// Load config from `devcontainer.json` and optional `.sandbox.toml`.
    ///
    /// Container settings (image, user, workspaceFolder, etc.) come
    /// exclusively from `devcontainer.json`.  Sandbox-specific settings
    /// (runtime, network, host, agent) come from `.sandbox.toml` when
    /// present.
    fn default_workspace_folder(repo_root: &Path) -> PathBuf {
        let basename = repo_root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "workspace".to_string());
        PathBuf::from(format!("/workspaces/{}", basename))
    }

    pub fn load(repo_root: &Path) -> Result<Self> {
        // Load devcontainer.json if present (lowest precedence)
        let devcontainer_info = DevContainer::find_and_load(repo_root)?;
        let (devcontainer, devcontainer_dir) = match devcontainer_info {
            Some((dc, dir)) => {
                dc.warn_unsupported_fields();
                (Some(dc), Some(dir))
            }
            None => (None, None),
        };

        // Load .sandbox.toml if present (highest precedence)
        let config_path = repo_root.join(".sandbox.toml");
        let toml_config = if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read {}", config_path.display()))?;
            toml::from_str(&contents)
                .with_context(|| format!("Failed to parse {}", config_path.display()))?
        } else {
            TomlConfig::default()
        };

        // Parse run_args from devcontainer.json for network, runtime, and devices
        let parsed_run_args = devcontainer
            .as_ref()
            .and_then(|dc| dc.run_args.as_ref())
            .map(|args| parse_run_args(args));
        let dc_network = parsed_run_args.as_ref().and_then(|p| p.network);
        let dc_runtime = parsed_run_args.as_ref().and_then(|p| p.runtime);
        let dc_devices = parsed_run_args
            .as_ref()
            .map(|p| p.devices.clone())
            .unwrap_or_default();

        // Image comes from devcontainer.json only
        let provided_image = devcontainer.as_ref().and_then(|dc| dc.image.clone());

        let pending_build = if provided_image.is_none() {
            if let Some(dc) = &devcontainer {
                let dockerfile_opt = dc
                    .dockerfile
                    .as_ref()
                    .or_else(|| dc.build.as_ref().and_then(|b| b.dockerfile.as_ref()));
                if let Some(dockerfile) = dockerfile_opt {
                    let context = dc
                        .build
                        .as_ref()
                        .and_then(|b| b.context.as_ref())
                        .cloned()
                        .unwrap_or_else(|| ".".to_string());

                    let (args, target, cache_from, options) = if let Some(build) = &dc.build {
                        (
                            build.args.clone(),
                            build.target.clone(),
                            build.cache_from.clone(),
                            build.options.clone(),
                        )
                    } else {
                        (None, None, None, None)
                    };

                    // Resolve paths relative to devcontainer.json directory
                    let dc_dir = devcontainer_dir
                        .as_ref()
                        .expect("devcontainer_dir must be set if devcontainer is set");
                    let resolved_dockerfile = dc_dir
                        .join(dockerfile)
                        .strip_prefix(repo_root)
                        .expect("dockerfile must be under repo_root")
                        .to_string_lossy()
                        .to_string();
                    let resolved_context = dc_dir
                        .join(&context)
                        .strip_prefix(repo_root)
                        .expect("context must be under repo_root")
                        .to_string_lossy()
                        .to_string();

                    Some(ImageRecipe {
                        dockerfile: resolved_dockerfile,
                        context: resolved_context,
                        args,
                        target,
                        cache_from,
                        options,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let repo_path = devcontainer
            .as_ref()
            .and_then(|dc| dc.workspace_folder.as_ref())
            .map(PathBuf::from)
            .unwrap_or_else(|| Self::default_workspace_folder(repo_root));

        let user = devcontainer
            .as_ref()
            .and_then(|dc| dc.user().map(String::from));

        let runtime = toml_config.runtime.or(dc_runtime);

        let network = toml_config.network.or(dc_network).unwrap_or_default();

        let container_env = devcontainer
            .as_ref()
            .and_then(|dc| dc.container_env.clone())
            .unwrap_or_default();

        // Eagerly resolve ${localEnv:VAR} in remote_env; leave
        // ${containerEnv:VAR} for lazy resolution at exec time.
        let remote_env: std::collections::HashMap<String, String> = devcontainer
            .as_ref()
            .and_then(|dc| dc.remote_env.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, resolve_local_env_vars(&v)))
            .collect();

        // Parse mounts from devcontainer.json
        let mounts =
            if let Some(dc_mounts) = devcontainer.as_ref().and_then(|dc| dc.mounts.as_ref()) {
                dc_mounts
                    .iter()
                    .map(|m| m.to_mount_object())
                    .collect::<Result<Vec<_>>>()
                    .context("parsing mounts from devcontainer.json")?
            } else {
                Vec::new()
            };

        // Reject unsubstituted variables in mounts — variable substitution
        // (e.g. ${devcontainerId}) is not yet implemented.
        for m in &mounts {
            let fields = [m.source.as_deref(), Some(m.target.as_str())];
            for field in fields.into_iter().flatten() {
                if field.contains("${") {
                    bail!(
                        "mounts variable substitution not implemented: found '{field}' in mount spec"
                    );
                }
            }
        }

        // Validate required fields
        let image = provided_image.unwrap_or_else(String::new);
        if pending_build.is_none() && image.is_empty() {
            anyhow::bail!(formatdoc! {"
                No image or build specified.
                Please set image or build.dockerfile in devcontainer.json.
            "});
        }

        // Validate agent model options
        let model_options_count = toml_config.agent.model.is_some() as usize
            + toml_config.agent.custom_anthropic_model.is_some() as usize
            + toml_config.agent.custom_gemini_model.is_some() as usize
            + toml_config.agent.custom_xai_model.is_some() as usize;

        if model_options_count > 1 {
            bail!("Configuration error: Only one of 'model', 'custom-anthropic-model', 'custom-gemini-model', or 'custom-xai-model' can be specified in [agent] section.");
        }

        // Build container runtime options from devcontainer.json fields
        let runtime_options = ContainerRuntimeOptions {
            privileged: devcontainer.as_ref().and_then(|dc| dc.privileged),
            init: devcontainer.as_ref().and_then(|dc| dc.init),
            cap_add: devcontainer.as_ref().and_then(|dc| dc.cap_add.clone()),
            security_opt: devcontainer.as_ref().and_then(|dc| dc.security_opt.clone()),
            devices: if dc_devices.is_empty() {
                None
            } else {
                Some(dc_devices)
            },
        };

        Ok(Self {
            runtime,
            network,
            image,
            pending_build,
            user,
            repo_path,
            container_env,
            remote_env,
            mounts,
            runtime_options,
            forward_ports: devcontainer
                .as_ref()
                .and_then(|dc| dc.forward_ports.clone())
                .unwrap_or_default(),
            ports_attributes: devcontainer
                .as_ref()
                .and_then(|dc| dc.ports_attributes.clone())
                .unwrap_or_default(),
            agent: toml_config.agent,
            host: toml_config.host,
            on_create_command: devcontainer
                .as_ref()
                .and_then(|dc| dc.on_create_command.clone()),
            post_create_command: devcontainer
                .as_ref()
                .and_then(|dc| dc.post_create_command.clone()),
            post_start_command: devcontainer
                .as_ref()
                .and_then(|dc| dc.post_start_command.clone()),
            post_attach_command: devcontainer
                .as_ref()
                .and_then(|dc| dc.post_attach_command.clone()),
            wait_for: devcontainer.as_ref().and_then(|dc| dc.wait_for.clone()),
        })
    }
}

/// Resolve all `${localEnv:VAR}` references in `value` using the host's
/// environment, leaving any other substitution patterns (e.g.
/// `${containerEnv:VAR}`) untouched.
pub fn resolve_local_env_vars(value: &str) -> String {
    let mut result = value.to_string();
    while let Some(start) = result.find("${localEnv:") {
        let after = start + "${localEnv:".len();
        if let Some(end) = result[after..].find('}') {
            let var_name = &result[after..after + end];
            let replacement = std::env::var(var_name).unwrap_or_default();
            result = format!(
                "{}{}{}",
                &result[..start],
                replacement,
                &result[after + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

/// Parsed results from devcontainer.json runArgs.
struct ParsedRunArgs {
    network: Option<Network>,
    runtime: Option<Runtime>,
    devices: Vec<String>,
}

/// Parse run_args to extract network, runtime, and device settings.
///
/// Looks for:
/// - `--network=host` or `--network host` -> Network::UnsafeHost
/// - `--runtime=<runtime>` or `--runtime <runtime>` -> appropriate Runtime
/// - `--device=<spec>` or `--device <spec>` -> device mappings
fn parse_run_args(args: &[String]) -> ParsedRunArgs {
    let mut network = None;
    let mut runtime = None;
    let mut devices = Vec::new();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        // Handle --network
        if let Some(value) = arg.strip_prefix("--network=") {
            if value == "host" {
                network = Some(Network::UnsafeHost);
            }
        } else if arg == "--network" {
            if let Some(value) = iter.next() {
                if value == "host" {
                    network = Some(Network::UnsafeHost);
                }
            }
        }

        // Handle --runtime
        if let Some(value) = arg.strip_prefix("--runtime=") {
            runtime = parse_runtime_value(value);
        } else if arg == "--runtime" {
            if let Some(value) = iter.next() {
                runtime = parse_runtime_value(value);
            }
        }

        // Handle --device
        if let Some(value) = arg.strip_prefix("--device=") {
            devices.push(value.to_string());
        } else if arg == "--device" {
            if let Some(value) = iter.next() {
                devices.push(value.to_string());
            }
        }
    }

    ParsedRunArgs {
        network,
        runtime,
        devices,
    }
}

/// Parse a runtime string value into a Runtime enum.
fn parse_runtime_value(value: &str) -> Option<Runtime> {
    match value {
        "runsc" => Some(Runtime::Runsc),
        "runc" => Some(Runtime::Runc),
        "sysbox-runc" => Some(Runtime::SysboxRunc),
        _ => None,
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

/// Get the state directory for sandbox data.
/// Uses $XDG_STATE_HOME/sandbox or ~/.local/state/sandbox as fallback.
pub fn get_state_dir() -> Result<PathBuf> {
    let state_base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".local/state")
        });

    Ok(state_base.join("sandbox"))
}

/// Get the runtime directory for sandbox sockets.
/// Uses $XDG_RUNTIME_DIR/sandbox or /tmp/sandbox-<uid> as fallback.
pub fn get_runtime_dir() -> Result<PathBuf> {
    let runtime_base = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Fallback to /tmp/sandbox-<uid>
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/sandbox-{}", uid))
        });

    Ok(runtime_base.join("sandbox"))
}

/// Check if deterministic test mode is enabled via SANDBOX_TEST_DETERMINISTIC_IDS.
///
/// Returns:
/// - `Ok(true)` if set to "1"
/// - `Ok(false)` if not set
/// - `Err(...)` if set to any other value
pub fn is_deterministic_test_mode() -> Result<bool> {
    match std::env::var("SANDBOX_TEST_DETERMINISTIC_IDS") {
        Ok(value) if value == "1" => Ok(true),
        Ok(value) => bail!(
            "SANDBOX_TEST_DETERMINISTIC_IDS must be '1' if set, got '{}'",
            value
        ),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(e).context("failed to read SANDBOX_TEST_DETERMINISTIC_IDS"),
    }
}
