//! Configuration types and `.sandbox.toml` parser.
//!
//! This module provides:
//! - Runtime and Model enums for CLI and config file parsing
//! - SandboxConfig for parsing `.sandbox.toml` at the repository root
//! - Utility functions for state directory paths
//!
//! Configuration is loaded with the following precedence (highest to lowest):
//! 1. `.sandbox.toml` in the repository root
//! 2. `devcontainer.json` (in `.devcontainer/` or root)

use crate::devcontainer::DevContainer;
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
    fn test_remote_docker_parse_invalid_url() {
        assert!(RemoteDocker::parse("not-a-url").is_err());
    }

    #[test]
    fn test_parse_run_args_network_equals() {
        let args = vec!["--network=host".to_string()];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, Some(Network::UnsafeHost));
        assert_eq!(runtime, None);
    }

    #[test]
    fn test_parse_run_args_network_separate() {
        let args = vec!["--network".to_string(), "host".to_string()];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, Some(Network::UnsafeHost));
        assert_eq!(runtime, None);
    }

    #[test]
    fn test_parse_run_args_runtime_equals() {
        let args = vec!["--runtime=sysbox-runc".to_string()];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, None);
        assert_eq!(runtime, Some(Runtime::SysboxRunc));
    }

    #[test]
    fn test_parse_run_args_runtime_separate() {
        let args = vec!["--runtime".to_string(), "runsc".to_string()];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, None);
        assert_eq!(runtime, Some(Runtime::Runsc));
    }

    #[test]
    fn test_parse_run_args_both() {
        let args = vec![
            "--network=host".to_string(),
            "--runtime=sysbox-runc".to_string(),
        ];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, Some(Network::UnsafeHost));
        assert_eq!(runtime, Some(Runtime::SysboxRunc));
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
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, Some(Network::UnsafeHost));
        assert_eq!(runtime, Some(Runtime::Runc));
    }

    #[test]
    fn test_parse_run_args_unknown_runtime() {
        let args = vec!["--runtime=unknown-runtime".to_string()];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, None);
        assert_eq!(runtime, None);
    }

    #[test]
    fn test_parse_run_args_non_host_network() {
        let args = vec!["--network=bridge".to_string()];
        let (network, runtime) = super::parse_run_args(&args);
        assert_eq!(network, None);
        assert_eq!(runtime, None);
    }

    #[test]
    fn test_toml_remote_unknown_field() {
        let toml_str = r#"
            image = "alpine"
            remote = "user@host:22"
        "#;
        let result: Result<super::TomlConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_toml_host_option() {
        let toml_str = r#"
            image = "alpine"
            host = "user@host:22"
        "#;
        let config: super::TomlConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.host, Some("user@host:22".to_string()));
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
    pub fn parse(s: &str) -> Result<Self> {
        let url = Url::parse(s).with_context(|| format!("Invalid URL: {}", s))?;

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
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct TomlConfig {
    /// Container runtime (runsc, runc, sysbox-runc).
    runtime: Option<Runtime>,

    /// Network configuration.
    network: Option<Network>,

    /// Docker image to use.
    image: Option<String>,

    /// User to run as inside the sandbox container.
    user: Option<String>,

    /// Path to the repo checkout inside the container.
    repo_path: Option<PathBuf>,

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

/// Merged configuration from `.sandbox.toml` and `devcontainer.json`.
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

    /// Agent configuration.
    pub agent: AgentConfig,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// If not set, uses local Docker.
    pub host: Option<String>,
}

impl SandboxConfig {
    /// Load config from `.sandbox.toml` and/or `devcontainer.json`.
    ///
    /// Precedence (highest to lowest):
    /// 1. `.sandbox.toml` values
    /// 2. `devcontainer.json` values (from `.devcontainer/` or root)
    ///
    /// At least one config source must provide `image` and `repo_path`.
    pub fn load(repo_root: &Path) -> Result<Self> {
        // Load devcontainer.json if present (lowest precedence)
        let devcontainer_info = DevContainer::find_and_load(repo_root)?;
        let (devcontainer, devcontainer_dir) = match devcontainer_info {
            Some((dc, dir)) => (Some(dc), Some(dir)),
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

        // Parse run_args from devcontainer.json for network and runtime
        let (dc_network, dc_runtime) = devcontainer
            .as_ref()
            .and_then(|dc| dc.run_args.as_ref())
            .map(|args| parse_run_args(args))
            .unwrap_or((None, None));

        // Merge with toml taking precedence
        let provided_image = toml_config
            .image
            .or_else(|| devcontainer.as_ref().and_then(|dc| dc.image.clone()));

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

        let repo_path = toml_config.repo_path.or_else(|| {
            devcontainer
                .as_ref()
                .and_then(|dc| dc.workspace_folder.as_ref())
                .map(PathBuf::from)
        });

        let user = toml_config.user.or_else(|| {
            devcontainer
                .as_ref()
                .and_then(|dc| dc.user().map(String::from))
        });

        let runtime = toml_config.runtime.or(dc_runtime);

        let network = toml_config.network.or(dc_network).unwrap_or_default();

        // Validate required fields
        let image = provided_image.unwrap_or_else(String::new);
        if pending_build.is_none() && image.is_empty() {
            anyhow::bail!(formatdoc! {"
                No image or build specified.
                Please set image in .sandbox.toml or build.dockerfile/dockerfile in devcontainer.json.
            "});
        }

        let repo_path = repo_path.ok_or_else(|| {
            anyhow::anyhow!(formatdoc! {"
                No repo path specified.
                Please set 'repo-path' in .sandbox.toml or 'workspaceFolder' in devcontainer.json.
            "})
        })?;

        // Validate agent model options
        let model_options_count = toml_config.agent.model.is_some() as usize
            + toml_config.agent.custom_anthropic_model.is_some() as usize
            + toml_config.agent.custom_gemini_model.is_some() as usize
            + toml_config.agent.custom_xai_model.is_some() as usize;

        if model_options_count > 1 {
            bail!("Configuration error: Only one of 'model', 'custom-anthropic-model', 'custom-gemini-model', or 'custom-xai-model' can be specified in [agent] section.");
        }

        Ok(Self {
            runtime,
            network,
            image,
            pending_build,
            user,
            repo_path,
            agent: toml_config.agent,
            host: toml_config.host,
        })
    }
}

/// Parse run_args to extract network and runtime settings.
///
/// Looks for:
/// - `--network=host` or `--network host` -> Network::UnsafeHost
/// - `--runtime=<runtime>` or `--runtime <runtime>` -> appropriate Runtime
fn parse_run_args(args: &[String]) -> (Option<Network>, Option<Runtime>) {
    let mut network = None;
    let mut runtime = None;
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
    }

    (network, runtime)
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
