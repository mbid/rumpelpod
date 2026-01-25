//! Configuration types and `.sandbox.toml` parser.
//!
//! This module provides:
//! - Runtime and Model enums for CLI and config file parsing
//! - SandboxConfig for parsing `.sandbox.toml` at the repository root
//! - Utility functions for state directory paths

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
    fn test_remote_docker_parse_host_only() {
        let remote = RemoteDocker::parse("docker.example.com").unwrap();
        assert_eq!(remote.host, "docker.example.com");
        assert_eq!(remote.port, 22);
        // User depends on environment, just check it's not empty
        assert!(!remote.user.is_empty());
    }

    #[test]
    fn test_remote_docker_parse_user_and_host() {
        let remote = RemoteDocker::parse("deploy@docker.example.com").unwrap();
        assert_eq!(remote.host, "docker.example.com");
        assert_eq!(remote.user, "deploy");
        assert_eq!(remote.port, 22);
    }

    #[test]
    fn test_remote_docker_parse_host_and_port() {
        let remote = RemoteDocker::parse("docker.example.com:2222").unwrap();
        assert_eq!(remote.host, "docker.example.com");
        assert_eq!(remote.port, 2222);
    }

    #[test]
    fn test_remote_docker_parse_full() {
        let remote = RemoteDocker::parse("deploy@docker.example.com:2222").unwrap();
        assert_eq!(remote.host, "docker.example.com");
        assert_eq!(remote.user, "deploy");
        assert_eq!(remote.port, 2222);
    }

    #[test]
    fn test_remote_docker_parse_empty_host_fails() {
        assert!(RemoteDocker::parse("").is_err());
        assert!(RemoteDocker::parse("deploy@").is_err());
        assert!(RemoteDocker::parse("deploy@:22").is_err());
    }

    #[test]
    fn test_remote_docker_parse_invalid_port_fails() {
        assert!(RemoteDocker::parse("docker.example.com:notaport").is_err());
        assert!(RemoteDocker::parse("docker.example.com:99999").is_err());
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

/// Parsed remote Docker host specification.
///
/// Parsed from a string like `user@host:port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteDocker {
    /// SSH user for remote connection.
    pub user: String,
    /// Remote Docker host (hostname or IP).
    pub host: String,
    /// SSH port.
    pub port: u16,
}

impl RemoteDocker {
    /// Parse a remote specification string.
    ///
    /// Supported formats:
    /// - `host` - just hostname, default user and port
    /// - `user@host` - user and host, default port
    /// - `host:port` - host and port, default user
    /// - `user@host:port` - all three
    pub fn parse(s: &str) -> Result<Self> {
        let default_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        const DEFAULT_PORT: u16 = 22;

        // Check for user@ prefix
        let (user, rest) = if let Some(idx) = s.find('@') {
            (s[..idx].to_string(), &s[idx + 1..])
        } else {
            (default_user, s)
        };

        // Check for :port suffix
        let (host, port) = if let Some(idx) = rest.rfind(':') {
            let port_str = &rest[idx + 1..];
            let port = port_str
                .parse::<u16>()
                .with_context(|| format!("Invalid port number: {}", port_str))?;
            (rest[..idx].to_string(), port)
        } else {
            (rest.to_string(), DEFAULT_PORT)
        };

        if host.is_empty() {
            bail!("Remote host cannot be empty");
        }

        Ok(Self { user, host, port })
    }
}

/// Top-level configuration structure parsed from `.sandbox.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SandboxConfig {
    /// Container runtime (runsc, runc, sysbox-runc).
    #[serde(default)]
    pub runtime: Option<Runtime>,

    /// Network configuration.
    #[serde(default)]
    pub network: Network,

    pub image: String,

    /// User to run as inside the sandbox container.
    /// If not specified, the image's USER directive is used.
    /// The image must have a non-root USER set, or this field must be explicitly provided.
    #[serde(default)]
    pub user: Option<String>,

    /// Path to the repo checkout inside the container.
    /// `sandbox enter` will use this as the working directory base.
    pub repo_path: PathBuf,

    #[serde(default)]
    pub agent: AgentConfig,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// If not set, uses local Docker.
    #[serde(default)]
    pub remote: Option<String>,
}

impl SandboxConfig {
    /// Load config from the `.sandbox.toml` file in the given repo root.
    /// Returns an error if the file doesn't exist.
    pub fn load(repo_root: &Path) -> Result<Self> {
        let config_path = repo_root.join(".sandbox.toml");

        if !config_path.exists() {
            let path = config_path.display();
            bail!(formatdoc! {"
                No .sandbox.toml config file found at {path}.
                Please create a .sandbox.toml file to configure the sandbox.
            "});
        }

        let path = config_path.display();
        let contents = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read {path}"))?;

        let config: SandboxConfig =
            toml::from_str(&contents).with_context(|| format!("Failed to parse {path}"))?;

        // Validate that only one model option is set
        let model_options_count = config.agent.model.is_some() as usize
            + config.agent.custom_anthropic_model.is_some() as usize
            + config.agent.custom_gemini_model.is_some() as usize
            + config.agent.custom_xai_model.is_some() as usize;

        if model_options_count > 1 {
            bail!("Configuration error: Only one of 'model', 'custom-anthropic-model', 'custom-gemini-model', or 'custom-xai-model' can be specified in [agent] section.");
        }

        Ok(config)
    }
}

/// Agent configuration.
#[derive(Debug, Clone, Deserialize, Default)]
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
