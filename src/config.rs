//! Configuration types for sandbox settings.
//!
//! This module provides:
//! - Model enum for CLI and config file parsing
//! - AgentConfig / TomlConfig for `.sandbox.toml`
//! - Utility functions for state directory paths
//!
//! Container settings (image, user, workspace, mounts, runArgs, etc.) come from
//! `devcontainer.json`.  The optional `.sandbox.toml` provides sandbox-specific
//! settings that have no devcontainer equivalent (host, agent).

use anyhow::{bail, Context, Result};
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
        write!(f, "{}", s)
    }
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

/// Configuration from `.sandbox.toml`.
///
/// Fields that have equivalents in devcontainer.json (image, user,
/// workspaceFolder, runtime, network) are intentionally omitted — they
/// should be set in devcontainer.json instead (runtime and network via
/// `runArgs`).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TomlConfig {
    #[serde(default)]
    pub agent: AgentConfig,

    /// Remote Docker host specification (e.g., "user@host:port").
    pub host: Option<String>,
}

/// Load `.sandbox.toml` from the given repo root, if present.
pub fn load_toml_config(repo_root: &Path) -> Result<TomlConfig> {
    let config_path = repo_root.join(".sandbox.toml");
    if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read {}", config_path.display()))?;
        let config: TomlConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse {}", config_path.display()))?;

        // Validate agent model options
        let model_options_count = config.agent.model.is_some() as usize
            + config.agent.custom_anthropic_model.is_some() as usize
            + config.agent.custom_gemini_model.is_some() as usize
            + config.agent.custom_xai_model.is_some() as usize;
        if model_options_count > 1 {
            bail!("Configuration error: Only one of 'model', 'custom-anthropic-model', 'custom-gemini-model', or 'custom-xai-model' can be specified in [agent] section.");
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

/// Check if direct git config writes are enabled via SANDBOX_TEST_DIRECT_GIT_CONFIG.
///
/// When set, git config entries and remotes are written directly to `.git/config`
/// instead of invoking `git config` or `git remote add`. This avoids flaky lock
/// failures on overlay2 under heavy parallelism in tests.
///
/// Returns:
/// - `Ok(true)` if set to "1"
/// - `Ok(false)` if not set
/// - `Err(...)` if set to any other value
pub fn is_direct_git_config_mode() -> Result<bool> {
    match std::env::var("SANDBOX_TEST_DIRECT_GIT_CONFIG") {
        Ok(value) if value == "1" => Ok(true),
        Ok(value) => bail!(
            "SANDBOX_TEST_DIRECT_GIT_CONFIG must be '1' if set, got '{}'",
            value
        ),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(e).context("failed to read SANDBOX_TEST_DIRECT_GIT_CONFIG"),
    }
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
