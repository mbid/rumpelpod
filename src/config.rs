//! Configuration types and `.sandbox.toml` parser.
//!
//! This module provides:
//! - Runtime and Model enums for CLI and config file parsing
//! - SandboxConfig for parsing `.sandbox.toml` at the repository root
//! - Utility functions for state directory paths

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use indoc::formatdoc;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Container runtime to use for sandboxing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Deserialize)]
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

impl Runtime {
    /// Get the runtime name as used by Docker's --runtime flag.
    pub fn docker_runtime_name(&self) -> &'static str {
        match self {
            Runtime::Runsc => "runsc",
            Runtime::Runc => "runc",
            Runtime::SysboxRunc => "sysbox-runc",
        }
    }
}

/// Model to use for the agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Model {
    // Claude models (Anthropic)
    /// Claude Opus 4.5 - most capable model
    #[default]
    #[value(name = "opus")]
    Opus,
    /// Claude Sonnet 4.5 - balanced performance and cost
    #[value(name = "sonnet")]
    Sonnet,
    /// Claude Haiku 4.5 - fast and cost-effective
    #[value(name = "haiku")]
    Haiku,

    // Grok models (xAI)
    /// Grok 3 Mini - lightweight reasoning model, cost-effective
    #[value(name = "grok-3-mini")]
    Grok3Mini,
    /// Grok 4 - most capable reasoning model from xAI
    #[value(name = "grok-4")]
    Grok4,
    /// Grok 4.1 Fast - frontier model optimized for agentic tool calling
    #[value(name = "grok-4.1-fast")]
    Grok41Fast,
}

impl Model {
    /// Get the model identifier as used by the provider's API.
    pub fn api_model_id(&self) -> &'static str {
        match self {
            Model::Opus => "claude-opus-4-5-20251101",
            Model::Sonnet => "claude-sonnet-4-5-20250929",
            Model::Haiku => "claude-haiku-4-5-20251001",
            Model::Grok3Mini => "grok-3-mini",
            Model::Grok4 => "grok-4",
            Model::Grok41Fast => "grok-4-1-fast",
        }
    }
}

/// Top-level configuration structure parsed from `.sandbox.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Container runtime (runsc, runc, sysbox-runc).
    #[serde(default)]
    pub runtime: Option<Runtime>,

    #[serde(default)]
    pub image: Option<String>,

    /// User to run as inside the sandbox container.
    #[serde(default)]
    pub user: Option<String>,

    /// Path to the repo checkout inside the container.
    /// When set, `sandbox enter` will use this as the working directory base.
    #[serde(default, rename = "repo-path")]
    pub repo_path: Option<PathBuf>,

    #[serde(default)]
    pub agent: AgentConfig,
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

        Ok(config)
    }
}

/// Agent configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Default model.
    pub model: Option<Model>,
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
