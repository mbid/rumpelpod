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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Model {
    // Claude models (Anthropic)
    /// Claude Opus 4.5 - most capable model
    #[default]
    #[value(name = "claude-opus-4-5")]
    Opus,
    /// Claude Sonnet 4.5 - balanced performance and cost
    #[value(name = "claude-sonnet-4-5")]
    Sonnet,
    /// Claude Haiku 4.5 - fast and cost-effective
    #[value(name = "claude-haiku-4-5")]
    Haiku,

    // Grok models (xAI)
    /// Grok 3 Mini - lightweight reasoning model, cost-effective
    #[value(name = "grok-3-mini")]
    Grok3Mini,
    /// Grok 4 - most capable reasoning model from xAI
    #[value(name = "grok-4")]
    Grok4,
    /// Grok 4.1 Fast - frontier model optimized for agentic tool calling
    #[value(name = "grok-4-1-fast")]
    Grok41Fast,

    // Gemini models (Google)
    /// Gemini 2.5 Flash - fast, stable, best price-performance
    #[value(name = "gemini-2.5-flash")]
    Gemini25Flash,
    /// Gemini 3 Flash - frontier model built for speed and scale
    #[value(name = "gemini-3-flash")]
    Gemini3Flash,
    /// Gemini 3 Pro - most intelligent frontier model
    #[value(name = "gemini-3-pro")]
    Gemini3Pro,
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
