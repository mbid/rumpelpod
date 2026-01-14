//! Configuration types and `.sandbox.toml` parser.
//!
//! This module provides:
//! - Runtime and Model enums for CLI and config file parsing
//! - SandboxConfig for parsing `.sandbox.toml` at the repository root
//! - Utility functions for state directory paths

use crate::llm::types::{anthropic, gemini, xai};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Model {
    Anthropic(anthropic::Model),
    Gemini(gemini::Model),
    Xai(xai::Model),
}

impl Default for Model {
    fn default() -> Self {
        Model::Anthropic(anthropic::Model::Opus)
    }
}

impl std::fmt::Display for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Model::Anthropic(m) => std::fmt::Display::fmt(m, f),
            Model::Gemini(m) => std::fmt::Display::fmt(m, f),
            Model::Xai(m) => std::fmt::Display::fmt(m, f),
        }
    }
}

impl ValueEnum for Model {
    fn value_variants<'a>() -> &'a [Self] {
        static VARIANTS: std::sync::OnceLock<Vec<Model>> = std::sync::OnceLock::new();
        VARIANTS.get_or_init(|| {
            let mut v = Vec::new();
            for m in anthropic::Model::value_variants() {
                v.push(Model::Anthropic(*m));
            }
            for m in gemini::Model::value_variants() {
                v.push(Model::Gemini(*m));
            }
            for m in xai::Model::value_variants() {
                v.push(Model::Xai(*m));
            }
            v
        })
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Model::Anthropic(m) => m.to_possible_value(),
            Model::Gemini(m) => m.to_possible_value(),
            Model::Xai(m) => m.to_possible_value(),
        }
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
        // 3. The string is used exactly as is for the API (implied by usage of to_string() in agent code).

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
