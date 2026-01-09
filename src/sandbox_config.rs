//! Parser for the `.sandbox.toml` configuration file at the repository root.
//!
//! This file specifies sandbox settings: environment variables to pass through,
//! mount configurations, image build settings, and agent options.

use anyhow::{bail, Context, Result};
use indoc::formatdoc;
use serde::Deserialize;
use std::path::Path;

use crate::config::{Model, Runtime};

/// Top-level configuration structure parsed from `.sandbox.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Container runtime (runsc, runc, sysbox-runc).
    #[serde(default)]
    pub runtime: Option<Runtime>,

    #[serde(default)]
    pub image: Option<String>,

    #[serde(default)]
    pub agent: AgentConfig,
}

/// Agent configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Default model.
    pub model: Option<Model>,
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
