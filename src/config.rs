use anyhow::Result;
use clap::ValueEnum;
use std::path::PathBuf;

/// Container runtime to use for sandboxing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, serde::Deserialize)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, serde::Deserialize)]
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
