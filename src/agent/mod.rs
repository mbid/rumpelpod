//! Agent module for running AI assistants inside sandboxes.

mod anthropic;
pub mod common;
mod xai;

use anyhow::Result;

use crate::config::Model;
use crate::llm::cache::LlmCache;

pub use anthropic::run_claude_agent;
pub use xai::run_grok_agent;

/// Run an agent with the specified model.
/// Routes to the appropriate provider implementation based on the model.
pub fn run_agent(container_name: &str, model: Model, cache: Option<LlmCache>) -> Result<()> {
    match model {
        Model::Opus | Model::Sonnet | Model::Haiku => {
            run_claude_agent(container_name, model, cache)
        }
        Model::Grok3Mini | Model::Grok41Fast => run_grok_agent(container_name, model, cache),
    }
}
