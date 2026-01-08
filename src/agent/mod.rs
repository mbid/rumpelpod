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
///
/// The `uid` parameter specifies the user ID to run commands as inside the container.
/// This ensures secondary group membership is applied correctly.
pub fn run_agent(
    container_name: &str,
    uid: u32,
    model: Model,
    cache: Option<LlmCache>,
) -> Result<()> {
    match model {
        Model::Opus | Model::Sonnet | Model::Haiku => {
            run_claude_agent(container_name, uid, model, cache)
        }
        Model::Grok3Mini | Model::Grok4 | Model::Grok41Fast => {
            run_grok_agent(container_name, uid, model, cache)
        }
    }
}
