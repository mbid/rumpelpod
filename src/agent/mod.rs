//! Agent module for running AI assistants inside sandboxes.

mod anthropic;
pub mod common;
pub mod history;
mod xai;

use anyhow::Result;

use crate::cli::AgentCommand;
use crate::config::{Model, SandboxConfig};
use crate::enter;
use crate::git::get_repo_root;
use crate::llm::cache::LlmCache;

use anthropic::run_claude_agent;
use common::{model_api_id, model_provider};
use history::{resolve_conversation, ConversationChoice, ConversationTracker};
use xai::run_grok_agent;

/// Entry point for the `sandbox agent` CLI subcommand.
pub fn agent(cmd: &AgentCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let sandbox_config = SandboxConfig::load(&repo_root)?;

    // Determine the model to use (CLI flag takes precedence over config)
    let model = cmd.model.or(sandbox_config.agent.model).unwrap_or_default();

    // Resolve which conversation to use (new or resume)
    let choice = resolve_conversation(&repo_root, &cmd.name, cmd.new, cmd.r#continue)?;

    let (initial_history, conversation_id) = match choice {
        ConversationChoice::New => (None, None),
        ConversationChoice::Resume(id) => {
            let history = history::load_conversation(id)?;
            (Some(history), Some(id))
        }
    };

    // Create tracker for persisting the conversation
    let tracker = ConversationTracker::new(
        repo_root.clone(),
        cmd.name.clone(),
        model_api_id(model).to_string(),
        conversation_id,
    )?;

    // Launch the sandbox container
    let launch_result = enter::launch_sandbox(&cmd.name)?;

    // Set up LLM cache if specified
    let cache = cmd
        .cache
        .as_ref()
        .map(|path| LlmCache::new(path, model_provider(model)))
        .transpose()?;

    // Run the agent loop
    let container_name = &launch_result.container_id.0;
    let user = &launch_result.user;
    let repo_path = &sandbox_config.repo_path;

    match model {
        Model::Opus | Model::Sonnet | Model::Haiku => run_claude_agent(
            container_name,
            user,
            repo_path,
            model,
            cache,
            initial_history,
            tracker,
        ),
        Model::Grok3Mini | Model::Grok4 | Model::Grok41Fast => run_grok_agent(
            container_name,
            user,
            repo_path,
            model,
            cache,
            initial_history,
            tracker,
        ),
    }
}
