//! Agent module for running AI assistants inside sandboxes.

mod anthropic;
pub mod common;
mod gemini;
pub mod history;
mod xai;

use anyhow::{Context, Result};

use crate::cli::AgentCommand;
use crate::config::{Model, SandboxConfig};
use crate::enter;
use crate::git::get_repo_root;
use crate::llm::cache::LlmCache;

use anthropic::run_claude_agent;
use common::{model_api_id, model_provider};
use gemini::run_gemini_agent;
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
            let (history, saved_model_name) = history::load_conversation(id)?;

            let current_provider = model_provider(model);
            // Parse the saved model name into a Model value to determine its provider
            let saved_model = serde_json::from_str::<Model>(&format!("\"{}\"", saved_model_name))
                .with_context(|| {
                    format!(
                        "Failed to parse model '{}' from conversation history. The database may be corrupt.\n\
                         Try deleting the sandbox with 'sandbox delete {}' to start fresh.",
                        saved_model_name, cmd.name
                    )
                })?;

            let saved_provider = model_provider(saved_model);
            if current_provider != saved_provider {
                anyhow::bail!(
                    "Cannot resume conversation started with {} ({}) using {} ({})",
                    saved_model_name,
                    saved_provider,
                    model,
                    current_provider
                );
            }

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
        .map(|path| LlmCache::new(path, &model_provider(model).to_string()))
        .transpose()?;

    // Run the agent loop
    let container_name = &launch_result.container_id.0;
    let user = &launch_result.user;
    let repo_path = &sandbox_config.repo_path;

    match model {
        Model::Anthropic(_) => run_claude_agent(
            container_name,
            user,
            repo_path,
            model,
            cache,
            sandbox_config.agent.anthropic_base_url,
            initial_history,
            tracker,
        ),
        Model::Xai(_) => run_grok_agent(
            container_name,
            user,
            repo_path,
            model,
            cache,
            initial_history,
            tracker,
        ),
        Model::Gemini(_) => run_gemini_agent(
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
