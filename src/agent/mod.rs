//! Agent module for running AI assistants inside sandboxes.

mod anthropic;
pub mod common;
mod gemini;
pub mod history;
mod xai;

use anyhow::Result;

use crate::cli::AgentCommand;
use crate::config::{Model as ConfigModel, SandboxConfig};
use crate::enter;
use crate::git::get_repo_root;
use crate::llm::cache::LlmCache;
use crate::llm::types::{anthropic as anthropic_types, gemini as gemini_types, xai as xai_types};

use anthropic::run_claude_agent;
use common::{model_provider, Provider};
use gemini::run_gemini_agent;
use history::{resolve_conversation, ConversationChoice, ConversationTracker};
use xai::run_grok_agent;

enum EffectiveModel {
    Anthropic(anthropic_types::Model),
    Gemini(gemini_types::Model),
    Xai(xai_types::Model),
}

impl EffectiveModel {
    fn api_id(&self) -> String {
        match self {
            EffectiveModel::Anthropic(m) => m.to_string(),
            EffectiveModel::Gemini(m) => m.to_string(),
            EffectiveModel::Xai(m) => m.to_string(),
        }
    }

    fn provider(&self) -> Provider {
        match self {
            EffectiveModel::Anthropic(_) => Provider::Anthropic,
            EffectiveModel::Gemini(_) => Provider::Gemini,
            EffectiveModel::Xai(_) => Provider::Xai,
        }
    }
}

fn resolve_model(cmd: &AgentCommand, config: &SandboxConfig) -> EffectiveModel {
    // 1. CLI custom models
    if let Some(s) = &cmd.custom_anthropic_model {
        return EffectiveModel::Anthropic(anthropic_types::Model::Custom(s.clone()));
    }
    if let Some(s) = &cmd.custom_gemini_model {
        return EffectiveModel::Gemini(gemini_types::Model::Custom(s.clone()));
    }
    if let Some(s) = &cmd.custom_xai_model {
        return EffectiveModel::Xai(xai_types::Model::Custom(s.clone()));
    }

    // 2. CLI model (overrides config)
    if let Some(m) = cmd.model {
        return convert_config_model(m);
    }

    // 3. Config custom models
    if let Some(s) = &config.agent.custom_anthropic_model {
        return EffectiveModel::Anthropic(anthropic_types::Model::Custom(s.clone()));
    }
    if let Some(s) = &config.agent.custom_gemini_model {
        return EffectiveModel::Gemini(gemini_types::Model::Custom(s.clone()));
    }
    if let Some(s) = &config.agent.custom_xai_model {
        return EffectiveModel::Xai(xai_types::Model::Custom(s.clone()));
    }

    // 4. Config model
    if let Some(m) = config.agent.model {
        return convert_config_model(m);
    }

    // 5. Default
    convert_config_model(ConfigModel::default())
}

fn convert_config_model(m: ConfigModel) -> EffectiveModel {
    match m {
        ConfigModel::ClaudeOpus => EffectiveModel::Anthropic(anthropic_types::Model::Opus),
        ConfigModel::ClaudeSonnet => EffectiveModel::Anthropic(anthropic_types::Model::Sonnet),
        ConfigModel::ClaudeHaiku => EffectiveModel::Anthropic(anthropic_types::Model::Haiku),
        ConfigModel::Gemini25Flash => EffectiveModel::Gemini(gemini_types::Model::Gemini25Flash),
        ConfigModel::Gemini3Flash => EffectiveModel::Gemini(gemini_types::Model::Gemini3Flash),
        ConfigModel::Gemini3Pro => EffectiveModel::Gemini(gemini_types::Model::Gemini3Pro),
        ConfigModel::Grok3Mini => EffectiveModel::Xai(xai_types::Model::Grok3Mini),
        ConfigModel::Grok4 => EffectiveModel::Xai(xai_types::Model::Grok4),
        ConfigModel::Grok41Fast => EffectiveModel::Xai(xai_types::Model::Grok41Fast),
    }
}

/// Entry point for the `sandbox agent` CLI subcommand.
pub fn agent(cmd: &AgentCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let sandbox_config = SandboxConfig::load(&repo_root)?;

    // Determine the model to use
    let model = resolve_model(cmd, &sandbox_config);

    // Resolve which conversation to use (new or resume)
    let choice = resolve_conversation(&repo_root, &cmd.name, cmd.new, cmd.r#continue)?;

    let (initial_history, conversation_id) = match choice {
        ConversationChoice::New => (None, None),
        ConversationChoice::Resume(id) => {
            let (history, saved_model_name, saved_provider_str) = history::load_conversation(id)?;
            let current_provider = model.provider();

            // Check if providers match.
            // Note: Old databases might have empty provider strings.
            // If saved provider is empty, we fall back to the old heuristic (try to parse model name).
            // But since we are adding the column now, all new conversations will have provider.
            // For existing ones (if any, though this is a new feature), the migration adds the column.
            // Wait, we didn't add a migration step because rusqlite/sqlite handles adding columns gracefully?
            // Actually, init_db uses CREATE TABLE IF NOT EXISTS. If the table exists, it won't add the column!
            // The prompt said: "No need to preserve backwards compatiblity, no migrations etc needed."
            // So we assume it's fine if we just break old databases or rely on the user deleting them.
            // Or `init_db` could be updated to ALTER TABLE. But sticking to "no migrations needed" means
            // we probably assume fresh start or compatible enough.
            //
            // Ideally we check compatibility based on provider.
            let saved_provider = if saved_provider_str.is_empty() {
                // Try to guess from model name for backward compatibility/incomplete data
                if let Ok(saved_model) =
                    serde_json::from_str::<ConfigModel>(&format!("\"{}\"", saved_model_name))
                {
                    model_provider(saved_model)
                } else {
                    // Fallback for custom models without provider info -> assume Anthropic
                    Provider::Anthropic
                }
            } else {
                match saved_provider_str.as_str() {
                    "anthropic" => Provider::Anthropic,
                    "gemini" => Provider::Gemini,
                    "xai" => Provider::Xai,
                    _ => {
                        // Unknown provider string? fallback or error.
                        // Let's error safe.
                        anyhow::bail!(
                            "Unknown provider in conversation history: {}",
                            saved_provider_str
                        );
                    }
                }
            };

            if current_provider != saved_provider {
                anyhow::bail!(
                    "Cannot resume conversation started with {} ({}) using {} ({})",
                    saved_model_name,
                    saved_provider,
                    model.api_id(),
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
        model.api_id(),
        model.provider().to_string(),
        conversation_id,
    )?;

    // Launch the sandbox container
    let launch_result = enter::launch_sandbox(&cmd.name)?;

    // Set up LLM cache if specified
    // We need a provider string for the cache.
    let provider_str = match &model {
        EffectiveModel::Anthropic(_) => "anthropic",
        EffectiveModel::Gemini(_) => "gemini",
        EffectiveModel::Xai(_) => "xai",
    };

    let cache = cmd
        .cache
        .as_ref()
        .map(|path| LlmCache::new(path, provider_str))
        .transpose()?;

    // Run the agent loop
    let container_name = &launch_result.container_id.0;
    let user = &launch_result.user;
    let docker_socket = &launch_result.docker_socket;
    let repo_path = &sandbox_config.repo_path;
    let thinking_budget = cmd.thinking_budget.or(sandbox_config.agent.thinking_budget);

    match model {
        EffectiveModel::Anthropic(m) => {
            let enable_websearch = if cmd.disable_anthropic_websearch {
                false
            } else if cmd.enable_anthropic_websearch {
                true
            } else {
                sandbox_config.agent.anthropic_websearch.unwrap_or(true)
            };

            run_claude_agent(
                container_name,
                user,
                repo_path,
                docker_socket,
                m,
                thinking_budget,
                cache,
                sandbox_config.agent.anthropic_base_url,
                enable_websearch,
                initial_history,
                tracker,
            )
        }
        EffectiveModel::Xai(m) => run_grok_agent(
            container_name,
            user,
            repo_path,
            docker_socket,
            m,
            cache,
            initial_history,
            tracker,
        ),
        EffectiveModel::Gemini(m) => run_gemini_agent(
            container_name,
            user,
            repo_path,
            docker_socket,
            m,
            cache,
            initial_history,
            tracker,
        ),
    }
}
