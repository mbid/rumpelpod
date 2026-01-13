//! Google Gemini agent implementation.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::chat_println;
use crate::config::Model;
use crate::llm::cache::LlmCache;
use crate::llm::client::gemini::Client;
use crate::llm::types::gemini::{
    Content, FinishReason, FunctionCallingConfig, FunctionCallingMode, FunctionDeclaration,
    GenerateContentRequest, GenerationConfig, Part, Role, SystemInstruction, Tool, ToolConfig,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_vim, model_api_id, read_agents_md, ToolName,
    MAX_TOKENS,
};
use super::history::ConversationTracker;

fn make_function_declaration(name: ToolName) -> FunctionDeclaration {
    FunctionDeclaration {
        name: name.to_string(),
        description: name.description().to_string(),
        parameters: name.parameters(),
    }
}

pub fn run_gemini_agent(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    model: Model,
    cache: Option<LlmCache>,
    initial_history: Option<serde_json::Value>,
    mut tracker: ConversationTracker,
) -> Result<()> {
    let client = Client::new_with_cache(cache)?;

    let mut stdout = std::io::stdout();

    let mut chat_history = String::new();

    // Read AGENTS.md once at startup to include project-specific instructions
    let agents_md = read_agents_md(container_name, user, repo_path);
    let system_prompt = build_system_prompt(agents_md.as_deref());

    // Load initial history if resuming, otherwise start fresh
    let mut contents: Vec<Content> = match initial_history {
        Some(ref json) => serde_json::from_value(json.clone())
            .context("Failed to deserialize contents from JSON")?,
        None => Vec::new(),
    };

    let is_tty = std::io::stdin().is_terminal();

    // Non-TTY mode reads entire stdin upfront and exits after one response
    let initial_prompt = if !is_tty {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("Failed to read stdin")?;
        Some(input.trim().to_string())
    } else {
        None
    };

    // Track if we've processed the initial prompt (for non-TTY mode)
    let mut processed_initial = false;

    // Build the tools list
    let tools = vec![Tool {
        function_declarations: vec![
            make_function_declaration(ToolName::Bash),
            make_function_declaration(ToolName::Edit),
            make_function_declaration(ToolName::Write),
        ],
    }];

    loop {
        let user_input = if let Some(ref prompt) = initial_prompt {
            if processed_initial {
                break;
            }
            processed_initial = true;
            prompt.clone()
        } else {
            let input = get_input_via_vim(&chat_history)?;
            if input.is_empty() {
                if confirm_exit()? {
                    break;
                }
                continue;
            }
            input
        };

        chat_println!(chat_history, "> {}", user_input);
        stdout.flush()?;

        contents.push(Content {
            role: Role::User,
            parts: vec![Part::text(user_input)],
        });

        loop {
            let request = GenerateContentRequest {
                contents: contents.clone(),
                tools: Some(tools.clone()),
                tool_config: Some(ToolConfig {
                    function_calling_config: FunctionCallingConfig {
                        mode: FunctionCallingMode::Auto,
                        allowed_function_names: None,
                    },
                }),
                system_instruction: Some(SystemInstruction {
                    parts: vec![Part::text(system_prompt.clone())],
                }),
                generation_config: Some(GenerationConfig {
                    temperature: Some(0.0),
                    max_output_tokens: Some(MAX_TOKENS),
                    ..Default::default()
                }),
            };

            let response = client.generate_content(model_api_id(model), request)?;

            if response.candidates.is_empty() {
                anyhow::bail!("No candidates in response");
            }

            let candidate = &response.candidates[0];
            let response_content = &candidate.content;

            // Process the response parts
            let mut has_function_call = false;
            let mut function_responses: Vec<Part> = Vec::new();

            for part in &response_content.parts {
                match part {
                    Part::Text(text) => {
                        if !text.is_empty() {
                            chat_println!(chat_history, "{}", text);
                        }
                    }
                    Part::FunctionCall(fc) => {
                        has_function_call = true;
                        let tool_name = ToolName::from_str(&fc.name);

                        let (output, success) = match tool_name {
                            Ok(ToolName::Bash) => {
                                let command = fc
                                    .args
                                    .get("command")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                chat_println!(chat_history, "$ {}", command);

                                let (output, success) = execute_bash_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    command,
                                )?;

                                if !output.is_empty() {
                                    chat_println!(chat_history, "{}", output);
                                }

                                (output, success)
                            }
                            Ok(ToolName::Edit) => {
                                let file_path = fc
                                    .args
                                    .get("file_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let old_string = fc
                                    .args
                                    .get("old_string")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let new_string = fc
                                    .args
                                    .get("new_string")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                let (output, success) = execute_edit_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    file_path,
                                    old_string,
                                    new_string,
                                )?;

                                if success {
                                    chat_println!(chat_history, "[edit] {}", file_path);
                                } else {
                                    chat_println!(chat_history, "[edit] {} (failed)", file_path);
                                    chat_println!(chat_history, "{}", output);
                                }
                                (output, success)
                            }
                            Ok(ToolName::Write) => {
                                let file_path = fc
                                    .args
                                    .get("file_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let content = fc
                                    .args
                                    .get("content")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                let (output, success) = execute_write_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    file_path,
                                    content,
                                )?;

                                if success {
                                    chat_println!(chat_history, "[write] {}", file_path);
                                } else {
                                    chat_println!(chat_history, "[write] {} (failed)", file_path);
                                    chat_println!(chat_history, "{}", output);
                                }
                                (output, success)
                            }
                            Err(_) => {
                                let error_msg = format!("Unknown tool: {}", fc.name);
                                chat_println!(chat_history, "[error] {}", error_msg);
                                (error_msg, false)
                            }
                        };

                        // Build the function response
                        let response_value = if success {
                            serde_json::json!({ "result": output })
                        } else {
                            serde_json::json!({ "error": output })
                        };

                        function_responses.push(Part::function_response(&fc.name, response_value));
                    }
                    _ => {}
                }
            }

            // Add the model's response to contents
            contents.push(Content {
                role: Role::Model,
                parts: response_content.parts.clone(),
            });

            // If there were function calls, add the function responses
            if has_function_call && !function_responses.is_empty() {
                contents.push(Content {
                    role: Role::User,
                    parts: function_responses,
                });
            }

            // Save conversation after each model turn (including function results)
            tracker.save(
                &serde_json::to_value(&contents).context("Failed to serialize contents to JSON")?,
            )?;

            // Check if we should continue (function calls mean we need another round)
            // Check finish reason - if it indicates function call, continue
            let should_continue = has_function_call
                && candidate.finish_reason != Some(FinishReason::Stop)
                && candidate.finish_reason != Some(FinishReason::MaxTokens);

            if !should_continue {
                break;
            }
        }
    }

    Ok(())
}
