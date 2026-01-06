//! xAI (Grok) agent implementation.

use anyhow::{Context, Result};
use std::io::{IsTerminal, Read, Write};
use std::str::FromStr;

use crate::chat_println;
use crate::config::Model;
use crate::llm::cache::LlmCache;
use crate::llm::client::xai::Client;
use crate::llm::types::xai::{
    ChatCompletionRequest, FinishReason, FunctionDefinition, Message, MessageContent, Role,
    SearchMode, SearchParameters, Tool, ToolChoice, ToolChoiceMode, ToolType,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_vim, read_agents_md, ToolName, MAX_TOKENS,
};

fn make_tool(name: ToolName) -> Tool {
    Tool {
        tool_type: ToolType::Function,
        function: FunctionDefinition {
            name: name.to_string(),
            description: name.description().to_string(),
            parameters: name.parameters(),
        },
    }
}

pub fn run_grok_agent(container_name: &str, model: Model, cache: Option<LlmCache>) -> Result<()> {
    let client = Client::new_with_cache(cache)?;

    let mut stdout = std::io::stdout();

    let mut messages: Vec<Message> = Vec::new();
    let mut chat_history = String::new();

    // Read AGENTS.md once at startup to include project-specific instructions
    let agents_md = read_agents_md(container_name);
    let system_prompt = build_system_prompt(agents_md.as_deref());

    // Add system message at the start
    messages.push(Message {
        role: Role::System,
        content: Some(MessageContent::Text(system_prompt)),
        tool_calls: None,
        tool_call_id: None,
    });

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

        messages.push(Message {
            role: Role::User,
            content: Some(MessageContent::Text(user_input)),
            tool_calls: None,
            tool_call_id: None,
        });

        loop {
            let request = ChatCompletionRequest {
                model: model.api_model_id().to_string(),
                messages: messages.clone(),
                max_tokens: Some(MAX_TOKENS),
                temperature: Some(0.0),
                top_p: None,
                tools: Some(vec![
                    make_tool(ToolName::Bash),
                    make_tool(ToolName::Edit),
                    make_tool(ToolName::Write),
                ]),
                tool_choice: Some(ToolChoice::Mode(ToolChoiceMode::Auto)),
                stream: Some(false),
                // Enable live search for web queries
                search_parameters: Some(SearchParameters {
                    mode: Some(SearchMode::Auto),
                    return_citations: Some(true),
                    ..Default::default()
                }),
            };

            let response = client.chat_completion(request)?;

            if response.choices.is_empty() {
                anyhow::bail!("No choices in response");
            }

            let choice = &response.choices[0];
            let assistant_message = &choice.message;

            // Handle text content if present
            if let Some(ref content) = assistant_message.content {
                if !content.is_empty() {
                    chat_println!(chat_history, "{}", content);
                }
            }

            // Check if there are tool calls
            let has_tool_calls = assistant_message
                .tool_calls
                .as_ref()
                .map(|tc| !tc.is_empty())
                .unwrap_or(false);

            if has_tool_calls {
                // Add assistant message with tool calls
                messages.push(Message {
                    role: Role::Assistant,
                    content: assistant_message.content.clone().map(MessageContent::Text),
                    tool_calls: assistant_message.tool_calls.clone(),
                    tool_call_id: None,
                });

                // Process each tool call
                for tool_call in assistant_message.tool_calls.as_ref().unwrap() {
                    let tool_name = ToolName::from_str(&tool_call.function.name);
                    let args: serde_json::Value =
                        serde_json::from_str(&tool_call.function.arguments)
                            .unwrap_or(serde_json::json!({}));

                    let (output, success) = match tool_name {
                        Ok(ToolName::Bash) => {
                            let command =
                                args.get("command").and_then(|v| v.as_str()).unwrap_or("");

                            chat_println!(chat_history, "$ {}", command);

                            let (output, success) =
                                execute_bash_in_sandbox(container_name, command)?;

                            if !output.is_empty() {
                                chat_println!(chat_history, "{}", output);
                            }

                            (output, success)
                        }
                        Ok(ToolName::Edit) => {
                            let file_path =
                                args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                            let old_string = args
                                .get("old_string")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let new_string = args
                                .get("new_string")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            let (output, success) = execute_edit_in_sandbox(
                                container_name,
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
                            let file_path =
                                args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                            let content =
                                args.get("content").and_then(|v| v.as_str()).unwrap_or("");

                            let (output, success) =
                                execute_write_in_sandbox(container_name, file_path, content)?;

                            if success {
                                chat_println!(chat_history, "[write] {}", file_path);
                            } else {
                                chat_println!(chat_history, "[write] {} (failed)", file_path);
                                chat_println!(chat_history, "{}", output);
                            }
                            (output, success)
                        }
                        Err(_) => {
                            let tool_name = &tool_call.function.name;
                            let error_msg = format!("Unknown tool: {tool_name}");
                            chat_println!(chat_history, "[error] {}", error_msg);
                            (error_msg, false)
                        }
                    };

                    // For xAI API, we don't have explicit error handling like Anthropic
                    // but we still provide the output (which may include error info)
                    let _ = success;

                    // Add tool result message
                    messages.push(Message {
                        role: Role::Tool,
                        content: Some(MessageContent::Text(output)),
                        tool_calls: None,
                        tool_call_id: Some(tool_call.id.clone()),
                    });
                }
            } else {
                // No tool calls - add the assistant message and exit inner loop
                messages.push(Message {
                    role: Role::Assistant,
                    content: assistant_message.content.clone().map(MessageContent::Text),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }

            // Check if we should continue (tool calls) or break
            if choice.finish_reason != Some(FinishReason::ToolCalls) {
                break;
            }
        }
    }

    Ok(())
}
