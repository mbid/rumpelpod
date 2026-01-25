//! xAI (Grok) agent implementation.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::llm::cache::LlmCache;
use crate::llm::client::xai::Client;
use crate::llm::types::xai::{
    ChatCompletionRequest, FinishReason, FunctionDefinition, Message, MessageContent, Model, Role,
    SearchMode, SearchParameters, Tool, ToolChoice, ToolChoiceMode, ToolType,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_editor, read_agents_md, ToolName, MAX_TOKENS,
};
use super::history::ConversationTracker;

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

/// Convert the internal messages to JSON for persistence.
#[allow(clippy::too_many_arguments)]
pub fn run_grok_agent(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    docker_socket: &Path,
    model: Model,
    cache: Option<LlmCache>,
    initial_history: Option<serde_json::Value>,
    mut tracker: ConversationTracker,
) -> Result<()> {
    let client = Client::new_with_cache(cache)?;

    let mut stdout = std::io::stdout();

    // Read AGENTS.md once at startup to include project-specific instructions
    let agents_md = read_agents_md(container_name, user, repo_path, docker_socket);
    let system_prompt = build_system_prompt(agents_md.as_deref());

    // Load initial history if resuming, otherwise start with system message
    let mut messages: Vec<Message> = match initial_history {
        Some(ref json) => serde_json::from_value(json.clone())
            .context("Failed to deserialize messages from JSON")?,
        None => Vec::new(),
    };

    // Add system message at the start if not resuming
    if messages.is_empty() {
        messages.push(Message {
            role: Role::System,
            content: Some(MessageContent::Text(system_prompt)),
            tool_calls: None,
            tool_call_id: None,
        });
    }

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
            let chat_history = format_xai_history(&messages);
            let input = get_input_via_editor(&chat_history)?;
            if input.is_empty() {
                if confirm_exit()? {
                    break;
                }
                continue;
            }
            input
        };

        println!("> {user_input}");
        stdout.flush()?;

        messages.push(Message {
            role: Role::User,
            content: Some(MessageContent::Text(user_input)),
            tool_calls: None,
            tool_call_id: None,
        });

        tracker.save(
            &serde_json::to_value(&messages).context("Failed to serialize messages to JSON")?,
        )?;

        loop {
            let request = ChatCompletionRequest {
                model: model.to_string(),
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
                    println!("{content}");
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

                            println!("$ {command}");

                            let (output, success) = execute_bash_in_sandbox(
                                container_name,
                                user,
                                repo_path,
                                docker_socket,
                                command,
                            )?;

                            if !output.is_empty() {
                                println!("{output}");
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
                                user,
                                repo_path,
                                docker_socket,
                                file_path,
                                old_string,
                                new_string,
                            )?;

                            if success {
                                println!("[edit] {file_path}");
                            } else {
                                println!("[edit] {file_path} (failed)");
                                println!("{output}");
                            }
                            (output, success)
                        }
                        Ok(ToolName::Write) => {
                            let file_path =
                                args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                            let content =
                                args.get("content").and_then(|v| v.as_str()).unwrap_or("");

                            let (output, success) = execute_write_in_sandbox(
                                container_name,
                                user,
                                repo_path,
                                docker_socket,
                                file_path,
                                content,
                            )?;

                            if success {
                                println!("[write] {file_path}");
                            } else {
                                println!("[write] {file_path} (failed)");
                                println!("{output}");
                            }
                            (output, success)
                        }
                        // WebSearch is Gemini-specific; xAI uses search_parameters
                        Ok(ToolName::WebSearch) => {
                            unreachable!("WebSearch tool is only used by Gemini agent")
                        }
                        Err(_) => {
                            let tool_name = &tool_call.function.name;
                            let error_msg = format!("Unknown tool: {tool_name}");
                            println!("[error] {error_msg}");
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

            // Save conversation after each assistant turn (including tool results)
            tracker.save(
                &serde_json::to_value(&messages).context("Failed to serialize messages to JSON")?,
            )?;

            // Check if we should continue (tool calls) or break
            if choice.finish_reason != Some(FinishReason::ToolCalls) {
                break;
            }
        }
    }

    Ok(())
}

/// Format xAI messages into human-readable chat history.
fn format_xai_history(messages: &[Message]) -> String {
    use crate::llm::types::xai::ContentPart;

    let mut output = String::new();

    for msg in messages {
        match msg.role {
            Role::System => {
                // Skip system messages - they're not part of chat history display
            }
            Role::User => {
                if let Some(ref content) = msg.content {
                    let text = match content {
                        MessageContent::Text(s) => s.as_str(),
                        MessageContent::Parts(parts) => {
                            // Take first text part if available
                            parts
                                .iter()
                                .find_map(|p| match p {
                                    ContentPart::Text { text } => Some(text.as_str()),
                                    // Images are not displayed in text history
                                    ContentPart::ImageUrl { .. } => None,
                                })
                                .unwrap_or("")
                        }
                    };
                    if !text.is_empty() {
                        output.push_str(&format!("> {text}\n"));
                    }
                }
            }
            Role::Assistant => {
                // Handle text content
                if let Some(ref content) = msg.content {
                    let text = match content {
                        MessageContent::Text(s) => s.as_str(),
                        MessageContent::Parts(parts) => parts
                            .iter()
                            .find_map(|p| match p {
                                ContentPart::Text { text } => Some(text.as_str()),
                                // Images are not displayed in text history
                                ContentPart::ImageUrl { .. } => None,
                            })
                            .unwrap_or(""),
                    };
                    if !text.is_empty() {
                        output.push_str(&format!("{text}\n"));
                    }
                }

                // Handle tool calls
                if let Some(ref tool_calls) = msg.tool_calls {
                    for tc in tool_calls {
                        let args: serde_json::Value =
                            serde_json::from_str(&tc.function.arguments).unwrap_or_default();
                        match tc.function.name.as_str() {
                            "bash" => {
                                if let Some(cmd) = args.get("command").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("$ {cmd}\n"));
                                }
                            }
                            "edit" => {
                                if let Some(path) = args.get("file_path").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("[edit] {path}\n"));
                                }
                            }
                            "write" => {
                                if let Some(path) = args.get("file_path").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("[write] {path}\n"));
                                }
                            }
                            // Unknown tools are ignored in history display
                            _ => {}
                        }
                    }
                }
            }
            Role::Tool => {
                // Tool results are shown inline after commands
                if let Some(ref content) = msg.content {
                    let text = match content {
                        MessageContent::Text(s) => s.as_str(),
                        MessageContent::Parts(parts) => parts
                            .iter()
                            .find_map(|p| match p {
                                ContentPart::Text { text } => Some(text.as_str()),
                                // Images are not displayed in text history
                                ContentPart::ImageUrl { .. } => None,
                            })
                            .unwrap_or(""),
                    };
                    if !text.is_empty() {
                        output.push_str(&format!("{text}\n"));
                    }
                }
            }
        }
    }

    output
}
