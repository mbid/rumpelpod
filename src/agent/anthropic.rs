//! Anthropic (Claude) agent implementation.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::chat_println;
use crate::config::Model;
use crate::llm::cache::LlmCache;
use crate::llm::client::anthropic::Client;
use crate::llm::types::anthropic::{
    CacheControl, ContentBlock, CustomTool, FetchToolType, Message, MessagesRequest, Role,
    ServerTool, StopReason, SystemBlock, SystemPrompt, Tool, WebSearchToolType,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_vim, model_api_id, read_agents_md, ToolName,
    MAX_TOKENS,
};

fn make_tool(name: ToolName) -> Tool {
    Tool::Custom(CustomTool {
        name: name.to_string(),
        description: name.description().to_string(),
        input_schema: name.parameters(),
        cache_control: None,
    })
}

fn websearch_tool() -> Tool {
    Tool::Server(ServerTool::WebSearch {
        tool_type: WebSearchToolType::WebSearch20250305,
        max_uses: None,
        allowed_domains: None,
        blocked_domains: None,
        user_location: None,
    })
}

fn fetch_tool() -> Tool {
    Tool::Server(ServerTool::WebFetch {
        tool_type: FetchToolType::WebFetch20250910,
        max_uses: None,
        allowed_domains: None,
        blocked_domains: None,
    })
}

/// The Anthropic API can return empty text blocks but rejects them on input.
/// See: https://github.com/anthropics/anthropic-sdk-python/issues/461
/// Returns None if the message would be empty after filtering.
fn filter_invalid_content(Message { role, content }: Message) -> Option<Message> {
    let content: Vec<ContentBlock> = content
        .into_iter()
        .filter(|block| match block {
            ContentBlock::Text { text, .. } => !text.trim().is_empty(),
            _ => true,
        })
        .collect();

    if content.is_empty() {
        None
    } else {
        Some(Message { role, content })
    }
}

pub fn run_claude_agent(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    model: Model,
    cache: Option<LlmCache>,
) -> Result<()> {
    let client = Client::new_with_cache(cache)?;

    let mut stdout = std::io::stdout();

    let mut messages: Vec<Message> = Vec::new();
    let mut chat_history = String::new();

    // Read AGENTS.md once at startup to include project-specific instructions
    let agents_md = read_agents_md(container_name, user, repo_path);
    let system_prompt = build_system_prompt(agents_md.as_deref());

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

    loop {
        let user_input = if let Some(ref prompt) = initial_prompt {
            if !messages.is_empty() {
                break;
            }
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
            content: vec![ContentBlock::Text {
                text: user_input,
                cache_control: None,
            }],
        });

        loop {
            // Cache conversation history by marking the last content block.
            // Single breakpoint at the end is optimal for non-rewinding multi-turn agents.
            let mut request_messages = messages.clone();
            if let Some(last_msg) = request_messages.last_mut() {
                if last_msg.role == Role::User {
                    if let Some(last_content) = last_msg.content.last_mut() {
                        match last_content {
                            ContentBlock::Text { cache_control, .. } => {
                                *cache_control = Some(CacheControl::default());
                            }
                            ContentBlock::ToolResult { cache_control, .. } => {
                                *cache_control = Some(CacheControl::default());
                            }
                            _ => {}
                        }
                    }
                }
            }

            let request = MessagesRequest {
                model: model_api_id(model).to_string(),
                max_tokens: MAX_TOKENS,
                system: Some(SystemPrompt::Blocks(vec![SystemBlock::Text {
                    text: system_prompt.clone(),
                    cache_control: Some(CacheControl::default()),
                }])),
                messages: request_messages,
                tools: Some(vec![
                    make_tool(ToolName::Bash),
                    make_tool(ToolName::Edit),
                    make_tool(ToolName::Write),
                    websearch_tool(),
                    fetch_tool(),
                ]),
                temperature: None,
                top_p: None,
                top_k: None,
            };

            let response = client.messages(request)?;

            let mut has_tool_use = false;
            let mut tool_results: Vec<ContentBlock> = Vec::new();

            for block in &response.content {
                match block {
                    ContentBlock::Text { text, .. } => {
                        chat_println!(chat_history, "{}", text);
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        has_tool_use = true;
                        let tool_name = ToolName::from_str(name)
                            .map_err(|_| anyhow::anyhow!("Unknown tool: {}", name))?;

                        let (output, success) = match tool_name {
                            ToolName::Bash => {
                                let command =
                                    input.get("command").and_then(|v| v.as_str()).unwrap_or("");

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
                            ToolName::Edit => {
                                let file_path = input
                                    .get("file_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let old_string = input
                                    .get("old_string")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let new_string = input
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
                            ToolName::Write => {
                                let file_path = input
                                    .get("file_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let content =
                                    input.get("content").and_then(|v| v.as_str()).unwrap_or("");

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
                        };

                        // Anthropic API requires non-empty content when is_error is true.
                        // Tool implementations must ensure this - panic if violated.
                        assert!(
                            success || !output.is_empty(),
                            "Tool error with empty output - tool implementation must provide error message"
                        );

                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: output,
                            is_error: if success { None } else { Some(true) },
                            cache_control: None,
                        });
                    }
                    ContentBlock::ToolResult { .. } => {}
                    ContentBlock::Image { .. } => {}
                    // Server-side tools (web_search, web_fetch) are handled by the API
                    ContentBlock::ServerToolUse { name, input, .. } => {
                        if name == "web_search" {
                            let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
                            chat_println!(chat_history, "[search] {}", query);
                        } else if name == "web_fetch" {
                            let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("");
                            chat_println!(chat_history, "[fetch] {}", url);
                        }
                    }
                    ContentBlock::WebSearchToolResult { .. } => {}
                    ContentBlock::WebFetchToolResult { content, .. } => {
                        use crate::llm::types::anthropic::WebFetchResult;
                        match content {
                            WebFetchResult::WebFetchToolError { error_code }
                            | WebFetchResult::WebFetchToolResultError { error_code } => {
                                chat_println!(chat_history, "[fetch] (failed: {})", error_code);
                            }
                            WebFetchResult::WebFetchResult { .. } => {}
                        }
                    }
                    ContentBlock::WebFetchToolResultError { error_code, .. } => {
                        chat_println!(chat_history, "[fetch] (failed: {})", error_code);
                    }
                }
            }

            // Filter out invalid content blocks (e.g., empty text blocks) that the API
            // returns but then rejects on subsequent requests.
            let assistant_message = Message {
                role: Role::Assistant,
                content: response.content.clone(),
            };
            if let Some(filtered) = filter_invalid_content(assistant_message) {
                messages.push(filtered);
            }

            if has_tool_use && !tool_results.is_empty() {
                messages.push(Message {
                    role: Role::User,
                    content: tool_results,
                });
            }

            if response.stop_reason != StopReason::ToolUse {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_removes_empty_text_blocks() {
        let message = Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "".to_string(),
                    cache_control: None,
                },
                ContentBlock::ToolUse {
                    id: "test".to_string(),
                    name: "bash".to_string(),
                    input: serde_json::json!({"command": "ls"}),
                },
            ],
        };

        let filtered = filter_invalid_content(message).unwrap();
        assert_eq!(filtered.content.len(), 1);
        assert!(matches!(filtered.content[0], ContentBlock::ToolUse { .. }));
    }

    #[test]
    fn test_filter_returns_none_if_all_blocks_invalid() {
        let message = Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "".to_string(),
                cache_control: None,
            }],
        };

        assert!(filter_invalid_content(message).is_none());
    }

    #[test]
    fn test_filter_preserves_valid_text_blocks() {
        let message = Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "".to_string(),
                    cache_control: None,
                },
                ContentBlock::Text {
                    text: "valid text".to_string(),
                    cache_control: None,
                },
            ],
        };

        let filtered = filter_invalid_content(message).unwrap();
        assert_eq!(filtered.content.len(), 1);
        if let ContentBlock::Text { text, .. } = &filtered.content[0] {
            assert_eq!(text, "valid text");
        } else {
            panic!("Expected Text block");
        }
    }
}
