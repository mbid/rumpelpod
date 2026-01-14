//! Anthropic (Claude) agent implementation.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::config::Model;
use crate::llm::cache::LlmCache;
use crate::llm::client::anthropic::Client;
use crate::llm::types::anthropic::{
    CacheControl, ContentBlock, CustomTool, FetchToolType, Message, MessagesRequest, Role,
    ServerTool, StopReason, SystemBlock, SystemPrompt, Tool, WebSearchToolType,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_editor, model_api_id, read_agents_md, ToolName,
    MAX_TOKENS,
};
use super::history::ConversationTracker;

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
            // Filter empty text blocks
            ContentBlock::Text { text, .. } => !text.trim().is_empty(),
            // Keep all other content block types
            ContentBlock::Image { .. }
            | ContentBlock::ToolUse { .. }
            | ContentBlock::ToolResult { .. }
            | ContentBlock::ServerToolUse { .. }
            | ContentBlock::WebSearchToolResult { .. }
            | ContentBlock::WebFetchToolResult { .. }
            | ContentBlock::WebFetchToolResultError { .. } => true,
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
    initial_history: Option<serde_json::Value>,
    mut tracker: ConversationTracker,
) -> Result<()> {
    let client = Client::new_with_cache(cache)?;

    let mut stdout = std::io::stdout();

    // Load initial history if resuming a conversation
    let mut messages: Vec<Message> = match initial_history {
        Some(ref json) => serde_json::from_value(json.clone())
            .context("Failed to deserialize messages from JSON")?,
        None => Vec::new(),
    };

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

    // Track whether we've processed the initial prompt (for non-TTY mode)
    let mut processed_initial = false;

    loop {
        let user_input = if let Some(ref prompt) = initial_prompt {
            if processed_initial {
                break;
            }
            processed_initial = true;
            prompt.clone()
        } else {
            let chat_history = format_anthropic_history(&messages);
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
                            ContentBlock::Text { cache_control, .. }
                            | ContentBlock::Image { cache_control, .. }
                            | ContentBlock::ToolResult { cache_control, .. } => {
                                *cache_control = Some(CacheControl::default());
                            }
                            // Tool use and server tool blocks don't support cache control
                            ContentBlock::ToolUse { .. }
                            | ContentBlock::ServerToolUse { .. }
                            | ContentBlock::WebSearchToolResult { .. }
                            | ContentBlock::WebFetchToolResult { .. }
                            | ContentBlock::WebFetchToolResultError { .. } => {}
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
                        println!("{text}");
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        has_tool_use = true;
                        let tool_name = ToolName::from_str(name)
                            .map_err(|_| anyhow::anyhow!("Unknown tool: {}", name))?;

                        let (output, success) = match tool_name {
                            ToolName::Bash => {
                                let command =
                                    input.get("command").and_then(|v| v.as_str()).unwrap_or("");

                                println!("$ {command}");

                                let (output, success) = execute_bash_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    command,
                                )?;

                                if !output.is_empty() {
                                    println!("{output}");
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
                                    println!("[edit] {file_path}");
                                } else {
                                    println!("[edit] {file_path} (failed)");
                                    println!("{output}");
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
                                    println!("[write] {file_path}");
                                } else {
                                    println!("[write] {file_path} (failed)");
                                    println!("{output}");
                                }
                                (output, success)
                            }
                            // WebSearch is Gemini-specific; Anthropic uses server-side web_search
                            ToolName::WebSearch => {
                                unreachable!("WebSearch tool is only used by Gemini agent")
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
                            println!("[search] {query}");
                        } else if name == "web_fetch" {
                            let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("");
                            println!("[fetch] {url}");
                        }
                    }
                    ContentBlock::WebSearchToolResult { .. } => {}
                    ContentBlock::WebFetchToolResult { content, .. } => {
                        use crate::llm::types::anthropic::WebFetchResult;
                        match content {
                            WebFetchResult::WebFetchToolError { error_code }
                            | WebFetchResult::WebFetchToolResultError { error_code } => {
                                println!("[fetch] (failed: {error_code})");
                            }
                            WebFetchResult::WebFetchResult { .. } => {}
                        }
                    }
                    ContentBlock::WebFetchToolResultError { error_code, .. } => {
                        println!("[fetch] (failed: {error_code})");
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

            // Save conversation after each assistant turn (including tool results)
            tracker.save(
                &serde_json::to_value(&messages).context("Failed to serialize messages to JSON")?,
            )?;

            if response.stop_reason != StopReason::ToolUse {
                break;
            }
        }
    }

    Ok(())
}

/// Format Anthropic messages into human-readable chat history.
fn format_anthropic_history(messages: &[Message]) -> String {
    let mut output = String::new();

    for msg in messages {
        match msg.role {
            Role::User => {
                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text, .. } => {
                            output.push_str(&format!("> {text}\n"));
                        }
                        ContentBlock::ToolResult { content, .. } => {
                            // Tool results are shown inline when tools are executed,
                            // no need to show again
                            if !content.is_empty() {
                                output.push_str(&format!("{content}\n"));
                            }
                        }
                        // Images are not displayed in chat history
                        ContentBlock::Image { .. }
                        | ContentBlock::ToolUse { .. }
                        | ContentBlock::ServerToolUse { .. }
                        | ContentBlock::WebSearchToolResult { .. }
                        | ContentBlock::WebFetchToolResult { .. }
                        | ContentBlock::WebFetchToolResultError { .. } => {}
                    }
                }
            }
            Role::Assistant => {
                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text, .. } => {
                            if !text.trim().is_empty() {
                                output.push_str(&format!("{text}\n"));
                            }
                        }
                        ContentBlock::ToolUse { name, input, .. } => {
                            if name == "bash" {
                                if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("$ {cmd}\n"));
                                }
                            } else if name == "edit" {
                                if let Some(path) = input.get("file_path").and_then(|v| v.as_str())
                                {
                                    output.push_str(&format!("[edit] {path}\n"));
                                }
                            } else if name == "write" {
                                if let Some(path) = input.get("file_path").and_then(|v| v.as_str())
                                {
                                    output.push_str(&format!("[write] {path}\n"));
                                }
                            }
                        }
                        ContentBlock::ServerToolUse { name, input, .. } => {
                            if name == "web_search" {
                                if let Some(query) = input.get("query").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("[search] {query}\n"));
                                }
                            } else if name == "web_fetch" {
                                if let Some(url) = input.get("url").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("[fetch] {url}\n"));
                                }
                            }
                        }
                        // Results from server tools are not displayed in chat history
                        ContentBlock::Image { .. }
                        | ContentBlock::ToolResult { .. }
                        | ContentBlock::WebSearchToolResult { .. }
                        | ContentBlock::WebFetchToolResult { .. }
                        | ContentBlock::WebFetchToolResultError { .. } => {}
                    }
                }
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_anthropic_history_user_message() {
        let messages = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Hello, how are you?".to_string(),
                cache_control: None,
            }],
        }];

        let result = format_anthropic_history(&messages);
        assert_eq!(result, "> Hello, how are you?\n");
    }

    #[test]
    fn test_format_anthropic_history_assistant_text() {
        let messages = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "I'm doing well!".to_string(),
                cache_control: None,
            }],
        }];

        let result = format_anthropic_history(&messages);
        assert_eq!(result, "I'm doing well!\n");
    }

    #[test]
    fn test_format_anthropic_history_tool_use() {
        let messages = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "test-123".to_string(),
                name: "bash".to_string(),
                input: serde_json::json!({"command": "ls -la"}),
            }],
        }];

        let result = format_anthropic_history(&messages);
        assert_eq!(result, "$ ls -la\n");
    }

    #[test]
    fn test_format_anthropic_history_empty() {
        assert_eq!(format_anthropic_history(&[]), "");
    }

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
