//! Anthropic (Claude) agent implementation.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use retry::delay::jitter;

use crate::daemon::protocol::LaunchResult;
use crate::llm::cache::LlmCache;
use crate::llm::client::anthropic::Client;
use crate::llm::error::LlmError;
use crate::llm::types::anthropic::{
    CacheControl, ContentBlock, CustomTool, Effort, Message, MessagesRequest, Model, OutputConfig,
    Role, ServerTool, StopReason, SystemBlock, SystemPrompt, ThinkingConfig, Tool,
    WebSearchToolType,
};
use crate::pod::PodClient;

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_pod, execute_edit_in_pod,
    execute_write_in_pod, get_input_via_editor, read_agents_md, ToolName, MAX_TOKENS,
};
use super::history::ConversationTracker;
use crate::enter::{merge_env, resolve_remote_env};

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
            | ContentBlock::WebFetchToolResultError { .. }
            | ContentBlock::Thinking { .. }
            | ContentBlock::RedactedThinking { .. } => true,
        })
        .collect();

    if content.is_empty() {
        None
    } else {
        Some(Message { role, content })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_claude_agent(
    pod_handle: JoinHandle<Result<LaunchResult>>,
    pod_name: &str,
    repo_path: &Path,
    remote_env: std::collections::HashMap<String, String>,
    model: Model,
    thinking_budget: Option<u32>,
    cache: Option<LlmCache>,
    anthropic_base_url: Option<String>,
    enable_websearch: bool,
    initial_history: Option<serde_json::Value>,
    mut tracker: ConversationTracker,
) -> Result<()> {
    let client = Client::new_with_cache(cache, anthropic_base_url)?;

    let mut stdout = std::io::stdout();

    // Load initial history if resuming a conversation
    let mut messages: Vec<Message> = match initial_history {
        Some(ref json) => serde_json::from_value(json.clone())
            .context("Failed to deserialize messages from JSON")?,
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

    // Track whether we've processed the initial prompt (for non-TTY mode)
    let mut processed_initial = false;

    // When continuing a conversation in TTY mode, allow editing the last user message
    let mut editable_last_message: Option<String> = None;
    if is_tty && !messages.is_empty() {
        if let Some(last_msg) = messages.last() {
            if last_msg.role == Role::User {
                // Extract the text from the last user message
                for block in &last_msg.content {
                    if let ContentBlock::Text { text, .. } = block {
                        editable_last_message = Some(format!("{}\n", text));
                        break;
                    }
                }
                // Pop the last user message so it can be edited
                if editable_last_message.is_some() {
                    messages.pop();
                }
            }
        }
    }

    // Get the first user input immediately if interactive
    let mut pending_user_input: Option<String> = None;
    if is_tty {
        let chat_history = format_anthropic_history(&messages);
        // Loop to handle empty input + confirm exit
        loop {
            let input =
                get_input_via_editor(&chat_history, editable_last_message.as_deref(), pod_name)?;
            if input.is_empty() {
                if confirm_exit()? {
                    return Ok(());
                }
                continue;
            }
            pending_user_input = Some(input);
            // Clear editable message after first edit so it doesn't reappear
            editable_last_message = None;
            break;
        }
    }

    // Now wait for pod
    let launch_result = pod_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Pod thread panicked: {:?}", e))??;
    let container_name = &launch_result.container_id.0;
    let user = &launch_result.user;
    let docker_socket = &launch_result.docker_socket;
    let pod = PodClient::new(&launch_result.container_url, &launch_result.container_token)?;

    // Resolve ${containerEnv:VAR} now that the container is running
    let remote_env = resolve_remote_env(&remote_env, docker_socket, container_name);
    let remote_env = merge_env(launch_result.probed_env.clone(), remote_env);

    // Read AGENTS.md once at startup to include project-specific instructions
    let agents_md = read_agents_md(&pod, repo_path);
    let system_prompt = build_system_prompt(agents_md.as_deref());

    loop {
        let user_input = if let Some(input) = pending_user_input.take() {
            input
        } else if let Some(ref prompt) = initial_prompt {
            if processed_initial {
                break;
            }
            processed_initial = true;
            prompt.clone()
        } else {
            let chat_history = format_anthropic_history(&messages);
            let editable = editable_last_message.take();
            let input = get_input_via_editor(&chat_history, editable.as_deref(), pod_name)?;
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

        tracker.save(
            &serde_json::to_value(&messages).context("Failed to serialize messages to JSON")?,
        )?;

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
                            | ContentBlock::WebFetchToolResultError { .. }
                            | ContentBlock::Thinking { .. }
                            | ContentBlock::RedactedThinking { .. } => {}
                        }
                    }
                }
            }

            let mut tools = vec![
                make_tool(ToolName::Bash),
                make_tool(ToolName::Edit),
                make_tool(ToolName::Write),
            ];

            if enable_websearch {
                tools.push(websearch_tool());
            }

            let mut max_tokens = MAX_TOKENS;
            let mut thinking = None;
            let mut output_config = None;

            // Determine effective thinking budget
            // If explicit CLI flag/TOML option is set to 0, thinking is disabled.
            // Otherwise, use the provided value, or default to 32000 for Opus.
            let effective_budget = match thinking_budget {
                Some(0) => None,
                Some(b) => Some(b),
                None => {
                    if matches!(model, Model::Opus | Model::Opus46) {
                        // Claude Code uses ~32k tokens for reasoning.
                        // We adopt this default for Opus to match its capability profile.
                        Some(32_000)
                    } else {
                        None
                    }
                }
            };

            if let Some(budget) = effective_budget {
                thinking = Some(ThinkingConfig {
                    r#type: "enabled".to_string(),
                    budget_tokens: budget,
                });

                // Increase max_tokens to accommodate the large thinking budget + response
                // Opus 4.5 supports up to 64k output tokens.
                max_tokens = 64_000;

                // For Opus, we also set high effort when thinking is enabled
                if matches!(model, Model::Opus | Model::Opus46) {
                    output_config = Some(OutputConfig {
                        effort: Effort::High,
                    });
                }
            }

            let request = MessagesRequest {
                model: model.to_string(),
                max_tokens,
                system: Some(SystemPrompt::Blocks(vec![SystemBlock::Text {
                    text: system_prompt.clone(),
                    cache_control: Some(CacheControl::default()),
                }])),
                messages: request_messages,
                tools: Some(tools),
                thinking,
                output_config,
                temperature: None,
                top_p: None,
                top_k: None,
            };

            // Retry logic: up to 3 retries with 60s, 600s, 3600s delays with full jitter.
            let mut delays = [
                Duration::from_secs(60),
                Duration::from_secs(600),
                Duration::from_secs(3600),
            ]
            .into_iter()
            .map(jitter);

            let response = loop {
                let err = match client.messages(request.clone()) {
                    Ok(response) => break response,
                    Err(err) => err,
                };

                let delay = match &err {
                    LlmError::RateLimited { retry_after } => {
                        let delay = match delays.next() {
                            Some(delay) => delay,
                            None => {
                                return Err(err.into());
                            }
                        };
                        // This might look wrong: Why not max(delay, retry_after)? But with that
                        // formula we'd lose the jitter we apply to retry_after in case retry_after
                        // < delay.
                        delay + retry_after.unwrap_or(Duration::ZERO)
                    }
                    LlmError::RequestError(_) => match delays.next() {
                        Some(delay) => delay,
                        None => {
                            return Err(err.into());
                        }
                    },
                    LlmError::Other(_) => {
                        return Err(err.into());
                    }
                };

                eprintln!("{err}");
                eprintln!("Retrying in {delay} seconds", delay = delay.as_secs());
                thread::sleep(delay);
            };

            let mut has_tool_use = false;
            let mut tool_results: Vec<ContentBlock> = Vec::new();

            for block in &response.content {
                match block {
                    ContentBlock::Text { text, .. } => {
                        println!("{text}");
                    }
                    ContentBlock::Thinking { thinking, .. } => {
                        println!("<thinking>\n{}\n</thinking>", thinking);
                    }
                    ContentBlock::RedactedThinking { .. } => {
                        println!("<thinking>\n[redacted]\n</thinking>");
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

                                let (output, success) = execute_bash_in_pod(
                                    &pod,
                                    pod_name,
                                    user,
                                    repo_path,
                                    &remote_env,
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

                                let (output, success) = execute_edit_in_pod(
                                    &pod, repo_path, file_path, old_string, new_string,
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

                                let (output, success) =
                                    execute_write_in_pod(&pod, repo_path, file_path, content)?;

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
                        | ContentBlock::WebFetchToolResultError { .. }
                        | ContentBlock::Thinking { .. }
                        | ContentBlock::RedactedThinking { .. } => {}
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
                        ContentBlock::Thinking { thinking, .. } => {
                            output.push_str(&format!("<thinking>\n{}\n</thinking>\n", thinking));
                        }
                        ContentBlock::RedactedThinking { .. } => {
                            output.push_str("<thinking>\n[redacted]\n</thinking>\n");
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
