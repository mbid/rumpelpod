//! xAI (Grok) agent implementation using the new /v1/responses API.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use retry::delay::jitter;

use crate::daemon::protocol::LaunchResult;
use crate::llm::cache::LlmCache;
use crate::llm::client::xai::Client;
use crate::llm::error::LlmError;
use crate::llm::types::xai::{
    FunctionCall, Message, MessageContent, MessageContentPart, Model, ResponseInput,
    ResponseInputItem, ResponseOutputItem, ResponseRequest, Role, Tool, ToolCall, ToolCallType,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_editor, read_agents_md, ToolName,
};
use super::history::ConversationTracker;
use crate::enter::resolve_remote_env;

fn make_tool(name: ToolName) -> Tool {
    Tool::Function {
        name: name.to_string(),
        description: name.description().to_string(),
        parameters: name.parameters(),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AgentState {
    messages: Vec<Message>,
    response_id: Option<String>,
}

/// Convert the internal messages to JSON for persistence.
#[allow(clippy::too_many_arguments)]
pub fn run_grok_agent(
    sandbox_handle: JoinHandle<Result<LaunchResult>>,
    sandbox_name: &str,
    repo_path: &Path,
    remote_env: std::collections::HashMap<String, String>,
    model: Model,
    cache: Option<LlmCache>,
    initial_history: Option<serde_json::Value>,
    mut tracker: ConversationTracker,
) -> Result<()> {
    let client = Client::new_with_cache(cache)?;

    let mut stdout = std::io::stdout();

    // Load state
    let mut state: AgentState = match initial_history {
        Some(ref json) => {
            // Try to deserialize as AgentState (new format)
            if let Ok(s) = serde_json::from_value(json.clone()) {
                s
            } else {
                // Try to deserialize as Vec<Message> (legacy format)
                match serde_json::from_value::<Vec<Message>>(json.clone()) {
                    Ok(msgs) => AgentState {
                        messages: msgs,
                        response_id: None, // No session ID for legacy history
                    },
                    Err(_) => AgentState {
                        messages: Vec::new(),
                        response_id: None,
                    },
                }
            }
        }
        None => AgentState {
            messages: Vec::new(),
            response_id: None,
        },
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

    // When continuing a conversation in TTY mode, allow editing the last user message
    let mut editable_last_message: Option<String> = None;
    if is_tty && state.messages.len() > 1 {
        // Check if last message is a user message (skip the system message at index 0)
        if let Some(last_msg) = state.messages.last() {
            if last_msg.role == Role::User {
                // Extract the text from the last user message
                if let Some(MessageContent::Text(text)) = &last_msg.content {
                    if !text.is_empty() {
                        editable_last_message = Some(format!("> {}\n", text));
                    }
                }
                // Pop the last user message so it can be edited
                if editable_last_message.is_some() {
                    state.messages.pop();
                }
            }
        }
    }

    // Get the first user input immediately if interactive
    let mut pending_user_input: Option<String> = None;
    if is_tty {
        let chat_history = format_xai_history(&state.messages);
        loop {
            let input = get_input_via_editor(
                &chat_history,
                editable_last_message.as_deref(),
                sandbox_name,
            )?;
            if input.is_empty() {
                if confirm_exit()? {
                    return Ok(());
                }
                continue;
            }
            pending_user_input = Some(input);
            editable_last_message = None;
            break;
        }
    }

    // Now wait for sandbox
    let launch_result = sandbox_handle
        .join()
        .map_err(|e| anyhow::anyhow!("Sandbox thread panicked: {:?}", e))??;
    let container_name = &launch_result.container_id.0;
    let user = &launch_result.user;
    let docker_socket = &launch_result.docker_socket;

    // Resolve ${containerEnv:VAR} now that the container is running
    let remote_env = resolve_remote_env(&remote_env, docker_socket, container_name);

    // Read AGENTS.md once at startup to include project-specific instructions
    let agents_md = read_agents_md(container_name, user, repo_path, docker_socket);
    let system_prompt = build_system_prompt(agents_md.as_deref());

    // If we have legacy history without a response_id, we can't really "resume" the server-side session.
    // We'll have to start a new session. We can keep the local messages for context display,
    // but the model won't see them unless we replay them (which we skip for now as per "discard old endpoint").
    // We'll just append the system prompt to the next user message if we are effectively starting fresh (no response_id).

    // Add system message to local history if empty
    if state.messages.is_empty() {
        state.messages.push(Message {
            role: Role::System,
            content: Some(MessageContent::Text(system_prompt.clone())),
            tool_calls: None,
            tool_call_id: None,
        });
    }

    loop {
        // 1. Get User Input
        let user_input = if let Some(input) = pending_user_input.take() {
            input
        } else if let Some(ref prompt) = initial_prompt {
            if processed_initial {
                break;
            }
            processed_initial = true;
            prompt.clone()
        } else {
            let chat_history = format_xai_history(&state.messages);
            let editable = editable_last_message.take();
            let input = get_input_via_editor(&chat_history, editable.as_deref(), sandbox_name)?;
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

        state.messages.push(Message {
            role: Role::User,
            content: Some(MessageContent::Text(user_input.clone())),
            tool_calls: None,
            tool_call_id: None,
        });
        tracker.save(&serde_json::to_value(&state).context("Failed to serialize state")?)?;

        // 2. Prepare Request
        // If we have no response_id, it's a new session.
        // We prepend the system prompt to the user input for the first request.
        let (input_text, response_id) = if state.response_id.is_none() {
            // For the very first request, include system prompt
            // Note: We already added System message to state.messages for display.
            // Here we ensure the model gets it.
            (format!("{}\n\n{}", system_prompt, user_input), None)
        } else {
            (user_input, state.response_id.clone())
        };

        let mut current_input = ResponseInput::Prompt(input_text);
        let mut current_response_id = response_id;

        // 3. Loop for Assistant Turn (handle tool calls)
        loop {
            let request = ResponseRequest {
                model: model.to_string(),
                input: current_input,
                previous_response_id: current_response_id.clone(),
                tools: Some(vec![
                    make_tool(ToolName::Bash),
                    make_tool(ToolName::Edit),
                    make_tool(ToolName::Write),
                    Tool::WebSearch {
                        allowed_domains: None,
                        excluded_domains: None,
                    },
                ]),
                stream: Some(false),
                store: Some(true), // Ensure history is stored
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
                let err = match client.create_response(request.clone()) {
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

            // Update session ID
            state.response_id = Some(response.id.clone());
            current_response_id = Some(response.id.clone()); // For next loop iteration

            // Process Output items
            let items = response.output.unwrap_or_default();

            let mut tool_outputs = Vec::new();
            let mut assistant_text_parts = Vec::new();
            let mut assistant_tool_calls = Vec::new();

            for item in items {
                match item {
                    ResponseOutputItem::Text { text } => {
                        println!("{}", text);
                        assistant_text_parts.push(text);
                    }
                    ResponseOutputItem::FunctionCall {
                        call_id,
                        name,
                        arguments,
                    } => {
                        assistant_tool_calls.push(ToolCall {
                            id: call_id.clone(),
                            tool_type: ToolCallType::Function,
                            function: FunctionCall {
                                name: name.clone(),
                                arguments: arguments.clone(),
                            },
                        });

                        // Execute Tool
                        let tool_name = ToolName::from_str(&name);
                        let args: serde_json::Value =
                            serde_json::from_str(&arguments).unwrap_or(serde_json::json!({}));

                        let (output, success) = match tool_name {
                            Ok(ToolName::Bash) => {
                                let command =
                                    args.get("command").and_then(|v| v.as_str()).unwrap_or("");
                                println!("$ {command}");
                                let (out, ok) = execute_bash_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    docker_socket,
                                    &remote_env,
                                    command,
                                )?;
                                if !out.is_empty() {
                                    println!("{out}");
                                }
                                (out, ok)
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
                                let (out, ok) = execute_edit_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    docker_socket,
                                    &remote_env,
                                    file_path,
                                    old_string,
                                    new_string,
                                )?;
                                if ok {
                                    println!("[edit] {file_path}");
                                } else {
                                    println!("[edit] {file_path} (failed)");
                                    println!("{out}");
                                }
                                (out, ok)
                            }
                            Ok(ToolName::Write) => {
                                let file_path =
                                    args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
                                let content =
                                    args.get("content").and_then(|v| v.as_str()).unwrap_or("");
                                let (out, ok) = execute_write_in_sandbox(
                                    container_name,
                                    user,
                                    repo_path,
                                    docker_socket,
                                    &remote_env,
                                    file_path,
                                    content,
                                )?;
                                if ok {
                                    println!("[write] {file_path}");
                                } else {
                                    println!("[write] {file_path} (failed)");
                                    println!("{out}");
                                }
                                (out, ok)
                            }
                            Ok(ToolName::WebSearch) => {
                                unreachable!("WebSearch tool is not used locally")
                            }
                            Err(_) => {
                                let error_msg = format!("Unknown tool: {name}");
                                println!("[error] {error_msg}");
                                (error_msg, false)
                            }
                        };
                        let _ = success; // Not explicitly sending success bool to API, just output

                        tool_outputs
                            .push(ResponseInputItem::FunctionCallOutput { call_id, output });
                    }
                    ResponseOutputItem::Message { content, role: _ } => {
                        for part in content {
                            match part {
                                MessageContentPart::OutputText { text } => {
                                    println!("{}", text);
                                    assistant_text_parts.push(text);
                                }
                                MessageContentPart::Unknown => {
                                    // Skip unknown content parts (e.g., annotations)
                                }
                            }
                        }
                    }
                    ResponseOutputItem::WebSearchCall { .. } => {
                        // Server-side web search - results will be in the Message
                        println!("[web search]");
                    }
                    ResponseOutputItem::XSearchCall { .. } => {
                        anyhow::bail!("Unexpected X search call - X search is not enabled");
                    }
                    ResponseOutputItem::Reasoning { .. } | ResponseOutputItem::Unknown => {
                        // Skip reasoning and unknown types silently
                    }
                }
            }

            // Update local history
            if !assistant_text_parts.is_empty() || !assistant_tool_calls.is_empty() {
                state.messages.push(Message {
                    role: Role::Assistant,
                    content: if assistant_text_parts.is_empty() {
                        None
                    } else {
                        Some(MessageContent::Text(assistant_text_parts.join("\n")))
                    },
                    tool_calls: if assistant_tool_calls.is_empty() {
                        None
                    } else {
                        Some(assistant_tool_calls.clone())
                    },
                    tool_call_id: None,
                });
            }

            // If we executed tools, add their results to history and prepare next request
            if !tool_outputs.is_empty() {
                // Add tool results to local history
                for output_item in &tool_outputs {
                    match output_item {
                        ResponseInputItem::FunctionCallOutput { call_id, output } => {
                            state.messages.push(Message {
                                role: Role::Tool,
                                content: Some(MessageContent::Text(output.clone())),
                                tool_calls: None,
                                tool_call_id: Some(call_id.clone()),
                            });
                        }
                    }
                }

                // Save state before next request
                tracker
                    .save(&serde_json::to_value(&state).context("Failed to serialize state")?)?;

                // Prepare next input (tool outputs)
                current_input = ResponseInput::Items(tool_outputs);
                // Loop continues
            } else {
                // No tool calls, we are done with this turn
                tracker
                    .save(&serde_json::to_value(&state).context("Failed to serialize state")?)?;
                break;
            }
        }
    }

    Ok(())
}

/// Format xAI messages into human-readable chat history.
fn format_xai_history(messages: &[Message]) -> String {
    let mut output = String::new();

    for msg in messages {
        match msg.role {
            Role::System => {
                // Skip system messages
            }
            Role::User => {
                if let Some(MessageContent::Text(text)) = &msg.content {
                    if !text.is_empty() {
                        output.push_str(&format!("> {text}\n"));
                    }
                }
            }
            Role::Assistant => {
                if let Some(MessageContent::Text(text)) = &msg.content {
                    if !text.is_empty() {
                        output.push_str(&format!("{text}\n"));
                    }
                }
                if let Some(tool_calls) = &msg.tool_calls {
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
                            _ => {}
                        }
                    }
                }
            }
            Role::Tool => {
                if let Some(MessageContent::Text(text)) = &msg.content {
                    if !text.is_empty() {
                        output.push_str(&format!("{text}\n"));
                    }
                }
            }
        }
    }

    output
}
