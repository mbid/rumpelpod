//! Google Gemini agent implementation.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::config::Model;
use crate::llm::cache::LlmCache;
use crate::llm::client::gemini::Client;
use crate::llm::types::gemini::{
    Content, FinishReason, FunctionCallingConfig, FunctionCallingMode, FunctionDeclaration,
    GenerateContentRequest, GenerationConfig, Part, Role, SystemInstruction, Tool, ToolConfig,
};

use super::common::{
    build_system_prompt, confirm_exit, execute_bash_in_sandbox, execute_edit_in_sandbox,
    execute_write_in_sandbox, get_input_via_editor, model_api_id, read_agents_md, ToolName,
    MAX_TOKENS,
};
use super::history::ConversationTracker;

fn make_function_declaration(name: ToolName) -> FunctionDeclaration {
    // Gemini API doesn't support additionalProperties in function parameters
    let mut params = name.parameters();
    if let Some(obj) = params.as_object_mut() {
        obj.remove("additionalProperties");
    }
    FunctionDeclaration {
        name: name.to_string(),
        description: name.description().to_string(),
        parameters: params,
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

    // Build the tools list - function declarations only.
    // Multi-tool use (combining google_search with function_declarations) is only
    // supported by the Live API, not the generateContent API we use here.
    // See: https://ai.google.dev/gemini-api/docs/function-calling#multi-tool_use
    let tools = vec![Tool {
        function_declarations: Some(vec![
            make_function_declaration(ToolName::Bash),
            make_function_declaration(ToolName::Edit),
            make_function_declaration(ToolName::Write),
        ]),
        google_search: None,
    }];

    loop {
        let user_input = if let Some(ref prompt) = initial_prompt {
            if processed_initial {
                break;
            }
            processed_initial = true;
            prompt.clone()
        } else {
            let chat_history = format_gemini_history(&contents);
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

            // Log Google Search queries if grounding was used
            if let Some(ref grounding) = candidate.grounding_metadata {
                for query in &grounding.web_search_queries {
                    println!("[search] {query}");
                }
            }

            // Process the response parts
            let mut has_function_call = false;
            let mut function_responses: Vec<Part> = Vec::new();

            for part in &response_content.parts {
                match part {
                    Part::Text(text) => {
                        if !text.is_empty() {
                            println!("{text}");
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
                                    println!("[edit] {file_path}");
                                } else {
                                    println!("[edit] {file_path} (failed)");
                                    println!("{output}");
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
                                    println!("[write] {file_path}");
                                } else {
                                    println!("[write] {file_path} (failed)");
                                    println!("{output}");
                                }
                                (output, success)
                            }
                            Err(_) => {
                                let error_msg = format!("Unknown tool: {}", fc.name);
                                println!("[error] {error_msg}");
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
                    // Model responses don't contain inline data or function responses
                    Part::InlineData(_) | Part::FunctionResponse(_) => {}
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

/// Format Gemini contents into human-readable chat history.
fn format_gemini_history(contents: &[Content]) -> String {
    let mut output = String::new();

    for content in contents {
        match content.role {
            Role::User => {
                for part in &content.parts {
                    match part {
                        Part::Text(text) => {
                            // User text messages (but not function responses)
                            if !text.is_empty() {
                                output.push_str(&format!("> {text}\n"));
                            }
                        }
                        Part::FunctionResponse(fr) => {
                            // Function response - show result or error inline
                            if let Some(result) = fr.response.get("result").and_then(|v| v.as_str())
                            {
                                if !result.is_empty() {
                                    output.push_str(&format!("{result}\n"));
                                }
                            } else if let Some(error) =
                                fr.response.get("error").and_then(|v| v.as_str())
                            {
                                if !error.is_empty() {
                                    output.push_str(&format!("{error}\n"));
                                }
                            }
                        }
                        // User messages don't contain function calls or inline data
                        Part::InlineData(_) | Part::FunctionCall(_) => {}
                    }
                }
            }
            Role::Model => {
                for part in &content.parts {
                    match part {
                        Part::Text(text) => {
                            if !text.is_empty() {
                                output.push_str(&format!("{text}\n"));
                            }
                        }
                        Part::FunctionCall(fc) => match fc.name.as_str() {
                            "bash" => {
                                if let Some(cmd) = fc.args.get("command").and_then(|v| v.as_str()) {
                                    output.push_str(&format!("$ {cmd}\n"));
                                }
                            }
                            "edit" => {
                                if let Some(path) =
                                    fc.args.get("file_path").and_then(|v| v.as_str())
                                {
                                    output.push_str(&format!("[edit] {path}\n"));
                                }
                            }
                            "write" => {
                                if let Some(path) =
                                    fc.args.get("file_path").and_then(|v| v.as_str())
                                {
                                    output.push_str(&format!("[write] {path}\n"));
                                }
                            }
                            // Unknown tools are ignored in history display
                            _ => {}
                        },
                        // Model responses don't contain function responses or inline data
                        Part::InlineData(_) | Part::FunctionResponse(_) => {}
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
    use crate::llm::types::gemini::{FunctionCall, FunctionResponse};

    #[test]
    fn test_format_gemini_history_conversation() {
        let contents = vec![
            Content {
                role: Role::User,
                parts: vec![Part::Text("What time is it?".to_string())],
            },
            Content {
                role: Role::Model,
                parts: vec![Part::Text(
                    "I don't have access to the current time.".to_string(),
                )],
            },
        ];

        let result = format_gemini_history(&contents);
        assert_eq!(
            result,
            "> What time is it?\nI don't have access to the current time.\n"
        );
    }

    #[test]
    fn test_format_gemini_history_function_call() {
        let contents = vec![Content {
            role: Role::Model,
            parts: vec![Part::FunctionCall(FunctionCall {
                name: "edit".to_string(),
                args: serde_json::json!({"file_path": "src/main.rs"}),
            })],
        }];

        let result = format_gemini_history(&contents);
        assert_eq!(result, "[edit] src/main.rs\n");
    }

    #[test]
    fn test_format_gemini_history_function_response() {
        let contents = vec![Content {
            role: Role::User,
            parts: vec![Part::FunctionResponse(FunctionResponse {
                name: "bash".to_string(),
                response: serde_json::json!({"result": "file1.txt\nfile2.txt"}),
            })],
        }];

        let result = format_gemini_history(&contents);
        assert_eq!(result, "file1.txt\nfile2.txt\n");
    }

    #[test]
    fn test_format_gemini_history_empty() {
        assert_eq!(format_gemini_history(&[]), "");
    }
}
