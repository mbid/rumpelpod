//! Common utilities shared between agent implementations.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use bollard::Docker;
use indoc::formatdoc;
use log::debug;
use sha2::{Digest, Sha256};
use strum::{Display, EnumString};

use crate::config::Model;
use crate::docker_exec::{exec_capture, exec_check, exec_command, exec_with_stdin};

pub const MAX_TOKENS: u32 = 4096;
pub const AGENTS_MD_PATH: &str = "AGENTS.md";

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum Provider {
    Anthropic,
    Gemini,
    Xai,
}

/// Get the provider for this model.
pub fn model_provider(model: Model) -> Provider {
    match model {
        Model::ClaudeOpus | Model::ClaudeSonnet | Model::ClaudeHaiku => Provider::Anthropic,
        Model::Gemini25Flash | Model::Gemini3Flash | Model::Gemini3Pro => Provider::Gemini,
        Model::Grok41Fast | Model::Grok41FastNonReasoning => Provider::Xai,
    }
}

/// Create a Docker connection for executing commands in containers.
fn docker_connect(docker_socket: &Path) -> Result<Docker> {
    Docker::connect_with_socket(
        docker_socket.to_string_lossy().as_ref(),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("connecting to Docker daemon")
}

pub const BASE_SYSTEM_PROMPT: &str = "You are a helpful assistant running inside a sandboxed environment. You can execute bash commands to help the user.";

// Tool names used by all agent implementations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ToolName {
    Bash,
    Edit,
    Write,
    /// Web search tool for Gemini (workaround for API limitation that prevents
    /// combining google_search with function_declarations in generateContent API)
    WebSearch,
}

impl ToolName {
    pub fn description(&self) -> &'static str {
        match self {
            ToolName::Bash => {
                "Execute a bash command inside the sandbox and return the output.\n\
                               The working directory is the project root."
            }
            ToolName::Edit => "Perform a search-and-replace edit on a file.",
            ToolName::Write => {
                "Write content to a new file. Returns an error if the file already exists."
            }
            ToolName::WebSearch => {
                "Search the web for information. Use this tool when you need to find \
                 current information or facts that may be beyond your knowledge cutoff. \
                 Provide a detailed query describing what information you need."
            }
        }
    }

    pub fn parameters(&self) -> serde_json::Value {
        match self {
            ToolName::Bash => serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute"
                    }
                },
                "required": ["command"]
            }),
            ToolName::Edit => serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The path to the file to modify (relative to repo root)"
                    },
                    "old_string": {
                        "type": "string",
                        "description": "The text to replace (must appear exactly once in the file)"
                    },
                    "new_string": {
                        "type": "string",
                        "description": "The replacement text"
                    }
                },
                "required": ["file_path", "old_string", "new_string"],
                "additionalProperties": false
            }),
            ToolName::Write => serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The path to the file to create (relative to repo root)"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write to the file"
                    }
                },
                "required": ["file_path", "content"],
                "additionalProperties": false
            }),
            ToolName::WebSearch => serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query to find information on the web"
                    }
                },
                "required": ["query"]
            }),
        }
    }
}

/// Read AGENTS.md from the sandbox if it exists.
pub fn read_agents_md(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    docker_socket: &Path,
) -> Option<String> {
    debug!("Reading {} from sandbox", AGENTS_MD_PATH);
    let docker = docker_connect(docker_socket).ok()?;
    let workdir = repo_path.to_string_lossy().to_string();

    let output = exec_command(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(vec!["GIT_EDITOR=false"]),
        vec!["cat", AGENTS_MD_PATH],
    )
    .ok()?;

    debug!("{} loaded successfully", AGENTS_MD_PATH);
    String::from_utf8(output).ok()
}

pub fn build_system_prompt(agents_md: Option<&str>) -> String {
    match agents_md {
        Some(content) => format!("{BASE_SYSTEM_PROMPT}\n\n{content}"),
        None => BASE_SYSTEM_PROMPT.to_string(),
    }
}

pub fn execute_edit_in_sandbox(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    docker_socket: &Path,
    file_path: &str,
    old_string: &str,
    new_string: &str,
) -> Result<(String, bool)> {
    let docker = docker_connect(docker_socket)?;
    let workdir = repo_path.to_string_lossy().to_string();
    let env = vec!["GIT_EDITOR=false"];

    debug!("Reading file for edit: {}", file_path);
    let output = match exec_command(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env.clone()),
        vec!["cat", file_path],
    ) {
        Ok(output) => output,
        Err(e) => return Ok((format!("Error reading file: {e}"), false)),
    };
    debug!("File read completed");

    let content = match String::from_utf8(output) {
        Ok(s) => s,
        Err(_) => return Ok(("File contains invalid UTF-8".to_string(), false)),
    };

    let count = content.matches(old_string).count();

    if count == 0 {
        return Ok((format!("old_string not found in {file_path}"), false));
    }

    if count > 1 {
        return Ok((
            format!(
                "Found {count} occurrences of old_string in {file_path}. \
                 Provide more context to make the match unique."
            ),
            false,
        ));
    }

    let new_content = content.replacen(old_string, new_string, 1);

    debug!("Writing edited file: {}", file_path);
    let escaped_path = file_path.replace('\'', "'\\''");
    let write_cmd = format!("cat > '{escaped_path}'");

    if let Err(e) = exec_with_stdin(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env),
        vec!["bash", "-c", &write_cmd],
        Some(new_content.as_bytes()),
    ) {
        return Ok((format!("Error writing file: {e}"), false));
    }
    debug!("Write completed");

    Ok((format!("Successfully edited {file_path}"), true))
}

pub fn execute_write_in_sandbox(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    docker_socket: &Path,
    file_path: &str,
    content: &str,
) -> Result<(String, bool)> {
    let docker = docker_connect(docker_socket)?;
    let workdir = repo_path.to_string_lossy().to_string();
    let env = vec!["GIT_EDITOR=false"];

    debug!("Checking if file exists: {}", file_path);
    let exists = exec_check(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        vec!["test", "-e", file_path],
    )
    .context("Failed to check if file exists")?;

    if exists {
        return Ok((format!("File {file_path} already exists"), false));
    }

    if let Some(parent) = std::path::Path::new(file_path).parent() {
        if !parent.as_os_str().is_empty() {
            let escaped_parent = parent.display().to_string().replace('\'', "'\\''");
            let mkdir_cmd = format!("mkdir -p '{escaped_parent}'");
            debug!("Creating parent directories for: {}", file_path);
            let _ = exec_command(
                &docker,
                container_name,
                Some(user),
                Some(&workdir),
                Some(env.clone()),
                vec!["bash", "-c", &mkdir_cmd],
            );
        }
    }

    debug!("Writing new file: {}", file_path);
    let escaped_path = file_path.replace('\'', "'\\''");
    let write_cmd = format!("cat > '{escaped_path}'");

    if let Err(e) = exec_with_stdin(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env),
        vec!["bash", "-c", &write_cmd],
        Some(content.as_bytes()),
    ) {
        return Ok((format!("Error writing file: {e}"), false));
    }
    debug!("Write completed");

    Ok((format!("Successfully wrote {file_path}"), true))
}

fn save_output_to_file(
    docker: &Docker,
    container_name: &str,
    user: &str,
    repo_path: &Path,
    data: &[u8],
) -> Result<String> {
    // Generate deterministic ID from content hash for reproducible cache keys
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let id = hex::encode(&hash[..6]);

    let output_file = format!("/tmp/agent/bash-output-{id}");
    debug!("Saving large output to file: {output_file}");

    let workdir = repo_path.to_string_lossy().to_string();
    let env = vec!["GIT_EDITOR=false"];

    // Create /tmp/agent directory if it doesn't exist
    debug!("Creating /tmp/agent directory");
    exec_command(
        docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env.clone()),
        vec!["bash", "-c", "mkdir -p /tmp/agent"],
    )
    .context("Failed to create /tmp/agent directory")?;

    // Write the output to file
    let len = data.len();
    debug!("Writing output data ({len} bytes)");
    let write_cmd = format!("cat > {output_file}");
    exec_with_stdin(
        docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env),
        vec!["bash", "-c", &write_cmd],
        Some(data),
    )
    .context("Failed to write output to file")?;
    debug!("Output saved to file");

    Ok(output_file)
}

pub fn execute_bash_in_sandbox(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    docker_socket: &Path,
    command: &str,
) -> Result<(String, bool)> {
    const MAX_OUTPUT_SIZE: usize = 30000;

    let docker = docker_connect(docker_socket)?;
    let workdir = repo_path.to_string_lossy().to_string();
    let env = vec!["GIT_EDITOR=false"];

    debug!("Executing bash in sandbox: {}", command);
    let output = exec_capture(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env),
        vec!["bash", "-c", command],
    )
    .context("Failed to execute command in sandbox")?;
    debug!(
        "Bash command completed with exit code: {}",
        output.exit_code
    );

    // Combine stdout and stderr as raw bytes
    let combined_bytes = if output.stderr.is_empty() {
        output.stdout.clone()
    } else if output.stdout.is_empty() {
        output.stderr.clone()
    } else {
        let mut combined = output.stdout.clone();
        combined.push(b'\n');
        combined.extend_from_slice(&output.stderr);
        combined
    };

    // Check if output exceeds limit - save to file if so
    if combined_bytes.len() > MAX_OUTPUT_SIZE {
        let output_file =
            save_output_to_file(&docker, container_name, user, repo_path, &combined_bytes)?;
        let len = combined_bytes.len();
        return Ok((
            formatdoc! {r#"
                Output is too large ({len} bytes). Full output available at {output_file}.
                Use `tail -n 100 {output_file}` to see the end of the output, or `grep` to search.
            "#},
            false,
        ));
    }

    // Validate UTF-8 - save to file if invalid
    let combined = match String::from_utf8(combined_bytes.clone()) {
        Ok(s) => s,
        Err(_) => {
            let output_file =
                save_output_to_file(&docker, container_name, user, repo_path, &combined_bytes)?;
            return Ok((
                format!("Output is not valid UTF-8. Full output available at {output_file}"),
                false,
            ));
        }
    };

    let success = output.success();

    // If command failed with no output, report the exit status
    if !success && combined.is_empty() {
        return Ok((format!("exited with status {}", output.exit_code), false));
    }

    Ok((combined, success))
}

/// Prompts user to confirm exit when they submit empty input.
/// Returns true if user wants to exit (Enter or 'y'), false otherwise.
pub fn confirm_exit() -> Result<bool> {
    eprintln!("Exit? [Y/n] ");
    std::io::stderr().flush()?;

    let mut buf = [0u8; 1];
    let bytes_read = std::io::stdin().read(&mut buf)?;

    if bytes_read == 0 || buf[0] == b'\n' || buf[0] == b'y' || buf[0] == b'Y' {
        return Ok(true);
    }

    // Discard remaining input so it doesn't leak to the next prompt
    let mut discard = String::new();
    std::io::stdin().read_line(&mut discard)?;

    Ok(false)
}

/// Get user input by launching an editor on a temp file containing the chat history.
/// Returns the new message (content after the chat history prefix).
/// If the user doesn't preserve the chat history prefix, prompts to retry.
///
/// The editor can be overridden via the `EDITOR` environment variable,
/// defaulting to `vim`.
pub fn get_input_via_editor(chat_history: &str) -> Result<String> {
    use std::fs;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());

    loop {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let temp_file = temp_dir.join(format!("sandbox-chat-{pid}.txt"));

        fs::write(&temp_file, chat_history).context("Failed to write temp file for editor")?;

        let status = Command::new(&editor)
            .arg(&temp_file)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("Failed to launch editor")?;

        if !status.success() {
            anyhow::bail!("editor exited with non-zero status");
        }

        let edited_content = fs::read_to_string(&temp_file).context("Failed to read temp file")?;
        let _ = fs::remove_file(&temp_file);

        // Prevent accidental editing of history
        if !edited_content.starts_with(chat_history) {
            eprintln!("Error: The chat history prefix was modified. Please keep it intact.");
            eprint!("Press Enter to try again...");
            std::io::stderr().flush()?;

            let mut buf = [0u8; 1];
            let _ = std::io::stdin().read(&mut buf);
            continue;
        }

        let new_message = edited_content[chat_history.len()..].trim().to_string();
        return Ok(new_message);
    }
}
