//! Common utilities shared between agent implementations.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use log::debug;
use sha2::{Digest, Sha256};
use strum::{Display, EnumString};

use crate::config::Model;

pub const MAX_TOKENS: u32 = 4096;
pub const AGENTS_MD_PATH: &str = "AGENTS.md";

/// Get the model identifier as used by the provider's API.
pub fn model_api_id(model: Model) -> String {
    model.to_string()
}

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
        Model::Anthropic(_) => Provider::Anthropic,
        Model::Gemini(_) => Provider::Gemini,
        Model::Xai(_) => Provider::Xai,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_provider() {
        use crate::llm::types::anthropic;
        use crate::llm::types::gemini;
        use crate::llm::types::xai;

        assert_eq!(
            model_provider(Model::Anthropic(anthropic::Model::Opus)),
            Provider::Anthropic
        );
        assert_eq!(
            model_provider(Model::Gemini(gemini::Model::Gemini25Flash)),
            Provider::Gemini
        );
        assert_eq!(
            model_provider(Model::Xai(xai::Model::Grok4)),
            Provider::Xai
        );
    }
}

/// Build a docker exec command that runs as the specified user in the given repo_path.
/// This ensures secondary group membership is applied correctly.
///
/// If `interactive` is true, adds the `-i` flag for commands that need stdin.
fn docker_exec_cmd(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    interactive: bool,
) -> Command {
    let mut cmd = Command::new("docker");
    cmd.args(["exec", "--user", user, "--workdir"]);
    cmd.arg(repo_path);
    if interactive {
        cmd.arg("-i");
    }
    cmd.arg(container_name);
    cmd
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
pub fn read_agents_md(container_name: &str, user: &str, repo_path: &Path) -> Option<String> {
    debug!("Reading {} from sandbox", AGENTS_MD_PATH);
    let output = docker_exec_cmd(container_name, user, repo_path, false)
        .args(["cat", AGENTS_MD_PATH])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        debug!("{} not found or not readable", AGENTS_MD_PATH);
        return None;
    }

    debug!("{} loaded successfully", AGENTS_MD_PATH);
    String::from_utf8(output.stdout).ok()
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
    file_path: &str,
    old_string: &str,
    new_string: &str,
) -> Result<(String, bool)> {
    debug!("Reading file for edit: {}", file_path);
    let output = docker_exec_cmd(container_name, user, repo_path, false)
        .args(["cat", file_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to read file in sandbox")?;
    debug!("File read completed");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok((format!("Error reading file: {stderr}"), false));
    }

    let content = match String::from_utf8(output.stdout) {
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
    let mut write_process = docker_exec_cmd(container_name, user, repo_path, true)
        .args(["bash", "-c", &write_cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to write file in sandbox")?;

    let mut stdin = write_process
        .stdin
        .take()
        .expect("Process was launched with piped stdin");
    stdin
        .write_all(new_content.as_bytes())
        .context("Failed to write to stdin")?;
    drop(stdin);

    debug!("Waiting for write process to complete");
    let output = write_process
        .wait_with_output()
        .context("Failed to wait for write process")?;
    debug!("Write process completed with status: {:?}", output.status);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok((format!("Error writing file: {stderr}"), false));
    }

    Ok((format!("Successfully edited {file_path}"), true))
}

pub fn execute_write_in_sandbox(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    file_path: &str,
    content: &str,
) -> Result<(String, bool)> {
    debug!("Checking if file exists: {}", file_path);
    let output = docker_exec_cmd(container_name, user, repo_path, false)
        .args(["test", "-e", file_path])
        .output()
        .context("Failed to check if file exists")?;

    if output.status.success() {
        return Ok((format!("File {file_path} already exists"), false));
    }

    if let Some(parent) = std::path::Path::new(file_path).parent() {
        if !parent.as_os_str().is_empty() {
            let escaped_parent = parent.display().to_string().replace('\'', "'\\''");
            let mkdir_cmd = format!("mkdir -p '{escaped_parent}'");
            debug!("Creating parent directories for: {}", file_path);
            let _ = docker_exec_cmd(container_name, user, repo_path, false)
                .args(["bash", "-c", &mkdir_cmd])
                .output();
        }
    }

    debug!("Writing new file: {}", file_path);
    let escaped_path = file_path.replace('\'', "'\\''");
    let write_cmd = format!("cat > '{escaped_path}'");
    let mut write_process = docker_exec_cmd(container_name, user, repo_path, true)
        .args(["bash", "-c", &write_cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to write file in sandbox")?;

    let mut stdin = write_process
        .stdin
        .take()
        .expect("Process was launched with piped stdin");
    stdin
        .write_all(content.as_bytes())
        .context("Failed to write to stdin")?;
    drop(stdin);

    debug!("Waiting for write process to complete");
    let output = write_process
        .wait_with_output()
        .context("Failed to wait for write process")?;
    debug!("Write process completed with status: {:?}", output.status);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok((format!("Error writing file: {}", stderr), false));
    }

    Ok((format!("Successfully wrote {file_path}"), true))
}

fn save_output_to_file(
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

    let output_file = format!("/agent/bash-output-{id}");
    debug!("Saving large output to file: {}", output_file);

    // Create /agent directory if it doesn't exist
    debug!("Creating /agent directory");
    docker_exec_cmd(container_name, user, repo_path, false)
        .args(["bash", "-c", "mkdir -p /agent"])
        .output()
        .context("Failed to create /agent directory")?;

    // Write the output to file
    debug!("Writing output data ({} bytes)", data.len());
    let write_cmd = format!("cat > {output_file}");
    let mut write_process = docker_exec_cmd(container_name, user, repo_path, true)
        .args(["bash", "-c", &write_cmd])
        .stdin(Stdio::piped())
        .spawn()
        .context("Failed to write output to file")?;

    let mut stdin = write_process
        .stdin
        .take()
        .expect("Process was launched with piped stdin");
    stdin.write_all(data).context("Failed to write to stdin")?;
    drop(stdin);

    debug!("Waiting for output save process to complete");
    write_process
        .wait()
        .context("Failed to wait for write process")?;
    debug!("Output saved to file");

    Ok(output_file)
}

pub fn execute_bash_in_sandbox(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    command: &str,
) -> Result<(String, bool)> {
    const MAX_OUTPUT_SIZE: usize = 30000;

    debug!("Executing bash in sandbox: {}", command);
    let output = docker_exec_cmd(container_name, user, repo_path, false)
        .args(["bash", "-c", command])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to execute command in sandbox")?;
    debug!("Bash command completed with status: {:?}", output.status);

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
        let output_file = save_output_to_file(container_name, user, repo_path, &combined_bytes)?;
        return Ok((format!("Full output available at {output_file}"), false));
    }

    // Validate UTF-8 - save to file if invalid
    let combined = match String::from_utf8(combined_bytes.clone()) {
        Ok(s) => s,
        Err(_) => {
            let output_file =
                save_output_to_file(container_name, user, repo_path, &combined_bytes)?;
            return Ok((
                format!("Output is not valid UTF-8. Full output available at {output_file}"),
                false,
            ));
        }
    };

    let success = output.status.success();

    // If command failed with no output, report the exit status
    if !success && combined.is_empty() {
        let exit_code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Ok((format!("exited with status {exit_code}"), false));
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
