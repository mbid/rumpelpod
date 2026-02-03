//! Common utilities shared between agent implementations.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use bollard::Docker;
use indoc::formatdoc;
use log::debug;
use strum::{Display, EnumString};

use crate::config::{get_runtime_dir, is_deterministic_test_mode, Model};
use crate::docker_exec::{
    exec_capture_with_timeout, exec_check, exec_command, exec_with_stdin, ExecResult,
};
use rand::{distr::Alphanumeric, Rng};

/// Starting PID for deterministic mode. We start at 1000 so PIDs are easy to
/// recognize (1000, 1001, 1002, ...).
const DETERMINISTIC_PID_START: u32 = 1000;

/// Get and increment the next deterministic PID from a file.
///
/// In deterministic mode, we store the last used PID in a file so that each
/// test (which typically has its own XDG_RUNTIME_DIR) gets consistent PIDs.
/// The file is stored in `$XDG_RUNTIME_DIR/sandbox/last_pid`.
///
/// NOTE: This is not thread-safe. If multiple processes try to spawn commands
/// simultaneously in the same test environment, they may get the same PID.
/// For now this is a known limitation since tests typically run sequentially.
fn get_next_deterministic_pid() -> Result<u32> {
    let pid_file = get_runtime_dir()
        .context("failed to get runtime directory for deterministic PID file")?
        .join("last_pid");

    // Read the last PID from file, defaulting to START - 1 so first call returns START
    let last_pid = match std::fs::read_to_string(&pid_file) {
        Ok(contents) => {
            let trimmed = contents.trim();
            // Treat empty file same as missing file
            if trimmed.is_empty() {
                DETERMINISTIC_PID_START - 1
            } else {
                trimmed
                    .parse::<u32>()
                    .context("failed to parse last PID file contents")?
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DETERMINISTIC_PID_START - 1,
        Err(e) => return Err(e).context("failed to read last PID file"),
    };

    let next_pid = last_pid + 1;

    // Ensure the directory exists and write the new PID
    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent).context("failed to create runtime directory")?;
    }
    std::fs::write(&pid_file, next_pid.to_string()).context("failed to write last PID file")?;

    Ok(next_pid)
}

pub const MAX_TOKENS: u32 = 4096;
pub const AGENTS_MD_PATH: &str = "AGENTS.md";
pub const DEFAULT_BASH_TIMEOUT: u64 = 120;

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

pub fn execute_bash_in_sandbox(
    container_name: &str,
    user: &str,
    repo_path: &Path,
    docker_socket: &Path,
    command: &str,
) -> Result<(String, bool)> {
    const MAX_OUTPUT_SIZE: usize = 30000;

    // Get timeout from env or default to 120s
    let timeout_secs = std::env::var("AGENT_BASH_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BASH_TIMEOUT);
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let docker = docker_connect(docker_socket)?;
    let workdir = repo_path.to_string_lossy().to_string();
    let env = vec!["GIT_EDITOR=false"];

    // Generate ID for output file. In deterministic mode, we use the PID we're
    // about to assign to the command for a unique but predictable filename.
    let (id, deterministic_pid) = if is_deterministic_test_mode()? {
        let pid = get_next_deterministic_pid()?;
        (pid.to_string(), Some(pid))
    } else {
        let random_id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        (random_id, None)
    };
    let output_file = format!("/tmp/agent/bash-{id}.log");

    debug!("Executing bash in sandbox: {}", command);

    // In test mode, set ns_last_pid to get a deterministic PID for this command.
    // This requires the container to run in privileged mode (set by daemon when
    // SANDBOX_TEST_DETERMINISTIC_IDS is enabled), which makes /proc/sys writable.
    if let Some(next_pid) = deterministic_pid {
        let ns_last_pid = next_pid - 1;
        // Set ns_last_pid so the next process gets `next_pid`.
        // We run this as root since writing to ns_last_pid requires CAP_SYS_ADMIN.
        exec_command(
            &docker,
            container_name,
            Some("root"),
            None,
            None,
            vec![
                "sh",
                "-c",
                &format!("echo {ns_last_pid} > /proc/sys/kernel/ns_last_pid"),
            ],
        )
        .context("failed to set ns_last_pid for deterministic PIDs")?;
    }

    // Wrapper to print PID and redirect to file + tee
    // echo $$ prints the PID of the shell.
    // We use a subshell or block for the command so we can redirect its output.
    // We use `set -o pipefail` so if the command fails, the pipeline fails (and we get the exit code).
    let wrapped_command = format!(
        "mkdir -p /tmp/agent; echo $$; set -o pipefail; ( {command} ) 2>&1 | tee {output_file}"
    );

    let exec_result = exec_capture_with_timeout(
        &docker,
        container_name,
        Some(user),
        Some(&workdir),
        Some(env),
        vec!["bash", "-c", &wrapped_command],
        timeout,
    )
    .context("Failed to execute command in sandbox")?;

    match exec_result {
        ExecResult::Completed(output) => {
            debug!(
                "Bash command completed with exit code: {}",
                output.exit_code
            );

            let mut combined_bytes = output.stdout;
            // Append any stderr just in case (though tee redirects to stdout)
            if !output.stderr.is_empty() {
                combined_bytes.push(b'\n');
                combined_bytes.extend_from_slice(&output.stderr);
            }

            // Remove PID line (first line)
            if let Some(idx) = combined_bytes.iter().position(|&b| b == b'\n') {
                combined_bytes = combined_bytes[idx + 1..].to_vec();
            } else {
                // Only PID or empty?
                combined_bytes.clear();
            }

            // Check if output exceeds limit
            let len = combined_bytes.len();
            if len > MAX_OUTPUT_SIZE {
                return Ok((
                    formatdoc! {r#"
                        Output is too large ({len} bytes). Full output available at {output_file}.
                        Use `tail -n 100 {output_file}` to see the end of the output, or `grep` to search.
                    "#},
                    false,
                ));
            }

            // Validate UTF-8
            let combined = match String::from_utf8(combined_bytes) {
                Ok(s) => s,
                Err(_) => {
                    return Ok((
                        format!(
                            "Output is not valid UTF-8. Full output available at {output_file}"
                        ),
                        false,
                    ));
                }
            };

            let success = output.exit_code == 0;

            // If command failed with no output, report the exit status
            if !success && combined.is_empty() {
                return Ok((format!("exited with status {}", output.exit_code), false));
            }

            Ok((combined, success))
        }
        ExecResult::TimedOut { stdout, stderr } => {
            debug!("Bash command timed out");

            let mut combined_bytes = stdout;
            if !stderr.is_empty() {
                combined_bytes.push(b'\n');
                combined_bytes.extend_from_slice(&stderr);
            }

            // Extract PID
            let pid = if let Some(idx) = combined_bytes.iter().position(|&b| b == b'\n') {
                let pid_str = String::from_utf8_lossy(&combined_bytes[..idx]).to_string();
                combined_bytes = combined_bytes[idx + 1..].to_vec();
                pid_str
            } else {
                "unknown".to_string()
            };

            let len = combined_bytes.len();
            if len > MAX_OUTPUT_SIZE {
                return Ok((
                    formatdoc! {r#"
                        Command timed out after {timeout_secs} seconds.
                        Process is still running with PID {pid}.
                        Output so far is too large ({len} bytes). Full output available at {output_file}.
                    "#},
                    false,
                ));
            }

            let combined = String::from_utf8_lossy(&combined_bytes).to_string();

            Ok((
                formatdoc! {r#"
                    Command timed out after {timeout_secs} seconds.
                    Process is still running with PID {pid}.
                    Output so far (saved to {output_file}):
                    {combined}
                "#},
                false,
            ))
        }
    }
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
///
/// If `editable_suffix` is provided, it will be appended to the chat history as editable
/// content (useful when continuing a conversation and allowing the user to edit the last message).
///
/// The `sandbox_name` parameter is used in the temp file name to help identify which sandbox
/// the chat session belongs to.
pub fn get_input_via_editor(
    chat_history: &str,
    editable_suffix: Option<&str>,
    sandbox_name: &str,
) -> Result<String> {
    use std::fs;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());

    loop {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let temp_file = temp_dir.join(format!("sandbox-chat-{sandbox_name}-{pid}.txt"));

        let initial_content = if let Some(suffix) = editable_suffix {
            format!("{}{}", chat_history, suffix)
        } else {
            chat_history.to_string()
        };

        fs::write(&temp_file, initial_content).context("Failed to write temp file for editor")?;

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
            if editable_suffix.is_some() {
                eprintln!("You can only edit the last user message (after the history prefix).");
            }
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
