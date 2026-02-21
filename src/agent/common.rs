//! Common utilities shared between agent implementations.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use indoc::formatdoc;
use log::debug;
use strum::{Display, EnumString};

use crate::config::{get_runtime_dir, is_deterministic_test_mode, Model};
use crate::pod_client::PodClient;
use rand::{distr::Alphanumeric, RngExt};

/// Starting PID for deterministic mode. We start at 1000 so PIDs are easy to
/// recognize (1000, 1050, 1100, ...).
const DETERMINISTIC_PID_START: u32 = 1000;

/// PID increment for deterministic mode. We increment by 50 to leave room for
/// internal Docker processes that may be spawned for each command execution.
const DETERMINISTIC_PID_INCREMENT: u32 = 50;

/// Get and increment the next deterministic PID from a file.
///
/// In deterministic mode, we store the last used PID in a per-pod file.
/// The file is stored at `$DETERMINISTIC_PID_DIR/<pod_name>` if the env var
/// is set, otherwise at `$XDG_RUNTIME_DIR/rumpelpod/deterministic-pids/<pod_name>`.
///
/// NOTE: This is not thread-safe. If multiple processes try to spawn commands
/// simultaneously in the same test environment, they may get the same PID.
/// For now this is a known limitation since tests typically run sequentially.
fn get_next_deterministic_pid(pod_name: &str) -> Result<u32> {
    let pid_dir = match std::env::var("DETERMINISTIC_PID_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => get_runtime_dir()
            .context("failed to get runtime directory for deterministic PID file")?
            .join("deterministic-pids"),
    };
    let pid_file = pid_dir.join(pod_name);

    // Read the last PID from file, defaulting to START - INCREMENT so first call returns START
    let last_pid = match std::fs::read_to_string(&pid_file) {
        Ok(contents) => {
            let trimmed = contents.trim();
            // Treat empty file same as missing file
            if trimmed.is_empty() {
                DETERMINISTIC_PID_START - DETERMINISTIC_PID_INCREMENT
            } else {
                trimmed
                    .parse::<u32>()
                    .context("failed to parse last PID file contents")?
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            DETERMINISTIC_PID_START - DETERMINISTIC_PID_INCREMENT
        }
        Err(e) => return Err(e).context("failed to read last PID file"),
    };

    let next_pid = last_pid + DETERMINISTIC_PID_INCREMENT;

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
        Model::ClaudeOpus | Model::ClaudeOpus46 | Model::ClaudeSonnet | Model::ClaudeHaiku => {
            Provider::Anthropic
        }
        Model::Gemini25Flash | Model::Gemini3Flash | Model::Gemini3Pro => Provider::Gemini,
        Model::Grok41Fast | Model::Grok41FastNonReasoning => Provider::Xai,
    }
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
                "Execute a bash command inside the pod and return the output.\n\
                               The working directory is the project root.\n\
                               If a command times out, wait and get output: `tail --pid=<PID> -f <output_file>`.\n\
                               If some output was already printed, use `tail -n +<START_LINE> --pid=<PID> -f <output_file>` to skip it."
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

/// Read AGENTS.md from the pod if it exists.
pub fn read_agents_md(pod: &PodClient, repo_path: &Path) -> Option<String> {
    debug!("Reading {} from pod", AGENTS_MD_PATH);
    let agents_path = repo_path.join(AGENTS_MD_PATH);
    let data = pod.fs_read(&agents_path).ok()?;
    debug!("{} loaded successfully", AGENTS_MD_PATH);
    String::from_utf8(data).ok()
}

pub fn build_system_prompt(agents_md: Option<&str>) -> String {
    match agents_md {
        Some(content) => format!("{BASE_SYSTEM_PROMPT}\n\n{content}"),
        None => BASE_SYSTEM_PROMPT.to_string(),
    }
}

pub fn execute_edit_in_pod(
    pod: &PodClient,
    repo_path: &Path,
    file_path: &str,
    old_string: &str,
    new_string: &str,
) -> Result<(String, bool)> {
    let full_path = repo_path.join(file_path);

    debug!("Reading file for edit: {}", file_path);
    let output = match pod.fs_read(&full_path) {
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
    if let Err(e) = pod.fs_write(&full_path, new_content.as_bytes(), None, false) {
        return Ok((format!("Error writing file: {e}"), false));
    }
    debug!("Write completed");

    Ok((format!("Successfully edited {file_path}"), true))
}

pub fn execute_write_in_pod(
    pod: &PodClient,
    repo_path: &Path,
    file_path: &str,
    content: &str,
) -> Result<(String, bool)> {
    let full_path = repo_path.join(file_path);

    debug!("Checking if file exists: {}", file_path);
    match pod.fs_stat(&full_path) {
        Ok(stat) if stat.exists => {
            return Ok((format!("File {file_path} already exists"), false));
        }
        _ => {}
    }

    debug!("Writing new file: {}", file_path);
    // create_parents: true will create parent directories
    if let Err(e) = pod.fs_write(&full_path, content.as_bytes(), None, true) {
        return Ok((format!("Error writing file: {e}"), false));
    }
    debug!("Write completed");

    Ok((format!("Successfully wrote {file_path}"), true))
}

pub fn execute_bash_in_pod(
    pod: &PodClient,
    pod_name: &str,
    user: &str,
    repo_path: &Path,
    remote_env: &[(String, String)],
    command: &str,
) -> Result<(String, bool)> {
    use base64::Engine;

    const MAX_OUTPUT_SIZE: usize = 30000;

    // Get timeout from env or default to 120s
    let timeout_secs = std::env::var("AGENT_BASH_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BASH_TIMEOUT);

    let mut env: Vec<String> = vec!["GIT_EDITOR=false".to_string()];
    for (k, v) in remote_env {
        env.push(format!("{k}={v}"));
    }

    // Generate ID for output file. In deterministic mode, we use the PID we're
    // about to assign to the command for a unique but predictable filename.
    let (id, deterministic_pid) = if is_deterministic_test_mode()? {
        let pid = get_next_deterministic_pid(pod_name)?;
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

    debug!("Executing bash in pod: {}", command);

    // In test mode, set ns_last_pid to get a deterministic PID for this command.
    if let Some(next_pid) = deterministic_pid {
        let ns_last_pid = next_pid - 1;
        pod.run(
            &[
                "sh",
                "-c",
                &format!("echo {ns_last_pid} > /proc/sys/kernel/ns_last_pid"),
            ],
            Some("root"),
            None,
            &[],
            None,
            None,
        )
        .context("failed to set ns_last_pid for deterministic PIDs")?;
    }

    // Wrapper to print PID and redirect to file + tee
    let wrapped_command = format!(
        "mkdir -p /tmp/agent; echo $$; set -o pipefail; ( {command} ) 2>&1 | stdbuf -o0 tee {output_file}"
    );

    let result = pod
        .run(
            &["bash", "-c", &wrapped_command],
            Some(user),
            Some(repo_path),
            &env,
            None,
            Some(timeout_secs),
        )
        .context("Failed to execute command in pod")?;

    let stdout = base64::engine::general_purpose::STANDARD
        .decode(&result.stdout)
        .unwrap_or_default();
    let stderr = base64::engine::general_purpose::STANDARD
        .decode(&result.stderr)
        .unwrap_or_default();

    if result.timed_out {
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
        let lines_so_far = combined_bytes.iter().filter(|&&b| b == b'\n').count();
        let next_line = lines_so_far + 1;
        let tail_cmd = format!("tail -n +{next_line} --pid={pid} -f {output_file}");

        if len > MAX_OUTPUT_SIZE {
            return Ok((
                formatdoc! {r#"
                    Command timed out after {timeout_secs} seconds.
                    Process is still running with PID {pid}.
                    Output so far is too large ({len} bytes). Full output available at {output_file}.
                    To get remaining output: `{tail_cmd}`
                "#},
                false,
            ));
        }

        let combined = String::from_utf8_lossy(&combined_bytes).to_string();

        return Ok((
            formatdoc! {r#"
                Command timed out after {timeout_secs} seconds.
                Process is still running with PID {pid}.
                Output so far (saved to {output_file}):
                {combined}
                To get remaining output: `{tail_cmd}`
            "#},
            false,
        ));
    }

    debug!(
        "Bash command completed with exit code: {}",
        result.exit_code
    );

    let mut combined_bytes = stdout;
    if !stderr.is_empty() {
        combined_bytes.push(b'\n');
        combined_bytes.extend_from_slice(&stderr);
    }

    // Remove PID line (first line)
    if let Some(idx) = combined_bytes.iter().position(|&b| b == b'\n') {
        combined_bytes = combined_bytes[idx + 1..].to_vec();
    } else {
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
                format!("Output is not valid UTF-8. Full output available at {output_file}"),
                false,
            ));
        }
    };

    let success = result.exit_code == 0;

    // If command failed with no output, report the exit status
    if !success && combined.is_empty() {
        return Ok((format!("exited with status {}", result.exit_code), false));
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
///
/// If `editable_suffix` is provided, it will be appended to the chat history as editable
/// content (useful when continuing a conversation and allowing the user to edit the last message).
///
/// The `pod_name` parameter is used in the temp file name to help identify which pod
/// the chat session belongs to.
pub fn get_input_via_editor(
    chat_history: &str,
    editable_suffix: Option<&str>,
    pod_name: &str,
) -> Result<String> {
    use std::fs;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());

    loop {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let temp_file = temp_dir.join(format!("rumpelpod-chat-{pod_name}-{pid}.txt"));

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
