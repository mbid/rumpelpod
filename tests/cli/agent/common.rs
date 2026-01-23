//! Common utilities for agent integration tests.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use crate::common::{build_test_image, write_test_sandbox_config, TestDaemon, TestRepo};

/// Default model for tests that don't depend on provider-specific behavior.
/// Using Haiku as it's the fastest and cheapest option.
pub const DEFAULT_MODEL: &str = "claude-haiku-4-5";

/// Provider-specific models for tests that need to verify provider-specific behavior.
pub const ANTHROPIC_MODEL: &str = "claude-haiku-4-5";
pub const XAI_MODEL: &str = "grok-3-mini";
pub const GEMINI_MODEL: &str = "gemini-2.5-flash";

/// Get the llm-cache directory path.
pub fn llm_cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache")
}

/// Run agent with a prompt using the default model (interactive mode via PTY).
/// Use this for tests that verify shared implementation code.
pub fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
) -> InteractiveOutput {
    run_agent_interactive_model_and_args(repo, daemon, &[prompt], DEFAULT_MODEL, &[])
}

/// Run agent with a prompt and extra CLI arguments using the default model (interactive mode).
/// Use this for tests that verify shared implementation code.
pub fn run_agent_with_prompt_and_args(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
    extra_args: &[&str],
) -> InteractiveOutput {
    run_agent_interactive_model_and_args(repo, daemon, &[prompt], DEFAULT_MODEL, extra_args)
}

/// Run agent with a prompt using a specific model (interactive mode via PTY).
/// Use this for tests that need to verify provider-specific behavior.
pub fn run_agent_with_prompt_and_model(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
    model: &str,
) -> InteractiveOutput {
    run_agent_interactive_model_and_args(repo, daemon, &[prompt], model, &[])
}

/// Set up a basic test repo with sandbox config.
pub fn setup_test_repo() -> TestRepo {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);
    repo
}

/// Create a mock editor script that saves original content for verification
/// and exits immediately (simulating user not typing anything = empty input = exit).
pub fn create_mock_editor_exit(script_dir: &Path, verify_file: &Path) -> PathBuf {
    use indoc::formatdoc;

    let script_path = script_dir.join("mock-editor.sh");
    let verify_file_str = verify_file.to_string_lossy();
    let script_content = formatdoc! {r#"
        #!/bin/bash
        FILE="$1"
        cp "$FILE" "{verify_file_str}"
    "#};
    fs::write(&script_path, &script_content).expect("Failed to write mock editor script");

    let perms = std::fs::Permissions::from_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("Failed to set script permissions");

    script_path
}

/// Create a mock editor script that appends messages from a list one after the other.
/// The first message becomes the initial prompt, subsequent messages are sent in order.
/// When all messages are exhausted, the editor does nothing (empty input triggers exit).
///
/// Returns the path to the mock editor script.
pub fn create_mock_editor_with_messages(script_dir: &Path, messages: &[&str]) -> PathBuf {
    use indoc::formatdoc;

    let script_path = script_dir.join("mock-editor.sh");
    let state_file = script_dir.join("editor-state.txt");
    let messages_file = script_dir.join("messages.txt");

    // Write messages to a file (one per line, base64-encoded to handle multi-line messages)
    let encoded_messages: Vec<String> = messages
        .iter()
        .map(|m| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(m.as_bytes())
        })
        .collect();
    fs::write(&messages_file, encoded_messages.join("\n")).expect("Failed to write messages file");

    // Initialize state to 0
    fs::write(&state_file, "0").expect("Failed to write state file");

    let state_file_str = state_file.to_string_lossy();
    let messages_file_str = messages_file.to_string_lossy();

    let script_content = formatdoc! {r#"
        #!/bin/bash
        FILE="$1"
        STATE_FILE="{state_file_str}"
        MESSAGES_FILE="{messages_file_str}"

        # Read current index
        INDEX=$(cat "$STATE_FILE")

        # Get the message at this index (1-indexed for sed)
        LINE=$((INDEX + 1))
        ENCODED_MSG=$(sed -n "${{LINE}}p" "$MESSAGES_FILE")

        if [ -n "$ENCODED_MSG" ]; then
            # Decode and append message to the file
            MSG=$(echo "$ENCODED_MSG" | base64 -d)
            echo "$MSG" >> "$FILE"

            # Increment index
            echo $((INDEX + 1)) > "$STATE_FILE"
        fi
        # If no message, do nothing (empty input triggers exit)
    "#};
    fs::write(&script_path, &script_content).expect("Failed to write mock editor script");

    let perms = std::fs::Permissions::from_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("Failed to set script permissions");

    script_path
}

/// Output from an interactive agent run.
pub struct InteractiveOutput {
    pub stdout: String,
    pub success: bool,
}

/// Action to take when the conversation picker is shown.
#[allow(dead_code)]
pub enum PickerAction {
    /// Select a conversation by index (e.g., 0 for most recent).
    Select(usize),
    /// Press Enter to select the default (most recent) conversation.
    SelectDefault,
    /// Cancel the picker with Ctrl+C.
    Cancel,
}

/// Run agent interactively with a list of messages using PTY.
/// Messages are sent one at a time via a mock editor.
/// The first message is the initial prompt, subsequent messages are follow-ups.
/// After all messages are sent, the agent exits (empty editor input triggers exit).
#[allow(dead_code)]
pub fn run_agent_interactive(
    repo: &TestRepo,
    daemon: &TestDaemon,
    messages: &[&str],
) -> InteractiveOutput {
    run_agent_interactive_model_and_args(repo, daemon, messages, DEFAULT_MODEL, &[])
}

/// Run agent interactively with a specific model.
#[allow(dead_code)]
pub fn run_agent_interactive_and_model(
    repo: &TestRepo,
    daemon: &TestDaemon,
    messages: &[&str],
    model: &str,
) -> InteractiveOutput {
    run_agent_interactive_model_and_args(repo, daemon, messages, model, &[])
}

/// Run agent interactively with extra CLI arguments.
#[allow(dead_code)]
pub fn run_agent_interactive_and_args(
    repo: &TestRepo,
    daemon: &TestDaemon,
    messages: &[&str],
    extra_args: &[&str],
) -> InteractiveOutput {
    run_agent_interactive_model_and_args(repo, daemon, messages, DEFAULT_MODEL, extra_args)
}

/// Run agent interactively with a list of messages, model, and extra CLI arguments using PTY.
pub fn run_agent_interactive_model_and_args(
    repo: &TestRepo,
    daemon: &TestDaemon,
    messages: &[&str],
    model: &str,
    extra_args: &[&str],
) -> InteractiveOutput {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let editor_path = create_mock_editor_with_messages(temp_dir.path(), messages);

    let cache_dir = llm_cache_dir();
    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("Failed to create PTY");

    let sandbox_bin = cargo::cargo_bin!("sandbox");

    let mut cmd = CommandBuilder::new(sandbox_bin);
    cmd.cwd(repo.path());
    cmd.env(
        "SANDBOX_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.env("EDITOR", editor_path.to_str().unwrap());
    cmd.args([
        "agent",
        "test",
        "--model",
        model,
        "--cache",
        cache_dir.to_str().unwrap(),
    ]);
    for arg in extra_args {
        cmd.arg(arg);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    // Set up reader to collect output
    let mut reader = pair
        .master
        .try_clone_reader()
        .expect("Failed to clone reader");
    let mut writer = pair.master.take_writer().expect("Failed to get writer");

    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            if tx
                .send(String::from_utf8_lossy(&buffer[..n]).to_string())
                .is_err()
            {
                break;
            }
        }
    });

    // Collect output and handle exit confirmation
    let mut output = String::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(120);

    loop {
        // Check if process has exited
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain remaining output
                while let Ok(s) = rx.try_recv() {
                    output.push_str(&s);
                }
                return InteractiveOutput {
                    stdout: output,
                    success: status.exit_code() == 0,
                };
            }
            Ok(None) => {
                // Process still running
            }
            Err(e) => panic!("Error waiting for process: {}", e),
        }

        // Collect any available output
        while let Ok(s) = rx.try_recv() {
            output.push_str(&s);
        }

        // Check for exit confirmation prompt and respond with 'y'
        if output.contains("Exit? [Y/n]") {
            // Clear the match so we don't respond multiple times
            output = output.replace("Exit? [Y/n]", "Exit? [Y/n] (answered)");
            let _ = writeln!(writer, "y");
        }

        // Check for unexpected conversation picker prompt
        // Tests that expect the picker should use run_agent_expecting_picker instead
        if output.contains("Select [0-") && output.contains("default") {
            let _ = child.kill();
            panic!(
                "Unexpected conversation picker prompt. Use run_agent_expecting_picker for tests \
                 that expect the picker.\nOutput so far:\n{}",
                output
            );
        }

        // Check timeout
        if start.elapsed() > timeout {
            let _ = child.kill();
            panic!(
                "Process did not exit within timeout.\nOutput so far:\n{}",
                output
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
}

/// Run agent expecting the conversation picker to appear.
///
/// Use this for tests that verify behavior when multiple conversations exist
/// and no --continue or --new flag is provided. The picker will be handled
/// according to the specified action.
pub fn run_agent_expecting_picker(
    repo: &TestRepo,
    daemon: &TestDaemon,
    messages: &[&str],
    picker_action: PickerAction,
) -> InteractiveOutput {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let editor_path = create_mock_editor_with_messages(temp_dir.path(), messages);

    let cache_dir = llm_cache_dir();
    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("Failed to create PTY");

    let sandbox_bin = cargo::cargo_bin!("sandbox");

    let mut cmd = CommandBuilder::new(sandbox_bin);
    cmd.cwd(repo.path());
    cmd.env(
        "SANDBOX_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.env("EDITOR", editor_path.to_str().unwrap());
    cmd.args([
        "agent",
        "test",
        "--model",
        DEFAULT_MODEL,
        "--cache",
        cache_dir.to_str().unwrap(),
    ]);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    let mut reader = pair
        .master
        .try_clone_reader()
        .expect("Failed to clone reader");
    let mut writer = pair.master.take_writer().expect("Failed to get writer");

    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            if tx
                .send(String::from_utf8_lossy(&buffer[..n]).to_string())
                .is_err()
            {
                break;
            }
        }
    });

    let mut output = String::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(120);
    let mut picker_handled = false;

    loop {
        // Check if process has exited
        match child.try_wait() {
            Ok(Some(status)) => {
                while let Ok(s) = rx.try_recv() {
                    output.push_str(&s);
                }
                return InteractiveOutput {
                    stdout: output,
                    success: status.exit_code() == 0,
                };
            }
            Ok(None) => {}
            Err(e) => panic!("Error waiting for process: {}", e),
        }

        while let Ok(s) = rx.try_recv() {
            output.push_str(&s);
        }

        // Handle the conversation picker prompt
        if !picker_handled && output.contains("Select [0-") && output.contains("default") {
            picker_handled = true;
            match picker_action {
                PickerAction::Select(index) => {
                    let _ = writeln!(writer, "{}", index);
                }
                PickerAction::SelectDefault => {
                    // Press Enter to select the default
                    let _ = writeln!(writer);
                }
                PickerAction::Cancel => {
                    // Send Ctrl+C (ASCII 3) to cancel
                    let _ = writer.write_all(&[3]);
                }
            }
        }

        // Handle exit confirmation
        if output.contains("Exit? [Y/n]") {
            output = output.replace("Exit? [Y/n]", "Exit? [Y/n] (answered)");
            let _ = writeln!(writer, "y");
        }

        if start.elapsed() > timeout {
            let _ = child.kill();
            panic!(
                "Process did not exit within timeout.\nOutput so far:\n{}",
                output
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
}
