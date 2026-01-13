//! Integration tests for the agent using Anthropic Claude models.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use indoc::formatdoc;
use sandbox::CommandExt;

use super::{llm_cache_dir, run_agent_with_prompt_and_model, run_agent_with_prompt_model_and_args};
use crate::common::{build_test_image, write_test_sandbox_config, TestDaemon, TestRepo};

const MODEL: &str = "haiku";

/// Helper to run agent with a prompt using Claude Haiku.
fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
) -> std::process::Output {
    run_agent_with_prompt_and_model(repo, daemon, prompt, MODEL)
}

/// Helper to run agent with a prompt and extra CLI arguments.
fn run_agent_with_prompt_and_args(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
    extra_args: &[&str],
) -> std::process::Output {
    run_agent_with_prompt_model_and_args(repo, daemon, prompt, MODEL, extra_args)
}

/// Set up a basic test repo with sandbox config.
fn setup_test_repo() -> TestRepo {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);
    repo
}

#[test]
fn agent_reads_file() {
    let repo = TestRepo::new();

    // Create a file with secret content (must be before building image)
    let secret_content = "SECRET_VALUE_12345";
    fs::write(repo.path().join("secret.txt"), secret_content).expect("Failed to write secret.txt");

    // Commit the file so it's in the repo for the image build
    Command::new("git")
        .args(["add", "secret.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    Command::new("git")
        .args(["commit", "-m", "Add secret"])
        .current_dir(repo.path())
        .success()
        .expect("git commit failed");

    // Build image after file is committed
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Run `cat secret.txt` and tell me what it contains.",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(secret_content),
        "Agent output should contain the secret content.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_edits_file() {
    let repo = TestRepo::new();

    // Create a file with original content (must be before building image)
    let original_content = "Hello World";
    fs::write(repo.path().join("greeting.txt"), original_content)
        .expect("Failed to write greeting.txt");

    // Commit the file
    Command::new("git")
        .args(["add", "greeting.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    Command::new("git")
        .args(["commit", "-m", "Add greeting"])
        .current_dir(repo.path())
        .success()
        .expect("git commit failed");

    // Build image after file is committed
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Use the edit tool to replace 'World' with 'Universe' in greeting.txt, then run `cat greeting.txt` and tell me the result.",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Universe"),
        "Agent output should contain the edited content 'Universe'.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_writes_file() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let expected_content = "WRITTEN_BY_AGENT_12345";

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        &format!(
            "Run `echo '{expected_content}' > newfile.txt` \
             then run `cat newfile.txt` and tell me the result."
        ),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(expected_content),
        "Agent output should contain the written content.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_web_search() {
    // Test that the Anthropic agent can use web search to find information past its knowledge cutoff.
    // The US penny production ended in November 2025, after the model's training data.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The last US penny was minted on November 12, 2025
    assert!(
        stdout.contains("2025-11-12"),
        "Agent should find that the last US penny was minted on 2025-11-12.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_handles_command_with_empty_output_and_nonzero_exit() {
    // Regression test: The Anthropic API rejects tool_result blocks with empty
    // content when is_error is true. Commands like `false` or `exit 1` produce
    // no output but exit with non-zero status.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Run the command `false` and tell me what happened.",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The agent should NOT fail with the API error about empty content
    assert!(
        !stderr.contains("content cannot be empty"),
        "Agent failed with empty content error.\nstderr: {}",
        stderr
    );
}

#[test]
fn agent_large_file_output() {
    // Regression test: reading a file that exceeds the 30000 character limit
    // should not cause the agent to deadlock.
    let repo = TestRepo::new();

    // Create a large file (must be before building image)
    let large_content = "x".repeat(35000);
    fs::write(repo.path().join("large.txt"), &large_content).expect("Failed to write large.txt");

    // Commit the file
    Command::new("git")
        .args(["add", "large.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    Command::new("git")
        .args(["commit", "-m", "Add large file"])
        .current_dir(repo.path())
        .success()
        .expect("git commit failed");

    // Build image after file is committed
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Run exactly one tool: `cat large.txt`. After that single tool call, stop immediately and tell me what you observed. Do not run any other tools.",
    );

    // Agent should complete without deadlocking and mention the output file
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/agent/bash-output-"),
        "Agent should report that output was saved to a file.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

// ============================================================================
// Conversation history tests
// ============================================================================

#[test]
fn agent_new_flag_starts_fresh_conversation() {
    // Running with --new should always start a new conversation,
    // even if previous conversations exist.
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // First run creates a conversation
    let output1 = run_agent_with_prompt(&repo, &daemon, "Say 'first conversation'");
    assert!(output1.status.success(), "First agent run should succeed");

    // Second run with --new should start fresh (not resume)
    let output2 =
        run_agent_with_prompt_and_args(&repo, &daemon, "Say 'second conversation'", &["--new"]);
    assert!(
        output2.status.success(),
        "Second agent run with --new should succeed"
    );

    // The second conversation shouldn't see context from the first
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        !stdout2.contains("first conversation"),
        "--new should start fresh without previous context"
    );
}

#[test]
fn agent_continue_flag_resumes_conversation() {
    // Running with --continue=0 should resume the most recent conversation.
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // First run: tell the agent a secret code to remember
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "Remember this secret code: ZEBRA_DELTA_9876. Just acknowledge you've memorized it.",
    );
    assert!(output1.status.success(), "First agent run should succeed");

    // Second run with --continue=0: resume and ask about the code
    let output2 = run_agent_with_prompt_and_args(
        &repo,
        &daemon,
        "What was the secret code I asked you to remember?",
        &["--continue=0"],
    );
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        output2.status.success(),
        "Second agent run should succeed.\nstdout: {}\nstderr: {}",
        stdout2,
        stderr2
    );

    // The resumed conversation should have context from the first run
    assert!(
        stdout2.contains("ZEBRA") || stdout2.contains("DELTA") || stdout2.contains("9876"),
        "Resumed conversation should remember the secret code.\nstdout: {}\nstderr: {}",
        stdout2,
        stderr2
    );
}

#[test]
fn agent_auto_resumes_single_conversation() {
    // Without flags, agent should auto-resume if there's exactly one conversation.
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // First run: tell the agent a secret
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "Remember: the secret code is FOXTROT_HOTEL_2468. Acknowledge.",
    );
    assert!(output1.status.success(), "First agent run should succeed");

    // Second run without flags should auto-resume the single conversation
    let output2 = run_agent_with_prompt(&repo, &daemon, "What was the secret code I mentioned?");
    assert!(output2.status.success(), "Second agent run should succeed");

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("FOXTROT") || stdout2.contains("HOTEL") || stdout2.contains("2468"),
        "Auto-resumed conversation should remember the secret code.\nstdout: {}",
        stdout2
    );
}

#[test]
fn agent_errors_with_multiple_conversations_no_flag() {
    // Without flags and multiple conversations, non-TTY mode should error.
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // Create first conversation
    let output1 = run_agent_with_prompt(&repo, &daemon, "First conversation");
    assert!(output1.status.success(), "First agent run should succeed");

    // Create second conversation with --new
    let output2 = run_agent_with_prompt_and_args(&repo, &daemon, "Second conversation", &["--new"]);
    assert!(output2.status.success(), "Second agent run should succeed");

    // Third run without flags should fail (multiple conversations, non-TTY)
    let output3 = run_agent_with_prompt(&repo, &daemon, "Which conversation am I in?");
    assert!(
        !output3.status.success(),
        "Agent should fail when multiple conversations exist without flags"
    );

    let stderr3 = String::from_utf8_lossy(&output3.stderr);
    assert!(
        stderr3.contains("Multiple conversations") || stderr3.contains("--continue"),
        "Error should mention multiple conversations.\nstderr: {}",
        stderr3
    );
}

#[test]
fn agent_continue_out_of_range_errors() {
    // --continue=N with N out of range should error.
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // Create one conversation
    let output1 = run_agent_with_prompt(&repo, &daemon, "Single conversation");
    assert!(output1.status.success(), "First agent run should succeed");

    // Try to continue conversation index 5 (only index 0 exists)
    let output2 =
        run_agent_with_prompt_and_args(&repo, &daemon, "This should fail", &["--continue=5"]);
    assert!(
        !output2.status.success(),
        "Agent should fail with out-of-range conversation index"
    );

    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("out of range") || stderr2.contains("Only 1 conversation"),
        "Error should mention index out of range.\nstderr: {}",
        stderr2
    );
}

#[test]
fn agent_continue_no_conversations_errors() {
    // --continue=0 with no existing conversations should error.
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // Try to continue when no conversations exist
    let output =
        run_agent_with_prompt_and_args(&repo, &daemon, "This should fail", &["--continue=0"]);
    assert!(
        !output.status.success(),
        "Agent should fail with --continue when no conversations exist"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No conversations") || stderr.contains("no conversation"),
        "Error should mention no conversations exist.\nstderr: {}",
        stderr
    );
}

// ============================================================================
// Interactive mode / editor tests
// ============================================================================

/// Create a mock editor script that saves original content for verification
/// and exits immediately (simulating user not typing anything = empty input = exit).
fn create_mock_editor_exit(script_dir: &Path, verify_file: &Path) -> PathBuf {
    let script_path = script_dir.join("mock-editor.sh");
    let verify_file_str = verify_file.to_string_lossy();
    let script_content = formatdoc! {r#"
        #!/bin/bash
        # Mock editor: save original content for verification, then exit without changes
        # (simulating user closing editor without adding new input)
        FILE="$1"
        cp "$FILE" "{verify_file_str}"
        # Exit successfully, file unchanged means empty input -> agent will prompt for exit
    "#};
    fs::write(&script_path, &script_content).expect("Failed to write mock editor script");

    let perms = std::fs::Permissions::from_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("Failed to set script permissions");

    script_path
}

#[test]
fn agent_interactive_resume_shows_history() {
    // When resuming a conversation in interactive mode, the editor should show
    // the previous chat history.
    //
    // This test uses a PTY to simulate a real terminal, allowing us to test the
    // interactive code path where get_input_via_vim is called.
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::Write as IoWrite;
    use std::time::Duration;

    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // First run: create a conversation with a unique identifier via non-TTY mode
    let unique_marker = "UNIQUE_HISTORY_MARKER_XYZ123";
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        &format!("Remember this marker: {unique_marker}. Just acknowledge."),
    );
    assert!(output1.status.success(), "First agent run should succeed");

    // Create temp directory for mock editor script and verification file
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let verify_file = temp_dir.path().join("editor-content.txt");

    // Create mock editor that saves the initial content and exits
    let editor_path = create_mock_editor_exit(temp_dir.path(), &verify_file);

    // Second run: resume in interactive mode with PTY
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

    let sandbox_bin = assert_cmd::cargo::cargo_bin!("sandbox");

    let mut cmd = CommandBuilder::new(&sandbox_bin);
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
        MODEL,
        "--cache",
        cache_dir.to_str().unwrap(),
        "--continue=0",
    ]);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    // Wait for the mock editor to run and capture the content
    std::thread::sleep(Duration::from_secs(2));

    // After editor exits with empty input, agent prompts "Exit? [Y/n]"
    // Send 'y' + Enter to confirm exit
    {
        let mut writer = pair.master.take_writer().expect("Failed to get writer");
        writeln!(writer, "y").expect("Failed to write to PTY");
    }

    // Wait for process to complete with timeout
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    panic!("Process did not exit within timeout");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for process: {}", e),
        }
    }

    // Check that the verification file was created and contains the history
    assert!(
        verify_file.exists(),
        "Verification file should exist (editor was invoked)"
    );

    let editor_content =
        fs::read_to_string(&verify_file).expect("Failed to read verification file");
    assert!(
        editor_content.contains(unique_marker),
        "Editor should have received chat history containing the unique marker.\nEditor content:\n{}",
        editor_content
    );
}
