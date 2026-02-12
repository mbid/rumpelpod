//! Tests for conversation history management.
//!
//! These tests verify the shared history management code in `history.rs`, so we
//! only need to test with one model since the implementation is identical across
//! all providers.

use std::fs;
use std::io::{Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use crate::common::TestDaemon;

use rumpelpod::daemon::protocol::{Daemon, DaemonClient};

use super::common::{
    create_mock_editor_exit, llm_cache_dir, run_agent_expecting_picker,
    run_agent_interactive_and_args, run_agent_with_prompt, run_agent_with_prompt_and_args,
    setup_test_repo, PickerAction, DEFAULT_MODEL,
};

#[test]
fn agent_new_flag_starts_fresh_conversation() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt(&repo, &daemon, "Say 'first conversation'");
    assert!(output1.success, "First agent run should succeed");

    let output2 =
        run_agent_with_prompt_and_args(&repo, &daemon, "Say 'second conversation'", &["--new"]);
    assert!(
        output2.success,
        "Second agent run with --new should succeed"
    );

    assert!(
        !output2.stdout.contains("first conversation"),
        "--new should start fresh without previous context"
    );
}

#[test]
fn agent_continue_flag_resumes_conversation() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "Remember this secret code: ZEBRA_DELTA_9876. Just acknowledge you've memorized it.",
    );
    assert!(output1.success, "First agent run should succeed");

    let output2 = run_agent_with_prompt_and_args(
        &repo,
        &daemon,
        "What was the secret code I asked you to remember?",
        &["--continue=0"],
    );
    assert!(output2.success, "Second agent run should succeed");

    assert!(
        output2.stdout.contains("ZEBRA")
            || output2.stdout.contains("DELTA")
            || output2.stdout.contains("9876"),
        "Resumed conversation should remember the secret code.\nstdout: {}",
        output2.stdout
    );
}

#[test]
fn agent_auto_resumes_single_conversation() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "Remember: the secret code is FOXTROT_HOTEL_2468. Acknowledge.",
    );
    assert!(output1.success, "First agent run should succeed");

    let output2 = run_agent_with_prompt(&repo, &daemon, "What was the secret code I mentioned?");
    assert!(output2.success, "Second agent run should succeed");

    assert!(
        output2.stdout.contains("FOXTROT")
            || output2.stdout.contains("HOTEL")
            || output2.stdout.contains("2468"),
        "Auto-resumed conversation should remember the secret code.\nstdout: {}",
        output2.stdout
    );
}

#[test]
fn agent_errors_with_multiple_conversations_no_flag() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt(&repo, &daemon, "First conversation");
    assert!(output1.success, "First agent run should succeed");

    let output2 = run_agent_with_prompt_and_args(&repo, &daemon, "Second conversation", &["--new"]);
    assert!(output2.success, "Second agent run should succeed");

    // In interactive mode, the picker is shown. Cancel it with Ctrl+C.
    let output3 = run_agent_expecting_picker(
        &repo,
        &daemon,
        &["Which conversation am I in?"],
        PickerAction::Cancel,
    );
    assert!(
        !output3.success,
        "Agent should fail when picker is cancelled"
    );

    assert!(
        output3.stdout.contains("existing conversations")
            || output3.stdout.contains("Multiple conversations"),
        "Output should mention existing conversations.\noutput: {}",
        output3.stdout
    );
}

#[test]
fn agent_continue_out_of_range_errors() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt(&repo, &daemon, "Single conversation");
    assert!(output1.success, "First agent run should succeed");

    let output2 =
        run_agent_with_prompt_and_args(&repo, &daemon, "This should fail", &["--continue=5"]);
    assert!(
        !output2.success,
        "Agent should fail with out-of-range conversation index"
    );

    // In interactive mode, stdout and stderr are combined
    assert!(
        output2.stdout.contains("out of range") || output2.stdout.contains("Only 1 conversation"),
        "Error should mention index out of range.\noutput: {}",
        output2.stdout
    );
}

#[test]
fn agent_continue_no_conversations_errors() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output =
        run_agent_with_prompt_and_args(&repo, &daemon, "This should fail", &["--continue=0"]);
    assert!(
        !output.success,
        "Agent should fail with --continue when no conversations exist"
    );

    // In interactive mode, stdout and stderr are combined
    assert!(
        output.stdout.contains("No conversations") || output.stdout.contains("no conversation"),
        "Error should mention no conversations exist.\noutput: {}",
        output.stdout
    );
}

#[test]
fn agent_interactive_resume_shows_history() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let unique_marker = "UNIQUE_HISTORY_MARKER_XYZ123";
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        &format!("Remember this marker: {unique_marker}. Just acknowledge."),
    );
    assert!(output1.success, "First agent run should succeed");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let verify_file = temp_dir.path().join("editor-content.txt");

    let editor_path = create_mock_editor_exit(temp_dir.path(), &verify_file);

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

    let rumpel_bin = cargo::cargo_bin!("rumpel");

    let mut cmd = CommandBuilder::new(rumpel_bin);
    cmd.cwd(repo.path());
    cmd.env(
        "RUMPELPOD_DAEMON_SOCKET",
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
        "--continue=0",
    ]);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    // Monitor output and respond to prompts instead of blind sleep,
    // since Docker Desktop on macOS can be slower to reach prompts.
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
    let timeout = Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {}
            Err(e) => panic!("Error waiting for process: {}", e),
        }

        while let Ok(s) = rx.try_recv() {
            output.push_str(&s);
        }

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

#[test]
fn agent_picker_default_selection_on_enter() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // 1. Create first conversation
    run_agent_with_prompt_and_args(
        &repo,
        &daemon,
        "Remember this color: BLUE_99. Just acknowledge.",
        &["--new"],
    );

    // 2. Create second conversation (will be most recent)
    run_agent_with_prompt_and_args(
        &repo,
        &daemon,
        "Remember this color: RED_11. Just acknowledge.",
        &["--new"],
    );

    // 3. Run interactively, press Enter at picker to select default (most recent)
    let output = run_agent_expecting_picker(
        &repo,
        &daemon,
        &["What color did I tell you?"],
        PickerAction::SelectDefault,
    );

    assert!(
        output.stdout.contains("RED_11"),
        "Agent should remember color from most recent conversation (RED_11).\nOutput:\n{}",
        output.stdout
    );
    assert!(
        !output.stdout.contains("BLUE_99"),
        "Agent should NOT remember color from older conversation (BLUE_99).\nOutput:\n{}",
        output.stdout
    );
}

#[test]
fn agent_resume_user_last_message_no_double_prefix() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    // 1. Run agent normally to create the pod and a conversation.
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "Remember this secret code: ZEBRA_DELTA_9876. Just acknowledge you've memorized it.",
    );
    assert!(output1.success, "First agent run should succeed");

    assert!(
        output1.success,
        "First run must succeed.\nOutput:\n{}",
        output1.stdout
    );

    // 2. Overwrite the conversation with one that ends in a user message.
    //    This simulates the agent being killed after saving the user message
    //    but before receiving the LLM response.
    let client = DaemonClient::new_unix(&daemon.socket_path);
    // Resolve repo path the same way the agent does (via git)
    let repo_path = {
        let repo = git2::Repository::discover(repo.path()).expect("Failed to discover repo");
        repo.workdir().expect("No workdir").to_path_buf()
    };
    let conversations = client
        .list_conversations(repo_path.clone(), "test".to_string())
        .expect("Failed to list conversations");
    assert!(
        !conversations.is_empty(),
        "Should have a conversation for repo_path={}\nOutput1:\n{}",
        repo_path.display(),
        output1.stdout,
    );
    let conv_id = conversations[0].id;

    let history = serde_json::json!([
        {
            "role": "user",
            "content": [{"type": "text", "text": "Hello there"}]
        },
        {
            "role": "assistant",
            "content": [{"type": "text", "text": "Hi! How can I help?"}]
        },
        {
            "role": "user",
            "content": [{"type": "text", "text": "PENDING_USER_MSG_7777"}]
        }
    ]);

    client
        .save_conversation(
            Some(conv_id),
            repo_path.clone(),
            "test".to_string(),
            "claude-haiku-4-5".to_string(),
            "anthropic".to_string(),
            history,
        )
        .expect("Failed to save conversation");

    // 3. Resume. The last message is from the user, so the agent offers it as
    //    an editable suffix. The mock editor has no new messages, so the suffix
    //    is submitted unchanged. The agent will fail (no cached LLM response),
    //    but user messages are printed before the LLM call.
    let output = run_agent_interactive_and_args(&repo, &daemon, &[], &["--continue=0"]);

    assert!(
        !output.stdout.contains("> >"),
        "Resumed user message should not have double '> >' prefix.\nOutput:\n{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("> PENDING_USER_MSG_7777"),
        "Output should show the resumed user message with single '>' prefix.\nOutput:\n{}",
        output.stdout
    );
}
