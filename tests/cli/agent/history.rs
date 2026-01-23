//! Tests for conversation history management.
//!
//! These tests verify the shared history management code in `history.rs`, so we
//! only need to test with one model since the implementation is identical across
//! all providers.

use std::fs;
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use crate::common::TestDaemon;

use super::common::{
    create_mock_editor_exit, llm_cache_dir, run_agent_expecting_picker, run_agent_with_prompt,
    run_agent_with_prompt_and_args, setup_test_repo, PickerAction, DEFAULT_MODEL,
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
        "--continue=0",
    ]);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    thread::sleep(Duration::from_secs(2));

    {
        let mut writer = pair.master.take_writer().expect("Failed to get writer");
        writeln!(writer, "y").expect("Failed to write to PTY");
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    panic!("Process did not exit within timeout");
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for process: {}", e),
        }
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
