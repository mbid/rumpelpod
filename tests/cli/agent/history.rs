//! Tests for conversation history management.
//!
//! These tests verify the shared history management code in `history.rs`, so we
//! only need to test with one model (Haiku) since the implementation is identical
//! across all providers.

use std::fs;
use std::io::{Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use crate::common::TestDaemon;

use super::common::{
    create_mock_editor_exit, llm_cache_dir, run_agent_with_prompt_and_model,
    run_agent_with_prompt_model_and_args, setup_test_repo, ANTHROPIC_MODEL,
};

#[test]
fn agent_new_flag_starts_fresh_conversation() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Say 'first conversation'",
        ANTHROPIC_MODEL,
    );
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Say 'second conversation'",
        ANTHROPIC_MODEL,
        &["--new"],
    );
    assert!(
        output2.status.success(),
        "Second agent run with --new should succeed"
    );

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        !stdout2.contains("first conversation"),
        "--new should start fresh without previous context"
    );
}

#[test]
fn agent_continue_flag_resumes_conversation() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Remember this secret code: ZEBRA_DELTA_9876. Just acknowledge you've memorized it.",
        ANTHROPIC_MODEL,
    );
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "What was the secret code I asked you to remember?",
        ANTHROPIC_MODEL,
        &["--continue=0"],
    );
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(output2.status.success(), "Second agent run should succeed");

    assert!(
        stdout2.contains("ZEBRA") || stdout2.contains("DELTA") || stdout2.contains("9876"),
        "Resumed conversation should remember the secret code.\nstdout: {}\nstderr: {}",
        stdout2,
        stderr2
    );
}

#[test]
fn agent_auto_resumes_single_conversation() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Remember: the secret code is FOXTROT_HOTEL_2468. Acknowledge.",
        ANTHROPIC_MODEL,
    );
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "What was the secret code I mentioned?",
        ANTHROPIC_MODEL,
    );
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
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 =
        run_agent_with_prompt_and_model(&repo, &daemon, "First conversation", ANTHROPIC_MODEL);
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Second conversation",
        ANTHROPIC_MODEL,
        &["--new"],
    );
    assert!(output2.status.success(), "Second agent run should succeed");

    let output3 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Which conversation am I in?",
        ANTHROPIC_MODEL,
    );
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
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 =
        run_agent_with_prompt_and_model(&repo, &daemon, "Single conversation", ANTHROPIC_MODEL);
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "This should fail",
        ANTHROPIC_MODEL,
        &["--continue=5"],
    );
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
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "This should fail",
        ANTHROPIC_MODEL,
        &["--continue=0"],
    );
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

#[test]
fn agent_interactive_resume_shows_history() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let unique_marker = "UNIQUE_HISTORY_MARKER_XYZ123";
    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        &format!("Remember this marker: {unique_marker}. Just acknowledge."),
        ANTHROPIC_MODEL,
    );
    assert!(output1.status.success(), "First agent run should succeed");

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
        ANTHROPIC_MODEL,
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
    run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Remember this color: BLUE_99. Just acknowledge.",
        ANTHROPIC_MODEL,
        &["--new"],
    );

    // 2. Create second conversation (will be most recent)
    run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Remember this color: RED_11. Just acknowledge.",
        ANTHROPIC_MODEL,
        &["--new"],
    );

    // 3. Run interactively, press Enter at picker
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
    let mut cmd = CommandBuilder::new(&sandbox_bin);
    cmd.cwd(repo.path());
    cmd.env(
        "SANDBOX_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.args(["agent", "test", "--model", ANTHROPIC_MODEL]);

    let _child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn interactive agent");

    let mut reader = pair
        .master
        .try_clone_reader()
        .expect("Failed to clone reader");
    let mut writer = pair.master.take_writer().expect("Failed to get writer");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1024];
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

    // Read until we see the picker prompt
    let mut output_acc = String::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(30);
    let mut prompted = false;

    while start.elapsed() < timeout {
        while let Ok(s) = rx.try_recv() {
            output_acc.push_str(&s);
        }
        if output_acc.contains("Select [0-") && output_acc.contains("default 0") {
            prompted = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        prompted,
        "Did not see selection prompt in time. Output:\n{}",
        output_acc
    );

    // Press Enter
    writeln!(writer).expect("Failed to send newline");

    // Now the agent should be running in the selected conversation (RED_11).
    // We send a question and check the response.
    // Wait for the next prompt "You: " or similar if it exists, or just wait a bit.
    thread::sleep(Duration::from_secs(2));
    writeln!(writer, "What color did I tell you?").expect("Failed to send question");

    // Check for RED_11 in output
    let mut saw_red = false;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        while let Ok(s) = rx.try_recv() {
            output_acc.push_str(&s);
        }
        if output_acc.contains("RED_11") {
            saw_red = true;
            break;
        }
        if output_acc.contains("BLUE_99") {
            panic!("Picked wrong conversation (BLUE_99 instead of RED_11)");
        }
        thread::sleep(Duration::from_millis(100));
    }

    assert!(
        saw_red,
        "Agent did not remember the correct color (RED_11). Output:\n{}",
        output_acc
    );
}
