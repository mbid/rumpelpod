//! Test that the pod name appears in the agent chat history file path.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use crate::common::{build_test_image, write_test_pod_config, TestDaemon, TestRepo};

use super::common::{llm_cache_dir, ANTHROPIC_MODEL};

/// Test that verifies the temp file path by capturing it from the mock editor.
#[test]
fn temp_file_path_contains_pod_name() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a temp directory for the mock editor script
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let path_capture_file = temp_dir.path().join("captured-path.txt");

    // Create a mock editor that:
    // 1. Saves the file path to path_capture_file (only on first invocation)
    // 2. Appends a simple command to the chat history file on first invocation
    // 3. Does nothing on subsequent invocations (to trigger exit)
    let state_file = temp_dir.path().join("editor-state.txt");
    let editor_script_path = temp_dir.path().join("mock-editor.sh");
    let script_content = format!(
        r#"#!/bin/bash
FILE="$1"
STATE_FILE="{state}"

# Check if this is the first invocation
if [ ! -f "$STATE_FILE" ]; then
    # First invocation: capture path and add command
    echo "$FILE" > "{path_capture}"
    echo "echo test" >> "$FILE"
    touch "$STATE_FILE"
fi
# Subsequent invocations: do nothing (empty input will trigger exit)
"#,
        path_capture = path_capture_file.to_string_lossy(),
        state = state_file.to_string_lossy()
    );
    fs::write(&editor_script_path, script_content).expect("Failed to write editor script");

    let perms = std::fs::Permissions::from_mode(0o755);
    fs::set_permissions(&editor_script_path, perms).expect("Failed to set script permissions");

    // Set up environment to use our mock editor
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

    let mut cmd = CommandBuilder::new("rumpel");
    cmd.cwd(repo.path());
    cmd.env(
        "RUMPELPOD_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.env("EDITOR", editor_script_path.to_str().unwrap());
    cmd.env("RUMPELPOD_TEST_DETERMINISTIC_IDS", "1");
    cmd.args([
        "agent",
        "my-test-pod",
        "--model",
        ANTHROPIC_MODEL,
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

    // Collect output and handle exit confirmation
    let mut output = String::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(60);

    loop {
        // Check if process has exited
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Drain remaining output
                while let Ok(s) = rx.try_recv() {
                    output.push_str(&s);
                }
                break;
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
            output = output.replace("Exit? [Y/n]", "Exit? [Y/n] (answered)");
            let _ = writeln!(writer, "y");
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

    // Now verify that the path capture file was created
    assert!(
        path_capture_file.exists(),
        "Mock editor should have saved the temp file path.\nAgent output:\n{}",
        output
    );

    let captured_path = fs::read_to_string(&path_capture_file)
        .expect("Failed to read captured path")
        .trim()
        .to_string();

    // Verify that the path contains the pod name
    let path = PathBuf::from(&captured_path);
    let filename = path
        .file_name()
        .expect("Path should have a filename")
        .to_string_lossy();

    assert!(
        filename.contains("my-test-pod"),
        "Temp file name should contain the pod name 'my-test-pod', but got: {}",
        filename
    );

    // Also verify the expected format: rumpelpod-chat-{pod_name}-{pid}.txt
    assert!(
        filename.starts_with("rumpelpod-chat-my-test-pod-"),
        "Temp file name should start with 'rumpelpod-chat-my-test-pod-', but got: {}",
        filename
    );

    assert!(
        filename.ends_with(".txt"),
        "Temp file name should end with '.txt', but got: {}",
        filename
    );
}
