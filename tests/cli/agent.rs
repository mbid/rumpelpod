//! Integration tests for the `sandbox agent` subcommand.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use sandbox::CommandExt;

use crate::common::{
    build_test_image, sandbox_command, write_test_sandbox_config, TestDaemon, TestRepo,
};

/// Get the llm-cache directory path.
fn llm_cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache")
}

/// Helper to run agent with a prompt via stdin.
fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
) -> std::process::Output {
    let cache_dir = llm_cache_dir();
    let mut cmd = sandbox_command(repo, daemon);
    cmd.args([
        "agent",
        "test",
        "--model",
        "haiku",
        "--cache",
        cache_dir.to_str().unwrap(),
    ]);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn agent");

    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    writeln!(stdin, "{}", prompt).expect("Failed to write to stdin");
    drop(child.stdin.take());

    child.wait_with_output().expect("Failed to wait for agent")
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
