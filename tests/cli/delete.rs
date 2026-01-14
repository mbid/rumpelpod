//! Integration tests for the `sandbox delete` subcommand.

use std::io::Write;
use std::process::Stdio;

use crate::common::{
    build_test_image, sandbox_command, write_test_sandbox_config, TestDaemon, TestRepo,
};

use super::agent::llm_cache_dir;

#[test]
fn delete_smoke_test() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First create a sandbox by entering it
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-delete", "--", "echo", "created"])
        .output()
        .expect("Failed to run sandbox enter command");

    assert!(
        output.status.success(),
        "sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Now delete the sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "test-delete"])
        .output()
        .expect("Failed to run sandbox delete command");

    assert!(
        output.status.success(),
        "sandbox delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn delete_nonexistent_sandbox_succeeds() {
    // Deleting a sandbox that doesn't exist should succeed (idempotent)
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "nonexistent"])
        .output()
        .expect("Failed to run sandbox delete command");

    assert!(
        output.status.success(),
        "sandbox delete of nonexistent sandbox failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn delete_then_recreate_same_name() {
    // After deleting a sandbox, we should be able to create a new one with the same name.
    // This verifies that all resources (container, network) are properly cleaned up.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "recyclable", "--", "echo", "first"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "first sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Delete sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "recyclable"])
        .output()
        .expect("Failed to run sandbox delete command");
    assert!(
        output.status.success(),
        "sandbox delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create sandbox with the same name again
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "recyclable", "--", "echo", "second"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "second sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Helper to run agent with a prompt, returning the output.
fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    sandbox_name: &str,
    prompt: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let cache_dir = llm_cache_dir();
    let mut cmd = sandbox_command(repo, daemon);
    cmd.args([
        "agent",
        sandbox_name,
        "--model",
        "claude-haiku-4-5",
        "--cache",
    ]);
    cmd.arg(cache_dir);
    cmd.args(extra_args);
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
fn delete_sandbox_clears_conversation_history() {
    // Deleting a sandbox should also delete all conversation history for that sandbox.
    // This test verifies that after deletion, an agent started in a recreated sandbox
    // with the same name does NOT have access to the old conversation history.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First, create a conversation and tell the agent a secret
    let unique_marker = "PELICAN_GAMMA_5555";
    let output1 = run_agent_with_prompt(
        &repo,
        &daemon,
        "history-test",
        &format!("Remember this code: {unique_marker}. Acknowledge."),
        &[],
    );
    assert!(
        output1.status.success(),
        "First agent run should succeed: {}",
        String::from_utf8_lossy(&output1.stderr)
    );

    // Delete the sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["delete", "history-test"])
        .output()
        .expect("Failed to run sandbox delete command");
    assert!(
        output.status.success(),
        "sandbox delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Now start a new agent in a sandbox with the same name and ask about the code.
    // Since the sandbox was deleted, the conversation history should be gone,
    // and the agent should NOT know the code.
    let output2 = run_agent_with_prompt(
        &repo,
        &daemon,
        "history-test",
        "Do you remember any code I asked you to remember? If so, what is it?",
        &[],
    );
    assert!(
        output2.status.success(),
        "Second agent run should succeed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        !stdout2.contains("PELICAN") && !stdout2.contains("GAMMA") && !stdout2.contains("5555"),
        "Agent should NOT remember the code after sandbox deletion.\n\
         This indicates conversation history was not deleted.\nstdout: {}",
        stdout2
    );
}
