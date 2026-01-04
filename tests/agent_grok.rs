//! Integration tests for the `sandbox agent` subcommand using xAI Grok models.

mod common;

use std::fs;

use common::{run_git, AgentBuilder, SandboxFixture};

const GROK_MODEL: &str = "grok-3-mini";

#[test]
fn test_grok_agent_reads_file() {
    let fixture = SandboxFixture::new("test-grok-agent");

    let secret_content = "GROK_SECRET_VALUE_12345";
    fs::write(fixture.repo.dir.join("secret.txt"), secret_content)
        .expect("Failed to write secret.txt");

    run_git(&fixture.repo.dir, &["add", "secret.txt"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    let output = AgentBuilder::new(&fixture)
        .model(GROK_MODEL)
        .run_with_prompt("Run `cat secret.txt` and tell me what it contains.");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(secret_content),
        "Agent output should contain the secret content.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_grok_agent_edits_file() {
    let fixture = SandboxFixture::new("test-grok-agent-edit");

    let original_content = "Hello World";
    fs::write(fixture.repo.dir.join("greeting.txt"), original_content)
        .expect("Failed to write greeting.txt");

    run_git(&fixture.repo.dir, &["add", "greeting.txt"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    let output = AgentBuilder::new(&fixture)
        .model(GROK_MODEL)
        .run_with_prompt("Use the edit tool to replace 'World' with 'Universe' in greeting.txt, then run `cat greeting.txt` and tell me the result.");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Universe"),
        "Agent output should contain the edited content 'Universe'.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_grok_agent_writes_file() {
    let fixture = SandboxFixture::new("test-grok-agent-write");
    let expected_content = "GROK_WRITTEN_12345";

    let output = AgentBuilder::new(&fixture)
        .model(GROK_MODEL)
        .run_with_prompt(&format!(
            "Use the write tool to create a file called newfile.txt with the content '{}', then run `cat newfile.txt` and tell me the result.",
            expected_content
        ));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(expected_content),
        "Agent output should contain the written content.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_grok_agent_handles_empty_output() {
    // Regression test: Commands like `false` produce no output but exit with non-zero status.
    // Ensure the agent handles this gracefully.
    let fixture = SandboxFixture::new("test-grok-agent-empty-error");

    let output = AgentBuilder::new(&fixture)
        .model(GROK_MODEL)
        .run_with_prompt("Run the command `false` and tell me what happened.");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The agent should NOT fail - it should complete gracefully
    assert!(
        output.status.success() || !stderr.contains("error"),
        "Agent failed unexpectedly.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}
