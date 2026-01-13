//! Smoke tests for the agent using xAI Grok models.

use std::fs;
use std::process::Command;

use sandbox::CommandExt;

use super::run_agent_with_prompt_and_model;
use crate::common::{build_test_image, write_test_sandbox_config, TestDaemon, TestRepo};

const MODEL: &str = "grok-3-mini";

/// Helper to run agent with a prompt using Grok 3 Mini.
fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
) -> std::process::Output {
    run_agent_with_prompt_and_model(repo, daemon, prompt, MODEL)
}

#[test]
fn xai_agent_reads_file() {
    let repo = TestRepo::new();

    // Create a file with secret content (must be before building image)
    let secret_content = "XAI_SECRET_42";
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
