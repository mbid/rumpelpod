//! Smoke tests for the agent - run with every supported model.

use std::fs;
use std::process::Command;

use sandbox::CommandExt;

use crate::common::{
    build_test_image, create_commit, write_test_sandbox_config, TestDaemon, TestRepo,
};

use super::common::run_agent_with_prompt_and_model;

// This is used as smoke test and executed with every explicitly supported model.
fn agent_reads_file(model: &str) {
    let repo = TestRepo::new();

    let secret_content = "AGENT_SECRET_12345";
    fs::write(repo.path().join("secret.txt"), secret_content).expect("Failed to write secret.txt");

    Command::new("git")
        .args(["add", "secret.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add secret");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Run `cat secret.txt` and tell me what it contains.",
        model,
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
fn agent_reads_file_claude_haiku_4_5() {
    agent_reads_file("claude-haiku-4-5");
}

#[test]
fn agent_reads_file_claude_sonnet_4_5() {
    agent_reads_file("claude-sonnet-4-5");
}

#[test]
fn agent_reads_file_claude_opus_4_5() {
    agent_reads_file("claude-opus-4-5");
}

#[test]
fn agent_reads_file_grok_4() {
    agent_reads_file("grok-4");
}

#[test]
fn agent_reads_file_grok_4_1() {
    agent_reads_file("grok-4-1");
}

#[test]
fn agent_reads_file_gemini_2_5_flash() {
    agent_reads_file("gemini-2.5-flash");
}

#[test]
fn agent_reads_file_gemini_3_flash_preview() {
    agent_reads_file("gemini-3-flash-preview");
}

#[test]
fn agent_reads_file_gemini_3_pro_preview() {
    agent_reads_file("gemini-3-pro-preview");
}
