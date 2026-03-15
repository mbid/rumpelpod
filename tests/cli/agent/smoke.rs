//! Smoke tests for the agent - run with every supported model.

use std::fs;
use std::process::Command;

use rumpelpod::CommandExt;

use crate::common::{create_commit, TestRepo};
use crate::executor::{write_test_devcontainer, TestExecutor};

use super::common::run_agent_with_prompt_and_model;

// This is used as smoke test and executed with every explicitly supported model.
fn agent_reads_file(model: &str, test_name: &str) {
    let repo = TestRepo::new();

    let secret_content = "AGENT_SECRET_12345";
    fs::write(repo.path().join("secret.txt"), secret_content).expect("Failed to write secret.txt");

    Command::new("git")
        .args(["add", "secret.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add secret");

    let exec = TestExecutor::start(test_name);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let output = run_agent_with_prompt_and_model(
        &repo,
        &exec.daemon,
        "Run `cat secret.txt` and tell me what it contains.",
        model,
    );

    assert!(
        output.stdout.contains(secret_content),
        "Agent output should contain the secret content.\nstdout: {}",
        output.stdout
    );
}

#[test]
fn agent_reads_file_claude_haiku_4_5() {
    agent_reads_file("claude-haiku-4-5", "agent-smoke-haiku");
}

#[test]
fn agent_reads_file_claude_sonnet_4_5() {
    agent_reads_file("claude-sonnet-4-5", "agent-smoke-sonnet");
}

#[test]
fn agent_reads_file_claude_opus_4_5() {
    agent_reads_file("claude-opus-4-5", "agent-smoke-opus45");
}

#[test]
fn agent_reads_file_claude_opus_4_6() {
    agent_reads_file("claude-opus-4-6", "agent-smoke-opus46");
}

#[test]
fn agent_reads_file_grok_4_1_fast_reasoning() {
    agent_reads_file("grok-4-1-fast-reasoning", "agent-smoke-grok");
}

#[test]
fn agent_reads_file_gemini_2_5_flash() {
    agent_reads_file("gemini-2.5-flash", "agent-smoke-gemflash");
}

#[test]
fn agent_reads_file_gemini_3_flash_preview() {
    agent_reads_file("gemini-3-flash-preview", "agent-smoke-gem3flash");
}

#[test]
fn agent_reads_file_gemini_3_pro_preview() {
    agent_reads_file("gemini-3-pro-preview", "agent-smoke-gem3pro");
}
