//! Smoke tests for the agent using Google Gemini models.

use std::fs;
use std::process::Command;

use sandbox::CommandExt;

use super::run_agent_with_prompt_and_model;
use crate::common::{build_test_image, write_test_sandbox_config, TestDaemon, TestRepo};

const MODEL: &str = "gemini-2.5-flash";

/// Helper to run agent with a prompt using Gemini 2.5 Flash.
fn run_agent_with_prompt(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
) -> std::process::Output {
    run_agent_with_prompt_and_model(repo, daemon, prompt, MODEL)
}

#[test]
fn gemini_agent_reads_file() {
    let repo = TestRepo::new();

    // Create a file with secret content (must be before building image)
    let secret_content = "GEMINI_SECRET_99";
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
#[should_panic(expected = "2025-11-12")]
fn gemini_agent_web_search_not_supported() {
    // Gemini agent doesn't have web search enabled - combining google_search with
    // function_declarations is only supported by the Live API.
    // This test verifies that the agent cannot answer questions requiring web search.
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // This will panic because the output won't contain the correct date (2025-11-12)
    // since Gemini can't search the web for this information.
    assert!(
        stdout.contains("2025-11-12"),
        "Agent should find that the last US penny was minted on 2025-11-12.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}
