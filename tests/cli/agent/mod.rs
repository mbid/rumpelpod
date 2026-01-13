//! Integration tests for the `sandbox agent` subcommand.
//!
//! Tests are organized by model provider:
//! - `anthropic`: Tests for Claude models (haiku, sonnet, opus)
//! - `xai`: Tests for Grok models
//! - `gemini`: Tests for Google Gemini models

mod anthropic;
mod gemini;
mod xai;

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use crate::common::{sandbox_command, TestDaemon, TestRepo};

/// Get the llm-cache directory path.
pub(super) fn llm_cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache")
}

/// Helper to run agent with a prompt via stdin using a specific model.
fn run_agent_with_prompt_and_model(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
    model: &str,
) -> std::process::Output {
    run_agent_with_prompt_model_and_args(repo, daemon, prompt, model, &[])
}

/// Helper to run agent with a prompt, model, and extra CLI arguments.
fn run_agent_with_prompt_model_and_args(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
    model: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let cache_dir = llm_cache_dir();
    let mut cmd = sandbox_command(repo, daemon);
    cmd.args(["agent", "test", "--model", model, "--cache"]);
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
