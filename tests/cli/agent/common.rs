//! Common utilities for agent integration tests.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::common::{
    build_test_image, sandbox_command, write_test_sandbox_config, TestDaemon, TestRepo,
};

pub const ANTHROPIC_MODEL: &str = "claude-haiku-4-5";
pub const XAI_MODEL: &str = "grok-3-mini";
pub const GEMINI_MODEL: &str = "gemini-2.5-flash";

/// Get the llm-cache directory path.
pub fn llm_cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache")
}

/// Helper to run agent with a prompt via stdin using a specific model.
pub fn run_agent_with_prompt_and_model(
    repo: &TestRepo,
    daemon: &TestDaemon,
    prompt: &str,
    model: &str,
) -> std::process::Output {
    run_agent_with_prompt_model_and_args(repo, daemon, prompt, model, &[])
}

/// Helper to run agent with a prompt, model, and extra CLI arguments.
pub fn run_agent_with_prompt_model_and_args(
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

/// Set up a basic test repo with sandbox config.
pub fn setup_test_repo() -> TestRepo {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);
    repo
}

/// Create a mock editor script that saves original content for verification
/// and exits immediately (simulating user not typing anything = empty input = exit).
pub fn create_mock_editor_exit(script_dir: &Path, verify_file: &Path) -> PathBuf {
    use indoc::formatdoc;

    let script_path = script_dir.join("mock-editor.sh");
    let verify_file_str = verify_file.to_string_lossy();
    let script_content = formatdoc! {r#"
        #!/bin/bash
        FILE="$1"
        cp "$FILE" "{verify_file_str}"
    "#};
    fs::write(&script_path, &script_content).expect("Failed to write mock editor script");

    let perms = std::fs::Permissions::from_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("Failed to set script permissions");

    script_path
}
