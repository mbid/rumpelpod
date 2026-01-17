//! Integration tests for the `sandbox agent` subcommand.
//!
//! Tests are now consolidated into a single file with parametrized implementation
//! functions for each model provider: anthropic, xai, gemini.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo;
use indoc::formatdoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use sandbox::CommandExt;
use tempfile::TempDir;

use crate::common::{
    build_test_image, create_commit, sandbox_command, write_test_sandbox_config, TestDaemon,
    TestRepo,
};

const ANTHROPIC_MODEL: &str = "claude-haiku-4-5";
const XAI_MODEL: &str = "grok-3-mini";
const GEMINI_MODEL: &str = "gemini-2.5-flash";

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

/// Set up a basic test repo with sandbox config.
fn setup_test_repo() -> TestRepo {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);
    repo
}

/// Create a mock editor script that saves original content for verification
/// and exits immediately (simulating user not typing anything = empty input = exit).
fn create_mock_editor_exit(script_dir: &Path, verify_file: &Path) -> PathBuf {
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

// ============================================================================
// Basic agent functionality tests
// ============================================================================

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
fn agent_reads_file_anthropic() {
    agent_reads_file(ANTHROPIC_MODEL);
}

#[test]
fn agent_reads_file_xai() {
    agent_reads_file(XAI_MODEL);
}

#[test]
fn agent_reads_file_gemini() {
    agent_reads_file(GEMINI_MODEL);
}

fn agent_edits_file(model: &str) {
    let repo = TestRepo::new();

    let original_content = "Hello World";
    fs::write(repo.path().join("greeting.txt"), original_content)
        .expect("Failed to write greeting.txt");

    Command::new("git")
        .args(["add", "greeting.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add greeting");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Use the edit tool to replace 'World' with 'Universe' in greeting.txt, then run `cat greeting.txt` and tell me the result.",
        model,
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
fn agent_edits_file_anthropic() {
    agent_edits_file(ANTHROPIC_MODEL);
}

#[test]
fn agent_edits_file_xai() {
    agent_edits_file(XAI_MODEL);
}

#[test]
fn agent_edits_file_gemini() {
    agent_edits_file(GEMINI_MODEL);
}

fn agent_writes_file(model: &str) {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let expected_content = "WRITTEN_BY_AGENT_12345";

    let output = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        &format!(
            "Run `echo '{expected_content}' > newfile.txt` \
             then run `cat newfile.txt` and tell me the result."
        ),
        model,
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
fn agent_writes_file_anthropic() {
    agent_writes_file(ANTHROPIC_MODEL);
}

#[test]
fn agent_writes_file_xai() {
    agent_writes_file(XAI_MODEL);
}

#[test]
fn agent_writes_file_gemini() {
    agent_writes_file(GEMINI_MODEL);
}

fn agent_web_search(model: &str, extra_args: &[&str]) {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        model,
        extra_args,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2025-11-12"),
        "Agent should find that the last US penny was minted on 2025-11-12.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_web_search_anthropic() {
    // Default should be enabled, so no flags needed
    agent_web_search(ANTHROPIC_MODEL, &[]);
}

#[test]
fn agent_web_search_anthropic_explicit_enable() {
    agent_web_search(ANTHROPIC_MODEL, &["--enable-anthropic-websearch"]);
}

#[test]
fn agent_web_search_xai() {
    agent_web_search(XAI_MODEL, &[]);
}

#[test]
fn agent_web_search_gemini() {
    agent_web_search(GEMINI_MODEL, &[]);
}

#[test]
fn agent_web_search_disabled_anthropic() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The agent should refuse or fail to find the info.
    // Based on previous failure, it says "I don't have the ability to search the web".
    assert!(
        stdout.contains("don't have the ability to search the web")
            || stdout.contains("cannot search the web")
            || !stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled.\nstdout: {}",
        stdout
    );
}

#[test]
fn agent_web_search_anthropic_config_disable_works() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Disable websearch in config
    let config_path = repo.path().join(".sandbox.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    let daemon = TestDaemon::start();

    // Run without CLI flag - should be disabled by config
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &[],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("don't have the ability to search the web") || 
        stdout.contains("cannot search the web") ||
        !stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled via config.\nstdout: {}",
        stdout
    );
}

#[test]
fn agent_web_search_anthropic_config_disable_cli_enable() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Disable websearch in config
    let config_path = repo.path().join(".sandbox.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = false\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    let daemon = TestDaemon::start();

    // Run WITH enable CLI flag - should be enabled despite config
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &["--enable-anthropic-websearch"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2025-11-12"),
        "Agent should find the date when web search is enabled via CLI overriding config.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_web_search_anthropic_flags_conflict() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // --enable AND --disable -> should fail with conflict error
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Test",
        ANTHROPIC_MODEL,
        &["--enable-anthropic-websearch", "--disable-anthropic-websearch"],
    );

    assert!(
        !output.status.success(),
        "Agent should fail when conflicting flags are provided"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("argument '--enable-anthropic-websearch' cannot be used with '--disable-anthropic-websearch'") ||
        stderr.contains("argument '--disable-anthropic-websearch' cannot be used with '--enable-anthropic-websearch'"),
        "Error should mention conflicting arguments.\nstderr: {}",
        stderr
    );
}

#[test]
fn agent_web_search_anthropic_config_enable_cli_disable() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Enable websearch in config
    let config_path = repo.path().join(".sandbox.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("Failed to read config");
    config.push_str("\n[agent]\nanthropic-websearch = true\n");
    std::fs::write(&config_path, config).expect("Failed to update config");

    let daemon = TestDaemon::start();

    // Run WITH disable CLI flag
    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Search the web: When was the last US penny minted? Answer with just the date in yyyy-mm-dd format.",
        ANTHROPIC_MODEL,
        &["--disable-anthropic-websearch"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("don't have the ability to search the web")
            || stdout.contains("cannot search the web")
            || !stdout.contains("2025-11-12"),
        "Agent should NOT find the date when web search is disabled via CLI override.\nstdout: {}",
        stdout
    );
}

fn agent_handles_command_with_empty_output_and_nonzero_exit(model: &str) {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Run the command `false` and tell me what happened.",
        model,
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("content cannot be empty"),
        "Agent failed with empty content error.\nstderr: {}",
        stderr
    );
}

#[test]
fn agent_handles_command_with_empty_output_and_nonzero_exit_anthropic() {
    agent_handles_command_with_empty_output_and_nonzero_exit(ANTHROPIC_MODEL);
}

#[test]
fn agent_handles_command_with_empty_output_and_nonzero_exit_xai() {
    agent_handles_command_with_empty_output_and_nonzero_exit(XAI_MODEL);
}

#[test]
fn agent_handles_command_with_empty_output_and_nonzero_exit_gemini() {
    agent_handles_command_with_empty_output_and_nonzero_exit(GEMINI_MODEL);
}

fn agent_large_file_output(model: &str) {
    let repo = TestRepo::new();

    let large_content = "x".repeat(35000);
    fs::write(repo.path().join("large.txt"), &large_content).expect("Failed to write large.txt");

    Command::new("git")
        .args(["add", "large.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add large file");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Run exactly one tool: `cat large.txt`. After that single tool call, stop immediately and tell me what you observed. Do not run any other tools.",
        model,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/agent/bash-output-"),
        "Agent should report that output was saved to a file.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_large_file_output_anthropic() {
    agent_large_file_output(ANTHROPIC_MODEL);
}

#[test]
fn agent_large_file_output_xai() {
    agent_large_file_output(XAI_MODEL);
}

#[test]
fn agent_large_file_output_gemini() {
    agent_large_file_output(GEMINI_MODEL);
}

// Conversation history tests

fn agent_new_flag_starts_fresh_conversation(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 =
        run_agent_with_prompt_and_model(&repo, &daemon, "Say 'first conversation'", model);
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Say 'second conversation'",
        model,
        &["--new"],
    );
    assert!(
        output2.status.success(),
        "Second agent run with --new should succeed"
    );

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        !stdout2.contains("first conversation"),
        "--new should start fresh without previous context"
    );
}

#[test]
fn agent_new_flag_starts_fresh_conversation_anthropic() {
    agent_new_flag_starts_fresh_conversation(ANTHROPIC_MODEL);
}

#[test]
fn agent_new_flag_starts_fresh_conversation_xai() {
    agent_new_flag_starts_fresh_conversation(XAI_MODEL);
}

#[test]
fn agent_new_flag_starts_fresh_conversation_gemini() {
    agent_new_flag_starts_fresh_conversation(GEMINI_MODEL);
}

fn agent_continue_flag_resumes_conversation(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Remember this secret code: ZEBRA_DELTA_9876. Just acknowledge you've memorized it.",
        model,
    );
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "What was the secret code I asked you to remember?",
        model,
        &["--continue=0"],
    );
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(output2.status.success(), "Second agent run should succeed");

    assert!(
        stdout2.contains("ZEBRA") || stdout2.contains("DELTA") || stdout2.contains("9876"),
        "Resumed conversation should remember the secret code.\nstdout: {}\nstderr: {}",
        stdout2,
        stderr2
    );
}

#[test]
fn agent_continue_flag_resumes_conversation_anthropic() {
    agent_continue_flag_resumes_conversation(ANTHROPIC_MODEL);
}

#[test]
fn agent_continue_flag_resumes_conversation_xai() {
    agent_continue_flag_resumes_conversation(XAI_MODEL);
}

#[test]
fn agent_continue_flag_resumes_conversation_gemini() {
    agent_continue_flag_resumes_conversation(GEMINI_MODEL);
}

fn agent_auto_resumes_single_conversation(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "Remember: the secret code is FOXTROT_HOTEL_2468. Acknowledge.",
        model,
    );
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        "What was the secret code I mentioned?",
        model,
    );
    assert!(output2.status.success(), "Second agent run should succeed");

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("FOXTROT") || stdout2.contains("HOTEL") || stdout2.contains("2468"),
        "Auto-resumed conversation should remember the secret code.\nstdout: {}",
        stdout2
    );
}

#[test]
fn agent_auto_resumes_single_conversation_anthropic() {
    agent_auto_resumes_single_conversation(ANTHROPIC_MODEL);
}

#[test]
fn agent_auto_resumes_single_conversation_xai() {
    agent_auto_resumes_single_conversation(XAI_MODEL);
}

#[test]
fn agent_auto_resumes_single_conversation_gemini() {
    agent_auto_resumes_single_conversation(GEMINI_MODEL);
}

fn agent_errors_with_multiple_conversations_no_flag(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(&repo, &daemon, "First conversation", model);
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "Second conversation",
        model,
        &["--new"],
    );
    assert!(output2.status.success(), "Second agent run should succeed");

    let output3 =
        run_agent_with_prompt_and_model(&repo, &daemon, "Which conversation am I in?", model);
    assert!(
        !output3.status.success(),
        "Agent should fail when multiple conversations exist without flags"
    );

    let stderr3 = String::from_utf8_lossy(&output3.stderr);
    assert!(
        stderr3.contains("Multiple conversations") || stderr3.contains("--continue"),
        "Error should mention multiple conversations.\nstderr: {}",
        stderr3
    );
}

#[test]
fn agent_errors_with_multiple_conversations_no_flag_anthropic() {
    agent_errors_with_multiple_conversations_no_flag(ANTHROPIC_MODEL);
}

#[test]
fn agent_errors_with_multiple_conversations_no_flag_xai() {
    agent_errors_with_multiple_conversations_no_flag(XAI_MODEL);
}

#[test]
fn agent_errors_with_multiple_conversations_no_flag_gemini() {
    agent_errors_with_multiple_conversations_no_flag(GEMINI_MODEL);
}

fn agent_continue_out_of_range_errors(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output1 = run_agent_with_prompt_and_model(&repo, &daemon, "Single conversation", model);
    assert!(output1.status.success(), "First agent run should succeed");

    let output2 = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "This should fail",
        model,
        &["--continue=5"],
    );
    assert!(
        !output2.status.success(),
        "Agent should fail with out-of-range conversation index"
    );

    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("out of range") || stderr2.contains("Only 1 conversation"),
        "Error should mention index out of range.\nstderr: {}",
        stderr2
    );
}

#[test]
fn agent_continue_out_of_range_errors_anthropic() {
    agent_continue_out_of_range_errors(ANTHROPIC_MODEL);
}

#[test]
fn agent_continue_out_of_range_errors_xai() {
    agent_continue_out_of_range_errors(XAI_MODEL);
}

#[test]
fn agent_continue_out_of_range_errors_gemini() {
    agent_continue_out_of_range_errors(GEMINI_MODEL);
}

fn agent_continue_no_conversations_errors(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt_model_and_args(
        &repo,
        &daemon,
        "This should fail",
        model,
        &["--continue=0"],
    );
    assert!(
        !output.status.success(),
        "Agent should fail with --continue when no conversations exist"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No conversations") || stderr.contains("no conversation"),
        "Error should mention no conversations exist.\nstderr: {}",
        stderr
    );
}

#[test]
fn agent_continue_no_conversations_errors_anthropic() {
    agent_continue_no_conversations_errors(ANTHROPIC_MODEL);
}

#[test]
fn agent_continue_no_conversations_errors_xai() {
    agent_continue_no_conversations_errors(XAI_MODEL);
}

#[test]
fn agent_continue_no_conversations_errors_gemini() {
    agent_continue_no_conversations_errors(GEMINI_MODEL);
}

fn agent_interactive_resume_shows_history(model: &str) {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();

    let unique_marker = "UNIQUE_HISTORY_MARKER_XYZ123";
    let output1 = run_agent_with_prompt_and_model(
        &repo,
        &daemon,
        &format!("Remember this marker: {unique_marker}. Just acknowledge."),
        model,
    );
    assert!(output1.status.success(), "First agent run should succeed");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let verify_file = temp_dir.path().join("editor-content.txt");

    let editor_path = create_mock_editor_exit(temp_dir.path(), &verify_file);

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

    let sandbox_bin = cargo::cargo_bin!("sandbox");

    let mut cmd = CommandBuilder::new(&sandbox_bin);
    cmd.cwd(repo.path());
    cmd.env(
        "SANDBOX_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.env("EDITOR", editor_path.to_str().unwrap());
    cmd.args([
        "agent",
        "test",
        "--model",
        model,
        "--cache",
        cache_dir.to_str().unwrap(),
        "--continue=0",
    ]);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    thread::sleep(Duration::from_secs(2));

    {
        let mut writer = pair.master.take_writer().expect("Failed to get writer");
        writeln!(writer, "y").expect("Failed to write to PTY");
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    panic!("Process did not exit within timeout");
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for process: {}", e),
        }
    }

    assert!(
        verify_file.exists(),
        "Verification file should exist (editor was invoked)"
    );

    let editor_content =
        fs::read_to_string(&verify_file).expect("Failed to read verification file");
    assert!(
        editor_content.contains(unique_marker),
        "Editor should have received chat history containing the unique marker.\nEditor content:\n{}",
        editor_content
    );
}

#[test]
fn agent_interactive_resume_shows_history_anthropic() {
    agent_interactive_resume_shows_history(ANTHROPIC_MODEL);
}

#[test]
fn agent_interactive_resume_shows_history_xai() {
    agent_interactive_resume_shows_history(XAI_MODEL);
}

#[test]
fn agent_interactive_resume_shows_history_gemini() {
    agent_interactive_resume_shows_history(GEMINI_MODEL);
}
