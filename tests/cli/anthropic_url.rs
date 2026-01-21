use crate::common::{build_test_image, sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH};
use indoc::formatdoc;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

#[test]
fn test_anthropic_base_url_garbage_errors() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    let config = formatdoc! {r#"
        runtime = "runc"
        image = "{image_id}"
        repo-path = "{TEST_REPO_PATH}"
        [agent]
        model = "claude-sonnet-4-5"
        anthropic-base-url = "https://invalid.example.com/v1/messages"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // We need to provide an API key so it actually tries to make a request
    // instead of failing early due to missing key and no cache.
    let mut cmd = sandbox_command(&repo, &daemon);
    cmd.args(["agent", "test"]);
    cmd.env("ANTHROPIC_API_KEY", "dummy-key");
    // Ensure we attempt network request (disable offline mode)
    cmd.env("SANDBOX_TEST_LLM_OFFLINE", "0");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn agent");
    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    writeln!(stdin, "Hello").expect("Failed to write to stdin");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("Failed to wait for agent");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Agent should fail with garbage URL. stderr: {}",
        stderr
    );
    // reqwest error might contain "dns error" or "builder error" etc.
    assert!(
        stderr.contains("Anthropic API error")
            || stderr.contains("Failed to send request to Anthropic API")
            || stderr.contains("error sending request")
            || stderr.contains("builder error")
            || stderr.contains("invalid.example.com"),
        "stderr did not contain expected error message. stderr: {}",
        stderr
    );
}

#[test]
fn test_anthropic_base_url_default_works() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Test with the default URL (explicitly set)
    let config = formatdoc! {r#"
        runtime = "runc"
        image = "{image_id}"
        repo-path = "{TEST_REPO_PATH}"
        [agent]
        model = "claude-sonnet-4-5"
        anthropic-base-url = "https://api.anthropic.com/v1/messages"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    let cache_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache");

    let mut cmd = sandbox_command(&repo, &daemon);
    cmd.args(["agent", "test", "--cache", cache_dir.to_str().unwrap()]);
    // No API key needed because we have cache
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn agent");
    let stdin = child.stdin.as_mut().expect("Failed to open stdin");
    // Use a simple prompt that should be cached
    writeln!(stdin, "Say hello").expect("Failed to write to stdin");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("Failed to wait for agent");
    assert!(
        output.status.success(),
        "Agent should succeed with default URL and cache hit. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
