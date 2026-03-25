use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use indoc::formatdoc;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

#[test]
fn test_anthropic_base_url_default_works() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "anthropic-url-default");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");

    // Test with the default URL (explicitly set)
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
        anthropic-base-url = "https://api.anthropic.com/v1/messages"
    "#};
    fs::write(
        repo.path().join(".rumpelpod.toml"),
        format!("{}\n{config}", executor.toml),
    )
    .expect("Failed to write .rumpelpod.toml");

    let cache_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("llm-cache");

    let mut cmd = pod_command(&repo, &daemon);
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
