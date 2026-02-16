//! Smoke test: verify a simple prompt reaches the Claude CLI inside the
//! container, gets a response via the caching proxy, and exits cleanly.

use super::common::{run_claude_print, setup_claude_test_repo};
use super::proxy::claude_proxy;

#[test]
fn claude_smoke() {
    let proxy = claude_proxy();
    let (repo, daemon) = setup_claude_test_repo(proxy);

    let output = run_claude_print(
        &repo,
        &daemon,
        proxy,
        "What is the capital of France? Reply with just the city name, nothing else.",
        "claude-haiku-4-5",
    );

    assert!(
        output.success,
        "rumpel claude exited with failure.\nFull output:\n{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Paris"),
        "Claude should respond with 'Paris'.\nFull output:\n{}",
        output.stdout
    );
}
