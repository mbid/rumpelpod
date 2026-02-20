//! Smoke test: verify a simple prompt reaches the Claude CLI inside the
//! container and produces a visible response via the caching proxy.

use super::common::{setup_claude_test_repo, ClaudeSession};
use super::proxy::claude_proxy;

#[test]
fn claude_smoke() {
    let proxy = claude_proxy();
    let (repo, daemon) = setup_claude_test_repo(proxy);

    let mut session = ClaudeSession::spawn(&repo, &daemon, proxy, "claude-haiku-4-5", &[]);

    session.wait_for("Welcome to Opus 4.6");
    session.send("What is the capital of France? Reply with just the city name, nothing else.");

    session.wait_for("Paris");
}
