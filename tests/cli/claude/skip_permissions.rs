//! Test that --skip-permissions-workaround injects PreToolUse hooks
//! into the container's settings.json and suppresses
//! --dangerously-skip-permissions.

use super::common::{run_claude_print_with_flags, setup_claude_test_repo};
use super::proxy::claude_proxy;

#[test]
fn skip_permissions_workaround_smoke() {
    let proxy = claude_proxy();
    let (repo, daemon) = setup_claude_test_repo(proxy);

    let output = run_claude_print_with_flags(
        &repo,
        &daemon,
        proxy,
        "What is the capital of France? Reply with just the city name, nothing else.",
        "claude-haiku-4-5",
        &["--skip-permissions-workaround"],
    );

    assert!(
        output.success,
        "rumpel claude --skip-permissions-workaround exited with failure.\nFull output:\n{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Paris"),
        "Claude should respond with 'Paris'.\nFull output:\n{}",
        output.stdout
    );
}
