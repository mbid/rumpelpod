//! Test that --dangerously-skip-permissions-workaround injects
//! PermissionRequest hooks into the container's settings.json and
//! suppresses --dangerously-skip-permissions.

use super::common::{run_claude_print_with_flags, setup_claude_test_repo};
use super::proxy::claude_proxy;

#[test]
fn skip_permissions_workaround_smoke() {
    let proxy = claude_proxy();
    let (repo, daemon) = setup_claude_test_repo(proxy);

    // Ask Claude to run a bash command -- this requires tool-use permission
    // that only the PermissionRequest hook can grant (the test harness does
    // not pass --dangerously-skip-permissions).
    let output = run_claude_print_with_flags(
        &repo,
        &daemon,
        proxy,
        "Run `echo rumpel-permissions-ok` in bash and tell me the output, nothing else.",
        "claude-haiku-4-5",
        &["--dangerously-skip-permissions-workaround"],
    );

    assert!(
        output.success,
        "rumpel claude --dangerously-skip-permissions-workaround exited with failure.\nFull output:\n{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("rumpel-permissions-ok"),
        "Claude should have executed bash and returned the echo output.\nFull output:\n{}",
        output.stdout
    );
}
