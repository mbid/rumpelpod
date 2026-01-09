//! Integration tests verifying that sandbox branches appear immediately on the host
//! when a sandbox is entered (before any commits are made).

mod common;

use std::process::Command;

use common::SandboxFixture;

/// When entering a sandbox, the `sandbox/<name>` and `sandbox/<name>@<name>` branches
/// should immediately appear as remote tracking branches on the host.
///
/// This ensures the host can track sandbox branches from the moment of creation,
/// not just after the first commit triggers the post-commit hook.
#[test]
fn test_sandbox_branch_appears_on_host_immediately() {
    let fixture = SandboxFixture::new("foo");

    // Enter the sandbox (just run a simple command to ensure it's initialized)
    let output = fixture.run(&["true"]);
    assert!(
        output.status.success(),
        "Failed to enter sandbox: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check that sandbox/foo remote tracking branch exists on the host
    let output = Command::new("git")
        .current_dir(&fixture.repo.dir)
        .args(["rev-parse", "--verify", "refs/remotes/sandbox/foo"])
        .output()
        .expect("Failed to run git command");
    assert!(
        output.status.success(),
        "Expected refs/remotes/sandbox/foo to exist on host immediately after entering sandbox.\n\
         This branch should be pushed to meta.git when the sandbox is created.\n\
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check that sandbox/foo@foo remote tracking branch exists on the host
    let output = Command::new("git")
        .current_dir(&fixture.repo.dir)
        .args(["rev-parse", "--verify", "refs/remotes/sandbox/foo@foo"])
        .output()
        .expect("Failed to run git command");
    assert!(
        output.status.success(),
        "Expected refs/remotes/sandbox/foo@foo to exist on host immediately after entering sandbox.\n\
         This branch should be pushed to meta.git when the sandbox is created.\n\
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
