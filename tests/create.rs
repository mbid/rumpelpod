//! Integration tests for sandbox creation.

mod common;

use common::SandboxFixture;

/// A sandbox should only have the sandbox branch locally, not master or other branches.
///
/// When a sandbox is created, git clone creates a default branch (usually master).
/// We then create/checkout the sandbox branch, but the original default branch
/// remains. This test verifies that only the sandbox branch exists in the clone.
#[test]
fn test_sandbox_has_only_sandbox_branch() {
    let fixture = SandboxFixture::new("test-only-sandbox-branch");

    // Get list of all local branches inside the sandbox
    let output = fixture.run(&["git", "branch", "--list"]);
    assert!(
        output.status.success(),
        "Failed to list branches: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let branches_output = String::from_utf8_lossy(&output.stdout);
    let branches: Vec<&str> = branches_output
        .lines()
        .map(|line| line.trim().trim_start_matches("* ").trim())
        .filter(|line| !line.is_empty())
        .collect();

    assert_eq!(
        branches.len(),
        1,
        "Expected exactly one local branch, but found {}: {:?}",
        branches.len(),
        branches
    );

    assert_eq!(
        branches[0], fixture.name,
        "Expected only the sandbox branch '{}', but found '{}'",
        fixture.name, branches[0]
    );
}
