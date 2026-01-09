//! Integration tests for the git gateway functionality.
//!
//! Tests verify that commits and branches are synchronized between the host
//! repository and the gateway bare repository.

use std::fs;
use std::path::Path;
use std::process::Command;

use sandbox::CommandExt;

use crate::common::{sandbox_command, TestDaemon, TestRepo};

/// Get the list of branches in a repository.
fn get_branches(repo_path: &Path) -> Vec<String> {
    let output: String = Command::new("git")
        .args(["for-each-ref", "--format=%(refname:short)", "refs/heads/"])
        .current_dir(repo_path)
        .success()
        .expect("Failed to list branches")
        .try_into()
        .unwrap();
    output
        .lines()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Get the commit hash at HEAD of a branch.
fn get_branch_commit(repo_path: &Path, branch: &str) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", branch])
        .current_dir(repo_path)
        .success()
        .ok()
        .map(|b| String::try_from(b).unwrap().trim().to_string())
}

/// Create a commit with a given message in the repo.
fn create_commit(repo_path: &Path, message: &str) {
    Command::new("git")
        .args(["commit", "--allow-empty", "-m", message])
        .current_dir(repo_path)
        .success()
        .expect("git commit failed");
}

/// Create a new branch in the repo.
fn create_branch(repo_path: &Path, name: &str) {
    Command::new("git")
        .args(["checkout", "-b", name])
        .current_dir(repo_path)
        .success()
        .expect("git checkout -b failed");
}

/// Checkout an existing branch.
fn checkout_branch(repo_path: &Path, name: &str) {
    Command::new("git")
        .args(["checkout", name])
        .current_dir(repo_path)
        .success()
        .expect("git checkout failed");
}

/// Delete a branch.
fn delete_branch(repo_path: &Path, name: &str) {
    Command::new("git")
        .args(["branch", "-D", name])
        .current_dir(repo_path)
        .success()
        .expect("git branch -D failed");
}

/// Reset current branch to a specific commit.
fn reset_to(repo_path: &Path, commit: &str) {
    Command::new("git")
        .args(["reset", "--hard", commit])
        .current_dir(repo_path)
        .success()
        .expect("git reset failed");
}

/// Get the gateway path for a repo by reading the sandbox remote URL.
fn get_gateway_path(repo_path: &Path) -> Option<std::path::PathBuf> {
    Command::new("git")
        .args(["remote", "get-url", "sandbox"])
        .current_dir(repo_path)
        .success()
        .ok()
        .map(|b| std::path::PathBuf::from(String::try_from(b).unwrap().trim()))
}

#[test]
fn gateway_initial_branches_pushed() {
    // Create repo with multiple branches before launching sandbox
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    // Create additional branches
    create_branch(repo.path(), "feature-a");
    create_commit(repo.path(), "Feature A commit");

    create_branch(repo.path(), "feature-b");
    create_commit(repo.path(), "Feature B commit");

    checkout_branch(repo.path(), "master");

    let daemon = TestDaemon::start();

    // Launch sandbox - this should set up gateway and push all branches
    sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "hello"])
        .success()
        .expect("Failed to run sandbox enter");

    // Verify gateway was created and has all branches as host/<branch>
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    assert!(gateway.exists(), "Gateway repo should exist");

    let gateway_branches = get_branches(&gateway);
    assert!(
        gateway_branches.contains(&"host/master".to_string()),
        "Gateway should have host/master, got: {:?}",
        gateway_branches
    );
    assert!(
        gateway_branches.contains(&"host/feature-a".to_string()),
        "Gateway should have host/feature-a, got: {:?}",
        gateway_branches
    );
    assert!(
        gateway_branches.contains(&"host/feature-b".to_string()),
        "Gateway should have host/feature-b, got: {:?}",
        gateway_branches
    );
}

#[test]
fn gateway_commit_updates_branch() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway
    sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let initial_commit = get_branch_commit(&gateway, "host/master");

    // Create a new commit in the host repo
    create_commit(repo.path(), "New commit");
    let new_host_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Gateway should now have the new commit on host/master
    let new_gateway_commit = get_branch_commit(&gateway, "host/master");
    assert_eq!(
        new_gateway_commit,
        Some(new_host_commit.clone()),
        "Gateway host/master should be updated after commit"
    );
    assert_ne!(
        new_gateway_commit, initial_commit,
        "Gateway commit should have changed"
    );
}

#[test]
fn gateway_force_push_updates_branch() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway
    sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Create two commits
    create_commit(repo.path(), "Commit 1");
    let commit1 = get_branch_commit(repo.path(), "HEAD").unwrap();

    create_commit(repo.path(), "Commit 2");

    // Now reset back to commit 1 (non-fast-forward)
    reset_to(repo.path(), &commit1);

    // Create a different commit (divergent history)
    create_commit(repo.path(), "Alternate commit");
    let alternate_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Gateway should have the alternate commit (force push via hook)
    let gateway_commit = get_branch_commit(&gateway, "host/master");
    assert_eq!(
        gateway_commit,
        Some(alternate_commit),
        "Gateway should have the force-pushed commit"
    );
}

#[test]
fn gateway_new_branch_with_commit_pushed() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway
    sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Verify new-feature doesn't exist yet
    let branches_before = get_branches(&gateway);
    assert!(
        !branches_before.contains(&"host/new-feature".to_string()),
        "host/new-feature should not exist yet"
    );

    // Create new branch and make a commit (triggers post-commit hook)
    create_branch(repo.path(), "new-feature");
    create_commit(repo.path(), "New feature commit");

    // Gateway should now have the new branch
    let branches_after = get_branches(&gateway);
    assert!(
        branches_after.contains(&"host/new-feature".to_string()),
        "Gateway should have host/new-feature after commit on new branch, got: {:?}",
        branches_after
    );
}

#[test]
#[should_panic = "should be deleted from gateway"]
fn gateway_branch_deletion_propagates() {
    let repo = TestRepo::new();
    fs::write(repo.path().join(".sandbox.toml"), "image = \"debian:13\"")
        .expect("Failed to write .sandbox.toml");

    // Create a branch before launching sandbox
    create_branch(repo.path(), "to-delete");
    create_commit(repo.path(), "Branch commit");
    checkout_branch(repo.path(), "master");

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway with the branch
    sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Verify branch exists in gateway
    let branches_before = get_branches(&gateway);
    assert!(
        branches_before.contains(&"host/to-delete".to_string()),
        "host/to-delete should exist before deletion"
    );

    // Delete the branch in host repo
    delete_branch(repo.path(), "to-delete");

    // Branch should be deleted from gateway
    let branches_after = get_branches(&gateway);
    assert!(
        !branches_after.contains(&"host/to-delete".to_string()),
        "host/to-delete should be deleted from gateway, got: {:?}",
        branches_after
    );
}
