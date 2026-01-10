//! Integration tests for the git gateway functionality.
//!
//! Tests verify that commits and branches are synchronized between the host
//! repository and the gateway bare repository, and that sandboxes can access
//! the gateway via HTTP.

use std::path::Path;
use std::process::Command;

use sandbox::CommandExt;

use crate::common::{
    build_test_image, sandbox_command, write_test_sandbox_config, TestDaemon, TestRepo,
};

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

    // Create additional branches before building the image
    create_branch(repo.path(), "feature-a");
    create_commit(repo.path(), "Feature A commit");

    create_branch(repo.path(), "feature-b");
    create_commit(repo.path(), "Feature B commit");

    checkout_branch(repo.path(), "master");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

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
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

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

    // Create a branch before building the image
    create_branch(repo.path(), "to-delete");
    create_commit(repo.path(), "Branch commit");
    checkout_branch(repo.path(), "master");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

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

#[test]
fn gateway_http_remotes_configured_in_container() {
    // Test that the container gets "host" and "sandbox" remotes pointing to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", "http-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Check that remotes are configured
    let remotes_output = sandbox_command(&repo, &daemon)
        .args(["enter", "http-test", "--", "git", "remote"])
        .success()
        .expect("Failed to get git remotes");

    let remotes = String::from_utf8_lossy(&remotes_output);

    assert!(
        remotes.contains("host"),
        "Container should have 'host' remote, got: {}",
        remotes
    );
    assert!(
        remotes.contains("sandbox"),
        "Container should have 'sandbox' remote, got: {}",
        remotes
    );
}

#[test]
fn gateway_http_fetch_works_from_container() {
    // Test that a container can actually fetch from the gateway via HTTP
    let repo = TestRepo::new();

    // Create a branch with a commit before building the image
    create_branch(repo.path(), "test-branch");
    create_commit(repo.path(), "Test commit for fetch");
    let test_commit = get_branch_commit(repo.path(), "HEAD").unwrap();
    checkout_branch(repo.path(), "master");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox (this sets up gateway and pushes branches)
    sandbox_command(&repo, &daemon)
        .args(["enter", "fetch-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Fetch from host remote inside the container
    sandbox_command(&repo, &daemon)
        .args(["enter", "fetch-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch from host remote");

    // Verify the fetched commit matches
    let fetched_commit_output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "fetch-test",
            "--",
            "git",
            "rev-parse",
            "host/test-branch",
        ])
        .success()
        .expect("Failed to get fetched commit");

    let fetched_commit = String::from_utf8_lossy(&fetched_commit_output)
        .trim()
        .to_string();

    assert_eq!(
        fetched_commit, test_commit,
        "Fetched commit should match host commit"
    );
}

#[test]
fn gateway_http_fetch_new_commits_after_create() {
    // Test that new commits made on host after container creation can be fetched
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox first
    sandbox_command(&repo, &daemon)
        .args(["enter", "new-commits-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Initial fetch
    sandbox_command(&repo, &daemon)
        .args(["enter", "new-commits-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to initial fetch");

    // Now create a new commit on host (after container exists)
    create_commit(repo.path(), "New commit after container creation");
    let new_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Fetch again - should get the new commit
    sandbox_command(&repo, &daemon)
        .args(["enter", "new-commits-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch new commits");

    // Verify we got the new commit
    let fetched_commit_output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "new-commits-test",
            "--",
            "git",
            "rev-parse",
            "host/master",
        ])
        .success()
        .expect("Failed to get fetched commit");

    let fetched_commit = String::from_utf8_lossy(&fetched_commit_output)
        .trim()
        .to_string();

    assert_eq!(
        fetched_commit, new_commit,
        "Should be able to fetch new commits made after container creation"
    );
}

#[test]
fn gateway_http_works_with_non_root_user() {
    // Test that git remotes work when running as a non-root user
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Check that remotes are configured
    let remotes_output = sandbox_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "git", "remote", "-v"])
        .success()
        .expect("Failed to get git remotes");

    let remotes = String::from_utf8_lossy(&remotes_output);

    assert!(
        remotes.contains("host"),
        "Container should have 'host' remote, got: {}",
        remotes
    );

    // Fetch should work
    sandbox_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch from host remote");
}
