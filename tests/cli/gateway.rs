//! Integration tests for the git gateway functionality.
//!
//! Tests verify that commits and branches are synchronized between the host
//! repository and the gateway bare repository, and that sandboxes can access
//! the gateway via HTTP.

use std::path::Path;
use std::process::Command;

use sandbox::CommandExt;

use crate::common::{
    build_test_image, create_commit, sandbox_command, write_test_sandbox_config,
    write_test_sandbox_config_with_network, TestDaemon, TestRepo,
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

/// Get the list of sandbox remote-tracking refs in a repository.
/// These are refs pushed by sandboxes, matching the pattern refs/remotes/sandbox/*@*
/// (excludes refs/remotes/sandbox/host/* which are created by host pushes).
fn get_sandbox_remote_refs(repo_path: &Path) -> Vec<String> {
    let output: String = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/remotes/sandbox/",
        ])
        .current_dir(repo_path)
        .success()
        .expect("Failed to list remote refs")
        .try_into()
        .unwrap();
    output
        .lines()
        .filter(|s| !s.is_empty())
        // Filter to only sandbox refs with @ (exclude host/* refs)
        .filter(|s| s.contains('@'))
        .map(String::from)
        .collect()
}

/// Get the commit hash at a remote-tracking ref.
fn get_remote_ref_commit(repo_path: &Path, ref_name: &str) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", &format!("refs/remotes/{}", ref_name)])
        .current_dir(repo_path)
        .success()
        .ok()
        .map(|b| String::try_from(b).unwrap().trim().to_string())
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

/// Amend the current commit with a new message.
fn amend_commit(repo_path: &Path, message: &str) {
    Command::new("git")
        .args(["commit", "--amend", "--allow-empty", "-m", message])
        .current_dir(repo_path)
        .success()
        .expect("git commit --amend failed");
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
fn gateway_new_branch_creation_pushed() {
    // Test that creating a new branch (without making a commit) is immediately pushed
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

    // Create new branch WITHOUT making a commit - should still be pushed
    create_branch(repo.path(), "new-feature");

    // Gateway should now have the new branch (reference-transaction hook triggers on branch creation)
    let branches_after = get_branches(&gateway);
    assert!(
        branches_after.contains(&"host/new-feature".to_string()),
        "Gateway should have host/new-feature after branch creation (no commit needed), got: {:?}",
        branches_after
    );

    // Verify the commit is the same as master
    let master_commit = get_branch_commit(repo.path(), "master").unwrap();
    let gateway_commit = get_branch_commit(&gateway, "host/new-feature");
    assert_eq!(
        gateway_commit,
        Some(master_commit),
        "New branch should point to same commit as master"
    );
}

#[test]
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
fn gateway_host_reset_propagates() {
    // Test that resetting a branch (without making a new commit) updates the gateway
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

    // Create some commits
    create_commit(repo.path(), "Commit 1");
    let commit1 = get_branch_commit(repo.path(), "HEAD").unwrap();

    create_commit(repo.path(), "Commit 2");
    let commit2 = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Verify gateway has commit2
    let gateway_commit = get_branch_commit(&gateway, "host/master");
    assert_eq!(
        gateway_commit,
        Some(commit2.clone()),
        "Gateway should have commit2"
    );

    // Reset back to commit1 (no new commit created)
    reset_to(repo.path(), &commit1);

    // Gateway should now have commit1 (reference-transaction hook triggers on reset)
    let gateway_commit_after_reset = get_branch_commit(&gateway, "host/master");
    assert_eq!(
        gateway_commit_after_reset,
        Some(commit1),
        "Gateway should have commit1 after reset"
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

#[test]
fn gateway_sandbox_commit_triggers_push() {
    // Test that creating a commit in the sandbox triggers a push to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "commit-push-test";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Create a commit in the sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Sandbox commit",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    // Get the commit hash from the sandbox
    let sandbox_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get sandbox commit");

    let sandbox_commit = String::from_utf8_lossy(&sandbox_commit_output)
        .trim()
        .to_string();

    // Check that the gateway has the branch sandbox/<sandbox_name>@<sandbox_name>
    // (sandbox is on a branch named after itself, not "master")
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("sandbox/{}@{}", sandbox_name, sandbox_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(sandbox_commit),
        "Gateway should have branch '{}' with sandbox's commit",
        expected_branch
    );
}

#[test]
fn gateway_sandbox_push_works_from_new_branch() {
    // Test that pushing from a new branch in sandbox works
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "new-branch-push";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Create a new branch and commit in the sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature-from-sandbox",
        ])
        .success()
        .expect("Failed to create branch in sandbox");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Feature commit",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    // Get the commit hash from the sandbox
    let sandbox_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get sandbox commit");

    let sandbox_commit = String::from_utf8_lossy(&sandbox_commit_output)
        .trim()
        .to_string();

    // Check that the gateway has the branch
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("sandbox/feature-from-sandbox@{}", sandbox_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(sandbox_commit),
        "Gateway should have branch '{}' with sandbox's commit",
        expected_branch
    );
}

#[test]
fn gateway_multiple_sandboxes_push_independently() {
    // Test that multiple sandboxes can push to the gateway without conflicts
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch two sandboxes
    sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-a", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox-a enter");

    sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-b", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox-b enter");

    // Create commits in both sandboxes on the same branch name
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "sandbox-a",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from A",
        ])
        .success()
        .expect("Failed to create commit in sandbox-a");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "sandbox-b",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from B",
        ])
        .success()
        .expect("Failed to create commit in sandbox-b");

    // Get commit hashes
    let commit_a_output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-a", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get sandbox-a commit");
    let commit_a = String::from_utf8_lossy(&commit_a_output).trim().to_string();

    let commit_b_output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-b", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get sandbox-b commit");
    let commit_b = String::from_utf8_lossy(&commit_b_output).trim().to_string();

    // Check that the gateway has both branches with different commits
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    let gateway_commit_a = get_branch_commit(&gateway, "sandbox/sandbox-a@sandbox-a");
    let gateway_commit_b = get_branch_commit(&gateway, "sandbox/sandbox-b@sandbox-b");

    assert_eq!(
        gateway_commit_a,
        Some(commit_a.clone()),
        "Gateway should have sandbox-a's commit"
    );
    assert_eq!(
        gateway_commit_b,
        Some(commit_b.clone()),
        "Gateway should have sandbox-b's commit"
    );

    // The commits should be different
    assert_ne!(
        commit_a, commit_b,
        "Commits from different sandboxes should be different"
    );
}

#[test]
fn gateway_sandbox_amend_triggers_push() {
    // Test that amending a commit in the sandbox triggers a push to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "amend-push-test";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Create a commit in the sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Original commit",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    let original_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get original commit");
    let original_commit = String::from_utf8_lossy(&original_commit_output)
        .trim()
        .to_string();

    // Amend the commit
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--amend",
            "--allow-empty",
            "-m",
            "Amended commit",
        ])
        .success()
        .expect("Failed to amend commit in sandbox");

    let amended_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get amended commit");
    let amended_commit = String::from_utf8_lossy(&amended_commit_output)
        .trim()
        .to_string();

    // Commits should differ
    assert_ne!(
        original_commit, amended_commit,
        "Amended commit should have different hash"
    );

    // Check that the gateway has the amended commit
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("sandbox/{}@{}", sandbox_name, sandbox_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(amended_commit),
        "Gateway should have the amended commit, not the original"
    );
}

#[test]
fn gateway_host_amend_updates_branch() {
    // Test that amending a commit on the host updates the gateway
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

    // Create a commit on the host
    create_commit(repo.path(), "Original commit");
    let original_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Amend the commit
    amend_commit(repo.path(), "Amended commit");
    let amended_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    assert_ne!(
        original_commit, amended_commit,
        "Amended commit should have different hash"
    );

    // Gateway should have the amended commit
    let gateway_commit = get_branch_commit(&gateway, "host/master");
    assert_eq!(
        gateway_commit,
        Some(amended_commit),
        "Gateway should have the amended commit"
    );
}

#[test]
fn gateway_sandbox_cannot_push_to_other_sandbox_namespace() {
    // Test that sandbox-a cannot push to sandbox-b's namespace
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox-a
    sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-a", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox-a enter");

    // Launch sandbox-b and create a commit so it has a branch in the gateway
    sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-b", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox-b enter");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "sandbox-b",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from B",
        ])
        .success()
        .expect("Failed to create commit in sandbox-b");

    // Get sandbox-b's commit
    let commit_b_output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-b", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get sandbox-b commit");
    let commit_b = String::from_utf8_lossy(&commit_b_output).trim().to_string();

    // Verify sandbox-b's branch exists in gateway
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let gateway_commit_b = get_branch_commit(&gateway, "sandbox/sandbox-b@sandbox-b");
    assert_eq!(
        gateway_commit_b,
        Some(commit_b.clone()),
        "Gateway should have sandbox-b's commit"
    );

    // Now try to have sandbox-a push directly to sandbox-b's namespace
    // This should fail because of access control
    let result = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "sandbox-a",
            "--",
            "git",
            "push",
            "sandbox",
            "HEAD:refs/heads/sandbox/sandbox-b@sandbox-b",
            "--force",
        ])
        .output()
        .expect("Failed to execute push command");

    // The push should fail
    assert!(
        !result.status.success(),
        "Push to another sandbox's namespace should fail, but it succeeded"
    );

    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("sandbox 'sandbox-a' cannot push to") || stderr.contains("cannot push"),
        "Error message should mention access control, got: {}",
        stderr
    );

    // Verify sandbox-b's branch still has its original commit (not overwritten)
    let gateway_commit_b_after = get_branch_commit(&gateway, "sandbox/sandbox-b@sandbox-b");
    assert_eq!(
        gateway_commit_b_after,
        Some(commit_b),
        "sandbox-b's branch should not have been modified"
    );
}

#[test]
fn gateway_sandbox_cannot_push_to_host_namespace() {
    // Test that a sandbox cannot push to the host/* namespace
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Get host/master commit before the attack
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let host_commit_before = get_branch_commit(&gateway, "host/master");

    // Create a commit in sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "test",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Malicious commit",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    // Try to push to host/master - should be rejected
    let result = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "test",
            "--",
            "git",
            "push",
            "sandbox",
            "HEAD:refs/heads/host/master",
            "--force",
        ])
        .output()
        .expect("Failed to execute push command");

    // The push should fail
    assert!(
        !result.status.success(),
        "Push to host namespace should fail, but it succeeded"
    );

    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("cannot push to") || stderr.contains("sandbox"),
        "Error message should mention access control, got: {}",
        stderr
    );

    // Verify host/master still has its original commit
    let host_commit_after = get_branch_commit(&gateway, "host/master");
    assert_eq!(
        host_commit_after, host_commit_before,
        "host/master should not have been modified"
    );
}

#[test]
fn gateway_sandbox_can_push_to_own_namespace() {
    // Test that a sandbox can push to its own namespace (positive test)
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "my-sandbox";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Create a new branch and commit
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature",
        ])
        .success()
        .expect("Failed to create branch");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Feature commit",
        ])
        .success()
        .expect("Failed to create commit");

    // Get the commit hash
    let commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit");
    let commit = String::from_utf8_lossy(&commit_output).trim().to_string();

    // Manually push to our own namespace with explicit refspec
    let explicit_push = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "push",
            "sandbox",
            &format!("HEAD:refs/heads/sandbox/feature@{}", sandbox_name),
            "--force",
        ])
        .output()
        .expect("Failed to execute push command");

    assert!(
        explicit_push.status.success(),
        "Push to own namespace should succeed, but failed: {}",
        String::from_utf8_lossy(&explicit_push.stderr)
    );

    // Verify the branch exists with our commit
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("sandbox/feature@{}", sandbox_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(commit),
        "Gateway should have our commit on {}",
        expected_branch
    );
}

#[test]
fn gateway_sandbox_reset_triggers_push() {
    // Test that resetting in the sandbox (without making a new commit) triggers a push to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "reset-push-test";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Create two commits in the sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit 1",
        ])
        .success()
        .expect("Failed to create commit 1");

    let commit1_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit1");
    let commit1 = String::from_utf8_lossy(&commit1_output).trim().to_string();

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit 2",
        ])
        .success()
        .expect("Failed to create commit 2");

    // Verify gateway has commit2
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("sandbox/{}@{}", sandbox_name, sandbox_name);

    // Reset back to commit1 (no new commit created)
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "reset",
            "--hard",
            &commit1,
        ])
        .success()
        .expect("Failed to reset in sandbox");

    // Gateway should now have commit1 (reference-transaction hook triggers on reset)
    let gateway_commit_after_reset = get_branch_commit(&gateway, &expected_branch);
    assert_eq!(
        gateway_commit_after_reset,
        Some(commit1),
        "Gateway should have commit1 after reset"
    );
}

#[test]
fn gateway_sandbox_branch_creation_triggers_push() {
    // Test that creating a new branch (without making a commit) in the sandbox triggers a push
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "branch-create-test";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Verify branch doesn't exist yet
    let expected_branch = format!("sandbox/new-feature@{}", sandbox_name);
    let branches_before = get_branches(&gateway);
    assert!(
        !branches_before.contains(&expected_branch),
        "Branch should not exist yet"
    );

    // Get the current commit
    let current_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get current commit");
    let current_commit = String::from_utf8_lossy(&current_commit_output)
        .trim()
        .to_string();

    // Create a new branch WITHOUT making a commit
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "checkout",
            "-b",
            "new-feature",
        ])
        .success()
        .expect("Failed to create branch in sandbox");

    // Gateway should now have the new branch (reference-transaction hook triggers on branch creation)
    let branches_after = get_branches(&gateway);
    assert!(
        branches_after.contains(&expected_branch),
        "Gateway should have branch {} after creation (no commit needed), got: {:?}",
        expected_branch,
        branches_after
    );

    // Verify the commit is the same as before
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);
    assert_eq!(
        gateway_commit,
        Some(current_commit),
        "New branch should point to same commit as before"
    );
}

#[test]
fn gateway_sandbox_push_syncs_to_host_remote_ref() {
    // Test that when a sandbox pushes to gateway, it appears as a remote-tracking ref in host
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "sync-test";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Note: The sandbox branch is created and checked out on first entry, which
    // triggers a push to the gateway. This is expected behavior - sandboxes now
    // automatically sync their initial branch.
    let expected_ref = format!("sandbox/{}@{}", sandbox_name, sandbox_name);

    // Create a commit in the sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Sandbox commit",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    // Get the commit hash
    let commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit");
    let commit = String::from_utf8_lossy(&commit_output).trim().to_string();

    // Host should have the sandbox commit as a remote-tracking ref
    let refs_after = get_sandbox_remote_refs(repo.path());
    assert!(
        refs_after.contains(&expected_ref),
        "Host should have remote ref {}, got: {:?}",
        expected_ref,
        refs_after
    );

    // Verify the commit matches
    let host_commit = get_remote_ref_commit(repo.path(), &expected_ref);
    assert_eq!(
        host_commit,
        Some(commit),
        "Host remote ref should point to sandbox commit"
    );
}

#[test]
fn gateway_sandbox_branch_sync_to_host() {
    // Test that creating a new branch in sandbox syncs to host remote refs
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "branch-sync-test";

    // Launch sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Create a new branch in sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature-x",
        ])
        .success()
        .expect("Failed to create branch in sandbox");

    // Host should have the new branch as a remote-tracking ref
    let expected_ref = format!("sandbox/feature-x@{}", sandbox_name);
    let refs = get_sandbox_remote_refs(repo.path());
    assert!(
        refs.contains(&expected_ref),
        "Host should have remote ref {}, got: {:?}",
        expected_ref,
        refs
    );
}

#[test]
fn gateway_multiple_sandboxes_sync_to_host() {
    // Test that multiple sandboxes can sync independently to host remote refs
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create first sandbox and commit
    let sandbox1 = "multi-sync-1";
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox1,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from sandbox 1",
        ])
        .success()
        .expect("Failed to create commit in sandbox 1");

    let commit1_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox1, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit 1");
    let commit1 = String::from_utf8_lossy(&commit1_output).trim().to_string();

    // Create second sandbox and commit
    let sandbox2 = "multi-sync-2";
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox2,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from sandbox 2",
        ])
        .success()
        .expect("Failed to create commit in sandbox 2");

    let commit2_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox2, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit 2");
    let commit2 = String::from_utf8_lossy(&commit2_output).trim().to_string();

    // Host should have both remote refs
    let refs = get_sandbox_remote_refs(repo.path());
    let expected_ref1 = format!("sandbox/{}@{}", sandbox1, sandbox1);
    let expected_ref2 = format!("sandbox/{}@{}", sandbox2, sandbox2);

    assert!(
        refs.contains(&expected_ref1),
        "Host should have remote ref {}, got: {:?}",
        expected_ref1,
        refs
    );
    assert!(
        refs.contains(&expected_ref2),
        "Host should have remote ref {}, got: {:?}",
        expected_ref2,
        refs
    );

    // Verify commits match
    assert_eq!(
        get_remote_ref_commit(repo.path(), &expected_ref1),
        Some(commit1),
        "First sandbox remote ref should have correct commit"
    );
    assert_eq!(
        get_remote_ref_commit(repo.path(), &expected_ref2),
        Some(commit2),
        "Second sandbox remote ref should have correct commit"
    );
}

#[test]
fn gateway_sandbox_reset_syncs_to_host_via_force_push() {
    // Test that resetting in sandbox (requiring force push) syncs to host remote refs
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "force-push-test";

    // Launch sandbox and create two commits
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "First commit",
        ])
        .success()
        .expect("Failed to create first commit");

    let commit1_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit1");
    let commit1 = String::from_utf8_lossy(&commit1_output).trim().to_string();

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Second commit",
        ])
        .success()
        .expect("Failed to create second commit");

    let commit2_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit2");
    let commit2 = String::from_utf8_lossy(&commit2_output).trim().to_string();

    // Verify host has commit2
    let expected_ref = format!("sandbox/{}@{}", sandbox_name, sandbox_name);
    assert_eq!(
        get_remote_ref_commit(repo.path(), &expected_ref),
        Some(commit2.clone()),
        "Host should have commit2 before reset"
    );

    // Reset back to commit1 (requires force push to update host remote ref)
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "reset",
            "--hard",
            &commit1,
        ])
        .success()
        .expect("Failed to reset in sandbox");

    // Host remote ref should now point to commit1 (force push succeeded)
    assert_eq!(
        get_remote_ref_commit(repo.path(), &expected_ref),
        Some(commit1),
        "Host remote ref should be updated to commit1 after reset (force push)"
    );
}

#[test]
fn gateway_host_head_synced_on_setup() {
    // Test that host/HEAD is synced to the gateway when the gateway is set up
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Get the current HEAD commit before launching sandbox
    let head_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Launch sandbox - this triggers gateway setup
    sandbox_command(&repo, &daemon)
        .args(["enter", "head-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    // Verify gateway has host/HEAD
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let gateway_branches = get_branches(&gateway);
    assert!(
        gateway_branches.contains(&"host/HEAD".to_string()),
        "Gateway should have host/HEAD, got: {:?}",
        gateway_branches
    );

    // Verify host/HEAD points to the correct commit
    let gateway_head_commit = get_branch_commit(&gateway, "host/HEAD");
    assert_eq!(
        gateway_head_commit,
        Some(head_commit.clone()),
        "Gateway host/HEAD should point to the host's current HEAD"
    );
}

#[test]
fn gateway_host_head_available_in_sandbox() {
    // Test that sandbox can access host/HEAD as a remote-tracking ref
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Get the current HEAD commit
    let head_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Launch sandbox and fetch host refs
    sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-head-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch host refs");

    // Verify sandbox can resolve host/HEAD
    let sandbox_head_output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "sandbox-head-test",
            "--",
            "git",
            "rev-parse",
            "host/HEAD",
        ])
        .success()
        .expect("Failed to resolve host/HEAD in sandbox");

    let sandbox_head_commit = String::from_utf8_lossy(&sandbox_head_output)
        .trim()
        .to_string();

    assert_eq!(
        sandbox_head_commit, head_commit,
        "Sandbox should be able to resolve host/HEAD to the host's current commit"
    );
}

#[test]
fn gateway_host_head_updates_on_commit() {
    // Test that host/HEAD is updated when a new commit is made
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway
    sandbox_command(&repo, &daemon)
        .args(["enter", "head-commit-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Get initial host/HEAD commit
    let initial_head = get_branch_commit(&gateway, "host/HEAD").unwrap();

    // Make a new commit on host
    create_commit(repo.path(), "Test commit for HEAD update");
    let new_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Verify gateway's host/HEAD is updated
    let updated_head = get_branch_commit(&gateway, "host/HEAD").unwrap();

    assert_ne!(
        initial_head, updated_head,
        "host/HEAD should be updated after commit"
    );
    assert_eq!(
        updated_head, new_commit,
        "host/HEAD should point to the new commit"
    );
}

#[test]
fn gateway_host_head_updates_on_branch_switch() {
    // Test that host/HEAD is updated when switching branches
    let repo = TestRepo::new();

    // Create a feature branch with different commit
    create_branch(repo.path(), "feature");
    create_commit(repo.path(), "Feature commit");
    let feature_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    checkout_branch(repo.path(), "master");
    let master_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Sanity check: different commits
    assert_ne!(master_commit, feature_commit);

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway (currently on master)
    sandbox_command(&repo, &daemon)
        .args(["enter", "branch-switch-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Verify host/HEAD points to master commit
    assert_eq!(
        get_branch_commit(&gateway, "host/HEAD"),
        Some(master_commit.clone()),
        "host/HEAD should point to master commit initially"
    );

    // Switch to feature branch
    checkout_branch(repo.path(), "feature");

    // Verify host/HEAD now points to feature commit
    assert_eq!(
        get_branch_commit(&gateway, "host/HEAD"),
        Some(feature_commit.clone()),
        "host/HEAD should point to feature commit after branch switch"
    );

    // Sandbox should see the updated HEAD after fetch
    sandbox_command(&repo, &daemon)
        .args(["enter", "branch-switch-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch after branch switch");

    let sandbox_head_output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "branch-switch-test",
            "--",
            "git",
            "rev-parse",
            "host/HEAD",
        ])
        .success()
        .expect("Failed to resolve host/HEAD");

    let sandbox_head = String::from_utf8_lossy(&sandbox_head_output)
        .trim()
        .to_string();

    assert_eq!(
        sandbox_head, feature_commit,
        "Sandbox host/HEAD should reflect the branch switch"
    );
}

#[test]
fn gateway_host_head_works_in_detached_state() {
    // Test that host/HEAD works correctly when host is in detached HEAD state
    let repo = TestRepo::new();

    // Create a few commits to have history
    create_commit(repo.path(), "First commit");
    let first_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    create_commit(repo.path(), "Second commit");
    let second_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox to set up gateway (on master at second_commit)
    sandbox_command(&repo, &daemon)
        .args(["enter", "detached-head-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run sandbox enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Verify host/HEAD points to second_commit
    assert_eq!(
        get_branch_commit(&gateway, "host/HEAD"),
        Some(second_commit.clone()),
        "host/HEAD should point to second_commit initially"
    );

    // Checkout first commit in detached HEAD state
    Command::new("git")
        .args(["checkout", &first_commit])
        .current_dir(repo.path())
        .success()
        .expect("git checkout (detached) failed");

    // Verify host/HEAD now points to first_commit
    assert_eq!(
        get_branch_commit(&gateway, "host/HEAD"),
        Some(first_commit.clone()),
        "host/HEAD should point to first_commit in detached HEAD state"
    );

    // Sandbox should be able to fetch and resolve the detached HEAD commit
    sandbox_command(&repo, &daemon)
        .args(["enter", "detached-head-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch in detached HEAD state");

    let sandbox_head_output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "detached-head-test",
            "--",
            "git",
            "rev-parse",
            "host/HEAD",
        ])
        .success()
        .expect("Failed to resolve host/HEAD");

    let sandbox_head = String::from_utf8_lossy(&sandbox_head_output)
        .trim()
        .to_string();

    assert_eq!(
        sandbox_head, first_commit,
        "Sandbox host/HEAD should resolve to the detached HEAD commit"
    );
}

#[test]
fn gateway_primary_branch_alias_works_on_host() {
    // Test that sandbox/<name> resolves to the same commit as sandbox/<name>@<name>
    // For the alias to be created, the sandbox must be on a branch with the same name
    // as the sandbox (the "primary branch").
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "alias-test";

    // Launch sandbox - it automatically creates and checks out a branch named after
    // the sandbox (the "primary branch")
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to launch sandbox");

    // Create a commit on the primary branch
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "test commit for alias",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    // Get commit from sandbox
    let commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get sandbox HEAD");
    let sandbox_commit = String::from_utf8_lossy(&commit_output).trim().to_string();

    // Verify host has both refs pointing to the same commit
    let full_ref = format!("sandbox/{}@{}", sandbox_name, sandbox_name);
    let alias_ref = format!("sandbox/{}", sandbox_name);

    let full_ref_commit = get_remote_ref_commit(repo.path(), &full_ref);
    let alias_ref_commit = get_remote_ref_commit(repo.path(), &alias_ref);

    assert_eq!(
        full_ref_commit,
        Some(sandbox_commit.clone()),
        "Full ref sandbox/{}@{} should point to sandbox commit",
        sandbox_name,
        sandbox_name
    );
    assert_eq!(
        alias_ref_commit,
        Some(sandbox_commit),
        "Alias ref sandbox/{} should point to same commit as full ref",
        sandbox_name
    );
}

#[test]
fn gateway_alias_deleted_with_sandbox() {
    // Test that alias ref is removed when sandbox is deleted
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "delete-alias-test";

    // Launch sandbox - it automatically creates and checks out the primary branch
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to launch sandbox");

    // Create a commit on the primary branch
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "test commit",
        ])
        .success()
        .expect("Failed to create commit in sandbox");

    // Verify refs exist
    let full_ref = format!("sandbox/{}@{}", sandbox_name, sandbox_name);
    let alias_ref = format!("sandbox/{}", sandbox_name);

    assert!(
        get_remote_ref_commit(repo.path(), &full_ref).is_some(),
        "Full ref should exist before deletion"
    );
    assert!(
        get_remote_ref_commit(repo.path(), &alias_ref).is_some(),
        "Alias ref should exist before deletion"
    );

    // Delete the sandbox
    sandbox_command(&repo, &daemon)
        .args(["delete", sandbox_name])
        .success()
        .expect("Failed to delete sandbox");

    // Verify refs are removed
    assert!(
        get_remote_ref_commit(repo.path(), &full_ref).is_none(),
        "Full ref should be removed after deletion"
    );
    assert!(
        get_remote_ref_commit(repo.path(), &alias_ref).is_none(),
        "Alias ref should be removed after deletion"
    );
}

#[test]
fn gateway_alias_does_not_conflict_with_branches() {
    // Test that sandbox `alice` creating branch `bob` doesn't affect sandbox `bob`'s alias
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch sandbox `bob` - it automatically creates and checks out its primary branch
    sandbox_command(&repo, &daemon)
        .args(["enter", "bob", "--", "echo", "setup"])
        .success()
        .expect("Failed to launch bob sandbox");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "bob",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "bob commit",
        ])
        .success()
        .expect("Failed to create commit in bob sandbox");

    let bob_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", "bob", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get bob HEAD");
    let bob_commit = String::from_utf8_lossy(&bob_commit_output)
        .trim()
        .to_string();

    // Create sandbox `alice` and create a branch named `bob` with different commit
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "alice",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "alice commit",
        ])
        .success()
        .expect("Failed to create commit in alice sandbox");

    sandbox_command(&repo, &daemon)
        .args(["enter", "alice", "--", "git", "checkout", "-b", "bob"])
        .success()
        .expect("Failed to create bob branch in alice sandbox");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "alice",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "alice bob-branch commit",
        ])
        .success()
        .expect("Failed to create commit on bob branch in alice sandbox");

    let alice_bob_commit_output = sandbox_command(&repo, &daemon)
        .args(["enter", "alice", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get alice bob-branch HEAD");
    let alice_bob_commit = String::from_utf8_lossy(&alice_bob_commit_output)
        .trim()
        .to_string();

    // Verify sandbox/bob alias still points to bob's primary branch, not alice's bob branch
    let bob_alias_commit = get_remote_ref_commit(repo.path(), "sandbox/bob");
    let bob_full_commit = get_remote_ref_commit(repo.path(), "sandbox/bob@bob");
    let alice_bob_branch_commit = get_remote_ref_commit(repo.path(), "sandbox/bob@alice");

    assert_ne!(
        bob_commit, alice_bob_commit,
        "Bob and alice's bob-branch should have different commits"
    );
    assert_eq!(
        bob_alias_commit,
        Some(bob_commit.clone()),
        "sandbox/bob alias should point to bob's primary branch"
    );
    assert_eq!(
        bob_full_commit,
        Some(bob_commit),
        "sandbox/bob@bob should point to bob's commit"
    );
    assert_eq!(
        alice_bob_branch_commit,
        Some(alice_bob_commit),
        "sandbox/bob@alice should point to alice's bob-branch commit"
    );
}

#[test]
fn gateway_non_primary_branches_have_no_alias() {
    // Test that non-primary branches (feature@sandbox) don't get an alias
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "no-alias-test";

    // Launch sandbox - it automatically creates and checks out its primary branch
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to launch sandbox");

    // Create initial commit on primary branch
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "primary commit",
        ])
        .success()
        .expect("Failed to create commit on primary branch");

    // Create a feature branch
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature",
        ])
        .success()
        .expect("Failed to create feature branch");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "feature commit",
        ])
        .success()
        .expect("Failed to create commit on feature branch");

    // Verify feature@sandbox_name exists but sandbox/feature alias does not
    let feature_ref = format!("sandbox/feature@{}", sandbox_name);
    assert!(
        get_remote_ref_commit(repo.path(), &feature_ref).is_some(),
        "sandbox/feature@{} should exist",
        sandbox_name
    );
    assert!(
        get_remote_ref_commit(repo.path(), "sandbox/feature").is_none(),
        "sandbox/feature alias should not exist (only primary branches get aliases)"
    );

    // Verify primary branch alias still works
    let primary_alias_commit =
        get_remote_ref_commit(repo.path(), &format!("sandbox/{}", sandbox_name));
    let primary_full_commit = get_remote_ref_commit(
        repo.path(),
        &format!("sandbox/{}@{}", sandbox_name, sandbox_name),
    );
    assert!(
        primary_alias_commit.is_some(),
        "Primary branch alias should exist"
    );
    assert_eq!(
        primary_alias_commit, primary_full_commit,
        "Primary branch alias should point to same commit as full ref"
    );
}

#[test]
fn sandbox_has_branch_named_after_sandbox() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Enter sandbox and check the current branch name
    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "my-sandbox",
            "--",
            "git",
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .success()
        .expect("sandbox enter failed");

    let branch = String::from_utf8_lossy(&stdout).trim().to_string();
    assert_eq!(
        branch, "my-sandbox",
        "Expected branch 'my-sandbox' to be checked out, got '{}'",
        branch
    );
}

#[test]
fn sandbox_branch_points_to_host_head() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Get the host's HEAD commit
    let host_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to get host HEAD");
    let host_head = String::from_utf8_lossy(&host_head).trim().to_string();

    // Enter sandbox and get its HEAD commit
    let sandbox_head = sandbox_command(&repo, &daemon)
        .args(["enter", "test-branch", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("sandbox enter failed");
    let sandbox_head = String::from_utf8_lossy(&sandbox_head).trim().to_string();

    assert_eq!(
        sandbox_head, host_head,
        "Sandbox HEAD ({}) should match host HEAD ({})",
        sandbox_head, host_head
    );
}

#[test]
fn sandbox_has_host_remote_refs() {
    let repo = TestRepo::new();

    // Create a branch on the host before building the image
    Command::new("git")
        .args(["checkout", "-b", "feature-branch"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to create feature branch");

    Command::new("git")
        .args(["commit", "--allow-empty", "-m", "Feature commit"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to commit on feature branch");

    // Switch back to the default branch
    Command::new("git")
        .args(["checkout", "-"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to switch back");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Enter sandbox and list remote refs
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "test-refs", "--", "git", "branch", "-r"])
        .success()
        .expect("sandbox enter failed");

    let refs = String::from_utf8_lossy(&stdout);

    // Should have host/HEAD and host/master (or main) and host/feature-branch
    assert!(
        refs.contains("host/HEAD"),
        "Expected host/HEAD in remote refs: {}",
        refs
    );
    assert!(
        refs.contains("host/feature-branch"),
        "Expected host/feature-branch in remote refs: {}",
        refs
    );
}

#[test]
fn sandbox_branch_is_different_from_host_branches() {
    // The sandbox branch should be a new branch, not one that already exists on host
    let repo = TestRepo::new();

    // Create a branch named "existing" on host
    Command::new("git")
        .args(["checkout", "-b", "existing"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to create existing branch");

    Command::new("git")
        .args(["checkout", "-"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to switch back");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // The sandbox named "existing" should still have its own branch, separate
    // from the host's "existing" branch (which becomes host/existing)
    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "existing",
            "--",
            "git",
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .success()
        .expect("sandbox enter failed");

    let branch = String::from_utf8_lossy(&stdout).trim().to_string();
    assert_eq!(
        branch, "existing",
        "Expected branch 'existing' to be checked out, got '{}'",
        branch
    );

    // Check that both the local branch and remote ref exist
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "existing", "--", "git", "branch", "-a"])
        .success()
        .expect("sandbox enter failed");

    let branches = String::from_utf8_lossy(&stdout);
    assert!(
        branches.contains("* existing"),
        "Expected '* existing' (checked out local branch) in: {}",
        branches
    );
    assert!(
        branches.contains("remotes/host/existing"),
        "Expected 'remotes/host/existing' in: {}",
        branches
    );
}

#[test]
fn re_entering_sandbox_preserves_branch() {
    // Re-entering a sandbox should not reset the branch or checkout
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First enter - creates the sandbox and branch
    sandbox_command(&repo, &daemon)
        .args(["enter", "persist-test", "--", "echo", "first"])
        .success()
        .expect("first sandbox enter failed");

    // Make a commit in the sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "persist-test",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Sandbox commit",
        ])
        .success()
        .expect("sandbox commit failed");

    // Get the sandbox HEAD after the commit
    let head_after_commit = sandbox_command(&repo, &daemon)
        .args(["enter", "persist-test", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("git rev-parse failed");
    let head_after_commit = String::from_utf8_lossy(&head_after_commit)
        .trim()
        .to_string();

    // Re-enter the sandbox and check HEAD is still at the same commit
    let head_after_reenter = sandbox_command(&repo, &daemon)
        .args(["enter", "persist-test", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("git rev-parse failed after re-enter");
    let head_after_reenter = String::from_utf8_lossy(&head_after_reenter)
        .trim()
        .to_string();

    assert_eq!(
        head_after_commit, head_after_reenter,
        "Re-entering sandbox should preserve HEAD commit"
    );

    // Check we're still on the same branch
    let branch = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "persist-test",
            "--",
            "git",
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .success()
        .expect("git rev-parse --abbrev-ref failed");
    let branch = String::from_utf8_lossy(&branch).trim().to_string();

    assert_eq!(
        branch, "persist-test",
        "Re-entering sandbox should preserve branch name"
    );
}

/// Get the upstream tracking branch for a local branch in the sandbox.
fn get_sandbox_upstream(
    repo: &TestRepo,
    daemon: &TestDaemon,
    sandbox_name: &str,
    branch: &str,
) -> Option<String> {
    sandbox_command(repo, daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "rev-parse",
            "--abbrev-ref",
            &format!("{}@{{upstream}}", branch),
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

#[test]
fn sandbox_primary_branch_has_upstream_when_host_on_branch() {
    // When the host is on a branch, the sandbox's primary branch should track it
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Host is on "master" branch by default (from TestRepo::new)
    let sandbox_name = "upstream-test";

    // Enter sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("sandbox enter failed");

    // Check that the primary branch tracks host/master
    let upstream = get_sandbox_upstream(&repo, &daemon, sandbox_name, sandbox_name);
    assert_eq!(
        upstream,
        Some("host/master".to_string()),
        "Primary branch should track host/master"
    );
}

#[test]
fn sandbox_primary_branch_tracks_host_feature_branch() {
    // When the host is on a feature branch, the sandbox should track that branch
    let repo = TestRepo::new();

    // Create and switch to a feature branch
    create_branch(repo.path(), "feature-xyz");
    create_commit(repo.path(), "Feature commit");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "feature-upstream-test";

    // Enter sandbox while host is on feature-xyz
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("sandbox enter failed");

    // Check that the primary branch tracks host/feature-xyz
    let upstream = get_sandbox_upstream(&repo, &daemon, sandbox_name, sandbox_name);
    assert_eq!(
        upstream,
        Some("host/feature-xyz".to_string()),
        "Primary branch should track host/feature-xyz"
    );
}

#[test]
fn sandbox_primary_branch_has_no_upstream_when_host_detached() {
    // When the host is in detached HEAD state, the sandbox should have no upstream
    let repo = TestRepo::new();

    // Create a commit and get its hash
    create_commit(repo.path(), "Test commit");
    let commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Build image while still on master branch
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    // Now detach HEAD by checking out the commit directly
    Command::new("git")
        .args(["checkout", &commit])
        .current_dir(repo.path())
        .success()
        .expect("git checkout (detached) failed");

    let daemon = TestDaemon::start();
    let sandbox_name = "detached-upstream-test";

    // Enter sandbox while host is detached
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "setup"])
        .success()
        .expect("sandbox enter failed");

    // Check that the primary branch has no upstream
    let upstream = get_sandbox_upstream(&repo, &daemon, sandbox_name, sandbox_name);
    assert!(
        upstream.is_none(),
        "Primary branch should have no upstream when host is detached, got: {:?}",
        upstream
    );
}

#[test]
fn sandbox_re_entry_does_not_change_upstream() {
    // Re-entering a sandbox should not change the upstream, even if host branch changed
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let sandbox_name = "upstream-preserve-test";

    // First entry while on master
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "first entry"])
        .success()
        .expect("first sandbox enter failed");

    // Verify upstream is host/master
    let upstream_before = get_sandbox_upstream(&repo, &daemon, sandbox_name, sandbox_name);
    assert_eq!(
        upstream_before,
        Some("host/master".to_string()),
        "Primary branch should track host/master initially"
    );

    // Switch host to a different branch
    create_branch(repo.path(), "other-branch");

    // Re-enter sandbox
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "second entry"])
        .success()
        .expect("second sandbox enter failed");

    // Verify upstream is still host/master (not changed to host/other-branch)
    let upstream_after = get_sandbox_upstream(&repo, &daemon, sandbox_name, sandbox_name);
    assert_eq!(
        upstream_after,
        Some("host/master".to_string()),
        "Primary branch upstream should not change on re-entry"
    );
}

#[test]
fn sandbox_unsafe_host_network_mode() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Configure unsafe-host network
    write_test_sandbox_config_with_network(&repo, &image_id, "unsafe-host");

    let daemon = TestDaemon::start();
    let sandbox_name = "unsafe-host-test";

    // Enter sandbox and verify it works
    sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "hello"])
        .success()
        .expect("sandbox enter failed");

    // Verify git sync works by pushing a branch from sandbox
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature",
        ])
        .success()
        .expect("git checkout failed");

    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            sandbox_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "feature commit",
        ])
        .success()
        .expect("git commit failed");

    // The branch should appear in host as refs/remotes/sandbox/feature@unsafe-host-test
    // Note: get_sandbox_remote_refs returns short names like "sandbox/feature@unsafe-host-test"
    // Wait, get_sandbox_remote_refs returns refname:short, so it is "origin/..."?
    // No, the function queries "refs/remotes/sandbox/", so it returns "sandbox/feature@..."

    // Let's verify get_sandbox_remote_refs implementation
    // "refs/remotes/sandbox/*" -> refname:short -> "sandbox/..."

    let remote_refs = get_sandbox_remote_refs(repo.path());
    let expected_ref = format!("sandbox/feature@{}", sandbox_name);
    assert!(
        remote_refs.contains(&expected_ref),
        "Sandbox branch not synced to host. Found: {:?}",
        remote_refs
    );
}

#[test]
fn sandbox_unsafe_host_network_mode_requires_runc() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Configure unsafe-host network with runsc (should fail).
    // Use write_test_sandbox_config to set up devcontainer.json with the image,
    // then override .sandbox.toml with runsc + unsafe-host.
    write_test_sandbox_config(&repo, &image_id);
    let config = "runtime = \"runsc\"\nnetwork = \"unsafe-host\"\n";
    std::fs::write(repo.path().join(".sandbox.toml"), config)
        .expect("Failed to write .sandbox.toml");

    let daemon = TestDaemon::start();
    let sandbox_name = "unsafe-host-fail-test";

    // Enter sandbox and verify it fails with helpful message
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "hello"])
        .output()
        .expect("Failed to execute sandbox command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("network='unsafe-host' is only supported with runtime='runc'"));
}
