//! Integration tests for the git gateway functionality.
//!
//! Tests verify that commits and branches are synchronized between the host
//! repository and the gateway bare repository, and that pods can access
//! the gateway via HTTP.

use std::path::{Path, PathBuf};
use std::process::Command;

use rumpelpod::CommandExt;

use crate::common::{
    build_test_image, create_commit, pod_command, write_test_pod_config,
    write_test_pod_config_with_network, TestDaemon, TestRepo,
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

/// Get the list of pod remote-tracking refs in a repository.
/// These are refs pushed by pods, matching the pattern refs/remotes/rumpelpod/*@*
/// (excludes refs/remotes/rumpelpod/host/* which are created by host pushes).
fn get_pod_remote_refs(repo_path: &Path) -> Vec<String> {
    let output: String = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/remotes/rumpelpod/",
        ])
        .current_dir(repo_path)
        .success()
        .expect("Failed to list remote refs")
        .try_into()
        .unwrap();
    output
        .lines()
        .filter(|s| !s.is_empty())
        // Filter to only pod refs with @ (exclude host/* refs)
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

/// Get the gateway path for a repo by reading the rumpelpod remote URL.
fn get_gateway_path(repo_path: &Path) -> Option<std::path::PathBuf> {
    Command::new("git")
        .args(["remote", "get-url", "rumpelpod"])
        .current_dir(repo_path)
        .success()
        .ok()
        .map(|b| std::path::PathBuf::from(String::try_from(b).unwrap().trim()))
}

#[test]
fn gateway_initial_branches_pushed() {
    // Create repo with multiple branches before launching pod
    let repo = TestRepo::new();

    // Create additional branches before building the image
    create_branch(repo.path(), "feature-a");
    create_commit(repo.path(), "Feature A commit");

    create_branch(repo.path(), "feature-b");
    create_commit(repo.path(), "Feature B commit");

    checkout_branch(repo.path(), "master");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod - this should set up gateway and push all branches
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "hello"])
        .success()
        .expect("Failed to run rumpel enter");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway with the branch
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
    // Test that the container gets "host" and "rumpelpod" remotes pointing to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", "http-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Check that remotes are configured
    let remotes_output = pod_command(&repo, &daemon)
        .args(["enter", "http-test", "--", "git", "remote"])
        .success()
        .expect("Failed to get git remotes");

    let remotes = String::from_utf8_lossy(&remotes_output);

    assert!(
        remotes.contains("host"),
        "Container should have remote, got: {}",
        remotes
    );
    assert!(
        remotes.contains("rumpelpod"),
        "Container should have remote, got: {}",
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod (this sets up gateway and pushes branches)
    pod_command(&repo, &daemon)
        .args(["enter", "fetch-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Fetch from host remote inside the container
    pod_command(&repo, &daemon)
        .args(["enter", "fetch-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch from host remote");

    // Verify the fetched commit matches
    let fetched_commit_output = pod_command(&repo, &daemon)
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod first
    pod_command(&repo, &daemon)
        .args(["enter", "new-commits-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Initial fetch
    pod_command(&repo, &daemon)
        .args(["enter", "new-commits-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to initial fetch");

    // Now create a new commit on host (after container exists)
    create_commit(repo.path(), "New commit after container creation");
    let new_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Fetch again - should get the new commit
    pod_command(&repo, &daemon)
        .args(["enter", "new-commits-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch new commits");

    // Verify we got the new commit
    let fetched_commit_output = pod_command(&repo, &daemon)
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Check that remotes are configured
    let remotes_output = pod_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "git", "remote", "-v"])
        .success()
        .expect("Failed to get git remotes");

    let remotes = String::from_utf8_lossy(&remotes_output);

    assert!(
        remotes.contains("host"),
        "Container should have remote, got: {}",
        remotes
    );

    // Fetch should work
    pod_command(&repo, &daemon)
        .args(["enter", "user-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch from host remote");
}

#[test]
fn gateway_pod_commit_triggers_push() {
    // Test that creating a commit in the pod triggers a push to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "commit-push-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit in the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Pod commit",
        ])
        .success()
        .expect("Failed to create commit in pod");

    // Get the commit hash from the pod
    let pod_commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get pod commit");

    let pod_commit = String::from_utf8_lossy(&pod_commit_output)
        .trim()
        .to_string();

    // Check that the gateway has the branch rumpelpod/<pod_name>@<pod_name>
    // (pod is on a branch named after itself, not "master")
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("rumpelpod/{}@{}", pod_name, pod_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(pod_commit),
        "Gateway should have branch '{}' with pod's commit",
        expected_branch
    );
}

#[test]
fn gateway_pod_push_works_from_new_branch() {
    // Test that pushing from a new branch in pod works
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "new-branch-push";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a new branch and commit in the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature-from-pod",
        ])
        .success()
        .expect("Failed to create branch in pod");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Feature commit",
        ])
        .success()
        .expect("Failed to create commit in pod");

    // Get the commit hash from the pod
    let pod_commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get pod commit");

    let pod_commit = String::from_utf8_lossy(&pod_commit_output)
        .trim()
        .to_string();

    // Check that the gateway has the branch
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let expected_branch = format!("rumpelpod/feature-from-pod@{}", pod_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(pod_commit),
        "Gateway should have branch '{}' with pod's commit",
        expected_branch
    );
}

#[test]
fn gateway_multiple_pods_push_independently() {
    // Test that multiple pods can push to the gateway without conflicts
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch two pods
    pod_command(&repo, &daemon)
        .args(["enter", "pod-a", "--", "echo", "setup"])
        .success()
        .expect("Failed to run pod-a enter");

    pod_command(&repo, &daemon)
        .args(["enter", "pod-b", "--", "echo", "setup"])
        .success()
        .expect("Failed to run pod-b enter");

    // Create commits in both pods on the same branch name
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "pod-a",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from A",
        ])
        .success()
        .expect("Failed to create commit in pod-a");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            "pod-b",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from B",
        ])
        .success()
        .expect("Failed to create commit in pod-b");

    // Get commit hashes
    let commit_a_output = pod_command(&repo, &daemon)
        .args(["enter", "pod-a", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get pod-a commit");
    let commit_a = String::from_utf8_lossy(&commit_a_output).trim().to_string();

    let commit_b_output = pod_command(&repo, &daemon)
        .args(["enter", "pod-b", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get pod-b commit");
    let commit_b = String::from_utf8_lossy(&commit_b_output).trim().to_string();

    // Check that the gateway has both branches with different commits
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    let gateway_commit_a = get_branch_commit(&gateway, "rumpelpod/pod-a@pod-a");
    let gateway_commit_b = get_branch_commit(&gateway, "rumpelpod/pod-b@pod-b");

    assert_eq!(
        gateway_commit_a,
        Some(commit_a.clone()),
        "Gateway should have pod-a's commit"
    );
    assert_eq!(
        gateway_commit_b,
        Some(commit_b.clone()),
        "Gateway should have pod-b's commit"
    );

    // The commits should be different
    assert_ne!(
        commit_a, commit_b,
        "Commits from different pods should be different"
    );
}

#[test]
fn gateway_pod_amend_triggers_push() {
    // Test that amending a commit in the pod triggers a push to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "amend-push-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit in the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Original commit",
        ])
        .success()
        .expect("Failed to create commit in pod");

    let original_commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get original commit");
    let original_commit = String::from_utf8_lossy(&original_commit_output)
        .trim()
        .to_string();

    // Amend the commit
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--amend",
            "--allow-empty",
            "-m",
            "Amended commit",
        ])
        .success()
        .expect("Failed to amend commit in pod");

    let amended_commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
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
    let expected_branch = format!("rumpelpod/{}@{}", pod_name, pod_name);
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
fn gateway_pod_cannot_push_to_other_pod_namespace() {
    // Test that pod-a cannot push to pod-b's namespace
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod-a
    pod_command(&repo, &daemon)
        .args(["enter", "pod-a", "--", "echo", "setup"])
        .success()
        .expect("Failed to run pod-a enter");

    // Launch pod-b and create a commit so it has a branch in the gateway
    pod_command(&repo, &daemon)
        .args(["enter", "pod-b", "--", "echo", "setup"])
        .success()
        .expect("Failed to run pod-b enter");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            "pod-b",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from B",
        ])
        .success()
        .expect("Failed to create commit in pod-b");

    // Get pod-b's commit
    let commit_b_output = pod_command(&repo, &daemon)
        .args(["enter", "pod-b", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get pod-b commit");
    let commit_b = String::from_utf8_lossy(&commit_b_output).trim().to_string();

    // Verify pod-b's branch exists in gateway
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let gateway_commit_b = get_branch_commit(&gateway, "rumpelpod/pod-b@pod-b");
    assert_eq!(
        gateway_commit_b,
        Some(commit_b.clone()),
        "Gateway should have pod-b's commit"
    );

    // Now try to have pod-a push directly to pod-b's namespace
    // This should fail because of access control
    let result = pod_command(&repo, &daemon)
        .args([
            "enter",
            "pod-a",
            "--",
            "git",
            "push",
            "rumpelpod",
            "HEAD:refs/heads/rumpelpod/pod-b@pod-b",
            "--force",
        ])
        .output()
        .expect("Failed to execute push command");

    // The push should fail
    assert!(
        !result.status.success(),
        "Push to another pod's namespace should fail, but it succeeded"
    );

    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("pod 'pod-a' cannot push to") || stderr.contains("cannot push"),
        "Error message should mention access control, got: {}",
        stderr
    );

    // Verify pod-b's branch still has its original commit (not overwritten)
    let gateway_commit_b_after = get_branch_commit(&gateway, "rumpelpod/pod-b@pod-b");
    assert_eq!(
        gateway_commit_b_after,
        Some(commit_b),
        "pod-b's branch should not have been modified"
    );
}

#[test]
fn gateway_pod_cannot_push_to_host_namespace() {
    // Test that a pod cannot push to the host/* namespace
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Get host/master commit before the attack
    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");
    let host_commit_before = get_branch_commit(&gateway, "host/master");

    // Create a commit in pod
    pod_command(&repo, &daemon)
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
        .expect("Failed to create commit in pod");

    // Try to push to host/master - should be rejected
    let result = pod_command(&repo, &daemon)
        .args([
            "enter",
            "test",
            "--",
            "git",
            "push",
            "rumpelpod",
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
        stderr.contains("cannot push to") || stderr.contains("rumpelpod"),
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
fn gateway_pod_can_push_to_own_namespace() {
    // Test that a pod can push to its own namespace (positive test)
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "my-pod";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a new branch and commit
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "checkout", "-b", "feature"])
        .success()
        .expect("Failed to create branch");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
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
    let commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit");
    let commit = String::from_utf8_lossy(&commit_output).trim().to_string();

    // Manually push to our own namespace with explicit refspec
    let explicit_push = pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "push",
            "rumpelpod",
            &format!("HEAD:refs/heads/rumpelpod/feature@{}", pod_name),
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
    let expected_branch = format!("rumpelpod/feature@{}", pod_name);
    let gateway_commit = get_branch_commit(&gateway, &expected_branch);

    assert_eq!(
        gateway_commit,
        Some(commit),
        "Gateway should have our commit on {}",
        expected_branch
    );
}

#[test]
fn gateway_pod_reset_triggers_push() {
    // Test that resetting in the pod (without making a new commit) triggers a push to the gateway
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "reset-push-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create two commits in the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit 1",
        ])
        .success()
        .expect("Failed to create commit 1");

    let commit1_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit1");
    let commit1 = String::from_utf8_lossy(&commit1_output).trim().to_string();

    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
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
    let expected_branch = format!("rumpelpod/{}@{}", pod_name, pod_name);

    // Reset back to commit1 (no new commit created)
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "reset", "--hard", &commit1])
        .success()
        .expect("Failed to reset in pod");

    // Gateway should now have commit1 (reference-transaction hook triggers on reset)
    let gateway_commit_after_reset = get_branch_commit(&gateway, &expected_branch);
    assert_eq!(
        gateway_commit_after_reset,
        Some(commit1),
        "Gateway should have commit1 after reset"
    );
}

#[test]
fn gateway_pod_branch_creation_triggers_push() {
    // Test that creating a new branch (without making a commit) in the pod triggers a push
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "branch-create-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    let gateway = get_gateway_path(repo.path()).expect("Gateway should be configured");

    // Verify branch doesn't exist yet
    let expected_branch = format!("rumpelpod/new-feature@{}", pod_name);
    let branches_before = get_branches(&gateway);
    assert!(
        !branches_before.contains(&expected_branch),
        "Branch should not exist yet"
    );

    // Get the current commit
    let current_commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get current commit");
    let current_commit = String::from_utf8_lossy(&current_commit_output)
        .trim()
        .to_string();

    // Create a new branch WITHOUT making a commit
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "checkout",
            "-b",
            "new-feature",
        ])
        .success()
        .expect("Failed to create branch in pod");

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
fn gateway_pod_push_syncs_to_host_remote_ref() {
    // Test that when a pod pushes to gateway, it appears as a remote-tracking ref in host
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "sync-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Note: The pod branch is created and checked out on first entry, which
    // triggers a push to the gateway. This is expected behavior - pods now
    // automatically sync their initial branch.
    let expected_ref = format!("rumpelpod/{}@{}", pod_name, pod_name);

    // Create a commit in the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Pod commit",
        ])
        .success()
        .expect("Failed to create commit in pod");

    // Get the commit hash
    let commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit");
    let commit = String::from_utf8_lossy(&commit_output).trim().to_string();

    // Host should have remote-tracking ref
    let refs_after = get_pod_remote_refs(repo.path());
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
        "Host remote ref should point to pod commit"
    );
}

#[test]
fn gateway_pod_branch_sync_to_host() {
    // Test that creating a new branch in pod syncs to host remote refs
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "branch-sync-test";

    // Launch pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a new branch in pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "checkout",
            "-b",
            "feature-x",
        ])
        .success()
        .expect("Failed to create branch in pod");

    // Host should have remote-tracking ref
    let expected_ref = format!("rumpelpod/feature-x@{}", pod_name);
    let refs = get_pod_remote_refs(repo.path());
    assert!(
        refs.contains(&expected_ref),
        "Host should have remote ref {}, got: {:?}",
        expected_ref,
        refs
    );
}

#[test]
fn gateway_multiple_pods_sync_to_host() {
    // Test that multiple pods can sync independently to host remote refs
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create first pod and commit
    let pod1 = "multi-sync-1";
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod1,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from pod 1",
        ])
        .success()
        .expect("Failed to create commit in pod 1");

    let commit1_output = pod_command(&repo, &daemon)
        .args(["enter", pod1, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit 1");
    let commit1 = String::from_utf8_lossy(&commit1_output).trim().to_string();

    // Create second pod and commit
    let pod2 = "multi-sync-2";
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod2,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Commit from pod 2",
        ])
        .success()
        .expect("Failed to create commit in pod 2");

    let commit2_output = pod_command(&repo, &daemon)
        .args(["enter", pod2, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit 2");
    let commit2 = String::from_utf8_lossy(&commit2_output).trim().to_string();

    // Host should have remote refs
    let refs = get_pod_remote_refs(repo.path());
    let expected_ref1 = format!("rumpelpod/{}@{}", pod1, pod1);
    let expected_ref2 = format!("rumpelpod/{}@{}", pod2, pod2);

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
        "First pod remote ref should have correct commit"
    );
    assert_eq!(
        get_remote_ref_commit(repo.path(), &expected_ref2),
        Some(commit2),
        "Second pod remote ref should have correct commit"
    );
}

#[test]
fn gateway_pod_reset_syncs_to_host_via_force_push() {
    // Test that resetting in pod (requiring force push) syncs to host remote refs
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "force-push-test";

    // Launch pod and create two commits
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "First commit",
        ])
        .success()
        .expect("Failed to create first commit");

    let commit1_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit1");
    let commit1 = String::from_utf8_lossy(&commit1_output).trim().to_string();

    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Second commit",
        ])
        .success()
        .expect("Failed to create second commit");

    let commit2_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get commit2");
    let commit2 = String::from_utf8_lossy(&commit2_output).trim().to_string();

    // Verify host has commit2
    let expected_ref = format!("rumpelpod/{}@{}", pod_name, pod_name);
    assert_eq!(
        get_remote_ref_commit(repo.path(), &expected_ref),
        Some(commit2.clone()),
        "Host should have commit2 before reset"
    );

    // Reset back to commit1 (requires force push to update host remote ref)
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "reset", "--hard", &commit1])
        .success()
        .expect("Failed to reset in pod");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Get the current HEAD commit before launching pod
    let head_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Launch pod - this triggers gateway setup
    pod_command(&repo, &daemon)
        .args(["enter", "head-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
fn gateway_host_head_available_in_pod() {
    // Test that pod can access host/HEAD as a remote-tracking ref
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Get the current HEAD commit
    let head_commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Launch pod and fetch host refs
    pod_command(&repo, &daemon)
        .args(["enter", "pod-head-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch host refs");

    // Verify pod can resolve host/HEAD
    let pod_head_output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "pod-head-test",
            "--",
            "git",
            "rev-parse",
            "host/HEAD",
        ])
        .success()
        .expect("Failed to resolve host/HEAD in pod");

    let pod_head_commit = String::from_utf8_lossy(&pod_head_output).trim().to_string();

    assert_eq!(
        pod_head_commit, head_commit,
        "Pod should be able to resolve host/HEAD to the host's current commit"
    );
}

#[test]
fn gateway_host_head_updates_on_commit() {
    // Test that host/HEAD is updated when a new commit is made
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway
    pod_command(&repo, &daemon)
        .args(["enter", "head-commit-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway (currently on master)
    pod_command(&repo, &daemon)
        .args(["enter", "branch-switch-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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

    // Pod should see the updated HEAD after fetch
    pod_command(&repo, &daemon)
        .args(["enter", "branch-switch-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch after branch switch");

    let pod_head_output = pod_command(&repo, &daemon)
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

    let pod_head = String::from_utf8_lossy(&pod_head_output).trim().to_string();

    assert_eq!(
        pod_head, feature_commit,
        "Pod host/HEAD should reflect the branch switch"
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod to set up gateway (on master at second_commit)
    pod_command(&repo, &daemon)
        .args(["enter", "detached-head-test", "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

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

    // Pod should be able to fetch and resolve the detached HEAD commit
    pod_command(&repo, &daemon)
        .args(["enter", "detached-head-test", "--", "git", "fetch", "host"])
        .success()
        .expect("Failed to fetch in detached HEAD state");

    let pod_head_output = pod_command(&repo, &daemon)
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

    let pod_head = String::from_utf8_lossy(&pod_head_output).trim().to_string();

    assert_eq!(
        pod_head, first_commit,
        "Pod host/HEAD should resolve to the detached HEAD commit"
    );
}

#[test]
fn gateway_primary_branch_alias_works_on_host() {
    // Test that rumpelpod/<name> resolves to the same commit as rumpelpod/<name>@<name>
    // For the alias to be created, the pod must be on a branch with the same name
    // as the pod (the "primary branch").
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "alias-test";

    // Launch pod - it automatically creates and checks out a branch named after
    // the pod (the "primary branch")
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to launch pod");

    // Create a commit on the primary branch
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "test commit for alias",
        ])
        .success()
        .expect("Failed to create commit in pod");

    // Get commit from pod
    let commit_output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get pod HEAD");
    let pod_commit = String::from_utf8_lossy(&commit_output).trim().to_string();

    // Verify host has both refs pointing to the same commit
    let full_ref = format!("rumpelpod/{}@{}", pod_name, pod_name);
    let alias_ref = format!("rumpelpod/{}", pod_name);

    let full_ref_commit = get_remote_ref_commit(repo.path(), &full_ref);
    let alias_ref_commit = get_remote_ref_commit(repo.path(), &alias_ref);

    assert_eq!(
        full_ref_commit,
        Some(pod_commit.clone()),
        "Full ref rumpelpod/{}@{} should point to pod commit",
        pod_name,
        pod_name
    );
    assert_eq!(
        alias_ref_commit,
        Some(pod_commit),
        "Alias ref rumpelpod/{} should point to same commit as full ref",
        pod_name
    );
}

#[test]
fn gateway_alias_deleted_with_pod() {
    // Test that alias ref is removed when pod is deleted
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "delete-alias-test";

    // Launch pod - it automatically creates and checks out the primary branch
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to launch pod");

    // Create a commit on the primary branch
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "test commit",
        ])
        .success()
        .expect("Failed to create commit in pod");

    // Verify refs exist
    let full_ref = format!("rumpelpod/{}@{}", pod_name, pod_name);
    let alias_ref = format!("rumpelpod/{}", pod_name);

    assert!(
        get_remote_ref_commit(repo.path(), &full_ref).is_some(),
        "Full ref should exist before deletion"
    );
    assert!(
        get_remote_ref_commit(repo.path(), &alias_ref).is_some(),
        "Alias ref should exist before deletion"
    );

    // Delete the pod
    pod_command(&repo, &daemon)
        .args(["delete", pod_name])
        .success()
        .expect("Failed to delete pod");

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
    // Test that pod `alice` creating branch `bob` does not affect pod `bob`'s alias
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Launch pod `bob` - it automatically creates and checks out its primary branch
    pod_command(&repo, &daemon)
        .args(["enter", "bob", "--", "echo", "setup"])
        .success()
        .expect("Failed to launch bob pod");

    pod_command(&repo, &daemon)
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
        .expect("Failed to create commit in bob pod");

    let bob_commit_output = pod_command(&repo, &daemon)
        .args(["enter", "bob", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get bob HEAD");
    let bob_commit = String::from_utf8_lossy(&bob_commit_output)
        .trim()
        .to_string();

    // Create pod `alice` and create a branch named `bob` with different commit
    pod_command(&repo, &daemon)
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
        .expect("Failed to create commit in alice pod");

    pod_command(&repo, &daemon)
        .args(["enter", "alice", "--", "git", "checkout", "-b", "bob"])
        .success()
        .expect("Failed to create bob branch in alice pod");

    pod_command(&repo, &daemon)
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
        .expect("Failed to create commit on bob branch in alice pod");

    let alice_bob_commit_output = pod_command(&repo, &daemon)
        .args(["enter", "alice", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("Failed to get alice bob-branch HEAD");
    let alice_bob_commit = String::from_utf8_lossy(&alice_bob_commit_output)
        .trim()
        .to_string();

    // Verify rumpelpod/bob alias still points to bob's primary branch, not alice's bob branch
    let bob_alias_commit = get_remote_ref_commit(repo.path(), "rumpelpod/bob");
    let bob_full_commit = get_remote_ref_commit(repo.path(), "rumpelpod/bob@bob");
    let alice_bob_branch_commit = get_remote_ref_commit(repo.path(), "rumpelpod/bob@alice");

    assert_ne!(
        bob_commit, alice_bob_commit,
        "Bob and alice's bob-branch should have different commits"
    );
    assert_eq!(
        bob_alias_commit,
        Some(bob_commit.clone()),
        "rumpelpod/bob alias should point to bob's primary branch"
    );
    assert_eq!(
        bob_full_commit,
        Some(bob_commit),
        "rumpelpod/bob@bob should point to bob's commit"
    );
    assert_eq!(
        alice_bob_branch_commit,
        Some(alice_bob_commit),
        "rumpelpod/bob@alice should point to alice's bob-branch commit"
    );
}

#[test]
fn gateway_non_primary_branches_have_no_alias() {
    // Test that non-primary branches (feature@pod) don't get an alias
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "no-alias-test";

    // Launch pod - it automatically creates and checks out its primary branch
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to launch pod");

    // Create initial commit on primary branch
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
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
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "checkout", "-b", "feature"])
        .success()
        .expect("Failed to create feature branch");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "feature commit",
        ])
        .success()
        .expect("Failed to create commit on feature branch");

    // Verify feature@pod_name exists but rumpelpod/feature alias does not
    let feature_ref = format!("rumpelpod/feature@{}", pod_name);
    assert!(
        get_remote_ref_commit(repo.path(), &feature_ref).is_some(),
        "rumpelpod/feature@{} should exist",
        pod_name
    );
    assert!(
        get_remote_ref_commit(repo.path(), "rumpelpod/feature").is_none(),
        "rumpelpod/feature alias should not exist (only primary branches get aliases)"
    );

    // Verify primary branch alias still works
    let primary_alias_commit =
        get_remote_ref_commit(repo.path(), &format!("rumpelpod/{}", pod_name));
    let primary_full_commit =
        get_remote_ref_commit(repo.path(), &format!("rumpelpod/{}@{}", pod_name, pod_name));
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
fn pod_has_branch_named_after_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Enter pod and check the current branch name
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "my-pod",
            "--",
            "git",
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ])
        .success()
        .expect("rumpel enter failed");

    let branch = String::from_utf8_lossy(&stdout).trim().to_string();
    assert_eq!(
        branch, "my-pod",
        "Expected branch 'my-pod' to be checked out, got '{}'",
        branch
    );
}

#[test]
fn pod_branch_points_to_host_head() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Get the host's HEAD commit
    let host_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .success()
        .expect("Failed to get host HEAD");
    let host_head = String::from_utf8_lossy(&host_head).trim().to_string();

    // Enter pod and get its HEAD commit
    let pod_head = pod_command(&repo, &daemon)
        .args(["enter", "test-branch", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("rumpel enter failed");
    let pod_head = String::from_utf8_lossy(&pod_head).trim().to_string();

    assert_eq!(
        pod_head, host_head,
        "Pod HEAD ({}) should match host HEAD ({})",
        pod_head, host_head
    );
}

#[test]
fn pod_has_host_remote_refs() {
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Enter pod and list remote refs
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "test-refs", "--", "git", "branch", "-r"])
        .success()
        .expect("rumpel enter failed");

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
fn pod_branch_is_different_from_host_branches() {
    // The pod branch should be a new branch, not one that already exists on host
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
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // The pod named "existing" should still have its own branch, separate
    // from the host's "existing" branch (which becomes host/existing)
    let stdout = pod_command(&repo, &daemon)
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
        .expect("rumpel enter failed");

    let branch = String::from_utf8_lossy(&stdout).trim().to_string();
    assert_eq!(
        branch, "existing",
        "Expected branch 'existing' to be checked out, got '{}'",
        branch
    );

    // Check that both the local branch and remote ref exist
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "existing", "--", "git", "branch", "-a"])
        .success()
        .expect("rumpel enter failed");

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
fn re_entering_pod_preserves_branch() {
    // Re-entering a pod should not reset the branch or checkout
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // First enter - creates the pod and branch
    pod_command(&repo, &daemon)
        .args(["enter", "persist-test", "--", "echo", "first"])
        .success()
        .expect("first rumpel enter failed");

    // Make a commit in the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "persist-test",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "Pod commit",
        ])
        .success()
        .expect("pod commit failed");

    // Get the pod HEAD after the commit
    let head_after_commit = pod_command(&repo, &daemon)
        .args(["enter", "persist-test", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("git rev-parse failed");
    let head_after_commit = String::from_utf8_lossy(&head_after_commit)
        .trim()
        .to_string();

    // Re-enter the pod and check HEAD is still at the same commit
    let head_after_reenter = pod_command(&repo, &daemon)
        .args(["enter", "persist-test", "--", "git", "rev-parse", "HEAD"])
        .success()
        .expect("git rev-parse failed after re-enter");
    let head_after_reenter = String::from_utf8_lossy(&head_after_reenter)
        .trim()
        .to_string();

    assert_eq!(
        head_after_commit, head_after_reenter,
        "Re-entering pod should preserve HEAD commit"
    );

    // Check we're still on the same branch
    let branch = pod_command(&repo, &daemon)
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
        "Re-entering pod should preserve branch name"
    );
}

/// Get the upstream tracking branch for a local branch in the pod.
fn get_pod_upstream(
    repo: &TestRepo,
    daemon: &TestDaemon,
    pod_name: &str,
    branch: &str,
) -> Option<String> {
    pod_command(repo, daemon)
        .args([
            "enter",
            pod_name,
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
fn pod_primary_branch_has_upstream_when_host_on_branch() {
    // When the host is on a branch, the pod's primary branch should track it
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Host is on "master" branch by default (from TestRepo::new)
    let pod_name = "upstream-test";

    // Enter pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("rumpel enter failed");

    // Check that the primary branch tracks host/master
    let upstream = get_pod_upstream(&repo, &daemon, pod_name, pod_name);
    assert_eq!(
        upstream,
        Some("host/master".to_string()),
        "Primary branch should track host/master"
    );
}

#[test]
fn pod_primary_branch_tracks_host_feature_branch() {
    // When the host is on a feature branch, the pod should track that branch
    let repo = TestRepo::new();

    // Create and switch to a feature branch
    create_branch(repo.path(), "feature-xyz");
    create_commit(repo.path(), "Feature commit");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "feature-upstream-test";

    // Enter pod while host is on feature-xyz
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("rumpel enter failed");

    // Check that the primary branch tracks host/feature-xyz
    let upstream = get_pod_upstream(&repo, &daemon, pod_name, pod_name);
    assert_eq!(
        upstream,
        Some("host/feature-xyz".to_string()),
        "Primary branch should track host/feature-xyz"
    );
}

#[test]
fn pod_primary_branch_has_no_upstream_when_host_detached() {
    // When the host is in detached HEAD state, the pod should have no upstream
    let repo = TestRepo::new();

    // Create a commit and get its hash
    create_commit(repo.path(), "Test commit");
    let commit = get_branch_commit(repo.path(), "HEAD").unwrap();

    // Build image while still on master branch
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    // Now detach HEAD by checking out the commit directly
    Command::new("git")
        .args(["checkout", &commit])
        .current_dir(repo.path())
        .success()
        .expect("git checkout (detached) failed");

    let daemon = TestDaemon::start();
    let pod_name = "detached-upstream-test";

    // Enter pod while host is detached
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("rumpel enter failed");

    // Check that the primary branch has no upstream
    let upstream = get_pod_upstream(&repo, &daemon, pod_name, pod_name);
    assert!(
        upstream.is_none(),
        "Primary branch should have no upstream when host is detached, got: {:?}",
        upstream
    );
}

#[test]
fn pod_re_entry_does_not_change_upstream() {
    // Re-entering a pod should not change the upstream, even if host branch changed
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "upstream-preserve-test";

    // First entry while on master
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "first entry"])
        .success()
        .expect("first rumpel enter failed");

    // Verify upstream is host/master
    let upstream_before = get_pod_upstream(&repo, &daemon, pod_name, pod_name);
    assert_eq!(
        upstream_before,
        Some("host/master".to_string()),
        "Primary branch should track host/master initially"
    );

    // Switch host to a different branch
    create_branch(repo.path(), "other-branch");

    // Re-enter pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "second entry"])
        .success()
        .expect("second rumpel enter failed");

    // Verify upstream is still host/master (not changed to host/other-branch)
    let upstream_after = get_pod_upstream(&repo, &daemon, pod_name, pod_name);
    assert_eq!(
        upstream_after,
        Some("host/master".to_string()),
        "Primary branch upstream should not change on re-entry"
    );
}

#[test]
fn pod_unsafe_host_network_mode() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");

    // Configure unsafe-host network
    write_test_pod_config_with_network(&repo, &image_id, "unsafe-host");

    let daemon = TestDaemon::start();
    let pod_name = "unsafe-host-test";

    // Enter pod and verify it works
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "hello"])
        .success()
        .expect("rumpel enter failed");

    // Verify git sync works by pushing a branch from pod
    pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "git", "checkout", "-b", "feature"])
        .success()
        .expect("git checkout failed");

    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "feature commit",
        ])
        .success()
        .expect("git commit failed");

    // The branch should appear in host as refs/remotes/rumpelpod/feature@unsafe-host-test
    // Note: get_pod_remote_refs returns short names like "rumpelpod/feature@unsafe-host-test"
    // Wait, get_pod_remote_refs returns refname:short, so it is "origin/..."?
    // No, the function queries "refs/remotes/rumpelpod/", so it returns "rumpelpod/feature@..."

    // Let's verify get_pod_remote_refs implementation
    // "refs/remotes/rumpelpod/*" -> refname:short -> "rumpelpod/..."

    let remote_refs = get_pod_remote_refs(repo.path());
    let expected_ref = format!("rumpelpod/feature@{}", pod_name);
    assert!(
        remote_refs.contains(&expected_ref),
        "Pod branch not synced to host. Found: {:?}",
        remote_refs
    );
}

// -- Git LFS tests ------------------------------------------------------------

/// Dockerfile snippet that installs git-lfs in the test container.
/// Switches to root for apt-get, then back to the test user.
const LFS_DOCKERFILE: &str = "\
USER root\n\
RUN apt-get update && apt-get install -y git-lfs\n\
USER testuser";

/// Set up an LFS-tracked file in a host repo and return the file's content.
///
/// Configures git-lfs, creates a `.gitattributes` tracking `*.bin` files,
/// writes a binary file, and commits everything.
fn setup_lfs_repo(repo_path: &Path) -> Vec<u8> {
    Command::new("git")
        .args(["lfs", "install", "--local"])
        .current_dir(repo_path)
        .success()
        .expect("git lfs install failed");

    Command::new("git")
        .args(["lfs", "track", "*.bin"])
        .current_dir(repo_path)
        .success()
        .expect("git lfs track failed");

    // Deterministic "large" content (just needs to be tracked by LFS)
    let content = b"lfs-test-content-1234567890\n";
    std::fs::write(repo_path.join("large.bin"), content).expect("write large.bin");

    Command::new("git")
        .args(["add", ".gitattributes", "large.bin"])
        .current_dir(repo_path)
        .success()
        .expect("git add failed");

    Command::new("git")
        .args(["commit", "-m", "add LFS file"])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(repo_path)
        .success()
        .expect("git commit failed");

    content.to_vec()
}

/// Return the LFS object storage path for a given OID under a base dir.
fn lfs_object_path(base: &Path, oid: &str) -> PathBuf {
    base.join("lfs")
        .join("objects")
        .join(&oid[..2])
        .join(&oid[2..4])
        .join(oid)
}

#[test]
fn gateway_lfs_download_from_host() {
    // Verify that an LFS file committed on the host is available in the
    // pod with full content (not a pointer).
    let repo = TestRepo::new();
    let content = setup_lfs_repo(repo.path());

    let image_id =
        build_test_image(repo.path(), LFS_DOCKERFILE).expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "lfs-download";

    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "cat", "large.bin"])
        .success()
        .expect("pod enter failed");

    assert_eq!(
        output, content,
        "LFS file content in pod should match host content"
    );
}

#[test]
fn gateway_lfs_upload_from_pod() {
    // Verify that creating an LFS file inside a pod stores the object
    // in the gateway's LFS directory.
    let repo = TestRepo::new();

    // Set up LFS tracking in the host repo so .gitattributes is present
    Command::new("git")
        .args(["lfs", "install", "--local"])
        .current_dir(repo.path())
        .success()
        .expect("git lfs install failed");

    Command::new("git")
        .args(["lfs", "track", "*.bin"])
        .current_dir(repo.path())
        .success()
        .expect("git lfs track failed");

    Command::new("git")
        .args(["add", ".gitattributes"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");

    Command::new("git")
        .args(["commit", "-m", "track bin files with LFS"])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(repo.path())
        .success()
        .expect("git commit failed");

    let image_id =
        build_test_image(repo.path(), LFS_DOCKERFILE).expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "lfs-upload";

    // Create an LFS file inside the pod, commit, and push
    pod_command(&repo, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "sh",
            "-c",
            "echo pod-lfs-content > upload.bin && git add upload.bin && git commit -m 'add upload.bin'",
        ])
        .success()
        .expect("pod commit failed");

    // The pod reference-transaction hook should have pushed to the
    // gateway.  The LFS pre-push hook uploads the object to the gateway's
    // LFS storage via our HTTP server.

    // Compute the expected OID (sha256 of the file content)
    let file_content = b"pod-lfs-content\n";
    let oid = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(file_content);
        hex::encode(h.finalize())
    };

    let gateway = get_gateway_path(repo.path()).expect("gateway should exist");
    let obj_path = lfs_object_path(&gateway, &oid);

    assert!(
        obj_path.exists(),
        "LFS object should exist in gateway storage at {}",
        obj_path.display()
    );

    let stored = std::fs::read(&obj_path).expect("read LFS object");
    assert_eq!(
        stored, file_content,
        "Stored LFS object content should match"
    );
}
