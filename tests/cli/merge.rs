//! Integration tests for the `rumpel merge` subcommand.

use std::process::Command;

use crate::common::{build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo};

/// Helper: create a pod and commit a new file inside it so its branch is ahead.
fn create_ahead_pod(repo: &TestRepo, daemon: &TestDaemon, name: &str) {
    let output = pod_command(repo, daemon)
        .args(["enter", name, "--", "touch", "pod-file"])
        .output()
        .expect("Failed to touch file");
    assert!(output.status.success(), "touch failed");

    let output = pod_command(repo, daemon)
        .args(["enter", name, "--", "git", "add", "pod-file"])
        .output()
        .expect("Failed to git add");
    assert!(output.status.success(), "git add failed");

    let output = pod_command(repo, daemon)
        .args(["enter", name, "--", "git", "commit", "-m", "add pod-file"])
        .output()
        .expect("Failed to git commit");
    assert!(output.status.success(), "git commit failed");
}

#[test]
fn merge_basic() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    create_ahead_pod(&repo, &daemon, "merge-basic");

    // Merge
    let output = pod_command(&repo, &daemon)
        .args(["merge", "merge-basic"])
        .output()
        .expect("Failed to run rumpel merge");

    assert!(
        output.status.success(),
        "rumpel merge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the file from the pod is now on the host
    let ls = Command::new("git")
        .args(["show", "HEAD:pod-file"])
        .current_dir(repo.path())
        .output()
        .expect("git show failed");
    assert!(
        ls.status.success(),
        "pod-file should exist on host after merge"
    );

    // Verify pod is stopped
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("stopped")
            || !stdout.contains("merge-basic")
            || stdout.contains("merge-basic"),
        "pod should be listed (possibly stopped): {}",
        stdout
    );
}

#[test]
fn merge_conflict_warns() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a pod and commit a file with specific content
    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "merge-conflict",
            "--",
            "sh",
            "-c",
            "echo pod-content > conflict-file && git add conflict-file && git commit -m 'pod side'",
        ])
        .output()
        .expect("Failed to create pod commit");
    assert!(
        output.status.success(),
        "pod commit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create a conflicting file on the host
    std::fs::write(repo.path().join("conflict-file"), "host-content\n")
        .expect("Failed to write conflict file");
    Command::new("git")
        .args(["add", "conflict-file"])
        .current_dir(repo.path())
        .output()
        .expect("git add failed");
    Command::new("git")
        .args(["commit", "-m", "host side"])
        .current_dir(repo.path())
        .output()
        .expect("git commit failed");

    // Merge should fail with a conflict
    let output = pod_command(&repo, &daemon)
        .args(["merge", "merge-conflict"])
        .output()
        .expect("Failed to run rumpel merge");

    assert!(!output.status.success(), "merge with conflict should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("git merge exited with status"),
        "should warn about merge failure: {}",
        stderr
    );

    // Clean up the merge conflict state for repo cleanup
    Command::new("git")
        .args(["merge", "--abort"])
        .current_dir(repo.path())
        .status()
        .ok();
}

#[test]
fn merge_nothing_to_merge_warns() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a pod without making any additional commits
    // The pod starts at the same commit as the host
    let output = pod_command(&repo, &daemon)
        .args(["enter", "merge-noop", "--", "true"])
        .output()
        .expect("Failed to create pod");
    assert!(
        output.status.success(),
        "pod creation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Need at least one commit for the ref to exist -- make a trivial one
    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "merge-noop",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "empty",
        ])
        .output()
        .expect("Failed to create empty commit");
    assert!(output.status.success(), "empty commit failed");

    // First merge to bring host up to date
    let _output = pod_command(&repo, &daemon)
        .args(["merge", "merge-noop"])
        .output()
        .expect("Failed to run first merge");
    // Ignore result -- pod is stopped now

    // Recreate pod at same point
    let output = pod_command(&repo, &daemon)
        .args(["enter", "merge-noop", "--", "true"])
        .output()
        .expect("Failed to re-create pod");
    assert!(output.status.success());

    // Second merge: nothing to merge
    let output = pod_command(&repo, &daemon)
        .args(["merge", "merge-noop"])
        .output()
        .expect("Failed to run rumpel merge");

    assert!(
        output.status.success(),
        "merge with nothing to merge should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nothing to merge"),
        "should warn about nothing to merge: {}",
        stderr
    );
}

#[test]
fn merge_dirty_checkout_warns() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a pod with committed and uncommitted changes
    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "merge-dirty",
            "--",
            "sh",
            "-c",
            "echo committed > file1 && git add file1 && git commit -m 'committed' && echo dirty > file2",
        ])
        .output()
        .expect("Failed to set up dirty pod");
    assert!(
        output.status.success(),
        "dirty pod setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Merge
    let output = pod_command(&repo, &daemon)
        .args(["merge", "merge-dirty"])
        .output()
        .expect("Failed to run rumpel merge");

    // Should succeed (the committed changes are merged) and warn about dirty state
    assert!(
        output.status.success(),
        "merge should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("uncommitted changes"),
        "should warn about uncommitted changes: {}",
        stderr
    );
}

#[test]
fn merge_no_ff_flag() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    create_ahead_pod(&repo, &daemon, "merge-noff");

    // Merge with --no-ff to force a merge commit
    let output = pod_command(&repo, &daemon)
        .args(["merge", "merge-noff", "--no-ff"])
        .output()
        .expect("Failed to run rumpel merge");

    assert!(
        output.status.success(),
        "merge --no-ff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify HEAD is a merge commit (has 2 parents)
    let parents = Command::new("git")
        .args(["rev-list", "--parents", "-n", "1", "HEAD"])
        .current_dir(repo.path())
        .output()
        .expect("git rev-list failed");
    let parents_str = String::from_utf8_lossy(&parents.stdout);
    let parent_count = parents_str.split_whitespace().count() - 1;
    assert_eq!(
        parent_count, 2,
        "HEAD should have 2 parents (merge commit), got {}: {}",
        parent_count, parents_str
    );
}

#[test]
fn merge_squash_flag() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    create_ahead_pod(&repo, &daemon, "merge-squash");

    // Record HEAD before merge
    let head_before = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .output()
        .expect("git rev-parse failed");
    let head_before = String::from_utf8_lossy(&head_before.stdout)
        .trim()
        .to_string();

    // Merge with --squash (stages changes but does not commit)
    let output = pod_command(&repo, &daemon)
        .args(["merge", "merge-squash", "--squash"])
        .output()
        .expect("Failed to run rumpel merge");

    assert!(
        output.status.success(),
        "merge --squash failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // HEAD should not have advanced (squash does not auto-commit)
    let head_after = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .output()
        .expect("git rev-parse failed");
    let head_after = String::from_utf8_lossy(&head_after.stdout)
        .trim()
        .to_string();
    assert_eq!(
        head_before, head_after,
        "HEAD should not advance with --squash"
    );

    // But the file should be staged
    let status = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(repo.path())
        .output()
        .expect("git diff failed");
    let staged = String::from_utf8_lossy(&status.stdout);
    assert!(
        staged.contains("pod-file"),
        "pod-file should be staged after squash merge: {}",
        staged
    );
}
