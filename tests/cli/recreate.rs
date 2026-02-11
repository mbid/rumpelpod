//! Integration tests for the `rumpel recreate` subcommand. subcommand.

use crate::common::{
    build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo,
};
use rumpelpod::CommandExt;

#[test]
fn recreate_preserves_dirty_files_but_resets_container() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // 1. Enter pod and create a dirty file in the repo, and a file in /tmp
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "test",
            "--",
            "sh",
            "-c",
            "echo 'dirty content' > dirty_file.txt && echo 'temp content' > /tmp/temp_file.txt",
        ])
        .success()
        .expect("rumpel enter failed");

    // 2. Recreate the pod
    pod_command(&repo, &daemon)
        .args(["recreate", "test"])
        .success()
        .expect("pod recreate failed");

    // 3. Verify dirty file exists and has correct content (repo is preserved)
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "cat", "dirty_file.txt"])
        .success()
        .expect("pod check failed");

    let content = String::from_utf8_lossy(&stdout);
    assert_eq!(content.trim(), "dirty content");

    // 4. Verify /tmp/temp_file.txt is gone (container was reset)
    let status = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "test", "-f", "/tmp/temp_file.txt"])
        .status()
        .expect("pod check failed");

    assert!(
        !status.success(),
        "File in /tmp should have been removed after recreate"
    );
}

#[test]
fn recreate_preserves_untracked_files() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // 1. Create untracked file
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "touch", "untracked.txt"])
        .success()
        .expect("rumpel enter failed");

    // 2. Recreate
    pod_command(&repo, &daemon)
        .args(["recreate", "test"])
        .success()
        .expect("pod recreate failed");

    // 3. Verify file exists
    pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "ls", "untracked.txt"])
        .success()
        .expect("untracked file should exist");
}

#[test]
fn recreate_preserves_modified_tracked_files() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // 1. Modify a tracked file (README.md exists in the test repo)
    // Actually TestRepo doesn't create README.md. It creates an empty commit.
    // Let's modify a file that we create and commit first.

    // Create a file and commit it
    std::process::Command::new("git")
        .args(["checkout", "-b", "main"])
        .current_dir(repo.path())
        .output()
        .expect("git checkout failed");

    std::fs::write(repo.path().join("tracked.txt"), "original").expect("write failed");
    std::process::Command::new("git")
        .args(["add", "tracked.txt"])
        .current_dir(repo.path())
        .output()
        .expect("git add failed");
    std::process::Command::new("git")
        .args(["commit", "-m", "add tracked file"])
        .current_dir(repo.path())
        .output()
        .expect("git commit failed");

    // 2. Modify it in pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "test",
            "--",
            "sh",
            "-c",
            "echo 'modification' >> tracked.txt",
        ])
        .success()
        .expect("rumpel enter failed");

    // 3. Recreate
    pod_command(&repo, &daemon)
        .args(["recreate", "test"])
        .success()
        .expect("pod recreate failed");

    // 4. Verify modification exists
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "cat", "tracked.txt"])
        .success()
        .expect("check failed");

    let content = String::from_utf8_lossy(&stdout);
    assert!(content.contains("modification"));
}
