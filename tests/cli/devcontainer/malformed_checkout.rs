//! Tests that `rumpel enter` recovers from malformed git checkouts.
//!
//! When the container image already has a .git directory in a broken state
//! (detached HEAD, unborn branch, dirty index/tree, untracked files),
//! rumpel should fix it transparently rather than failing.

use rumpelpod::CommandExt;

use crate::common::{
    build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo, TEST_REPO_PATH,
};

/// Enter a pod and verify the repo has the host commit and a clean working tree.
fn assert_repo_usable(repo: &TestRepo, daemon: &TestDaemon, pod_name: &str) {
    let script = format!(
        "git -C {TEST_REPO_PATH} log --oneline && \
         echo '---GIT_STATUS---' && \
         git -C {TEST_REPO_PATH} status --porcelain"
    );

    let stdout = pod_command(repo, daemon)
        .args(["enter", pod_name, "--", "sh", "-c", &script])
        .success()
        .expect("rumpel enter should succeed");

    let output = String::from_utf8_lossy(&stdout);
    let (log_part, status_part) = output
        .split_once("---GIT_STATUS---")
        .expect("output should contain separator");

    assert!(
        log_part.contains("Initial commit"),
        "repo should contain the host's initial commit, got: {log_part}"
    );

    let status = status_part.trim();
    assert!(
        status.is_empty(),
        "working tree should be clean, got: {status}"
    );
}

#[test]
fn recover_from_detached_head() {
    let repo = TestRepo::new();
    let image_id = build_test_image(
        repo.path(),
        "RUN git -C /home/testuser/workspace checkout --detach",
    )
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    assert_repo_usable(&repo, &daemon, "recover-detached");
}

#[test]
fn recover_from_unborn_branch() {
    let repo = TestRepo::new();
    // Replace the real repo with a bare git init (no commits at all)
    let image_id = build_test_image(
        repo.path(),
        "RUN rm -rf /home/testuser/workspace/.git && git init /home/testuser/workspace",
    )
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    assert_repo_usable(&repo, &daemon, "recover-unborn");
}

#[test]
fn recover_from_dirty_index() {
    let repo = TestRepo::new();
    let image_id = build_test_image(
        repo.path(),
        "RUN cd /home/testuser/workspace && echo staged > staged.txt && git add staged.txt",
    )
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    assert_repo_usable(&repo, &daemon, "recover-dirty-index");
}

#[test]
fn recover_from_dirty_working_tree() {
    let repo = TestRepo::new();
    // Add a tracked file, commit, then modify it
    let extra = concat!(
        "RUN cd /home/testuser/workspace && ",
        "echo original > tracked.txt && ",
        "git add tracked.txt && ",
        "git -c user.email=t@t -c user.name=T commit -m 'add file' && ",
        "echo modified > tracked.txt",
    );
    let image_id = build_test_image(repo.path(), extra).expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    assert_repo_usable(&repo, &daemon, "recover-dirty-tree");
}

#[test]
fn recover_from_untracked_files() {
    let repo = TestRepo::new();
    let image_id = build_test_image(
        repo.path(),
        "RUN echo untracked > /home/testuser/workspace/untracked.txt",
    )
    .expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();
    assert_repo_usable(&repo, &daemon, "recover-untracked");
}
