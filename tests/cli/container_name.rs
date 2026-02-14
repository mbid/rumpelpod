//! Integration tests for container name sanitization.
//!
//! Docker container names must match `[a-zA-Z0-9][a-zA-Z0-9_.-]+`. Repo
//! directory names with special characters are sanitized in docker_name().
//! Pod names are validated at the CLI to reject invalid characters early,
//! since they also appear in git refspecs and hostnames.

use crate::common::{build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo};

#[test]
fn unicode_pod_name_is_rejected() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "caf\u{00e9}-\u{1f680}", "--", "echo", "hello"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        !output.status.success(),
        "Unicode pod name should be rejected"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid character"),
        "Should report invalid character, got: {}",
        stderr,
    );
}

#[test]
fn unicode_repo_path() {
    // The temp dir name contains unicode, which ends up in the container name.
    // docker_name() sanitizes this so it still works.
    let repo = TestRepo::new_with_prefix("rumpelpod-\u{00fc}bung-");
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "test", "--", "echo", "hello"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        output.status.success(),
        "Unicode repo path should work: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn spaces_in_pod_name_rejected() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "my pod", "--", "echo", "hello"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        !output.status.success(),
        "Pod name with spaces should be rejected"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid character"),
        "Should report invalid character, got: {}",
        stderr,
    );
}
