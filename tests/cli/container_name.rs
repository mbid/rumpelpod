//! Integration tests for container name sanitization.
//!
//! Docker container names must match `[a-zA-Z0-9][a-zA-Z0-9_.-]+`. Pod names
//! and repo directory names with unicode or other special characters must be
//! sanitized before use as Docker container names.

use crate::common::{build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo};

#[test]
fn unicode_pod_name() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // A pod name with unicode should still produce a valid container.
    let output = pod_command(&repo, &daemon)
        .args(["enter", "caf\u{00e9}-\u{1f680}", "--", "echo", "hello"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        output.status.success(),
        "Unicode pod name should work: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[test]
fn unicode_repo_path() {
    // The temp dir name contains unicode, which ends up in the container name.
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
fn spaces_in_pod_name() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "my pod", "--", "echo", "hello"])
        .output()
        .expect("rumpel enter failed to execute");

    assert!(
        output.status.success(),
        "Pod name with spaces should work: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}
