//! Integration tests for the `sandbox list` subcommand.

use crate::common::{
    build_test_image, sandbox_command, write_test_sandbox_config, TestDaemon, TestRepo,
};

#[test]
fn list_empty_returns_header_only() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should have header line and separator
    assert!(stdout.contains("NAME"));
    assert!(stdout.contains("GIT"));
    assert!(stdout.contains("STATUS"));
    assert!(stdout.contains("CREATED"));
    assert!(stdout.contains("HOST"));
    assert!(stdout.contains("----"));
}

#[test]
fn list_shows_created_sandbox() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-list", "--", "echo", "hello"])
        .output()
        .expect("Failed to run sandbox enter command");

    assert!(
        output.status.success(),
        "sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List sandboxes
    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test-list"),
        "Expected sandbox 'test-list' in output: {}",
        stdout
    );
    assert!(
        stdout.contains("running"),
        "Expected 'running' status in output: {}",
        stdout
    );
    assert!(
        stdout.contains("local"),
        "Expected 'local' host in output: {}",
        stdout
    );
}

#[test]
fn list_shows_repo_state() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-state", "--", "echo", "hello"])
        .output()
        .expect("Failed to run sandbox enter command");

    assert!(
        output.status.success(),
        "sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Initial state should be "up to date" (tracked via branch)
    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("up to date") || stdout.contains("ahead") || stdout.contains("behind"),
        "Expected repo state in output: {}",
        stdout
    );

    // Make a commit in the sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-state", "--", "touch", "newfile"])
        .output()
        .expect("Failed to touch file");
    assert!(output.status.success());

    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "test-state", "--", "git", "add", "newfile"])
        .output()
        .expect("Failed to git add");
    assert!(output.status.success());

    let output = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "test-state",
            "--",
            "git",
            "commit",
            "-m",
            "new file",
        ])
        .output()
        .expect("Failed to git commit");
    assert!(output.status.success());

    // Check list again - should show ahead
    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ahead 1"),
        "Expected 'ahead 1' in output: {}",
        stdout
    );
}

#[test]
fn list_shows_multiple_sandboxes() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create first sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-one", "--", "echo", "one"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "first sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create second sandbox
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "sandbox-two", "--", "echo", "two"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "second sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List sandboxes
    let output = sandbox_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sandbox-one"),
        "Expected 'sandbox-one' in output: {}",
        stdout
    );
    assert!(
        stdout.contains("sandbox-two"),
        "Expected 'sandbox-two' in output: {}",
        stdout
    );
}

#[test]
fn list_does_not_show_other_repo_sandboxes() {
    let repo1 = TestRepo::new();
    let image_id1 = build_test_image(repo1.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo1, &image_id1);

    let repo2 = TestRepo::new();
    let image_id2 = build_test_image(repo2.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo2, &image_id2);

    let daemon = TestDaemon::start();

    // Create sandbox in repo1
    let output = sandbox_command(&repo1, &daemon)
        .args(["enter", "repo1-sandbox", "--", "echo", "repo1"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "repo1 sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Create sandbox in repo2
    let output = sandbox_command(&repo2, &daemon)
        .args(["enter", "repo2-sandbox", "--", "echo", "repo2"])
        .output()
        .expect("Failed to run sandbox enter command");
    assert!(
        output.status.success(),
        "repo2 sandbox enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List sandboxes from repo1 - should only see repo1-sandbox
    let output = sandbox_command(&repo1, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repo1-sandbox"),
        "Expected 'repo1-sandbox' in output: {}",
        stdout
    );
    assert!(
        !stdout.contains("repo2-sandbox"),
        "Should not see 'repo2-sandbox' from other repo in output: {}",
        stdout
    );

    // List sandboxes from repo2 - should only see repo2-sandbox
    let output = sandbox_command(&repo2, &daemon)
        .arg("list")
        .output()
        .expect("Failed to run sandbox list command");

    assert!(
        output.status.success(),
        "sandbox list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repo2-sandbox"),
        "Expected 'repo2-sandbox' in output: {}",
        stdout
    );
    assert!(
        !stdout.contains("repo1-sandbox"),
        "Should not see 'repo1-sandbox' from other repo in output: {}",
        stdout
    );
}
