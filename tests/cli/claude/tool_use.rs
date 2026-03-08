//! Tests verifying that the Claude CLI can use tools (read files, write
//! files, run commands) inside the container, exercised end-to-end
//! through the caching proxy.

use std::process::Command;
use std::time::{Duration, Instant};

use rumpelpod::CommandExt;

use super::common::{setup_claude_test_repo, ClaudeSession};
use super::proxy::claude_proxy;
use crate::common::{create_commit, pod_command};

/// Prompts must fit on a single 80-column terminal line (including ~4
/// chars of TUI chrome) so that `send()` can find its needle without
/// being broken by a line wrap.  Keep prompts under ~76 characters.

#[test]
fn claude_read_file() {
    let proxy = claude_proxy();
    let (repo, daemon, fake_home) = setup_claude_test_repo(proxy);

    // Commit a file so the gateway syncs it into the container.
    std::fs::write(repo.path().join("hello.txt"), "rumpelpod-test-content-42\n")
        .expect("write hello.txt to test repo");
    Command::new("git")
        .args(["add", "hello.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add hello.txt");
    create_commit(repo.path(), "Add hello.txt");

    let mut session = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        fake_home.path(),
        "claude-haiku-4-5",
        &[],
    );

    session.wait_for("~/workspace");
    session.send("Read hello.txt. Reply with only the file contents.");

    // The file content only appears on screen after Claude reads it,
    // not in the prompt itself.
    session.wait_for("rumpelpod-test-content-42");
}

#[test]
fn claude_write_file() {
    let proxy = claude_proxy();
    let (repo, daemon, fake_home) = setup_claude_test_repo(proxy);

    let mut session = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        fake_home.path(),
        "claude-haiku-4-5",
        &[],
    );

    session.wait_for("~/workspace");
    session.send("Write 'rumpelpod-write-ok' to output.txt");

    // Poll via `rumpel enter` until the file appears inside the
    // container.  This avoids relying on screen output matching
    // (the prompt text already contains the filename and content).
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let result = pod_command(&repo, &daemon)
            .args(["enter", "test", "--", "cat", "output.txt"])
            .output()
            .expect("rumpel enter failed to execute");

        if result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);
            if stdout.contains("rumpelpod-write-ok") {
                break;
            }
        }

        assert!(
            Instant::now() < deadline,
            "output.txt not created with expected content within timeout",
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn claude_run_command() {
    let proxy = claude_proxy();
    let (repo, daemon, fake_home) = setup_claude_test_repo(proxy);

    let mut session = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        fake_home.path(),
        "claude-haiku-4-5",
        &[],
    );

    session.wait_for("~/workspace");

    // tr joins space-separated words with dashes: the prompt has
    // "rumpelpod cmd ok" (spaces) but the output on screen is
    // "rumpelpod-cmd-ok" (dashes), avoiding a premature match.
    session.send("Run: echo 'rumpelpod cmd ok' | tr ' ' '-'");

    session.wait_for("rumpelpod-cmd-ok");
}
