// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that `rumpel fork` carries Claude Code conversation state
//! across to the new pod: start a session with a known UUID in pod A,
//! ask a memorable question, detach, fork to pod B, then resume the
//! same UUID in B and confirm the prior turn is in the history.

use std::time::{Duration, Instant};

use rumpelpod::CommandExt;

use super::common::{setup_claude_test_repo, ClaudeSession};
use crate::common::{pod_command, TestDaemon, TestRepo};

/// Ctrl-a then 'd' detaches without ending the session.
const CTRL_A: u8 = 0x01;

/// Pre-chosen session UUID; --resume picks the same JSONL file.
const SESSION_ID: &str = "11111111-2222-3333-4444-555555555555";

/// Block until `rumpel list` shows the pod's CLAUDE column is no
/// longer "processing".  The Stop hook runs asynchronously after the
/// last token renders, so a fork that triggers immediately after
/// `wait_for("Paris")` would race the state transition.
fn wait_until_claude_idle(repo: &TestRepo, daemon: &TestDaemon, pod: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let stdout = pod_command(repo, daemon)
            .arg("list")
            .success()
            .expect("rumpel list failed");
        let stdout = String::from_utf8_lossy(&stdout);
        let row = stdout
            .lines()
            .find(|l| l.split_whitespace().next() == Some(pod))
            .unwrap_or("");
        if !row.contains("processing") && !row.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "claude state stayed 'processing' for pod {pod} for 30s; list output:\n{stdout}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn fork_carries_claude_session() {
    let (home, repo, _executor, daemon) = setup_claude_test_repo();

    // 1. Start a session on the source pod with our known UUID and
    //    ask a question whose answer we can match later.
    let mut session = ClaudeSession::spawn_for_pod(
        &repo,
        &daemon,
        home.path(),
        "src",
        true,
        "claude-haiku-4-5",
        &["--session-id", SESSION_ID],
    );
    session.wait_for("~/workspace");
    session.send("What is the capital of France? Reply with just the city name, nothing else.");
    session.wait_for("Paris");

    // Detach so the in-pod claude process keeps the JSONL on disk.
    session.write_raw(&[CTRL_A, b'd']);
    session.wait_for_exit();

    // 2. Fork the source pod.
    // The Stop hook lands at the pod server slightly after the
    // response renders, so the daemon may still see claude as
    // "processing" right after wait_for("Paris") returns.  Wait for
    // the state to flip via `rumpel list` before forking, otherwise
    // the daemon refuses without --allow-processing.
    wait_until_claude_idle(&repo, &daemon, "src");

    pod_command(&repo, &daemon)
        .args(["fork", "src", "fk"])
        .success()
        .expect("rumpel fork failed");

    // 3. Resume the same UUID inside the new pod -- the file must
    //    have been carried over by the agent-files transfer for the
    //    CLI to find it.
    let mut resumed = ClaudeSession::spawn_for_pod(
        &repo,
        &daemon,
        home.path(),
        "fk",
        false,
        "claude-haiku-4-5",
        &["--resume", SESSION_ID],
    );
    resumed.wait_for("~/workspace");

    // The resumed TUI replays the prior user turn back into the
    // conversation view, so the previously-asked prompt should be
    // visible on screen without any new input.
    resumed.wait_for("capital of France");
}

/// Sanity check: without a fork, `--resume <uuid>` finds the prior
/// session.  This guards against the test passing for the wrong reason
/// (e.g. claude finding the session via some non-file mechanism).
#[test]
fn fork_test_baseline_resume_works_in_place() {
    let (home, repo, _executor, daemon) = setup_claude_test_repo();

    let mut session = ClaudeSession::spawn_for_pod(
        &repo,
        &daemon,
        home.path(),
        "src",
        true,
        "claude-haiku-4-5",
        &["--session-id", SESSION_ID],
    );
    session.wait_for("~/workspace");
    session.send("What is the capital of France? Reply with just the city name, nothing else.");
    session.wait_for("Paris");
    session.write_raw(&[CTRL_A, b'd']);
    session.wait_for_exit();

    // Make sure the JSONL is on disk inside the pod before we resume,
    // so a failure of the fork test cannot be mistaken for a baseline
    // problem.
    let listing = pod_command(&repo, &daemon)
        .args([
            "enter",
            "src",
            "--",
            "ls",
            "/home/testuser/.claude/projects",
        ])
        .success()
        .expect("listing claude projects dir failed");
    let listing = String::from_utf8_lossy(&listing);
    assert!(
        !listing.trim().is_empty(),
        "claude projects dir should not be empty, got: {listing:?}"
    );

    let mut resumed = ClaudeSession::spawn_for_pod(
        &repo,
        &daemon,
        home.path(),
        "src",
        false,
        "claude-haiku-4-5",
        &["--resume", SESSION_ID],
    );
    resumed.wait_for("~/workspace");
    resumed.wait_for("capital of France");
}
