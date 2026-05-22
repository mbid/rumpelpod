// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that `claude.sessions` controls whether host-recorded
//! Claude Code sessions are copied into the pod for `--resume`.
//!
//! Records a host session by running the real `claude` CLI so the
//! JSONL on disk is exactly what a user running `claude` on their
//! laptop would produce, then spawns claude in a pod with `--resume
//! <uuid>`.  With the flag on the session is carried across; with
//! the flag off (the default) the pod-side CLI reports "No
//! conversation found".
//!
//! The host-side claude is pointed at the daemon's LLM cache proxy
//! via `ANTHROPIC_BASE_URL` so subsequent runs serve from cache
//! instead of hitting the real Anthropic API every time.

use std::process::{Command, Stdio};

use super::common::{setup_claude_test_repo, ClaudeSession};
use crate::common::{TestDaemon, TestRepo};

/// Pre-chosen session UUID; --session-id records under this UUID and
/// --resume looks it up.
const SESSION_ID: &str = "11111111-2222-3333-4444-555555555555";

/// Merge `"claude": { "sessions": {} }` into the `.rumpelpod.json`
/// that `setup_claude_test_repo` wrote, enabling the host-to-pod
/// session copy.  The executor body already on disk can be `{}`
/// (Docker) or contain executor-specific fields that must be
/// preserved.
fn enable_sessions(repo: &TestRepo) {
    let path = repo.path().join(".rumpelpod.json");
    let existing = std::fs::read(&path).expect("read .rumpelpod.json");
    let mut obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&existing).expect("parse .rumpelpod.json");
    obj.insert("claude".to_string(), serde_json::json!({ "sessions": {} }));
    std::fs::write(&path, serde_json::to_vec_pretty(&obj).unwrap()).expect("write .rumpelpod.json");
}

/// Run claude on the host in --print mode, writing a session JSONL
/// under `home/.claude/projects/<host-encoded>/<uuid>.jsonl`.
///
/// `ANTHROPIC_BASE_URL` points at the daemon's cache proxy so
/// responses are served from `llm-cache/` on subsequent runs.  A
/// syntactically-valid-looking `ANTHROPIC_API_KEY` is supplied only
/// to satisfy claude's own "am I logged in?" check; the proxy
/// substitutes the daemon's real key on cache miss.
///
/// `--bare` skips CLAUDE.md auto-discovery, hooks, and other
/// per-machine bits that would otherwise inject the current date and
/// other host-specific text into the request body, making the cache
/// key drift day to day.
fn record_host_session(repo: &TestRepo, home: &std::path::Path, daemon: &TestDaemon) {
    let base_url = daemon.llm_cache_proxy_url("anthropic");
    let output = Command::new("claude")
        .current_dir(repo.path())
        .env_clear()
        .env("HOME", home)
        .env("PATH", home.join(".local/bin"))
        .env("ANTHROPIC_API_KEY", "sk-ant-api03-placeholder-for-tests")
        .env("ANTHROPIC_BASE_URL", &base_url)
        .args([
            "-p",
            "--bare",
            "--model",
            "claude-haiku-4-5",
            "--session-id",
            SESSION_ID,
            "What is the capital of France? Reply with just the city name, nothing else.",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run host claude");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "host claude failed\nstatus: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status,
    );
    assert!(
        stdout.contains("Paris"),
        "host claude response missing 'Paris'\nstdout: {stdout}\nstderr: {stderr}",
    );
}

#[test]
fn resume_host_session_with_sessions_enabled() {
    let (home, repo, _executor, daemon) = setup_claude_test_repo();
    home.link_local_bin("claude");
    enable_sessions(&repo);
    record_host_session(&repo, home.path(), &daemon);

    let mut resumed = ClaudeSession::spawn_for_pod(
        &repo,
        &daemon,
        home.path(),
        "resumer",
        true,
        "claude-haiku-4-5",
        &["--resume", SESSION_ID],
    );
    resumed.wait_for("~/workspace");
    resumed.wait_for("capital of France");
}

/// With the flag off (the default), a host-recorded session must not
/// be visible inside the pod.  The claude CLI in the pod reports
/// "No conversation found" and exits, leaving that exact text on the
/// TUI's screen.
#[test]
fn resume_host_session_with_sessions_disabled_by_default() {
    let (home, repo, _executor, daemon) = setup_claude_test_repo();
    home.link_local_bin("claude");
    // Deliberately do NOT call enable_sessions.
    record_host_session(&repo, home.path(), &daemon);

    let mut resumed = ClaudeSession::spawn_for_pod(
        &repo,
        &daemon,
        home.path(),
        "resumer",
        true,
        "claude-haiku-4-5",
        &["--resume", SESSION_ID],
    );
    resumed.wait_for(&format!(
        "No conversation found with session ID: {SESSION_ID}"
    ));
}
