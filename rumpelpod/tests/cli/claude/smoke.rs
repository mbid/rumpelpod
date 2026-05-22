// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Smoke test: verify a simple prompt reaches the Claude CLI inside the
//! container and produces a visible response via the caching proxy.

use super::common::{setup_claude_test_repo, ClaudeSession};

#[test]
fn claude_smoke() {
    let (home, repo, _executor, daemon) = setup_claude_test_repo();

    let mut session = ClaudeSession::spawn(&repo, &daemon, home.path(), "claude-haiku-4-5", &[]);

    // Wait for the TUI to finish loading.  "~/workspace" appears in the
    // status line once the CLI is ready for input.
    session.wait_for("~/workspace");
    session.send("What is the capital of France? Reply with just the city name, nothing else.");

    session.wait_for("Paris");
}
