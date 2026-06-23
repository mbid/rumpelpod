// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Smoke test: verify that the grok CLI runs inside the container, talks
//! to the xAI API through the pod server's LLM cache proxy, and renders
//! a response in its TUI.

use super::common::{setup_grok_test_repo, GrokSession, GROK_TEST_MODEL};

#[test]
fn grok_smoke() {
    let (home, repo, _executor, daemon) = setup_grok_test_repo();

    let mut session = GrokSession::spawn(&repo, &daemon, home.path(), GROK_TEST_MODEL);

    session.send("What is the capital of France? Reply with just the city name, nothing else.");
    session.wait_for("Paris");
}
