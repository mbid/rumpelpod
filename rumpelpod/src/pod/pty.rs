// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pod-side adapter for the generic PTY screen-session machinery.
//!
//! Wires the `/claude` WebSocket route to the shared `pty_session`
//! bridge, with a cmd-transform that resolves the in-container Claude
//! CLI binary path before the first spawn.

use std::path::{Path, PathBuf};

use anyhow::Result;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::State;
use axum::response::Response;

pub use crate::pty_session::PtySessions;
use crate::pty_session::{serve_ws_session, CmdTransform};

// ---------------------------------------------------------------------------
// Claude CLI resolution
// ---------------------------------------------------------------------------

/// Return the path to the Claude CLI binary, which must be pre-installed
/// in the container image (baked in by the prepared image build).
fn find_claude_cli() -> Result<PathBuf> {
    let bin_path = Path::new(crate::daemon::CLAUDE_CONTAINER_BIN);
    if bin_path.exists() {
        return Ok(bin_path.to_path_buf());
    }

    if let Some(found) = crate::which("claude") {
        return Ok(found);
    }

    Err(anyhow::anyhow!(
        "Claude CLI not found at {} or in PATH",
        crate::daemon::CLAUDE_CONTAINER_BIN
    ))
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn claude_session_handler(
    ws: WebSocketUpgrade,
    State(state): State<super::server::PodServerState>,
) -> Response {
    ws.on_upgrade(move |socket| {
        let transform: CmdTransform = Box::new(|cmd: &mut Vec<String>| {
            let claude_bin = find_claude_cli()?;
            cmd[0] = claude_bin.to_string_lossy().into_owned();
            Ok(())
        });
        serve_ws_session(socket, state.pty_sessions, Some(transform))
    })
}
