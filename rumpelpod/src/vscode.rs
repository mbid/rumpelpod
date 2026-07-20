// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Types shared with the VS Code extension.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Agent command that owns a pod's interactive terminal.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export_to = "AgentKind.ts")]
pub enum AgentKind {
    Claude,
    Codex,
    Grok,
    Pi,
}

impl AgentKind {
    pub fn command(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Grok => "grok",
            Self::Pi => "pi",
        }
    }
}
