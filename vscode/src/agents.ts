// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { AgentKind } from "./generated/protocol";

export const AGENTS: readonly AgentKind[] = ["claude", "codex", "grok", "pi"];

export function isAgentKind(value: unknown): value is AgentKind {
  return typeof value === "string" && AGENTS.some((agent) => agent === value);
}

export function agentLabel(agent: AgentKind): string {
  switch (agent) {
    case "claude":
      return "Claude Code";
    case "codex":
      return "Codex";
    case "grok":
      return "Grok";
    case "pi":
      return "pi";
  }
}

export function agentDescription(agent: AgentKind): string {
  switch (agent) {
    case "claude":
      return "Run Claude Code inside the pod";
    case "codex":
      return "Run the Codex TUI connected to the pod";
    case "grok":
      return "Run the xAI Grok CLI inside the pod";
    case "pi":
      return "Run the pi coding agent inside the pod";
  }
}
