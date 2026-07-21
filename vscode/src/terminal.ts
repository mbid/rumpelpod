// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";
import { createHash } from "node:crypto";

import type { AgentKind } from "./generated/protocol";
import type { Repository } from "./model";

const TERMINAL_KEY_ENV = "RUMPELPOD_VSCODE_TERMINAL";

export class AgentTerminals implements vscode.Disposable {
  private readonly terminals = new Map<string, vscode.Terminal>();
  private readonly closeSubscription: vscode.Disposable;
  private readonly openSubscription: vscode.Disposable;

  public constructor() {
    this.openSubscription = vscode.window.onDidOpenTerminal((terminal) => {
      const identity = terminalIdentity(terminal);
      const matched =
        identity === undefined
          ? [...this.terminals.entries()].find(([, candidate]) =>
              sameTerminal(candidate, terminal),
            )
          : undefined;
      const key = identity ?? matched?.[0];
      if (key === undefined) {
        return;
      }
      const existing = this.terminals.get(key);
      if (existing === undefined || existing === terminal) {
        this.terminals.set(key, terminal);
        return;
      }
      if (terminal.exitStatus !== undefined) {
        terminal.dispose();
        return;
      }
      existing.dispose();
      this.terminals.set(key, terminal);
    });
    this.closeSubscription = vscode.window.onDidCloseTerminal((terminal) => {
      for (const [key, candidate] of this.terminals) {
        if (candidate === terminal) {
          this.terminals.delete(key);
          return;
        }
      }
    });
  }

  public waitForRestoration(): Promise<void> {
    // VS Code restores persistent terminals independently of extension activation.
    // Let that list settle before deciding which assigned agents need a new process.
    return new Promise((resolve) => {
      const earliest = Date.now() + 1_000;
      let quietTimer: NodeJS.Timeout;
      let deadline: NodeJS.Timeout;
      const finish = (): void => {
        clearTimeout(quietTimer);
        clearTimeout(deadline);
        opened.dispose();
        resolve();
      };
      const schedule = (): void => {
        clearTimeout(quietTimer);
        const delay = Math.max(250, earliest - Date.now());
        quietTimer = setTimeout(finish, delay);
      };
      const opened = vscode.window.onDidOpenTerminal(schedule);
      deadline = setTimeout(finish, 3_000);
      schedule();
    });
  }

  public show(
    repository: Repository,
    pod: string,
    agent: AgentKind,
    executable: string,
  ): vscode.Terminal {
    const key = terminalKey(repository, pod);
    const name = terminalName(repository, pod, agent);
    const candidates = new Set([
      ...matchingTerminals(key, name, repository.root),
      ...(this.terminals.get(key) === undefined ? [] : [this.terminals.get(key)]),
    ]);
    const existing = [...candidates].find(
      (candidate): candidate is vscode.Terminal =>
        candidate !== undefined && candidate.exitStatus === undefined,
    );
    for (const candidate of candidates) {
      if (candidate !== undefined && candidate !== existing) {
        candidate.dispose();
      }
    }
    if (existing !== undefined) {
      this.terminals.set(key, existing);
      existing.show(false);
      return existing;
    }
    this.terminals.delete(key);

    const terminal = vscode.window.createTerminal({
      name,
      cwd: repository.root,
      env: { [TERMINAL_KEY_ENV]: key },
      iconPath: new vscode.ThemeIcon("terminal"),
      location: {
        viewColumn: vscode.ViewColumn.One,
        preserveFocus: false,
      },
      message: `Starting ${agent} in rumpelpod ${pod}`,
      shellArgs: [agent, "--create", pod],
      shellPath: executable,
    });
    this.terminals.set(key, terminal);
    terminal.show(false);
    return terminal;
  }

  public replace(repository: Repository, pod: string): void {
    const key = terminalKey(repository, pod);
    const prefix = terminalNamePrefix(repository, pod);
    const terminals = new Set([
      ...matchingTerminals(key, prefix, repository.root, true),
      ...(this.terminals.get(key) === undefined ? [] : [this.terminals.get(key)]),
    ]);
    this.terminals.delete(key);
    for (const terminal of terminals) {
      if (terminal !== undefined) {
        terminal.dispose();
      }
    }
  }

  public dispose(): void {
    this.closeSubscription.dispose();
    this.openSubscription.dispose();
  }
}

function terminalKey(repository: Repository, pod: string): string {
  return JSON.stringify([repository.root, pod]);
}

function terminalName(repository: Repository, pod: string, agent: AgentKind): string {
  return `${terminalNamePrefix(repository, pod)}${agent})`;
}

function terminalNamePrefix(repository: Repository, pod: string): string {
  // Restored terminals can lose their cwd and environment, so the visible name
  // must distinguish roots even when workspace folders share a basename.
  const rootIdentity = createHash("sha256")
    .update(repository.root)
    .digest("hex")
    .slice(0, 12);
  return `Rumpelpod: ${repository.name}/${pod} [${rootIdentity}] (`;
}

function matchingTerminals(
  key: string,
  name: string,
  repositoryRoot: string,
  prefix = false,
): vscode.Terminal[] {
  return vscode.window.terminals.filter((terminal) => {
    if (terminalIdentity(terminal) === key) {
      return true;
    }
    const nameMatches = prefix ? terminal.name.startsWith(name) : terminal.name === name;
    if (!nameMatches) {
      return false;
    }
    const cwd = terminalCwd(terminal);
    return cwd === undefined || cwd === repositoryRoot;
  });
}

function terminalIdentity(terminal: vscode.Terminal): string | undefined {
  const creationOptions = terminal.creationOptions;
  return "env" in creationOptions
    ? (creationOptions.env?.[TERMINAL_KEY_ENV] ?? undefined)
    : undefined;
}

function terminalCwd(terminal: vscode.Terminal): string | undefined {
  const creationOptions = terminal.creationOptions;
  if (!("cwd" in creationOptions)) {
    return undefined;
  }
  const cwd = creationOptions.cwd;
  if (typeof cwd === "string") {
    return cwd;
  }
  return cwd?.fsPath;
}

function sameTerminal(left: vscode.Terminal, right: vscode.Terminal): boolean {
  if (left.name !== right.name) {
    return false;
  }
  const leftCwd = terminalCwd(left);
  const rightCwd = terminalCwd(right);
  return leftCwd === undefined || rightCwd === undefined || leftCwd === rightCwd;
}
