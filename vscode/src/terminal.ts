// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { AgentKind } from "./generated/protocol";
import type { Repository } from "./model";

const TERMINAL_KEY_ENV = "RUMPELPOD_VSCODE_TERMINAL";

export class AgentTerminals implements vscode.Disposable {
  private readonly terminals = new Map<string, vscode.Terminal>();
  private readonly closeSubscription: vscode.Disposable;

  public constructor() {
    this.closeSubscription = vscode.window.onDidCloseTerminal((terminal) => {
      for (const [key, candidate] of this.terminals) {
        if (candidate === terminal) {
          this.terminals.delete(key);
          return;
        }
      }
    });
  }

  public show(
    repository: Repository,
    pod: string,
    agent: AgentKind,
    executable: string,
  ): vscode.Terminal {
    const key = terminalKey(repository, pod);
    const existing = this.terminals.get(key) ?? findRestoredTerminal(key);
    if (existing !== undefined) {
      this.terminals.set(key, existing);
      existing.show(false);
      return existing;
    }

    const terminal = vscode.window.createTerminal({
      name: `Rumpelpod: ${repository.name}/${pod} (${agent})`,
      cwd: repository.root,
      env: { [TERMINAL_KEY_ENV]: key },
      iconPath: new vscode.ThemeIcon("terminal"),
      location: {
        viewColumn: vscode.ViewColumn.One,
        preserveFocus: false,
      },
      message: `Starting ${agent} in rumpelpod ${pod}`,
    });
    this.terminals.set(key, terminal);
    terminal.show(false);
    terminal.sendText(
      `${quoteForPosixShell(executable)} ${agent} --create ${quoteForPosixShell(pod)}`,
      true,
    );
    return terminal;
  }

  public replace(repository: Repository, pod: string): void {
    const key = terminalKey(repository, pod);
    const terminal = this.terminals.get(key) ?? findRestoredTerminal(key);
    if (terminal !== undefined) {
      this.terminals.delete(key);
      terminal.dispose();
    }
  }

  public dispose(): void {
    this.closeSubscription.dispose();
  }
}

function terminalKey(repository: Repository, pod: string): string {
  return JSON.stringify([repository.root, pod]);
}

function findRestoredTerminal(key: string): vscode.Terminal | undefined {
  return vscode.window.terminals.find((terminal) => {
    const creationOptions = terminal.creationOptions;
    return "env" in creationOptions && creationOptions.env?.[TERMINAL_KEY_ENV] === key;
  });
}

function quoteForPosixShell(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
