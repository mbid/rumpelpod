// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import { RumpelpodController } from "./controller";
import { DaemonEvents } from "./events";
import { RumpelpodModel } from "./model";
import { ReviewDocuments } from "./review";
import { AgentTerminals } from "./terminal";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Rumpelpod", { log: true });
  const model = new RumpelpodModel(context.workspaceState, output);
  const terminals = new AgentTerminals();
  const reviews = new ReviewDocuments();
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.name = "Rumpelpod Active Agent";
  status.command = "rumpelpod.showPods";
  const controller = new RumpelpodController(model, terminals, reviews, status);
  const events = new DaemonEvents(model, controller);

  context.subscriptions.push(
    output,
    terminals,
    reviews,
    status,
    controller,
    events,
    vscode.commands.registerCommand("rumpelpod.showPods", () =>
      runCommand(model, "selecting a pod", () => controller.showPodSwitcher()),
    ),
    vscode.commands.registerCommand("rumpelpod.refresh", () =>
      runCommand(model, "refreshing the active pod", () => controller.refresh()),
    ),
    vscode.commands.registerCommand("rumpelpod.createPod", () =>
      runCommand(model, "creating a pod", () => controller.createPod()),
    ),
    vscode.commands.registerCommand("rumpelpod.changeActiveAgent", () =>
      runCommand(model, "changing the active agent", () => controller.changeActiveAgent()),
    ),
    vscode.commands.registerCommand("rumpelpod.pickReviewFile", () =>
      runCommand(model, "selecting a review file", () => controller.pickReviewFile()),
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("rumpelpod.defaultAgent")) {
        controller.updateStatus();
      }
      if (event.affectsConfiguration("rumpelpod.executable")) {
        events.restart();
      }
    }),
  );

  controller.updateStatus();
  void events.start().catch((error: unknown) => {
    model.logError("starting rumpelpod daemon events", error);
    events.restart();
  });
  void runCommand(model, "removing obsolete review placeholders", () =>
    reviews.clearPlaceholders(),
  );
  void runCommand(model, "restoring the active pod", () => controller.restoreLastPod());
}

export function deactivate(): void {}

async function runCommand(
  model: RumpelpodModel,
  context: string,
  command: () => Promise<void>,
): Promise<void> {
  try {
    await command();
  } catch (error) {
    model.logError(context, error);
    await vscode.window.showErrorMessage(`Rumpelpod failed while ${context}: ${errorMessage(error)}`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
