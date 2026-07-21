// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import { RumpelpodController } from "./controller";
import { RumpelpodModel } from "./model";
import { ReviewDocuments } from "./review";
import { AgentTerminals } from "./terminal";
import { PodItem, PodTreeProvider, ReviewFileItem } from "./tree";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Rumpelpod", { log: true });
  const model = new RumpelpodModel(context.workspaceState, output);
  const tree = new PodTreeProvider(model);
  const terminals = new AgentTerminals();
  const reviews = new ReviewDocuments();
  const controller = new RumpelpodController(model, tree, terminals, reviews);

  const treeView = vscode.window.createTreeView("rumpelpod.pods", {
    treeDataProvider: tree,
    showCollapseAll: true,
  });

  context.subscriptions.push(
    output,
    tree,
    terminals,
    reviews,
    controller,
    treeView,
    vscode.commands.registerCommand("rumpelpod.refresh", () => controller.refresh()),
    vscode.commands.registerCommand("rumpelpod.createPod", () =>
      runCommand(model, "creating a pod", () => controller.createPod()),
    ),
    vscode.commands.registerCommand("rumpelpod.openPod", (item: PodItem) =>
      runCommand(model, `opening pod ${item.pod.name}`, () => controller.openPod(item)),
    ),
    vscode.commands.registerCommand("rumpelpod.changeAgent", (item: PodItem) =>
      runCommand(model, `changing the agent for ${item.pod.name}`, () =>
        controller.changeAgent(item),
      ),
    ),
    vscode.commands.registerCommand("rumpelpod.openReviewFile", (item: ReviewFileItem) =>
      runCommand(model, `opening review file ${item.file.path}`, () =>
        controller.openReviewFile(item),
      ),
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("rumpelpod.defaultAgent")) {
        tree.refresh();
      }
    }),
  );

  void runCommand(model, "restoring assigned pods", () => controller.restoreAssignedPods());
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
