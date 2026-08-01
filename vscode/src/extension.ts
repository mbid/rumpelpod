// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import { RumpelpodController } from "./controller";
import { DaemonEvents } from "./events";
import { RumpelpodModel } from "./model";
import { ReviewDocuments } from "./review";
import { AGENT_VIEW_ID, AgentTerminals, type AgentViewAction } from "./terminal";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Rumpelpod", { log: true });
  const model = new RumpelpodModel(context.workspaceState, output);
  const terminals = new AgentTerminals(context.extensionUri, (operation, error) => {
    model.logError(operation, error);
  });
  const reviews = new ReviewDocuments((operation, error) => {
    model.logError(operation, error);
  });
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.name = "Rumpelpod Active Pod";
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
    terminals.onDidShow(() => {
      void runCommand(model, "opening the Rumpelpod view", () => controller.enterMode());
    }),
    terminals.onDidRequestAction((action) => {
      void runCommand(
        model,
        viewActionContext(action),
        () => controller.handleViewAction(action),
        () => dismissFailedMenu(terminals, action),
      );
    }),
    vscode.window.registerWebviewViewProvider(AGENT_VIEW_ID, terminals, {
      webviewOptions: { retainContextWhenHidden: true },
    }),
    vscode.commands.registerCommand("rumpelpod.showPods", () =>
      runCommand(model, "selecting a pod", () => controller.showPodSwitcher()),
    ),
    vscode.commands.registerCommand("rumpelpod.refresh", () =>
      runCommand(model, "refreshing the active pod", () => controller.refresh(true)),
    ),
    vscode.commands.registerCommand("rumpelpod.createPod", () =>
      runCommand(model, "creating a pod", () => controller.createPod()),
    ),
    vscode.commands.registerCommand("rumpelpod.launchAgent", () =>
      runCommand(model, "launching an agent", () => controller.launchAgentMenu()),
    ),
    vscode.commands.registerCommand("rumpelpod.openActiveShell", () =>
      runCommand(model, "opening a pod shell", async () => controller.openActiveShell()),
    ),
    vscode.commands.registerCommand("rumpelpod.restartSession", () =>
      runCommand(model, "restarting the current session", () => controller.restartCurrentSession()),
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("rumpelpod.executable")) {
        events.restart();
      }
    }),
  );

  controller.updateStatus();
  void vscode.commands.executeCommand("setContext", "rumpelpod.hasActivePod", false);
  void events.start().catch((error: unknown) => {
    model.logError("starting rumpelpod daemon events", error);
    events.restart();
  });
  void runCommand(model, "removing obsolete review placeholders", () =>
    reviews.clearPlaceholders(),
  );
}

function dismissFailedMenu(terminals: AgentTerminals, action: AgentViewAction): void {
  switch (action.type) {
    case "launchAgentMenu":
    case "createPodMenu":
    case "podMenu":
      terminals.dismissMenu(action.request);
      return;
    case "createPod":
    case "openPod":
    case "openShell":
    case "refresh":
    case "launchAgent":
    case "restartSession":
      return;
  }
}

function viewActionContext(action: AgentViewAction): string {
  switch (action.type) {
    case "launchAgentMenu":
      return "opening the agent selector";
    case "createPod":
      return "creating a pod";
    case "createPodMenu":
      return "opening pod creation";
    case "openPod":
      return "selecting a pod";
    case "openShell":
      return "opening a pod shell";
    case "podMenu":
      return "listing pods";
    case "refresh":
      return "refreshing the active pod";
    case "launchAgent":
      return "launching an agent";
    case "restartSession":
      return "restarting the current session";
  }
}

export function deactivate(): void {}

async function runCommand(
  model: RumpelpodModel,
  context: string,
  command: () => Promise<void>,
  onError?: () => void,
): Promise<void> {
  try {
    await command();
  } catch (error) {
    onError?.();
    model.logError(context, error);
    await vscode.window.showErrorMessage(`Rumpelpod failed while ${context}: ${errorMessage(error)}`);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
