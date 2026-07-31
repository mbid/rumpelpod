// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";
import { randomBytes } from "node:crypto";
import type * as NodePty from "node-pty";

import type { AgentKind } from "./generated/protocol";
import { agentLabel } from "./agents";
import type { Repository } from "./model";

let nodePty: typeof NodePty | undefined;

export const AGENT_VIEW_ID = "rumpelpod.agent";

const MAX_BUFFERED_OUTPUT = 1_048_576;
const MIN_COLUMNS = 2;
const MAX_COLUMNS = 500;
const MIN_ROWS = 2;
const MAX_ROWS = 300;
const SHELL_TERMINAL_ENV = "RUMPELPOD_VSCODE_SHELL";

interface AgentSelection {
  readonly agent: AgentKind;
  readonly executable: string;
  readonly generation: number;
  readonly pod: string;
  readonly repository: Repository;
  readonly repositoryState: string;
  readonly state: string;
}

interface RunningAgent {
  readonly data: NodePty.IDisposable;
  readonly exit: NodePty.IDisposable;
  readonly process: NodePty.IPty;
  readonly session: number;
}

type ViewMessage =
  | { readonly cols: number; readonly rows: number; readonly type: "ready" }
  | { readonly data: string; readonly session: number; readonly type: "input" }
  | { readonly sequence: number; readonly session: number; readonly type: "outputAck" }
  | { readonly cols: number; readonly rows: number; readonly session: number; readonly type: "resize" }
  | { readonly session: number; readonly type: "restart" };

export class AgentTerminals implements vscode.WebviewViewProvider, vscode.Disposable {
  private readonly didShowEmitter = new vscode.EventEmitter<void>();
  private readonly legacyTerminalSubscription: vscode.Disposable;
  private readonly shells = new Set<vscode.Terminal>();
  private readonly shellCloseSubscription: vscode.Disposable;
  private bufferedOutput = "";
  private columns = 80;
  private disposed = false;
  private generation = 0;
  private outputInFlight:
    | { readonly data: string; readonly sequence: number; readonly session: number }
    | undefined;
  private outputSequence = 0;
  private pausedOutput: NodePty.IPty | undefined;
  private ready = false;
  private rows = 24;
  private running: RunningAgent | undefined;
  private selection: AgentSelection | undefined;
  private session = 0;
  private switches = Promise.resolve();
  private view: vscode.WebviewView | undefined;
  private viewMessage: string | undefined;
  private viewState: "empty" | "exited" | "running" | "starting" = "empty";

  public readonly onDidShow = this.didShowEmitter.event;

  public constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly reportError: (context: string, error: unknown) => void,
  ) {
    for (const terminal of vscode.window.terminals) {
      disposeLegacyAgentTerminal(terminal);
    }
    this.legacyTerminalSubscription = vscode.window.onDidOpenTerminal((terminal) => {
      disposeLegacyAgentTerminal(terminal);
    });
    this.shellCloseSubscription = vscode.window.onDidCloseTerminal((terminal) => {
      this.shells.delete(terminal);
    });
  }

  public resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.reserveReattachment();
    this.view = webviewView;
    this.ready = false;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "dist")],
    };
    webviewView.webview.html = this.html(webviewView.webview);
    webviewView.webview.onDidReceiveMessage((message: unknown) => {
      this.handleMessage(message);
    });
    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) {
        this.didShowEmitter.fire();
        this.reconcileCurrent("restoring the active agent");
      }
    });
    webviewView.onDidDispose(() => {
      if (this.view === webviewView) {
        this.view = undefined;
        this.ready = false;
      }
    });
    this.updateView();
    if (webviewView.visible) {
      this.didShowEmitter.fire();
    }
  }

  public async showActive(
    repository: Repository,
    pod: string,
    agent: AgentKind,
    executable: string,
  ): Promise<void> {
    const current = this.selection;
    const sameSelection =
      current?.repository.root === repository.root &&
      current.pod === pod &&
      current.agent === agent &&
      current.executable === executable;
    let generation = current?.generation ?? this.generation;
    if (!sameSelection || (this.running === undefined && this.viewState === "exited")) {
      generation = ++this.generation;
      this.selection = {
        agent,
        executable,
        generation,
        pod,
        repository,
        repositoryState: sameSelection ? current.repositoryState : "",
        state: sameSelection ? current.state : "starting",
      };
      this.session += 1;
      this.resetOutputBuffer();
      this.updateView("starting");
    }

    await vscode.commands.executeCommand("workbench.view.extension.rumpelpod");
    if (this.selection?.generation !== generation || this.disposed) {
      return;
    }
    this.view?.show(false);
    await this.reconcile(generation);
  }

  public updateActiveState(
    repository: Repository,
    pod: string,
    agent: AgentKind,
    state: string,
    repositoryState: string,
  ): void {
    const selected = this.selection;
    if (
      selected?.repository.root !== repository.root ||
      selected.pod !== pod ||
      selected.agent !== agent
    ) {
      return;
    }
    this.selection = { ...selected, repositoryState, state };
    this.updateView();
  }

  public async restartActive(): Promise<void> {
    const selected = this.selection;
    if (selected === undefined) {
      throw new Error("select a pod before restarting its agent attachment");
    }
    const generation = ++this.generation;
    this.selection = { ...selected, generation };
    this.session += 1;
    this.resetOutputBuffer();
    this.updateView("starting");
    await this.reconcile(generation);
  }

  public showShell(repository: Repository, pod: string, executable: string): vscode.Terminal {
    const terminal = vscode.window.createTerminal({
      name: `Rumpelpod shell: ${repository.name}/${pod}`,
      cwd: repository.root,
      env: { [SHELL_TERMINAL_ENV]: terminalKey(repository, pod) },
      iconPath: new vscode.ThemeIcon("terminal-bash"),
      location: vscode.TerminalLocation.Panel,
      message: `Opening a shell in rumpelpod ${pod}`,
      shellArgs: ["enter", pod],
      shellPath: executable,
    });
    this.shells.add(terminal);
    terminal.show(false);
    return terminal;
  }

  public dispose(): void {
    this.disposed = true;
    this.generation += 1;
    this.didShowEmitter.dispose();
    this.legacyTerminalSubscription.dispose();
    this.shellCloseSubscription.dispose();
    const running = this.running;
    this.running = undefined;
    if (running !== undefined) {
      running.data.dispose();
      running.exit.dispose();
      try {
        running.process.write("\x01d");
      } catch (error) {
        this.reportError("detaching the active agent", error);
      }
      setTimeout(() => {
        try {
          running.process.kill();
        } catch (error) {
          this.reportError("closing the active agent attachment", error);
        }
      }, 250);
    }
  }

  private async startNow(selected: AgentSelection, session: number): Promise<void> {
    this.updateView("starting");
    let process: NodePty.IPty;
    try {
      process = loadNodePty().spawn(selected.executable, [selected.agent, "--create", selected.pod], {
        cols: this.columns,
        cwd: selected.repository.root,
        env: { ...globalThis.process.env },
        name: "xterm-256color",
        rows: this.rows,
      });
    } catch (error) {
      this.updateView("exited", `Starting ${agentLabel(selected.agent)} failed: ${errorMessage(error)}`);
      throw error;
    }
    const running: RunningAgent = {
      data: process.onData((data) => {
        this.handleOutput(session, data);
      }),
      exit: process.onExit((event) => {
        this.handleExit(running, event);
      }),
      process,
      session,
    };
    this.running = running;
    this.updateView("running");
  }

  private handleOutput(session: number, data: string): void {
    if (session !== this.session) {
      return;
    }
    this.bufferedOutput = `${this.bufferedOutput}${data}`;
    this.pauseOutputIfNeeded();
    this.flushBufferedOutput();
  }

  private handleExit(running: RunningAgent, event: { exitCode: number; signal?: number }): void {
    if (this.running !== running) {
      return;
    }
    running.data.dispose();
    running.exit.dispose();
    this.running = undefined;
    const signal = event.signal === undefined ? "" : `, signal ${event.signal}`;
    this.updateView(
      "exited",
      `${agentLabel(this.selection?.agent ?? "codex")} attachment exited (${event.exitCode}${signal}).`,
    );
  }

  private handleMessage(value: unknown): void {
    if (!isViewMessage(value)) {
      return;
    }
    switch (value.type) {
      case "ready":
        if (this.ready) {
          this.reserveReattachment();
        }
        this.ready = true;
        this.columns = clamp(value.cols, MIN_COLUMNS, MAX_COLUMNS);
        this.rows = clamp(value.rows, MIN_ROWS, MAX_ROWS);
        this.updateView(
          this.running?.session === this.session ? "running" : this.viewState,
        );
        this.flushBufferedOutput();
        this.reconcileCurrent("starting the active agent");
        return;
      case "input":
        if (value.session === this.session && this.running !== undefined) {
          this.running.process.write(value.data);
        }
        return;
      case "outputAck":
        if (
          value.session === this.session &&
          this.outputInFlight?.session === value.session &&
          this.outputInFlight.sequence === value.sequence
        ) {
          this.outputInFlight = undefined;
          this.flushBufferedOutput();
          this.resumeOutputIfPossible();
        }
        return;
      case "resize":
        if (value.session !== this.session) {
          return;
        }
        this.columns = clamp(value.cols, MIN_COLUMNS, MAX_COLUMNS);
        this.rows = clamp(value.rows, MIN_ROWS, MAX_ROWS);
        if (this.running !== undefined) {
          this.running.process.resize(this.columns, this.rows);
        }
        return;
      case "restart":
        if (value.session === this.session) {
          void this.restartActive().catch((error: unknown) => {
            this.reportError("restarting the active agent", error);
          });
        }
        return;
    }
  }

  private flushBufferedOutput(): void {
    if (
      this.bufferedOutput.length === 0 ||
      this.view === undefined ||
      !this.ready ||
      this.outputInFlight !== undefined
    ) {
      return;
    }
    const view = this.view;
    const data = this.bufferedOutput;
    const session = this.session;
    const sequence = ++this.outputSequence;
    this.bufferedOutput = "";
    const output = { data, sequence, session };
    this.outputInFlight = output;
    void Promise.resolve(
      view.webview.postMessage({ data, sequence, session, type: "output" }),
    ).then(
      (delivered) => {
        if (!delivered) {
          this.restoreUndeliveredOutput(output);
        }
      },
      (error: unknown) => {
        this.restoreUndeliveredOutput(output, error);
      },
    );
  }

  private updateView(
    viewState?: "empty" | "exited" | "running" | "starting",
    message?: string,
  ): void {
    if (viewState !== undefined) {
      if (viewState !== this.viewState || message !== undefined) {
        this.viewMessage = message;
      }
      this.viewState = viewState;
    }
    const selected = this.selection;
    const view = this.view;
    void vscode.commands.executeCommand(
      "setContext",
      "rumpelpod.hasActivePod",
      selected !== undefined,
    );
    if (view === undefined) {
      return;
    }
    if (selected === undefined) {
      view.title = "Agent";
      view.description = undefined;
    } else {
      view.title = `${selected.pod} / ${agentLabel(selected.agent)}`;
      const details = [selected.state, selected.repositoryState].filter((value) => value.length > 0);
      view.description = details.join(" / ");
    }
    void view.webview.postMessage({
      agent: selected?.agent ?? "",
      message: this.viewMessage ?? emptyMessage(selected, this.viewState),
      pod: selected?.pod ?? "",
      repository: selected?.repository.name ?? "",
      repositoryState: selected?.repositoryState ?? "",
      session: this.session,
      state: selected === undefined ? "empty" : this.viewState,
      type: "state",
    });
  }

  private async stopRunning(): Promise<void> {
    const running = this.running;
    this.running = undefined;
    if (running === undefined) {
      return;
    }
    if (this.pausedOutput === running.process) {
      this.resumePausedOutput();
    }
    running.data.dispose();
    running.exit.dispose();
    let exited = false;
    let resolveExit: (() => void) | undefined;
    const processExited = new Promise<void>((resolve) => {
      resolveExit = resolve;
    });
    const exit = running.process.onExit(() => {
      exited = true;
      resolveExit?.();
    });
    try {
      running.process.write("\x01d");
    } catch (error) {
      this.reportError("detaching the previous agent", error);
    }
    await Promise.race([processExited, delay(500)]);
    if (!exited) {
      try {
        running.process.kill();
      } catch (error) {
        this.reportError("closing the previous agent attachment", error);
      }
      await Promise.race([processExited, delay(500)]);
    }
    exit.dispose();
  }

  private reconcileCurrent(context: string): void {
    const generation = this.selection?.generation;
    if (generation === undefined) {
      return;
    }
    void this.reconcile(generation).catch((error: unknown) => {
      this.reportError(context, error);
    });
  }

  private reserveReattachment(): void {
    if (this.selection === undefined || this.running === undefined) {
      return;
    }
    const generation = ++this.generation;
    this.selection = { ...this.selection, generation };
    this.session += 1;
    this.resetOutputBuffer();
    this.viewMessage = undefined;
    this.viewState = "starting";
  }

  private pauseOutputIfNeeded(): void {
    const process = this.running?.process;
    if (
      this.queuedOutputLength() < MAX_BUFFERED_OUTPUT ||
      process === undefined ||
      this.pausedOutput !== undefined
    ) {
      return;
    }
    try {
      process.pause();
      this.pausedOutput = process;
    } catch (error) {
      this.reportError("pausing agent output", error);
    }
  }

  private resetOutputBuffer(): void {
    this.bufferedOutput = "";
    this.outputInFlight = undefined;
    this.resumePausedOutput();
  }

  private restoreUndeliveredOutput(
    output: {
      readonly data: string;
      readonly sequence: number;
      readonly session: number;
    },
    error?: unknown,
  ): void {
    if (this.outputInFlight !== output) {
      return;
    }
    this.outputInFlight = undefined;
    if (output.session === this.session) {
      this.bufferedOutput = `${output.data}${this.bufferedOutput}`;
      this.ready = false;
      this.pauseOutputIfNeeded();
    }
    if (error !== undefined) {
      this.reportError("sending agent output to the terminal", error);
    }
  }

  private resumeOutputIfPossible(): void {
    if (this.queuedOutputLength() < MAX_BUFFERED_OUTPUT / 2) {
      this.resumePausedOutput();
    }
  }

  private queuedOutputLength(): number {
    return this.bufferedOutput.length + (this.outputInFlight?.data.length ?? 0);
  }

  private resumePausedOutput(): void {
    const process = this.pausedOutput;
    this.pausedOutput = undefined;
    if (process === undefined) {
      return;
    }
    try {
      process.resume();
    } catch (error) {
      this.reportError("resuming agent output", error);
    }
  }

  private reconcile(generation: number): Promise<void> {
    return this.enqueueSwitch(async () => {
      const selected = this.selection;
      if (
        selected?.generation !== generation ||
        !this.ready ||
        this.disposed
      ) {
        return;
      }
      const session = this.session;
      if (this.running?.session === session) {
        return;
      }
      await this.stopRunning();
      if (
        this.selection?.generation !== generation ||
        this.session !== session ||
        !this.ready ||
        this.disposed
      ) {
        return;
      }
      await this.startNow(selected, session);
    });
  }

  private enqueueSwitch(update: () => Promise<void>): Promise<void> {
    const result = this.switches.then(update);
    this.switches = result.catch(() => {});
    return result;
  }

  private html(webview: vscode.Webview): string {
    const nonce = randomBytes(24).toString("base64");
    const script = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, "dist/webview.js"));
    const styles = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, "dist/webview.css"));
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; font-src ${webview.cspSource}; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="${styles}">
  <title>Rumpelpod Agent</title>
</head>
<body>
  <main id="app">
    <div id="terminal" aria-label="Rumpelpod agent terminal"></div>
    <div id="empty">
      <p id="empty-message">Select or create a pod from the view toolbar.</p>
      <button id="restart" type="button">Restart attachment</button>
    </div>
  </main>
  <script nonce="${nonce}" src="${script}"></script>
</body>
</html>`;
  }
}

function emptyMessage(
  selected: AgentSelection | undefined,
  state: "empty" | "exited" | "running" | "starting",
): string {
  if (selected === undefined) {
    return "Select or create a pod from the view toolbar.";
  }
  switch (state) {
    case "empty":
      return "Select or create a pod from the view toolbar.";
    case "exited":
      return `${agentLabel(selected.agent)} is not attached.`;
    case "running":
    case "starting":
      return `Starting ${agentLabel(selected.agent)} in ${selected.pod}.`;
  }
}

function isViewMessage(value: unknown): value is ViewMessage {
  if (typeof value !== "object" || value === null || !("type" in value)) {
    return false;
  }
  switch (value.type) {
    case "ready":
      return hasDimensions(value);
    case "input":
      return (
        "data" in value &&
        typeof value.data === "string" &&
        "session" in value &&
        typeof value.session === "number"
      );
    case "outputAck":
      return (
        "sequence" in value &&
        typeof value.sequence === "number" &&
        "session" in value &&
        typeof value.session === "number"
      );
    case "resize":
      return (
        hasDimensions(value) &&
        "session" in value &&
        typeof value.session === "number"
      );
    case "restart":
      return "session" in value && typeof value.session === "number";
    default:
      return false;
  }
}

function hasDimensions(value: object): value is { readonly cols: number; readonly rows: number } {
  return (
    "cols" in value &&
    typeof value.cols === "number" &&
    Number.isFinite(value.cols) &&
    "rows" in value &&
    typeof value.rows === "number" &&
    Number.isFinite(value.rows)
  );
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, Math.floor(value)));
}

function terminalKey(repository: Repository, pod: string): string {
  return JSON.stringify([repository.root, pod]);
}

function disposeLegacyAgentTerminal(terminal: vscode.Terminal): void {
  if (terminal.name.startsWith("Rumpelpod: ")) {
    terminal.dispose();
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function loadNodePty(): typeof NodePty {
  if (nodePty !== undefined) {
    return nodePty;
  }
  try {
    nodePty = require("./node-pty/lib/index.js") as typeof NodePty;
  } catch (error) {
    throw new Error(
      `The Rumpelpod terminal helper cannot run on ${process.platform}-${process.arch}. Install a Rumpelpod VSIX built for this platform: ${errorMessage(error)}`,
      { cause: error },
    );
  }
  return nodePty;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
