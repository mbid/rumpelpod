// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";
import { randomBytes } from "node:crypto";
import type * as NodePty from "node-pty";

import type { AgentKind } from "./generated/protocol";
import { agentLabel, isAgentKind } from "./agents";
import type { Repository } from "./model";

let nodePty: typeof NodePty | undefined;

export const AGENT_VIEW_ID = "rumpelpod.agent";

const MAX_BUFFERED_OUTPUT = 1_048_576;
const MIN_COLUMNS = 2;
const MAX_COLUMNS = 500;
const MIN_ROWS = 2;
const MAX_ROWS = 300;
const TERMINATION_GRACE_MILLISECONDS = 500;
type TerminalTab = "agent" | "shell";
type MenuKind = "agent" | "create" | "pod";

export interface AgentMenuOption {
  readonly agent: AgentKind;
  readonly current: boolean;
  readonly description: string;
  readonly label: string;
}

export interface PodMenuOption {
  readonly active: boolean;
  readonly detail: string;
  readonly name: string;
  readonly repository: string;
  readonly status: string;
  readonly summary: string;
}

export interface RepositoryMenuOption {
  readonly name: string;
  readonly root: string;
}

export type AgentViewAction =
  | { readonly request: number; readonly type: "changeAgent" }
  | {
      readonly agent: AgentKind;
      readonly pod: string;
      readonly repository: string;
      readonly type: "createPod";
    }
  | { readonly request: number; readonly type: "createPodMenu" }
  | { readonly type: "openShell" }
  | { readonly pod: string; readonly repository: string; readonly type: "openPod" }
  | { readonly request: number; readonly type: "podMenu" }
  | { readonly type: "refresh" }
  | { readonly type: "restartAgent" }
  | { readonly agent: AgentKind; readonly type: "setAgent" };

interface AgentSelection {
  readonly agent: AgentKind;
  readonly executable: string;
  readonly generation: number;
  readonly pod: string;
  readonly repository: Repository;
  readonly repositoryState: string;
  readonly state: string;
}

interface RunningTerminal {
  readonly data: NodePty.IDisposable;
  readonly exit: NodePty.IDisposable;
  readonly process: NodePty.IPty;
  readonly session: number;
  readonly tab: TerminalTab;
}

interface TerminalChannel {
  bufferedOutput: string;
  outputInFlight:
    | { readonly data: string; readonly sequence: number; readonly session: number }
    | undefined;
  outputSequence: number;
  pausedOutput: NodePty.IPty | undefined;
  running: RunningTerminal | undefined;
  session: number;
  viewMessage: string | undefined;
  viewState: "empty" | "exited" | "running" | "starting";
}

type ViewMessage =
  | { readonly cols: number; readonly rows: number; readonly type: "ready" }
  | {
      readonly data: string;
      readonly session: number;
      readonly tab: TerminalTab;
      readonly type: "input";
    }
  | {
      readonly sequence: number;
      readonly session: number;
      readonly tab: TerminalTab;
      readonly type: "outputAck";
    }
  | {
      readonly cols: number;
      readonly rows: number;
      readonly session: number;
      readonly tab: TerminalTab;
      readonly type: "resize";
    }
  | { readonly session: number; readonly tab: TerminalTab; readonly type: "restart" }
  | { readonly tab: TerminalTab; readonly type: "selectTab" }
  | AgentViewAction
  | { readonly focused: boolean; readonly type: "terminalFocus" };

interface AgentMenuMessage {
  readonly agents: readonly AgentMenuOption[];
  readonly request: number;
  readonly type: "agentMenu";
}

interface CreatePodMenuMessage {
  readonly agents: readonly AgentMenuOption[];
  readonly repositories: readonly RepositoryMenuOption[];
  readonly request: number;
  readonly type: "createPodMenu";
}

interface PodMenuMessage {
  readonly pods: readonly PodMenuOption[];
  readonly request: number;
  readonly type: "podMenu";
}

interface DismissMenuMessage {
  readonly request: number;
  readonly type: "dismissMenu";
}

interface BeginMenuMessage {
  readonly menu: MenuKind;
  readonly request: number;
  readonly type: "beginMenu";
}

function newChannel(): TerminalChannel {
  return {
    bufferedOutput: "",
    outputInFlight: undefined,
    outputSequence: 0,
    pausedOutput: undefined,
    running: undefined,
    session: 0,
    viewMessage: undefined,
    viewState: "empty",
  };
}

export class AgentTerminals implements vscode.WebviewViewProvider, vscode.Disposable {
  private readonly didRequestActionEmitter = new vscode.EventEmitter<AgentViewAction>();
  private readonly didShowEmitter = new vscode.EventEmitter<void>();
  private readonly legacyTerminalSubscription: vscode.Disposable;
  private readonly agentChannel = newChannel();
  private readonly shellChannel = newChannel();
  private activeTab: TerminalTab = "agent";
  private columns = 80;
  private disposed = false;
  private generation = 0;
  private menuRevealDepth = 0;
  private nextHostMenuRequest = 0;
  private ready = false;
  private rows = 24;
  private selection: AgentSelection | undefined;
  private shellKey: string | undefined;
  private shellSwitches = Promise.resolve();
  private switches = Promise.resolve();
  private terminalFocused = false;
  private view: vscode.WebviewView | undefined;

  public readonly onDidShow = this.didShowEmitter.event;
  public readonly onDidRequestAction = this.didRequestActionEmitter.event;

  public hasFocus(): boolean {
    return this.terminalFocused;
  }

  public async restoreFocus(): Promise<void> {
    const view = this.view;
    if (view === undefined) {
      return;
    }
    await view.webview.postMessage({ type: "focus" });
  }

  public async beginMenu(menu: MenuKind, request?: number): Promise<number> {
    if (request !== undefined) {
      return request;
    }
    const hostRequest = --this.nextHostMenuRequest;
    this.menuRevealDepth += 1;
    try {
      await vscode.commands.executeCommand("workbench.view.extension.rumpelpod");
      if (this.disposed) {
        return hostRequest;
      }
      this.view?.show(false);
      await this.view?.webview.postMessage({
        menu,
        request: hostRequest,
        type: "beginMenu",
      } satisfies BeginMenuMessage);
    } finally {
      await delay(0);
      this.menuRevealDepth -= 1;
    }
    return hostRequest;
  }

  public async showAgentMenu(
    agents: readonly AgentMenuOption[],
    request: number,
  ): Promise<void> {
    await this.showMenu({ agents, request, type: "agentMenu" });
  }

  public dismissMenu(request: number): void {
    void this.view?.webview.postMessage({ request, type: "dismissMenu" } satisfies DismissMenuMessage);
  }

  public async showCreatePodMenu(
    repositories: readonly RepositoryMenuOption[],
    agents: readonly AgentMenuOption[],
    request: number,
  ): Promise<void> {
    await this.showMenu({ agents, repositories, request, type: "createPodMenu" });
  }

  public async showPodMenu(pods: readonly PodMenuOption[], request: number): Promise<void> {
    await this.showMenu({ pods, request, type: "podMenu" });
  }

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
  }

  public resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.reserveReattachment();
    this.reserveBufferedOutput(this.shellChannel);
    this.view = webviewView;
    this.ready = false;
    this.terminalFocused = false;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "dist")],
    };
    webviewView.webview.html = this.html(webviewView.webview);
    webviewView.webview.onDidReceiveMessage((message: unknown) => {
      this.handleMessage(message);
    });
    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible && this.menuRevealDepth === 0) {
        this.didShowEmitter.fire();
        this.reconcileCurrent("restoring the active agent");
      }
    });
    webviewView.onDidDispose(() => {
      if (this.view === webviewView) {
        this.view = undefined;
        this.ready = false;
        this.terminalFocused = false;
      }
    });
    this.updateView();
    if (webviewView.visible && this.menuRevealDepth === 0) {
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
    if (
      !sameSelection ||
      (this.agentChannel.running === undefined && this.agentChannel.viewState === "exited")
    ) {
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
      this.agentChannel.session += 1;
      this.resetOutputBuffer(this.agentChannel);
      this.updateChannel(this.agentChannel, "starting");
    }

    const key = terminalKey(repository, pod);
    const closePreviousShell = this.shellKey !== undefined && this.shellKey !== key;
    this.activeTab = "agent";
    if (closePreviousShell) {
      this.shellKey = undefined;
    }
    this.updateView();
    if (closePreviousShell) {
      await this.enqueueShellSwitch(async () => {
        await this.stopRunning(this.shellChannel, "closing the previous pod shell");
        this.resetChannel(this.shellChannel);
      });
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
    this.agentChannel.session += 1;
    this.resetOutputBuffer(this.agentChannel);
    this.updateChannel(this.agentChannel, "starting");
    await this.reconcile(generation);
  }

  public showShell(repository: Repository, pod: string, executable: string): void {
    const selected = this.selection;
    if (selected?.repository.root !== repository.root || selected.pod !== pod) {
      throw new Error(`select ${pod} before opening its shell`);
    }
    this.activeTab = "shell";
    this.updateView();
    void this.openShellView(repository, pod, executable).catch((error: unknown) => {
      this.reportError("opening the pod shell", error);
    });
  }

  public dispose(): void {
    this.disposed = true;
    this.generation += 1;
    this.terminalFocused = false;
    this.didRequestActionEmitter.dispose();
    this.didShowEmitter.dispose();
    this.legacyTerminalSubscription.dispose();
    for (const channel of [this.agentChannel, this.shellChannel]) {
      const running = channel.running;
      channel.running = undefined;
      if (running === undefined) {
        continue;
      }
      if (channel.pausedOutput === running.process) {
        this.resumePausedOutput(channel);
      }
      const context = `closing the active ${running.tab}`;
      void this.terminateRunning(running, context).catch((error: unknown) => {
        this.reportError(context, error);
      });
    }
  }

  private async showMenu(
    message: AgentMenuMessage | CreatePodMenuMessage | PodMenuMessage,
  ): Promise<void> {
    if (this.disposed) {
      return;
    }
    await this.view?.webview.postMessage(message);
  }

  private async startNow(selected: AgentSelection, session: number): Promise<void> {
    this.updateChannel(this.agentChannel, "starting");
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
      this.updateChannel(
        this.agentChannel,
        "exited",
        `Starting ${agentLabel(selected.agent)} failed: ${errorMessage(error)}`,
      );
      throw error;
    }
    const running: RunningTerminal = {
      data: process.onData((data) => {
        this.handleOutput(this.agentChannel, running, data);
      }),
      exit: process.onExit((event) => {
        this.handleExit(this.agentChannel, running, event);
      }),
      process,
      session,
      tab: "agent",
    };
    this.agentChannel.running = running;
    this.updateChannel(this.agentChannel, "running");
  }

  private async startShell(repository: Repository, pod: string, executable: string): Promise<void> {
    return this.enqueueShellSwitch(() => this.startShellNow(repository, pod, executable));
  }

  private async startShellNow(
    repository: Repository,
    pod: string,
    executable: string,
  ): Promise<void> {
    const key = terminalKey(repository, pod);
    if (this.shellKey === key && this.shellChannel.running !== undefined) {
      this.updateView();
      return;
    }
    await this.stopRunning(this.shellChannel, "closing the previous pod shell");
    if (
      this.disposed ||
      this.selection?.repository.root !== repository.root ||
      this.selection.pod !== pod
    ) {
      return;
    }
    this.shellKey = key;
    this.shellChannel.session += 1;
    this.resetOutputBuffer(this.shellChannel);
    this.updateChannel(this.shellChannel, "starting");
    let process: NodePty.IPty;
    try {
      process = loadNodePty().spawn(executable, ["enter", pod], {
        cols: this.columns,
        cwd: repository.root,
        env: { ...globalThis.process.env },
        name: "xterm-256color",
        rows: this.rows,
      });
    } catch (error) {
      this.updateChannel(
        this.shellChannel,
        "exited",
        `Starting the shell failed: ${errorMessage(error)}`,
      );
      throw error;
    }
    const session = this.shellChannel.session;
    const running: RunningTerminal = {
      data: process.onData((data) => {
        this.handleOutput(this.shellChannel, running, data);
      }),
      exit: process.onExit((event) => {
        this.handleExit(this.shellChannel, running, event);
      }),
      process,
      session,
      tab: "shell",
    };
    this.shellChannel.running = running;
    this.updateChannel(this.shellChannel, "running");
  }

  private async openShellView(
    repository: Repository,
    pod: string,
    executable: string,
  ): Promise<void> {
    await vscode.commands.executeCommand("workbench.view.extension.rumpelpod");
    this.view?.show(false);
    await this.startShell(repository, pod, executable);
  }

  private handleOutput(
    channel: TerminalChannel,
    running: RunningTerminal,
    data: string,
  ): void {
    if (channel.running !== running || running.session !== channel.session) {
      return;
    }
    channel.bufferedOutput = `${channel.bufferedOutput}${data}`;
    this.pauseOutputIfNeeded(channel);
    this.flushBufferedOutput(channel, running.tab);
  }

  private handleExit(
    channel: TerminalChannel,
    running: RunningTerminal,
    event: { exitCode: number; signal?: number },
  ): void {
    if (channel.running !== running) {
      return;
    }
    running.data.dispose();
    running.exit.dispose();
    channel.running = undefined;
    if (running.tab === "shell") {
      this.shellKey = undefined;
      this.activeTab = "agent";
    }
    const signal = event.signal === undefined ? "" : `, signal ${event.signal}`;
    const label = running.tab === "agent"
      ? `${agentLabel(this.selection?.agent ?? "codex")} attachment`
      : "Shell";
    this.updateChannel(
      channel,
      "exited",
      `${label} exited (${event.exitCode}${signal}).`,
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
        this.updateChannel(
          this.agentChannel,
          this.agentChannel.running?.session === this.agentChannel.session
            ? "running"
            : this.agentChannel.viewState,
        );
        this.flushBufferedOutput(this.agentChannel, "agent");
        this.flushBufferedOutput(this.shellChannel, "shell");
        this.reconcileCurrent("starting the active agent");
        return;
      case "input":
        {
          const channel = this.channel(value.tab);
          if (value.session === channel.session && channel.running !== undefined) {
            channel.running.process.write(value.data);
          }
        }
        return;
      case "outputAck":
        {
          const channel = this.channel(value.tab);
          if (
            value.session === channel.session &&
            channel.outputInFlight?.session === value.session &&
            channel.outputInFlight.sequence === value.sequence
          ) {
            channel.outputInFlight = undefined;
            this.flushBufferedOutput(channel, value.tab);
            this.resumeOutputIfPossible(channel);
          }
        }
        return;
      case "resize":
        {
          const channel = this.channel(value.tab);
          if (value.session !== channel.session) {
            return;
          }
          this.columns = clamp(value.cols, MIN_COLUMNS, MAX_COLUMNS);
          this.rows = clamp(value.rows, MIN_ROWS, MAX_ROWS);
          channel.running?.process.resize(this.columns, this.rows);
        }
        return;
      case "restart":
        if (value.tab === "agent") {
          if (value.session !== this.agentChannel.session) {
            return;
          }
          void this.restartActive().catch((error: unknown) => {
            this.reportError("restarting the active agent", error);
          });
          return;
        }
        if (value.session === this.shellChannel.session) {
          const selected = this.selection;
          if (selected === undefined) {
            this.reportError("restarting the active pod shell", new Error("no pod is selected"));
            return;
          }
          this.shellKey = undefined;
          void this.startShell(selected.repository, selected.pod, selected.executable).catch(
            (error: unknown) => {
              this.reportError("restarting the active pod shell", error);
            },
          );
        }
        return;
      case "changeAgent":
      case "createPod":
      case "createPodMenu":
      case "openPod":
      case "openShell":
      case "podMenu":
      case "refresh":
      case "restartAgent":
      case "setAgent":
        this.didRequestActionEmitter.fire(value);
        return;
      case "selectTab":
        if (value.tab === "agent") {
          this.activeTab = "agent";
          this.updateView();
          return;
        }
        const selected = this.selection;
        if (selected === undefined) {
          this.reportError("opening the pod shell", new Error("select a pod first"));
          return;
        }
        this.showShell(selected.repository, selected.pod, selected.executable);
        return;
      case "terminalFocus":
        this.terminalFocused = value.focused;
        return;
    }
  }

  private flushBufferedOutput(channel: TerminalChannel, tab: TerminalTab): void {
    if (
      channel.bufferedOutput.length === 0 ||
      this.view === undefined ||
      !this.ready ||
      channel.outputInFlight !== undefined
    ) {
      return;
    }
    const view = this.view;
    const data = channel.bufferedOutput;
    const session = channel.session;
    const sequence = ++channel.outputSequence;
    channel.bufferedOutput = "";
    const output = { data, sequence, session };
    channel.outputInFlight = output;
    void Promise.resolve(
      view.webview.postMessage({ data, sequence, session, tab, type: "output" }),
    ).then(
      (delivered) => {
        if (!delivered) {
          this.restoreUndeliveredOutput(channel, output);
        }
      },
      (error: unknown) => {
        this.restoreUndeliveredOutput(channel, output, error);
      },
    );
  }

  private updateChannel(
    channel: TerminalChannel,
    viewState?: "empty" | "exited" | "running" | "starting",
    message?: string,
  ): void {
    if (viewState !== undefined) {
      if (viewState !== channel.viewState || message !== undefined) {
        channel.viewMessage = message;
      }
      channel.viewState = viewState;
    }
    this.updateView();
  }

  private updateView(): void {
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
    view.title = "";
    view.description = undefined;
    void view.webview.postMessage({
      activeTab: this.activeTab,
      agent: selected?.agent ?? "",
      agentMessage:
        this.agentChannel.viewMessage ?? emptyMessage(selected, this.agentChannel.viewState),
      agentSession: this.agentChannel.session,
      agentState: selected === undefined ? "empty" : this.agentChannel.viewState,
      pod: selected?.pod ?? "",
      repository: selected?.repository.name ?? "",
      repositoryState: selected?.repositoryState ?? "",
      shellMessage: this.shellChannel.viewMessage ?? shellMessage(this.shellChannel.viewState),
      shellOpen: this.shellKey !== undefined,
      shellSession: this.shellChannel.session,
      shellState: selected === undefined ? "empty" : this.shellChannel.viewState,
      type: "state",
    });
  }

  private async stopRunning(channel: TerminalChannel, context: string): Promise<void> {
    const running = channel.running;
    channel.running = undefined;
    if (running === undefined) {
      return;
    }
    if (channel.pausedOutput === running.process) {
      this.resumePausedOutput(channel);
    }
    await this.terminateRunning(running, context);
  }

  private async terminateRunning(running: RunningTerminal, context: string): Promise<void> {
    let exited = false;
    let resolveExit: (() => void) | undefined;
    const processExited = new Promise<void>((resolve) => {
      resolveExit = resolve;
    });
    const exit = running.process.onExit(() => {
      exited = true;
      resolveExit?.();
    });
    running.data.dispose();
    running.exit.dispose();
    try {
      if (running.tab === "agent") {
        running.process.write("\x01d");
      } else {
        running.process.kill();
      }
    } catch (error) {
      this.reportError(context, error);
    }
    await Promise.race([processExited, delay(TERMINATION_GRACE_MILLISECONDS)]);
    if (!exited) {
      try {
        running.process.kill();
      } catch (error) {
        this.reportError(context, error);
      }
      await Promise.race([processExited, delay(TERMINATION_GRACE_MILLISECONDS)]);
    }
    if (!exited) {
      this.reportError(
        context,
        new Error(`${running.tab} terminal did not exit after fallback kill`),
      );
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
    if (this.selection === undefined || this.agentChannel.running === undefined) {
      return;
    }
    const generation = ++this.generation;
    this.selection = { ...this.selection, generation };
    this.agentChannel.session += 1;
    this.resetOutputBuffer(this.agentChannel);
    this.agentChannel.viewMessage = undefined;
    this.agentChannel.viewState = "starting";
  }

  private reserveBufferedOutput(channel: TerminalChannel): void {
    const output = channel.outputInFlight;
    if (output === undefined) {
      return;
    }
    channel.outputInFlight = undefined;
    if (output.session === channel.session) {
      channel.bufferedOutput = `${output.data}${channel.bufferedOutput}`;
    }
  }

  private pauseOutputIfNeeded(channel: TerminalChannel): void {
    const process = channel.running?.process;
    if (
      this.queuedOutputLength(channel) < MAX_BUFFERED_OUTPUT ||
      process === undefined ||
      channel.pausedOutput !== undefined
    ) {
      return;
    }
    try {
      process.pause();
      channel.pausedOutput = process;
    } catch (error) {
      this.reportError("pausing terminal output", error);
    }
  }

  private resetOutputBuffer(channel: TerminalChannel): void {
    channel.bufferedOutput = "";
    channel.outputInFlight = undefined;
    this.resumePausedOutput(channel);
  }

  private restoreUndeliveredOutput(
    channel: TerminalChannel,
    output: {
      readonly data: string;
      readonly sequence: number;
      readonly session: number;
    },
    error?: unknown,
  ): void {
    if (channel.outputInFlight !== output) {
      return;
    }
    channel.outputInFlight = undefined;
    if (output.session === channel.session) {
      channel.bufferedOutput = `${output.data}${channel.bufferedOutput}`;
      this.ready = false;
      this.pauseOutputIfNeeded(channel);
    }
    if (error !== undefined) {
      this.reportError("sending terminal output to the webview", error);
    }
  }

  private resumeOutputIfPossible(channel: TerminalChannel): void {
    if (this.queuedOutputLength(channel) < MAX_BUFFERED_OUTPUT / 2) {
      this.resumePausedOutput(channel);
    }
  }

  private queuedOutputLength(channel: TerminalChannel): number {
    return channel.bufferedOutput.length + (channel.outputInFlight?.data.length ?? 0);
  }

  private resumePausedOutput(channel: TerminalChannel): void {
    const process = channel.pausedOutput;
    channel.pausedOutput = undefined;
    if (process === undefined) {
      return;
    }
    try {
      process.resume();
    } catch (error) {
      this.reportError("resuming terminal output", error);
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
      const session = this.agentChannel.session;
      if (this.agentChannel.running?.session === session) {
        return;
      }
      await this.stopRunning(this.agentChannel, "closing the previous agent attachment");
      if (
        this.selection?.generation !== generation ||
        this.agentChannel.session !== session ||
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

  private enqueueShellSwitch(update: () => Promise<void>): Promise<void> {
    const result = this.shellSwitches.then(update);
    this.shellSwitches = result.catch(() => {});
    return result;
  }

  private channel(tab: TerminalTab): TerminalChannel {
    switch (tab) {
      case "agent":
        return this.agentChannel;
      case "shell":
        return this.shellChannel;
    }
  }

  private resetChannel(channel: TerminalChannel): void {
    channel.session += 1;
    this.resetOutputBuffer(channel);
    channel.viewMessage = undefined;
    channel.viewState = "empty";
    this.updateView();
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
    <header id="pod-header">
      <button id="pod-selector" type="button" aria-label="Select pod" aria-expanded="false">
        <span id="pod-name">Select pod</span>
        <span id="pod-chevron" aria-hidden="true"></span>
      </button>
      <div id="pod-actions" aria-label="Pod actions">
        <button id="open-shell" class="icon-action" type="button" aria-label="Open shell" title="Open shell">
          <svg aria-hidden="true" viewBox="0 0 20 20"><path d="M3 5.5 7.5 10 3 14.5M9.5 14.5H17"/></svg>
        </button>
        <button id="change-agent" class="icon-action" type="button" aria-label="Change agent" title="Change agent" aria-expanded="false">
          <svg aria-hidden="true" viewBox="0 0 20 20"><circle cx="10" cy="6" r="3"/><path d="M4.5 16c.7-3 2.5-4.5 5.5-4.5s4.8 1.5 5.5 4.5"/></svg>
        </button>
        <button id="create-pod" class="icon-action" type="button" aria-label="Create pod" title="Create pod" aria-expanded="false">
          <svg aria-hidden="true" viewBox="0 0 20 20"><path d="M10 3v14M3 10h14"/></svg>
        </button>
        <button id="more-actions" class="icon-action" type="button" aria-label="More pod actions" title="More pod actions" aria-expanded="false">
          <svg aria-hidden="true" viewBox="0 0 20 20"><circle cx="4" cy="10" r="1"/><circle cx="10" cy="10" r="1"/><circle cx="16" cy="10" r="1"/></svg>
        </button>
      </div>
    </header>
    <nav id="terminal-tabs" aria-label="Pod terminal" role="tablist">
      <button id="agent-tab" class="terminal-tab" type="button" role="tab" aria-controls="agent-surface" aria-selected="true">agent</button>
      <button id="shell-tab" class="terminal-tab" type="button" role="tab" aria-controls="shell-surface" aria-selected="false">shell</button>
    </nav>
    <div id="surfaces">
      <section id="agent-surface" class="surface">
        <div id="agent-terminal" class="terminal" aria-label="Rumpelpod agent terminal"></div>
        <div id="agent-empty" class="empty">
          <p id="agent-empty-message">Select or create a pod.</p>
          <button id="agent-restart" class="restart" type="button">Restart attachment</button>
        </div>
      </section>
      <section id="shell-surface" class="surface">
        <div id="shell-terminal" class="terminal" aria-label="Rumpelpod shell terminal"></div>
        <div id="shell-empty" class="empty">
          <p id="shell-empty-message">Select a pod to open its shell.</p>
          <button id="shell-restart" class="restart" type="button">Restart shell</button>
        </div>
      </section>
    </div>
    <div id="popover-layer"></div>
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
    return "Select or create a pod above.";
  }
  switch (state) {
    case "empty":
      return "Select or create a pod above.";
    case "exited":
      return `${agentLabel(selected.agent)} is not attached.`;
    case "running":
    case "starting":
      return `Starting ${agentLabel(selected.agent)} in ${selected.pod}.`;
  }
}

function shellMessage(state: "empty" | "exited" | "running" | "starting"): string {
  switch (state) {
    case "empty":
      return "Select shell to open a terminal in this pod.";
    case "exited":
      return "The pod shell has exited.";
    case "running":
    case "starting":
      return "Starting the pod shell.";
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
        typeof value.session === "number" &&
        "tab" in value &&
        isTerminalTab(value.tab)
      );
    case "outputAck":
      return (
        "sequence" in value &&
        typeof value.sequence === "number" &&
        "session" in value &&
        typeof value.session === "number" &&
        "tab" in value &&
        isTerminalTab(value.tab)
      );
    case "resize":
      return (
        hasDimensions(value) &&
        "session" in value &&
        typeof value.session === "number" &&
        "tab" in value &&
        isTerminalTab(value.tab)
      );
    case "restart":
      return (
        "session" in value &&
        typeof value.session === "number" &&
        "tab" in value &&
        isTerminalTab(value.tab)
      );
    case "changeAgent":
    case "createPodMenu":
    case "podMenu":
      return "request" in value && isRequest(value.request);
    case "openShell":
    case "refresh":
    case "restartAgent":
      return true;
    case "createPod":
      return (
        "agent" in value &&
        isAgentKind(value.agent) &&
        "pod" in value &&
        typeof value.pod === "string" &&
        "repository" in value &&
        typeof value.repository === "string"
      );
    case "openPod":
      return (
        "pod" in value &&
        typeof value.pod === "string" &&
        "repository" in value &&
        typeof value.repository === "string"
      );
    case "setAgent":
      return "agent" in value && isAgentKind(value.agent);
    case "selectTab":
      return "tab" in value && isTerminalTab(value.tab);
    case "terminalFocus":
      return "focused" in value && typeof value.focused === "boolean";
    default:
      return false;
  }
}

function isTerminalTab(value: unknown): value is TerminalTab {
  switch (value) {
    case "agent":
    case "shell":
      return true;
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

function isRequest(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, Math.floor(value)));
}

function terminalKey(repository: Repository, pod: string): string {
  return JSON.stringify([repository.root, pod]);
}

function disposeLegacyAgentTerminal(terminal: vscode.Terminal): void {
  if (
    terminal.name.startsWith("Rumpelpod: ") ||
    terminal.name.startsWith("Rumpelpod shell: ")
  ) {
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
