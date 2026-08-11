// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";
import { randomBytes } from "node:crypto";
import type * as NodePty from "node-pty";

import { AGENTS, agentLabel, isAgentKind, type AgentKind } from "./agents";
import type { Repository } from "./model";

let nodePty: typeof NodePty | undefined;

export const AGENT_VIEW_ID = "rumpelpod.agent";

const MAX_BUFFERED_OUTPUT = 1_048_576;
const MIN_COLUMNS = 2;
const MAX_COLUMNS = 500;
const MIN_ROWS = 2;
const MAX_ROWS = 300;
const TERMINATION_GRACE_MILLISECONDS = 500;
type TerminalTab = AgentKind | "shell";
type MenuKind = "agent" | "create" | "pod";

export interface AgentMenuOption {
  readonly agent: AgentKind;
  readonly description: string;
  readonly label: string;
  readonly launched: boolean;
  readonly selected: boolean;
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
  | { readonly request: number; readonly type: "launchAgentMenu" }
  | {
      readonly agent: AgentKind;
      readonly pod: string;
      readonly repository: string;
      readonly type: "createPod";
    }
  | { readonly request: number; readonly type: "createPodMenu" }
  | { readonly type: "addSshKey" }
  | { readonly type: "deletePod" }
  | { readonly type: "mergePod" }
  | { readonly type: "openShell" }
  | { readonly type: "openPort" }
  | { readonly type: "openPortExternal" }
  | { readonly pod: string; readonly repository: string; readonly type: "openPod" }
  | { readonly request: number; readonly type: "podMenu" }
  | { readonly type: "refresh" }
  | { readonly type: "stopPod" }
  | { readonly type: "viewDiff" }
  | { readonly agent: AgentKind; readonly type: "launchAgent" };

interface AgentSelection {
  readonly agents: readonly AgentKind[];
  readonly executable: string;
  readonly generation: number;
  readonly pod: string;
  readonly repository: Repository;
  readonly repositoryState: string;
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
  private readonly agentChannels = new Map<AgentKind, TerminalChannel>(
    AGENTS.map((agent) => [agent, newChannel()]),
  );
  private readonly shellChannel = newChannel();
  private activeTab: TerminalTab = "codex";
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
  private tabBeforeShell: AgentKind | undefined;
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
  ) {}

  public resolveWebviewView(webviewView: vscode.WebviewView): void {
    for (const channel of this.agentChannels.values()) {
      this.reserveBufferedOutput(channel);
    }
    this.reserveBufferedOutput(this.shellChannel);
    this.reserveReattachment();
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
        this.reconcileCurrent("restoring the pod agent sessions");
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
    agents: readonly AgentKind[],
    executable: string,
  ): Promise<void> {
    const orderedAgents = uniqueAgents(agents);
    const firstAgent = orderedAgents[0];
    if (firstAgent === undefined) {
      throw new Error(`pod '${pod}' has no agent sessions to attach`);
    }
    const current = this.selection;
    const sameSelection =
      current?.repository.root === repository.root &&
      current.pod === pod &&
      current.executable === executable &&
      sameAgents(current.agents, orderedAgents);
    let generation = current?.generation ?? this.generation;
    if (!sameSelection) {
      generation = ++this.generation;
      this.selection = {
        agents: orderedAgents,
        executable,
        generation,
        pod,
        repository,
        repositoryState: "",
      };
      for (const availableAgent of AGENTS) {
        const channel = this.agentChannel(availableAgent);
        channel.session += 1;
        this.resetOutputBuffer(channel);
        channel.viewMessage = undefined;
        channel.viewState = orderedAgents.includes(availableAgent) ? "starting" : "empty";
      }
    }

    const key = terminalKey(repository, pod);
    const closePreviousShell = this.shellKey !== undefined && this.shellKey !== key;
    if (
      !sameSelection ||
      (this.activeTab === "shell"
        ? this.shellKey !== key
        : !orderedAgents.includes(this.activeTab))
    ) {
      this.activeTab = firstAgent;
    }
    if (closePreviousShell) {
      this.shellKey = undefined;
      this.tabBeforeShell = undefined;
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

  public async launchAgent(
    repository: Repository,
    pod: string,
    agent: AgentKind,
    executable: string,
  ): Promise<void> {
    const selected = this.selection;
    if (
      selected?.repository.root !== repository.root ||
      selected.pod !== pod ||
      selected.executable !== executable
    ) {
      throw new Error(`select ${pod} before launching ${agentLabel(agent)}`);
    }
    this.activeTab = agent;
    if (selected.agents.includes(agent)) {
      this.updateView();
      const channel = this.agentChannel(agent);
      if (channel.viewState === "empty" || channel.viewState === "exited") {
        await this.restartActive();
      }
      await this.restoreFocus();
      return;
    }
    const generation = ++this.generation;
    this.selection = {
      ...selected,
      agents: [...selected.agents, agent],
      generation,
    };
    const channel = this.agentChannel(agent);
    channel.session += 1;
    this.resetOutputBuffer(channel);
    this.updateChannel(channel, "starting");
    await vscode.commands.executeCommand("workbench.view.extension.rumpelpod");
    if (this.selection?.generation !== generation || this.disposed) {
      return;
    }
    this.view?.show(false);
    await this.reconcile(generation);
    await this.restoreFocus();
  }

  public updateActiveRepositoryState(
    repository: Repository,
    pod: string,
    repositoryState: string,
  ): void {
    const selected = this.selection;
    if (
      selected?.repository.root !== repository.root ||
      selected.pod !== pod
    ) {
      return;
    }
    this.selection = { ...selected, repositoryState };
    this.updateView();
  }

  public async clearActive(repository: Repository, pod: string): Promise<void> {
    const selected = this.selection;
    if (selected?.repository.root !== repository.root || selected.pod !== pod) {
      return;
    }
    this.generation += 1;
    this.selection = undefined;
    this.shellKey = undefined;
    this.tabBeforeShell = undefined;
    this.activeTab = "codex";
    this.updateView();
    await Promise.all([
      this.enqueueSwitch(async () => {
        for (const agent of AGENTS) {
          const channel = this.agentChannel(agent);
          await this.stopRunning(channel, `closing the inactive pod's ${agent} attachment`);
          this.resetChannel(channel);
        }
      }),
      this.enqueueShellSwitch(async () => {
        await this.stopRunning(this.shellChannel, "closing the inactive pod shell");
        this.resetChannel(this.shellChannel);
      }),
    ]);
  }

  public async restartActive(): Promise<void> {
    const selected = this.selection;
    if (selected === undefined) {
      throw new Error("select a pod before restarting a session");
    }
    if (this.activeTab === "shell") {
      if (this.shellKey === undefined) {
        throw new Error("open a pod shell before restarting it");
      }
      this.shellKey = undefined;
      await this.startShell(selected.repository, selected.pod, selected.executable);
      return;
    }
    const agent = this.activeTab;
    if (!selected.agents.includes(agent)) {
      throw new Error(`${agentLabel(agent)} has not been launched in ${selected.pod}`);
    }
    const generation = ++this.generation;
    this.selection = { ...selected, generation };
    const channel = this.agentChannel(agent);
    channel.session += 1;
    this.resetOutputBuffer(channel);
    this.updateChannel(channel, "starting");
    await this.reconcile(generation);
  }

  public showShell(repository: Repository, pod: string, executable: string): void {
    const selected = this.selection;
    if (selected?.repository.root !== repository.root || selected.pod !== pod) {
      throw new Error(`select ${pod} before opening its shell`);
    }
    if (this.activeTab !== "shell") {
      this.tabBeforeShell = this.activeTab;
      this.activeTab = "shell";
    }
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
    for (const channel of [...this.agentChannels.values(), this.shellChannel]) {
      const running = channel.running;
      channel.running = undefined;
      if (running === undefined) {
        continue;
      }
      if (channel.pausedOutput === running.process) {
        this.resumePausedOutput(channel);
      }
      const context = `closing the ${running.tab} session`;
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

  private async startNow(
    selected: AgentSelection,
    agent: AgentKind,
    channel: TerminalChannel,
    session: number,
  ): Promise<void> {
    this.updateChannel(channel, "starting");
    let process: NodePty.IPty;
    try {
      process = loadNodePty().spawn(selected.executable, [agent, "--create", selected.pod], {
        cols: this.columns,
        cwd: selected.repository.root,
        env: { ...globalThis.process.env },
        name: "xterm-256color",
        rows: this.rows,
      });
    } catch (error) {
      this.updateChannel(
        channel,
        "exited",
        `Starting ${agentLabel(agent)} failed: ${errorMessage(error)}`,
      );
      throw error;
    }
    const running: RunningTerminal = {
      data: process.onData((data) => {
        this.handleOutput(channel, running, data);
      }),
      exit: process.onExit((event) => {
        this.handleExit(channel, running, event);
      }),
      process,
      session,
      tab: agent,
    };
    channel.running = running;
    this.updateChannel(channel, "running");
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
      if (this.activeTab === "shell") {
        const returnTab = this.tabBeforeShell;
        if (returnTab !== undefined && this.selection?.agents.includes(returnTab) === true) {
          this.activeTab = returnTab;
        } else {
          const firstAgent = this.selection?.agents[0];
          if (firstAgent !== undefined) {
            this.activeTab = firstAgent;
          }
        }
      }
      this.tabBeforeShell = undefined;
    }
    const signal = event.signal === undefined ? "" : `, signal ${event.signal}`;
    const label = running.tab === "shell" ? "Shell" : `${agentLabel(running.tab)} attachment`;
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
        for (const agent of AGENTS) {
          const channel = this.agentChannel(agent);
          this.updateChannel(
            channel,
            channel.running?.session === channel.session ? "running" : channel.viewState,
          );
          this.flushBufferedOutput(channel, agent);
        }
        this.flushBufferedOutput(this.shellChannel, "shell");
        this.reconcileCurrent("starting the pod agent sessions");
        return;
      case "input":
        {
          const channel = this.channel(value.tab);
          if (
            value.session === channel.session &&
            channel.running !== undefined &&
            channel.running.session === channel.session
          ) {
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
          if (channel.running?.session === channel.session) {
            channel.running.process.resize(this.columns, this.rows);
          }
        }
        return;
      case "restart":
        if (value.tab !== this.activeTab || value.session !== this.channel(value.tab).session) {
          return;
        }
        void this.restartActive().catch((error: unknown) => {
          this.reportError("restarting the selected session", error);
        });
        return;
      case "launchAgentMenu":
      case "addSshKey":
      case "createPod":
      case "createPodMenu":
      case "deletePod":
      case "mergePod":
      case "openPod":
      case "openPort":
      case "openPortExternal":
      case "openShell":
      case "podMenu":
      case "refresh":
      case "stopPod":
      case "viewDiff":
      case "launchAgent":
        this.didRequestActionEmitter.fire(value);
        return;
      case "selectTab":
        if (!this.hasSession(value.tab)) {
          return;
        }
        if (value.tab === "shell" && this.activeTab !== "shell") {
          this.tabBeforeShell = this.activeTab;
        }
        this.activeTab = value.tab;
        this.updateView();
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
    const sessions = selected === undefined
      ? []
      : selected.agents.map((agent) => this.sessionState(agent, selected));
    if (selected !== undefined && this.shellKey !== undefined) {
      sessions.push(this.sessionState("shell", selected));
    }
    void view.webview.postMessage({
      activeTab: this.activeTab,
      pod: selected?.pod ?? "",
      repository: selected?.repository.name ?? "",
      repositoryState: selected?.repositoryState ?? "",
      sessions,
      type: "state",
    });
  }

  private sessionState(tab: TerminalTab, selected: AgentSelection): {
    readonly key: string;
    readonly label: string;
    readonly message: string;
    readonly session: number;
    readonly state: "empty" | "exited" | "running" | "starting";
    readonly tab: TerminalTab;
  } {
    const channel = this.channel(tab);
    return {
      key: terminalKey(selected.repository, selected.pod),
      label: tab,
      message:
        channel.viewMessage ??
        (tab === "shell"
          ? shellMessage(channel.viewState)
          : emptyMessage(tab, selected.pod, channel.viewState)),
      session: channel.session,
      state: channel.viewState,
      tab,
    };
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
      if (running.tab === "shell") {
        running.process.kill();
      } else {
        running.process.write("\x01d");
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
    const selected = this.selection;
    if (
      selected === undefined ||
      !selected.agents.some((agent) => this.agentChannel(agent).running !== undefined)
    ) {
      return;
    }
    const generation = ++this.generation;
    this.selection = { ...selected, generation };
    for (const agent of selected.agents) {
      const channel = this.agentChannel(agent);
      if (channel.running === undefined) {
        continue;
      }
      channel.session += 1;
      this.resetOutputBuffer(channel);
      channel.viewMessage = undefined;
      channel.viewState = "starting";
    }
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
      const results = await Promise.allSettled(
        AGENTS.map(async (agent) => {
          const channel = this.agentChannel(agent);
          const session = channel.session;
          if (channel.running?.session === session) {
            return;
          }
          await this.stopRunning(channel, `closing the previous ${agent} attachment`);
          if (
            this.selection?.generation !== generation ||
            channel.session !== session ||
            !this.ready ||
            this.disposed ||
            !selected.agents.includes(agent) ||
            channel.viewState !== "starting"
          ) {
            return;
          }
          await this.startNow(selected, agent, channel, session);
        }),
      );
      const failures = results
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) => result.reason);
      if (failures.length === 1) {
        throw failures[0];
      }
      if (failures.length > 1) {
        throw new AggregateError(failures, "starting pod agent sessions failed");
      }
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
      case "claude":
      case "codex":
      case "grok":
      case "pi":
        return this.agentChannel(tab);
      case "shell":
        return this.shellChannel;
    }
  }

  private agentChannel(agent: AgentKind): TerminalChannel {
    const channel = this.agentChannels.get(agent);
    if (channel === undefined) {
      throw new Error(`terminal channel for ${agent} is not initialized`);
    }
    return channel;
  }

  private hasSession(tab: TerminalTab): boolean {
    const selected = this.selection;
    if (selected === undefined) {
      return false;
    }
    switch (tab) {
      case "claude":
      case "codex":
      case "grok":
      case "pi":
        return selected.agents.includes(tab);
      case "shell":
        return this.shellKey !== undefined;
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
  <title>Rumpelpod Sessions</title>
</head>
<body>
  <main id="app">
    <header id="pod-header">
      <button id="pod-selector" type="button" aria-label="Select pod" aria-expanded="false" aria-haspopup="listbox">
        <span id="pod-name">Select pod</span>
        <span id="pod-chevron" aria-hidden="true"></span>
      </button>
      <div id="pod-actions" role="toolbar" aria-label="Pod actions">
        <button id="open-shell" class="icon-action" type="button" aria-label="Open shell" title="Open shell">
          <svg aria-hidden="true" viewBox="0 0 20 20"><path d="M3 5.5 7.5 10 3 14.5M9.5 14.5H17"/></svg>
        </button>
        <button id="launch-agent" class="icon-action" type="button" aria-label="Launch agent" title="Launch agent" aria-expanded="false" aria-haspopup="menu">
          <svg aria-hidden="true" viewBox="0 0 20 20"><circle cx="10" cy="6" r="3"/><path d="M4.5 16c.7-3 2.5-4.5 5.5-4.5s4.8 1.5 5.5 4.5"/></svg>
        </button>
        <button id="merge-pod" class="icon-action" type="button" aria-label="Merge pod" title="Merge pod">
          <svg aria-hidden="true" viewBox="0 0 20 20"><circle cx="5" cy="4" r="2"/><circle cx="5" cy="16" r="2"/><circle cx="15" cy="10" r="2"/><path d="M5 6v3c0 1.7 1.3 3 3 3h5M5 14v-2"/></svg>
        </button>
        <button id="more-actions" class="icon-action" type="button" aria-label="More pod actions" title="More pod actions" aria-expanded="false" aria-haspopup="menu">
          <svg aria-hidden="true" viewBox="0 0 20 20"><circle cx="4" cy="10" r="1"/><circle cx="10" cy="10" r="1"/><circle cx="16" cy="10" r="1"/></svg>
        </button>
      </div>
    </header>
    <nav id="terminal-tabs" aria-label="Pod terminal" role="tablist" hidden>
      <button id="claude-tab" class="terminal-tab" type="button" role="tab" aria-controls="claude-surface" aria-selected="false" hidden>claude</button>
      <button id="codex-tab" class="terminal-tab" type="button" role="tab" aria-controls="codex-surface" aria-selected="true" hidden>codex</button>
      <button id="grok-tab" class="terminal-tab" type="button" role="tab" aria-controls="grok-surface" aria-selected="false" hidden>grok</button>
      <button id="pi-tab" class="terminal-tab" type="button" role="tab" aria-controls="pi-surface" aria-selected="false" hidden>pi</button>
      <button id="shell-tab" class="terminal-tab" type="button" role="tab" aria-controls="shell-surface" aria-selected="false" hidden>shell</button>
    </nav>
    <div id="surfaces">
      <div id="no-sessions" class="empty">Create or select a pod.</div>
      <section id="claude-surface" class="surface" hidden>
        <div id="claude-terminal" class="terminal" aria-label="Rumpelpod Claude terminal"></div>
        <div id="claude-empty" class="empty">
          <p id="claude-empty-message">Create or select a pod.</p>
          <button id="claude-restart" class="restart" type="button">Restart Claude</button>
        </div>
      </section>
      <section id="codex-surface" class="surface" hidden>
        <div id="codex-terminal" class="terminal" aria-label="Rumpelpod Codex terminal"></div>
        <div id="codex-empty" class="empty">
          <p id="codex-empty-message">Create or select a pod.</p>
          <button id="codex-restart" class="restart" type="button">Restart Codex</button>
        </div>
      </section>
      <section id="grok-surface" class="surface" hidden>
        <div id="grok-terminal" class="terminal" aria-label="Rumpelpod Grok terminal"></div>
        <div id="grok-empty" class="empty">
          <p id="grok-empty-message">Create or select a pod.</p>
          <button id="grok-restart" class="restart" type="button">Restart Grok</button>
        </div>
      </section>
      <section id="pi-surface" class="surface" hidden>
        <div id="pi-terminal" class="terminal" aria-label="Rumpelpod pi terminal"></div>
        <div id="pi-empty" class="empty">
          <p id="pi-empty-message">Create or select a pod.</p>
          <button id="pi-restart" class="restart" type="button">Restart pi</button>
        </div>
      </section>
      <section id="shell-surface" class="surface" hidden>
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
  agent: AgentKind,
  pod: string,
  state: "empty" | "exited" | "running" | "starting",
): string {
  switch (state) {
    case "empty":
      return "Create or select a pod above.";
    case "exited":
      return `${agentLabel(agent)} is not attached.`;
    case "running":
    case "starting":
      return `Starting ${agentLabel(agent)} in ${pod}.`;
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
    case "launchAgentMenu":
    case "createPodMenu":
    case "podMenu":
      return "request" in value && isRequest(value.request);
    case "openShell":
    case "addSshKey":
    case "deletePod":
    case "mergePod":
    case "openPort":
    case "openPortExternal":
    case "refresh":
    case "stopPod":
    case "viewDiff":
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
    case "launchAgent":
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
    case "claude":
    case "codex":
    case "grok":
    case "pi":
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

function uniqueAgents(agents: readonly AgentKind[]): readonly AgentKind[] {
  return [...new Set(agents)];
}

function sameAgents(left: readonly AgentKind[], right: readonly AgentKind[]): boolean {
  return left.length === right.length && left.every((agent, index) => agent === right[index]);
}

function terminalKey(repository: Repository, pod: string): string {
  return JSON.stringify([repository.root, pod]);
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
