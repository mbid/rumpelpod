// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import "@xterm/xterm/css/xterm.css";
import "./webview.css";

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";

type TerminalTab = "agent" | "shell";
type ViewState = "empty" | "exited" | "running" | "starting";

interface WebviewApi<State> {
  getState(): State | undefined;
  postMessage(message: unknown): void;
  setState(state: State): void;
}

declare function acquireVsCodeApi<State = unknown>(): WebviewApi<State>;

interface PersistedState {
  readonly activeTab?: TerminalTab;
  readonly agent?: string;
  readonly pod?: string;
  readonly repository?: string;
}

interface AgentStateMessage {
  readonly activeTab: TerminalTab;
  readonly agent: string;
  readonly agentMessage: string;
  readonly agentSession: number;
  readonly agentState: ViewState;
  readonly pod: string;
  readonly repository: string;
  readonly repositoryState: string;
  readonly shellMessage: string;
  readonly shellSession: number;
  readonly shellState: ViewState;
  readonly type: "state";
}

interface OutputMessage {
  readonly data: string;
  readonly sequence: number;
  readonly session: number;
  readonly tab: TerminalTab;
  readonly type: "output";
}

interface FocusMessage {
  readonly type: "focus";
}

interface TerminalSurface {
  readonly empty: HTMLElement;
  readonly fit: FitAddon;
  readonly restart: HTMLElement;
  readonly terminal: Terminal;
}

type HostMessage = AgentStateMessage | FocusMessage | OutputMessage;

const vscode = acquireVsCodeApi<PersistedState>();
const body = document.body;
const podSelector = requiredElement("pod-selector");
const podName = requiredElement("pod-name");
const agentTab = requiredElement("agent-tab");
const shellTab = requiredElement("shell-tab");
const surfaces: Record<TerminalTab, TerminalSurface> = {
  agent: createSurface("agent"),
  shell: createSurface("shell"),
};

let activeTab: TerminalTab = "agent";
let resizeTimer: number | undefined;
const sessions: Record<TerminalTab, number> = { agent: 0, shell: 0 };

for (const tab of terminalTabs()) {
  const surface = surfaces[tab];
  surface.terminal.onData((data) => {
    const session = sessions[tab];
    if (session !== 0) {
      vscode.postMessage({ data, session, tab, type: "input" });
    }
  });
  surface.restart.addEventListener("click", () => {
    const session = sessions[tab];
    if (session !== 0) {
      vscode.postMessage({ session, tab, type: "restart" });
    }
  });
}

podSelector.addEventListener("click", () => {
  vscode.postMessage({ type: "selectPod" });
});
agentTab.addEventListener("click", () => selectTab("agent"));
shellTab.addEventListener("click", () => selectTab("shell"));

window.addEventListener("message", (event: MessageEvent<unknown>) => {
  if (!isHostMessage(event.data)) {
    return;
  }
  const message = event.data;
  switch (message.type) {
    case "state":
      activeTab = message.activeTab;
      sessions.agent = message.agentSession;
      sessions.shell = message.shellSession;
      body.dataset.rumpelpodActiveTab = activeTab;
      body.dataset.rumpelpodAgent = message.agent;
      body.dataset.rumpelpodPod = message.pod;
      body.dataset.rumpelpodRepository = message.repository;
      body.dataset.rumpelpodRepositoryState = message.repositoryState;
      podName.textContent = message.pod.length === 0 ? "Select pod" : message.pod;
      agentTab.textContent = message.agent.length === 0 ? "agent" : message.agent.toLowerCase();
      updateSelectedTab();
      updateSurface("agent", message.agentSession, message.agentState, message.agentMessage);
      updateSurface("shell", message.shellSession, message.shellState, message.shellMessage);
      vscode.setState({
        activeTab,
        agent: message.agent,
        pod: message.pod,
        repository: message.repository,
      });
      scheduleFit();
      return;
    case "output":
      if (message.session !== sessions[message.tab]) {
        return;
      }
      surfaces[message.tab].terminal.write(message.data, () => {
        if (message.session === sessions[message.tab]) {
          if (message.tab === "agent") {
            body.dataset.rumpelpodRenderedSession = String(message.session);
          }
          vscode.postMessage({
            sequence: message.sequence,
            session: message.session,
            tab: message.tab,
            type: "outputAck",
          });
        }
      });
      return;
    case "focus":
      surfaces[activeTab].terminal.focus();
      reportTerminalFocus();
      return;
  }
});

for (const tab of terminalTabs()) {
  new ResizeObserver(scheduleFit).observe(requiredElement(`${tab}-terminal`));
}
document.addEventListener("visibilitychange", scheduleFit);
document.addEventListener("focusin", reportTerminalFocus);
document.addEventListener("focusout", () => queueMicrotask(reportTerminalFocus));
window.addEventListener("resize", scheduleFit);

const restored = vscode.getState();
if (restored?.pod !== undefined) {
  body.dataset.rumpelpodPod = restored.pod;
  podName.textContent = restored.pod;
}
if (restored?.agent !== undefined) {
  body.dataset.rumpelpodAgent = restored.agent;
  agentTab.textContent = restored.agent.toLowerCase();
}
if (restored?.repository !== undefined) {
  body.dataset.rumpelpodRepository = restored.repository;
}
if (restored?.activeTab !== undefined) {
  activeTab = restored.activeTab;
}
body.dataset.rumpelpodActiveTab = activeTab;
body.dataset.rumpelpodAgentView = "true";
body.dataset.rumpelpodRenderedSession = "";
body.dataset.rumpelpodSession = "0";
body.dataset.rumpelpodState = "empty";
updateSelectedTab();

scheduleFit();
vscode.postMessage({
  cols: surfaces[activeTab].terminal.cols,
  rows: surfaces[activeTab].terminal.rows,
  type: "ready",
});

function createSurface(tab: TerminalTab): TerminalSurface {
  const terminal = new Terminal({
    allowProposedApi: false,
    convertEol: false,
    cursorBlink: true,
    cursorStyle: "block",
    fontFamily: cssVariable("--vscode-editor-font-family"),
    fontSize: 13,
    screenReaderMode: true,
    scrollback: 10_000,
    theme: {
      background: cssVariable("--vscode-sideBar-background"),
      foreground: cssVariable("--vscode-sideBar-foreground"),
      cursor: cssVariable("--vscode-terminalCursor-foreground"),
      selectionBackground: cssVariable("--vscode-terminal-selectionBackground"),
    },
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(requiredElement(`${tab}-terminal`));
  return {
    empty: requiredElement(`${tab}-empty-message`),
    fit,
    restart: requiredElement(`${tab}-restart`),
    terminal,
  };
}

function selectTab(tab: TerminalTab): void {
  if (activeTab === tab) {
    return;
  }
  activeTab = tab;
  body.dataset.rumpelpodActiveTab = tab;
  updateSelectedTab();
  vscode.postMessage({ tab, type: "selectTab" });
  scheduleFit();
}

function updateSelectedTab(): void {
  agentTab.setAttribute("aria-selected", String(activeTab === "agent"));
  shellTab.setAttribute("aria-selected", String(activeTab === "shell"));
}

function updateSurface(tab: TerminalTab, session: number, state: ViewState, message: string): void {
  const previousSession = Number(body.dataset[`rumpelpod${capitalize(tab)}Session`] ?? "0");
  sessions[tab] = session;
  body.dataset[`rumpelpod${capitalize(tab)}Session`] = String(session);
  body.dataset[`rumpelpod${capitalize(tab)}State`] = state;
  surfaces[tab].empty.textContent = message;
  if (session !== previousSession && state === "starting") {
    surfaces[tab].terminal.reset();
  }
  if (tab === activeTab) {
    body.dataset.rumpelpodSession = String(session);
    body.dataset.rumpelpodState = state;
  }
}

function scheduleFit(): void {
  if (resizeTimer !== undefined) {
    window.clearTimeout(resizeTimer);
  }
  resizeTimer = window.setTimeout(() => {
    resizeTimer = undefined;
    const state = body.dataset[`rumpelpod${capitalize(activeTab)}State`];
    if (state !== "running" && state !== "starting") {
      return;
    }
    const surface = surfaces[activeTab];
    surface.fit.fit();
    const session = sessions[activeTab];
    if (session !== 0) {
      body.dataset.rumpelpodSession = String(session);
      body.dataset.rumpelpodState = state;
      vscode.postMessage({
        cols: surface.terminal.cols,
        rows: surface.terminal.rows,
        session,
        tab: activeTab,
        type: "resize",
      });
    }
  }, 25);
}

let terminalFocused = false;

function reportTerminalFocus(): void {
  const activeElement = document.activeElement;
  const focused =
    activeElement instanceof HTMLTextAreaElement && activeElement.closest(".terminal") !== null;
  if (focused === terminalFocused) {
    return;
  }
  terminalFocused = focused;
  vscode.postMessage({ focused, type: "terminalFocus" });
}

function capitalize(tab: TerminalTab): "Agent" | "Shell" {
  switch (tab) {
    case "agent":
      return "Agent";
    case "shell":
      return "Shell";
  }
}

function terminalTabs(): readonly TerminalTab[] {
  return ["agent", "shell"];
}

function cssVariable(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function requiredElement(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`missing webview element: ${id}`);
  }
  return element;
}

function isHostMessage(value: unknown): value is HostMessage {
  if (typeof value !== "object" || value === null || !("type" in value)) {
    return false;
  }
  switch (value.type) {
    case "focus":
      return true;
    case "output":
      return (
        "data" in value &&
        typeof value.data === "string" &&
        "sequence" in value &&
        typeof value.sequence === "number" &&
        "session" in value &&
        typeof value.session === "number" &&
        "tab" in value &&
        isTerminalTab(value.tab)
      );
    case "state":
      return (
        "activeTab" in value &&
        isTerminalTab(value.activeTab) &&
        "agent" in value &&
        typeof value.agent === "string" &&
        "agentMessage" in value &&
        typeof value.agentMessage === "string" &&
        "agentSession" in value &&
        typeof value.agentSession === "number" &&
        "agentState" in value &&
        isViewState(value.agentState) &&
        "pod" in value &&
        typeof value.pod === "string" &&
        "repository" in value &&
        typeof value.repository === "string" &&
        "repositoryState" in value &&
        typeof value.repositoryState === "string" &&
        "shellMessage" in value &&
        typeof value.shellMessage === "string" &&
        "shellSession" in value &&
        typeof value.shellSession === "number" &&
        "shellState" in value &&
        isViewState(value.shellState)
      );
  }
  return false;
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

function isViewState(value: unknown): value is ViewState {
  switch (value) {
    case "empty":
    case "exited":
    case "running":
    case "starting":
      return true;
    default:
      return false;
  }
}
