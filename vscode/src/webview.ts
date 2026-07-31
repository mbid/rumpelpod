// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import "@xterm/xterm/css/xterm.css";
import "./webview.css";

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";

interface WebviewApi<State> {
  getState(): State | undefined;
  postMessage(message: unknown): void;
  setState(state: State): void;
}

declare function acquireVsCodeApi<State = unknown>(): WebviewApi<State>;

type ViewState = "empty" | "exited" | "running" | "starting";

interface PersistedState {
  readonly agent?: string;
  readonly pod?: string;
  readonly repository?: string;
}

interface AgentStateMessage {
  readonly agent: string;
  readonly message: string;
  readonly pod: string;
  readonly repository: string;
  readonly repositoryState: string;
  readonly session: number;
  readonly state: ViewState;
  readonly type: "state";
}

interface OutputMessage {
  readonly data: string;
  readonly sequence: number;
  readonly session: number;
  readonly type: "output";
}

type HostMessage = AgentStateMessage | OutputMessage;

const vscode = acquireVsCodeApi<PersistedState>();
const body = document.body;
const terminalElement = requiredElement("terminal");
const emptyMessage = requiredElement("empty-message");
const restart = requiredElement("restart");
const fit = new FitAddon();
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

let activeSession = 0;
let resizeTimer: number | undefined;

terminal.loadAddon(fit);
terminal.open(terminalElement);
terminal.onData((data) => {
  if (activeSession !== 0) {
    vscode.postMessage({ data, session: activeSession, type: "input" });
  }
});

restart.addEventListener("click", () => {
  if (activeSession !== 0) {
    vscode.postMessage({ session: activeSession, type: "restart" });
  }
});

window.addEventListener("message", (event: MessageEvent<unknown>) => {
  if (!isHostMessage(event.data)) {
    return;
  }
  const message = event.data;
  switch (message.type) {
    case "state":
      activeSession = message.session;
      body.dataset.rumpelpodAgent = message.agent;
      body.dataset.rumpelpodPod = message.pod;
      body.dataset.rumpelpodRepository = message.repository;
      body.dataset.rumpelpodRepositoryState = message.repositoryState;
      body.dataset.rumpelpodSession = String(message.session);
      body.dataset.rumpelpodState = message.state;
      emptyMessage.textContent = message.message;
      vscode.setState({
        agent: message.agent,
        pod: message.pod,
        repository: message.repository,
      });
      if (message.state === "starting") {
        body.dataset.rumpelpodRenderedSession = "";
        terminal.reset();
      }
      scheduleFit();
      return;
    case "output":
      if (message.session === activeSession) {
        terminal.write(message.data, () => {
          if (message.session === activeSession) {
            body.dataset.rumpelpodRenderedSession = String(message.session);
            vscode.postMessage({
              sequence: message.sequence,
              session: message.session,
              type: "outputAck",
            });
          }
        });
      }
      return;
  }
});

new ResizeObserver(scheduleFit).observe(terminalElement);
document.addEventListener("visibilitychange", scheduleFit);
window.addEventListener("resize", scheduleFit);

const restored = vscode.getState();
if (restored?.pod !== undefined) {
  body.dataset.rumpelpodPod = restored.pod;
}
if (restored?.agent !== undefined) {
  body.dataset.rumpelpodAgent = restored.agent;
}
if (restored?.repository !== undefined) {
  body.dataset.rumpelpodRepository = restored.repository;
}
body.dataset.rumpelpodAgentView = "true";
body.dataset.rumpelpodRenderedSession = "";
body.dataset.rumpelpodSession = "0";
body.dataset.rumpelpodState = "empty";
emptyMessage.textContent = "Select or create a pod from the view toolbar.";

scheduleFit();
vscode.postMessage({ cols: terminal.cols, rows: terminal.rows, type: "ready" });

function scheduleFit(): void {
  if (resizeTimer !== undefined) {
    window.clearTimeout(resizeTimer);
  }
  resizeTimer = window.setTimeout(() => {
    resizeTimer = undefined;
    if (body.dataset.rumpelpodState !== "running" && body.dataset.rumpelpodState !== "starting") {
      return;
    }
    fit.fit();
    if (activeSession !== 0) {
      vscode.postMessage({
        cols: terminal.cols,
        rows: terminal.rows,
        session: activeSession,
        type: "resize",
      });
    }
  }, 25);
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
    case "output":
      return (
        "data" in value &&
        typeof value.data === "string" &&
        "sequence" in value &&
        typeof value.sequence === "number" &&
        "session" in value &&
        typeof value.session === "number"
      );
    case "state":
      return (
        "agent" in value &&
        typeof value.agent === "string" &&
        "message" in value &&
        typeof value.message === "string" &&
        "pod" in value &&
        typeof value.pod === "string" &&
        "repository" in value &&
        typeof value.repository === "string" &&
        "repositoryState" in value &&
        typeof value.repositoryState === "string" &&
        "session" in value &&
        typeof value.session === "number" &&
        "state" in value &&
        isViewState(value.state)
      );
  }
  return false;
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
