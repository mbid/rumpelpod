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
  readonly shellOpen: boolean;
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

interface DismissMenuMessage {
  readonly request: number;
  readonly type: "dismissMenu";
}

interface BeginMenuMessage {
  readonly menu: "agent" | "create" | "pod";
  readonly request: number;
  readonly type: "beginMenu";
}

interface AgentMenuOption {
  readonly agent: string;
  readonly current: boolean;
  readonly description: string;
  readonly label: string;
}

interface AgentMenuMessage {
  readonly agents: readonly AgentMenuOption[];
  readonly request: number;
  readonly type: "agentMenu";
}

interface CreatePodMenuMessage {
  readonly agents: readonly AgentMenuOption[];
  readonly repositories: readonly { readonly name: string; readonly root: string }[];
  readonly request: number;
  readonly type: "createPodMenu";
}

interface PodMenuMessage {
  readonly pods: readonly {
    readonly active: boolean;
    readonly detail: string;
    readonly name: string;
    readonly repository: string;
    readonly status: string;
    readonly summary: string;
  }[];
  readonly request: number;
  readonly type: "podMenu";
}

interface TerminalSurface {
  readonly empty: HTMLElement;
  readonly fit: FitAddon;
  readonly restart: HTMLElement;
  readonly terminal: Terminal;
}

type HostMessage =
  | AgentMenuMessage
  | AgentStateMessage
  | BeginMenuMessage
  | CreatePodMenuMessage
  | DismissMenuMessage
  | FocusMessage
  | OutputMessage
  | PodMenuMessage;

const vscode = acquireVsCodeApi<PersistedState>();
const body = document.body;
const podSelector = requiredButton("pod-selector");
const podName = requiredElement("pod-name");
const agentTab = requiredButton("agent-tab");
const shellTab = requiredButton("shell-tab");
const changeAgent = requiredButton("change-agent");
const createPod = requiredButton("create-pod");
const moreActions = requiredButton("more-actions");
const openShell = requiredButton("open-shell");
const popoverLayer = requiredElement("popover-layer");
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
  requestPopover(podSelector, "Select pod", "podMenu");
});
changeAgent.addEventListener("click", () => {
  requestPopover(changeAgent, "Select agent", "changeAgent");
});
createPod.addEventListener("click", () => {
  requestPopover(createPod, "Create pod", "createPodMenu");
});
moreActions.addEventListener("click", () => renderMoreMenu());
openShell.addEventListener("click", () => vscode.postMessage({ type: "openShell" }));
agentTab.addEventListener("click", () => selectTab("agent"));
shellTab.addEventListener("click", () => selectTab("shell"));

window.addEventListener("message", (event: MessageEvent<unknown>) => {
  if (!isHostMessage(event.data)) {
    return;
  }
  const message = event.data;
  switch (message.type) {
    case "agentMenu":
      if (!acceptMenuResponse(message.request)) {
        return;
      }
      renderAgentMenu(message.agents);
      return;
    case "beginMenu":
      showHostMenuRequest(message);
      return;
    case "createPodMenu":
      if (!acceptMenuResponse(message.request)) {
        return;
      }
      renderCreatePodMenu(message.repositories, message.agents);
      return;
    case "dismissMenu":
      if (message.request === expectedMenuRequest) {
        dismissPopover();
      }
      return;
    case "podMenu":
      if (!acceptMenuResponse(message.request)) {
        return;
      }
      renderPodMenu(message.pods);
      return;
    case "state":
      activeTab = message.activeTab;
      sessions.agent = message.agentSession;
      sessions.shell = message.shellSession;
      body.dataset.rumpelpodActiveTab = activeTab;
      body.dataset.rumpelpodAgent = message.agent;
      body.dataset.rumpelpodPod = message.pod;
      body.dataset.rumpelpodRepository = message.repository;
      body.dataset.rumpelpodRepositoryState = message.repositoryState;
      body.dataset.rumpelpodShellOpen = String(message.shellOpen);
      podName.textContent = message.pod.length === 0 ? "Select pod" : message.pod;
      agentTab.textContent = message.agent.length === 0 ? "agent" : message.agent.toLowerCase();
      const hasPod = message.pod.length > 0;
      changeAgent.disabled = !hasPod;
      moreActions.disabled = !hasPod;
      openShell.disabled = !hasPod;
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
body.dataset.rumpelpodShellOpen = "false";
body.dataset.rumpelpodState = "empty";
changeAgent.disabled = true;
moreActions.disabled = true;
openShell.disabled = true;
updateSelectedTab();

scheduleFit();
vscode.postMessage({
  cols: surfaces[activeTab].terminal.cols,
  rows: surfaces[activeTab].terminal.rows,
  type: "ready",
});

let activePopover: HTMLElement | undefined;
let activePopoverAnchor: HTMLButtonElement | undefined;
let expectedMenuRequest = 0;
let nextMenuRequest = 0;

document.addEventListener("pointerdown", (event) => {
  const target = event.target;
  if (
    activePopover === undefined ||
    !(target instanceof Node) ||
    activePopover.contains(target) ||
    activePopoverAnchor?.contains(target) === true
  ) {
    return;
  }
  dismissPopover();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && activePopover !== undefined) {
    event.preventDefault();
    dismissPopover(true);
  }
});
window.addEventListener("resize", () => {
  if (activePopover !== undefined && activePopoverAnchor !== undefined) {
    positionPopover(activePopover, activePopoverAnchor);
  }
});

function requestPopover(
  anchor: HTMLButtonElement,
  label: string,
  type: "changeAgent" | "createPodMenu" | "podMenu",
): void {
  const request = ++nextMenuRequest;
  showLoadingPopover(anchor, `${type}-loading`, label, request);
  vscode.postMessage({ request, type });
}

function showHostMenuRequest(message: BeginMenuMessage): void {
  switch (message.menu) {
    case "agent":
      showLoadingPopover(changeAgent, "changeAgent-loading", "Select agent", message.request);
      return;
    case "create":
      showLoadingPopover(createPod, "createPodMenu-loading", "Create pod", message.request);
      return;
    case "pod":
      showLoadingPopover(podSelector, "podMenu-loading", "Select pod", message.request);
      return;
  }
}

function showLoadingPopover(
  anchor: HTMLButtonElement,
  id: string,
  label: string,
  request: number,
): void {
  expectedMenuRequest = request;
  const popover = openPopover(anchor, id, label);
  const loading = document.createElement("p");
  loading.className = "popover-empty";
  loading.textContent = "Loading...";
  popover.append(loading);
}

function acceptMenuResponse(request: number): boolean {
  return request === expectedMenuRequest;
}

function renderPodMenu(pods: PodMenuMessage["pods"]): void {
  const popover = openPopover(podSelector, "pod-popover", "Select pod");
  const search = document.createElement("input");
  search.className = "popover-input";
  search.placeholder = "Filter pods";
  search.setAttribute("aria-label", "Filter pods");
  const list = document.createElement("div");
  list.className = "popover-options";
  list.setAttribute("role", "listbox");
  popover.append(search, list);
  enableOptionKeyboardNavigation(list);

  const render = (): void => {
    list.replaceChildren();
    const filter = search.value.trim().toLowerCase();
    const visible = pods.filter((pod) =>
      `${pod.name} ${pod.summary} ${pod.detail}`.toLowerCase().includes(filter)
    );
    if (visible.length === 0) {
      list.append(textElement("p", "popover-empty", "No matching pods"));
      return;
    }
    for (const pod of visible) {
      const option = menuOption(pod.name, pod.summary, pod.detail);
      option.dataset.status = pod.status;
      option.setAttribute("aria-selected", String(pod.active));
      option.addEventListener("click", () => {
        dismissPopover();
        vscode.postMessage({
          pod: pod.name,
          repository: pod.repository,
          type: "openPod",
        });
      });
      list.append(option);
    }
  };
  search.addEventListener("input", render);
  search.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      focusFirstOption(list);
    }
  });
  render();
  search.focus();
}

function renderAgentMenu(agents: readonly AgentMenuOption[]): void {
  const popover = openPopover(changeAgent, "agent-popover", "Select agent");
  const list = document.createElement("div");
  list.className = "popover-options";
  list.setAttribute("role", "listbox");
  for (const agent of agents) {
    const option = menuOption(
      agent.label,
      agent.current ? "Current agent" : agent.description,
    );
    option.setAttribute("aria-selected", String(agent.current));
    option.addEventListener("click", () => {
      dismissPopover();
      vscode.postMessage({ agent: agent.agent, type: "setAgent" });
    });
    list.append(option);
  }
  popover.append(list);
  enableOptionKeyboardNavigation(list);
  focusSelectedOption(list);
}

function renderCreatePodMenu(
  repositories: CreatePodMenuMessage["repositories"],
  agents: readonly AgentMenuOption[],
): void {
  const popover = openPopover(createPod, "create-popover", "Create pod");
  const form = document.createElement("form");
  form.className = "create-form";
  const name = document.createElement("input");
  name.id = "pod-name-input";
  name.className = "popover-input";
  name.placeholder = "feature-name";
  name.autocomplete = "off";
  name.required = true;
  form.append(field("Pod name", name));

  const agent = document.createElement("select");
  agent.id = "pod-agent-input";
  agent.className = "popover-input";
  for (const option of agents) {
    const element = document.createElement("option");
    element.value = option.agent;
    element.textContent = option.label;
    element.selected = option.current;
    agent.append(element);
  }
  form.append(field("Agent", agent));

  const repository = document.createElement("select");
  repository.id = "pod-repository-input";
  repository.className = "popover-input";
  for (const option of repositories) {
    const element = document.createElement("option");
    element.value = option.root;
    element.textContent = option.name;
    repository.append(element);
  }
  if (repositories.length > 1) {
    form.append(field("Repository", repository));
  }

  const error = textElement("p", "form-error", "");
  error.id = "pod-name-error";
  error.setAttribute("aria-live", "polite");
  const submit = document.createElement("button");
  submit.className = "primary-action";
  submit.type = "submit";
  submit.textContent = "Create";
  form.append(error, submit);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const message = validatePodName(name.value);
    if (message !== undefined) {
      error.textContent = message;
      name.focus();
      return;
    }
    const repositoryRoot = repository.value || repositories[0]?.root;
    if (repositoryRoot === undefined) {
      error.textContent = "No Git repository is open";
      return;
    }
    dismissPopover();
    vscode.postMessage({
      agent: agent.value,
      pod: name.value,
      repository: repositoryRoot,
      type: "createPod",
    });
  });
  popover.append(form);
  name.focus();
}

function renderMoreMenu(): void {
  const popover = openPopover(moreActions, "more-popover", "Pod actions");
  const list = document.createElement("div");
  list.className = "popover-options";
  list.setAttribute("role", "menu");
  for (const [label, type] of [
    ["Refresh pod", "refresh"],
    ["Restart agent attachment", "restartAgent"],
  ] as const) {
    const option = menuOption(label);
    option.setAttribute("role", "menuitem");
    option.addEventListener("click", () => {
      dismissPopover();
      vscode.postMessage({ type });
    });
    list.append(option);
  }
  popover.append(list);
  enableOptionKeyboardNavigation(list);
  focusFirstOption(list);
}

function openPopover(
  anchor: HTMLButtonElement,
  id: string,
  label: string,
): HTMLElement {
  dismissPopover(false, false);
  const popover = document.createElement("section");
  popover.id = id;
  popover.className = "popover";
  popover.setAttribute("aria-label", label);
  popover.setAttribute("role", "dialog");
  popoverLayer.append(popover);
  activePopover = popover;
  activePopoverAnchor = anchor;
  anchor.setAttribute("aria-expanded", "true");
  positionPopover(popover, anchor);
  return popover;
}

function positionPopover(popover: HTMLElement, anchor: HTMLButtonElement): void {
  const bounds = anchor.getBoundingClientRect();
  const margin = 6;
  popover.style.top = `${bounds.bottom + 3}px`;
  if (anchor === podSelector) {
    popover.style.left = `${margin}px`;
    popover.style.right = `${margin}px`;
    return;
  }
  popover.style.left = "auto";
  popover.style.right = `${Math.max(margin, window.innerWidth - bounds.right)}px`;
}

function dismissPopover(restoreFocus = false, invalidateRequest = true): void {
  const anchor = activePopoverAnchor;
  activePopover?.remove();
  activePopover = undefined;
  activePopoverAnchor = undefined;
  if (invalidateRequest) {
    expectedMenuRequest = ++nextMenuRequest;
  }
  anchor?.setAttribute("aria-expanded", "false");
  if (restoreFocus) {
    anchor?.focus();
  }
}

function menuOption(title: string, description?: string, detail?: string): HTMLButtonElement {
  const option = document.createElement("button");
  option.className = "popover-option";
  option.type = "button";
  option.setAttribute("role", "option");
  option.append(textElement("span", "option-title", title));
  if (description !== undefined && description.length > 0) {
    option.append(textElement("span", "option-description", description));
  }
  if (detail !== undefined && detail.length > 0) {
    option.append(textElement("span", "option-detail", detail));
  }
  return option;
}

function field(label: string, control: HTMLInputElement | HTMLSelectElement): HTMLLabelElement {
  const element = document.createElement("label");
  element.className = "form-field";
  element.append(textElement("span", "form-label", label), control);
  return element;
}

function textElement(tag: "p" | "span", className: string, text: string): HTMLElement {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = text;
  return element;
}

function focusFirstOption(container: HTMLElement): void {
  container.querySelector<HTMLButtonElement>("button")?.focus();
}

function focusSelectedOption(container: HTMLElement): void {
  const selected = container.querySelector<HTMLButtonElement>('[aria-selected="true"]');
  (selected ?? container.querySelector<HTMLButtonElement>("button"))?.focus();
}

function enableOptionKeyboardNavigation(container: HTMLElement): void {
  container.addEventListener("keydown", (event) => {
    if (!["ArrowDown", "ArrowUp", "End", "Home"].includes(event.key)) {
      return;
    }
    const options = Array.from(container.querySelectorAll<HTMLButtonElement>("button"));
    if (options.length === 0) {
      return;
    }
    event.preventDefault();
    const current = options.findIndex((option) => option === document.activeElement);
    let next: number;
    switch (event.key) {
      case "ArrowDown":
        next = current < 0 ? 0 : (current + 1) % options.length;
        break;
      case "ArrowUp":
        next = current <= 0 ? options.length - 1 : current - 1;
        break;
      case "End":
        next = options.length - 1;
        break;
      case "Home":
        next = 0;
        break;
      default:
        return;
    }
    options[next]?.focus();
  });
}

function validatePodName(value: string): string | undefined {
  if (value.length === 0) {
    return "Pod name must not be empty";
  }
  if (value.length > 63) {
    return "Pod name must be at most 63 characters";
  }
  if (!/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(value)) {
    return "Use lower-case letters, numbers, and internal hyphens";
  }
  return undefined;
}

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

function requiredButton(id: string): HTMLButtonElement {
  const element = requiredElement(id);
  if (!(element instanceof HTMLButtonElement)) {
    throw new Error(`webview element is not a button: ${id}`);
  }
  return element;
}

function isHostMessage(value: unknown): value is HostMessage {
  if (typeof value !== "object" || value === null || !("type" in value)) {
    return false;
  }
  switch (value.type) {
    case "agentMenu":
      return (
        "agents" in value &&
        Array.isArray(value.agents) &&
        value.agents.every(isAgentOption) &&
        "request" in value &&
        isRequest(value.request)
      );
    case "beginMenu":
      return (
        "menu" in value &&
        isMenuKind(value.menu) &&
        "request" in value &&
        isRequest(value.request)
      );
    case "createPodMenu":
      return (
        "agents" in value &&
        Array.isArray(value.agents) &&
        value.agents.every(isAgentOption) &&
        "repositories" in value &&
        Array.isArray(value.repositories) &&
        value.repositories.every(isRepositoryOption) &&
        "request" in value &&
        isRequest(value.request)
      );
    case "dismissMenu":
      return "request" in value && isRequest(value.request);
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
    case "podMenu":
      return (
        "pods" in value &&
        Array.isArray(value.pods) &&
        value.pods.every(isPodOption) &&
        "request" in value &&
        isRequest(value.request)
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
        "shellOpen" in value &&
        typeof value.shellOpen === "boolean" &&
        "shellSession" in value &&
        typeof value.shellSession === "number" &&
        "shellState" in value &&
        isViewState(value.shellState)
      );
  }
  return false;
}

function isAgentOption(value: unknown): value is AgentMenuOption {
  return (
    typeof value === "object" &&
    value !== null &&
    "agent" in value &&
    typeof value.agent === "string" &&
    "current" in value &&
    typeof value.current === "boolean" &&
    "description" in value &&
    typeof value.description === "string" &&
    "label" in value &&
    typeof value.label === "string"
  );
}

function isPodOption(value: unknown): value is PodMenuMessage["pods"][number] {
  return (
    typeof value === "object" &&
    value !== null &&
    "active" in value &&
    typeof value.active === "boolean" &&
    "detail" in value &&
    typeof value.detail === "string" &&
    "name" in value &&
    typeof value.name === "string" &&
    "repository" in value &&
    typeof value.repository === "string" &&
    "status" in value &&
    typeof value.status === "string" &&
    "summary" in value &&
    typeof value.summary === "string"
  );
}

function isRepositoryOption(
  value: unknown,
): value is CreatePodMenuMessage["repositories"][number] {
  return (
    typeof value === "object" &&
    value !== null &&
    "name" in value &&
    typeof value.name === "string" &&
    "root" in value &&
    typeof value.root === "string"
  );
}

function isRequest(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value !== 0;
}

function isMenuKind(value: unknown): value is BeginMenuMessage["menu"] {
  switch (value) {
    case "agent":
    case "create":
    case "pod":
      return true;
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
