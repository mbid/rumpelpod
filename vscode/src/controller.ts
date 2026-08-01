// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { AgentKind, PodInfo } from "./generated/protocol";
import { AGENTS, agentDescription, agentLabel } from "./agents";
import type { Repository, RumpelpodModel } from "./model";
import type { ReviewDocuments } from "./review";
import type {
  AgentMenuOption,
  AgentTerminals,
  AgentViewAction,
  PodMenuOption,
} from "./terminal";

interface ActivePod {
  readonly agent: AgentKind;
  readonly generation: number;
  readonly info: PodInfo | undefined;
  readonly pod: string;
  readonly repository: Repository;
}

export class RumpelpodController implements vscode.Disposable {
  private readonly scheduledRefreshes = new Set<NodeJS.Timeout>();
  private active: ActivePod | undefined;
  private modeEntries = Promise.resolve();
  private reviewUpdates = Promise.resolve();
  private selectionGeneration = 0;
  private statusUpdates = Promise.resolve();

  public constructor(
    private readonly model: RumpelpodModel,
    private readonly terminals: AgentTerminals,
    private readonly reviewDocuments: ReviewDocuments,
    private readonly status: vscode.StatusBarItem,
  ) {}

  public async showPodSwitcher(request?: number): Promise<void> {
    const menuRequest = await this.terminals.beginMenu("pod", request);
    try {
      const repositories = await this.model.repositories();
      if (repositories.length === 0) {
        throw new Error("open a Git repository before selecting a pod");
      }

      const picks = (
        await Promise.all(
          repositories.map(async (repository) => {
            const pods = await this.model.listPods(repository, false);
            return pods.map((pod) => this.podPick(repository, pod, repositories.length > 1));
          }),
        )
      ).flat();
      await this.terminals.showPodMenu(picks, menuRequest);
    } catch (error) {
      this.terminals.dismissMenu(menuRequest);
      throw error;
    }
  }

  public enterMode(): Promise<void> {
    const result = this.modeEntries.then(async () => {
      if (this.active === undefined) {
        const restored = await this.restoreLastPod();
        if (restored) {
          return;
        }
      }
      const selected = this.active;
      if (selected === undefined) {
        await this.showPodSwitcher();
        return;
      }
      await this.terminals.showActive(
        selected.repository,
        selected.pod,
        selected.agent,
        this.model.executable(),
      );
      this.updateStatus();
      await this.refreshActiveReview(false);
    });
    this.modeEntries = result.catch(() => {});
    return result;
  }

  public async refresh(sync: boolean): Promise<void> {
    const failures = (
      await Promise.allSettled([
        this.refreshPodStatus(sync),
        this.refreshActiveReview(true),
      ])
    )
      .filter((result): result is PromiseRejectedResult => result.status === "rejected")
      .map((result) => result.reason);
    if (failures.length === 1) {
      throw failures[0];
    }
    if (failures.length > 1) {
      throw new AggregateError(failures, "rumpelpod status and review refreshes failed");
    }
  }

  public refreshPodStatus(sync: boolean): Promise<void> {
    const selected = this.active;
    return this.enqueueStatusUpdate(async () => {
      if (selected === undefined) {
        if (this.active === undefined) {
          this.updateStatus();
        }
        return;
      }
      const pods = await this.model.listPods(selected.repository, sync);
      const active = this.currentSelection(selected);
      if (active === undefined) {
        return;
      }
      const info = pods.find((pod) => pod.name === selected.pod);
      this.active = { ...active, info };
      this.updateStatus();
    });
  }

  public refreshActiveReview(preserveFocus = true): Promise<void> {
    const selected = this.active;
    return this.enqueueReviewUpdate(async () => {
      if (selected === undefined) {
        if (this.active === undefined) {
          await this.reviewDocuments.clear();
        }
        return;
      }
      const plan = await this.model.review(selected.repository, selected.pod);
      const active = this.currentSelection(selected);
      if (active === undefined) {
        return;
      }
      const restoreTerminalFocus = preserveFocus && this.terminals.hasFocus();
      try {
        if (plan.files.length === 0) {
          await this.reviewDocuments.openEmpty(selected.repository, selected.pod, preserveFocus);
          return;
        }
        await this.reviewDocuments.open(
          selected.repository,
          selected.pod,
          plan,
          preserveFocus,
        );
      } finally {
        if (restoreTerminalFocus) {
          await this.terminals.restoreFocus();
        }
      }
    });
  }

  public isActivePod(repositoryRoot: string, pod: string): boolean {
    return this.active?.repository.root === repositoryRoot && this.active.pod === pod;
  }

  public async createPod(request?: number): Promise<void> {
    const menuRequest = await this.terminals.beginMenu("create", request);
    try {
      const repositories = await this.model.repositories();
      if (repositories.length === 0) {
        throw new Error("open a Git repository before creating a pod");
      }
      await this.terminals.showCreatePodMenu(
        repositories.map((repository) => ({
          name: repository.name,
          root: repository.root,
        })),
        this.agentOptions(this.model.defaultAgent()),
        menuRequest,
      );
    } catch (error) {
      this.terminals.dismissMenu(menuRequest);
      throw error;
    }
  }

  public async handleViewAction(action: AgentViewAction): Promise<void> {
    switch (action.type) {
      case "changeAgent":
        await this.changeActiveAgent(action.request);
        return;
      case "createPod":
        await this.createPodSelection(action.repository, action.agent, action.pod);
        return;
      case "createPodMenu":
        await this.createPod(action.request);
        return;
      case "openPod":
        await this.openPodSelection(action.repository, action.pod);
        return;
      case "openShell":
        this.openActiveShell();
        return;
      case "podMenu":
        await this.showPodSwitcher(action.request);
        return;
      case "refresh":
        await this.refresh(true);
        return;
      case "restartAgent":
        await this.restartActiveAgent();
        return;
      case "setAgent":
        await this.setActiveAgent(action.agent);
        return;
    }
  }

  private async createPodSelection(
    repositoryRoot: string,
    agent: AgentKind,
    pod: string,
  ): Promise<void> {
    const validationError = validatePodName(pod);
    if (validationError !== undefined) {
      throw new Error(validationError);
    }
    const repository = await this.repositoryByRoot(repositoryRoot);
    const generation = ++this.selectionGeneration;
    await this.reclaimRestoredReview();
    if (generation !== this.selectionGeneration) {
      return;
    }
    await this.model.setAgent(repository, pod, agent);
    await this.model.rememberPod(repository, pod);
    if (generation !== this.selectionGeneration) {
      return;
    }
    this.active = {
      agent,
      generation,
      info: undefined,
      pod,
      repository,
    };
    this.updateStatus();
    const selected = this.active;
    await this.enqueueReviewUpdate(async () => {
      if (this.currentSelection(selected) !== undefined) {
        await this.reviewDocuments.openEmpty(repository, pod);
      }
    });
    await this.terminals.showActive(repository, pod, agent, this.model.executable());
    this.updateStatus();
    this.scheduleRefreshes();
  }

  public async openPod(repository: Repository, pod: PodInfo): Promise<void> {
    const generation = ++this.selectionGeneration;
    await this.reclaimRestoredReview();
    if (generation !== this.selectionGeneration) {
      return;
    }
    const agent = this.model.getAgent(repository, pod.name) ?? this.model.defaultAgent();
    await this.model.setAgent(repository, pod.name, agent);
    await this.model.rememberPod(repository, pod.name);
    if (generation !== this.selectionGeneration) {
      return;
    }
    this.active = {
      agent,
      generation,
      info: pod,
      pod: pod.name,
      repository,
    };
    const selected = this.active;
    this.updateStatus();
    await this.terminals.showActive(repository, pod.name, agent, this.model.executable());
    this.updateStatus();

    try {
      await this.refreshActiveReview(false);
    } catch (error) {
      this.model.logError(`opening review for ${pod.name}`, error);
      if (this.currentSelection(selected) === undefined) {
        return;
      }
      const message = errorMessage(error);
      try {
        await this.reviewDocuments.clear();
      } catch (clearError) {
        this.model.logError(`clearing review for ${pod.name}`, clearError);
      }
      await vscode.window.showWarningMessage(
        `The ${pod.name} agent is open, but its review is not available: ${message}`,
      );
    }
  }

  public async changeActiveAgent(request?: number): Promise<void> {
    const selected = this.active;
    if (selected === undefined) {
      throw new Error("select a pod before changing its agent");
    }
    const menuRequest = await this.terminals.beginMenu("agent", request);
    try {
      await this.terminals.showAgentMenu(this.agentOptions(selected.agent), menuRequest);
    } catch (error) {
      this.terminals.dismissMenu(menuRequest);
      throw error;
    }
  }

  private async setActiveAgent(agent: AgentKind): Promise<void> {
    const selected = this.active;
    if (selected === undefined) {
      throw new Error("select a pod before changing its agent");
    }
    let active = this.currentSelection(selected);
    if (active === undefined) {
      return;
    }
    await this.model.setAgent(active.repository, active.pod, agent);
    active = this.currentSelection(selected);
    if (active === undefined) {
      return;
    }
    this.active = { ...active, agent };
    this.updateStatus();
    await this.terminals.showActive(
      active.repository,
      active.pod,
      agent,
      this.model.executable(),
    );
    this.updateStatus();
  }

  public openActiveShell(): void {
    const selected = this.active;
    if (selected === undefined) {
      throw new Error("select a pod before opening a shell");
    }
    this.terminals.showShell(
      selected.repository,
      selected.pod,
      this.model.executable(),
    );
  }

  public restartActiveAgent(): Promise<void> {
    return this.terminals.restartActive();
  }

  public async restoreLastPod(): Promise<boolean> {
    const generation = this.selectionGeneration;
    if (this.active !== undefined) {
      return false;
    }
    const last = this.model.lastPod();
    if (last === undefined) {
      return false;
    }
    const repositories = await this.model.repositories();
    const repository = repositories.find((candidate) => candidate.root === last.repository);
    if (repository === undefined) {
      return false;
    }
    const pods = await this.model.listPods(repository, false);
    const pod = pods.find((candidate) => candidate.name === last.pod);
    if (
      pod === undefined ||
      this.active !== undefined ||
      generation !== this.selectionGeneration
    ) {
      return false;
    }
    await this.openPod(repository, pod);
    return true;
  }

  public updateStatus(): void {
    const selected = this.active;
    if (selected === undefined) {
      this.status.text = "$(server-process) Rumpelpod";
      this.status.tooltip = "Select or create a rumpelpod";
      this.status.show();
      return;
    }
    const state = selected.info === undefined
      ? "starting"
      : agentActivity(selected.info, selected.agent) ?? podStatusLabel(selected.info.status);
    const repositoryState =
      selected.info?.repo_state === null || selected.info?.repo_state === undefined
        ? ""
        : ` / ${selected.info.repo_state}`;
    this.status.text =
      `$(comment-discussion) ${selected.pod} / ${agentLabel(selected.agent)} / ${state}${repositoryState}`;
    this.status.tooltip = statusTooltip(selected, state);
    this.status.show();
    this.terminals.updateActiveState(
      selected.repository,
      selected.pod,
      selected.agent,
      state,
      selected.info?.repo_state ?? "",
    );
  }

  public dispose(): void {
    for (const timeout of this.scheduledRefreshes) {
      clearTimeout(timeout);
    }
    this.scheduledRefreshes.clear();
  }

  private reclaimRestoredReview(): Promise<void> {
    const last = this.model.lastPod();
    if (this.active !== undefined || last === undefined) {
      return Promise.resolve();
    }
    return this.reviewDocuments.reclaimEmpty(last.repository, last.pod);
  }

  private currentSelection(selected: ActivePod): ActivePod | undefined {
    const active = this.active;
    if (
      active?.repository.root === selected.repository.root &&
      active.pod === selected.pod &&
      active.generation === selected.generation
    ) {
      return active;
    }
    return undefined;
  }

  private enqueueReviewUpdate(update: () => Promise<void>): Promise<void> {
    const result = this.reviewUpdates.then(update);
    this.reviewUpdates = result.catch(() => {});
    return result;
  }

  private enqueueStatusUpdate(update: () => Promise<void>): Promise<void> {
    const result = this.statusUpdates.then(update);
    this.statusUpdates = result.catch(() => {});
    return result;
  }

  private agentOptions(current: AgentKind): readonly AgentMenuOption[] {
    return AGENTS.map((agent) => ({
      agent,
      current: agent === current,
      description: agentDescription(agent),
      label: agentLabel(agent),
    }));
  }

  private async openPodSelection(repositoryRoot: string, podName: string): Promise<void> {
    const repository = await this.repositoryByRoot(repositoryRoot);
    const pods = await this.model.listPods(repository, false);
    const pod = pods.find((candidate) => candidate.name === podName);
    if (pod === undefined) {
      throw new Error(`pod '${podName}' is no longer available`);
    }
    await this.openPod(repository, pod);
  }

  private podPick(repository: Repository, pod: PodInfo, showRepository: boolean): PodMenuOption {
    const agent = this.model.getAgent(repository, pod.name) ?? this.model.defaultAgent();
    const activity = agentActivity(pod, agent);
    const descriptions = [
      showRepository ? repository.name : undefined,
      agentLabel(agent),
      activity ?? podStatusLabel(pod.status),
      pod.repo_state ?? undefined,
    ].filter((value): value is string => value !== undefined);
    return {
      active: this.isActivePod(repository.root, pod.name),
      detail: `Host: ${pod.host} - Created: ${pod.created}`,
      name: pod.name,
      repository: repository.root,
      status: podStatusLabel(pod.status),
      summary: descriptions.join(" - "),
    };
  }

  private async repositoryByRoot(root: string): Promise<Repository> {
    const repositories = await this.model.repositories();
    const repository = repositories.find((candidate) => candidate.root === root);
    if (repository === undefined) {
      throw new Error(`repository '${root}' is no longer open`);
    }
    return repository;
  }

  private scheduleRefreshes(): void {
    for (const delay of [1_000, 3_000, 10_000]) {
      const timeout = setTimeout(() => {
        this.scheduledRefreshes.delete(timeout);
        void this.refresh(false).catch((error: unknown) => {
          this.model.logError(`refreshing newly created pod ${this.active?.pod ?? "unknown"}`, error);
        });
      }, delay);
      this.scheduledRefreshes.add(timeout);
    }
  }
}

function agentActivity(pod: PodInfo, agent: AgentKind): string | undefined {
  switch (agent) {
    case "claude":
      switch (pod.claude_state) {
        case null:
          return undefined;
        case "processing":
          return "processing";
        case "waiting_for_input":
          return "waiting";
        case "auth_error":
          return "authentication error";
        case "stopped":
          return "stopped";
      }
      throw new Error(`unknown Claude state: ${String(pod.claude_state)}`);
    case "codex":
      switch (pod.codex_state) {
        case null:
          return undefined;
        case "processing":
          return "processing";
        case "idle":
          return "idle";
        case "error":
          return "error";
      }
      throw new Error(`unknown Codex state: ${String(pod.codex_state)}`);
    case "grok":
    case "pi":
      return undefined;
  }
}

function podStatusLabel(status: PodInfo["status"]): string {
  switch (status) {
    case "Running":
      return "running";
    case "Stopped":
      return "stopped";
    case "Gone":
      return "gone";
    case "Disconnected":
      return "disconnected";
    case "Stopping":
      return "stopping";
    case "Deleting":
      return "deleting";
    case "Broken":
      return "broken";
  }
}

function statusTooltip(selected: ActivePod, state: string): vscode.MarkdownString {
  const tooltip = new vscode.MarkdownString(undefined, true);
  tooltip.appendMarkdown(`**${selected.pod}**\n\n`);
  tooltip.appendMarkdown(`Agent: ${agentLabel(selected.agent)}\n\n`);
  tooltip.appendMarkdown(`State: ${state}\n\n`);
  if (selected.info?.repo_state !== null && selected.info?.repo_state !== undefined) {
    tooltip.appendMarkdown(`Repository: ${selected.info.repo_state}\n\n`);
  }
  tooltip.appendMarkdown("Select another pod or open a pod shell");
  return tooltip;
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
