// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { AgentKind, PodInfo, ReviewFile, ReviewPlan } from "./generated/protocol";
import { AGENTS, agentDescription, agentLabel } from "./agents";
import type { Repository, RumpelpodModel } from "./model";
import type { ReviewDocuments } from "./review";
import type { AgentTerminals } from "./terminal";

interface AgentPick extends vscode.QuickPickItem {
  readonly agent: AgentKind;
}

interface RepositoryPick extends vscode.QuickPickItem {
  readonly repository: Repository;
}

interface PodPick extends vscode.QuickPickItem {
  readonly agent: AgentKind;
  readonly pod: PodInfo;
  readonly repository: Repository;
}

interface ReviewFilePick extends vscode.QuickPickItem {
  readonly file: ReviewFile;
}

interface ActivePod {
  readonly agent: AgentKind;
  readonly currentFile: string | undefined;
  readonly generation: number;
  readonly info: PodInfo | undefined;
  readonly plan: ReviewPlan | undefined;
  readonly pod: string;
  readonly repository: Repository;
}

type SwitcherAction =
  | { readonly kind: "create" }
  | { readonly kind: "open"; readonly pick: PodPick }
  | { readonly kind: "shell"; readonly pick: PodPick };

const CREATE_POD_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("add"),
  tooltip: "Create Pod",
};

const OPEN_SHELL_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("terminal"),
  tooltip: "Open Pod Shell",
};

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

  public async showPodSwitcher(): Promise<void> {
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
    const picker = vscode.window.createQuickPick<PodPick>();
    picker.title = this.active === undefined ? "Rumpelpod" : `Rumpelpod: ${this.active.pod}`;
    picker.placeholder =
      picks.length === 0 ? "No pods yet. Use + to create one." : "Select a pod";
    picker.matchOnDescription = true;
    picker.matchOnDetail = true;
    picker.buttons = [CREATE_POD_BUTTON];
    picker.items = picks;
    const activePick = picks.find((pick) => this.isActivePod(pick.repository.root, pick.pod.name));
    if (activePick !== undefined) {
      picker.activeItems = [activePick];
    }

    const action = await waitForSwitcherAction(picker);
    picker.dispose();
    if (action === undefined) {
      return;
    }
    switch (action.kind) {
      case "create":
        await this.createPod();
        return;
      case "open":
        await this.openPod(action.pick.repository, action.pick.pod);
        return;
      case "shell":
        this.terminals.showShell(
          action.pick.repository,
          action.pick.pod.name,
          this.model.executable(),
        );
        return;
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
      const file =
        plan.files.find((candidate) => candidate.path === active.currentFile) ?? plan.files[0];
      this.active = {
        ...active,
        currentFile: file?.path,
        plan,
      };
      if (file === undefined) {
        await this.reviewDocuments.openEmpty(selected.repository, selected.pod, preserveFocus);
        return;
      }
      await this.reviewDocuments.open(
        selected.repository,
        selected.pod,
        plan,
        file,
        preserveFocus,
      );
    });
  }

  public isActivePod(repositoryRoot: string, pod: string): boolean {
    return this.active?.repository.root === repositoryRoot && this.active.pod === pod;
  }

  public async createPod(): Promise<void> {
    const repository = await this.pickRepository();
    if (repository === undefined) {
      return;
    }
    const agent = await this.pickAgent(this.model.defaultAgent(), "Select the agent for the pod");
    if (agent === undefined) {
      return;
    }
    const pod = await vscode.window.showInputBox({
      prompt: "Name the new rumpelpod",
      placeHolder: "feature-name",
      ignoreFocusOut: true,
      validateInput: validatePodName,
    });
    if (pod === undefined) {
      return;
    }
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
      currentFile: undefined,
      generation,
      info: undefined,
      plan: undefined,
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
      currentFile: undefined,
      generation,
      info: pod,
      plan: undefined,
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

  public async changeActiveAgent(): Promise<void> {
    const selected = this.active;
    if (selected === undefined) {
      throw new Error("select a pod before changing its agent");
    }
    const agent = await this.pickAgent(selected.agent, `Select the agent for ${selected.pod}`);
    if (agent === undefined) {
      return;
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

  public async pickReviewFile(): Promise<void> {
    const selected = this.active;
    if (selected === undefined) {
      throw new Error("select a pod before selecting a review file");
    }
    const plan = await this.model.review(selected.repository, selected.pod);
    if (this.currentSelection(selected) === undefined) {
      return;
    }
    if (plan.files.length === 0) {
      await vscode.window.showInformationMessage(`${selected.pod} has no changes to review`);
      return;
    }
    const picks: ReviewFilePick[] = plan.files.map((file) => ({
      label: file.path,
      description: reviewFileDescription(file),
      file,
      picked: file.path === selected.currentFile,
    }));
    const pick = await vscode.window.showQuickPick(picks, {
      placeHolder: `Select a changed file in ${selected.pod}`,
      ignoreFocusOut: true,
      matchOnDescription: true,
    });
    const active = this.currentSelection(selected);
    if (pick === undefined || active === undefined) {
      return;
    }
    this.active = {
      ...active,
      currentFile: pick.file.path,
      plan,
    };
    await this.refreshActiveReview(false);
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

  private podPick(repository: Repository, pod: PodInfo, showRepository: boolean): PodPick {
    const agent = this.model.getAgent(repository, pod.name) ?? this.model.defaultAgent();
    const activity = agentActivity(pod, agent);
    const descriptions = [
      showRepository ? repository.name : undefined,
      agentLabel(agent),
      activity ?? podStatusLabel(pod.status),
      pod.repo_state ?? undefined,
    ].filter((value): value is string => value !== undefined);
    return {
      agent,
      buttons: [OPEN_SHELL_BUTTON],
      description: descriptions.join(" - "),
      detail: `Host: ${pod.host} - Created: ${pod.created}`,
      iconPath: podStatusIcon(pod.status),
      label: pod.name,
      pod,
      repository,
    };
  }

  private async pickRepository(): Promise<Repository | undefined> {
    const repositories = await this.model.repositories();
    if (repositories.length === 0) {
      throw new Error("open a Git repository before creating a pod");
    }
    if (repositories.length === 1) {
      return repositories[0];
    }
    const picks: RepositoryPick[] = repositories.map((repository) => ({
      label: repository.name,
      description: repository.root,
      repository,
    }));
    return (await vscode.window.showQuickPick(picks, {
      placeHolder: "Select a repository",
      ignoreFocusOut: true,
    }))?.repository;
  }

  private async pickAgent(
    current: AgentKind,
    placeHolder: string,
  ): Promise<AgentKind | undefined> {
    const picks: AgentPick[] = AGENTS.map((agent) => ({
      label: agentLabel(agent),
      description: agent === current ? "Current" : undefined,
      detail: agentDescription(agent),
      agent,
      picked: agent === current,
    }));
    return (await vscode.window.showQuickPick(picks, {
      placeHolder,
      ignoreFocusOut: true,
    }))?.agent;
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

function waitForSwitcherAction(
  picker: vscode.QuickPick<PodPick>,
): Promise<SwitcherAction | undefined> {
  return new Promise((resolve) => {
    picker.onDidAccept(() => {
      const pick = picker.selectedItems[0];
      if (pick !== undefined) {
        resolve({ kind: "open", pick });
        picker.hide();
      }
    });
    picker.onDidTriggerButton((button) => {
      if (button === CREATE_POD_BUTTON) {
        resolve({ kind: "create" });
        picker.hide();
      }
    });
    picker.onDidTriggerItemButton((event) => {
      resolve({ kind: "shell", pick: event.item });
      picker.hide();
    });
    picker.onDidHide(() => resolve(undefined));
    picker.show();
  });
}

function reviewFileDescription(file: ReviewFile): string {
  if (!file.base_exists) {
    return "added";
  }
  if (!file.target_exists) {
    return "deleted";
  }
  return "modified";
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

function podStatusIcon(status: PodInfo["status"]): vscode.ThemeIcon {
  switch (status) {
    case "Running":
      return new vscode.ThemeIcon("vm-running", new vscode.ThemeColor("testing.iconPassed"));
    case "Stopped":
      return new vscode.ThemeIcon("debug-stop");
    case "Gone":
      return new vscode.ThemeIcon("circle-slash");
    case "Disconnected":
      return new vscode.ThemeIcon("debug-disconnect");
    case "Stopping":
      return new vscode.ThemeIcon("loading~spin");
    case "Deleting":
      return new vscode.ThemeIcon("trash");
    case "Broken":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("problemsErrorIcon.foreground"));
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
