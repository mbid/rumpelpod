// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { AgentKind } from "./generated/protocol";
import { AGENTS, agentDescription, agentLabel } from "./agents";
import type { Repository, RumpelpodModel } from "./model";
import type { ReviewDocuments } from "./review";
import type { AgentTerminals } from "./terminal";
import {
  PodItem,
  type PodTreeProvider,
  ReviewFileItem,
} from "./tree";

interface AgentPick extends vscode.QuickPickItem {
  readonly agent: AgentKind;
}

interface RepositoryPick extends vscode.QuickPickItem {
  readonly repository: Repository;
}

export class RumpelpodController {
  private readonly scheduledRefreshes = new Set<NodeJS.Timeout>();

  public constructor(
    private readonly model: RumpelpodModel,
    private readonly tree: PodTreeProvider,
    private readonly terminals: AgentTerminals,
    private readonly reviewDocuments: ReviewDocuments,
  ) {}

  public refresh(): void {
    this.tree.refresh();
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
    await this.model.setAgent(repository, pod, agent);
    await this.model.rememberPod(repository, pod);
    this.terminals.show(repository, pod, agent, this.model.executable());
    this.scheduleRefreshes();
  }

  public async openPod(item: PodItem): Promise<void> {
    const agent = this.model.getAgent(item.repository, item.pod.name) ?? this.model.defaultAgent();
    await this.model.setAgent(item.repository, item.pod.name, agent);
    await this.model.rememberPod(item.repository, item.pod.name);
    this.terminals.show(item.repository, item.pod.name, agent, this.model.executable());

    try {
      const plan = await this.model.review(item.repository, item.pod.name);
      const first = plan.files[0];
      if (first !== undefined) {
        await this.reviewDocuments.open(item.repository, item.pod.name, plan, first);
      } else {
        await this.reviewDocuments.openStatus(
          item.repository,
          item.pod.name,
          `No changes to review for ${item.pod.name}.`,
        );
      }
    } catch (error) {
      this.model.logError(`opening review for ${item.pod.name}`, error);
      const message = errorMessage(error);
      try {
        await this.reviewDocuments.openStatus(
          item.repository,
          item.pod.name,
          `Review is not available for ${item.pod.name}: ${message}`,
        );
      } catch (statusError) {
        this.model.logError(`showing review status for ${item.pod.name}`, statusError);
      }
      await vscode.window.showWarningMessage(
        `The ${item.pod.name} agent is open, but its review is not available: ${message}`,
      );
    }
  }

  public async openReviewFile(item: ReviewFileItem): Promise<void> {
    await this.reviewDocuments.open(item.repository, item.pod.name, item.plan, item.file);
  }

  public async changeAgent(item: PodItem): Promise<void> {
    const current = this.model.getAgent(item.repository, item.pod.name) ?? this.model.defaultAgent();
    const agent = await this.pickAgent(current, `Select the agent for ${item.pod.name}`);
    if (agent === undefined) {
      return;
    }
    if (agent !== current) {
      this.terminals.replace(item.repository, item.pod.name);
    }
    await this.model.setAgent(item.repository, item.pod.name, agent);
    this.tree.refresh();
    this.terminals.show(item.repository, item.pod.name, agent, this.model.executable());
  }

  public async restoreLastPod(): Promise<void> {
    const last = this.model.lastPod();
    if (last === undefined) {
      return;
    }
    try {
      const item = await this.tree.findPod(last.repository, last.pod);
      if (item === undefined) {
        return;
      }
      const agent = this.model.getAgent(item.repository, item.pod.name);
      if (agent === undefined) {
        return;
      }
      this.terminals.show(item.repository, item.pod.name, agent, this.model.executable());
    } catch (error) {
      this.model.logError(`restoring pod ${last.pod}`, error);
    }
  }

  public dispose(): void {
    for (const timeout of this.scheduledRefreshes) {
      clearTimeout(timeout);
    }
    this.scheduledRefreshes.clear();
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
        this.tree.refresh();
      }, delay);
      this.scheduledRefreshes.add(timeout);
    }
  }
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
