// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { PodInfo, ReviewFile, ReviewPlan } from "./generated/protocol";
import { agentLabel } from "./agents";
import type { Repository, RumpelpodModel } from "./model";

export type RumpelpodTreeNode = RepositoryItem | PodItem | ReviewFileItem | MessageItem;

export class RepositoryItem extends vscode.TreeItem {
  public constructor(public readonly repository: Repository) {
    super(repository.name, vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = "rumpelpod.repository";
    this.description = repository.root;
    this.iconPath = new vscode.ThemeIcon("repo");
    this.tooltip = repository.root;
  }
}

export class PodItem extends vscode.TreeItem {
  public constructor(
    public readonly repository: Repository,
    public readonly pod: PodInfo,
  ) {
    super(pod.name, vscode.TreeItemCollapsibleState.Collapsed);
    this.command = {
      command: "rumpelpod.openPod",
      title: "Open Pod",
      arguments: [this],
    };
    this.contextValue = "rumpelpod.pod";
    this.iconPath = statusIcon(pod.status);
  }
}

export class ReviewFileItem extends vscode.TreeItem {
  public constructor(
    public readonly repository: Repository,
    public readonly pod: PodInfo,
    public readonly plan: ReviewPlan,
    public readonly file: ReviewFile,
  ) {
    super(file.path, vscode.TreeItemCollapsibleState.None);
    this.command = {
      command: "rumpelpod.openReviewFile",
      title: "Open Review File",
      arguments: [this],
    };
    this.contextValue = "rumpelpod.reviewFile";
    this.iconPath = new vscode.ThemeIcon(reviewFileIcon(file));
    this.tooltip = file.path;
  }
}

export class MessageItem extends vscode.TreeItem {
  public constructor(label: string, tooltip?: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "rumpelpod.message";
    this.iconPath = new vscode.ThemeIcon("info");
    this.tooltip = tooltip;
  }
}

export class PodTreeProvider implements vscode.TreeDataProvider<RumpelpodTreeNode> {
  private readonly changeEmitter = new vscode.EventEmitter<RumpelpodTreeNode | undefined>();
  private readonly pods = new Map<string, Promise<readonly PodInfo[]>>();
  private readonly reviews = new Map<string, Promise<ReviewPlan>>();

  public readonly onDidChangeTreeData = this.changeEmitter.event;

  public constructor(private readonly model: RumpelpodModel) {}

  public getTreeItem(element: RumpelpodTreeNode): vscode.TreeItem {
    if (element instanceof PodItem) {
      const agent = this.model.getAgent(element.repository, element.pod.name);
      const agentDescription = agent === undefined ? "agent not selected" : agentLabel(agent);
      const state = statusLabel(element.pod.status);
      element.description = `${agentDescription} - ${state}`;
      element.tooltip = podTooltip(element.pod, agentDescription);
    }
    return element;
  }

  public async getChildren(element?: RumpelpodTreeNode): Promise<RumpelpodTreeNode[]> {
    if (element instanceof MessageItem || element instanceof ReviewFileItem) {
      return [];
    }
    if (element instanceof PodItem) {
      return this.reviewChildren(element);
    }

    const repositories = await this.model.repositories();
    if (element instanceof RepositoryItem) {
      return this.podChildren(element.repository);
    }
    if (repositories.length === 0) {
      return [new MessageItem("No Git repository in this workspace")];
    }
    if (repositories.length === 1) {
      const repository = repositories[0];
      if (repository === undefined) {
        throw new Error("repository list changed while rendering the tree");
      }
      return this.podChildren(repository);
    }
    return repositories.map((repository) => new RepositoryItem(repository));
  }

  public async findPod(repositoryRoot: string, podName: string): Promise<PodItem | undefined> {
    const repositories = await this.model.repositories();
    const repository = repositories.find((candidate) => candidate.root === repositoryRoot);
    if (repository === undefined) {
      return undefined;
    }
    const pods = await this.loadPods(repository);
    const pod = pods.find((candidate) => candidate.name === podName);
    return pod === undefined ? undefined : new PodItem(repository, pod);
  }

  public refresh(): void {
    this.pods.clear();
    this.reviews.clear();
    this.changeEmitter.fire(undefined);
  }

  public dispose(): void {
    this.changeEmitter.dispose();
  }

  private async podChildren(repository: Repository): Promise<RumpelpodTreeNode[]> {
    try {
      const pods = await this.loadPods(repository);
      if (pods.length === 0) {
        return [new MessageItem("No pods. Use + to create one.")];
      }
      return pods.map((pod) => new PodItem(repository, pod));
    } catch (error) {
      this.model.logError(`listing pods for ${repository.root}`, error);
      return [new MessageItem("Could not list pods", errorMessage(error))];
    }
  }

  private async reviewChildren(item: PodItem): Promise<RumpelpodTreeNode[]> {
    try {
      const plan = await this.loadReview(item.repository, item.pod.name);
      if (plan.files.length === 0) {
        return [new MessageItem("No changes to review")];
      }
      return plan.files.map(
        (file) => new ReviewFileItem(item.repository, item.pod, plan, file),
      );
    } catch (error) {
      this.model.logError(`loading review for ${item.pod.name}`, error);
      return [new MessageItem("Review is not available", errorMessage(error))];
    }
  }

  private loadPods(repository: Repository): Promise<readonly PodInfo[]> {
    let loaded = this.pods.get(repository.root);
    if (loaded === undefined) {
      loaded = this.model.listPods(repository);
      this.pods.set(repository.root, loaded);
      loaded.catch(() => this.pods.delete(repository.root));
    }
    return loaded;
  }

  private loadReview(repository: Repository, pod: string): Promise<ReviewPlan> {
    const key = `${repository.root}\u0000${pod}`;
    let loaded = this.reviews.get(key);
    if (loaded === undefined) {
      loaded = this.model.review(repository, pod);
      this.reviews.set(key, loaded);
      loaded.catch(() => this.reviews.delete(key));
    }
    return loaded;
  }
}

function statusLabel(status: PodInfo["status"]): string {
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

function statusIcon(status: PodInfo["status"]): vscode.ThemeIcon {
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

function reviewFileIcon(file: ReviewFile): string {
  if (!file.base_exists) {
    return "diff-added";
  }
  if (!file.target_exists) {
    return "diff-removed";
  }
  return "diff-modified";
}

function podTooltip(pod: PodInfo, agent: string): vscode.MarkdownString {
  const tooltip = new vscode.MarkdownString(undefined, true);
  tooltip.appendMarkdown(`**${pod.name}**\n\n`);
  tooltip.appendMarkdown(`Agent: ${agent}\n\n`);
  tooltip.appendMarkdown(`Status: ${statusLabel(pod.status)}\n\n`);
  tooltip.appendMarkdown(`Host: ${pod.host}\n\n`);
  if (pod.repo_state !== null) {
    tooltip.appendMarkdown(`Repository: ${pod.repo_state}\n\n`);
  }
  tooltip.appendMarkdown(`Created: ${pod.created}`);
  return tooltip;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
