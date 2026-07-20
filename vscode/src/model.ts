// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as path from "node:path";
import * as vscode from "vscode";

import type { AgentKind, PodInfo, ReviewPlan } from "./generated/protocol";
import { isAgentKind } from "./agents";
import { runProcess } from "./process";

const AGENT_ASSIGNMENTS_KEY = "rumpelpod.agentAssignments";
const LAST_POD_KEY = "rumpelpod.lastPod";

export interface Repository {
  readonly name: string;
  readonly root: string;
}

interface LastPod {
  readonly repository: string;
  readonly pod: string;
}

export class RumpelpodModel {
  private repositoriesPromise: Promise<readonly Repository[]> | undefined;

  public constructor(
    private readonly workspaceState: vscode.Memento,
    private readonly output: vscode.OutputChannel,
  ) {}

  public async repositories(): Promise<readonly Repository[]> {
    this.repositoriesPromise ??= this.discoverRepositories();
    return this.repositoriesPromise;
  }

  public async listPods(repository: Repository): Promise<readonly PodInfo[]> {
    const output = await this.runRumpel(repository, ["list", "--sync", "--json"]);
    const parsed: unknown = JSON.parse(output);
    if (!Array.isArray(parsed) || !parsed.every(isPodInfo)) {
      throw new Error("rumpel list --json returned an unexpected payload");
    }
    return parsed;
  }

  public async review(repository: Repository, pod: string): Promise<ReviewPlan> {
    const output = await this.runRumpel(repository, ["review", pod, "--json"]);
    const parsed: unknown = JSON.parse(output);
    if (!isReviewPlan(parsed)) {
      throw new Error("rumpel review --json returned an unexpected payload");
    }
    return parsed;
  }

  public getAgent(repository: Repository, pod: string): AgentKind | undefined {
    const assignments = this.assignments();
    const candidate = assignments[assignmentKey(repository, pod)];
    return isAgentKind(candidate) ? candidate : undefined;
  }

  public async setAgent(repository: Repository, pod: string, agent: AgentKind): Promise<void> {
    const assignments = this.assignments();
    assignments[assignmentKey(repository, pod)] = agent;
    await this.workspaceState.update(AGENT_ASSIGNMENTS_KEY, assignments);
  }

  public defaultAgent(): AgentKind {
    const configured = vscode.workspace
      .getConfiguration("rumpelpod")
      .get<unknown>("defaultAgent", "codex");
    if (!isAgentKind(configured)) {
      throw new Error(`unknown rumpelpod.defaultAgent value: ${String(configured)}`);
    }
    return configured;
  }

  public executable(): string {
    const executable = vscode.workspace
      .getConfiguration("rumpelpod")
      .get<string>("executable", "rumpel")
      .trim();
    if (executable.length === 0) {
      throw new Error("rumpelpod.executable must not be empty");
    }
    return executable;
  }

  public async rememberPod(repository: Repository, pod: string): Promise<void> {
    await this.workspaceState.update(LAST_POD_KEY, {
      repository: repository.root,
      pod,
    } satisfies LastPod);
  }

  public lastPod(): LastPod | undefined {
    const value = this.workspaceState.get<unknown>(LAST_POD_KEY);
    if (
      typeof value !== "object" ||
      value === null ||
      !("repository" in value) ||
      !("pod" in value) ||
      typeof value.repository !== "string" ||
      typeof value.pod !== "string"
    ) {
      return undefined;
    }
    return { repository: value.repository, pod: value.pod };
  }

  public logError(context: string, error: unknown): void {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    this.output.appendLine(`${context}: ${message}`);
  }

  private assignments(): Record<string, unknown> {
    const value = this.workspaceState.get<unknown>(AGENT_ASSIGNMENTS_KEY);
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return {};
    }
    return { ...value };
  }

  private async runRumpel(repository: Repository, args: readonly string[]): Promise<string> {
    const executable = this.executable();
    this.output.appendLine(`$ ${[executable, ...args].join(" ")}`);
    const result = await runProcess(executable, args, repository.root);
    const stderr = result.stderr.toString("utf8").trim();
    if (stderr.length > 0) {
      this.output.appendLine(stderr);
    }
    return result.stdout.toString("utf8").trim();
  }

  private async discoverRepositories(): Promise<readonly Repository[]> {
    const folders = vscode.workspace.workspaceFolders ?? [];
    const roots = new Map<string, Repository>();
    for (const folder of folders) {
      try {
        const result = await runProcess(
          "git",
          ["rev-parse", "--show-toplevel"],
          folder.uri.fsPath,
        );
        const root = result.stdout.toString("utf8").trim();
        if (root.length === 0) {
          throw new Error("git rev-parse returned an empty repository path");
        }
        roots.set(root, { name: path.basename(root), root });
      } catch (error) {
        this.logError(`discovering repository for ${folder.uri.fsPath}`, error);
      }
    }
    return [...roots.values()].sort((left, right) => left.name.localeCompare(right.name));
  }
}

function assignmentKey(repository: Repository, pod: string): string {
  return `${repository.root}\u0000${pod}`;
}

function isPodInfo(value: unknown): value is PodInfo {
  return (
    typeof value === "object" &&
    value !== null &&
    "name" in value &&
    "status" in value &&
    "created" in value &&
    "host" in value &&
    "repo_state" in value &&
    "container_id" in value &&
    "last_commit_time" in value &&
    "claude_state" in value &&
    "codex_state" in value &&
    typeof value.name === "string" &&
    isPodStatus(value.status) &&
    typeof value.created === "string" &&
    typeof value.host === "string" &&
    isNullableString(value.repo_state) &&
    isNullableString(value.container_id) &&
    (value.last_commit_time === null || typeof value.last_commit_time === "number") &&
    isClaudeState(value.claude_state) &&
    isCodexState(value.codex_state)
  );
}

function isPodStatus(value: unknown): value is PodInfo["status"] {
  switch (value) {
    case "Running":
    case "Stopped":
    case "Gone":
    case "Disconnected":
    case "Stopping":
    case "Deleting":
    case "Broken":
      return true;
  }
  return false;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isClaudeState(value: unknown): value is PodInfo["claude_state"] {
  switch (value) {
    case null:
    case "processing":
    case "waiting_for_input":
    case "auth_error":
    case "stopped":
      return true;
  }
  return false;
}

function isCodexState(value: unknown): value is PodInfo["codex_state"] {
  switch (value) {
    case null:
    case "processing":
    case "idle":
    case "error":
      return true;
  }
  return false;
}

function isReviewPlan(value: unknown): value is ReviewPlan {
  return (
    typeof value === "object" &&
    value !== null &&
    "base" in value &&
    "target" in value &&
    "files" in value &&
    typeof value.base === "string" &&
    typeof value.target === "string" &&
    Array.isArray(value.files) &&
    value.files.every(
      (file) =>
        typeof file === "object" &&
        file !== null &&
        "path" in file &&
        "base_exists" in file &&
        "target_exists" in file &&
        typeof file.path === "string" &&
        typeof file.base_exists === "boolean" &&
        typeof file.target_exists === "boolean",
    )
  );
}
