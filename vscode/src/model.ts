// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as path from "node:path";
import * as vscode from "vscode";

import type { PodInfo, ReviewPlan } from "./generated/protocol";
import { isAgentKind, type AgentKind } from "./agents";
import type { RumpelpodDaemon } from "./daemon";
import { ProcessError, runProcess } from "./process";

const LAUNCHED_AGENTS_KEY = "rumpelpod.launchedAgents";
const LAST_POD_KEY = "rumpelpod.lastPod";

export interface Repository {
  readonly name: string;
  readonly root: string;
}

interface LastPod {
  readonly repository: string;
  readonly pod: string;
}

export class SshPassphraseRequiredError extends Error {
  public constructor(cause: unknown) {
    super("the selected SSH key requires a passphrase", { cause });
    this.name = "SshPassphraseRequiredError";
  }
}

export class RumpelpodModel {
  private repositoriesPromise: Promise<readonly Repository[]> | undefined;

  public constructor(
    private readonly workspaceState: vscode.Memento,
    private readonly output: vscode.OutputChannel,
    private readonly extensionUri: vscode.Uri,
    private readonly daemon: RumpelpodDaemon,
  ) {}

  public async repositories(): Promise<readonly Repository[]> {
    this.repositoriesPromise ??= this.discoverRepositories();
    return this.repositoriesPromise;
  }

  public invalidateRepositories(): void {
    this.repositoriesPromise = undefined;
  }

  public async listPods(
    repository: Repository,
    sync: boolean,
  ): Promise<readonly PodInfo[]> {
    return this.daemon.listPods(repository.root, sync);
  }

  public async review(repository: Repository, pod: string): Promise<ReviewPlan> {
    return this.daemon.review(repository.root, pod);
  }

  public async mergePod(repository: Repository, pod: string): Promise<void> {
    await this.runRumpel(repository, ["merge", pod, "--no-edit"]);
  }

  public async stopPod(repository: Repository, pod: string): Promise<void> {
    await this.runRumpel(repository, ["stop", "--wait", pod]);
  }

  public async deletePod(repository: Repository, pod: string): Promise<void> {
    await this.runRumpel(repository, ["delete", "--wait", "--force", pod]);
  }

  public async addSshKey(
    repository: Repository,
    pod: string,
    keyPath: string,
    passphrase?: string,
  ): Promise<void> {
    const environment = {
      DISPLAY: process.env.DISPLAY ?? "rumpelpod-vscode",
      SSH_ASKPASS: vscode.Uri.joinPath(
        this.extensionUri,
        "media",
        "ssh-askpass.sh",
      ).fsPath,
      SSH_ASKPASS_REQUIRE: "force",
      ...(passphrase === undefined
        ? {}
        : { RUMPELPOD_VSCODE_SSH_PASSPHRASE: passphrase }),
    };
    try {
      await this.runRumpel(repository, ["ssh-add", pod, keyPath], environment);
    } catch (error) {
      if (
        error instanceof ProcessError &&
        error.stderr.toLowerCase().includes("passphrase")
      ) {
        throw new SshPassphraseRequiredError(error);
      }
      throw error;
    }
  }

  public launchedAgents(repository: Repository, pod: string): readonly AgentKind[] | undefined {
    const sessions = this.savedAgentSessions();
    const candidate = sessions[assignmentKey(repository, pod)];
    if (candidate === undefined) {
      return undefined;
    }
    if (!Array.isArray(candidate) || candidate.length === 0 || !candidate.every(isAgentKind)) {
      throw new Error(`invalid saved agents for pod '${pod}'`);
    }
    return [...new Set(candidate)];
  }

  public async saveLaunchedAgents(
    repository: Repository,
    pod: string,
    agents: readonly AgentKind[],
  ): Promise<void> {
    if (agents.length === 0) {
      throw new Error(`cannot save an empty agent list for pod '${pod}'`);
    }
    const sessions = this.savedAgentSessions();
    sessions[assignmentKey(repository, pod)] = [...new Set(agents)];
    await this.workspaceState.update(LAUNCHED_AGENTS_KEY, sessions);
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

  public async forgetPod(repository: Repository, pod: string): Promise<void> {
    const sessions = this.savedAgentSessions();
    delete sessions[assignmentKey(repository, pod)];
    await this.workspaceState.update(LAUNCHED_AGENTS_KEY, sessions);
    await this.forgetRememberedPod(repository, pod);
  }

  public async forgetRememberedPod(repository: Repository, pod: string): Promise<void> {
    const last = this.lastPod();
    if (last?.repository === repository.root && last.pod === pod) {
      await this.workspaceState.update(LAST_POD_KEY, undefined);
    }
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

  private savedAgentSessions(): Record<string, unknown> {
    const value = this.workspaceState.get<unknown>(LAUNCHED_AGENTS_KEY);
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return {};
    }
    return { ...value };
  }

  private async runRumpel(
    repository: Repository,
    args: readonly string[],
    environment?: NodeJS.ProcessEnv,
  ): Promise<string> {
    const executable = this.executable();
    this.output.appendLine(`$ ${[executable, ...args].join(" ")}`);
    const result = await runProcess(executable, args, repository.root, { environment });
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
  return JSON.stringify([repository.root, pod]);
}
