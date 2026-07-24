// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { ReviewFile, ReviewPlan } from "./generated/protocol";
import type { Repository } from "./model";
import { runProcess } from "./process";

const REVIEW_SCHEME = "rumpelpod-review";
const BINARY_FILE_MESSAGE = "Binary file cannot be displayed by the text diff editor.\n";

interface ReviewDocumentDescriptor {
  readonly kind: "file";
  readonly exists: boolean;
  readonly path: string;
  readonly repository: string;
  readonly revision: string;
}

export class ReviewDocuments implements vscode.TextDocumentContentProvider, vscode.Disposable {
  private readonly registration: vscode.Disposable;
  private readonly content = new Map<string, Promise<string>>();

  public constructor() {
    this.registration = vscode.workspace.registerTextDocumentContentProvider(REVIEW_SCHEME, this);
  }

  public provideTextDocumentContent(uri: vscode.Uri): Promise<string> {
    const key = uri.toString();
    const existing = this.content.get(key);
    if (existing !== undefined) {
      return existing;
    }
    const loaded = this.load(uri);
    this.content.set(key, loaded);
    loaded.catch(() => this.content.delete(key));
    return loaded;
  }

  public async open(
    repository: Repository,
    pod: string,
    plan: ReviewPlan,
    file: ReviewFile,
    preserveFocus = false,
  ): Promise<void> {
    await this.clear();
    const base = reviewUri(repository, plan.base, file.path, file.base_exists, "base");
    const target = reviewUri(repository, plan.target, file.path, file.target_exists, "target");
    await vscode.commands.executeCommand(
      "vscode.diff",
      base,
      target,
      `${pod}: ${file.path}`,
      {
        preview: true,
        preserveFocus,
        viewColumn: vscode.ViewColumn.Two,
      } satisfies vscode.TextDocumentShowOptions,
    );
  }

  public async clear(): Promise<void> {
    const tabs = vscode.window.tabGroups.all.flatMap((group) =>
      group.tabs.filter((tab) => isReviewTab(tab)),
    );
    if (tabs.length > 0) {
      await vscode.window.tabGroups.close(tabs, true);
    }
    this.content.clear();
  }

  public async clearPlaceholders(): Promise<void> {
    const tabs = vscode.window.tabGroups.all.flatMap((group) =>
      group.tabs.filter((tab) => isReviewPlaceholderTab(tab)),
    );
    if (tabs.length > 0) {
      await vscode.window.tabGroups.close(tabs, true);
    }
  }

  public dispose(): void {
    this.registration.dispose();
    this.content.clear();
  }

  private async load(uri: vscode.Uri): Promise<string> {
    const descriptor = decodeDescriptor(uri);
    if (!descriptor.exists) {
      return "";
    }
    const object = `${descriptor.revision}:${descriptor.path}`;
    const result = await runProcess(
      "git",
      ["show", object],
      descriptor.repository,
    );
    if (result.stdout.includes(0)) {
      return BINARY_FILE_MESSAGE;
    }
    return result.stdout.toString("utf8");
  }
}

function isReviewTab(tab: vscode.Tab): boolean {
  const input = tab.input;
  if (input instanceof vscode.TabInputText) {
    return input.uri.scheme === REVIEW_SCHEME;
  }
  if (input instanceof vscode.TabInputTextDiff) {
    return input.original.scheme === REVIEW_SCHEME || input.modified.scheme === REVIEW_SCHEME;
  }
  return false;
}

function isReviewPlaceholderTab(tab: vscode.Tab): boolean {
  const input = tab.input;
  return input instanceof vscode.TabInputText && input.uri.scheme === REVIEW_SCHEME;
}

function reviewUri(
  repository: Repository,
  revision: string,
  filePath: string,
  exists: boolean,
  side: "base" | "target",
): vscode.Uri {
  const descriptor: ReviewDocumentDescriptor = {
    exists,
    kind: "file",
    path: filePath,
    repository: repository.root,
    revision,
  };
  return vscode.Uri.from({
    scheme: REVIEW_SCHEME,
    path: `/${side}/${filePath}`,
    query: encodeURIComponent(JSON.stringify(descriptor)),
  });
}

function decodeDescriptor(uri: vscode.Uri): ReviewDocumentDescriptor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeURIComponent(uri.query));
  } catch (error) {
    throw new Error(`invalid rumpelpod review URI: ${uri.toString()}`, { cause: error });
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("kind" in parsed) ||
    typeof parsed.kind !== "string"
  ) {
    throw new Error(`invalid rumpelpod review descriptor: ${uri.toString()}`);
  }
  if (
    parsed.kind !== "file" ||
    !("exists" in parsed) ||
    !("path" in parsed) ||
    !("repository" in parsed) ||
    !("revision" in parsed) ||
    typeof parsed.exists !== "boolean" ||
    typeof parsed.path !== "string" ||
    typeof parsed.repository !== "string" ||
    typeof parsed.revision !== "string"
  ) {
    throw new Error(`invalid rumpelpod review descriptor: ${uri.toString()}`);
  }
  return {
    exists: parsed.exists,
    kind: "file",
    path: parsed.path,
    repository: parsed.repository,
    revision: parsed.revision,
  };
}
