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

interface ReviewTab {
  readonly pod: string;
  readonly repository: string;
  readonly resources: readonly MultiDiffResource[];
  readonly source: string;
  readonly tab: vscode.Tab;
}

interface ReviewSnapshot {
  readonly pod: string;
  readonly repository: string;
  readonly resources: readonly MultiDiffResource[];
  readonly source: string;
}

interface MultiDiffResource {
  readonly modifiedUri: vscode.Uri;
  readonly originalUri: vscode.Uri;
}

interface OpenMultiDiffEditorOptions {
  readonly multiDiffSourceUri: vscode.Uri;
  readonly resources: readonly MultiDiffResource[];
  readonly title: string;
}

export class ReviewDocuments implements vscode.TextDocumentContentProvider, vscode.Disposable {
  private readonly registration: vscode.Disposable;
  private readonly tabSubscription: vscode.Disposable;
  private readonly content = new Map<string, Promise<string>>();
  private disposed = false;
  private operations = Promise.resolve();
  private pending: ReviewSnapshot | undefined;
  private review: ReviewTab | undefined;

  public constructor(
    private readonly reportError: (context: string, error: unknown) => void,
  ) {
    this.registration = vscode.workspace.registerTextDocumentContentProvider(REVIEW_SCHEME, this);
    this.tabSubscription = vscode.window.tabGroups.onDidChangeTabs(() => {
      void this.applyPendingReview().catch((error: unknown) => {
        this.reportError("refreshing the activated pod review", error);
      });
    });
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

  public async reveal(
    repository: Repository,
    pod: string,
    plan: ReviewPlan,
  ): Promise<void> {
    return this.enqueue(() => this.openNow(repository, pod, plan, false));
  }

  public async refresh(
    repository: Repository,
    pod: string,
    plan: ReviewPlan,
  ): Promise<void> {
    return this.enqueue(() => this.openNow(repository, pod, plan, true));
  }

  private async openNow(
    repository: Repository,
    pod: string,
    plan: ReviewPlan,
    refreshOnly: boolean,
  ): Promise<void> {
    const source = populatedReviewUri(repository, pod, plan);
    const sourceKey = source.toString();
    const resources = plan.files.map((file) => reviewResource(repository, plan, file));
    const current = this.review;
    const snapshot = {
      pod,
      repository: repository.root,
      resources,
      source: sourceKey,
    } satisfies ReviewSnapshot;
    const openTab = current === undefined ? undefined : this.findOpenTab(current);
    const currentIsOpen = openTab !== undefined;
    if (current !== undefined && openTab !== undefined && openTab !== current.tab) {
      this.review = { ...current, tab: openTab };
    }
    if (refreshOnly) {
      if (!samePod(current, repository, pod)) {
        return;
      }
      if (!currentIsOpen) {
        return;
      }
      if (current.source === sourceKey) {
        this.pending = undefined;
        return;
      }
      if (!this.isActive(current)) {
        this.pending = snapshot;
        return;
      }
    }
    this.pending = undefined;
    if (current?.source !== sourceKey || !currentIsOpen) {
      await this.clearNow();
    }
    const tab = await this.show(source, pod, resources);
    if (this.disposed) {
      await this.closeDisposedTab(tab);
    }
    this.review = { ...snapshot, tab };
  }

  public async revealEmpty(
    repository: Repository,
    pod: string,
  ): Promise<void> {
    return this.enqueue(() => this.openEmptyNow(repository, pod, false));
  }

  public async refreshEmpty(
    repository: Repository,
    pod: string,
  ): Promise<void> {
    return this.enqueue(() => this.openEmptyNow(repository, pod, true));
  }

  private async openEmptyNow(
    repository: Repository,
    pod: string,
    refreshOnly: boolean,
  ): Promise<void> {
    const source = emptyReviewUri(repository, pod);
    const sourceKey = source.toString();
    const current = this.review;
    const snapshot = {
      pod,
      repository: repository.root,
      resources: [],
      source: sourceKey,
    } satisfies ReviewSnapshot;
    const openTab = current === undefined ? undefined : this.findOpenTab(current);
    const currentIsOpen = openTab !== undefined;
    if (current !== undefined && openTab !== undefined && openTab !== current.tab) {
      this.review = { ...current, tab: openTab };
    }
    if (refreshOnly) {
      if (!samePod(current, repository, pod)) {
        return;
      }
      if (!currentIsOpen) {
        return;
      }
      if (current.source === sourceKey) {
        this.pending = undefined;
        return;
      }
      if (!this.isActive(current)) {
        this.pending = snapshot;
        return;
      }
    }
    this.pending = undefined;
    if (current?.source !== sourceKey || !currentIsOpen) {
      await this.clearNow();
    }
    const tab = await this.show(source, pod, []);
    if (this.disposed) {
      await this.closeDisposedTab(tab);
    }
    this.review = { ...snapshot, tab };
  }

  public async reclaimEmpty(repositoryRoot: string, pod: string): Promise<void> {
    return this.enqueue(() => this.reclaimEmptyNow(repositoryRoot, pod));
  }

  private async reclaimEmptyNow(repositoryRoot: string, pod: string): Promise<void> {
    const current = this.review;
    if (current !== undefined && this.findOpenTab(current) !== undefined) {
      return;
    }
    this.review = undefined;
    if (
      !vscode.window.tabGroups.all.some((group) =>
        group.tabs.some((tab) => isEmptyMultiDiffTab(tab, pod))
      )
    ) {
      return;
    }
    const source = emptyReviewUri(repositoryRoot, pod);
    const tab = await this.show(source, pod, []);
    if (this.disposed) {
      await this.closeDisposedTab(tab);
    }
    this.review = {
      pod,
      repository: repositoryRoot,
      resources: [],
      source: source.toString(),
      tab,
    };
  }

  private async show(
    source: vscode.Uri,
    pod: string,
    resources: readonly MultiDiffResource[],
  ): Promise<vscode.Tab> {
    // vscode.changes uses a random identity, which duplicates a restored review.
    await vscode.commands.executeCommand(
      "_workbench.openMultiDiffEditor",
      {
        multiDiffSourceUri: source,
        resources,
        title: pod,
      } satisfies OpenMultiDiffEditorOptions,
    );
    await vscode.commands.executeCommand("workbench.action.pinEditor");
    const tab = vscode.window.tabGroups.activeTabGroup.activeTab;
    if (tab === undefined || !tab.isPinned || !isMultiDiffTab(tab, resources.length)) {
      throw new Error(`VS Code did not open the review for pod '${pod}'`);
    }
    return tab;
  }

  public async clear(): Promise<void> {
    return this.enqueue(() => this.clearNow());
  }

  private async clearNow(): Promise<void> {
    const review = this.review;
    this.pending = undefined;
    this.review = undefined;
    const tabs = vscode.window.tabGroups.all.flatMap((group) =>
      group.tabs.filter((tab) =>
        (review !== undefined && isSameReviewTab(tab, review)) || isReviewTab(tab)
      ),
    );
    if (tabs.length > 0) {
      await vscode.window.tabGroups.close(tabs, true);
    }
    this.content.clear();
  }

  public async clearPlaceholders(): Promise<void> {
    return this.enqueue(() => this.clearPlaceholdersNow());
  }

  private async clearPlaceholdersNow(): Promise<void> {
    const tabs = vscode.window.tabGroups.all.flatMap((group) =>
      group.tabs.filter((tab) => isReviewPlaceholderTab(tab)),
    );
    if (tabs.length > 0) {
      await vscode.window.tabGroups.close(tabs, true);
    }
  }

  public dispose(): void {
    this.disposed = true;
    this.pending = undefined;
    this.review = undefined;
    this.registration.dispose();
    this.tabSubscription.dispose();
    this.content.clear();
  }

  private async applyPendingReview(): Promise<void> {
    return this.enqueue(async () => {
      const pending = this.pending;
      const current = this.review;
      if (
        pending === undefined ||
        current === undefined ||
        pending.repository !== current.repository ||
        pending.pod !== current.pod ||
        this.findOpenTab(current) === undefined ||
        !this.isActive(current)
      ) {
        return;
      }
      this.pending = undefined;
      try {
        await this.clearNow();
        const tab = await this.show(
          vscode.Uri.parse(pending.source),
          pending.pod,
          pending.resources,
        );
        if (this.disposed) {
          await this.closeDisposedTab(tab);
        }
        this.review = { ...pending, tab };
      } catch (error) {
        if (this.pending === undefined) {
          this.pending = pending;
        }
        throw error;
      }
    });
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.operations.then(() => {
      if (this.disposed) {
        throw new Error("Rumpelpod reviews have been disposed");
      }
      return operation();
    });
    this.operations = result.then(() => undefined, () => undefined);
    return result;
  }

  private async closeDisposedTab(tab: vscode.Tab): Promise<never> {
    await vscode.window.tabGroups.close(tab, true);
    throw new Error("Rumpelpod reviews were disposed while opening an editor");
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

  private findOpenTab(review: ReviewTab): vscode.Tab | undefined {
    return vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .find((tab) => isSameReviewTab(tab, review));
  }

  private isActive(review: ReviewTab): boolean {
    const active = vscode.window.tabGroups.activeTabGroup.activeTab;
    return active !== undefined && isSameReviewTab(active, review);
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
  const textDiffs = multiDiffs(input);
  return textDiffs !== undefined && textDiffs.length > 0 && textDiffs.every((diff) =>
    diff.original.scheme === REVIEW_SCHEME || diff.modified.scheme === REVIEW_SCHEME
  );
}

function isSameReviewTab(tab: vscode.Tab, review: ReviewTab): boolean {
  if (tab === review.tab) {
    return true;
  }
  if (tab.label !== review.tab.label) {
    return false;
  }
  const diffs = multiDiffs(tab.input);
  return diffs !== undefined && diffs.length === review.resources.length && diffs.every(
    (diff, index) => {
      const resource = review.resources[index];
      return resource !== undefined &&
        diff.original.toString() === resource.originalUri.toString() &&
        diff.modified.toString() === resource.modifiedUri.toString();
    },
  );
}

function isReviewPlaceholderTab(tab: vscode.Tab): boolean {
  const input = tab.input;
  return input instanceof vscode.TabInputText && input.uri.scheme === REVIEW_SCHEME;
}

function isEmptyMultiDiffTab(tab: vscode.Tab, pod: string): boolean {
  return tab.label === pod && multiDiffs(tab.input)?.length === 0;
}

function samePod(
  review: ReviewTab | undefined,
  repository: Repository,
  pod: string,
): review is ReviewTab {
  return review?.repository === repository.root && review.pod === pod;
}

function isMultiDiffTab(tab: vscode.Tab, resourceCount: number): boolean {
  return multiDiffs(tab.input)?.length === resourceCount;
}

function multiDiffs(input: unknown): readonly vscode.TabInputTextDiff[] | undefined {
  if (
    typeof input !== "object" ||
    input === null ||
    !("textDiffs" in input) ||
    !Array.isArray(input.textDiffs) ||
    !input.textDiffs.every((diff) => diff instanceof vscode.TabInputTextDiff)
  ) {
    return undefined;
  }
  return input.textDiffs;
}

function emptyReviewUri(repository: Repository | string, pod: string): vscode.Uri {
  const repositoryRoot = typeof repository === "string" ? repository : repository.root;
  return vscode.Uri.from({
    scheme: REVIEW_SCHEME,
    authority: "empty",
    path: `/${pod}`,
    query: encodeURIComponent(repositoryRoot),
  });
}

function populatedReviewUri(
  repository: Repository,
  pod: string,
  plan: ReviewPlan,
): vscode.Uri {
  return vscode.Uri.from({
    scheme: REVIEW_SCHEME,
    authority: "review",
    path: `/${pod}`,
    query: encodeURIComponent(JSON.stringify({
      base: plan.base,
      repository: repository.root,
      target: plan.target,
    })),
  });
}

function reviewResource(
  repository: Repository,
  plan: ReviewPlan,
  file: ReviewFile,
): MultiDiffResource {
  return {
    modifiedUri: reviewUri(
      repository,
      plan.target,
      file.path,
      file.target_exists,
      "target",
    ),
    originalUri: reviewUri(
      repository,
      plan.base,
      file.path,
      file.base_exists,
      "base",
    ),
  };
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
    authority: side,
    path: `/${filePath}`,
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
