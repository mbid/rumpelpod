// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as vscode from "vscode";

import type { ReviewFile, ReviewPlan } from "./generated/protocol";
import type { Repository } from "./model";
import { runProcess } from "./process";

const REVIEW_SCHEME = "rumpelpod-review";
const REVIEW_GENERATIONS_KEY = "rumpelpod.reviewGenerations";
const STORED_REVIEWS_KEY = "rumpelpod.openReviews";
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

interface StoredReview {
  readonly pod: string;
  readonly repository: string;
  readonly resources: readonly StoredReviewResource[];
  readonly source: string;
}

interface StoredReviewResource {
  readonly modified: string;
  readonly original: string;
}

interface ReviewRecord {
  readonly current: ReviewTab;
  readonly pending: ReviewSnapshot | undefined;
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
  private readonly closeTimers = new Map<string, NodeJS.Timeout>();
  private readonly content = new Map<string, Promise<string>>();
  private readonly reviews = new Map<string, ReviewRecord>();
  private disposed = false;
  private operations = Promise.resolve();

  public constructor(
    private readonly workspaceState: vscode.Memento,
    private readonly reportError: (context: string, error: unknown) => void,
  ) {
    this.registration = vscode.workspace.registerTextDocumentContentProvider(REVIEW_SCHEME, this);
    this.tabSubscription = vscode.window.tabGroups.onDidChangeTabs((event) => {
      this.scheduleClosedReviews(event.closed);
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
    const generation = this.reviewGeneration(repository.root, pod);
    const source = populatedReviewUri(repository, pod, plan, generation);
    const snapshot = {
      pod,
      repository: repository.root,
      resources: plan.files.map((file) => reviewResource(repository, plan, file)),
      source: source.toString(),
    } satisfies ReviewSnapshot;
    await this.updateNow(snapshot, refreshOnly);
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
    const generation = this.reviewGeneration(repository.root, pod);
    const source = emptyReviewUri(repository, pod, generation);
    const snapshot = {
      pod,
      repository: repository.root,
      resources: [],
      source: source.toString(),
    } satisfies ReviewSnapshot;
    await this.updateNow(snapshot, refreshOnly);
  }

  private async updateNow(snapshot: ReviewSnapshot, refreshOnly: boolean): Promise<void> {
    const key = reviewKey(snapshot.repository, snapshot.pod);
    const record = this.reviews.get(key);
    let current = record?.current;
    let openTab = current === undefined ? undefined : this.findOpenTab(current);
    let restoredShell: vscode.Tab | undefined;
    if (!refreshOnly && openTab === undefined) {
      const restoredTabs = this.findPodTabs(snapshot.repository, snapshot.pod);
      let exact = restoredTabs.find((tab) => isSnapshotReviewTab(tab, snapshot));
      const storedRestored = exact === undefined
        ? this.findStoredRestoredTab(snapshot)
        : undefined;
      if (snapshot.resources.length === 0) {
        exact = storedRestored;
      } else {
        restoredShell = storedRestored;
      }
      const staleTabs = restoredTabs.filter((tab) => tab !== exact);
      if (staleTabs.length > 0) {
        await vscode.window.tabGroups.close(staleTabs, true);
        for (const tab of staleTabs) {
          this.evictTab(tab);
        }
      }
      if (exact !== undefined) {
        current = { ...snapshot, tab: exact };
        openTab = exact;
        this.reviews.set(key, { current, pending: record?.pending });
      }
      if (restoredShell !== undefined) {
        await vscode.window.tabGroups.close(restoredShell, true);
        const shellIsOpen = vscode.window.tabGroups.all
          .flatMap((group) => group.tabs)
          .includes(restoredShell);
        if (shellIsOpen) {
          throw new Error(`VS Code did not close the restored review for pod '${snapshot.pod}'`);
        }
        this.evictTab(restoredShell);
        await this.advanceReviewGeneration(snapshot.repository, snapshot.pod);
        snapshot = reviewSnapshotWithGeneration(
          snapshot,
          this.reviewGeneration(snapshot.repository, snapshot.pod),
        );
      }
    }
    const currentIsOpen = openTab !== undefined;
    if (!refreshOnly && current !== undefined && !currentIsOpen) {
      await this.advanceReviewGeneration(snapshot.repository, snapshot.pod);
      snapshot = reviewSnapshotWithGeneration(
        snapshot,
        this.reviewGeneration(snapshot.repository, snapshot.pod),
      );
    }
    if (current !== undefined && openTab !== undefined && openTab !== current.tab) {
      current = { ...current, tab: openTab };
      this.reviews.set(key, { current, pending: record?.pending });
    }
    if (refreshOnly) {
      if (current === undefined || !currentIsOpen) {
        return;
      }
      if (current.source === snapshot.source) {
        this.reviews.set(key, { current, pending: undefined });
        await this.rememberReview(snapshot);
        return;
      }
      if (!this.isActive(current)) {
        this.reviews.set(key, { current, pending: snapshot });
        return;
      }
    }

    if (
      !refreshOnly &&
      current !== undefined &&
      openTab !== undefined &&
      current.source === snapshot.source
    ) {
      const tab = await this.focus(openTab, snapshot);
      this.reviews.set(key, { current: { ...snapshot, tab }, pending: undefined });
      await this.rememberReview(snapshot);
      return;
    }

    if (current !== undefined && (current.source !== snapshot.source || !currentIsOpen)) {
      await this.closeReviewNow(key, current);
    }
    const tab = await this.show(snapshot);
    if (this.disposed) {
      await this.closeDisposedTab(tab);
    }
    this.reviews.set(key, { current: { ...snapshot, tab }, pending: undefined });
    await this.rememberReview(snapshot);
  }

  private async show(snapshot: ReviewSnapshot): Promise<vscode.Tab> {
    // vscode.changes uses a random identity, which duplicates a restored review.
    await vscode.commands.executeCommand(
      "_workbench.openMultiDiffEditor",
      {
        multiDiffSourceUri: vscode.Uri.parse(snapshot.source),
        resources: snapshot.resources,
        title: snapshot.pod,
      } satisfies OpenMultiDiffEditorOptions,
    );
    return this.normalizeActive(snapshot, undefined);
  }

  private async focus(tab: vscode.Tab, snapshot: ReviewSnapshot): Promise<vscode.Tab> {
    const focused = await this.show(snapshot);
    if (focused === tab) {
      return focused;
    }
    const openTabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs);
    if (!openTabs.includes(tab)) {
      if (!isSnapshotReviewTab(focused, snapshot)) {
        throw new Error(`VS Code replaced the review for pod '${snapshot.pod}' with another editor`);
      }
      return focused;
    }
    if (!isSnapshotReviewTab(focused, snapshot)) {
      throw new Error(`VS Code opened another editor while focusing pod '${snapshot.pod}'`);
    }
    await vscode.window.tabGroups.close(focused, true);
    const remainingTabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs);
    if (remainingTabs.includes(focused)) {
      throw new Error(`VS Code did not close a duplicate review for pod '${snapshot.pod}'`);
    }
    await this.activateTab(tab, `review for pod '${snapshot.pod}'`);
    return this.normalizeActive(snapshot, tab);
  }

  private async activateTab(
    tab: vscode.Tab,
    description: string,
    matches: (active: vscode.Tab) => boolean = (active) => active === tab,
  ): Promise<void> {
    if (tab.group !== vscode.window.tabGroups.activeTabGroup) {
      await vscode.commands.executeCommand(focusGroupCommand(tab.group.viewColumn));
      if (tab.group !== vscode.window.tabGroups.activeTabGroup) {
        throw new Error(`VS Code did not focus the editor group containing the ${description}`);
      }
    }
    // Pod selection originates in the sidebar webview, which otherwise keeps
    // navigation commands from changing the editor group's active tab.
    await vscode.commands.executeCommand("workbench.action.focusActiveEditorGroup");
    const index = tab.group.tabs.indexOf(tab);
    if (index < 0) {
      throw new Error(`VS Code lost the ${description} while focusing it`);
    }
    if (index < 9) {
      await vscode.commands.executeCommand(`workbench.action.openEditorAtIndex${index + 1}`);
      const focused = vscode.window.tabGroups.activeTabGroup.activeTab;
      if (focused === undefined || !matches(focused)) {
        throw new Error(`VS Code did not focus the ${description}`);
      }
      return;
    }
    const active = tab.group.activeTab;
    if (active === undefined) {
      throw new Error(`VS Code has no active editor while focusing the ${description}`);
    }
    const activeIndex = tab.group.tabs.indexOf(active);
    if (activeIndex < 0) {
      throw new Error(`VS Code lost its active editor while focusing the ${description}`);
    }
    const steps = (index - activeIndex + tab.group.tabs.length) % tab.group.tabs.length;
    for (let step = 0; step < steps; step += 1) {
      await vscode.commands.executeCommand("workbench.action.nextEditor");
    }
    const focused = vscode.window.tabGroups.activeTabGroup.activeTab;
    if (focused === undefined || !matches(focused)) {
      throw new Error(`VS Code did not focus the ${description}`);
    }
  }

  private async normalizeActive(
    snapshot: ReviewSnapshot,
    expected: vscode.Tab | undefined,
  ): Promise<vscode.Tab> {
    let tab = vscode.window.tabGroups.activeTabGroup.activeTab;
    // Multi-diff tabs can render as previews before the tab API reports that state.
    await vscode.commands.executeCommand("workbench.action.keepEditor");
    tab = vscode.window.tabGroups.activeTabGroup.activeTab;
    if (tab?.isPinned === true) {
      await vscode.commands.executeCommand("workbench.action.unpinEditor");
      tab = vscode.window.tabGroups.activeTabGroup.activeTab;
    }
    const matchesReview = tab !== undefined && (
      expected === undefined
        ? isSnapshotReviewTab(tab, snapshot)
        : tab === expected
    );
    if (
      tab === undefined ||
      tab.isPinned ||
      tab.isPreview ||
      !matchesReview
    ) {
      const activeLabel = tab?.label ?? "none";
      const expectedLabel = expected?.label ?? "none";
      const sameTab = tab !== undefined && tab === expected;
      const snapshotMatch = tab !== undefined && isSnapshotReviewTab(tab, snapshot);
      throw new Error(
        `VS Code did not open the review for pod '${snapshot.pod}' ` +
          `(active '${activeLabel}', expected '${expectedLabel}', ` +
          `same tab ${sameTab}, snapshot match ${snapshotMatch})`,
      );
    }
    return tab;
  }

  public async close(repository: Repository, pod: string): Promise<void> {
    return this.enqueue(async () => {
      const key = reviewKey(repository.root, pod);
      const current = this.reviews.get(key)?.current;
      if (current !== undefined) {
        await this.closeReviewNow(key, current);
        return;
      }
      const stored = this.storedReview(repository.root, pod);
      const restored = stored === undefined ? undefined : this.findStoredRestoredTab(stored);
      const tabs = [
        ...this.findPodTabs(repository.root, pod),
        ...(restored === undefined ? [] : [restored]),
      ];
      if (tabs.length > 0) {
        await this.closeTabs(
          (tab) => tabs.includes(tab) || isPodReviewTab(tab, repository.root, pod),
          pod,
          stored,
        );
        for (const tab of tabs) {
          this.evictTab(tab);
        }
      }
      await this.forgetReview(repository.root, pod);
    });
  }

  private async closeReviewNow(key: string, review: ReviewTab): Promise<void> {
    this.reviews.delete(key);
    const tabs = vscode.window.tabGroups.all.flatMap((group) =>
      group.tabs.filter((tab) =>
        isSameReviewTab(tab, review) ||
        isPodReviewTab(tab, review.repository, review.pod)
      ),
    );
    if (tabs.length > 0) {
      await this.closeTabs(
        (tab) =>
          isSameReviewTab(tab, review) ||
          isPodReviewTab(tab, review.repository, review.pod),
        review.pod,
        review,
      );
    }
    this.evict(review);
    await this.forgetReview(review.repository, review.pod);
  }

  private async closeTabs(
    matches: (tab: vscode.Tab) => boolean,
    pod: string,
    snapshot: ReviewSnapshot | undefined,
  ): Promise<void> {
    const tabs = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter(matches);
    const active = vscode.window.tabGroups.activeTabGroup.activeTab;
    const activeReview = tabs.find((tab) => tab === active);
    const background = tabs.filter((tab) => tab !== activeReview);
    if (background.length > 0) {
      await vscode.window.tabGroups.close(background, true);
    }
    if (activeReview !== undefined) {
      if (vscode.window.tabGroups.activeTabGroup.activeTab !== activeReview) {
        throw new Error(`VS Code changed editors while closing the review for pod '${pod}'`);
      }
      if (snapshot !== undefined && isSnapshotReviewTab(activeReview, snapshot)) {
        await this.focus(activeReview, snapshot);
      }
      await this.closeActiveReview(matches, pod);
    }
    let remaining = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter(matches);
    for (const tab of remaining) {
      const tabIsOpen = vscode.window.tabGroups.all
        .flatMap((group) => group.tabs)
        .includes(tab);
      if (!tabIsOpen) {
        continue;
      }
      const previouslyActive = vscode.window.tabGroups.activeTabGroup.activeTab;
      if (snapshot !== undefined && isSnapshotReviewTab(tab, snapshot)) {
        await this.focus(tab, snapshot);
      } else {
        await this.activateTab(tab, `review for pod '${pod}'`);
      }
      await this.closeActiveReview(matches, pod);
      if (previouslyActive !== undefined) {
        const previousIsOpen = vscode.window.tabGroups.all
          .flatMap((group) => group.tabs)
          .includes(previouslyActive);
        if (previousIsOpen) {
          await this.activateTab(previouslyActive, "previously active editor");
        }
      }
    }
    remaining = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter(matches);
    if (remaining.length > 0) {
      throw new Error(`VS Code did not close the review for pod '${pod}'`);
    }
  }

  private async closeActiveReview(
    matches: (tab: vscode.Tab) => boolean,
    pod: string,
  ): Promise<void> {
    // code-server ignores editor commands while its sidebar webview still owns focus.
    await vscode.commands.executeCommand("workbench.action.focusActiveEditorGroup");
    await vscode.commands.executeCommand("workbench.action.keepEditor");
    let active = vscode.window.tabGroups.activeTabGroup.activeTab;
    if (active?.isPinned === true) {
      await vscode.commands.executeCommand("workbench.action.unpinEditor");
      active = vscode.window.tabGroups.activeTabGroup.activeTab;
    }
    if (active === undefined || !matches(active)) {
      throw new Error(`VS Code changed editors while closing the review for pod '${pod}'`);
    }
    await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
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
    for (const timer of this.closeTimers.values()) {
      clearTimeout(timer);
    }
    this.closeTimers.clear();
    this.reviews.clear();
    this.registration.dispose();
    this.tabSubscription.dispose();
    this.content.clear();
  }

  private async applyPendingReview(): Promise<void> {
    return this.enqueue(async () => {
      const active = vscode.window.tabGroups.activeTabGroup.activeTab;
      if (active === undefined) {
        return;
      }
      const selected = [...this.reviews.entries()].find(([, record]) =>
        isSameReviewTab(active, record.current)
      );
      if (selected === undefined) {
        return;
      }
      const [key, record] = selected;
      const pending = record.pending;
      if (pending === undefined) {
        return;
      }
      this.reviews.set(key, { current: record.current, pending: undefined });
      try {
        await this.closeReviewNow(key, record.current);
        const tab = await this.show(pending);
        if (this.disposed) {
          await this.closeDisposedTab(tab);
        }
        this.reviews.set(key, { current: { ...pending, tab }, pending: undefined });
        await this.rememberReview(pending);
      } catch (error) {
        if (!this.disposed && !this.reviews.has(key)) {
          this.reviews.set(key, { current: record.current, pending });
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

  private evict(snapshot: ReviewSnapshot): void {
    for (const resource of snapshot.resources) {
      this.content.delete(resource.modifiedUri.toString());
      this.content.delete(resource.originalUri.toString());
    }
  }

  private evictTab(tab: vscode.Tab): void {
    const diffs = multiDiffs(tab.input) ?? [];
    for (const diff of diffs) {
      this.content.delete(diff.modified.toString());
      this.content.delete(diff.original.toString());
    }
  }

  private scheduleClosedReviews(closedTabs: readonly vscode.Tab[]): void {
    // Browser reload reports teardown as tab closures before disposing the extension.
    if (vscode.window.tabGroups.all.every((group) => group.tabs.length === 0)) {
      return;
    }
    for (const [key, record] of this.reviews) {
      if (!closedTabs.some((tab) => isSameReviewTab(tab, record.current))) {
        continue;
      }
      const existing = this.closeTimers.get(key);
      if (existing !== undefined) {
        clearTimeout(existing);
      }
      const closed = record.current;
      const timer = setTimeout(() => {
        this.closeTimers.delete(key);
        if (this.disposed) {
          return;
        }
        void this.enqueue(async () => {
          if (this.reviews.get(key)?.current !== closed) {
            return;
          }
          const matchingTab = this.findOpenTab(closed) ?? this.findStoredRestoredTab(closed);
          if (
            matchingTab !== undefined ||
            vscode.window.tabGroups.all.every((group) => group.tabs.length === 0)
          ) {
            return;
          }
          this.reviews.delete(key);
          this.evict(closed);
          await this.forgetReview(closed.repository, closed.pod);
          await this.advanceReviewGeneration(closed.repository, closed.pod);
        }).catch((error: unknown) => {
          this.reportError("forgetting a closed pod review", error);
        });
      }, 500);
      this.closeTimers.set(key, timer);
    }
  }

  private findOpenTab(review: ReviewTab): vscode.Tab | undefined {
    const tabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs);
    return tabs.find((tab) => isSameReviewTab(tab, review));
  }

  private findPodTabs(repository: string, pod: string): readonly vscode.Tab[] {
    return vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter((tab) => isPodReviewTab(tab, repository, pod));
  }

  private findStoredRestoredTab(snapshot: ReviewSnapshot): vscode.Tab | undefined {
    const stored = Object.values(this.storedReviews()).filter((review) =>
      review.pod === snapshot.pod && review.resources.length === snapshot.resources.length
    );
    if (
      stored.length !== 1 ||
      !storedReviewMatchesSnapshot(stored[0], snapshot)
    ) {
      return undefined;
    }
    const candidates = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter((tab) => isOpaqueRestoredReviewTab(tab, snapshot));
    return candidates.length === 1 ? candidates[0] : undefined;
  }

  private storedReview(repository: string, pod: string): ReviewSnapshot | undefined {
    const stored = this.storedReviews()[reviewKey(repository, pod)];
    return stored === undefined ? undefined : snapshotFromStoredReview(stored);
  }

  private storedReviews(): Readonly<Record<string, StoredReview>> {
    const value = this.workspaceState.get<unknown>(STORED_REVIEWS_KEY);
    if (value === undefined) {
      return {};
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("invalid stored Rumpelpod review state");
    }
    const reviews: Record<string, StoredReview> = {};
    for (const [key, review] of Object.entries(value)) {
      if (!isStoredReview(review)) {
        throw new Error(`invalid stored Rumpelpod review '${key}'`);
      }
      reviews[key] = review;
    }
    return reviews;
  }

  private async rememberReview(snapshot: ReviewSnapshot): Promise<void> {
    const key = reviewKey(snapshot.repository, snapshot.pod);
    const timer = this.closeTimers.get(key);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.closeTimers.delete(key);
    }
    const reviews = { ...this.storedReviews() };
    reviews[key] = storedReviewFromSnapshot(snapshot);
    await this.workspaceState.update(STORED_REVIEWS_KEY, reviews);
  }

  private async forgetReview(repository: string, pod: string): Promise<void> {
    const reviews = { ...this.storedReviews() };
    delete reviews[reviewKey(repository, pod)];
    await this.workspaceState.update(STORED_REVIEWS_KEY, reviews);
  }

  private reviewGeneration(repository: string, pod: string): number {
    const generations = this.workspaceState.get<unknown>(REVIEW_GENERATIONS_KEY);
    if (generations === undefined) {
      return 0;
    }
    if (typeof generations !== "object" || generations === null || Array.isArray(generations)) {
      throw new Error("invalid stored Rumpelpod review generations");
    }
    const generation = (generations as Record<string, unknown>)[reviewKey(repository, pod)];
    if (generation === undefined) {
      return 0;
    }
    if (!Number.isSafeInteger(generation) || (generation as number) < 0) {
      throw new Error(`invalid stored Rumpelpod review generation for pod '${pod}'`);
    }
    return generation as number;
  }

  private async advanceReviewGeneration(repository: string, pod: string): Promise<void> {
    const value = this.workspaceState.get<unknown>(REVIEW_GENERATIONS_KEY);
    if (value !== undefined && (typeof value !== "object" || value === null || Array.isArray(value))) {
      throw new Error("invalid stored Rumpelpod review generations");
    }
    const generations = { ...(value as Record<string, unknown> | undefined) };
    generations[reviewKey(repository, pod)] = this.reviewGeneration(repository, pod) + 1;
    await this.workspaceState.update(REVIEW_GENERATIONS_KEY, generations);
  }

  private isActive(review: ReviewTab): boolean {
    const active = vscode.window.tabGroups.activeTabGroup.activeTab;
    return active !== undefined && isSameReviewTab(active, review);
  }
}

function isSameReviewTab(tab: vscode.Tab, review: ReviewTab): boolean {
  if (tab === review.tab) {
    return true;
  }
  if (review.resources.length === 0) {
    return false;
  }
  return isSnapshotReviewTab(tab, review);
}

function isSnapshotReviewTab(tab: vscode.Tab, snapshot: ReviewSnapshot): boolean {
  if (!isPodTabLabel(tab.label, snapshot.pod)) {
    return false;
  }
  const diffs = multiDiffs(tab.input);
  if (diffs === undefined || diffs.length !== snapshot.resources.length) {
    return false;
  }
  if (diffs.length === 0) {
    return true;
  }
  const actual = diffs.map((diff) => reviewResourceKey(diff.original, diff.modified)).sort();
  const expected = snapshot.resources
    .map((resource) => reviewResourceKey(resource.originalUri, resource.modifiedUri))
    .sort();
  return actual.every((resource, index) => resource === expected[index]);
}

function isReviewPlaceholderTab(tab: vscode.Tab): boolean {
  const input = tab.input;
  return input instanceof vscode.TabInputText && input.uri.scheme === REVIEW_SCHEME;
}

function isPodReviewTab(tab: vscode.Tab, repository: string, pod: string): boolean {
  if (!isPodTabLabel(tab.label, pod)) {
    return false;
  }
  const diffs = multiDiffs(tab.input);
  return diffs !== undefined && diffs.length > 0 && diffs.every((diff) =>
    reviewRepository(diff.original) === repository &&
    reviewRepository(diff.modified) === repository
  );
}

function isEmptyReviewTab(tab: vscode.Tab, pod: string): boolean {
  return isPodTabLabel(tab.label, pod) && multiDiffs(tab.input)?.length === 0;
}

function isOpaqueRestoredReviewTab(tab: vscode.Tab, snapshot: ReviewSnapshot): boolean {
  const count = snapshot.resources.length;
  const labelMatches = tab.label === snapshot.pod ||
    tab.label === `${snapshot.pod} (${count} file)` ||
    tab.label === `${snapshot.pod} (${count} files)`;
  return labelMatches && multiDiffs(tab.input)?.length === 0;
}

function isPodTabLabel(label: string, pod: string): boolean {
  return label === pod || label.startsWith(`${pod} (`);
}

function reviewResourceKey(original: vscode.Uri, modified: vscode.Uri): string {
  return JSON.stringify([original.toString(), modified.toString()]);
}

function reviewSnapshotWithGeneration(
  snapshot: ReviewSnapshot,
  generation: number,
): ReviewSnapshot {
  const uri = vscode.Uri.parse(snapshot.source);
  let query: unknown;
  try {
    query = JSON.parse(decodeURIComponent(uri.query));
  } catch (error) {
    throw new Error(`invalid Rumpelpod review source: ${snapshot.source}`, { cause: error });
  }
  if (typeof query !== "object" || query === null || Array.isArray(query)) {
    throw new Error(`invalid Rumpelpod review source: ${snapshot.source}`);
  }
  return {
    ...snapshot,
    source: uri.with({
      query: encodeURIComponent(JSON.stringify({ ...query, generation })),
    }).toString(),
  };
}

function storedReviewFromSnapshot(snapshot: ReviewSnapshot): StoredReview {
  return {
    pod: snapshot.pod,
    repository: snapshot.repository,
    resources: snapshot.resources.map((resource) => ({
      modified: resource.modifiedUri.toString(),
      original: resource.originalUri.toString(),
    })),
    source: snapshot.source,
  };
}

function snapshotFromStoredReview(review: StoredReview): ReviewSnapshot {
  return {
    pod: review.pod,
    repository: review.repository,
    resources: review.resources.map((resource) => ({
      modifiedUri: vscode.Uri.parse(resource.modified),
      originalUri: vscode.Uri.parse(resource.original),
    })),
    source: review.source,
  };
}

function storedReviewMatchesSnapshot(
  stored: StoredReview | undefined,
  snapshot: ReviewSnapshot,
): boolean {
  if (stored === undefined) {
    return false;
  }
  const actual = stored.resources
    .map((resource) => JSON.stringify([resource.original, resource.modified]))
    .sort();
  const expected = snapshot.resources
    .map((resource) => reviewResourceKey(resource.originalUri, resource.modifiedUri))
    .sort();
  return stored.pod === snapshot.pod &&
    stored.repository === snapshot.repository &&
    actual.length === expected.length &&
    actual.every((resource, index) => resource === expected[index]);
}

function isStoredReview(value: unknown): value is StoredReview {
  return typeof value === "object" &&
    value !== null &&
    "pod" in value &&
    typeof value.pod === "string" &&
    "repository" in value &&
    typeof value.repository === "string" &&
    "source" in value &&
    typeof value.source === "string" &&
    "resources" in value &&
    Array.isArray(value.resources) &&
    value.resources.every(isStoredReviewResource);
}

function isStoredReviewResource(value: unknown): value is StoredReviewResource {
  return typeof value === "object" &&
    value !== null &&
    "modified" in value &&
    typeof value.modified === "string" &&
    "original" in value &&
    typeof value.original === "string";
}

function focusGroupCommand(viewColumn: vscode.ViewColumn): string {
  switch (viewColumn) {
    case vscode.ViewColumn.Active:
      throw new Error("an editor tab resolved to the symbolic active group");
    case vscode.ViewColumn.Beside:
      throw new Error("an editor tab resolved to the symbolic beside group");
    case vscode.ViewColumn.One:
      return "workbench.action.focusFirstEditorGroup";
    case vscode.ViewColumn.Two:
      return "workbench.action.focusSecondEditorGroup";
    case vscode.ViewColumn.Three:
      return "workbench.action.focusThirdEditorGroup";
    case vscode.ViewColumn.Four:
      return "workbench.action.focusFourthEditorGroup";
    case vscode.ViewColumn.Five:
      return "workbench.action.focusFifthEditorGroup";
    case vscode.ViewColumn.Six:
      return "workbench.action.focusSixthEditorGroup";
    case vscode.ViewColumn.Seven:
      return "workbench.action.focusSeventhEditorGroup";
    case vscode.ViewColumn.Eight:
      return "workbench.action.focusEighthEditorGroup";
    case vscode.ViewColumn.Nine:
      return "workbench.action.focusLastEditorGroup";
  }
  throw new Error(`unknown editor view column: ${viewColumn}`);
}

function reviewKey(repository: string, pod: string): string {
  return JSON.stringify([repository, pod]);
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

function reviewRepository(uri: vscode.Uri): string | undefined {
  if (uri.scheme !== REVIEW_SCHEME) {
    return undefined;
  }
  return decodeDescriptor(uri).repository;
}

function emptyReviewUri(repository: Repository, pod: string, generation: number): vscode.Uri {
  return vscode.Uri.from({
    scheme: REVIEW_SCHEME,
    authority: "empty",
    path: `/${pod}`,
    query: encodeURIComponent(JSON.stringify({
      generation,
      repository: repository.root,
    })),
  });
}

function populatedReviewUri(
  repository: Repository,
  pod: string,
  plan: ReviewPlan,
  generation: number,
): vscode.Uri {
  return vscode.Uri.from({
    scheme: REVIEW_SCHEME,
    authority: "review",
    path: `/${pod}`,
    query: encodeURIComponent(JSON.stringify({
      base: plan.base,
      generation,
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
