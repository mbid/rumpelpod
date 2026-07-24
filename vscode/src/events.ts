// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcess } from "node:child_process";
import * as readline from "node:readline";

import type { DaemonEvent } from "./generated/protocol";
import type { RumpelpodController } from "./controller";
import type { RumpelpodModel } from "./model";

const RECONNECT_DELAYS_MS = [250, 1_000, 3_000, 10_000] as const;

export class DaemonEvents {
  private child: ChildProcess | undefined;
  private disposed = false;
  private flushTimer: NodeJS.Timeout | undefined;
  private pending = new Map<string, DaemonEvent>();
  private reconnectAttempt = 0;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private refreshChain = Promise.resolve();

  public constructor(
    private readonly model: RumpelpodModel,
    private readonly controller: RumpelpodController,
  ) {}

  public async start(): Promise<void> {
    this.stopProcess();
    const repositories = await this.model.repositories();
    if (this.disposed) {
      return;
    }
    const executable = this.model.executable();
    const child = spawn(executable, ["events", "--json"], {
      cwd: repositories[0]?.root,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.child = child;
    const lines = readline.createInterface({ input: child.stdout! });
    let stderr = "";
    let finished = false;

    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      if (stderr.length > 32 * 1024) {
        stderr = stderr.slice(-32 * 1024);
      }
    });
    lines.on("line", (line) => {
      this.reconnectAttempt = 0;
      try {
        this.queue(parseDaemonEvent(line));
      } catch (error) {
        this.model.logError("reading a rumpelpod daemon event", error);
      }
    });
    const finish = (error?: unknown): void => {
      if (finished || this.child !== child) {
        return;
      }
      finished = true;
      lines.close();
      this.child = undefined;
      const detail = stderr.trim();
      if (error !== undefined) {
        this.model.logError("connecting to rumpelpod daemon events", error);
      } else if (detail.length > 0) {
        this.model.logError("rumpelpod daemon event stream ended", new Error(detail));
      }
      this.scheduleReconnect();
    };
    child.on("error", finish);
    child.on("close", () => finish());
  }

  public restart(): void {
    this.reconnectAttempt = 0;
    this.stopProcess();
    void this.start().catch((error: unknown) => {
      this.model.logError("restarting rumpelpod daemon events", error);
      this.scheduleReconnect();
    });
  }

  public dispose(): void {
    this.disposed = true;
    this.stopProcess();
    if (this.flushTimer !== undefined) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.pending.clear();
  }

  private queue(event: DaemonEvent): void {
    if (event.type === "resync") {
      this.pending.clear();
      this.pending.set("resync", event);
    } else if (!this.pending.has("resync")) {
      this.pending.set(`${event.repository}\u0000${event.pod}\u0000${event.type}`, event);
    }
    if (this.flushTimer === undefined) {
      this.flushTimer = setTimeout(() => this.flush(), 100);
    }
  }

  private flush(): void {
    this.flushTimer = undefined;
    const events = [...this.pending.values()];
    this.pending.clear();
    this.refreshChain = this.refreshChain
      .then(() => this.apply(events))
      .catch((error: unknown) => {
        this.model.logError("refreshing from rumpelpod daemon events", error);
      });
  }

  private async apply(events: readonly DaemonEvent[]): Promise<void> {
    if (events.some((event) => event.type === "resync")) {
      await this.controller.refresh();
      return;
    }
    let refreshStatus = false;
    let refreshReview = false;
    for (const event of events) {
      switch (event.type) {
        case "resync":
          throw new Error("resync was not handled before targeted daemon events");
        case "pod_status_changed":
          if (!this.controller.isActivePod(event.repository, event.pod)) {
            break;
          }
          refreshStatus = true;
          break;
        case "pod_review_changed":
          if (!this.controller.isActivePod(event.repository, event.pod)) {
            break;
          }
          refreshStatus = true;
          refreshReview = true;
          break;
      }
    }
    const updates: Promise<void>[] = [];
    if (refreshStatus) {
      updates.push(this.controller.refreshPodStatus());
    }
    if (refreshReview) {
      updates.push(this.controller.refreshActiveReview(true));
    }
    const failures = (await Promise.allSettled(updates))
      .filter((result): result is PromiseRejectedResult => result.status === "rejected")
      .map((result) => result.reason);
    if (failures.length === 1) {
      throw failures[0];
    }
    if (failures.length > 1) {
      throw new AggregateError(failures, "rumpelpod status and review refreshes failed");
    }
  }

  private scheduleReconnect(): void {
    if (this.disposed || this.reconnectTimer !== undefined) {
      return;
    }
    const index = Math.min(this.reconnectAttempt, RECONNECT_DELAYS_MS.length - 1);
    const delay = RECONNECT_DELAYS_MS[index];
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.start().catch((error: unknown) => {
        this.model.logError("reconnecting to rumpelpod daemon events", error);
        this.scheduleReconnect();
      });
    }, delay);
  }

  private stopProcess(): void {
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    if (this.child !== undefined) {
      const child = this.child;
      this.child = undefined;
      child.kill();
    }
  }
}

function parseDaemonEvent(line: string): DaemonEvent {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch (error) {
    throw new Error(`rumpel events emitted invalid JSON: ${line}`, { cause: error });
  }
  if (typeof value !== "object" || value === null || !("type" in value)) {
    throw new Error(`rumpel events emitted an invalid payload: ${line}`);
  }
  switch (value.type) {
    case "resync":
      return { type: "resync" };
    case "pod_status_changed":
    case "pod_review_changed":
      if (
        !("repository" in value) ||
        !("pod" in value) ||
        typeof value.repository !== "string" ||
        typeof value.pod !== "string"
      ) {
        throw new Error(`rumpel events emitted an invalid pod payload: ${line}`);
      }
      return {
        type: value.type,
        repository: value.repository,
        pod: value.pod,
      };
  }
  throw new Error(`rumpel events emitted an unknown event: ${line}`);
}
