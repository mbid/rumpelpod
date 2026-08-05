// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { DaemonEventStream, RumpelpodDaemon } from "./daemon";
import type { DaemonEvent } from "./generated/protocol";
import type { RumpelpodController } from "./controller";
import type { RumpelpodModel } from "./model";

const RECONNECT_DELAYS_MS = [250, 1_000, 3_000, 10_000] as const;

export class DaemonEvents {
  private disposed = false;
  private flushTimer: NodeJS.Timeout | undefined;
  private pending = new Map<string, DaemonEvent>();
  private reconnectAttempt = 0;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private refreshChain = Promise.resolve();
  private stream: DaemonEventStream | undefined;

  public constructor(
    private readonly daemon: RumpelpodDaemon,
    private readonly model: RumpelpodModel,
    private readonly controller: RumpelpodController,
  ) {}

  public async start(): Promise<void> {
    this.stopStream();
    if (this.disposed) {
      return;
    }
    const stream = this.daemon.events((event) => {
      this.reconnectAttempt = 0;
      this.queue(event);
    });
    this.stream = stream;
    void stream.completion.then(
      () => {
        if (this.stream !== stream) {
          return;
        }
        this.stream = undefined;
        this.scheduleReconnect();
      },
      (error: unknown) => {
        if (this.stream !== stream) {
          return;
        }
        this.stream = undefined;
        this.model.logError("connecting to rumpelpod daemon events", error);
        this.scheduleReconnect();
      },
    );
  }

  public restart(): void {
    this.reconnectAttempt = 0;
    this.stopStream();
    void this.start().catch((error: unknown) => {
      this.model.logError("restarting rumpelpod daemon events", error);
      this.scheduleReconnect();
    });
  }

  public dispose(): void {
    this.disposed = true;
    this.stopStream();
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
      await this.controller.refresh(false);
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
      updates.push(this.controller.refreshPodStatus(false));
    }
    if (refreshReview) {
      updates.push(this.controller.refreshActiveReview());
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

  private stopStream(): void {
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    if (this.stream !== undefined) {
      const stream = this.stream;
      this.stream = undefined;
      stream.dispose();
    }
  }
}
