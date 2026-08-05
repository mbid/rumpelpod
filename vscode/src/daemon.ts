// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as http from "node:http";
import * as path from "node:path";

import type { DaemonEvent, PodInfo, ReviewPlan } from "./generated/protocol";

interface ListPodsResponse {
  readonly pods: readonly PodInfo[];
}

interface SseMessage {
  readonly data: string;
  readonly event: string;
}

type Validator<T> = (value: unknown) => value is T;

export class RumpelpodDaemon {
  private readonly socketPath = daemonSocketPath();

  public constructor(private readonly log: (message: string) => void) {}

  public async listPods(repository: string, sync: boolean): Promise<readonly PodInfo[]> {
    const response = await this.requestResult(
      "GET",
      "/pod",
      {
        repo_path: repository,
        sync,
        sync_refs: sync,
      },
      isListPodsResponse,
      "listing pods",
    );
    return [...response.pods].sort(comparePods);
  }

  public review(repository: string, pod: string): Promise<ReviewPlan> {
    return this.requestResult(
      "POST",
      "/review",
      {
        repo_path: repository,
        pod_name: pod,
        paths: [],
      },
      isReviewPlan,
      `preparing review for '${pod}'`,
    );
  }

  public events(onEvent: (event: DaemonEvent) => void): DaemonEventStream {
    return new DaemonEventStream(this.socketPath, onEvent);
  }

  private requestResult<T>(
    method: "GET" | "POST",
    endpoint: string,
    value: object,
    validator: Validator<T>,
    operation: string,
  ): Promise<T> {
    const body = JSON.stringify(value);
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const request = http.request(
        {
          socketPath: this.socketPath,
          path: endpoint,
          method,
          headers: {
            "content-length": Buffer.byteLength(body),
            "content-type": "application/json",
          },
        },
        (response) => {
          if (response.statusCode !== 200) {
            readHttpError(response, operation, fail);
            return;
          }

          response.setEncoding("utf8");
          const parser = new SseParser((message) => {
            try {
              switch (message.event) {
                case "log": {
                  const log: unknown = JSON.parse(message.data);
                  if (typeof log !== "string") {
                    throw new Error("daemon log event was not a string");
                  }
                  this.log(log);
                  return;
                }
                case "result": {
                  const result: unknown = JSON.parse(message.data);
                  if (!validator(result)) {
                    throw new Error(`rumpelpod daemon returned an invalid result while ${operation}`);
                  }
                  succeed(result);
                  response.destroy();
                  return;
                }
                case "error": {
                  const error: unknown = JSON.parse(message.data);
                  if (!isErrorResponse(error)) {
                    throw new Error("rumpelpod daemon returned an invalid error response");
                  }
                  fail(new Error(error.error));
                  return;
                }
                default:
                  throw new Error(`rumpelpod daemon returned unknown event '${message.event}'`);
              }
            } catch (error) {
              fail(error);
              response.destroy();
            }
          });
          response.on("data", (chunk: string) => {
            try {
              parser.push(chunk);
            } catch (error) {
              fail(error);
              response.destroy();
            }
          });
          response.on("error", fail);
          response.on("end", () => {
            fail(new Error(`rumpelpod daemon closed the stream before finishing ${operation}`));
          });
        },
      );

      const succeed = (result: T): void => {
        if (settled) {
          return;
        }
        settled = true;
        resolve(result);
      };
      const fail = (error: unknown): void => {
        if (settled) {
          return;
        }
        settled = true;
        reject(error);
      };

      request.on("error", fail);
      request.end(body);
    });
  }
}

export class DaemonEventStream {
  public readonly completion: Promise<void>;

  private disposed = false;
  private readonly request: http.ClientRequest;
  private response: http.IncomingMessage | undefined;
  private resolveCompletion!: () => void;
  private rejectCompletion!: (error: unknown) => void;
  private settled = false;

  public constructor(
    socketPath: string,
    private readonly onEvent: (event: DaemonEvent) => void,
  ) {
    this.completion = new Promise<void>((resolve, reject) => {
      this.resolveCompletion = resolve;
      this.rejectCompletion = reject;
    });
    this.request = http.request(
      {
        socketPath,
        path: "/events",
        method: "GET",
      },
      (response) => this.read(response),
    );
    this.request.on("error", (error) => this.finish(error));
    this.request.end();
  }

  public dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.finish();
    this.response?.destroy();
    this.request.destroy();
  }

  private read(response: http.IncomingMessage): void {
    this.response = response;
    if (response.statusCode !== 200) {
      readHttpError(response, "subscribing to events", (error) => this.finish(error));
      return;
    }

    response.setEncoding("utf8");
    const parser = new SseParser((message) => {
      try {
        if (message.event !== "daemon_event") {
          throw new Error(`rumpelpod daemon returned unknown event '${message.event}'`);
        }
        const value: unknown = JSON.parse(message.data);
        if (!isDaemonEvent(value)) {
          throw new Error("rumpelpod daemon returned an invalid event payload");
        }
        this.onEvent(value);
      } catch (error) {
        this.finish(error);
        response.destroy();
      }
    });
    response.on("data", (chunk: string) => {
      try {
        parser.push(chunk);
      } catch (error) {
        this.finish(error);
        response.destroy();
      }
    });
    response.on("error", (error) => this.finish(error));
    response.on("end", () => {
      if (this.disposed) {
        this.finish();
      } else {
        this.finish(new Error("rumpelpod daemon event stream ended"));
      }
    });
  }

  private finish(error?: unknown): void {
    if (this.settled) {
      return;
    }
    this.settled = true;
    if (error === undefined || this.disposed) {
      this.resolveCompletion();
    } else {
      this.rejectCompletion(error);
    }
  }
}

class SseParser {
  private buffer = "";

  public constructor(private readonly onMessage: (message: SseMessage) => void) {}

  public push(chunk: string): void {
    this.buffer += chunk;
    for (;;) {
      const boundary = this.buffer.indexOf("\n\n");
      if (boundary < 0) {
        return;
      }
      const frame = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary + 2);
      this.parseFrame(frame);
    }
  }

  private parseFrame(frame: string): void {
    let event: string | undefined;
    const data: string[] = [];
    for (const rawLine of frame.split("\n")) {
      const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
      if (line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("event: ")) {
        event = line.slice("event: ".length);
        continue;
      }
      if (line.startsWith("data: ")) {
        data.push(line.slice("data: ".length));
        continue;
      }
      if (line.length !== 0) {
        throw new Error(`rumpelpod daemon returned an invalid SSE line: ${line}`);
      }
    }
    if (event === undefined && data.length === 0) {
      return;
    }
    if (event === undefined || data.length === 0) {
      throw new Error("rumpelpod daemon returned an incomplete SSE event");
    }
    this.onMessage({ event, data: data.join("\n") });
  }
}

function daemonSocketPath(): string {
  const configured = process.env.RUMPELPOD_DAEMON_SOCKET;
  if (configured !== undefined) {
    return configured;
  }
  let runtimeDirectory = process.env.XDG_RUNTIME_DIR;
  if (runtimeDirectory === undefined) {
    const uid = process.getuid?.();
    if (uid === undefined) {
      throw new Error("rumpelpod daemon sockets are only supported on POSIX platforms");
    }
    runtimeDirectory = `/tmp/rumpelpod-${uid}`;
  }
  return path.join(runtimeDirectory, "rumpelpod.sock");
}

function comparePods(left: PodInfo, right: PodInfo): number {
  const leftRunning = left.status === "Running";
  const rightRunning = right.status === "Running";
  if (leftRunning !== rightRunning) {
    return leftRunning ? -1 : 1;
  }
  return (right.last_commit_time ?? Number.MIN_SAFE_INTEGER) -
    (left.last_commit_time ?? Number.MIN_SAFE_INTEGER);
}

function isListPodsResponse(value: unknown): value is ListPodsResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    "pods" in value &&
    Array.isArray(value.pods) &&
    value.pods.every(isPodInfo)
  );
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

function isDaemonEvent(value: unknown): value is DaemonEvent {
  if (typeof value !== "object" || value === null || !("type" in value)) {
    return false;
  }
  switch (value.type) {
    case "resync":
      return true;
    case "pod_status_changed":
    case "pod_review_changed":
      return (
        "repository" in value &&
        "pod" in value &&
        typeof value.repository === "string" &&
        typeof value.pod === "string"
      );
  }
  return false;
}

function isErrorResponse(value: unknown): value is { readonly error: string } {
  return (
    typeof value === "object" &&
    value !== null &&
    "error" in value &&
    typeof value.error === "string"
  );
}

function readHttpError(
  response: http.IncomingMessage,
  operation: string,
  fail: (error: unknown) => void,
): void {
  const status = response.statusCode ?? "unknown";
  let body = "";
  response.setEncoding("utf8");
  response.on("data", (chunk: string) => {
    body += chunk;
    if (body.length > 32 * 1024) {
      body = body.slice(-32 * 1024);
    }
  });
  response.on("error", fail);
  response.on("end", () => {
    const detail = body.trim();
    const suffix = detail.length === 0 ? "" : `: ${detail}`;
    fail(new Error(`rumpelpod daemon returned HTTP ${status} while ${operation}${suffix}`));
  });
}
