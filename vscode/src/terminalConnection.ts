// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { StringDecoder } from "node:string_decoder";
import * as vscode from "vscode";
import WebSocket = require("ws");

import { runProcess, type ProcessOutput } from "./process";

interface SessionRequest {
  readonly cmd: readonly string[];
  readonly env: readonly string[];
  readonly name: string;
  readonly type: "session";
  readonly workdir?: string;
}

interface AttachRequest {
  readonly extra_args: readonly string[];
  readonly type: "attach";
}

type TerminalRequest = AttachRequest | SessionRequest;

interface TerminalDescriptor {
  readonly path: string;
  readonly request: TerminalRequest;
  readonly socketPath: string;
}

export interface TerminalExitEvent {
  readonly exitCode: number;
  readonly signal?: number;
}

export interface TerminalProcess {
  close(terminate: boolean): void;
  onData(listener: (data: string) => void): vscode.Disposable;
  onExit(listener: (event: TerminalExitEvent) => void): vscode.Disposable;
  pause(): void;
  resize(columns: number, rows: number): void;
  resume(): void;
  write(data: string): void;
}

const RECONNECT_DELAY_MILLISECONDS = 1_000;
const TERMINATE_TIMEOUT_MILLISECONDS = 500;

export async function startTerminal(
  executable: string,
  cwd: string,
  kind: string,
  pod: string,
  columns: number,
  rows: number,
  reportError: (context: string, error: unknown) => void,
): Promise<TerminalProcess> {
  let output: ProcessOutput;
  try {
    output = await runProcess(executable, ["editor-session", kind, pod], cwd);
  } catch (error) {
    throw contextualError("preparing the terminal session", error);
  }
  let descriptor: TerminalDescriptor;
  try {
    descriptor = parseDescriptor(output.stdout.toString("utf8"));
  } catch (error) {
    throw contextualError("reading the terminal session descriptor", error);
  }
  const terminal = new DirectTerminal(descriptor, columns, rows, reportError);
  try {
    await terminal.start();
  } catch (error) {
    throw contextualError("connecting to the terminal session", error);
  }
  return terminal;
}

class DirectTerminal implements TerminalProcess {
  private readonly dataListeners = new Set<(data: string) => void>();
  private readonly exitListeners = new Set<(event: TerminalExitEvent) => void>();
  private columns: number;
  private connecting = false;
  private decoder = new StringDecoder("utf8");
  private exited = false;
  private pendingData = "";
  private reconnectTimer: NodeJS.Timeout | undefined;
  private rows: number;
  private socket: WebSocket | undefined;
  private started = false;
  private stopped = false;

  public constructor(
    private readonly descriptor: TerminalDescriptor,
    columns: number,
    rows: number,
    private readonly reportError: (context: string, error: unknown) => void,
  ) {
    this.columns = columns;
    this.rows = rows;
  }

  public async start(): Promise<void> {
    await this.connect(true);
    this.started = true;
  }

  public onData(listener: (data: string) => void): vscode.Disposable {
    this.dataListeners.add(listener);
    if (this.pendingData.length > 0) {
      const data = this.pendingData;
      this.pendingData = "";
      queueMicrotask(() => listener(data));
    }
    return new vscode.Disposable(() => this.dataListeners.delete(listener));
  }

  public onExit(listener: (event: TerminalExitEvent) => void): vscode.Disposable {
    this.exitListeners.add(listener);
    if (this.exited) {
      queueMicrotask(() => listener({ exitCode: 0 }));
    }
    return new vscode.Disposable(() => this.exitListeners.delete(listener));
  }

  public write(data: string): void {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(Buffer.from(data, "utf8"));
    }
  }

  public resize(columns: number, rows: number): void {
    this.columns = columns;
    this.rows = rows;
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ cols: columns, rows, type: "resize" }));
    }
  }

  public pause(): void {
    this.socket?.pause();
  }

  public resume(): void {
    this.socket?.resume();
  }

  public close(terminate: boolean): void {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    const socket = this.socket;
    if (socket === undefined) {
      this.fireExit();
      return;
    }
    if (terminate && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "terminate" }));
      setTimeout(() => {
        if (!this.exited) {
          socket.terminate();
        }
      }, TERMINATE_TIMEOUT_MILLISECONDS);
      return;
    }
    socket.close();
  }

  private connect(create: boolean): Promise<void> {
    this.connecting = true;
    this.decoder = new StringDecoder("utf8");
    return new Promise((resolve, reject) => {
      const socketPath = encodeURI(this.descriptor.socketPath);
      const socket = new WebSocket(`ws+unix://${socketPath}:${this.descriptor.path}`, {
        perMessageDeflate: false,
      });
      this.socket = socket;
      let opened = false;
      socket.once("open", () => {
        opened = true;
        this.connecting = false;
        socket.send(
          JSON.stringify({
            ...this.descriptor.request,
            cols: this.columns,
            create,
            rows: this.rows,
          }),
        );
        resolve();
      });
      socket.on("message", (data, isBinary) => this.handleMessage(socket, data, isBinary));
      socket.once("error", (error) => {
        if (!opened) {
          reject(error);
        } else {
          this.reportError("reading the terminal WebSocket", error);
        }
      });
      socket.once("close", () => {
        if (this.socket === socket) {
          this.socket = undefined;
        }
        this.connecting = false;
        if (this.stopped) {
          this.fireExit();
        } else if (this.started) {
          this.scheduleReconnect();
        }
      });
    });
  }

  private handleMessage(socket: WebSocket, data: WebSocket.RawData, isBinary: boolean): void {
    if (this.socket !== socket || this.stopped) {
      return;
    }
    const bytes = rawDataBuffer(data);
    if (isBinary) {
      const decoded = this.decoder.write(bytes);
      if (decoded.length > 0) {
        if (this.dataListeners.size === 0) {
          this.pendingData = `${this.pendingData}${decoded}`;
        } else {
          for (const listener of this.dataListeners) {
            listener(decoded);
          }
        }
      }
      return;
    }
    let control: unknown;
    try {
      control = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      this.reportError("parsing a terminal control message", error);
      return;
    }
    if (
      typeof control === "object" &&
      control !== null &&
      "type" in control &&
      control.type === "session_ended"
    ) {
      this.stopped = true;
      socket.close();
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.connecting || this.reconnectTimer !== undefined) {
      return;
    }
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.connect(false).catch((error: unknown) => {
        this.reportError("reconnecting the terminal WebSocket", error);
        this.scheduleReconnect();
      });
    }, RECONNECT_DELAY_MILLISECONDS);
  }

  private fireExit(): void {
    if (this.exited) {
      return;
    }
    this.exited = true;
    for (const listener of this.exitListeners) {
      listener({ exitCode: 0 });
    }
  }
}

function parseDescriptor(json: string): TerminalDescriptor {
  const value: unknown = JSON.parse(json);
  if (
    typeof value !== "object" ||
    value === null ||
    !("socketPath" in value) ||
    typeof value.socketPath !== "string" ||
    !("path" in value) ||
    typeof value.path !== "string" ||
    !("request" in value) ||
    !isTerminalRequest(value.request)
  ) {
    throw new Error("rumpel editor-session returned an unexpected descriptor");
  }
  return {
    path: value.path,
    request: value.request,
    socketPath: value.socketPath,
  };
}

function isTerminalRequest(value: unknown): value is TerminalRequest {
  if (typeof value !== "object" || value === null || !("type" in value)) {
    return false;
  }
  switch (value.type) {
    case "attach":
      return (
        "extra_args" in value &&
        Array.isArray(value.extra_args) &&
        value.extra_args.every((item) => typeof item === "string")
      );
    case "session":
      return (
        "name" in value &&
        typeof value.name === "string" &&
        "cmd" in value &&
        Array.isArray(value.cmd) &&
        value.cmd.every((item) => typeof item === "string") &&
        "env" in value &&
        Array.isArray(value.env) &&
        value.env.every((item) => typeof item === "string") &&
        (!("workdir" in value) || value.workdir === null || typeof value.workdir === "string")
      );
    default:
      return false;
  }
}

function rawDataBuffer(data: WebSocket.RawData): Buffer {
  if (Buffer.isBuffer(data)) {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data);
  }
  if (Array.isArray(data)) {
    return Buffer.concat(data);
  }
  throw new Error("unsupported terminal WebSocket payload");
}

function contextualError(context: string, error: unknown): Error {
  const detail = errorDetail(error);
  return new Error(`${context}: ${detail}`, { cause: error });
}

function errorDetail(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) {
    return error.message;
  }
  if (typeof error === "object" && error !== null) {
    const fields = ["code", "errno", "syscall", "address"]
      .filter((field) => field in error)
      .map((field) => `${field}=${String(Reflect.get(error, field))}`);
    if (fields.length > 0) {
      return fields.join(", ");
    }
  }
  const text = String(error);
  return text.length > 0 ? text : "unknown error";
}
