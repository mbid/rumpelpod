// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";

const DEFAULT_MAX_OUTPUT = 32 * 1024 * 1024;

export interface ProcessOutput {
  stdout: Buffer;
  stderr: Buffer;
}

export interface RunProcessOptions {
  readonly environment?: NodeJS.ProcessEnv;
  readonly maxOutput?: number;
}

export class ProcessError extends Error {
  public constructor(
    public readonly program: string,
    public readonly args: readonly string[],
    public readonly exitCode: number | null,
    public readonly stderr: string,
  ) {
    const command = [program, ...args].join(" ");
    const detail = stderr.trim();
    super(detail.length > 0 ? `${command} failed: ${detail}` : `${command} failed`);
    this.name = "ProcessError";
  }
}

export function runProcess(
  program: string,
  args: readonly string[],
  cwd: string,
  options: RunProcessOptions = {},
): Promise<ProcessOutput> {
  const maxOutput = options.maxOutput ?? DEFAULT_MAX_OUTPUT;
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, {
      cwd,
      env: options.environment === undefined
        ? undefined
        : { ...process.env, ...options.environment },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputLength = 0;
    let outputError: Error | undefined;

    const append = (chunks: Buffer[], chunk: Buffer): void => {
      if (outputError !== undefined) {
        return;
      }
      outputLength += chunk.length;
      if (outputLength > maxOutput) {
        outputError = new Error(`${program} produced more than ${maxOutput} bytes of output`);
        child.kill();
        return;
      }
      chunks.push(chunk);
    };

    child.stdout.on("data", (chunk: Buffer) => append(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => append(stderr, chunk));
    child.on("error", reject);
    child.on("close", (exitCode) => {
      if (outputError !== undefined) {
        reject(outputError);
        return;
      }
      const result = {
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      };
      if (exitCode !== 0) {
        reject(
          new ProcessError(
            program,
            args,
            exitCode,
            result.stderr.toString("utf8") || result.stdout.toString("utf8"),
          ),
        );
        return;
      }
      resolve(result);
    });
  });
}
