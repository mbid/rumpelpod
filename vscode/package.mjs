// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import * as path from "node:path";

const target = currentTarget();
const vsce = path.resolve("node_modules/@vscode/vsce/vsce");
const result = spawnSync(
  process.execPath,
  [
    vsce,
    "package",
    "--target",
    target,
    "--skip-license",
    "--out",
    "dist/rumpelpod-vscode.vsix",
    ...process.argv.slice(2),
  ],
  { stdio: "inherit" },
);

if (result.error !== undefined) {
  throw result.error;
}
if (result.status === null) {
  throw new Error(`vsce was terminated by signal ${result.signal ?? "unknown"}`);
}
process.exitCode = result.status;

function currentTarget() {
  switch (process.platform) {
    case "darwin":
      switch (process.arch) {
        case "arm64":
          return "darwin-arm64";
        default:
          return unsupportedTarget();
      }
    case "linux":
      if (!usesGlibc()) {
        return unsupportedTarget();
      }
      switch (process.arch) {
        case "arm64":
          return "linux-arm64";
        case "x64":
          return "linux-x64";
        default:
          return unsupportedTarget();
      }
    default:
      return unsupportedTarget();
  }
}

function usesGlibc() {
  const report = process.report?.getReport();
  return report?.header.glibcVersionRuntime !== undefined;
}

function unsupportedTarget() {
  throw new Error(
    `VS Code does not support a native extension target for ${process.platform}-${process.arch}`,
  );
}
