// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import * as path from "node:path";

const vsce = path.resolve("node_modules/@vscode/vsce/vsce");
const result = spawnSync(
  process.execPath,
  [
    vsce,
    "package",
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
