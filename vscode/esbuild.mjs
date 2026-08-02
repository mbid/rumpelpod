// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as esbuild from "esbuild";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const watch = process.argv.includes("--watch");
await stageRuntimeLicenses();
const extension = await esbuild.context({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  external: ["vscode"],
  format: "cjs",
  logLevel: "info",
  outfile: "dist/extension.js",
  platform: "node",
  sourcemap: true,
  target: "node20",
});

const webview = await esbuild.context({
  entryPoints: ["src/webview.ts"],
  bundle: true,
  format: "iife",
  loader: { ".css": "css" },
  logLevel: "info",
  outdir: "dist",
  platform: "browser",
  target: "es2022",
});

if (watch) {
  await Promise.all([extension.watch(), webview.watch()]);
} else {
  await Promise.all([extension.rebuild(), webview.rebuild()]);
  await Promise.all([extension.dispose(), webview.dispose()]);
}

async function stageRuntimeLicenses() {
  const licenses = path.resolve("dist/licenses");
  await fs.rm(path.resolve("dist/node-pty"), { force: true, recursive: true });
  await fs.rm(licenses, { force: true, recursive: true });
  await fs.mkdir(licenses, { recursive: true });
  await Promise.all([
    fs.copyFile(
      path.resolve("node_modules/@xterm/xterm/LICENSE"),
      path.join(licenses, "xterm.txt"),
    ),
    fs.copyFile(
      path.resolve("node_modules/@xterm/addon-fit/LICENSE"),
      path.join(licenses, "xterm-addon-fit.txt"),
    ),
    fs.copyFile(path.resolve("node_modules/ws/LICENSE"), path.join(licenses, "ws.txt")),
  ]);
}
