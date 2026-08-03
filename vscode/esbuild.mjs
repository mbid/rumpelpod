// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import * as esbuild from "esbuild";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const watch = process.argv.includes("--watch");
await stageRuntimeDependencies();
const extension = await esbuild.context({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  external: ["./node-pty/*", "vscode"],
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

async function stageRuntimeDependencies() {
  const source = path.resolve("node_modules/node-pty");
  const destination = path.resolve("dist/node-pty");
  const licenses = path.resolve("dist/licenses");
  await fs.rm(destination, { force: true, recursive: true });
  await fs.rm(licenses, { force: true, recursive: true });
  await fs.mkdir(destination, { recursive: true });
  await fs.mkdir(licenses, { recursive: true });
  await Promise.all([
    fs.copyFile(path.join(source, "LICENSE"), path.join(destination, "LICENSE")),
    fs.copyFile(path.join(source, "package.json"), path.join(destination, "package.json")),
    fs.cp(path.join(source, "lib"), path.join(destination, "lib"), { recursive: true }),
    fs.copyFile(
      path.resolve("node_modules/@xterm/xterm/LICENSE"),
      path.join(licenses, "xterm.txt"),
    ),
    fs.copyFile(
      path.resolve("node_modules/@xterm/addon-fit/LICENSE"),
      path.join(licenses, "xterm-addon-fit.txt"),
    ),
  ]);

  const nativeSources = [
    path.join(source, "build/Release"),
    path.join(source, "prebuilds", `${process.platform}-${process.arch}`),
  ];
  let copiedNativeBinding = false;
  for (const nativeSource of nativeSources) {
    try {
      await fs.access(nativeSource);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        continue;
      }
      throw error;
    }
    const relative = path.relative(source, nativeSource);
    const stagedNative = path.join(destination, relative);
    await fs.cp(nativeSource, stagedNative, { recursive: true });
    if (process.platform === "darwin") {
      await fs.chmod(path.join(stagedNative, "spawn-helper"), 0o755);
    }
    copiedNativeBinding = true;
  }
  if (!copiedNativeBinding) {
    throw new Error(`node-pty has no native binding for ${process.platform}-${process.arch}`);
  }
}
