// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pty = require("./dist/node-pty/lib/index.js");
const child = pty.spawn("/bin/sh", ["-c", "exit 0"]);
const exitCode = await new Promise((resolve, reject) => {
  const timeout = setTimeout(() => {
    child.kill();
    reject(new Error("native PTY smoke process did not exit within five seconds"));
  }, 5_000);
  child.onExit((event) => {
    clearTimeout(timeout);
    resolve(event.exitCode);
  });
});
if (exitCode !== 0) {
  throw new Error(`native PTY smoke process exited with ${exitCode}`);
}
