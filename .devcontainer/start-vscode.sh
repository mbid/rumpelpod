#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

workspace=${WORKSPACE:-/workspaces/rumpelpod}
extension_dir="$workspace/vscode"

if [ ! -d "$extension_dir/node_modules" ]; then
    cp -a /opt/rumpelpod-vscode-node-modules "$extension_dir/node_modules"
fi

npm --prefix "$extension_dir" run package
code-server --force --install-extension "$extension_dir/dist/rumpelpod-vscode.vsix"

exec code-server \
    --auth none \
    --bind-addr 0.0.0.0:3000 \
    --disable-telemetry \
    --disable-update-check \
    --disable-workspace-trust \
    "$workspace"
