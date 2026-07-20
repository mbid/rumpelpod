#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

workspace=${WORKSPACE:-/workspaces/rumpelpod}
extension_dir="$workspace/vscode"
export PATH="$HOME/.local/bin:$PATH"

credentials_dir="$HOME/.config/rumpelpod"
password_file="$credentials_dir/vscode-password"
if [ ! -f "$password_file" ]; then
    mkdir -p "$credentials_dir"
    umask 077
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n' > "$password_file"
fi
vscode_password=$(tr -d '\r\n' < "$password_file")
if [ -z "$vscode_password" ]; then
    echo "code-server password file is empty: $password_file" >&2
    exit 1
fi
export PASSWORD="$vscode_password"

npm --prefix "$extension_dir" ci --prefer-offline --no-audit --no-fund
npm --prefix "$extension_dir" run package
code-server --force --install-extension "$extension_dir/dist/rumpelpod-vscode.vsix"

exec code-server \
    --auth password \
    --bind-addr 0.0.0.0:3000 \
    --disable-telemetry \
    --disable-update-check \
    --disable-workspace-trust \
    "$workspace"
