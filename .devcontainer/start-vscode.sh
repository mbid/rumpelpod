#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

workspace=${WORKSPACE:-/workspaces/rumpelpod}
bind_addr=${RUMPELPOD_VSCODE_BIND_ADDR:-127.0.0.1:3000}
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

exec code-server \
    --auth password \
    --bind-addr "$bind_addr" \
    --disable-telemetry \
    --disable-update-check \
    --disable-workspace-trust \
    "$workspace"
