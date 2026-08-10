#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

# Not WORKSPACE: the devcontainer already uses that name for the
# rumpelpod checkout itself (entrypoint.sh).
workspace=${RUMPELPOD_VSCODE_WORKSPACE:-/workspaces/anyhow-demo}
export PATH="$HOME/.local/bin:$PATH"
unset PASSWORD HASHED_PASSWORD

exec code-server \
    --auth none \
    --bind-addr 127.0.0.1:3000 \
    --disable-telemetry \
    --disable-update-check \
    --disable-workspace-trust \
    "$workspace"
